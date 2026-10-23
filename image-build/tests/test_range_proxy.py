import importlib.util
import json
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

proxy = load("range_proxy", ROOT / "attacker" / "range_proxy.py")
harness = load("guest_exploit", ROOT / "attacker" / "exploit.py")


def request(target=b"/health.php", headers=((b"Host", b"192.168.10.55"),), body=b""):
    head = b"GET " + target + b" HTTP/1.1\r\n" + b"".join(key + b": " + value + b"\r\n" for key, value in headers) + b"\r\n"
    return head + body


class RequestFramingTests(unittest.TestCase):
    def test_real_origin_form_request_is_preserved(self):
        raw = request()
        method, target, version, headers = proxy.validate_raw_request(raw)
        self.assertEqual((method, target, version), ("GET", "/health.php", "HTTP/1.1"))
        self.assertEqual(headers, [("Host", "192.168.10.55")])

    def test_absolute_form_requires_matching_host(self):
        raw = request(b"http://192.168.10.55/health.php")
        proxy.validate_raw_request(raw)
        with self.assertRaisesRegex(ValueError, "disagree"):
            proxy.validate_raw_request(request(b"http://192.168.10.55/health.php", ((b"Host", b"example.invalid"),)))

    def test_external_destinations_are_refused(self):
        for host in (b"example.invalid", b"192.168.10.55.example.invalid", b"192.168.10.55:8080", b"user@192.168.10.55", b"192.168.10.55/path"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                proxy.validate_raw_request(request(headers=((b"Host", host),)))

    def test_content_length_must_match_actual_bytes(self):
        raw = request(headers=((b"Host", b"192.168.10.55"), (b"Content-Length", b"3")), body=b"abc")
        proxy.validate_raw_request(raw)
        with self.assertRaisesRegex(ValueError, "was not sent"):
            proxy.validate_raw_request(raw[:-1])

    def test_ambiguous_framing_is_refused(self):
        raw = request(headers=((b"Host", b"192.168.10.55"), (b"Content-Length", b"0"), (b"Transfer-Encoding", b"chunked")))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            proxy.validate_raw_request(raw)

    def test_chunked_body_must_be_complete(self):
        headers = ((b"Host", b"192.168.10.55"), (b"Transfer-Encoding", b"chunked"))
        proxy.validate_raw_request(request(headers=headers, body=b"3\r\nabc\r\n0\r\n\r\n"))
        for body in (b"3\r\nabcXX0\r\n\r\n", b"3\r\nabc\r\n0\r\n\r\nextra", b"Z\r\n"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                proxy.validate_raw_request(request(headers=headers, body=body))

    def test_malformed_tokens_and_folded_headers_are_refused(self):
        malformed = [
            b"GE T / HTTP/1.1\r\nHost: 192.168.10.55\r\n\r\n",
            b"GET / HTTP/1.evil\r\nHost: 192.168.10.55\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: 192.168.10.55\r\n Folded: no\r\n\r\n",
            b"GET / HTTP/1.1\r\nBad\x00Name: value\r\nHost: 192.168.10.55\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: 192.168.10.55\r\nX-Test: bad\x00value\r\n\r\n",
        ]
        for raw in malformed:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                proxy.validate_raw_request(raw)


class HarnessHonestyTests(unittest.TestCase):
    def test_saved_observation_never_claims_rce(self):
        with tempfile.TemporaryDirectory() as home:
            previous = os.environ.get("HOME")
            os.environ["HOME"] = home
            try:
                path = harness.save_evidence("test", "ordinary request", b"HTTP/1.1 500 Internal Server Error\r\n\r\n", 12)
                with open(path) as handle:
                    evidence = json.load(handle)
            finally:
                if previous is None:
                    os.environ.pop("HOME", None)
                else:
                    os.environ["HOME"] = previous
        self.assertFalse(evidence["rce_claimed"])
        self.assertEqual(evidence["response_bytes"], len(b"HTTP/1.1 500 Internal Server Error\r\n\r\n"))
        self.assertIn("raw socket inside attacker guest", evidence["provenance"])


if __name__ == "__main__":
    unittest.main()
