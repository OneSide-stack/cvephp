#!/usr/bin/env python3
"""RangeProxy: a small, honest HTTP training proxy for the isolated guest LAN.

Python 3.6+ standard library only. This is not Burp Suite. It accepts only
plain HTTP destined for the lab target and never provides Internet egress.
"""
from __future__ import print_function

import base64
import json
import os
import socket
import socketserver
import sys
import threading
import time
import traceback
import uuid
from datetime import datetime
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

TARGET_HOST = "192.168.10.55"
TARGET_PORT = 80
PROXY_PORT = 8080
MANAGEMENT_PORT = 8081
MAX_HEADERS = 64 * 1024
MAX_BODY = 32 * 1024 * 1024
MAX_RESPONSE = 64 * 1024 * 1024
MAX_EDITOR = 4 * 1024 * 1024
INTERCEPT_TIMEOUT = 180
EVIDENCE_DIR = os.path.expanduser(os.environ.get("RANGE_EVIDENCE_DIR", "~/lab-evidence"))
EVIDENCE_FILE = os.path.join(EVIDENCE_DIR, "requests.jsonl")
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}


def utcnow():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def html_escape(value):
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def b64(data):
    return base64.b64encode(data).decode("ascii")


def recv_exact(sock, length):
    chunks = []
    remaining = length
    while remaining:
        chunk = sock.recv(min(remaining, 1024 * 1024))
        if not chunk:
            raise ValueError("incomplete request body: peer closed with %d bytes remaining" % remaining)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def read_head(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            raise ValueError("connection closed before complete HTTP headers")
        data.extend(chunk)
        if len(data) > MAX_HEADERS:
            raise ValueError("HTTP headers exceed 64 KiB")
    # This proxy handles one request per connection. Anything after the head is
    # retained by the socket only when it arrived in the same recv; prepend it.
    boundary = data.index(b"\r\n\r\n") + 4
    return bytes(data[:boundary]), bytes(data[boundary:])


class BufferedSocket(object):
    def __init__(self, sock, initial=b""):
        self.sock = sock
        self.buffer = bytearray(initial)

    def read(self, length):
        while len(self.buffer) < length:
            chunk = self.sock.recv(min(1024 * 1024, length - len(self.buffer) + 8192))
            if not chunk:
                break
            self.buffer.extend(chunk)
        result = bytes(self.buffer[:length])
        del self.buffer[:length]
        return result

    def readline(self, limit=8192):
        while b"\r\n" not in self.buffer:
            if len(self.buffer) > limit:
                raise ValueError("overlong HTTP line")
            chunk = self.sock.recv(8192)
            if not chunk:
                break
            self.buffer.extend(chunk)
        index = self.buffer.find(b"\r\n")
        if index < 0:
            result = bytes(self.buffer)
            self.buffer.clear()
            return result
        result = bytes(self.buffer[:index + 2])
        del self.buffer[:index + 2]
        return result


def parse_headers(head):
    lines = head[:-4].split(b"\r\n")
    if not lines or lines[0].count(b" ") != 2:
        raise ValueError("malformed HTTP request line")
    try:
        method, target, version = lines[0].decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError):
        raise ValueError("request line must be ASCII: METHOD target HTTP/version")
    if not method or not version.startswith("HTTP/1."):
        raise ValueError("unsupported HTTP request line")
    headers = []
    for line in lines[1:]:
        if not line or line[:1] in (b" ", b"\t") or b":" not in line:
            raise ValueError("malformed or folded HTTP header")
        name, value = line.split(b":", 1)
        if not name or name.strip() != name:
            raise ValueError("invalid HTTP header name whitespace")
        try:
            headers.append((name.decode("ascii"), value.strip().decode("latin-1")))
        except UnicodeDecodeError:
            raise ValueError("non-ASCII HTTP header name")
    return method, target, version, headers


def header_values(headers, name):
    return [value for key, value in headers if key.lower() == name.lower()]


def validate_target(target, headers):
    values = header_values(headers, "host")
    if len(values) != 1:
        raise ValueError("exactly one Host header is required")
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlsplit(target)
        if parsed.scheme != "http":
            raise ValueError("only plain HTTP is supported; CONNECT/TLS is disabled")
        host = parsed.hostname
        port = parsed.port or 80
    else:
        if not target.startswith("/"):
            raise ValueError("only origin-form or absolute HTTP request targets are supported")
        host_header = values[0]
        parsed = urlsplit("http://" + host_header)
        host = parsed.hostname
        port = parsed.port or 80
    if host != TARGET_HOST or port != TARGET_PORT:
        raise ValueError("destination refused: this proxy is confined to %s:%d" % (TARGET_HOST, TARGET_PORT))


def validate_chunked(body):
    offset = 0
    while True:
        end = body.find(b"\r\n", offset)
        if end < 0:
            raise ValueError("incomplete chunk-size line")
        size_text = body[offset:end].split(b";", 1)[0]
        try:
            size = int(size_text, 16)
        except ValueError:
            raise ValueError("invalid chunk size")
        if size < 0:
            raise ValueError("negative chunk size")
        offset = end + 2
        if size == 0:
            # Zero chunk is followed by zero or more trailer lines and a final
            # blank line. An empty trailer section is just CRLF.
            while True:
                end = body.find(b"\r\n", offset)
                if end < 0:
                    raise ValueError("incomplete chunked trailer")
                line = body[offset:end]
                offset = end + 2
                if not line:
                    if offset != len(body):
                        raise ValueError("bytes follow the final chunk")
                    return
                if b":" not in line:
                    raise ValueError("malformed chunked trailer")
        if offset + size + 2 > len(body):
            raise ValueError("incomplete chunk data")
        offset += size
        if body[offset:offset + 2] != b"\r\n":
            raise ValueError("chunk data is not followed by CRLF")
        offset += 2


def validate_raw_request(raw):
    if len(raw) > MAX_EDITOR:
        raise ValueError("edited request exceeds the 4 MiB repeater limit")
    if b"\r\n\r\n" not in raw:
        raise ValueError("request must contain a CRLFCRLF header terminator")
    head, body = raw.split(b"\r\n\r\n", 1)
    head += b"\r\n\r\n"
    method, target, version, headers = parse_headers(head)
    validate_target(target, headers)
    transfer = header_values(headers, "transfer-encoding")
    lengths = header_values(headers, "content-length")
    if transfer and lengths:
        raise ValueError("ambiguous framing: both Transfer-Encoding and Content-Length")
    if transfer:
        if len(transfer) != 1 or transfer[0].lower().strip() != "chunked":
            raise ValueError("only a single chunked Transfer-Encoding is supported")
        validate_chunked(body)
    elif lengths:
        if len(lengths) != 1 or not lengths[0].isdigit():
            raise ValueError("Content-Length must appear once as a non-negative decimal")
        declared = int(lengths[0])
        if declared != len(body):
            raise ValueError("Content-Length is %d but editor contains %d body bytes; request was not sent" % (declared, len(body)))
    elif body:
        raise ValueError("body supplied without Content-Length or chunked framing")
    return method, target, version, headers


def read_client_request(sock):
    head, initial = read_head(sock)
    method, target, version, headers = parse_headers(head)
    validate_target(target, headers)
    stream = BufferedSocket(sock, initial)
    transfer = header_values(headers, "transfer-encoding")
    lengths = header_values(headers, "content-length")
    if transfer and lengths:
        raise ValueError("ambiguous request framing")
    if transfer:
        if len(transfer) != 1 or transfer[0].lower().strip() != "chunked":
            raise ValueError("unsupported Transfer-Encoding")
        body = bytearray()
        while True:
            line = stream.readline()
            body.extend(line)
            try:
                size = int(line.strip().split(b";", 1)[0], 16)
            except ValueError:
                raise ValueError("invalid chunk size")
            if size == 0:
                while True:
                    trailer = stream.readline()
                    body.extend(trailer)
                    if trailer == b"\r\n":
                        break
                break
            data = stream.read(size + 2)
            if len(data) != size + 2:
                raise ValueError("incomplete chunk data")
            body.extend(data)
            if len(body) > MAX_BODY:
                raise ValueError("request body exceeds proxy's 32 MiB intercept limit; use the guest research harness for streamed tests")
        body = bytes(body)
    elif lengths:
        if len(lengths) != 1 or not lengths[0].isdigit():
            raise ValueError("invalid Content-Length")
        length = int(lengths[0])
        if length > MAX_BODY:
            raise ValueError("request body exceeds proxy's 32 MiB intercept limit; use the guest research harness for streamed tests")
        body = stream.read(length)
        if len(body) != length:
            raise ValueError("incomplete request body")
    else:
        body = b""
        if initial:
            raise ValueError("unexpected bytes after a bodyless request")
    raw = head + body
    validate_raw_request(raw)
    return raw


def forward_request(raw):
    method, target, version, headers = validate_raw_request(raw)
    started = time.time()
    sock = socket.create_connection((TARGET_HOST, TARGET_PORT), 20)
    sock.settimeout(45)
    try:
        sock.sendall(raw)
        response = HTTPResponse(sock, method=method)
        response.begin()
        body = response.read(MAX_RESPONSE + 1)
        if len(body) > MAX_RESPONSE:
            raise ValueError("target response exceeds 64 MiB safety limit")
        response_headers = [(key, value) for key, value in response.getheaders() if key.lower() not in HOP_HEADERS and key.lower() != "content-length"]
        reason = response.reason or ""
        status_line = "HTTP/1.1 %d %s\r\n" % (response.status, reason)
        wire = bytearray(status_line.encode("latin-1"))
        for key, value in response_headers:
            wire.extend(("%s: %s\r\n" % (key, value)).encode("latin-1"))
        wire.extend(("Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)).encode("ascii"))
        wire.extend(body)
        evidence = {
            "status": response.status,
            "reason": reason,
            "headers": response.getheaders(),
            "body_base64": b64(body[:256 * 1024]),
            "body_bytes": len(body),
            "truncated_in_preview": len(body) > 256 * 1024,
            "elapsed_ms": int((time.time() - started) * 1000),
        }
        return bytes(wire), evidence
    finally:
        sock.close()


class Evidence(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.counter = 0
        if not os.path.isdir(EVIDENCE_DIR):
            os.makedirs(EVIDENCE_DIR)

    def record(self, kind, request_id, raw_request, response=None, error=None, source="browser"):
        with self.lock:
            self.counter += 1
            item = {
                "sequence": self.counter,
                "timestamp": utcnow(),
                "kind": kind,
                "id": request_id,
                "source": source,
                "request_base64": b64(raw_request),
                "request_bytes": len(raw_request),
                "response": response,
                "error": error,
                "provenance": "RangeProxy inside attacker guest",
            }
            line = json.dumps(item, sort_keys=True) + "\n"
            with open(EVIDENCE_FILE, "a") as handle:
                handle.write(line)
            return item


class HeldRequest(object):
    def __init__(self, request_id, raw):
        self.id = request_id
        self.raw = raw
        self.created = utcnow()
        self.event = threading.Event()
        self.response = None
        self.error = None


class ProxyState(object):
    def __init__(self):
        self.intercept = True
        self.lock = threading.Lock()
        self.held = {}
        self.last_result = None
        self.evidence = Evidence()

    def snapshot(self):
        with self.lock:
            return {
                "intercept": self.intercept,
                "pending": [{"id": item.id, "created": item.created, "bytes": len(item.raw), "request_line": item.raw.split(b"\r\n", 1)[0].decode("latin-1")} for item in self.held.values()],
                "requests_recorded": self.evidence.counter,
                "target": "http://%s:%d" % (TARGET_HOST, TARGET_PORT),
            }

    def process(self, raw, source):
        request_id = uuid.uuid4().hex[:12]
        with self.lock:
            should_hold = self.intercept
            if should_hold:
                held = HeldRequest(request_id, raw)
                self.held[request_id] = held
        if not should_hold:
            try:
                wire, response = forward_request(raw)
                self.evidence.record("forwarded", request_id, raw, response=response, source=source)
                return wire
            except Exception as exc:
                self.evidence.record("error", request_id, raw, error=str(exc), source=source)
                raise
        try:
            if not held.event.wait(INTERCEPT_TIMEOUT):
                with self.lock:
                    self.held.pop(request_id, None)
                self.evidence.record("intercept-timeout", request_id, raw, error="operator did not forward within 180 seconds", source=source)
                raise ValueError("intercept timed out after 180 seconds")
            if held.error:
                raise ValueError(held.error)
            return held.response
        finally:
            with self.lock:
                self.held.pop(request_id, None)

    def forward_held(self, request_id, raw, source="intercept"):
        with self.lock:
            held = self.held.get(request_id)
        if not held:
            raise ValueError("intercept no longer exists (it may have timed out)")
        try:
            wire, response = forward_request(raw)
            item = self.evidence.record("intercept-forwarded", request_id, raw, response=response, source=source)
            held.response = wire
            self.last_result = item
            return item
        except Exception as exc:
            held.error = str(exc)
            self.evidence.record("intercept-error", request_id, raw, error=str(exc), source=source)
            raise
        finally:
            held.event.set()


STATE = ProxyState()


def error_response(status, message):
    body = ("RangeProxy: %s\n" % message).encode("utf-8", "replace")
    reasons = {400: "Bad Request", 403: "Forbidden", 413: "Payload Too Large", 502: "Bad Gateway", 504: "Gateway Timeout"}
    head = "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (status, reasons.get(status, "Error"), len(body))
    return head.encode("ascii") + body


class ProxyTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)
        try:
            raw = read_client_request(self.request)
            wire = STATE.process(raw, "browser-proxy")
            self.request.sendall(wire)
        except Exception as exc:
            try:
                self.request.sendall(error_response(502, str(exc)))
            except Exception:
                pass


def layout(title, content):
    return """<!doctype html><html><head><meta charset=utf-8><title>%s</title>
<style>body{font-family:sans-serif;background:#101820;color:#e5edf3;margin:24px;line-height:1.4}a{color:#62d9c5}h1{font-size:24px}h2{font-size:18px;border-bottom:1px solid #38505d;padding-bottom:6px}table{border-collapse:collapse;width:100%%}td,th{padding:7px;border-bottom:1px solid #38505d;text-align:left}textarea{width:100%%;font-family:monospace;background:#081016;color:#e5edf3;border:1px solid #557080;padding:10px}input,button{font-size:14px;padding:7px;margin:3px 0}button{background:#2a756b;color:white;border:0}pre{white-space:pre-wrap;background:#081016;padding:12px;border:1px solid #38505d}.note{border-left:4px solid #e5a653;padding:8px;background:#242a2d}.ok{color:#72d6a0}.bad{color:#ff8b8b}</style></head><body>%s</body></html>""" % (html_escape(title), content)


class ManagementHandler(BaseHTTPRequestHandler):
    server_version = "RangeProxyManagement/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("management: " + fmt % args + "\n")

    def send_html(self, content, status=200):
        data = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, value):
        data = json.dumps(value, sort_keys=True).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def form(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("invalid management Content-Length")
        if length > MAX_EDITOR * 2:
            raise ValueError("management form too large")
        data = self.rfile.read(length)
        if len(data) != length:
            raise ValueError("incomplete management form")
        return parse_qs(data.decode("utf-8"), keep_blank_values=True)

    def do_GET(self):
        if self.path == "/api/state":
            self.send_json(STATE.snapshot())
            return
        if self.path.startswith("/request?"):
            query = parse_qs(urlsplit(self.path).query)
            request_id = query.get("id", [""])[0]
            with STATE.lock:
                held = STATE.held.get(request_id)
            if not held:
                self.send_html(layout("Intercept expired", "<h1>Intercept expired</h1><p><a href='/'>Return</a></p>"), 404)
                return
            content = "<h1>Held request %s</h1><p>Edit the actual HTTP message. Content-Length and chunk framing are checked before anything is sent.</p><form method=post action='/forward'><input type=hidden name=id value='%s'><textarea name=raw rows=24>%s</textarea><br><button type=submit>Forward to real target</button></form><form method=post action='/drop'><input type=hidden name=id value='%s'><button type=submit>Drop request</button></form>" % (request_id, request_id, html_escape(held.raw.decode("latin-1")), request_id)
            self.send_html(layout("Edit intercept", content))
            return
        state = STATE.snapshot()
        rows = "".join("<tr><td><a href='/request?id=%s'>%s</a></td><td>%s</td><td>%d</td></tr>" % (item["id"], html_escape(item["request_line"]), item["created"], item["bytes"]) for item in state["pending"])
        if not rows:
            rows = "<tr><td colspan=3>No paused requests. Enable interception, then browse to the target in another Dillo window.</td></tr>"
        default = "GET /health.php HTTP/1.1\r\nHost: 192.168.10.55\r\nUser-Agent: RangeRepeater/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        result = ""
        if STATE.last_result:
            item = STATE.last_result
            response = item.get("response") or {}
            body = base64.b64decode(response.get("body_base64", "")).decode("utf-8", "replace")
            result = "<h2>Last real target response</h2><p>Status <b>%s</b> · %s bytes · %s ms</p><pre>%s</pre>" % (response.get("status"), response.get("body_bytes"), response.get("elapsed_ms"), html_escape(body))
        content = """<h1>RangeProxy <small>guest training proxy</small></h1>
<p class=note>Running in the attacker guest. Not Burp Suite. Forwarding is restricted to <b>192.168.10.55:80</b>; TLS and Internet egress are disabled.</p>
<p>Management: <b>127.0.0.1:8081</b> · Proxy for Dillo/curl: <b>127.0.0.1:8080</b> · Evidence: <b>~/lab-evidence/requests.jsonl</b></p>
<h2>Intercept</h2><p>Interception is <b>%s</b>. %d request(s) recorded.</p>
<form method=post action='/toggle'><button type=submit>%s interception</button></form>
<table><tr><th>Request</th><th>Paused at</th><th>Bytes</th></tr>%s</table>
<h2>Repeater</h2><p>Compose one raw HTTP/1.1 request. It is sent through a real attacker-guest TCP socket to the target. Ambiguous or mismatched framing is rejected, not repaired silently.</p>
<form method=post action='/repeater'><textarea name=raw rows=14>%s</textarea><br><button type=submit>Send real request</button></form>%s
<p><a href='/'>Refresh</a></p>""" % ("ON" if state["intercept"] else "OFF", state["requests_recorded"], "Disable" if state["intercept"] else "Enable", rows, html_escape(default), result)
        self.send_html(layout("RangeProxy", content))

    def do_POST(self):
        try:
            form = self.form()
            if self.path == "/toggle":
                with STATE.lock:
                    STATE.intercept = not STATE.intercept
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            if self.path == "/drop":
                request_id = form.get("id", [""])[0]
                with STATE.lock:
                    held = STATE.held.get(request_id)
                if held:
                    held.error = "dropped by operator"
                    held.event.set()
                    STATE.evidence.record("intercept-dropped", request_id, held.raw, error="dropped by operator")
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
                return
            if self.path in ("/forward", "/repeater"):
                raw = form.get("raw", [""])[0].encode("latin-1")
                if self.path == "/forward":
                    request_id = form.get("id", [""])[0]
                    item = STATE.forward_held(request_id, raw)
                else:
                    request_id = uuid.uuid4().hex[:12]
                    wire, response = forward_request(raw)
                    item = STATE.evidence.record("repeater", request_id, raw, response=response, source="repeater")
                    del wire
                STATE.last_result = item
                body = base64.b64decode(item["response"]["body_base64"]).decode("utf-8", "replace")
                content = "<h1>Real target response</h1><p>Status <b>%d</b> · %d bytes · %d ms</p><h2>Response body</h2><pre>%s</pre><h2>Response headers</h2><pre>%s</pre><p><a href='/'>Back to RangeProxy</a></p>" % (item["response"]["status"], item["response"]["body_bytes"], item["response"]["elapsed_ms"], html_escape(body), html_escape("\n".join("%s: %s" % pair for pair in item["response"]["headers"])))
                self.send_html(layout("Target response", content))
                return
            self.send_html(layout("Not found", "<h1>Unknown action</h1>"), 404)
        except Exception as exc:
            self.send_html(layout("Request rejected", "<h1>Request was not sent</h1><p class=bad>%s</p><p><a href='/'>Back</a></p>" % html_escape(str(exc))), 400)


def main():
    print("RangeProxy evidence: %s" % EVIDENCE_FILE)
    proxy = ProxyTCPServer(("127.0.0.1", PROXY_PORT), ProxyHandler)
    management = socketserver.ThreadingMixIn()
    # Declared explicitly for Python 3.6, which predates ThreadingHTTPServer.
    class ManagementServer(socketserver.ThreadingMixIn, HTTPServer):
        allow_reuse_address = True
        daemon_threads = True
    management = ManagementServer(("127.0.0.1", MANAGEMENT_PORT), ManagementHandler)
    thread = threading.Thread(target=proxy.serve_forever)
    thread.daemon = True
    thread.start()
    print("RANGEPROXY_READY proxy=127.0.0.1:%d management=127.0.0.1:%d target=%s:%d" % (PROXY_PORT, MANAGEMENT_PORT, TARGET_HOST, TARGET_PORT))
    sys.stdout.flush()
    try:
        management.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        proxy.shutdown()
        management.server_close()
        proxy.server_close()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
