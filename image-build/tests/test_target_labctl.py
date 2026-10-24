import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LABCTL = ROOT / "target" / "overlay" / "usr" / "local" / "bin" / "labctl"
WEBROOT = ROOT / "target" / "webroot"


def render(root, proof_owner=None, enforce_root=True, name="labctl"):
    """Copy labctl with its fixed target paths redirected into a temp root.

    The ownership checks are parameterised so the same validation logic can be
    exercised without creating an `apache` account on the test host. The real
    script's own `root:apache 0640` contract is asserted separately.
    """
    owner = proof_owner or os.environ.get("USER", "user")
    text = LABCTL.read_text()
    text = text.replace("/var/log/apache2", f"{root}/log")
    text = text.replace("/var/www/html", f"{root}/webroot")
    text = text.replace("/run/cyber-range", f"{root}/run")
    text = text.replace("/usr/local/bin/php", "/bin/false")
    text = text.replace('chown root:apache "$FLAG"', 'chown "$(id -u):$(id -g)" "$FLAG"')
    text = text.replace('[ "$owner" = apache ]', '[ "$owner" = "${LAB_PROOF_OWNER:-$(id -un)}" ]')
    if not enforce_root:
        # Exercising the generation logic itself, which runs as the target's boot
        # control context. The real guard is asserted by its own test and by
        # StaticContractTests.
        text = text.replace(
            """[ "$(id -u)" = 0 ] || { echo 'provision requires the boot control context' >&2; exit 1; }""",
            "true",
        )
        text = text.replace("""[ "$(id -u)" = 0 ] || { echo 'seal requires root' >&2; exit 1; }""", "true")
    script = pathlib.Path(root) / name
    script.write_text(text)
    script.chmod(0o755)
    for directory in (f"{root}/log", f"{root}/webroot", f"{root}/run"):
        pathlib.Path(directory).mkdir(parents=True, exist_ok=True)
    return script


def run(script, *args, env=None):
    merged = dict(os.environ)
    merged.update(env or {})
    return subprocess.run(["sh", str(script), *args], capture_output=True, text=True, env=merged, timeout=60)


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="labctl-provision-")
        self.script = render(self.root, enforce_root=False)
        self.guarded = render(self.root, enforce_root=True, name="labctl-guarded")
        self.flag = pathlib.Path(self.root) / "webroot" / "flag.txt"
        self.challenge = pathlib.Path(self.root) / "run" / "challenge"

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def provision(self, challenge="session-challenge-0123456789"):
        result = run(self.script, "provision", challenge)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return result

    @unittest.skipIf(os.geteuid() == 0, "the non-root refusal is only observable as an unprivileged user")
    def test_provision_refuses_an_unprivileged_caller(self):
        result = run(self.guarded, "provision", "session-challenge-0123456789")
        self.assertEqual(result.returncode, 1)
        self.assertIn("boot control context", result.stderr)
        self.assertFalse(self.flag.exists())

    @unittest.skipIf(os.geteuid() != 0, "raising privileges is only possible as root")
    def test_provision_generates_inside_the_target(self):
        self.provision()

    def test_flag_is_generated_in_the_guest_and_only_its_digest_is_printed(self):
        result = self.provision()
        flag = self.flag.read_text().strip()
        self.assertRegex(flag, r"^RANGE\{[0-9a-f]{48}\}$")
        digest = hashlib.sha256(flag.encode()).hexdigest()
        self.assertIn(f"CYBER_RANGE_FLAG_PROVISIONED sha256={digest}", result.stdout)
        self.assertNotIn(flag, result.stdout)
        self.assertEqual(oct(self.flag.stat().st_mode & 0o777), "0o640")
        self.assertEqual(oct(self.challenge.stat().st_mode & 0o777), "0o600")
        self.assertEqual(self.challenge.read_text(), "session-challenge-0123456789")
        self.assertTrue((pathlib.Path(self.root) / "run" / "provisioned").exists())
        self.assertTrue((pathlib.Path(self.root) / "run" / "session-start").exists())

    def test_reset_generates_a_new_flag_and_removes_the_old_proof(self):
        self.provision()
        first = self.flag.read_text().strip()
        digest_first = hashlib.sha256(first.encode()).hexdigest()
        proof = pathlib.Path(self.root) / "webroot" / "rce-proof.txt"
        proof.write_text("old-challenge")
        time.sleep(1.1)
        second = self.provision("session-challenge-abcdefghijkl")
        rotated = self.flag.read_text().strip()
        self.assertNotEqual(first, rotated)
        self.assertNotEqual(digest_first, hashlib.sha256(rotated.encode()).hexdigest())
        self.assertFalse(proof.exists())
        self.assertIn("CYBER_RANGE_FLAG_PROVISIONED", second.stdout)

    def test_unsafe_challenge_characters_are_refused(self):
        for challenge in ("session-challenge-with spaces", "session-challenge-\"quote", "session-challenge-$(id)"):
            with self.subTest(challenge=challenge):
                result = run(self.script, "provision", challenge)
                self.assertNotEqual(result.returncode, 0)

    def test_short_or_long_challenges_are_refused(self):
        for challenge in ("short", "x" * 129):
            with self.subTest(length=len(challenge)):
                result = run(self.script, "provision", challenge)
                self.assertEqual(result.returncode, 2)
                self.assertIn("invalid provisioning challenge", result.stdout + result.stderr)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="labctl-evidence-")
        self.proof = pathlib.Path(self.root) / "webroot" / "rce-proof.txt"
        self.run_dir = pathlib.Path(self.root) / "run"
        self.script = render(self.root, proof_owner=os.environ.get("USER", "user"))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def seed_session(self, started=1000):
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "session-start").write_text(f"{started}\n")

    def test_absent_proof_is_not_evidence(self):
        self.seed_session()
        result = run(self.script, "evidence", "session-challenge-0123456789")
        self.assertEqual(result.returncode, 1)
        self.assertIn('"rce_evidence":false', result.stdout)
        self.assertIn("proof file absent", result.stdout)

    def test_wrong_content_is_rejected(self):
        self.seed_session()
        self.proof.write_text("a different challenge\n")
        result = run(self.script, "evidence", "session-challenge-0123456789")
        self.assertEqual(result.returncode, 1)
        self.assertIn('"challenge_match":false', result.stdout)
        self.assertIn('"rce_evidence":false', result.stdout)

    def test_wrong_owner_is_rejected(self):
        self.seed_session()
        self.proof.write_text("session-challenge-0123456789")
        result = run(self.script, "evidence", "session-challenge-0123456789", env={"LAB_PROOF_OWNER": "someone-else"})
        self.assertEqual(result.returncode, 1)
        self.assertIn('"rce_evidence":false', result.stdout)

    def test_stale_proof_from_before_this_session_is_rejected(self):
        self.seed_session(started=int(time.time()) + 60)
        self.proof.write_text("session-challenge-0123456789")
        result = run(self.script, "evidence", "session-challenge-0123456789")
        self.assertEqual(result.returncode, 1)
        self.assertIn('"rce_evidence":false', result.stdout)

    def test_matching_apache_owned_proof_is_the_only_accepted_evidence(self):
        self.seed_session(started=1000)
        self.proof.write_text("session-challenge-0123456789")
        future = time.time() + 10
        os.utime(self.proof, (future, future))
        result = run(
            self.script,
            "evidence",
            "session-challenge-0123456789",
            env={"LAB_PROOF_OWNER": os.environ.get("USER", "user")},
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('"rce_evidence":true', result.stdout)
        self.assertIn('"challenge_match":true', result.stdout)
        self.assertIn('"owner":"', result.stdout)

    def test_invalid_challenge_arguments_are_refused(self):
        self.seed_session()
        self.assertEqual(run(self.script, "evidence", "short").returncode, 2)
        self.assertEqual(run(self.script, "evidence").returncode, 2)


class StaticContractTests(unittest.TestCase):
    def test_target_generates_and_never_receives_plaintext_flag(self):
        text = LABCTL.read_text()
        self.assertIn("od -An -N24 -tx1 /dev/urandom", text)
        self.assertIn('chown root:apache "$FLAG"; chmod 0640 "$FLAG"', text)
        self.assertIn("sha256sum", text)
        self.assertNotRegex(text, r"RANGE\{[0-9a-f]{48}\}")

    def test_provision_and_seal_require_root(self):
        text = LABCTL.read_text()
        provision = text[text.index("  provision)"):text.index("  seal)")]
        seal = text[text.index("  seal)"):text.index("  echo 'usage: labctl ready|telemetry")]
        self.assertIn('[ "$(id -u)" = 0 ]', provision)
        self.assertIn('[ "$(id -u)" = 0 ]', seal)

    def test_web_application_cannot_execute_commands_or_emulate_a_shell(self):
        for path in sorted(WEBROOT.glob("*.php")):
            source = path.read_text()
            with self.subTest(path=path.name):
                self.assertNotRegex(source, r"\b(?:system|exec|shell_exec|passthru|popen|proc_open|eval)\s*\(")
                self.assertNotIn("rce-proof", source)
                self.assertNotIn("RANGE{", source)

    def test_flag_route_is_denied_by_the_apache_configuration(self):
        config = (ROOT / "target" / "90-cyber-range.conf").read_text()
        self.assertIn('<Files "flag.txt">', config)
        self.assertIn("Require all denied", config)

    def test_build_info_keeps_the_unverified_reproduction_label(self):
        dockerfile = (ROOT / "target" / "Dockerfile").read_text()
        self.assertIn("cve_reproduction_status=unverified-for-this-32-bit-build", dockerfile)


if __name__ == "__main__":
    unittest.main()
