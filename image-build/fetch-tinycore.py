#!/usr/bin/env python3
"""Resolve and checksum an offline TinyCore package set during image build."""
import hashlib
import pathlib
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
DEST = ROOT / "image-build" / "downloads" / "tinycore-packages"
REPOS = [
    "https://distro.ibiblio.org/tinycorelinux/11.x/x86/tcz/",
    "http://tinycorelinux.net/11.x/x86/tcz/",
]
PACKAGES = ["python3.6.tcz", "curl.tcz", "dillo.tcz", "iproute2.tcz", "nano.tcz"]


def fetch(url, path):
    last = None
    for attempt in range(4):
        try:
            with urllib.request.urlopen(url, timeout=60) as response, open(path, "wb") as output:
                while True:
                    block = response.read(1024 * 1024)
                    if not block:
                        break
                    output.write(block)
            return
        except Exception as exc:
            last = exc
            time.sleep(attempt + 1)
    raise last


def get(name, suffix=""):
    for repo in REPOS:
        try:
            target = DEST / (name + suffix)
            fetch(repo + name + suffix, target)
            return target
        except Exception:
            continue
    if suffix:
        return None
    raise RuntimeError("Unable to download required TinyCore package " + name)


def resolve():
    ordered = []
    seen = set()

    def visit(name):
        if name in seen:
            return
        seen.add(name)
        dep_file = get(name, ".dep")
        if dep_file:
            for line in dep_file.read_text().splitlines():
                dep = line.strip()
                if dep.endswith(".tcz") and "KERNEL" not in dep.upper():
                    visit(dep)
        ordered.append(name)

    for package in PACKAGES:
        visit(package)
    return ordered


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    packages = resolve()
    sums = []
    for package in packages:
        path = get(package)
        expected_file = get(package, ".md5.txt")
        if expected_file:
            expected = expected_file.read_text().split()[0]
            actual = hashlib.md5(path.read_bytes()).hexdigest()
            if actual.lower() != expected.lower():
                raise RuntimeError("TinyCore publisher MD5 mismatch for " + package)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        sums.append("%s  %s" % (digest, package))
        print(package, digest)
    (DEST / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    (DEST / "onboot-packages.lst").write_text("\n".join(packages) + "\n")
    print("Resolved %d offline packages" % len(packages))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("ERROR:", exc, file=sys.stderr)
        sys.exit(1)
