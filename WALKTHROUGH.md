# PHP2Shell — Full Walkthrough & Answer Key

> A TryHackMe / Hack The Box-style guided room for the **Nimbus Analytics**
> lab in this repository. You get the scenario, the tasks, hints, every command,
> the expected output, and a checked answer key — plus the report you should be
> able to write at the end.

| | |
|---|---|
| **Room** | PHP2Shell |
| **Target** | `http://127.0.0.1:8080` (loopback only) |
| **Difficulty** | Medium — Linux, Docker, PHP internals, vulnerability management |
| **Estimated time** | 90–120 minutes (tasks 1–10); 3–4 h with the capstone |
| **Prerequisites** | Docker, `curl`, `jq` (optional but recommended), `python3`, basic HTTP knowledge |
| **CVEs** | CVE-2026-109618 (OOM corruption), CVE-2026-109619 (stale global state) |
| **Win condition** | A defensible, evidence-backed patch finding — **not** a root shell |

> **Spoiler warning.** This is the solution guide. Every task has a hidden
> answer in a collapsible block, and the full answer key is at the end. If you
> are learning, read the task, try the command, write your answer in a
> worksheet, *then* open the spoiler.

**Contents:** [Room brief](#1-room-brief) ·
[Setup](#2-setup-do-this-once) · [Room map](#3-room-map) ·
[T1 verify](#task-1--start-and-verify-the-target) ·
[T2 recon](#task-2--black-box-recon-pretend-you-only-have-the-url) ·
[T3 fingerprint](#task-3--fingerprint-the-engine-black-box--white-box) ·
[T4 patch triage](#task-4--patch-triage-is-this-actually-vulnerable) ·
[T5 attack requirements](#task-5--read-the-attack-requirements-from-the-live-configuration) ·
[T6 baseline](#task-6--collect-a-defensible-baseline) ·
[T7 workers](#task-7--worker-lifecycle-and-same-worker-correlation) ·
[T8 OOM control](#task-8--bounded-oom-observe-the-engine-dont-over-claim) ·
[T9 report](#task-9--evidence-ladder-and-the-capstone-report) ·
[T10 detection](#task-10--detection-and-incident-hunt) ·
[T11 retest](#task-11--patch-and-retest) ·
[T12 teardown](#task-12--teardown) ·
[Answer key](#4-full-answer-key) ·
[Troubleshooting](#6-troubleshooting) ·
[Checklist](#10-completion-checklist)

---

## 1. Room brief

Nimbus Analytics runs a revenue dashboard on a single "VM-style" container:
`supervisord` (PID 1) starts `php-fpm` and `nginx`, nginx serves the dashboard on
`:80` and forwards `.php` requests to the FPM pool on `127.0.0.1:9000`. The
engine underneath is **PHP 8.4.26**, the last 8.4 release before the PHP2Shell
fixes.

Your job is *not* to pop a shell. Your job is to answer the question a client
actually pays for:

> "Are we exposed to CVE-2026-109618 / CVE-2026-109619, how do you know, and
> what exactly should we change?"

That means proving four things: **asset → patch status → reachability → evidence
tier**. Everything in this room builds toward the report in Task 9.

### Why this room has no "root.txt"

These are memory-corruption bugs in the PHP engine. Running random
memory-exhaustion payloads against a worker can crash it, leak another user's
request memory, or take the service down — and this repository deliberately
ships **no exploit**. A crash, an HTTP 500, an OOM error, or an OOM-killed
container is **not** proof of either CVE. This room therefore scores you on
evidence discipline, which is the actual senior-skill being tested:

| Tier | What you have | Honest claim |
|---|---|---|
| L0 | `.php` URL, `PHPSESSID`, `X-Powered-By` | "PHP is probably here" |
| L1 | version string / package below a fixed milestone | "Potentially affected — version match only" |
| L2 | L1 + web SAPI + patch status + attack requirements | "Likely exposed — unpatched engine, preconditions present" |
| L3 | L2 + sanitizer/debugger trace tied to the source revision + patched control | "Confirmed defect in this build" |
| L4 | L3 + a full demonstrated code-execution chain | "Confirmed RCE — isolated lab only" |

Most real engagements stop at **L2**, and L2 is enough to drive an emergency
patch. This room's normal completion is a clean **L2** finding. Task 9 and the
extra credit explain exactly what L3/L4 would additionally require.

### Rules of engagement

- Run the lab on **your own machine**, published on `127.0.0.1` only.
- Never expose this container to a LAN, the internet, or a cloud security group.
- Never point these commands at a host you do not own or have written permission
  to test.
- Do not download third-party PoCs for these CVEs. The vendor's own advice is to
  patch; a "quick check" can be destructive.
- Treat this as an isolated incident-response sandbox: no real credentials, no
  production data, delete it when you are done.

---

## 2. Setup (do this once)

### 2.1 Get the repo and pin the vulnerable build

```bash
git clone https://github.com/OneSide-stack/cvephp.git
cd cvephp

# Confirm the tag exists before building
docker manifest inspect php:8.4.26-fpm-alpine >/dev/null && echo "tag ok"

# Build context is php2shell-lab/; run every command in this room from the repo root
docker build -f php2shell-lab/Dockerfile \
  --build-arg PHP_IMAGE=php:8.4.26-fpm-alpine \
  -t php2shell-lab:8.4.26 php2shell-lab
```

If the tag is gone (old images get cleaned up), use any pre-patch 8.4/8.3 build
and pass it through `--build-arg`; record the substitution in your notes. Do
**not** invent a version string.

### 2.2 Run it as a "VM"

```bash
docker run -d --name php2shell-vm \
  --memory=256m --cpus=1 \
  -p 127.0.0.1:8080:80 \
  php2shell-lab:8.4.26
```

- `--memory=256m` matches the container to PHP's `memory_limit=256M`, so a
  runaway worker cannot eat your host. It also teaches the "container limit is
  not a security boundary" caveat from the advisory.
- `-p 127.0.0.1:8080:80` binds loopback only. If you write `-p 8080:80` Docker
  publishes on all interfaces — don't.
- Port busy? Change the host side (`-p 127.0.0.1:8081:80`) and set
  `BASE=http://127.0.0.1:8081` for the rest of the room.

### 2.3 Smoke test

```bash
BASE=http://127.0.0.1:8080

curl -s "$BASE/healthz"                                  # ok
curl -s "$BASE/index.php?api=ping" | jq .                # fingerprint
curl -sI "$BASE/" | head -n 12                            # headers
docker exec php2shell-vm supervisorctl status             # both daemons RUNNING
```

Expected ping (the `time` value changes):

```json
{
  "status": "ok",
  "service": "nimbus-analytics",
  "php": "8.4.26",
  "sapi": "fpm-fcgi",
  "time": "2026-10-25T12:00:00+00:00"
}
```

### 2.4 Open the in-app guide

The dashboard ships a five-tab **Solution** view. Deep links work:

- <http://127.0.0.1:8080/?view=lab> — Overview
- <http://127.0.0.1:8080/?view=lab&tab=cve618> — CVE-2026-109618
- <http://127.0.0.1:8080/?view=lab&tab=cve619> — CVE-2026-109619
- <http://127.0.0.1:8080/?view=lab&tab=verify> — Verify & Patch Test
- <http://127.0.0.1:8080/?view=lab&tab=field> — Real-World Hunt (10-step method)
- <http://127.0.0.1:8080/?view=runtime> — live `ini_get()` posture

### 2.5 Create an evidence directory

```bash
cd "$(git rev-parse --show-toplevel)"   # repo root
mkdir -p evidence
```

`evidence/` is already in `.gitignore`. Keep captures out of Git — they can
contain hostnames, paths, and configuration.

> **Checkpoint 0:** you have a running container, a JSON ping showing
> `8.4.26 / fpm-fcgi`, and two RUNNING daemons. If not, jump to
> [Troubleshooting](#6-troubleshooting) before continuing.

---

## 3. Room map

```
 Task 1  Start & verify .............. you are on the right service
 Task 2  Black-box recon ............. nginx :80 → FPM :9000
 Task 3  Fingerprint the engine ...... 8.4.26 / fpm-fcgi, CLI vs FPM
 Task 4  Patch triage ................ 8.4.27 / 8.5.12 are the fixes
 Task 5  Attack requirements ......... memory_limit, post_max_size, session, workers
 Task 6  Baseline evidence ........... collector + docker inspect, hashed
 Task 7  Worker lifecycle ............ prove same-PID vs recycling (619)
 Task 8  Bounded OOM control ......... what is NOT evidence
 Task 9  Evidence ladder + report .... L2, written like a professional
 Task 10 Detection & incident hunt ... what to grep, what it means
 Task 11 Patch & retest .............. close the finding with proof
 Task 12 Teardown .................... leave no vulnerable container behind
```

> **Shell note.** Unless a block says otherwise, run commands from the repository
> root. `BASE` is exported in Task 1; re-export it (and `BASE2` in Task 11) if
> you open a new terminal. Blocks assume the container names `php2shell-vm`
> (`:8080`) and `php2shell-patched` (`:8081`).

---

## Task 1 — Start and verify the target

**Goal:** prove the stack is healthy and learn the shape of the deployment.

```bash
BASE=http://127.0.0.1:8080

curl -s -o /dev/null -w 'healthz: %{http_code}\n' "$BASE/healthz"
curl -s -o /dev/null -w 'dashboard: %{http_code}\n' "$BASE/"
curl -s -o /dev/null -w 'ping: %{http_code}\n' "$BASE/index.php?api=ping"
curl -s -o /dev/null -w 'unknown api: %{http_code}\n' "$BASE/index.php?api=nope"

docker exec php2shell-vm supervisorctl status
```

Expected:

```text
healthz: 200
dashboard: 200
ping: 200
unknown api: 404
nginx                        RUNNING   pid 12, uptime 0:01:23
php-fpm                      RUNNING   pid 11, uptime 0:01:23
```

**Questions**

**Q1.** Which process is PID 1 inside the container?
**Q2.** Which two daemons are supervised, and which one starts first?
**Q3.** Which endpoint is served by nginx alone (no PHP involved), and why is
that distinction useful during triage?

<details>
<summary>Answers</summary>

**A1.** `supervisord` (the container command is
`/usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf`).
**A2.** `php-fpm` (priority 5) and `nginx` (priority 10) — FPM first so the
backend socket exists before the front door opens.
**A3.** `/healthz`, answered with `return 200 "ok\n";`. If `/healthz` works but
`?api=ping` fails, nginx is fine and the problem is the FPM pool/PHP engine.

</details>

✅ **Checkpoint 1:** four expected status codes and two RUNNING daemons.

---

## Task 2 — Black-box recon (pretend you only have the URL)

**Goal:** build the service map from the outside, exactly as you would on an
engagement, and notice what the deployment leaks.

### 2.1 Ports

```bash
nmap -sV -p 8080 127.0.0.1
```

Expected: one open port, `http`, `nginx`. There is nothing else to find — this
is a single-service box by design. That is itself a finding: **the attack
surface is the PHP runtime reached through nginx**, not a forgotten admin panel.

### 2.2 Headers

```bash
curl -sSI "$BASE/" | grep -iE '^(HTTP/|server|x-powered-by|x-content-type-options|x-frame-options|referrer-policy|set-cookie)'
```

Expected shape:

```text
HTTP/1.1 200 OK
Server: nginx/1.26.x
X-Powered-By: PHP/8.4.26
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
```

Three observations to write down:

1. `server_tokens` is left on — nginx advertises its version.
2. `X-Powered-By` advertises the PHP version because `expose_php=On`.
3. Security headers exist, which tells you the front door was "hardened" at the
   HTTP layer while the engine underneath was not patched. Classic real-world
   mismatch.

### 2.3 Endpoint behaviour

```bash
curl -s "$BASE/index.php?api=ping" | jq .
curl -s "$BASE/index.php?api=stats" | jq '.rps, .p95_ms, .status'
curl -s -i "$BASE/index.php?api=nope" | head -n 12
curl -s -i "$BASE/missing.php" | head -n 12
```

Expected body for the unknown API:

```json
{"error":"unknown endpoint","endpoint":"nope"}
```

`/missing.php` is more interesting:

```text
HTTP/1.1 404 Not Found
Content-Type: text/html; charset=UTF-8

File not found.
```

Why? The nginx location `~ \.php$` proxies **every** `.php` URL to FPM and sets
`SCRIPT_FILENAME $document_root$fastcgi_script_name` with no
`try_files $uri =404` existence guard. FPM then reports `Primary script
unknown` in its log. That is the historically bug-prone pattern the lab
replicates — **a configuration finding, not a vulnerability by itself**. Do not
turn this into an LFI fantasy; on this lab it only proves the proxy behaviour.

Check the FPM side:

```bash
docker logs php2shell-vm 2>&1 | tail -n 20
```

Expected (wording depends on the PHP build):

```text
[NOTICE] [pool www] child 24 said into stderr: "..." 
ERROR: Unable to open primary script: /var/www/html/missing.php (No such file or directory)
```

**Questions**

**Q4.** What web server and version does the target advertise?
**Q5.** Where does nginx send PHP requests?
**Q6.** Which response header leaks the PHP version, and which INI setting
controls it?
**Q7.** What does `/missing.php` prove about the nginx → FPM configuration?

<details>
<summary>Answers</summary>

**A4.** nginx, version visible in the `Server` header (e.g. `nginx/1.26.x`) —
`server_tokens` is on.
**A5.** `127.0.0.1:9000` via FastCGI (`upstream php-fpm-backend`).
**A6.** `X-Powered-By: PHP/8.4.26`; controlled by `expose_php`.
**A7.** Every `\.php$` request is proxied regardless of whether the file exists,
and `SCRIPT_FILENAME` is built from the document root without a
`try_files ... =404` guard. It confirms proxy behaviour and a hardening gap, not
code execution.

</details>

✅ **Checkpoint 2:** you can draw `client → nginx :80 → php-fpm :9000` and you
have three independent HTTP observations.

---

## Task 3 — Fingerprint the engine (black-box + white-box)

**Goal:** establish *which* PHP build answers web requests. A version banner is
L1 evidence; a version **plus the serving SAPI** is the foundation for
everything else.

### 3.1 Three signals

```bash
# 1. Lab's own fingerprint endpoint (authoritative for the web SAPI)
curl -s "$BASE/index.php?api=ping" | jq '{php, sapi, service}'

# 2. CLI build inside the same container — may differ from FPM
docker exec php2shell-vm php -v
docker exec php2shell-vm php -r 'echo PHP_VERSION, " ", PHP_SAPI, PHP_EOL;'

# 3. Which config is actually loaded
docker exec php2shell-vm php --ini
docker exec php2shell-vm php -i | grep -E '^(Server API|Loaded Configuration File|Scan this dir|Additional \.ini)'
```

Expected:

```json
{
  "php": "8.4.26",
  "sapi": "fpm-fcgi",
  "service": "nimbus-analytics"
}
```

```text
PHP 8.4.26 (cli) (built: ...)
8.4.26 cli
Configuration File (php.ini) Path: /usr/local/etc/php
Loaded Configuration File:         (none)
Scan for additional .ini files in: /usr/local/etc/php/conf.d
Additional .ini files parsed:      /usr/local/etc/php/conf.d/docker-php-ext-...,
                                   /usr/local/etc/php/conf.d/90-php2shell.ini
```

Notes for your report:

- Official PHP images ship **no active `php.ini`**; configuration lives in
  `conf.d/*.ini`. "I checked php.ini and it was fine" is meaningless here.
- `Server API` from `php -i` on the CLI says `cli`. You must read the web SAPI
  fingerprint over HTTP or run `php-fpm -i`; the CLI is a different process mode
  and does not exercise the FPM request lifecycle.
- `Zend Engine` and extensions are visible in the app's **Runtime Environment**
  view (`?view=runtime`).

### 3.2 Record the artefact identity

```bash
# Base image digest (what you actually built FROM)
docker image inspect php:8.4.26-fpm-alpine --format '{{index .RepoDigests 0}}'

# Local image ID (a locally built image has no RepoDigest of its own)
docker image inspect php2shell-lab:8.4.26 --format '{{.Id}}'

docker image ls --digests | grep -E 'php2shell|php +8\.4\.26'
```

Expected shape:

```text
php@sha256:............................................................
sha256:................................................................
php2shell-lab   8.4.26   ...   <none>   ...
```

**Q8.** What `php` and `sapi` values does the web endpoint report?
**Q9.** What SAPI does `docker exec ... php -r 'echo PHP_SAPI;'` report, and why
is it not enough?
**Q10.** Why does a locally built image show `<none>` under `DIGEST` in
`docker image ls --digests`, and what should you record instead?

<details>
<summary>Answers</summary>

**A8.** `8.4.26` and `fpm-fcgi`.
**A9.** `cli`. The CLI is a separate process mode; it cannot demonstrate
cross-request worker state or FPM's request start/shutdown behaviour.
**A10.** A local build is not pulled by digest, so it has no `RepoDigest`.
Record the base image digest **and** the local image ID (or push it to a private
registry and pin the resulting digest). A mutable tag is not evidence.

</details>

✅ **Checkpoint 3:** you can state "web SAPI = fpm-fcgi, engine = 8.4.26,
base digest = sha256:…" without looking at the README.

---

## Task 4 — Patch triage: is this actually vulnerable?

**Goal:** move from "old version" to "unpatched build", using primary sources.

### 4.1 Read the advisory ranges (not a blog)

With `gh` authenticated, or just `curl`:

```bash
gh api repos/php/php-src/security-advisories/GHSA-w8hw-w9fx-j79w \
  --jq '{cve:.cve_id,summary:.summary,vulns:[.vulnerabilities[]|{range:.vulnerable_version_range,fixed:.patched_versions}]}'

gh api repos/php/php-src/security-advisories/GHSA-6wmf-4rv5-p3rp \
  --jq '{cve:.cve_id,summary:.summary,vulns:[.vulnerabilities[]|{range:.vulnerable_version_range,fixed:.patched_versions}]}'

# No gh? The same data without authentication:
curl -s https://api.github.com/repos/php/php-src/security-advisories/GHSA-w8hw-w9fx-j79w \
  | jq '{cve:.cve_id, vulns:[.vulnerabilities[]|{range:.vulnerable_version_range,fixed:.patched_versions}]}'
curl -s https://api.github.com/repos/php/php-src/security-advisories/GHSA-6wmf-4rv5-p3rp \
  | jq '{cve:.cve_id, vulns:[.vulnerabilities[]|{range:.vulnerable_version_range,fixed:.patched_versions}]}'
```

Expected: four affected ranges per advisory, fixed in **8.2.35, 8.3.36,
8.4.27, 8.5.12**. Both advisories describe pre-auth RCE in the PHP engine, not
in this app.

Key facts to write into your notes:

| Fact | CVE-2026-109618 | CVE-2026-109619 |
|---|---|---|
| Class | OOM `longjmp` leaves request memory invalid; shutdown reads it | stale worker global points at freed request memory (UAF) |
| Demonstrated on | Apache `mod_php` (complete RCE) | `mod_php` **and FPM** session-upload-progress path |
| FPM status | source analysis says susceptible; **no complete FPM exploit demonstrated** | validated FPM path, needs a suitable app operation, a fatal error, and a later request on the same worker |
| Main config factor | finite `memory_limit`, multipart/post limits | `session.upload_progress.enabled`, `fatal_error_backtraces` (8.5), per-request INI, worker lifetime |
| Fix | 8.4.27 / 8.5.12 / 8.3.36 / 8.2.35 | same |

### 4.2 Decide for **this** build

| Observed | Verdict |
|---|---|
| `< 8.4.27`, no vendor backport | vulnerable build for both |
| Lower version + changelog shows the backport | patched — attach the changelog |
| 8.1 / 8.0 / 7.4 | no upstream binary fix; check LTS/source backport |
| `>= 8.4.27` | patched — still verify workers were restarted |

8.4.26 is one release below the 8.4 fix, and the image is built from upstream
`php-src`, so there is no distro backport to worry about. **Verdict: unpatched
for both CVEs.**

### 4.3 Build the patched control

You cannot prove a patch works without a control. Build the same Dockerfile
against the fixed release:

```bash
docker manifest inspect php:8.4.27-fpm-alpine >/dev/null \
  && echo "patched tag ok" \
  || echo "tag unavailable — use 8.5.12 and record the substitution"

docker build -f php2shell-lab/Dockerfile \
  --build-arg PHP_IMAGE=php:8.4.27-fpm-alpine \
  -t php2shell-lab:8.4.27 php2shell-lab

docker run -d --name php2shell-patched \
  --memory=256m --cpus=1 \
  -p 127.0.0.1:8081:80 \
  php2shell-lab:8.4.27
```

Verify the control:

```bash
curl -s http://127.0.0.1:8081/index.php?api=ping | jq '{php, sapi}'
# => { "php": "8.4.27", "sapi": "fpm-fcgi" }
```

This is the single most important habit in the room: **vulnerable vs patched,
identical topology and configuration.**

**Questions**

**Q11.** Which 8.4 and 8.5 releases contain the fix?
**Q12.** Which 8.2 and 8.3 releases contain the fix?
**Q13.** Which GHSA maps to which CVE?
**Q14.** For which CVE has PHP **not** demonstrated a complete FPM exploit?
**Q15.** Why does a version number alone never settle patch status?

<details>
<summary>Answers</summary>

**A11.** 8.4.27 and 8.5.12.
**A12.** 8.2.35 and 8.3.36.
**A13.** CVE-2026-109618 = GHSA-w8hw-w9fx-j79w; CVE-2026-109619 =
GHSA-6wmf-4rv5-p3rp.
**A14.** CVE-2026-109618 — FPM is susceptible by source analysis, but no
complete FPM exploit was demonstrated. (For 109619, the session-lifecycle RCE
was validated against both `mod_php` and FPM.)
**A15.** Distros backport fixes into lower version strings, containers can run a
stale worker after a package upgrade, and custom builds can differ from the
release. You must check the changelog/digest **and** that the new workers are
actually serving requests.

</details>

✅ **Checkpoint 4:** two containers running, two fingerprints, one decision:
8.4.26 unpatched, 8.4.27 patched.

---

## Task 5 — Read the attack requirements from the live configuration

**Goal:** turn the CVSS `AT:P` ("attack requirements present") into concrete,
observed config. This is where most beginners stop at a scanner screenshot;
here you produce the paragraph a client can act on.

### 5.1 Effective PHP configuration (web SAPI)

```bash
docker exec php2shell-vm php -i \
  | grep -E '^(memory_limit|post_max_size|upload_max_filesize|max_file_uploads|max_input_vars|max_input_nesting_level|session.upload_progress|log_errors|error_log|error_reporting|display_errors|display_startup_errors|max_execution_time|expose_php|cgi.fix_pathinfo|allow_url_include|disable_functions)' \
  | tee evidence/php-ini-vuln.txt
```

Expected in this image:

```text
memory_limit => 256M => 256M
post_max_size => 24M => 24M
upload_max_filesize => 16M => 16M
max_file_uploads => 20 => 20
max_input_vars => 1000 => 1000
max_input_nesting_level => 64 => 64
session.upload_progress.enabled => On => On
session.upload_progress.cleanup => On => On
log_errors => On => On
error_log => /proc/self/fd/2 => /proc/self/fd/2
error_reporting => 32767 => 32767
display_errors => On => On
max_execution_time => 60 => 60
expose_php => On => On
allow_url_include => Off => Off
disable_functions => no value => no value
```

(Exact formatting varies slightly by build; the values come from
`php2shell.ini` plus PHP defaults. `max_input_*` and `session.*` are defaults —
verify them in *your* build and record what you see.)

### 5.2 FPM pool and worker lifecycle

```bash
docker exec php2shell-vm sh -c \
  "grep -RInE '^[[:space:]]*(listen|pm|pm\.|user|group|catch_workers_output|clear_env)[[:space:]]*=' /usr/local/etc/php-fpm.d/"
```

Expected shape (official image defaults, overridden config may differ):

```text
/usr/local/etc/php-fpm.d/www.conf:listen = 127.0.0.1:9000
/usr/local/etc/php-fpm.d/www.conf:pm = dynamic
/usr/local/etc/php-fpm.d/www.conf:pm.max_children = 5
/usr/local/etc/php-fpm.d/www.conf:pm.start_servers = 2
/usr/local/etc/php-fpm.d/www.conf:pm.min_spare_servers = 1
/usr/local/etc/php-fpm.d/www.conf:pm.max_spare_servers = 3
/usr/local/etc/php-fpm.d/www.conf:pm.max_requests = 0
/usr/local/etc/php-fpm.d/zz-docker.conf:listen = 9000
/usr/local/etc/php-fpm.d/docker.conf:catch_workers_output = yes
```

The pool file also has an override in `zz-docker.conf` (`listen = 9000`).
`zz-*` files load last, so the **effective** listen address is `9000` on all
interfaces inside the container (reachable only from inside the container), not
`127.0.0.1:9000`. Confirm the winning value with
`docker exec php2shell-vm php-fpm -tt 2>&1 | grep -A2 '^\[www\]'` before you put
it in a report — "last loaded wins" is a classic PHP-FPM review trap.

Key reading: `pm.max_requests = 0` means **workers are long-lived**. That is the
condition CVE-2026-109619 needs — a producer and a consumer on the same worker.

### 5.3 Front door limits and per-request INI

```bash
docker exec php2shell-vm nginx -T 2>/dev/null \
  | grep -E 'client_max_body_size|fastcgi_pass|fastcgi_param SCRIPT_FILENAME|try_files|location ~'

docker exec php2shell-vm sh -c \
  "grep -RInE 'PHP_VALUE|PHP_ADMIN_VALUE|php_(admin_)?value' /etc/nginx/ 2>/dev/null" \
  || echo "no per-request INI overrides found"
```

Expected: `client_max_body_size 24m`, `fastcgi_pass php-fpm-backend`, and **no**
`PHP_VALUE` / `PHP_ADMIN_VALUE` overrides.

That last absence matters for 109619: the advisory names two early consumers —
per-request INI diagnostics (`PHP_VALUE`/`.htaccess`) and **session upload
progress**. This stack has the second (enabled by default) but not the first.

### 5.4 Map requirements to the two CVEs

Fill this in from *your* output:

| Requirement | Observed in lab | Why it matters |
|---|---|---|
| finite `memory_limit` | `256M` | 109618 needs a controllable OOM |
| permissive multipart limits | `post_max_size=24M`, `client_max_body_size=24m`, `upload_max_filesize=16M` | advisory's OOM strategies abuse multipart parts/headers |
| `session.upload_progress.enabled` | `On` | confirmed early producer/consumer for 109619; no `session_start()` needed |
| worker recycling | `pm.max_requests=0` | same worker must handle producer then consumer |
| per-request INI | none | the INI-diagnostic consumer is absent here |
| `log_errors` / `error_reporting` | `On` / `E_ALL` | without logs you cannot hunt or prove anything |
| `fatal_error_backtraces` | not present in 8.4 (8.5 feature) | the strongest 8.5 producer is irrelevant on this build |

### 5.5 Write the verdict sentence

> "SAPI=FPM, PHP 8.4.26, unpatched per upstream ranges. `memory_limit=256M`,
> multipart accepted up to 24 MB at the front door, `session.upload_progress`
> enabled, workers long-lived (`pm.max_requests=0`), no per-request INI
> overrides. Advisory preconditions for both CVEs are present. Exploitation was
> **not** attempted."

**Questions**

**Q16.** What are the effective `memory_limit`, `post_max_size`, and
`client_max_body_size`?
**Q17.** What are `pm`, `pm.max_children`, and `pm.max_requests`?
**Q18.** Is `session.upload_progress.enabled` on? Why is that important?
**Q19.** Are `PHP_VALUE` / `PHP_ADMIN_VALUE` overrides present in nginx?
**Q20.** Where do PHP errors go in this container?
**Q21.** Which of the two early consumers named by the 109619 advisory exists
here?

<details>
<summary>Answers</summary>

**A16.** `memory_limit=256M`, `post_max_size=24M`,
`client_max_body_size=24m`.
**A17.** `pm=dynamic`, `pm.max_children=5`, `pm.max_requests=0` (no recycling)
in the stock image unless you change the pool.
**A18.** Yes, `On` (PHP default). Session upload progress is the confirmed
early consumer/first-stage producer for CVE-2026-109619 and does not require the
application to call `session_start()`.
**A19.** No. The nginx config only passes standard FastCGI params, so the
INI-diagnostic consumer is absent.
**A20.** `error_log=/proc/self/fd/2`, i.e. the container's stderr → visible with
`docker logs php2shell-vm`; `log_errors=On`, `error_reporting=E_ALL`.
**A21.** Session upload progress. The per-request INI diagnostic consumer is
absent because there are no `PHP_VALUE`/`PHP_ADMIN_VALUE`/`.htaccess` overrides.

</details>

✅ **Checkpoint 5:** you can defend each line of the verdict sentence with a
command and its output.

---

## Task 6 — Collect a defensible baseline

**Goal:** capture the state of the asset before you change anything, in a form a
second tester can reproduce.

```bash
cd "$(git rev-parse --show-toplevel)"   # repo root

python3 cve-demonstrations/collect_runtime.py --port 8080 --json-pretty \
  > evidence/baseline-vuln.json

docker inspect php2shell-vm > evidence/inspect-vuln.json
docker logs --timestamps php2shell-vm > evidence/container-vuln.log 2>&1
docker exec php2shell-vm php -i > evidence/phpinfo-vuln.txt
docker exec php2shell-vm php-fpm -tt > evidence/fpm-vuln.txt 2>&1
docker exec php2shell-vm nginx -T > evidence/nginx-vuln.txt 2>&1

sha256sum evidence/* > evidence/SHA256SUMS
ls -lh evidence/
```

Read the collector output rather than just saving it:

```bash
jq '{ok, runtime_fingerprint: .runtime_fingerprint, checks, healthz_status: .healthz.status}' \
  evidence/baseline-vuln.json
```

Expected:

```json
{
  "ok": true,
  "runtime_fingerprint": {
    "php": "8.4.26",
    "sapi": "fpm-fcgi",
    "service": "nimbus-analytics",
    "status": "ok",
    "raw": { "...": "..." }
  },
  "checks": {
    "reachable": true,
    "sapi_is_fpm_fcgi": true,
    "has_php_version": true,
    "note": "sapi=fpm-fcgi confirms you hit PHP-FPM; cli/cgi would not exercise the same lifecycle"
  },
  "healthz_status": 200
}
```

The collector is deliberately boring: one ordinary GET on loopback, proxies and
redirects disabled, response size capped, no payload. That is what a
non-destructive baseline looks like.

**Q22.** Which field in `baseline-vuln.json` proves you reached FPM rather than
CLI or CGI?
**Q23.** Why does the collector refuse non-loopback hosts and disable proxies?
**Q24.** Why hash the evidence files?

<details>
<summary>Answers</summary>

**A22.** `checks.sapi_is_fpm_fcgi` (and
`runtime_fingerprint.sapi == "fpm-fcgi"`).
**A23.** To guarantee the tool cannot be pointed at third-party infrastructure
by accident, and to stop an environment proxy or redirect from silently sending
the request somewhere else.
**A24.** So the report can reference an unmodified artefact later; digests let a
reviewer confirm the capture you analysed is the capture they received.

</details>

✅ **Checkpoint 6:** `evidence/` contains JSON, inspect output, logs, phpinfo,
FPM config, nginx config, and hashes.

---

## Task 7 — Worker lifecycle and same-worker correlation

**Goal:** understand the condition 109619 depends on: **producer and consumer on
the same worker**. This is safe, read-only testing.

### 7.1 See the workers

```bash
docker exec php2shell-vm ps -ef | grep '[p]hp-fpm'
docker exec php2shell-vm supervisorctl status
```

Expected: one master process plus children (2 start servers by default), e.g.

```text
root  11  1  ... php-fpm: master process (/usr/local/etc/php-fpm.conf)
www-data 24 11 ... php-fpm: pool www
www-data 25 11 ... php-fpm: pool www
```

### 7.2 Ask which worker answered

The lab's ping endpoint exposes its worker PID only when you opt in:

```bash
curl -s "$BASE/index.php?api=ping&showpid=1" | jq '{php, sapi, pid}'
# => { "php": "8.4.26", "sapi": "fpm-fcgi", "pid": 24 }
```

Watch it bounce between workers:

```bash
for i in $(seq 1 8); do
  curl -s "$BASE/index.php?api=ping&showpid=1" | sed -E 's/.*"pid":([0-9]+).*/\1/'
done | sort | uniq -c
```

With two idle children you will usually see two PIDs. That is exactly why
same-worker correlation matters: a producer request can land on PID 24 and the
consumer on PID 25, and nothing happens.

### 7.3 Pin one worker

> Close the dashboard tab first — its 4-second poll would compete for the single
> worker.

```bash
cat > /tmp/zz-lab-worker.conf <<'EOF'
[www]
pm = static
pm.max_children = 1
pm.max_requests = 0
EOF

docker cp /tmp/zz-lab-worker.conf php2shell-vm:/usr/local/etc/php-fpm.d/zz-lab-worker.conf
docker exec php2shell-vm supervisorctl restart php-fpm
docker exec php2shell-vm ps -ef | grep '[p]hp-fpm'
```

Now consecutive requests must share the worker:

```bash
for i in 1 2 3 4; do
  curl -s "$BASE/index.php?api=ping&showpid=1" | jq -r '.pid'
done
# e.g. 31 31 31 31
```

### 7.4 Prove recycling breaks the link

```bash
cat > /tmp/zz-lab-worker.conf <<'EOF'
[www]
pm = static
pm.max_children = 1
pm.max_requests = 1
EOF

docker cp /tmp/zz-lab-worker.conf php2shell-vm:/usr/local/etc/php-fpm.d/zz-lab-worker.conf
docker exec php2shell-vm supervisorctl restart php-fpm

for i in 1 2 3 4; do
  curl -s "$BASE/index.php?api=ping&showpid=1" | jq -r '.pid'
done
# e.g. 32 33 34 35  → a fresh worker per request
```

Restore the stock pool when you are done:

```bash
docker exec php2shell-vm rm -f /usr/local/etc/php-fpm.d/zz-lab-worker.conf
docker exec php2shell-vm supervisorctl restart php-fpm
```

**Q25.** What does `pm.max_requests = 0` mean?
**Q26.** With `pm.max_requests = 1`, why did the PIDs change?
**Q27.** Why must both requests reach the same worker for CVE-2026-109619?
**Q28.** What is a "fresh-worker control", and why would you add one?

<details>
<summary>Answers</summary>

**A25.** No request-count limit: workers are not recycled and can live for the
whole container lifetime.
**A26.** FPM recycles the child after each request, so the next request is
handled by a brand-new process whose request heap contains nothing from the
previous request.
**A27.** The stale value lives in a **worker-global** that points into the freed
request heap. A different worker never saw the producer's state, so there is
nothing stale to consume.
**A28.** Re-running the same request sequence but forcing a *new* worker (e.g.
`supervisorctl restart php-fpm` between requests) — if the effect disappears, it
depends on cross-request state, which is the signature of 109619. It is a
control, not a trigger.

</details>

✅ **Checkpoint 7:** you have demonstrated same-PID and recycled-PID cases
without sending a single malicious request.

---

## Task 8 — Bounded OOM: observe the engine, don't over-claim

**Goal:** see what a memory-limit exhaustion actually looks like in this stack,
and — more importantly — learn why it is **not** evidence for 109618.

> This exercise is safe **because** the probe sets its own small limit and runs
> in a disposable container. Do not copy this pattern into production "testing".

### 8.1 Create a bounded probe

```bash
cat > /tmp/oom-probe.php <<'EOF'
<?php
declare(strict_types=1);
// Bounded diagnostic: the request can never exceed 16 MB of PHP memory.
ini_set('memory_limit', '16M');
$hold = [];
for ($i = 1; $i <= 64; $i++) {
    $hold[] = str_repeat('A', 1024 * 1024);
}
echo "unreachable\n";
EOF

docker cp /tmp/oom-probe.php php2shell-vm:/var/www/html/oom-probe.php
```

### 8.2 Trigger and observe

```bash
curl -s -i "$BASE/oom-probe.php" | head -n 20
docker logs --tail 30 php2shell-vm
```

Expected:

```text
HTTP/1.1 500 Internal Server Error
...
Fatal error: Allowed memory size of 16777216 bytes exhausted
(tried to allocate 1048576 bytes) in /var/www/html/oom-probe.php on line 7
```

Container log contains the same message, from the FPM worker. Note which PID
served it (pin one worker in Task 7 if you want it exact), and whether the
worker survives:

```bash
docker exec php2shell-vm ps -ef | grep '[p]hp-fpm'
curl -s "$BASE/index.php?api=ping" | jq '{status, php, sapi}'
```

The worker normally survives a PHP-level `memory_limit` fatal: PHP handles it,
FPM replaces the child if needed, and the pool keeps serving. A container OOM
kill (`docker inspect` shows `OOMKilled=true`) is a completely different event.

### 8.3 Run the identical probe on the patched control

```bash
docker cp /tmp/oom-probe.php php2shell-patched:/var/www/html/oom-probe.php
curl -s -i http://127.0.0.1:8081/oom-probe.php | head -n 12
```

Expected: **the same fatal error** on 8.4.27. This is the punchline:

- A memory-exhaustion fatal is normal PHP behaviour on vulnerable *and* patched
  builds.
- The vulnerability is about what the engine does *internally* around the OOM
  bailout, not about the error message.
- Therefore `Allowed memory size exhausted`, HTTP 500, a crashed worker, or an
  OOM-killed container are **not** evidence for CVE-2026-109618.

### 8.4 Clean up the probes

```bash
docker exec php2shell-vm rm -f /var/www/html/oom-probe.php
docker exec php2shell-patched rm -f /var/www/html/oom-probe.php
rm -f /tmp/oom-probe.php
```

**Q29.** What HTTP status and log message does the probe produce?
**Q30.** Does 8.4.27 behave differently for this probe? What does that prove?
**Q31.** What would you need in order to claim CVE-2026-109618 is confirmed in
this build?
**Q32.** Distinguish a PHP `memory_limit` fatal from a container OOM kill.

<details>
<summary>Answers</summary>

**A29.** HTTP 500 and
`Fatal error: Allowed memory size of 16777216 bytes exhausted ...`.
**A30.** No — the patched build fails identically. It proves the fatal error is
ordinary engine behaviour and **not** a vulnerability signature, so it cannot
distinguish vulnerable from patched.
**A31.** A diagnostic build (symbols + ASAN or equivalent), the vendor
regression test or a trigger derived from the exact fixing commit, a
sanitizer/debugger trace tied to that source revision, and the same sequence on a
patched build with identical config showing the trace disappear. That is L3; a
full code-execution chain would be L4.
**A32.** A PHP `memory_limit` fatal is raised *inside* the PHP engine and is
handled per request; the worker normally continues or is replaced. A container
OOM kill is the kernel/cgroup killing a process for exceeding `memory.max`; it
shows up in `docker inspect` as `OOMKilled=true` and can kill the master plus all
workers. Neither proves the CVE.

</details>

✅ **Checkpoint 8:** you produced a 500 on both builds and can explain why that
is a control, not a finding.

---

## Task 9 — Evidence ladder and the capstone report

**Goal:** label your claim honestly and write the deliverable.

### 9.1 Score your own evidence

Answer these from your captured artefacts:

1. Do you have an engine version? → L1.
2. Do you have the **web** SAPI, the patch status (upstream ranges + no
   backport), and the effective attack requirements? → L2.
3. Do you have a sanitizer/debugger trace on the exact source revision with a
   patched control? → L3.
4. Do you have a full, reproducible code-execution chain? → L4.

This room, completed normally, is **L2**. Write that down explicitly; do not
inflate it.

### 9.2 Fill the report

Save as `evidence/finding.md` (gitignored). Use your real values.

```markdown
Title:   Unpatched PHP engine (8.4.26) on nimbus-analytics — CVE-2026-109618 / -109619
Severity: Critical, CVSS v4.0 9.2 (AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)
Asset:    php2shell-vm / php:8.4.26-fpm-alpine
          base digest sha256:...
          local image ID sha256:...
          exposure: loopback lab only (simulated internet-facing)
Evidence tier: L2 — version + SAPI + patch status + attack requirements; no exploit attempted

Evidence:
  - Web SAPI: fpm-fcgi, PHP 8.4.26 via GET /index.php?api=ping (timestamp, baseline hash)
  - Container: php-fpm + nginx under supervisord, nginx :80 -> 127.0.0.1:9000
  - Patch status: upstream GHSA ranges list 8.4.27/8.5.12/8.3.36/8.2.35 as fixed;
    no vendor backport applies (upstream image, digest pinned)
  - Effective config: memory_limit=256M, post_max_size=24M,
    client_max_body_size=24m, upload_max_filesize=16M,
    session.upload_progress.enabled=On, pm=dynamic, pm.max_children=5,
    pm.max_requests=0, no PHP_VALUE/PHP_ADMIN_VALUE overrides,
    log_errors=On, error_reporting=E_ALL, error_log=/proc/self/fd/2
  - Advisory mapping: 109618 OOM/longjmp (no complete FPM exploit demonstrated);
    109619 stale worker state (session-lifecycle FPM path validated)
  - Lab control: bounded OOM probe returns identical HTTP 500 on 8.4.26 and 8.4.27,
    therefore not used as evidence
  - Log hunt: no worker-spawns-shell telemetry; lab has no internet exposure

Impact:  Pre-auth RCE is the vendor-rated impact on web-serving SAPIs, with
         FPM susceptibility differing per CVE. Exploitability on this asset was
         NOT tested. Patch before exposure regardless.
Caveats: Banners can be hidden or spoofed; backports change patch status; a crash,
         500, or OOM error is not RCE; 109618 has no demonstrated complete FPM
         exploit, which lowers confidence but not the patching urgency.

Fix:     Upgrade to PHP 8.4.27 / 8.5.12 / 8.3.36 / 8.2.35 (or newer), pin the new
         image digest, and restart every worker. Re-read effective config after
         restart.

Temporary mitigations (not a fix):
  - enforce memory_limit=-1 administratively only if you accept the DoS trade-off
    (partial mitigation for 109618)
  - keep post_max_size conservative; cap decoded size/parts/headers/fields at the
    front door; block multipart where unused
  - session.upload_progress.enabled=0 + restart workers (session path, 109619)
  - fatal_error_backtraces=0 on PHP 8.5 + restart workers
  - remove per-request INI overrides and attacker-reachable fatal errors/timeouts
  - consider pm.max_requests=1 (breaks same-worker requirement; costs performance)
  - do NOT use RLIMIT_AS/RLIMIT_DATA — it can trigger the vulnerable longjmp path
```

**Q33.** Which tier did you reach, and what single artefact is missing for L3?
**Q34.** Why is "no complete FPM exploit demonstrated for 109618" not a reason to
delay patching?
**Q35.** Name two temporary mitigations and the CVE each targets.

<details>
<summary>Answers</summary>

**A33.** L2. For L3 you need a sanitizer/debugger trace of the specific invalid
memory access on the identified engine path, tied to the exact source revision,
with a patched control — the repo does not ship a regression test or PoC.
**A34.** The engine is still unpatched, the attacker only needs one working path,
and the advisory's source analysis finds FPM susceptible; a demonstrated-vs-
suspected distinction is a confidence caveat, not an exposure exemption.
**A35.** Examples: `memory_limit=-1` enforced administratively (partial, 109618);
`session.upload_progress.enabled=0` (session path, 109619);
`fatal_error_backtraces=0` on 8.5 (109619); conservative `post_max_size` plus
front-door part/header/size caps (DoS/OOM reduction for both). Updating is the
only complete mitigation.

</details>

✅ **Checkpoint 9:** `evidence/finding.md` exists, states L2, and every claim
maps to a file in `evidence/`.

---

## Task 10 — Detection and incident hunt

**Goal:** if the asset had been internet-facing and unpatched since
2026-10-21, you would be looking for an incident, not just a misconfiguration.

### 10.1 Hunt the lab's own logs

```bash
docker logs php2shell-vm 2>&1 \
  | grep -iE 'Allowed memory size|Maximum execution time|Primary script unknown|SIGSEGV|signal 11|child .* exited|PHP (Warning|Deprecated|Fatal)' \
  | tail -n 50

docker exec php2shell-vm tail -n 50 /var/log/nginx/access.log
docker exec php2shell-vm tail -n 50 /var/log/nginx/error.log
```

Look for the patterns and note which ones are present **because you generated
them** (the OOM probe, the missing-file request) versus pre-existing noise.

### 10.2 What actually indicates exploitation

| Signal | Strength | Note |
|---|---|---|
| PHP worker spawning `sh`/`bash`/`curl`/`wget`/`nc` | highest | CISA's SIGMA rule targets this; still needs triage |
| Repeated pre-script warnings/deprecations | medium | 109619 INI-consumer hint; can be benign config |
| `Maximum execution time exceeded` on attacker-reachable routes | medium | a fatal interruption, one producer ingredient |
| `Allowed memory size exhausted` | low | expected PHP behaviour; not proof |
| HTTP 500 / worker crash / OOM kill | low | availability symptom, not exploitation |
| `PHP_SESSION_UPLOAD_PROGRESS` in multipart traffic | low–medium | feature is default-on; volume/context matters |

**Q36.** What is the highest-value detection signal, and why?
**Q37.** Why is `log_errors=On` / `error_reporting=E_ALL` a prerequisite for
hunting?
**Q38.** Why is an `Allowed memory size exhausted` line not proof of
CVE-2026-109618?

<details>
<summary>Answers</summary>

**A36.** A PHP worker process (`php-fpm`, `php-cgi`, `httpd`) spawning a shell or
downloader. Code execution implies a new child process from the web worker;
CISA published a SIGMA rule for exactly this behaviour. It still requires
context (cron jobs, legitimate integrations) before you call it compromise.
**A37.** Vulnerabilities in this class manifest as unusual diagnostics and
fatal-error ordering. If warnings/deprecations are suppressed or logged below
`E_ALL`, you lose the only cheap telemetry. Absence of a log line is not proof of
safety, but no visibility makes any conclusion unfalsifiable.
**A38.** The same message appears on a patched 8.4.27 build (Task 8). It is the
engine's normal `memory_limit` behaviour; the CVE is about memory corruption
around the OOM bailout, which requires a debugger/sanitizer trace to observe.

</details>

✅ **Checkpoint 10:** you have a greppable hunt query set and can rank signals.

---

## Task 11 — Patch and retest

**Goal:** close the finding with evidence, not vibes.

The patched control (`php2shell-patched` on `:8081`) is already running. Treat it
as the post-patch asset and repeat the same measurements.

```bash
BASE2=http://127.0.0.1:8081

python3 cve-demonstrations/collect_runtime.py --port 8081 --json-pretty \
  > evidence/baseline-patched.json

jq '{php: .runtime_fingerprint.php, sapi: .runtime_fingerprint.sapi,
     ok, sapi_is_fpm_fcgi: .checks.sapi_is_fpm_fcgi}' evidence/baseline-patched.json

jq -n --slurpfile v evidence/baseline-vuln.json --slurpfile p evidence/baseline-patched.json \
  '{vulnerable: $v[0].runtime_fingerprint.php, patched: $p[0].runtime_fingerprint.php}'
```

Then prove the **workers** are the new build, not just the package:

```bash
docker exec php2shell-patched supervisorctl restart php-fpm
docker exec php2shell-patched ps -ef | grep '[p]hp-fpm'
curl -s "$BASE2/index.php?api=ping&showpid=1" | jq .
```

Retest checklist:

| Check | How |
|---|---|
| New engine version | `?api=ping` shows 8.4.27 |
| New digest recorded | `docker image inspect php:8.4.27-fpm-alpine` |
| Workers restarted | new FPM child PIDs after restart |
| Config re-read | `php -i`, `php-fpm -tt`, `nginx -T` from the patched container |
| Temporary mitigations reviewed | keep or remove with a reason |
| Identical baseline re-run | `baseline-patched.json` compared with the vulnerable one |
| Detection deployed | hunt queries/rule in place |
| Finding closed only with evidence | report updated with both digests |

**Q39.** What is the difference between "upgraded the package" and "patched the
running service"?
**Q40.** Why re-run the *identical* baseline instead of just checking `php -v`?
**Q41.** When would you keep `session.upload_progress.enabled=0` even after
patching?

<details>
<summary>Answers</summary>

**A39.** A package upgrade replaces files on disk; old FPM workers keep the old
engine mapped in memory until they exit. You must restart/recycle every worker
(master and children) and verify new process start times and PIDs.
**A40.** Because a patch can be applied without changing behaviour, or change
behaviour in unexpected ways; identical inputs on identical topology are what
make the comparison defensible. It also catches config drift introduced during
the change window.
**A41.** The advisory suggests considering it permanently if the feature is
unused — it is rarely tested, widely enabled, and has been a repeated source of
lifecycle bugs. The same logic applies to keeping `pm.max_requests` low if
performance allows.

</details>

✅ **Checkpoint 11:** two baselines, two digests, one clear before/after.

---

## Task 12 — Teardown

```bash
docker rm -f php2shell-vm php2shell-patched
docker rmi php2shell-lab:8.4.26 php2shell-lab:8.4.27
docker ps -a | grep php2shell || echo "no lab containers left"
```

Optionally delete `evidence/` after you have submitted your report. Do not commit
it — it may contain host-specific configuration.

**Q42.** Why remove the images as well as the containers?
**Q43.** What should you check before publishing any lab port?

<details>
<summary>Answers</summary>

**A42.** The images are deliberately vulnerable runtimes. Leaving them on disk
invites accidental reuse; removing them keeps the isolated lab truly disposable.
**A43.** That the bind is loopback (`127.0.0.1:<port>:80`), never `0.0.0.0`/all
interfaces, and that the host firewall/cloud security group does not expose it.
Never put this image on a public network.

</details>

✅ **Room complete (L2).** You have a reproducible finding, a patched control,
and a report — which is the actual skill.

---

## 4. Full answer key

| # | Answer |
|---|---|
| Q1 | `supervisord` is PID 1 |
| Q2 | `php-fpm` (priority 5) and `nginx` (priority 10); FPM starts first |
| Q3 | `/healthz`, served by nginx alone; separates front-door health from FPM/PHP health |
| Q4 | nginx; version in the `Server` header (`server_tokens` on) |
| Q5 | `127.0.0.1:9000` over FastCGI |
| Q6 | `X-Powered-By: PHP/8.4.26`, controlled by `expose_php` |
| Q7 | All `.php` URLs are proxied to FPM with no file-existence guard (`SCRIPT_FILENAME` built from docroot; FPM logs "Primary script unknown") — a hardening gap, not RCE |
| Q8 | `php=8.4.26`, `sapi=fpm-fcgi` |
| Q9 | `cli`; a separate process mode that does not exercise FPM request/worker lifecycle |
| Q10 | Locally built images have no `RepoDigest`; record the base image digest plus the local image ID (or push and pin the registry digest) |
| Q11 | 8.4.27 and 8.5.12 |
| Q12 | 8.2.35 and 8.3.36 |
| Q13 | 109618 = GHSA-w8hw-w9fx-j79w; 109619 = GHSA-6wmf-4rv5-p3rp |
| Q14 | CVE-2026-109618 (FPM susceptible by source analysis, no complete FPM exploit demonstrated) |
| Q15 | Backports, stale workers after upgrade, and custom builds mean the version string alone is not patch status |
| Q16 | `memory_limit=256M`, `post_max_size=24M`, `client_max_body_size=24m` |
| Q17 | `pm=dynamic`, `pm.max_children=5`, `pm.max_requests=0` (stock image) |
| Q18 | Yes, `On`; confirmed early producer/consumer for 109619 and needs no `session_start()` |
| Q19 | No `PHP_VALUE`/`PHP_ADMIN_VALUE` overrides in nginx |
| Q20 | `error_log=/proc/self/fd/2` → container stderr / `docker logs`; `log_errors=On`, `E_ALL` |
| Q21 | Session upload progress consumer (INI-diagnostic consumer is absent) |
| Q22 | `checks.sapi_is_fpm_fcgi` / `runtime_fingerprint.sapi == fpm-fcgi` |
| Q23 | Prevent accidental third-party targeting and proxy/redirect surprises; keeps traffic loopback-only |
| Q24 | Integrity/provenance: reviewer can verify the analysed capture is unmodified |
| Q25 | `pm.max_requests=0` = unlimited; workers are never recycled |
| Q26 | FPM recycles the child after each request, so a fresh worker handles the next request |
| Q27 | The stale pointer lives in worker-global state; only the worker that served the producer can consume it |
| Q28 | Same sequence with a forced new worker; if the effect vanishes, it is cross-request state (109619 signature) |
| Q29 | HTTP 500 + `Fatal error: Allowed memory size of 16777216 bytes exhausted ...` |
| Q30 | No; patched build fails identically, so the fatal is not a vulnerability signature |
| Q31 | Diagnostic build with symbols/sanitizer, vendor regression test or verified trigger, a trace tied to the exact source revision, and a patched control |
| Q32 | PHP fatal is handled inside the engine per request; container OOM kill is the kernel/cgroup killing processes (`OOMKilled=true`), potentially the whole pool |
| Q33 | L2; missing an L3 sanitizer/debugger trace on the exact source revision with a patched control |
| Q34 | Unpatched engine + attacker needs one path + source analysis supports FPM susceptibility; confidence caveat ≠ exposure exemption |
| Q35 | `memory_limit=-1` admin-enforced (partial, 109618); `session.upload_progress.enabled=0` (109619); `fatal_error_backtraces=0` on 8.5 (109619); conservative `post_max_size` + front-door caps (both) |
| Q36 | PHP worker spawning a shell/downloader — direct code-execution side effect (CISA SIGMA rule), still needs triage |
| Q37 | The class shows up as unusual diagnostics/fatal ordering; without `E_ALL` + working `error_log` the telemetry does not exist |
| Q38 | Patched 8.4.27 produces the same message; it is normal `memory_limit` behaviour, not memory corruption |
| Q39 | Package upgrade changes files; restarting all workers is what changes the running service |
| Q40 | Identical inputs + topology make a defensible comparison and catch config drift |
| Q41 | If upload progress is unused — it is rarely tested and has been a repeated lifecycle bug source; advisory recommends considering it permanently |
| Q42 | The images are deliberately vulnerable; remove them so the lab is truly disposable |
| Q43 | Bind loopback only (`127.0.0.1:<port>:80`), never all interfaces; check host firewall/cloud security group |

---

## 5. Common mistakes (and what to do instead)

| Mistake | Correction |
|---|---|
| Reporting "PHP 8.4.26 = RCE" from a banner | Stop at L1/L2 and name the missing evidence |
| Testing only the CLI SAPI | Use `?api=ping`, `php-fpm -i`, or a real HTTP request; CLI ≠ FPM |
| Calling a crash / 500 / OOM kill "RCE confirmed" | It is a symptom; see Task 8 |
| Forgetting to restart workers after a patch | Old workers keep the old engine mapped |
| Treating a distro backport as vulnerable (or safe) without checking | Read the changelog/digest and record it |
| Running a public PoC "just to confirm" | Memory-corruption PoCs are unstable and can leak other tenants' data |
| Ignoring same-worker correlation for 109619 | Pin one worker, log PIDs, add a fresh-worker control |
| Publishing the lab on `0.0.0.0` | Loopback only; it is a deliberately vulnerable image |
| Committing `evidence/` to Git | It can contain host-specific config; it is gitignored |

---

## 6. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `docker: command not found` | Install Docker Engine/Desktop; on Linux add your user to the `docker` group |
| `manifest unknown` for `php:8.4.26-fpm-alpine` | Tag removed upstream; use another pre-patch tag via `--build-arg` and record it |
| `port is already allocated` | Publish `127.0.0.1:8081:80` and set `BASE` accordingly |
| Container exits immediately | `docker logs php2shell-vm`; check `supervisord.conf` was copied to `/etc/supervisor/conf.d/` |
| `?api=ping` returns 502 | FPM down or pool misconfigured; `supervisorctl status`, `docker logs` |
| `/healthz` works but PHP 502s | Front door fine, backend broken → FPM pool/PHP engine |
| `?api=ping&showpid=1` has no `pid` | You are running an image built before this feature; rebuild the image from this repo (the opt-in field is in `index.php`) |
| Charts/logs don't stream | Browser JS disabled or polling blocked; verify `?api=stats` with `curl` |
| `php -i` shows `Loaded Configuration File: (none)` | Official images configure through `conf.d/*.ini`; read `php --ini` |
| Permission error writing `evidence/` | Ensure you are in the repo root and the directory is writable |
| Only one FPM child after pinning | Expected: `pm=static`, `pm.max_children=1` |

---

## 7. Extra credit (optional, advanced)

1. **Source-diff the fix.** Clone `php-src`, fetch tags `php-8.4.26` and
   `php-8.4.27`, and summarise the OOM/shutdown changes:
   ```bash
   git clone --filter=blob:none https://github.com/php/php-src.git
   cd php-src
   git log --oneline php-8.4.26..php-8.4.27 -- Zend main ext/session
   git diff php-8.4.26..php-8.4.27 -- Zend/zend.c main/main.c | head -n 200
   ```
   Map each hunk to the advisory language (delayed soft OOM + hard `_exit()`;
   complete request-state reset). Write it up as evidence for L3 groundwork.

2. **Compare SAPIs.** Build `php:8.4.26-apache` with a minimal `index.php` and
   read the advisory's warning about `mod_php` calling request shutdown even when
   startup failed. Explain why `mod_php` is the highest-risk SAPI. Do not attempt
   exploitation.

3. **8.5-only producer.** Build `php:8.5.11-fpm-alpine`, inspect
   `fatal_error_backtraces`, and explain why this producer does not exist on the
   8.4 lab build.

4. **ASAN diagnostic build (L3 attempt).** Build PHP 8.4.26 from source with
   `--enable-debug` and `-fsanitize=address`, run the vendor regression test (it
   is not bundled here — obtain it from the fixing commit), and capture the
   trace. Repeat on 8.4.27 with identical flags. This is hours of work and is
   exactly what L3 requires.

5. **Write a detection rule.** Turn Task 10's highest-value signal into a Sigma
   rule (parent image = php-fpm/php-cgi/httpd; child = shell/downloader) and
   test it against synthetic process events. Document false positives.

6. **Patch gate in CI.** Add a pipeline check that extracts the PHP version from
   `?api=ping` and fails if it is below the fixed milestone for the running
   branch. Bonus: pin base image digests and fail on mutable tags.

7. **Red-team-vs-blue-team report swap.** Trade `evidence/finding.md` with a
   teammate. They should reproduce your conclusion from the report alone; any
   claim they cannot reproduce gets rewritten.

---

## 8. What to study next

- **PHP internals:** request lifecycle (`php_request_startup` /
  `php_request_shutdown`), FPM master/worker model, `pm` settings, Zend memory
  manager.
- **Vulnerability management:** CVSS v4.0 `AT:P`, backport verification, image
  digest pinning, patch SLAs.
- **Detection engineering:** Sigma rules for process ancestry, PHP-FPM logs,
  container runtime telemetry.
- **Practice boxes (authorized only):** TryHackMe web-fundamentals and
  vulnerability-research paths; Hack The Box "Web" and "Bug Bounty" content;
  PortSwigger Web Security Academy for general web exploitation.
- **Read the primary sources**, not blog summaries. Advisories change.

---

## 9. Primary sources

| Source | Link |
|---|---|
| PHP.net security advisory (21 Oct 2026) | <https://www.php.net/archive/2026.php#2026-10-21-5> |
| CVE-2026-109618 (OOM corruption) | <https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w> |
| CVE-2026-109619 (stale global state) | <https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp> |
| CVE records | <https://www.cve.org/CVERecord?id=CVE-2026-109618> · <https://www.cve.org/CVERecord?id=CVE-2026-109619> |
| CISA alert + SIGMA rule | <https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching> · <https://github.com/cisagov/SIGMA_Rules> |
| NCSC-NL/php2shell (inventory, affected products) | <https://github.com/NCSC-NL/php2shell> |
| Deeper methodology + workbooks | [`cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md`](cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md) · [`CVE-2026-109618.md`](cve-demonstrations/CVE-2026-109618.md) · [`CVE-2026-109619.md`](cve-demonstrations/CVE-2026-109619.md) |
| Lab build/run details | [`php2shell-lab/README.md`](php2shell-lab/README.md) |

Verified 2026-10-25. Re-check fixed versions and SAPI notes before every
engagement — vendor backports and advisory updates change the picture.

---

## 10. Completion checklist

- [ ] Container running loopback-only; `/healthz`, `/`, `?api=ping` all verified
- [ ] Service map drawn: nginx :80 → FPM 127.0.0.1:9000 under supervisord
- [ ] Web SAPI fingerprint captured (`8.4.26`, `fpm-fcgi`) + CLI comparison
- [ ] Base image digest and local image ID recorded
- [ ] Advisory ranges read from both GHSAs; 8.4.26 declared unpatched
- [ ] Patched control built and fingerprinted (`8.4.27`)
- [ ] Effective config captured: memory/multipart/session/workers/logging
- [ ] Attack requirements mapped to both CVEs; absent consumers identified
- [ ] Baseline collector run, evidence hashed and kept out of Git
- [ ] Same-PID vs recycled-worker behaviour demonstrated (`showpid=1`)
- [ ] Bounded OOM probe observed on both builds and explained as non-evidence
- [ ] Evidence tier stated (L2) with the L3 gap named
- [ ] Report filled from evidence only; mitigations and caveats included
- [ ] Hunt queries run; signal strength ranked
- [ ] Patch/retest completed with new digest + restarted workers
- [ ] Containers and images removed; port closed
- [ ] (Optional) Source diff, Sigma rule, or ASAN capstone attempted

---

*This room is documentation and safe laboratory practice only. It contains no
exploit code for CVE-2026-109618 or CVE-2026-109619. Use it on systems you own or
are explicitly authorized to test.*
