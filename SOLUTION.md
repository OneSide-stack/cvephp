# Solution — PHP2Shell lab + real-world tester guide

This repository has **two** "solutions": the in-app walkthrough and the field
guide for finding the same CVEs on real infrastructure — plus a **lab-only
impact chain** so the room ends at real access instead of at "possible".

Nothing here is a weaponised exploit. The CVEs are memory-corruption bugs in the
PHP engine with no public FPM exploit, so `php2shell-lab/lab-exploit.php`
*simulates* the documented lifetime violation inside the disposable container
(per-worker file instead of the worker heap, real bounded OOM bailout, same-worker
reuse, command execution, flag). It refuses to run on a patched engine. On real
infrastructure the deliverable is still the version-and-configuration finding:
patching beats "just trying a PoC" on production, where a crash can leak other
users' data.

## Where things live

| What | Where |
|---|---|
| **Guided room / walkthrough** (tasks, answers, report) | [`WALKTHROUGH.md`](WALKTHROUGH.md) |
| In-app **Solution** page (simple 16-step walkthrough, both chains + flags) | `php2shell-lab/index.php` → sidebar *Solution* |
| **Impact chain runner** (lab only, ends in code execution + flag) | `php2shell-lab/lab-exploit.php` → <http://127.0.0.1/lab-exploit.php> |
| One-command chain driver | `python3 cve-demonstrations/run_chain.py --chain both` |
| Full standalone step-by-step guide | [`cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md`](cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md) |
| Per-CVE evidence workbooks | [`CVE-2026-109618.md`](cve-demonstrations/CVE-2026-109618.md) · [`CVE-2026-109619.md`](cve-demonstrations/CVE-2026-109619.md) |
| Investigation instructions + baseline collector | [`cve-demonstrations/README.md`](cve-demonstrations/README.md) · [`collect_runtime.py`](cve-demonstrations/collect_runtime.py) |
| Build/run the isolated lab | [`php2shell-lab/README.md`](php2shell-lab/README.md) |

## The solution in one page

**Lab answer:** the two flaws are in the PHP engine, not in the dashboard app.
The lab pins `php:8.4.26-fpm-alpine` (SAPI `fpm-fcgi`), one release before the
fixes in **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. You "solve" it by proving which
engine build you hit, proving the preconditions, **completing both impact chains
to their flags**, and showing the identical chains are refused on a patched build:

| Chain | Steps | Flag |
|---|---|---|
| CVE-2026-109618 | `arm` → `oom` (same worker) → `fire` | `PHP2SHELL{109618-oom-bailout-reused-worker-memory}` |
| CVE-2026-109619 | `producer` (same worker) → `fire` | `PHP2SHELL{109619-stale-worker-global-after-fatal}` |

```bash
docker run -d --name php2shell-vm --memory=256m --cpus=1 -p 127.0.0.1:80:80 php2shell-lab:8.4.26
python3 cve-demonstrations/run_chain.py --chain both            # both flags
python3 cve-demonstrations/run_chain.py --chain both --base http://127.0.0.1:8081   # refused: patched
```

An OOM error, HTTP 500, crashed worker, or OOM-killed container is **not** a
solution by itself — Task 8 uses exactly that as a control. The chain is what
turns the finding into demonstrated impact, and the report must label it as a
lab simulation.

**Real-world answer (the 10-step tester loop):**

1. **Ground truth** — read the PHP.net advisory, both php-src GHSAs, the CISA
   alert and NCSC-NL's repo. Record fixed versions, SAPIs, and demonstrated vs
   suspected attack paths.
2. **Inventory** — hosts, FPM pools, containers/images, CI build contexts, and
   appliances that embed PHP. Prioritise internet-facing web-serving SAPIs.
3. **Fingerprint** — passive headers/404 pages remotely; `php -v`, `php -i`,
   `php-fpm -v`, `?api=ping` locally. Identify the SAPI that serves requests.
4. **Patch status** — compare against fixed releases **and** check vendor
   changelogs for backports; pin image digests; verify workers restarted.
5. **Attack requirements** — effective `memory_limit`, `post_max_size`,
   `session.upload_progress.enabled`, `fatal_error_backtraces`, per-request INI
   diagnostics, worker recycling (`pm.max_requests`), front-end body limits.
6. **Safe reproduction** — clone the stack in the isolated lab, build a
   diagnostic image with symbols/sanitizer, use the vendor regression test,
   correlate worker PIDs, add a fresh-worker control, repeat on a patched image.
7. **Evidence ladder** — L0 surface → L1 version → L2 preconditions → L3 trace →
   L4 RCE chain. Label the claim honestly; most engagements end at L2.
8. **Hunt** — PHP error/access logs, journald, EDR for a PHP worker spawning a
   shell (CISA SIGMA rule), upload-progress probes, pre-RINIT OOM fatals.
9. **Report** — asset + digest, SAPI, patch status, effective config, log hunt,
   evidence tier, caveats, fix and temporary mitigations.
10. **Retest** — new version/digest, workers restarted, config re-read, detection
    deployed, workbook steps re-run, finding closed with evidence.

Full commands, exercises, a report template and primary-source links are in
[`REAL-WORLD-TESTER-GUIDE.md`](cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md).

## Primary sources (verified 2026-10-25)

- [PHP.net security advisory](https://www.php.net/archive/2026.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) · [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618) · [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619)
- [CISA alert + SIGMA rule](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching) · [NCSC-NL/php2shell](https://github.com/NCSC-NL/php2shell)

Accuracy note: `mod_php` is the highest-risk SAPI. PHP validated the
CVE-2026-109619 session-lifecycle path against FPM, and reports **no complete
FPM exploit demonstrated for CVE-2026-109618** — keep that distinction when you
write up findings from this FPM lab.
