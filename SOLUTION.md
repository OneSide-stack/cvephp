# Solution — PHP2Shell lab + real-world tester guide

This repository has **two** "solutions": the in-app walkthrough and the field
guide for finding the same CVEs on real infrastructure. Both are deliberately
**no-exploit** — a version-and-configuration finding is enough to drive a patch,
and these are memory-corruption bugs that can crash workers or leak other users'
data if you "just try a PoC" on production.

## Where things live

| What | Where |
|---|---|
| In-app **Solution** view (5 tabs) | `php2shell-lab/index.php` → sidebar *Solution* |
| **Real-World Hunt — Tester Guide** tab | *Solution → Real-World Hunt* (new) |
| Full standalone step-by-step guide | [`cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md`](cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md) |
| Per-CVE evidence workbooks | [`CVE-2026-109618.md`](cve-demonstrations/CVE-2026-109618.md) · [`CVE-2026-109619.md`](cve-demonstrations/CVE-2026-109619.md) |
| Investigation instructions + baseline collector | [`cve-demonstrations/README.md`](cve-demonstrations/README.md) · [`collect_runtime.py`](cve-demonstrations/collect_runtime.py) |
| Build/run the isolated lab | [`php2shell-lab/README.md`](php2shell-lab/README.md) |

## The solution in one page

**Lab answer:** the two flaws are in the PHP engine, not in the dashboard app.
The lab pins `php:8.4.26-fpm-alpine` (SAPI `fpm-fcgi`), one release before the
fixes in **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35**. You "solve" it by proving which
engine build you hit, reproducing the specific defect on a diagnostic build with
a vendor regression test, capturing the trace, and showing the trace disappears
on a patched build with identical configuration. An OOM error, HTTP 500, crashed
worker, or OOM-killed container is **not** a solution.

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
