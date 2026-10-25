# cvephp

Security-research workspace for the **PHP2Shell** vulnerabilities
(CVE-2026-109618 / CVE-2026-109619).

## Contents

* [`php2shell-lab/`](./php2shell-lab/) — a self-contained, deliberately
  vulnerable Docker environment replicating a corporate web deployment
  (nginx + PHP-FPM **8.4.26** under Supervisor, with a realistic Tailwind
  analytics dashboard as the app) for analysing and testing the flaws.
* [`WALKTHROUGH.md`](./WALKTHROUGH.md) — **start here for hands-on practice**: a
  TryHackMe/Hack The Box-style guided room (setup → recon → fingerprint → patch
  triage → attack requirements → evidence → report → retest) with 12 tasks,
  expected output, hidden answers, a full answer key and a completion checklist.
* [`SOLUTION.md`](./SOLUTION.md) — entry point: the lab answer plus the ten-step
  real-world tester loop, with links to every workbook.
* [`cve-demonstrations/`](./cve-demonstrations/) — single folder covering
  **both** CVEs: how each claim would be validated, what triggers/diagnostics
  count as evidence, a safe loopback baseline collector (`collect_runtime.py`),
  and the [real-world tester guide](./cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md).
* **Solution** page in the lab UI — a short, simple 7-step walkthrough with
  copy buttons and checkboxes.

See [`php2shell-lab/README.md`](./php2shell-lab/README.md) for the exact
build/run/verify commands and [`cve-demonstrations/README.md`](./cve-demonstrations/README.md)
for the investigation workbooks and evidence template. New testers should start
with [`REAL-WORLD-TESTER-GUIDE.md`](./cve-demonstrations/REAL-WORLD-TESTER-GUIDE.md):
it teaches how to find and qualify these CVEs on infrastructure you are
authorized to test, without running exploit payloads against production.

> ⚠️ The lab image ships a known-vulnerable PHP runtime. Run it isolated;
> never expose it to networks you care about. As of 2026-10-25 the CVE identities,
> affected SAPIs and fixed versions (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) have been
> checked against the PHP.net advisory, both php-src GHSAs, the CISA alert and
> NCSC-NL's operational repo (see the tester guide). Still re-verify at the start
> of every engagement: vendor backports mean a version string alone never proves
> patch status.
