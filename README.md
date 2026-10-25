# cvephp

Security-research workspace for the **PHP2Shell** vulnerabilities
(CVE-2026-109618 / CVE-2026-109619).

## Contents

* [`php2shell-lab/`](./php2shell-lab/) — a self-contained, deliberately
  vulnerable Docker environment replicating a corporate web deployment
  (nginx + PHP-FPM **8.4.26** under Supervisor, with a realistic Tailwind
  analytics dashboard as the app) for analysing and testing the flaws.
* [`cve-demonstrations/`](./cve-demonstrations/) — single folder covering
  **both** CVEs: how each claim would be validated, what triggers/diagnostics
  count as evidence, and a safe loopback baseline collector (`collect_runtime.py`).

See [`php2shell-lab/README.md`](./php2shell-lab/README.md) for the exact
build/run/verify commands and [`cve-demonstrations/README.md`](./cve-demonstrations/README.md)
for the investigation workbooks and evidence template.

> ⚠️ The lab image ships a known-vulnerable PHP runtime. Run it isolated;
> never expose it to networks you care about. The CVE identities and fix versions
> stated in the lab description have not been independently verified here — check
> the CVE Program and vendor advisories before treating any version table as authoritative.
