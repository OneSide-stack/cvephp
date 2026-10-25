# cvephp

Security-research workspace for the **PHP2Shell** vulnerabilities
(CVE-2026-109618 / CVE-2026-109619).

## Contents

* [`php2shell-lab/`](./php2shell-lab/) — a self-contained, deliberately
  vulnerable Docker environment replicating a corporate web deployment
  (nginx + PHP-FPM **8.4.26** under Supervisor, with a realistic Tailwind
  analytics dashboard as the app) for analysing and testing the flaws.

See [`php2shell-lab/README.md`](./php2shell-lab/README.md) for the exact
build/run/verify commands.

> ⚠️ The lab image ships a known-vulnerable PHP runtime. Run it isolated;
> never expose it to networks you care about.
