# Enterprise Cyber Range — CVE-2026-109618 (PHP2Shell)

A browser-hosted, dual-guest x86 cyber range for investigating **CVE-2026-109618** against a real
Apache/mod_php target. The attacker workstation and the target server are genuine v86 virtual
machines connected only to each other over a session-scoped raw-Ethernet channel. There is no
backend, no relay, and no simulated HTTP layer.

## What the learner does

The **Vulnerability Lab** view is a gated eight-step exercise. Each step unlocks only when its own
requirement was verified from guest output:

1. **Reconnaissance** — read the target's SAPI, PHP build, `memory_limit`, `post_max_size`,
   upload-progress setting, flag permissions and the allocator patch marker.
2. **Baseline testing** — three ordinary requests from the attacker guest, each corroborated by the
   target's own access log.
3. **Request analysis** — one request and one modified POST through the real RangeProxy, visible in
   the guest proxy record and in the target log.
4. **Vulnerability investigation** — classify the build from the observed version *and* the patch
   marker, then record every applicable condition from the advisory.
5. **Controlled reproduction** — one bounded, chunked multipart probe with the real response,
   PHP/Apache log tails, and worker state before and after.
6. **Target-side verification** — process state, logs, and an honest verdict on whether any
   Apache-owned execution proof exists.
7. **Remediation** — compare the running build with the verified 8.2.35 patch, pinned source
   digests, and the advisory's configuration mitigations.
8. **Completion** — genuine CTF credit requires a fresh challenge file owned by `apache`,
   created after provisioning, plus the session flag read through that execution context.

Snapshot save/restore, attacker reboot, target reset (real v86 cold boot with a new
target-generated flag), and bounded guest recovery are available from the parent controls.

## Verified advisory facts

| Item | Value |
|---|---|
| Advisory | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) |
| Class | RCE via OOM corruption (`longjmp()` leaves request memory invalid; shutdown consumes it) |
| Affected | `< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12` |
| Patched | `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12` |
| Highest-risk SAPI | Apache mod_php (request shutdown runs even after failed startup) |
| Lab build | Alpine x86 (32-bit, musl), PHP 8.2.34, prefork mod_php |

The `8.2.34 → 8.2.35` source diff (tarball digests match the values pinned in
`image-build/target/php-source.sha256`) replaces the immediate OOM `longjmp()` with a delayed OOM
state machine plus `memory_hard_limit_percent`. The lab therefore classifies a build from two
independent observations — version and patch marker — and reports `unknown` when they conflict.
Full record: [`docs/CVE-VERIFICATION.md`](docs/CVE-VERIFICATION.md).

**What the lab does not claim:** genuine exploitation of this exact 32-bit musl/mod_php build is
unverified. No control-flow profile for it exists in this repository, and the advisory's confirmed
exploit was validated on a 64-bit reference setup. An OOM fatal, an HTTP 500, a dead worker, or a
version string is never treated as code execution. The genuine completion step stays closed unless
target-side proof exists; an explicitly labelled training simulation is recorded separately and
never changes genuine status.

## Run it

```sh
npm ci
npm run assets:runtime        # fetch pinned v86 runtime files if needed
node scripts/generate-asset-manifest.mjs
npm run assets:verify         # required guest ISOs must be present and checksummed
npm run dev                   # http://localhost:5173
```

Guest media is built by [`image-build/`](image-build) (see [`docs/IMAGES.md`](docs/IMAGES.md));
the repository intentionally excludes ISOs. Without them the UI refuses to boot and shows the
missing-asset error instead of a fake VM.

## Tests

```sh
npm run lint        # strict TypeScript project check
npm test            # 52 Vitest unit tests + 25 Python guest-tool tests
npm run build       # production build
npm run test:e2e    # Playwright shell tests (needs Chromium)
npm run test:e2e:guest  # dual-guest + proxy + practical-lab acceptance (needs guest images)
```

The guest-backed suites run in the **Build reproducible guest images** workflow, which builds the
images, verifies checksums, then executes the real v86 acceptance specs.

## Layout

- `src/lib/LabController.ts` — lifecycle, provisioning, network/telemetry checks, proxy acceptance,
  and the exercise actions that run real guest commands.
- `src/lib/exercise.ts` — pure step gating, condition assessment, probe interpretation, and the
  simulation separation rules.
- `src/lib/cve.ts` — verified advisory constants, version matrix, and patch marker.
- `src/views/LabView.tsx` — the learner-facing practical exercise.
- `image-build/target/` — Alpine/mod_php target build, `labctl` (flag provisioning + verification),
  and the training web application.
- `image-build/attacker/` — Tiny Core workstation, RangeProxy, research harness, notes.
