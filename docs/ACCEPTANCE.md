# Acceptance and evidence matrix

“Implemented” means code/configuration exists; “tested” means the named test actually ran;
“verified in guest” requires output from a running guest. A build, version string, HTTP status or
static review is not a substitute for the last column.

## Preserved results from the earlier milestone

[CI run 40081439535](https://github.com/OneSide-stack/cvephp/actions/runs/40081439535) at commit
`e99922b` passed on 2026-10-24 and remains the verified baseline for the dual-guest boot, isolated
networking, real HTTP, target telemetry, intercepting proxy, Repeater, and their error/recovery
gates (19.1 minutes, both Playwright/v86 specs). Those capabilities were not modified by this
milestone except for additive target-side commands, so their gates remain the reference evidence.

## This milestone: the practical vulnerability lab

| Requirement | Implementation | Test status |
|---|---|---|
| CVE verified from authoritative sources | `docs/CVE-VERIFICATION.md`: GHSA-w8hw-w9fx-j79w retrieved from `github.com`; `php-8.2.34`/`php-8.2.35` tarballs downloaded from `codeload.github.com` and matched against the pinned digests; allocator, `main.c`, Zend and session diffs examined | **Verified from primary sources** (not from a version banner) |
| Reconnaissance from the real target | `LabController.runRecon` reads `/health.php`, PHP CLI, `labctl telemetry`, `labctl build`, `ss -ltn`, and `stat` on the flag and `libphp.so` | Unit-tested gating and validation; guest-backed gate authored in `tests/guest/lab-exercise.spec.ts` |
| Baseline testing with target corroboration | `runBaselineSuite`: three unique markers, each required in the real access log | Unit-tested; guest-backed gate authored |
| Request analysis through proxy/Repeater | `analyzeProxiedRequests`: decoded RangeProxy record plus distinct target log lines for a forwarded request and a modified POST | Unit-tested proxy helpers (inherited); guest-backed gate authored |
| Vulnerability investigation | `investigateVulnerability` + `assessBuild` + `classifyObservedBuild`: version **and** `memory_hard_limit_percent` marker, conflict → `unknown` | 10 unit tests over vulnerable/patched/conflict/EOL inputs |
| Controlled reproduction | `runControlledProbe(1–64 MiB)`: real chunked multipart probe, target PHP/error/access logs, worker PIDs and counts before/after, bounded to 64 MiB, second confirmation above 16 MiB | Outcome classification unit-tested; guest-backed gate authored |
| Target-side verification | `verifyTargetSide`: `pidof httpd`, telemetry, `labctl evidence`, `stat` on flag/proof | Unit-tested verdict logic; guest-backed gate authored |
| Remediation comparison | `compareRemediation`: patch marker, pinned source digests, first-fixed table, advisory mitigations, explicit limitation when 8.2.35 media is absent | Unit-tested; guest-backed gate authored |
| Gated completion | `evaluateExercise` derives unlock/status per step; `submitFlag` refuses while prior steps are unmet | 12 unit tests over gating, failures, and session isolation |
| CTF flag in the target guest | `labctl provision` generates `RANGE{48 hex}` from `/dev/urandom` inside the target, writes `root:apache 0640`, prints only SHA-256; Apache denies `/flag.txt` (HTTP 403) | 24 executed Python tests: generation, rotation, permissions, digest-only output, proof removal, unsafe input, evidence validation |
| No flag in frontend data | Digest-only client check; unit test scans all `src/**` and fails on any literal flag | Executed: `tests/exercise.test.ts` |
| Reset restores real guest state | `resetExercise` cold-boots the target, re-provisions, and *requires* a changed digest and an absent previous proof before clearing progress | Guest-backed gate authored; failure logic unit-tested |
| Recovery | `recoverGuests` resumes a paused emulator, re-runs readiness, reboots only an unresponsive guest | Guest-backed gate authored; error handling reviewed |
| Genuine versus simulated completion | `validateGenuineCompletion`; simulation stored separately, never sets `genuine-rce`, never shows a shell | 4 unit tests |

## Report removal

The Evidence & Report navigation entry, `EvidenceView`, report exports, and `report.ts` were
removed. Evidence records remain an internal, guest-derived fact store used by the exercise; they
are no longer a reporting product. The lab view is the fifth navigation entry.

## Tests executed in this workspace

```text
npm run lint                — strict TypeScript project check: PASS
npm test                    — 52 Vitest tests: PASS (4 files)
                              python3 -m unittest: 25 tests, 24 PASS, 1 skipped
                              (skip: raising privileges is only observable as root)
npm run build               — production build: PASS
npm run test:e2e            — requires a Chromium binary (CI installs one)
npm run test:e2e:guest      — requires the checksummed guest images and Chromium (CI)
```

Unit coverage added in this milestone:

- `tests/exercise.test.ts` — advisory constants, build classification (vulnerable, patched,
  version/marker conflict, EOL branch, malformed version), target configuration validation (flag
  HTTP denial, `0640` ownership, listener, SAPI), condition recording, PHP quantity parsing, probe
  outcome classification (OOM, parser cap, no effect, transport error), step gating and failure
  surfacing, genuine completion validation and session isolation, digest comparison, flag shape,
  no-hardcoded-flag scan, simulation separation, reset semantics.
- `image-build/tests/test_target_labctl.py` — target flag generation/rotation, `0640`/`0600`
  permissions, digest-only output, previous-proof removal, unsafe/short/long challenge rejection,
  evidence acceptance only for Apache-owned challenge content newer than session start, non-root
  refusal, static contracts (no web-route command execution, `flag.txt` denied, build-info keeps the
  unverified label).

## New guest-backed acceptance gates

`tests/guest/lab-exercise.spec.ts` boots both real guests and then, through the UI only:

1. asserts the plaintext flag never appears in page data;
2. runs each of the seven actionable steps and requires the UI to report **Verified** with an
   *observed* detail, not a placeholder;
3. asserts the probe outcome is one of the recorded real outcomes and that the page never claims
   RCE success;
4. asserts genuine completion remains unavailable and the blocker is shown;
5. answers the labelled simulation from the observed values and asserts genuine status is unchanged;
6. resets the exercise and requires: zero verified steps, a **changed** flag digest, cleared
   simulation, and a still-running target display;
7. asserts no uncaught parent-browser errors.

## Explicit non-claims

- No genuine CVE-2026-109618 exploitation, RCE, or target shell has been demonstrated on this
  32-bit Alpine/musl build. `completedAs = "genuine-rce"` cannot be produced without a fresh
  Apache-owned challenge proof plus the matching session flag.
- The OOM probe is a bounded research primitive. An observed OOM, a dropped worker, or an HTTP 500
  is recorded as an observation and never as exploitation.
- The simulation is a knowledge check over observed facts. It is not exploitation evidence and is
  never presented as a shell.
- Distribution backports are not inferred: a version/marker conflict yields `unknown`, and the lab
  says so instead of guessing.
- The patched comparison boot requires the optional PHP 8.2.35 image; when it is absent the
  comparison is explicitly labelled as source-diff-based.
