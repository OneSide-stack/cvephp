# Acceptance and evidence matrix

This file is deliberately conservative. “Implemented” means code/configuration exists; “tested” means the stated test actually ran; “verified in guest” requires output from the running guest. A build, version string, HTTP status, or static review is not a substitute for the last column.

## Required dual-guest and proxy gates: current result

[CI run 40081439535](https://github.com/OneSide-stack/cvephp/actions/runs/40081439535), commit `e99922b`, passed on 2026-10-24. It reused the checksummed guest images and completed both independent Playwright/v86 specs in 19.1 minutes. The controller and independent browser checks report each gate separately as PASS, FAIL, or BLOCKED.

| Gate | Result | Guest-backed or independent evidence |
|---|---|---|
| Asset preflight | **PASS** | Both ISO entries and pinned v86/firmware were present; start loaded and verified their checksums |
| Dual boot and usability | **PASS** | TinyCore attacker X/tools and Alpine target display; both machines and the overall lab reached Ready |
| Isolated network | **PASS** | 8/8 checks: both `/24` addresses, guest ICMP, target TCP :80, HTTP, headers, target log, and no default route on the shared v86 `inbrowser` network |
| Real HTTP and target corroboration | **PASS** | Attacker curl received the real Assessment Portal; `learner-65a14a13a01f` matched the target's HTTP 200 Apache entry |
| Target telemetry | **PASS** | Apache/mod_php, PHP 8.2.34/`apache2handler`, 128 MiB PHP limit, live guest/RSS/process measurements, and refreshed guest logs |
| Proxy process/readiness | **PASS** | The attacker guest reported Dillo, the exact running proxy process, loopback proxy/management listeners, and target-only proxy configuration |
| Browser routing, interception ON | **PASS** | Real Dillo request `browser-original-61078b18949f` appeared in RangeProxy with GET method, absolute target URL, Host/Dillo headers, and empty GET body visible |
| Interception and hold | **PASS** | The original request remained held in RangeProxy and was independently absent from Apache before forwarding |
| Edit and forward | **PASS** | The held request was changed to `browser-edited-13f35f8bdef9`, explicitly forwarded, and returned the target's genuine HTTP 200 response/body |
| Target-log corroboration | **PASS** | One proxy forward record and one distinct Apache GET corroborated the edited marker (two byte-identical Apache occurrences from the two active logging directives); the original marker remained absent |
| Browser routing, interception OFF | **PASS** | Dillo request `browser-off-b19af86d80f4` produced both a RangeProxy forwarded record and a distinct Apache GET, ruling out silent direct-route fallback |
| Repeater | **PASS** | Separately edited POST `repeater-70d06958f9d5` returned the real JSON status/headers/body and was corroborated in Apache; arbitrary methods and general body editing are not claimed |
| Errors and recovery | **PASS** | Malformed framing rejection, held-request drop without target receipt, bounded proxy-down/paused-target/caller-timeout behavior, proxy/target recovery, and repeated requests all passed |
| Independent browser and final-log checks | **PASS** | No uncaught parent-browser errors; after an independent manual target refresh, the actual log viewer contained the edited, disabled, Repeater, recovery, and target-recovery markers and still excluded the held original |
| Parent controls during error tests | **PASS** | The independent spec switched among Attacker, Network, and Target views while error handling ran and confirmed Reset remained enabled; it did not perform a destructive reset |

The [cyber-range-guest-acceptance artifact](https://github.com/OneSide-stack/cvephp/actions/runs/40081439535/artifacts/12555743192) contains `proxy-acceptance.json`, the independent per-gate/browser summary, raw request/response captures, proxy evidence and diagnostics, guest configuration, target Apache logs (including the final refreshed log), and the independent Playwright report (240,469-byte ZIP; SHA-256 `19fcb90231cecb9d6a1de690751754e6cbe9ad33a6d9559274bf04bd8e52ddaf`). The separate [frontend/guest-tool CI run 40081439566](https://github.com/OneSide-stack/cvephp/actions/runs/40081439566) also passed.

The earlier required baseline remains [CI run 40067579565](https://github.com/OneSide-stack/cvephp/actions/runs/40067579565) at commit `b82c81f`; its six connectivity/telemetry gates passed independently before the proxy work. None of these results is CVE reproduction, RCE, target-shell, flag-retrieval, snapshot-restoration, or exploit-reliability evidence.

| Capability | Implementation | Test/evidence status |
|---|---|---|
| React/TypeScript five-view shell | Implemented: attacker, target, network, guide, evidence/report | TypeScript and Vite build executed locally; browser interaction tests are authored and run by CI when Chromium is available |
| v86 integration | Implemented with pinned `v86@0.5.472`, local firmware/WASM, real VGA/serial containers | **Verified in guest:** run `40067579565` booted both real guests to Ready |
| Attacker workstation | TinyCore 11.0 ISO remaster, X11, guest tool inventory, Dillo/terminal launchers | **Verified in guest:** graphical output plus curl/Dillo inventory passed in run `40067579565`; interactive launcher behavior is separate |
| Target housing | Alpine rootfs/initramfs, Apache prefork/mod_php, PHP 8.2.34 and optional 8.2.35 builds | **Verified in guest:** Alpine display, Apache/mod_php, and PHP 8.2.34 passed; optional 8.2.35 remains separate |
| Raw isolated networking | `inbrowser` ID 0, origin-wide exclusive Web Lock, concurrent labs refused, no default route/relay/NAT | **Verified in guest:** ICMP/HTTP and no default route passed; exclusive-channel/concurrent-session behavior remains implementation-reviewed |
| Readiness gate | Eight checks: two addresses, ICMP, listener, HTTP, headers, target access log, isolation | **Verified in guest:** 8/8 passed before Ready in run `40067579565` |
| Real browser/proxy traffic | Guest Dillo and Python RangeProxy, raw request editor/repeater, target-only destination | **Verified in guest:** run `40081439535` proved Dillo routing with interception ON/OFF, hold/edit/forward, independent Apache corroboration, and a separate edited POST Repeater exchange |
| Target logs and telemetry | Guest `labctl`, Apache/PHP log tails, `/proc` RSS/memory, PHP health/build identity | **Verified in guest:** fresh health, logs, memory, process, and PHP configuration passed in run `40067579565` |
| PHP memory semantics | Separate configured 128 MiB limit, Apache/mod_php RSS, and guest memory | Actual values and distinctions **verified in guest**; memory behavior under exploit load remains unverified |
| Per-session flag | Target `/dev/urandom` generation, target root writes `root:apache 0640`, digest-only client check, serial seal | Static/script checks executed; target filesystem permissions and reboot behavior **unverified** |
| RCE proof | Apache-owned challenge file with session mtime, then matching flag; no simulation credit | **No RCE reproduction or shell evidence has been obtained**; exact 32-bit reliability remains unverified |
| OOM research harness | Real streamed multipart probe with bounds and explicit no-RCE interpretation | Unit/static checks only; no OOM probe has run against the target |
| Snapshots | Paired v86 `save_state()` buffers, IndexedDB metadata, MAC translation, restore revalidation | Quota handling and real save/restore **unverified** |
| Report export | JSON/Markdown with evidence, logs, build identity, checksums, limitations | Unit-tested for truthfulness and content; browser download tested by Playwright when available |
| Offline shell | Production service worker plus verified IndexedDB asset cache | Service-worker/offline reload **unverified**; first cache requires local media/server |
| Parent controls during failure | Outside-canvas controls, cancellation, timeout handling, destructive confirmation | **Tested:** view switching and enabled Reset control passed during bounded proxy error handling in run `40081439535`; destructive reset and unrelated guest-crash behavior remain separately scoped |

## Tests actually executed in the current workspace

The following commands have run successfully after the latest controller edits at the time this document was written:

```text
npm run lint       — strict TypeScript project check
npm test           — 22 Vitest tests + 8 Python guest-tool tests
bash -n …          — shell syntax checks for build/boot/control scripts
python3 -m py_compile … — Python syntax compilation
```

`npm run build` completed successfully after the controller and UI edits. `npm run test:e2e` also completed locally: **4 Playwright tests passed** using a registry-packaged Chromium binary (persistent view containers, missing-image failure, report export, and narrow layout). This is browser-shell evidence, not guest-boot evidence. GitHub Actions results must be checked separately; a queued or completed image job is not a guest runtime test.

## Minimum real guest acceptance run

With verified images installed, perform and save evidence for the applicable scope. The current required CI gates cover steps 1–5 and preserve raw artifacts; a PASS there does not imply completion of steps 6–10.

1. Cold boot both guests; confirm real VGA/serial output and no missing/corrupt asset error.
2. Confirm `192.168.10.10/24` and `192.168.10.55/24` inside the respective guests.
3. Send attacker-originated ICMP and a uniquely marked HTTP request to `http://192.168.10.55/`; inspect actual target response headers/body and the matching Apache access-log entry.
4. Refresh target health, all three logs, Apache worker count/RSS, guest memory, PHP memory limit, and build hash. Keep the three memory concepts separate.
5. Run the real proxy acceptance: route Dillo through RangeProxy with interception ON/OFF, hold a unique request and prove target absence, edit and forward it, independently corroborate Apache, and exercise a separate Repeater request plus bounded failures/recovery. Preserve the per-gate JSON and raw evidence.
6. Save both states, restore them, and repeat network/service checks. Test quota failure handling with a deliberately constrained browser profile if possible.
7. Reboot each guest and verify that target provisioning/sealing and session proof invalidation behave as documented.
8. Run the bounded baseline/OOM research only in the isolated range. Record observed behavior without calling it RCE.
9. If genuine execution is established on the exact build, create the Apache-owned current-challenge proof through that execution context and submit the flag. Otherwise report RCE as unverified.
10. Cold-boot the PHP 8.2.35 comparison image and repeat applicable baseline/probe observations; do not describe this as patching the already-running vulnerable VM.

## Evidence labels

- **Implemented:** code/configuration exists and is identified by path.
- **Tested:** a named automated or manual test actually executed, with its result.
- **Verified in guest:** the cited output/file/process came from the running guest.
- **Limited:** a deliberate constraint such as no backend, proxy size cap, 32-bit profile, or browser quota.
- **Unverified:** no honest evidence yet. This remains the status for RCE and for capabilities without cited guest evidence.
