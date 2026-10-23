# Acceptance and evidence matrix

This file is deliberately conservative. “Implemented” means code/configuration exists; “tested” means the stated test actually ran; “verified in guest” requires output from the running guest. A build, version string, HTTP status, or static review is not a substitute for the last column.

| Capability | Implementation | Test/evidence status |
|---|---|---|
| React/TypeScript five-view shell | Implemented: attacker, target, network, guide, evidence/report | TypeScript and Vite build executed locally; browser interaction tests are authored and run by CI when Chromium is available |
| v86 integration | Implemented with pinned `v86@0.5.472`, local firmware/WASM, real VGA/serial containers | Runtime dual boot **unverified** in this workspace; no guest ISO was available locally |
| Attacker workstation | TinyCore 11.0 ISO remaster, X11, guest tool inventory, Dillo/terminal launchers | Image build and graphical boot **unverified** until CI artifact and v86 boot pass |
| Target housing | Alpine rootfs/initramfs, Apache prefork/mod_php, PHP 8.2.34 and optional 8.2.35 builds | Image build and Apache/PHP boot **unverified** until CI artifact and v86 boot pass |
| Raw isolated networking | `inbrowser`, random numeric ID, exclusive Web Lock, no default route/relay/NAT | Static implementation reviewed; real ICMP/ARP/HTTP and cross-session isolation **unverified** |
| Readiness gate | Eight checks: two addresses, ICMP, listener, HTTP, headers, target access log, isolation | No ready claim without all checks; actual guest execution **unverified** |
| Real browser/proxy traffic | Guest Dillo and Python RangeProxy, raw request editor/repeater, target-only destination | Python parser/framing tests executed; real guest-to-guest browser/proxy traffic **unverified** |
| Target logs and telemetry | Guest `labctl`, Apache/PHP log tails, `/proc` RSS/memory, PHP health/build identity | Shell syntax checked; live values and refresh behavior **unverified** |
| PHP memory semantics | Separate configured 128 MiB limit, Apache/mod_php RSS, and guest memory | Data sources implemented; actual numbers under load **unverified** |
| Per-session flag | Target `/dev/urandom` generation, target root writes `root:apache 0640`, digest-only client check, serial seal | Static/script checks executed; target filesystem permissions and reboot behavior **unverified** |
| RCE proof | Apache-owned challenge file with session mtime, then matching flag; no simulation credit | **No RCE reproduction or shell evidence has been obtained**; exact 32-bit reliability remains unverified |
| OOM research harness | Real streamed multipart probe with bounds and explicit no-RCE interpretation | Unit/static checks only; no OOM probe has run against the target |
| Snapshots | Paired v86 `save_state()` buffers, IndexedDB metadata, MAC translation, restore revalidation | Quota handling and real save/restore **unverified** |
| Report export | JSON/Markdown with evidence, logs, build identity, checksums, limitations | Unit-tested for truthfulness and content; browser download tested by Playwright when available |
| Offline shell | Production service worker plus verified IndexedDB asset cache | Service-worker/offline reload **unverified**; first cache requires local media/server |
| Parent controls during failure | Outside-canvas controls, cancellation, timeout handling, destructive confirmation | Controller code reviewed and type-checked; frozen/crashed guest behavior **unverified** |

## Tests actually executed in the current workspace

The following commands have run successfully after the latest controller edits at the time this document was written:

```text
npm run lint       — strict TypeScript project check
npm test           — 14 Vitest tests + 8 Python guest-tool tests
bash -n …          — shell syntax checks for build/boot/control scripts
python3 -m py_compile … — Python syntax compilation
```

`npm run build` completed successfully after the controller and UI edits. `npm run test:e2e` also completed locally: **4 Playwright tests passed** using a registry-packaged Chromium binary (persistent view containers, missing-image failure, report export, and narrow layout). This is browser-shell evidence, not guest-boot evidence. GitHub Actions results must be checked separately; a queued or completed image job is not a guest runtime test.

## Minimum real guest acceptance run

With verified images installed, perform and save evidence for:

1. Cold boot both guests; confirm real VGA/serial output and no missing/corrupt asset error.
2. Confirm `192.168.10.10/24` and `192.168.10.55/24` inside the respective guests.
3. Send attacker-originated ICMP and HTTP requests; inspect actual target response headers/body and matching Apache access-log entries.
4. Open Dillo to the portal and RangeProxy management UI; forward and edit a real request, then import its raw evidence.
5. Refresh target health, all three logs, Apache worker count/RSS, guest memory, PHP memory limit, and build hash. Keep the three memory concepts separate.
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
- **Unverified:** no honest evidence yet. This is the default for dual boot and RCE in the current workspace.
