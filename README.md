# Enterprise Cyber Range
## CVE-2026-109618 (PHP2Shell) Dual-OS Simulation

A responsive React/TypeScript control panel for **two genuine x86 guests running in v86 in the browser**. It is an isolated training range, not a JavaScript desktop, a canned exploit animation, or a hosted exploitation API.

> **Current verification boundary:** the frontend, guest-tool unit tests, shell checks, and production bundle can be tested without guest media. The large guest ISOs are intentionally not committed. A successful bundle or image build is not evidence of dual boot, HTTP reachability, snapshot restoration, or RCE. See [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md) for the evidence matrix and [docs/IMAGES.md](docs/IMAGES.md) for provisioning.

## What is implemented

- **Attacker workstation:** Tiny Core Linux 11.0 x86 graphical ISO, `192.168.10.10/24`, X11, Dillo, curl, Python research harness, nano/vi, and a real guest-side RangeProxy. The inventory is reported by `command -v` inside the guest; launchers are not shown for absent binaries.
- **Assessment target:** Alpine Linux x86, `192.168.10.55/24`, Apache prefork with source-built mod_php. PHP 8.2.34 is the vulnerable-source profile; PHP 8.2.35 is a separately built patched comparison profile. The web application is a custom training portal, not WordPress.
- **Real guest I/O:** v86 VGA and serial displays, guest shell commands, guest-originated HTTP, Apache/PHP log reads, `/proc` memory and process telemetry, and guest-side evidence files.
- **Lifecycle:** cold boot, hardware reboot, stop, reset, paired v86 state snapshots, restore with MAC translation, and post-restore readiness/network checks.
- **Evidence/report:** request/response and proxy artifacts, log tails, build identity, checksums, telemetry sources, JSON export, Markdown export, and explicit incomplete/unverified states.

## Requirements

For the browser lab:

- A current desktop Chrome, Edge, or Firefox with WebAssembly, BroadcastChannel, IndexedDB, and Web Locks.
- A static web server for this repository's built application. There is no application backend.
- Enough memory for two guests plus the browser/WASM runtime. The UI's standard allocation is **384 MiB attacker + 512 MiB target**; lower mode is **256 MiB + 384 MiB**. These figures do not include browser overhead.
- The pinned runtime files and guest images described below. Missing or corrupt required media fails closed.

For reproducible image builds:

- Linux with Docker, 32-bit x86 build support, curl, Python 3, Node 22+, and enough disk/time for two PHP source builds.
- Internet access **at image-build time only** for pinned source/media downloads. Neither guest downloads packages or uses a relay when the lab starts.

## Install and run the control panel

```sh
npm ci
npm run assets:runtime
npm run dev
```

The Vite server binds to `0.0.0.0`. Open the displayed local/preview URL, read **Lab Guide**, then use **Start lab**. The initial source checkout does not contain the ISOs, so startup is expected to show a visible missing-image error until they are provisioned; no substitute desktop is displayed.

Production bundle:

```sh
npm run build
npm run preview
```

`public/v86/` contains the pinned v86 WASM and firmware generated from the locked npm package. `public/lab-assets/manifest.json` is schema 1 and records byte lengths and SHA-256 digests. The browser verifies every loaded asset again before constructing a VM.

## Provision the guest images

The ISOs are excluded from Git because of their size. Build them with:

```sh
# From the repository root; Docker and build-time internet are required.
bash image-build/build-all.sh
```

Or build individually:

```sh
bash image-build/build-attacker.sh
bash image-build/build-target.sh 8.2.34 target-php-8.2.34.iso
BUILD_PATCHED=1 bash image-build/build-target.sh 8.2.35 target-php-8.2.35.iso
node scripts/generate-asset-manifest.mjs
node scripts/verify-assets.mjs
```

The expected output files are:

```text
public/lab-assets/attacker-tinycore-11.0.iso
public/lab-assets/target-php-8.2.34.iso       # required
public/lab-assets/target-php-8.2.35.iso       # optional comparison
```

The GitHub Actions **Build reproducible guest images** workflow produces the `cyber-range-guest-images` artifact. Download the artifact from a successful run and place its files at the same paths, then run `npm run assets:verify`. Do not use an unverified third-party image as a substitute.

See [docs/IMAGES.md](docs/IMAGES.md) for source pins, build details, and troubleshooting.

## Network and isolation contract

Both v86 instances use `net_device: { relay_url: "inbrowser", type: "ne2k" }`. The controller allocates a random numeric network ID per start/restore and holds an exclusive same-origin Web Lock named `enterprise-cyber-range-network-<id>`. v86 therefore uses a session-specific raw-Ethernet BroadcastChannel.

- No NAT, host LAN bridge, Internet gateway, public relay, `wsproxy`, Wisp, or fetch relay is configured.
- Both guest boot scripts remove default routes and configure only the `192.168.10.0/24` segment.
- Startup refuses to boot if Web Locks are unavailable or an exclusive identifier cannot be obtained.
- Readiness requires actual attacker/target addresses, ICMP, a target port-80 listener, an attacker-originated HTTP 200 with headers, a matching target access-log entry, and isolation checks.
- Restores use v86 state images and MAC translation, then repeat readiness and network checks. A saved state is not treated as proof that its network still works.

Browser isolation is not a host-security certification. Run untrusted research only in an appropriately isolated lab environment.

## Attacker tooling and evidence

RangeProxy is a small Python 3.6+ standard-library HTTP training proxy, **not Burp Suite**. It listens inside the attacker on `127.0.0.1:8080` and its management UI on `127.0.0.1:8081`. It accepts only plain HTTP for `192.168.10.55:80`, validates Host authority and framing, preserves editable raw requests, forwards them through a real socket, and stores request/response evidence. It refuses ambiguous Content-Length/Transfer-Encoding combinations and oversized editor requests. Dillo's only proxy exception is the proxy's own loopback management UI; the target is not exempted.

The guest research harness is `~/exploit.py`:

```sh
python3 ~/exploit.py baseline
python3 ~/exploit.py oom-probe --mib 16
# Disruptive larger probes require an explicit acknowledgement:
python3 ~/exploit.py oom-probe --mib 160 --i-understand-oom
```

The OOM probe is a bounded multipart/request-processing investigation, **not a portable RCE exploit**. It records transport/output observations and always sets `rce_claimed: false`. A version string, `Content-Length >= 134217728`, HTTP 500, OOM text, a payload marker, or a worker exit is not RCE evidence.

## Target telemetry and completion

The Target Server Housing view distinguishes:

- `memory_limit`: the PHP configuration ceiling (planned profile: **128 MiB / 134217728 bytes**), not current consumption.
- Apache/mod_php aggregate RSS from target `/proc/<pid>/status`, including Apache and loaded modules.
- Guest OS memory from target `/proc/meminfo` (`MemTotal - MemAvailable`).
- Actual Apache process count/state, PHP version/SAPI, worker PID, and `libphp.so` SHA-256.

A per-session flag is generated inside the target from `/dev/urandom` during provisioning and written by target root as `root:apache 0640`. Only its SHA-256 digest crosses the hidden serial channel; the plaintext flag is never embedded in frontend source or retained by the controller. The target serial login is then sealed to the unprivileged `lab` user using a boot-ID-bound marker. The browser retains the digest for the CTF check.

Completion requires **both**:

1. A fresh target-resident `/var/www/html/rce-proof.txt` owned by `apache`, containing the current session challenge and with a modification time within the provisioned session.
2. The matching session flag submitted through the client-side CTF mechanism.

The guide shows commands to run only through a genuinely established execution context. The application does not provide a special proof endpoint, and a simulated completion path is not offered. Client-side flag checking is a learning mechanism, not an authorization control.

## Snapshots and resets

**Save state** calls v86 `save_state()` for both running guests and stores the paired buffers, session metadata (including the flag digest, never its plaintext), and resource mode in IndexedDB. Quota/transaction failures are shown and no partial pair is called saved. Restores use fresh network IDs, MAC translation, and real readiness/network checks. Saving is limited to verified, sealed running sessions.

Reboot uses v86 hardware restart, reprovisions the target, removes old target proof, and repeats verification. Stop/reset controls live outside the guest canvas and remain available during guest timeouts. Destructive actions with unsaved progress require confirmation. Evidence export is separate from VM state snapshots.

## Tests and CI

```sh
npm test                 # Vitest + Python standard-library guest-tool tests
npm run lint             # strict TypeScript project check
npm run build            # runtime preparation + TypeScript + Vite production build
npm run test:e2e         # Playwright browser shell/missing-image acceptance tests
npm run test:e2e:guest   # Opt-in real checksummed dual-guest acceptance
```

The frontend workflow runs unit tests, guest-tool tests, the production build, and browser acceptance tests with a pinned registry-packaged Chromium (avoiding a runtime CDN dependency). The image workflow builds and verifies the ISO artifacts, then runs the opt-in real dual-guest suite when those artifacts exist. Browser shell tests cover navigation/persistent VM containers, visible missing-image failure, resource selection, report export, and narrow layouts; they do not prove guest boot without provisioned media. The guest suite additionally exercises real serial, network, HTTP, telemetry, proxy evidence, and report export.

For real acceptance, boot both images and record the checks in [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md). Do not mark RCE reproduced without fresh target-side execution evidence on the exact 32-bit build.

## Source and provenance notes

- v86 runtime: npm `v86@0.5.472`; upstream source reviewed at `cc37f35c43bf14865d74ad76879ecf9410f69eb1`.
- PHP sources: official `php/php-src` tags with SHA-256 pins in `image-build/target/php-source.sha256`.
- Alpine media: official release ISO plus its published SHA-256, downloaded during the image build.
- Tiny Core 11.0 base media: the publisher's current directory no longer carries 11.0. The build uses an immutable GitHub blob at commit `9be9b5f435281dc7d78467131dbc1b77e10a8198` (retrieved through the GitHub raw-blob API) and requires SHA-256 `778fc3788d9df3de72970827968b2b195aca827401db6f6f9cbdb737d4300bda`. This is a provenance/compatibility pin, not a claim of independent security audit.
- Vulnerability reference: [official PHP advisory GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w). Public exploit notes for other builds/architectures are not transferable proof for this target.

## License and safety

This is intentionally vulnerable training software for a private, isolated range. Do not expose the target, proxy, images, or a hosted instance to an untrusted network. Review the v86, Tiny Core, Alpine, Apache, PHP, and package licenses when redistributing built media.
