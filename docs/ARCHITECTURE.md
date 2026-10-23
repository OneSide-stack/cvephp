# Runtime architecture

```text
React parent UI (controls, report, guide, evidence)
        │ serial commands / v86 API / verified local buffers
        ├── v86 attacker ── Tiny Core X11 ── Dillo/curl/RangeProxy/exploit.py
        │        192.168.10.10/24                  │
        │             raw NE2000 Ethernet           │ real HTTP socket
        │             session BroadcastChannel      │
        └── v86 target ─── Alpine/OpenRC ─── Apache prefork + mod_php
                 192.168.10.55/24                  │
                                      custom PHP app, logs, /proc telemetry
```

The parent never implements guest HTTP, PHP, process, memory, or shell behavior. It sends commands over each guest's real serial shell and parses their output. Command markers provide framing only; they do not create the command's result.

## Controller boundaries

- `LabController.ts` owns generation IDs, lifecycle, network locks, provisioning, readiness, telemetry, evidence, and snapshots.
- `SerialChannel.ts` serializes real commands, captures actual output, and cancels pending operations on teardown/reboot.
- `assets.ts` accepts only local pinned paths and verifies exact length/SHA-256 before use.
- `storage.ts` stores verified assets, paired VM states, and a historical report in IndexedDB.
- `VmScreen.tsx` keeps both v86 screen containers mounted while views are hidden, so navigation cannot destroy a running guest.
- `report.ts` exports observations and limitations; it does not infer completion from payload markers or status strings.

A generation change invalidates older asynchronous operations. Serial commands reject on teardown, and stale promises cannot clear a newer operation or patch a new session.

## Provisioning boundary

The target's serial getty initially provides a hidden root control login solely so the controller can provision the session. Echo is disabled while the challenge is sent. Target root generates the flag from `/dev/urandom`, writes it as `root:apache 0640`, stores the challenge, creates the session timestamp/marker, removes old proof, and returns only the flag's SHA-256 digest. The controller never sends or retains plaintext flag material. The seal contains Linux's boot ID: subsequent getty respawns in that boot use `lab-login`, while a genuine reboot permits the next provisioning cycle. The visible VGA console is always the unprivileged lab login.

The browser stores the flag digest for the CTF check and stores that digest with paired VM snapshots for a consistent restore. This is not an authorization boundary; it is a training exercise.

## Evidence boundary

The only genuine RCE completion path is:

```text
fresh target file owned by apache
+ exact current session challenge
+ mtime within the provisioned session
+ matching session flag submission
```

The controller does not award completion for OOM, HTTP 500, a version, a large Content-Length, a payload marker, or a simulated terminal message. Public exploit profiles for other architectures/builds are research references, not evidence for this target.
