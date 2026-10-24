# Runtime architecture

```text
React parent UI (controls, vulnerability lab, guide)
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
- `storage.ts` stores verified assets, paired VM states, and exercise progress in IndexedDB.
- `VmScreen.tsx` keeps both v86 screen containers mounted while views are hidden, so navigation cannot destroy a running guest.
- `exercise.ts` is a pure model: it derives step status, unlock rules, build classification and
  probe interpretation from recorded facts. It never marks a step complete because a control was
  pressed; a control only records facts after real guest commands succeed.
- `cve.ts` holds the verified advisory constants, the first-fixed-release table and the
  allocator patch marker, each with its upstream provenance.

A generation change invalidates older asynchronous operations. Serial commands reject on teardown, and stale promises cannot clear a newer operation or patch a new session.

## Provisioning boundary

The target's serial getty initially provides a hidden root control login solely so the controller can provision the session. Echo is disabled while the challenge is sent. Target root generates the flag from `/dev/urandom`, writes it as `root:apache 0640`, stores the challenge, creates the session timestamp/marker, removes old proof, and returns only the flag's SHA-256 digest. The controller never sends or retains plaintext flag material. The seal contains Linux's boot ID: subsequent getty respawns in that boot use `lab-login`, while a genuine reboot permits the next provisioning cycle. The visible VGA console is always the unprivileged lab login.

The browser stores the flag digest for the CTF check and stores that digest with paired VM snapshots for a consistent restore. This is not an authorization boundary; it is a training exercise.

## Exercise and evidence boundary

Every gated step is backed by a real guest command; the parent never prints an assumed result:

1. reconnaissance reads `/health.php` over the guest network plus PHP CLI, `labctl telemetry`,
   `labctl build`, `ss -ltn`, and `stat` on the flag and `libphp.so`;
2. baseline sends three requests and requires each unique marker in the target's access log;
3. request analysis requires a decoded RangeProxy record *and* the matching Apache lines;
4. investigation classifies the build from the observed version and the `memory_hard_limit_percent`
   patch marker, and records each applicable condition with its observed value;
5. reproduction sends one bounded chunked multipart probe, then reads the target's PHP/error/access
   logs and worker state before and after;
6. target-side verification reads process state and attempts `labctl evidence`;
7. remediation compares the running build with the verified 8.2.35 diff and the advisory's
   mitigations, and states explicitly when the comparison image is not provisioned;
8. completion is derived only from an Apache-owned challenge proof plus the matching flag.

A probe outcome is recorded even when nothing interesting happens, and can never yield
`completedAs = "genuine-rce"`. The labelled simulation (a knowledge check answered from observed
values) is stored under `exercise.simulation` and `completedAs = "simulated-exercise"`; it performs
no target-side effect and never shows a fabricated shell.

The only genuine RCE completion path is:

```text
fresh target file owned by apache
+ exact current session challenge
+ mtime within the provisioned session
+ matching session flag submission
```

The controller does not award completion for OOM, HTTP 500, a version, a large Content-Length, a payload marker, or a simulated terminal message. Public exploit profiles for other architectures/builds are research references, not evidence for this target.

## Reset and recovery boundary

- **Reset exercise** cold-boots the target through v86, re-provisions it with a new session
  challenge, and requires the target to report a *different* flag digest and an absent previous
  proof before parent progress is cleared. The attacker guest keeps running.
- **Reset lab** destroys both emulators, clears session, flag, challenge, exercise facts and
  completion, and retains only cached assets and explicitly saved snapshots.
- **Check guest responsiveness** resumes a paused emulator and re-runs `labctl ready`; an
  unresponsive guest is rebooted through the same verified boot path.
