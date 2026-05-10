# Telemetry roadmap (M10 + later)

> **Status:** scaffolding. M10 ships the design + the SHA-256 hashing
> on Linux `file_open` (high-impact, low-cost). The other probes here
> are sequenced as M10.b through M10.h, each its own focused commit.

The PoC's M0–M7 telemetry covers process / file / network / module on
both Linux and Windows. M10 closes the remaining gaps that real EDR
products ship by default.

## What's already in place (M0–M7)

| Surface | Linux | Windows |
|---|---|---|
| Process create / exit | ✅ tracepoint sched_process_* (M6.2) | ✅ KMDF Ps-callback (M4.2) + ETW (M2.3c fallback) |
| File open | ✅ lsm/file_open (M6.3) | ✅ minifilter IRP_MJ_CREATE (M4.3) |
| Network connect | ✅ lsm/socket_connect (M6.4) | ✅ WFP ALE_AUTH_CONNECT (M4.7) |
| Module / image load | ✅ tracepoint:module:module_load (M6.x) | ✅ PsSetLoadImageNotifyRoutine (M4.2) |
| Registry | n/a | ✅ CmRegisterCallbackEx (M4.4) |
| Block exec / file open | ✅ lsm/bprm_check_security + lsm/file_open EPERM (M6.6) | ✅ Driver block-list (M5.2) |

## What's missing

| Surface | Linux probe | Windows probe | Substage |
|---|---|---|---|
| File hashing (SHA-256 on open) | background thread + Bloom cache | same | **M10.a (fully wired in this commit)** |
| DNS query observation | `lsm/socket_sendmsg` parse / kprobe `udp_sendmsg` | ETW DNS-Client provider | M10.b |
| AMSI (script content, .NET) | n/a (Linux equivalent: `lsm/bpf_check` for in-kernel, plus auditd execve buffer) | AMSI provider DLL | M10.c |
| Auth events | PAM hook (`pam_edr.so` → unix socket → agent) | Security event log forwarding via `wevtutil` | M10.d |
| USB events | udev netlink subscription | SetupAPI + WMI Win32_PnPEntity events | M10.e |
| Memory scanning (YARA) | `/proc/<pid>/mem` reads, scheduled | `OpenProcess(VM_READ)` + YARA-X | M10.f |
| Persistence inventory | systemd timers, cron, /etc/init.d, .bashrc/.profile, .ssh/authorized_keys writes | scheduled tasks, Run/RunOnce, services, WMI subscribers | M10.g |
| ETW Threat Intelligence | n/a | Microsoft-Windows-Threat-Intelligence subscription | M10.h |
| macOS endpoint | Endpoint Security framework client | n/a | M10.i |
| Container / K8s | DaemonSet with eBPF in privileged pod | n/a | M10.j |

## Per-substage shape

Each substage lands in three pieces:

1. **Probe code** — kernel-side hook (BPF C, ETW provider subscription, AMSI DLL, etc.) producing events into the existing ringbuf / drainer.
2. **Wire schema** — extend `proto/edr/v1/events.proto` with the new `Endpoint*Event` payload variant if the existing schema doesn't fit.
3. **Normalizer pass** — ECS mapping in `app/services/normalizer.py` so the event lands in `telemetry-*` with consistent field names.

The ringbuf, drainer, gRPC stream, Kafka topic, OpenSearch index, RBAC scoping, and alerting pipeline are **all unchanged** — every new probe slots into the existing plumbing.

## M10.a — Linux file hashing (this commit)

**Goal**: every `file_open` event for a *new path* (not in the per-host cache) carries a SHA-256 of the file's contents. Existing alerts and Sigma rules can match on the hash without an extra IOCTL or reqwest hop.

**Design**:

- The eBPF `lsm/file_open` hook stays observation-only (we already enrich with path resolution).
- A new userspace background thread wakes for each emitted file_open event whose path is *not* in a Bloom-filter cache.
- The thread reads the file (capped at 64 MiB, mmap'd), computes SHA-256, populates a small LRU cache, and ships a `FileHashEvent` (or augments the existing `FileEvent` if the upstream protobuf has a `hash` field — it does: `FileEvent.hash`).
- The Bloom filter is sized for ~1M unique paths with 1% FPR (~9.6 Mbit ≈ 1.2 MB). On overflow we rotate.
- Cache entries TTL out after 1 hour (catches binary updates).

**Performance budget**: SHA-256 on a 5 MB binary takes ~10 ms on modern hardware; for 1000 file opens/sec with 90% cache hits, the hashing thread does ~100 hashes/sec at ~10 ms each → 100% of one core in the worst case. Acceptable; the thread is below `nice 19` and pinned away from the BPF drainer.

**Out of scope for M10.a**: integrity verification (signed-binary check), entropy-based packed-binary detection, hash blocklist (M11 covers IOC matching against hashes).

## M10.b – M10.j — Sequenced

Each substage is independent and can be picked up by any future session. They share the M10.a's drainer / gRPC / normalizer plumbing; only the probe layer changes.

Recommended order (highest-marginal-value first):

1. **M10.a** Linux file hashing (this commit)
2. **M10.b** Linux DNS via `lsm/socket_sendmsg`
3. **M10.c** Windows AMSI provider — biggest single coverage gap on Windows
4. **M10.d** Auth events (PAM + Security event log) — highest-value for incident response
5. **M10.e** USB events
6. **M10.f** YARA memory scanning
7. **M10.g** Persistence inventory
8. **M10.h** ETW Threat Intelligence
9. **M10.i** macOS agent
10. **M10.j** Container / K8s

## What's NOT in M10

- Plaintext-before-TLS visibility (Schannel hooks on Windows). Tracked
  as a separate future project per `SESSION_HANDOFF.md` §1.
- Network packet capture (full pcap). The 5-tuple + process attribution
  we have today is enough for ATT&CK detection coverage; pcap adds
  storage cost and privacy concerns disproportionate to detection
  signal.
- eBPF for tracking credential-theft on Linux (LSASS-equivalent
  Mimikatz). Linux doesn't have a centralized credential store; the
  closest signal is `ptrace` of `kernel-keyring` services, which is
  niche. Not in scope.
