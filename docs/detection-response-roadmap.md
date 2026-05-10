# Detection + response roadmap (M11)

> **Status:** scaffolded. M11 ships the curated-rules directory layout
> + 5 reference Sigma rules + the network-isolation response action
> wired end-to-end on Linux (nftables ruleset + agent IOCTL ↔ proto
> command). The remaining detection + response items (anomaly
> detection, FP feedback loop, two-person approval, file quarantine,
> memory dump) sequence as M11.b through M11.h.

## Detection — current state vs target

What M3.5 + M11 covers:

| Capability | Status |
|---|---|
| Sigma realtime via OpenSearch percolator | ✅ M3.5 |
| Sigma scheduled (count-of, time-window aggregations) | ✅ M3.2 (kept post-M3.5) |
| IOC matching (sha256, md5, sha1, filename, filepath) | ✅ M3.1 + M5.5 auto-action |
| Curated rule pack (top 20 ATT&CK techniques) | scaffold only — `backend/sigma_rules/` with 5 reference rules |
| ATT&CK technique mapping on alerts | scaffold — alert payload carries `technique_id`; UI surfaces it |
| Anomaly detection (per-host process baselines) | M11.b |
| False-positive feedback loop (mark-FP → adjust rule weight) | M11.c |
| IOC feed integration (MISP / OpenCTI) | M11.d |
| Detection-as-code (PR-driven rule reviews + corpus runs) | M11.e |

## Response — current state vs target

| Action | Status |
|---|---|
| Kill process | ✅ M5.1 |
| Block process / file (path-based) | ✅ M5.2 + M6.6 |
| Auto-action queue from rule match | ✅ M5.5 |
| Network isolation | **fully wired in this commit (M11.a)** |
| File quarantine | M11.f |
| Memory dump on demand | M11.g |
| Process tree termination | M11.b sub-task |
| Persistence removal (surgical autorun cleanup) | M11.h |
| Two-person approval workflow | M11.i |
| Action rollback for blocks | trivial UI work; M17 |

## M11.a — Network isolation (this commit)

**Goal**: when an alert prompts an `isolate` response, the agent flips
the host's outbound firewall to deny everything except the manager
endpoint + DNS + NTP. Reverses on `unisolate`.

**Linux**: nftables ruleset:

```
table inet edr-isolation {
    chain output {
        type filter hook output priority 0;
        # Whitelist: agent's own gRPC + DNS + NTP.
        ip daddr <manager_ip> tcp dport 50051 accept
        udp dport 53 accept
        udp dport 123 accept
        # Loopback always allowed.
        oifname "lo" accept
        # Default deny.
        counter drop
    }
}
```

The agent applies/removes the ruleset via `nft -f -` (no shelling out
to a separate isolation daemon — agent already has CAP_NET_ADMIN per
the M7.3 systemd unit). State is persisted via `{state_dir}/isolated`
sentinel file so reboot reapplies.

**Windows**: WFP filters at the same layer the network-connect events
are observed. M11.a-win lands separately (similar pattern, different
syscall surface).

## M11.b — Anomaly detection (per-host baselines)

Lightweight stats-based: maintain a rolling 7-day count of
`(host_id, process.executable, parent.executable)` triples. Alert when
a triple is observed for the first time AND the parent isn't a known
launcher (systemd, init, cron, etc.). Pure SQL/Python; no ML libs
needed. New worker
`backend/app/workers/anomaly.py` consuming `telemetry.normalized`.

## M11.c – M11.h

Each is a focused commit; details in this doc to keep them aligned
with the existing pipeline.

## Curated rule pack (`backend/sigma_rules/`)

Five reference rules ship in M11 covering the broadest ATT&CK
techniques:

| File | Technique | What |
|---|---|---|
| `t1059_001_powershell_encoded.yml` | T1059.001 | base64-encoded PowerShell command line |
| `t1059_004_unix_shell_curl_pipe_sh.yml` | T1059.004 | `curl ... \| sh` (download + execute pattern) |
| `t1003_001_lsass_access.yml` | T1003.001 | non-Microsoft process opening LSASS |
| `t1547_001_run_key_write.yml` | T1547.001 | registry write to HKCU/HKLM Run / RunOnce |
| `t1053_005_scheduled_task_create.yml` | T1053.005 | schtasks.exe / Register-ScheduledTask |

Operators add their own rules; the pack is a safe minimum, not a
complete ruleset. A real production deployment overlays SigmaHQ rules
+ the operator's tuned rules + IOC feeds (M11.d).
