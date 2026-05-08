# ADR 0005 — Sigma evaluation: realtime via OpenSearch percolator

- **Status:** Accepted (supersedes the scheduled-correlation decision in [ADR 0004](0004-sigma-scheduled-correlation.md); the rationale in 0004 for not using Flink remains valid)
- **Date:** 2026-05-08

## Context

ADR 0004 chose periodic OpenSearch correlation as the Sigma evaluation engine. The implementation worked end-to-end in M3.2, but the resulting **detection latency is ~30–60s** (one tick + one indexing-lag window). For the kill/block response actions arriving in M5, that's far too slow — the malicious process has already done its work by the time the alert lands.

We considered two ways to drop the latency without giving up on pySigma's mature OpenSearch backend:

1. **OpenSearch percolator** — a built-in OS feature where queries are indexed (in a `percolator`-typed field) and incoming documents are matched against all registered queries in one round-trip.
2. **Lucene-in-process via `luqum`** — parse the Lucene query produced by pySigma and walk it against a Python dict in the worker process.

`luqum` evaluation would be sub-millisecond per event but doesn't reproduce OpenSearch's analyzer chain (case folding, tokenization, etc.), so test results in the UI ("how many matches in the last 24h?") would diverge from realtime matches. The percolator does reproduce OS semantics exactly because it *is* the same engine.

## Decision

Sigma rules are evaluated in realtime by a Kafka consumer (`app/workers/sigma_realtime.py`) that calls OpenSearch's percolate API once per ECS event.

Concretely:

- A new index `sigma-rules` holds one document per registered Sigma rule. The doc has a `query` field of type `percolator` containing `{"query_string": {"query": "<lucene>"}}`. The doc id is the rule's PG UUID.
- `app/api/rules.py` registers/unregisters in `sigma-rules` on every Sigma rule create / update / delete and on enabled flag toggles. Best-effort; the worker's startup sync recovers from any drift.
- `sigma_realtime` consumes `telemetry.normalized` (the same topic indexer + IOC detector consume), and for each event posts `POST /sigma-rules/_search` with a `percolate` query whose `document` is the ECS dict. Matched rule_ids come back; one Alert row is written per match.
- On startup, the worker reconciles `sigma-rules` with PG: registers every enabled Sigma rule, removes any percolator doc whose `rule_id` is no longer enabled or no longer exists. This handles the case where rule lifecycle hooks failed silently (OS unreachable when the rule was saved).

Field mappings on `sigma-rules` mirror `telemetry-*` exactly (same `_SHARED_PROPERTIES` block in `services/opensearch.py`), so percolator queries reference identically-mapped fields and don't drift from the live event shape.

## Rationale

- **No new dependency.** Percolator is a built-in OpenSearch feature; we already run OpenSearch.
- **Same query as the test path.** `POST /api/sigma/rules/{id}/test` runs the same Lucene query against historical telemetry; the realtime engine uses the same compiled Lucene against new events. UI test results and realtime alerts can never diverge on rule semantics.
- **Single round-trip per event.** Latency is dominated by Kafka delivery + one OS RTT (~10–50ms typical). End-to-end measured at ~1.1s in WSL — bottleneck is the Linux agent's 1s `/proc` poll, not the Sigma path.
- **Aggregation rules still possible.** The legacy `sigma_scheduler` worker is preserved (`make backend-sigma-scheduled`) for `condition: count(...) by user near 1m` style rules that don't fit a per-document model.

## Trade-offs

- **OpenSearch is on the hot path.** Every telemetry event becomes a search query against `sigma-rules`. With N rules and E events/sec, OS sees E searches/sec; each search internally evaluates against ≤N percolator docs. Practical capacity on a single-node dev OS is hundreds-to-low-thousands of events/sec. For higher throughput, scale OS or shard `sigma-rules`.
- **Refresh delay on rule registration.** New / updated rules become percolator-visible after the index's `refresh_interval` (1s for `sigma-rules`). The api hook uses `refresh="wait_for"` so the API call doesn't return until visibility — keeps the test endpoint and the realtime engine consistent.
- **No native dedup across restarts.** If the worker crashes and replays Kafka offsets from before the crash, percolator hits will re-emit alerts. Acceptable for now; M5 will key alerts by `(rule_id, event_id)` to dedupe.
- **Aggregation rules don't fit.** Time-window or count-of conditions need a different evaluator. We keep the scheduler available; if those rules become important, we'd add a small streaming aggregator (Materialize, Faust, or a custom counter) that publishes synthetic events into `telemetry.normalized` for downstream rules to percolate against.

## Alternatives considered

- **`luqum` in-process** — rejected because it diverges from OS analyzer semantics. Sub-millisecond eval is attractive, but UI/realtime drift is a real correctness/operability risk.
- **Stay on scheduled correlation** — rejected. The 30–60s latency is incompatible with M5 response actions.
- **Push percolator to a per-host index per agent** — rejected. Tens to hundreds of agents = tens to hundreds of small indices, no benefit for our scale.
- **Split rules into "fast" (percolator) and "slow" (scheduled) by feature usage** — already implicit. Default is realtime; aggregation rules go to scheduler if/when added.

## Consequences

- `make backend-sigma` now starts `sigma_realtime`. The previous scheduler is `make backend-sigma-scheduled`.
- Detection latency for per-event Sigma rules drops to ~1s end-to-end on Linux (agent poll-bound; lower with eBPF in M6).
- Rule editing in the UI is now load-bearing on OpenSearch availability — saving a rule does an OS write. Failure is logged but not fatal; the worker re-syncs on startup.
- The `alerts.raw` Kafka topic remains unused. We keep the partition layout in case a future engine needs it.
- Verified end-to-end in WSL: rule created → percolator doc visible in 1s → agent spawns process → alert in PG at t+1108ms (vs t+~43000ms for the scheduler).
