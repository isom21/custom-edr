# Observability + operations roadmap (M14)

> **Status:** scaffolded. M14 ships a Prometheus `/metrics` endpoint
> on the manager (M14.a) + the substage roadmap. The remaining items
> (agent-side Prometheus exporter, OpenTelemetry tracing, Grafana
> dashboards, SLO definitions, capacity model, runbooks) sequence as
> M14.b through M14.h.

## Substages

| Substage | Component | What |
|---|---|---|
| **M14.a (this commit)** | Manager | `/metrics` endpoint with built-in counters (request_total, request_latency_seconds, active_grpc_streams, kafka_produce_total, opensearch_index_total) |
| M14.b | Agent | Prometheus exporter on the agent, scraped by a sidecar or Prometheus federation |
| M14.c | All | OpenTelemetry tracing end-to-end (agent → gRPC → Kafka → normalizer → indexer → OpenSearch / Sigma → alert) |
| M14.d | Operator | Reference Grafana dashboards (manager request rate, alert latency, Kafka lag, OpenSearch ingest, agent fleet health) |
| M14.e | Operator | SLO definitions + burn-rate alerts (ingest p99 < 1s, detection p99 < 5s, agent uptime > 99.9% per-fleet) |
| M14.f | Operator | Capacity planning model (events/sec/host × host_count → infra sizing) |
| M14.g | Operator | Runbooks (`docs/runbooks/`) for the top-5 incident classes |
| M14.h | Manager | Crash-report endpoint + storage (M9.3 follow-up; sized here once we have the metrics surface) |

## M14.a — Manager `/metrics` (this commit)

**Goal**: Prometheus can scrape the manager and the operator can see
request rate, latency, and resource pressure without instrumenting
each handler manually.

**What ships**:

- `prometheus-client` Python lib added to `[dev]` (the `Counter` /
  `Histogram` types are tiny and zero-dependency).
- `app.core.metrics` exposes singletons:
    `requests_total{method,route,status}` — Counter
    `request_latency_seconds{method,route}` — Histogram
    `grpc_active_streams` — Gauge
    `kafka_produce_total{topic}` — Counter (wired into `app.services.kafka`)
- A FastAPI middleware records request metrics (similar shape to
  `RateLimitMiddleware`).
- New `/metrics` route in `app.api.metrics` returns the
  prometheus-format text.

**Bypass**: `/metrics` itself is exempt from rate-limiting (Prometheus
scrapes every 15s; would otherwise eat the anonymous bucket).

**Auth**: `/metrics` is unauthenticated *and* binds to localhost only
in production. The manager-side LB / ingress is responsible for
exposing it to the Prometheus scraper, not the public.

## What M14.a does NOT cover yet

- Agent-side metrics: that's M14.b. The agent already populates
  `AgentMetrics` on every Heartbeat (M9.4 schema), so the manager
  can render a fleet view without extra work; a true Prometheus
  exporter on the agent (so external scrapers can hit it) is
  separate.
- OpenTelemetry tracing: M14.c. Worth doing once we have a real
  Jaeger / Tempo / SigNoz on the dev stack.
- Grafana dashboards: M14.d. We ship them as JSON in
  `deploy/grafana/dashboards/` once we have stable metric names.

## SLOs to land in M14.e

These are the contractual targets that future M19 customer SLAs
attach to:

| SLO | Target | Measurement |
|---|---|---|
| Telemetry ingest end-to-end latency | p99 < 1s | OpenSearch `@timestamp` − agent emit time |
| Detection latency | p99 < 5s | alert `opened_at` − triggering event `@timestamp` |
| Manager API availability | 99.9% / month | request_total{status<500} / request_total |
| Agent fleet uptime | 99.9% per host / month | `last_seen_at` gap analysis from `audit_log` |
| Command dispatch latency | p99 < 2s | command `dispatched_at` − `created_at` |

Burn-rate alerts at 2% / 5% / 10% over 1h / 6h / 1d windows; pages
through whatever PagerDuty-equivalent the operator runs.
