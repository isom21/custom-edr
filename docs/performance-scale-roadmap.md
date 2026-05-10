# Performance + scale roadmap (M15)

> **Status:** scaffolded. M15 ships the k6 load-test harness shape
> (M15.a) + roadmap. Real load testing + the multi-instance manager
> rework + HA infra changes follow as M15.b through M15.h once the
> M14 metrics surface lights up the bottlenecks.

## Substages

| Substage | What |
|---|---|
| **M15.a (this commit)** | k6 / Locust load test harness (`tools/loadtest/`) |
| M15.b | Real agent benchmarks (cycles/event, syscall overhead) — needs `perf stat` runs on lab-linux + ETW kernel-process on lab-windows |
| M15.c | Per-stage latency budget enforced as test assertions in CI |
| M15.d | Backpressure + circuit breakers throughout (M7.7 fixed gRPC→Kafka; do indexer→OS, sigma_realtime→percolator, normalizer→Kafka) |
| M15.e | Multi-tenant data partitioning via PG row-level security |
| M15.f | Horizontal scaling for gRPC ingest with consistent-hash leases |
| M15.g | HA dev infra (PG Patroni, OpenSearch 3-node, Kafka 3-broker) + recovery drill runbook |
| M15.h | Kubernetes Helm chart for the manager (test via `kind`) |

## Targets (from M14.e)

The load test in M15.a aims at:

- **100 concurrent agent gRPC streams**: each emitting 50 events/sec
  → 5k events/sec aggregate. Ingest latency p99 < 1s.
- **10 concurrent admin REST users**: 5 reqs/sec each → 50 req/sec.
  Per-route p99 < 250ms.
- **Detector + sigma_realtime**: 5k events/sec input → no Kafka lag,
  alert latency p99 < 5s end-to-end.

## Why these later substages and not now

- **HA infra** is operator-side work; the dev `docker-compose` already
  uses dev-grade single-node Postgres / OpenSearch / Redpanda. Real
  HA is a 1-2 week swap when a customer requires it.
- **Multi-tenant** needs an architectural decision (separate-DB vs
  PG RLS) that deserves its own ADR + customer-driven sizing.
- **Horizontal scaling** is a redis + leader-election rework; non-
  trivial.
- **k8s Helm chart** is the same "1-2 week" swap as HA; mostly YAML
  + minor manager config knobs.

## M15.a — Load test harness

`tools/loadtest/` ships a k6 script that:

1. POSTs `/api/auth/login` once to mint a JWT.
2. Hits a representative mix of read-heavy endpoints:
    - `GET /api/hosts` (paginated)
    - `GET /api/alerts` (paginated)
    - `GET /api/commands` (paginated)
    - `GET /api/me`
3. Records p50 / p95 / p99 latency, req/sec, error rate.

The companion `simulate-agent.py` (Python) opens N concurrent gRPC
streams, each emitting M events/sec, to exercise the ingest path.
Both run against the dev stack on localhost.

Output goes to `target/loadtest/<timestamp>.json`. The follow-up
M15.c CI integration reads this JSON and asserts against the M14.e
SLO targets.
