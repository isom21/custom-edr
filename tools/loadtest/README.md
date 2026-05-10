# Load tests

M15.a harness. Two pieces:

| File | What |
|---|---|
| `rest.k6.js` | Manager REST surface — auth + read-heavy endpoints, asserts p99 < 250ms |
| `simulate-agent.py` | (M15.b follow-up) gRPC ingest simulator: N parallel agent streams, M events/sec each |

## Running the REST load test

```bash
# Install k6 (one-time): https://k6.io/docs/get-started/installation/
sudo apt install k6
# (or via Docker: docker run --rm -i --network host grafana/k6 run - <rest.k6.js)

# Bring up the dev stack as usual.
make backend-dev

# Run with 10 virtual users for 30s.
k6 run --vus 10 --duration 30s tools/loadtest/rest.k6.js

# CI-style: fail the run if SLOs are missed.
BASE=http://localhost:8000 \
EMAIL=admin@example.local \
PASSWORD=change-me-please-12chars \
k6 run --vus 50 --duration 2m \
  --summary-trend-stats="p(50),p(95),p(99),max" \
  tools/loadtest/rest.k6.js
```

`k6` returns non-zero if any threshold is breached (p99 > 250ms or
error rate > 1%). CI integration is M15.c follow-up.

## Output

By default k6 prints a summary to stdout. Pipe to JSON for archival:

```bash
k6 run --out json=target/loadtest/$(date +%s).json tools/loadtest/rest.k6.js
```

## What's NOT here yet

* gRPC ingest simulator — M15.b. Today the only ingest exercise is
  the smoke test (1 agent, real lab-linux).
* Sigma percolator stress — M15.b extends the agent simulator to
  emit events that match the curated rule pack.
* OpenSearch query-side stress — M15.c.
