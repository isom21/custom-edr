# ADR 0008 — Redis as a shared dependency, with HA pattern

Status: accepted (2026-05-15)

## Context

Redis crept into the stack across Phases 1-3 as the path of least
resistance for a handful of unrelated needs:

- **Rate limits** on the auth endpoints (`POST /api/auth/login`,
  `/api/auth/oidc/callback`, `/api/auth/mfa`) and on the SCIM bridge.
  Token-bucket state lives in `INCR` + `EXPIRE` keys.
- **Cross-process locks** for the audit-verifier loop, the dispatch
  watchdog, the rollout monitor, and the silence worker — anywhere two
  manager processes might do the same work twice. Lock acquisition is
  `SET key value NX PX <ms>`; release is the Lua compare-and-delete.
- **Short-lived caches**: the host-meta cache that feeds normalize-time
  tenant stamping; the OIDC nonce cache; the SCIM token-prefix cache.
- **Pub/sub for cache invalidation**: when an operator edits a rule or
  a host group, every manager process needs to drop its in-memory
  cache. The pub/sub channel `vigil:cache:invalidate` carries the
  prefix to evict.

The default `docker-compose.dev.yml` runs a single `redis:7-alpine`.
That is fine for development and small single-host deployments but is
a single point of failure for anyone running multi-process or multi-
host. Phase 3 needs a documented HA path before we can call it a real
production target.

## Decision

Treat Redis as a **shared but tolerated-degraded** dependency, with
two supported deployment shapes:

1. **Single-node (dev, demo, tiny installs).** One `redis:7-alpine`
   with append-only persistence. RPO is "the last second of writes";
   that is acceptable for the workloads above (rate limits and locks
   are inherently ephemeral; the host-meta cache rebuilds from
   Postgres on miss).
2. **Sentinel-fronted replica set (production).** Three-node
   `redis-sentinel` topology: one master, two replicas, three
   sentinels. Clients connect via the sentinel-aware Python driver
   and re-resolve the master on failover. RPO stays sub-second; RTO
   is sentinel's failover budget (~10 s with default quorum settings).
   The dispatch watchdog and audit verifier loop tolerate that gap by
   re-acquiring their leadership lock on reconnect, not by holding it
   forever.

The deliberate non-decision: **no Redis Cluster.** The keyspace is
small (low thousands of keys per manager), there is no need for
horizontal sharding, and Cluster's resharding semantics fight with
the lock pattern we use.

## Why Sentinel over alternatives

- **Postgres advisory locks** would remove Redis from the lock path
  but lose the `PX` expiry semantics — a manager crash holding an
  advisory lock blocks the queue until the connection times out.
- **Etcd / Zookeeper** would be a cleaner lock store but adds a third
  stateful service to the deployment for what is, in practice, four
  named locks total. Operators already have to operate Postgres,
  Kafka, OpenSearch, and Redis; adding a fifth is a non-trivial tax.
- **In-process locks + sticky routing** would work for the small
  cluster sizes the manager targets, but breaks the "any manager can
  serve any request" invariant the load balancer relies on.

## Failure modes the manager must tolerate

- **Redis unavailable.** All Redis-using paths fall back as follows:
  - Rate-limit: fail open (allow the request, log a warning, increment
    `edr_manager_rate_limit_fail_open_total`). The auth endpoints
    have a per-process LRU as a second line of defence.
  - Cross-process lock: refuse to start the worker rather than risk
    double-execution. The worker process exits non-zero so the
    supervisor restarts it on Redis recovery.
  - Host-meta cache: read straight from Postgres. Slower but correct.
  - Cache invalidation pub/sub: workers fall back to a 60 s timed
    refresh.
- **Sentinel split-brain.** Sentinel's quorum (2-of-3) prevents two
  managers from believing they hold the same lock. A network
  partition that hides one sentinel from the rest stalls failover
  rather than dual-promoting.

## Consequences

- New Redis-using code path: must document its fallback in the
  module docstring (rate-limit → fail-open; lock → exit-and-restart;
  cache → re-read source-of-truth).
- New worker leadership: use `redis_lock(name, ttl=)` from
  `backend/app/services/redis_lock.py`. Do not hand-roll `SET NX PX`.
- Deployment docs (`docs/install.md`) document the single-node default
  and link to the sentinel section for production. `docs/operator-
  guide.md` "Production deployment" chapter covers the failover drill.
- Smoke (`tools/smoke/`) does not cover sentinel failover; that lives
  in the production-deployment runbook and is exercised quarterly.

## Outstanding follow-ups

- Native Redis Cluster client support if a multi-region deployment
  ever needs it. Not on the roadmap.
- A health endpoint that surfaces "Redis degraded → fail-open active"
  so operators see the warning before the audit log fills with it.
