# ADR 0007 — Multi-tenancy via shared schema + row-level tenant_id

Status: accepted (2026-05-15)

## Context

The first two phases shipped a single-tenant manager: every operator
shared one logical organisation. That was the right starting point for
solo-dev / small-team installations, but Phase 3 #3.1 introduced
multi-tenancy so MSSPs and larger orgs can isolate hosts, alerts,
rules, and audit per customer without standing up a separate manager
deployment per tenant.

Three shapes were on the table:

1. **Database-per-tenant.** A connection-pool fanout indexed by tenant
   ID. Strongest isolation but the operator now has N migrations, N
   Alembic histories, N audit-key rotations to keep in lock-step. Cross-
   tenant analytics require federation. Adding a tenant is a heavy
   operation.
2. **Schema-per-tenant.** One Postgres database, N schemas. Migrations
   still fan out N-times (or get cute with `SET search_path`); ORM
   tooling fights the operator at every turn.
3. **Shared schema, row-level `tenant_id`.** Every operator-managed
   table grows a `tenant_id` FK to `tenant.id`; queries filter on it
   in code; cross-tenant resources surface as 404 (not 403) to avoid
   leaking existence.

## Decision

Shared schema with row-level `tenant_id`, with the following
invariants:

- **Every operator-managed table has a `tenant_id` FK to `tenant.id`.**
  Includes: `host`, `host_group`, `alert`, `incident`, `rule`,
  `rule_group`, `playbook`, `playbook_run`, `sequence_rule`,
  `api_token`, `scim_token`, `dashboard`, `intel_indicator`,
  `notification_destination`, `routing_rule`, `dns_block`,
  `allowlist_entry`, `job`, `vulnerability`, `quarantine_entry`,
  `audit_log`. Tables that are operator-shared (e.g. `tenant`,
  `user.global_role`, `vigil_meta`) do not.
- **Cross-tenant access surfaces as 404.** Returning 403 would leak
  existence; 404 means the resource may not exist or may not be ours.
  Super-admins can switch tenants via the `vigil_active_tenant_id`
  cookie to see other tenants' resources legitimately.
- **All API list queries flow through `apply_tenant_scope(stmt, actor,
  Model.tenant_id)`**. All single-resource GET / PATCH / DELETE flow
  through `_load_in_tenant(db, id, actor)`. Centralising the scope
  helper means a new endpoint can't forget to filter.
- **All ECS docs get a `tenant.id` field at normalize time** via
  `host_cache.host_meta_for(host_id)`. Sigma realtime, anomaly,
  sequence-detector, and the audit verifier loop all read this field
  to stamp the correct `tenant_id` on alerts they open.
- **Per-tenant uniqueness, not global.** Names like `rule.name`,
  `playbook.name`, `dashboard.name` use `UNIQUE(tenant_id, name)`
  rather than `UNIQUE(name)` so two tenants can both name a rule
  "linux-suspicious-shell".

## Why shared schema

- **Operator ergonomics.** One Alembic history, one audit chain, one
  backup. Adding a tenant is `INSERT INTO tenant` plus a name — not a
  schema migration.
- **Cross-tenant analytics stay trivial.** A super-admin's "fleet-wide
  alert volume" dashboard joins across all tenants in one query.
- **OpenSearch shape stays one index per signal type.** Tenant filtering
  happens at query time via the `tenant.id` term filter; the alternative
  (index-per-tenant) explodes the shard count past the cluster's healthy
  limit at three-digit tenant counts.
- **The audit chain stays one HMAC chain** keyed by `VIGIL_AUDIT_HMAC_KEY`
  but with a `tenant_id` column. Per-tenant verification is a `WHERE`
  clause; per-tenant rotation is a future migration.

## What we accept

- **Tenant isolation is enforced in application code, not by the DB.**
  A bug in `apply_tenant_scope` could leak; mitigated by the regression
  suite in `backend/tests/test_*_tenant_scope.py` (13 + files asserting
  cross-tenant 404, list invisibility, and create-stamps-tenant_id).
  Postgres row-level security is a future hardening — it would catch
  the application-bug case but pays a non-trivial planner cost on the
  joins this manager already runs.
- **One noisy tenant can saturate one Kafka consumer group.** Per-
  tenant rate-limiting on telemetry ingest is a known follow-up.
- **Tenant deletion is a heavy operation.** `ON DELETE RESTRICT` on
  every FK means a tenant carries a lot of rows; the cleanup path is
  a soft-delete flag + background reaper rather than `DELETE FROM
  tenant`.

## Consequences

- New endpoint checklist: pull `actor` from the dependency; filter
  list queries with `apply_tenant_scope`; load single resources with
  `_load_in_tenant`; stamp `tenant_id=actor.tenant_id` on create. A
  regression test in `backend/tests/test_<feature>_tenant_scope.py`
  asserts cross-tenant 404.
- New tables: add `tenant_id Uuid NOT NULL` with `FK -> tenant.id ON
  DELETE RESTRICT`, an index on `tenant_id`, and per-tenant uniqueness
  on any natural-key column. Migration revs `f6f7a8b9c0d1` → `a1c2e3f4d5b6`
  → `b3c4d5e6f7a9` → `c4d5e6f7a8b9` show the pattern.
- New workers that open alerts: resolve the tenant via
  `host_cache.resolve_alert_tenant_id(db, host_id=, ecs_tenant_id=)`,
  prefer the ECS doc's `tenant.id` over a fresh `db.get(Host)`.
- Super-admin UX: a tenant switcher in the header sets the
  `vigil_active_tenant_id` cookie; cleared on sign-out. Documented
  in `docs/rbac.md` "Tenancy".

## Outstanding follow-ups

- Postgres row-level security as a defence-in-depth layer.
- Per-tenant Kafka consumer-group rate limits.
- Per-tenant audit HMAC key (rotation per tenant, not per cluster).
