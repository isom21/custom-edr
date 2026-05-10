# Compliance + audit + privacy roadmap (M16)

> **Status:** scaffolded. M16 ships an append-only PG role for the
> audit log (M16.a) + the roadmap. Real compliance certifications
> (SOC 2, ISO 27001) wait on M19's customer-driven audit budget.

## Substages

| Substage | What |
|---|---|
| **M16.a (this commit)** | PG role + GRANT shape ensuring `audit_log` is INSERT-only for the manager DB user (DELETE/UPDATE revoked) |
| M16.b | Configurable retention per `action` prefix; pruner job |
| M16.c | Tamper-evident chain: rolling Merkle hash anchored to Sigstore Rekor |
| M16.d | Per-customer evidence export API (signed bundle: alert + context + audit trail) |
| M16.e | SOC 2 / ISO 27001 control-mapping document |
| M16.f | GDPR: data residency knobs, right-to-erasure API, DPA template |
| M16.g | PII scrubbing in event payloads (regex deny-list at agent) |
| M16.h | Data classification labels on events + audit-log payload redaction |

## M16.a — append-only audit log (this commit)

**Goal**: even if the manager's DB user is compromised at the SQL
level (e.g. via a SQL injection in a future regression), the
audit_log can't be retroactively edited or deleted.

**Approach**: a separate PG role `edr_audit_writer` owns the
`audit_log` table and grants the manager user only INSERT (no UPDATE,
DELETE, TRUNCATE). The manager's existing `app.services.audit.record()`
helper continues to write through the same connection — PostgreSQL
enforces the GRANT at SQL execution time.

**Operator opt-in**: this is a privilege-separation hardening that
breaks the dev workflow (you can't `DELETE FROM audit_log` to clean
up testing). It's gated by an alembic migration that operators apply
on their production DB only.

The migration (M16.a) creates the role + revokes the privileges. To
roll back, the migration's `downgrade` re-grants. Operators who want
to keep the dev workflow simple skip the migration.

**Pruning** (M16.b) lives outside the manager DB user's permissions:
a separate cron job runs as a privileged DB user that has DELETE on
`audit_log` filtered by retention policy.

## What this does NOT solve

- **Storage tampering** (someone with shell access on the DB host
  rewriting `*.dat` files): solved at the storage layer, not the SQL
  layer. Off-host WORM storage (S3 with object-lock) is M16.b.
- **Compromised manager process** writing fake entries: the manager
  *can* write whatever it wants. The signed evidence chain (M16.c)
  catches retroactive forgery; runtime impersonation needs full code
  review of the audit emission sites.
- **Operator with full DBA**: a real DBA can re-grant. SOC 2 covers
  this via process controls (separation of duties, ticketed access).

## SOC 2 / ISO 27001 control mapping (M16.e preview)

When the customer asks for SOC 2, the document we produce in M16.e
maps every Common Criteria control to the manager feature that
satisfies it:

  CC1 / CC2  Communication & Information   -> docs/operator-guide.md
  CC3        Risk Assessment                -> docs/threat-model.md
  CC4        Monitoring                     -> M14 metrics + audit_log
  CC5        Control Activities             -> M7.5 RBAC + this doc
  CC6        Logical & Physical Access     -> M13 identity + M7.1/M7.2
  CC7        System Operations              -> M14 runbooks + M9 lifecycle
  CC8        Change Management              -> CI gates (M8) + audit_log
  CC9        Risk Mitigation                -> threat-model + M11 detection

The auditor wants evidence; we run the smoke + load tests + show the
audit_log queries; that's roughly 60% of a Type-II readiness
package today.

## GDPR (M16.f)

Three concrete asks that real EU customers raise:

1. **Data residency**: per-region manager deploys (no cross-region
   replication of telemetry). Operator-side; manager gains a
   `region: str` config knob to refuse storing events from agents in
   a different region.
2. **Right to erasure**: a host's owner can request deletion of all
   events tied to that host. New endpoint
   `DELETE /api/hosts/{id}/data?purge=true`. Cascades through OpenSearch
   (delete-by-query), PG (FK ON DELETE CASCADE on alert.host_id),
   audit_log (kept; audit retention takes precedence over GDPR
   erasure for the manager's own actions per the EDPB exception for
   security log retention).
3. **DPA template**: docs/dpa-template.md (legal review required).
