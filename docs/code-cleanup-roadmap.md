# Code cleanup + customer docs roadmap (M17)

> **Status:** scaffolded. M17 ships:
>   * `CommandIn` Pydantic model validator (M17.a, fully wired)
>   * Customer-doc skeleton (`docs/api-reference.md` + `SECURITY.md`,
>     M17.b)
>
> The remaining specific code-level cleanups from §12 of the
> enterprise-grade list ship as M17.c through M17.j, each in its own
> tiny PR.

## What landed in this commit

**M17.a — `CommandIn` discriminated validation**: the router-level
`_validate_payload()` helper now has a Pydantic `model_validator` mirror
on the input schema, so bad payloads return 422 with structured
field-level errors instead of the router's bare-string `bad_request`.
The router still calls `_validate_payload` defensively for
non-Pydantic call sites (gRPC auto-action triggers in M5.5).

**M17.b — Customer doc skeleton**: `docs/api-reference.md` collects
the OpenAPI auto-generated reference plus per-endpoint examples;
`SECURITY.md` carries the responsible-disclosure policy + bug bounty
language (no platform yet).

## Substages M17.c – M17.j

These are mechanical and uncoupled:

| Substage | Cleanup |
|---|---|
| M17.c | `audit_log.api_token_id` FK alongside `user_id` (track per-token actions properly) |
| M17.d | bpffs pin gap closure on Linux restart (reuse pinned objects via aya pinned-FD path) |
| M17.e | Driver `ObCallbacks` for FILE_OBJECT (M7.2 follow-up) |
| M17.f | Rate limiting on gRPC ingest per host_id (mirrors M13.a for the gRPC surface) |
| M17.g | Enrollment token group pre-assignment (`POST /api/enrollment/tokens` accepts `host_group_ids`) |
| M17.h | `/api/users/{id}/groups` symmetric to `/api/host-groups/{id}/members` |
| M17.i | Bulk operations API (batch enroll, batch-add-to-group, batch-queue-commands) |
| M17.j | Manager → agent push for RuleSync + Command (server-stream; agent doesn't poll) |

Each is on the order of 50–150 lines and slots in without breaking
existing interfaces. They pile up into M17 but ship as individual
commits.

## Customer docs (M17.b shape)

`docs/api-reference.md` — auto-generated from OpenAPI but with
hand-written examples per endpoint. Generated at release time via:

```bash
curl http://localhost:8000/api/openapi.json \
  | python tools/docs/openapi-to-md.py \
  > docs/api-reference.md
```

`SECURITY.md` — top-level. Today's content is the responsible
disclosure policy. Bug bounty platform integration is M19 paid.

`docs/architecture/` — collects the "how the BPF takeover works",
"why ObCallbacks not PPL", "audit-log threat model" deep-dives.
First three written ahead of M19 customer asks.

`docs/migration/` — version-to-version migration guides. Empty until
v0.2.0 ships.
