# ADR 0006 — Testing strategy (M8)

Status: accepted (2026-05-10)

## Context

M0–M7 shipped without a unit/integration test suite. Verification was
exclusively via `tools/smoke/*` (curl + ssh against running services).
Smoke tests caught most regressions during initial bring-up but they're
brittle (network-dependent), expensive (full service stack), and
exercise only the happy paths.

M7's RBAC and self-protection introduced enough invariants that smoke
alone is no longer enough — silent failures in the BPF LSM hooks
freeze the host, RBAC bugs leak data, and a flaky smoke run is too
easy to dismiss.

## Decision

Layer four levels of testing:

1. **Static gates (fast, per-PR, no infra)**: clippy, fmt, audit, deny
   for Rust; ruff, pyright, pip-audit for Python; tsc, eslint,
   prettier, npm audit for the frontend.
2. **Unit + integration tests (per-PR, ephemeral infra)**: pytest with
   testcontainers spinning up Postgres + Redpanda + OpenSearch in CI.
   Covers RBAC scoping, alert state machine, command queue dispatch,
   protobuf round-trip, and similar host-independent logic. Function-
   scoped DB connection inside a SAVEPOINT-per-test for isolation.
3. **Smoke tests (per-release, real infra)**: existing
   `tools/smoke/*` against a live dev stack, including the lab-linux
   and lab-windows endpoints. Runs the BPF LSM self-protection
   verification and the M7.5 RBAC end-to-end flow.
4. **Mutation tests (on-demand, real infra)**: `tools/mutation/run.sh`
   patches the BPF C source with predefined mutations, rebuilds,
   deploys, and re-runs the smoke. Each mutation must be caught by
   the smoke; an escaped mutation indicates undertested behaviour.

## Why these layers, in this order

- Static gates are <30s per PR and catch the bulk of accidents
  (typos, import errors, dependency CVEs). They run on every PR with
  no infra cost.
- Integration tests with real infra (not mocks) catch schema-shape
  and ORM-driver bugs that mocked tests routinely miss. They're the
  middle tier: ~30s per run on CI's service containers.
- Smoke tests are slow (lab VMs, multi-minute setup) but the only
  way to verify real kernel-mode behaviour. Run on release branches
  + nightly on main.
- Mutation tests are the slowest (one full agent rebuild + redeploy
  per mutation) but the highest signal for the LSM hooks specifically.
  Run on demand by the developer touching the hooks.

## What we deliberately do NOT do

- **Mock the database in unit tests.** PG-specific types (uuid, jsonb,
  enum, server-side defaults) need real PG; `pytest_asyncio` +
  testcontainers is cheap enough.
- **Test the BPF C code in isolation.** No good harness exists for
  in-tree BPF unit tests; the verifier + kernel are the spec. We
  verify behaviour via smoke + mutation instead.
- **Aim for a single coverage number.** Hitting 100% on the audit
  helpers tells us nothing about the LSM correctness. Coverage gates
  per-package (`cov-fail-under`) ratchet up after the suite stabilises.

## Consequences

- New routers: every endpoint with a role gate must have a positive
  + negative integration test in `backend/tests/test_<feature>.py`.
- New BPF hooks: each must have a corresponding mutation entry in
  `tools/mutation/run.sh` that the smoke can kill.
- CI is multi-job: a green main requires `rust`, `python`,
  `frontend`, and `backend-integration` workflows all passing.
- We accept some redundancy between integration tests (RBAC scoping
  in pytest) and smoke (`50-rbac-e2e.sh`). They catch different
  failure modes — pytest catches code regressions, smoke catches
  deployment regressions.

## Outstanding follow-ups

- Coverage ratchet: pick a target (60% manager, 40% agent) once the
  suite stabilises and gate via `cov-fail-under`.
- Per-PR Windows VM build of `edr.sys` + `agent-windows.exe` via a
  self-hosted runner on lab-windows. Today the workflow `cargo check`s
  the windows-msvc target on a hosted runner; a real build needs the
  WDK headers + cl.exe.
- Differential fuzzing of the IOCTL surface (Windows driver) and BPF
  map operations (Linux) — deferred to a future M.
