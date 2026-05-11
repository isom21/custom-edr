"""M-audit-and-auth #6: audit-chain verifier runs on a schedule.

Reviewer's MEDIUM #6: `verify_chain` was CLI-only — no startup hook,
no Prometheus gauge, no /audit UI badge. A break is the loudest
possible signal of audit-log tampering, and catching it days late
defeats the purpose. The fix wires a background loop in
`app.workers.audit_verifier_loop` that pings the chain on a schedule
and emits three Prometheus gauges + a SOC alert on break.

Tests pin the gauge plumbing — the loop itself is an `asyncio` task
managed by lifespan, hard to drive deterministically from pytest. The
single-pass `_run_once()` is the load-bearing unit and is testable
directly.
"""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_run_once_updates_gauges_on_clean_chain() -> None:
    """A clean chain: breaks=0, rows_examined>0, last_run_timestamp
    populated. The fixture audit_log on the dev DB is whatever the
    suite has produced so far — `rows_examined` should be at least 1."""
    import time

    from app.core.metrics import (
        audit_chain_breaks,
        audit_chain_last_run_timestamp,
        audit_chain_rows_examined,
    )
    from app.workers.audit_verifier_loop import _run_once

    before_ts = time.time()
    await _run_once()
    # `prometheus_client` gauges have ._value.get() — direct read.
    assert audit_chain_breaks._value.get() == 0
    assert audit_chain_rows_examined._value.get() >= 1
    # Last-run gauge is in monotonic-ish unix seconds.
    last_run = audit_chain_last_run_timestamp._value.get()
    assert last_run >= before_ts - 1


def test_run_once_is_idempotent_under_repeated_calls() -> None:
    """Two passes in a row should both succeed without raising — the
    gauges are gauges, not counters, so the second run just overwrites
    with the same values."""
    import asyncio

    from app.workers.audit_verifier_loop import _run_once

    async def run_twice() -> None:
        await _run_once()
        await _run_once()

    asyncio.run(run_twice())


def test_audit_chain_break_rule_id_is_stable() -> None:
    """The synthetic rule id is hard-coded; the test pins the value so
    a future refactor that moves the constant elsewhere can't silently
    fragment existing chain-break alerts across two rules."""
    from app.workers.audit_verifier_loop import AUDIT_CHAIN_BREAK_RULE_ID

    assert str(AUDIT_CHAIN_BREAK_RULE_ID) == "a0a0a0a0-0000-0000-0000-000000000006"


def test_interval_floor_is_30s() -> None:
    """Operators can't dial the interval below 30 s — verify_chain
    walks every chained row and that's noticeable on a big audit_log.
    Defends against a typo'd `VIGIL_AUDIT_VERIFIER_INTERVAL_S=1`."""
    import os

    from app.workers.audit_verifier_loop import _interval_seconds

    os.environ["VIGIL_AUDIT_VERIFIER_INTERVAL_S"] = "1"
    try:
        assert _interval_seconds() == 30
    finally:
        os.environ.pop("VIGIL_AUDIT_VERIFIER_INTERVAL_S", None)


def test_interval_falls_back_to_default_on_garbage() -> None:
    import os

    from app.workers.audit_verifier_loop import _interval_seconds

    os.environ["VIGIL_AUDIT_VERIFIER_INTERVAL_S"] = "not-a-number"
    try:
        assert _interval_seconds() == 300
    finally:
        os.environ.pop("VIGIL_AUDIT_VERIFIER_INTERVAL_S", None)
