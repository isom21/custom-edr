"""gRPC agent stream pushes a fresh RuleSync when rules change.

Review MEDIUM #15: pre-fix, `RuleSync` was sent exactly once at stream
open and never again. Toggling a YARA / IOC rule in the UI did not
reach already-connected agents until they reconnected.

The full integration (rule edit → notification → stream push) needs a
gRPC server and a fake agent; this test pins the read-side contract:
`_build_rule_sync` reflects the *current* DB state, and the helper
hook `MAX(updated_at)` advances when a rule is patched, which is the
signal the per-stream resync dispatcher polls on.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import func, select


@pytest.fixture
async def _enabled_yara_rule(db_session):
    from app.models import Rule, RuleAction, RuleKind, Severity

    r = Rule(
        kind=RuleKind.YARA,
        name=f"r-{os.urandom(3).hex()}",
        severity=Severity.MEDIUM,
        action=RuleAction.ALERT,
        body='rule t { strings: $a = "hi" condition: $a }',
        enabled=True,
        revision=1,
    )
    db_session.add(r)
    await db_session.flush()
    return r


@pytest.mark.asyncio
async def test_build_rule_sync_reflects_current_rule_set(db_session, _enabled_yara_rule):
    from app.grpc.services import AgentService

    svc = AgentService.__new__(AgentService)
    sync = await svc._build_rule_sync(db_session)
    names = [y.name for y in sync.yara]
    assert _enabled_yara_rule.name in names


@pytest.mark.asyncio
async def test_max_updated_at_advances_on_rule_patch(db_session, _enabled_yara_rule):
    from app.models import Rule, Severity

    # Capture the watermark the resync dispatcher uses to decide
    # whether to push a fresh sync.
    before = (await db_session.execute(select(func.max(Rule.updated_at)))).scalar_one()

    # Mutate the rule (mirrors the api/rules PATCH path).
    _enabled_yara_rule.severity = Severity.CRITICAL
    _enabled_yara_rule.revision += 1
    await db_session.flush()

    after = (await db_session.execute(select(func.max(Rule.updated_at)))).scalar_one()
    assert after is not None and (before is None or after > before), (
        "MAX(Rule.updated_at) must advance when a rule is patched — that's the resync trigger"
    )


@pytest.mark.asyncio
async def test_disabled_rule_excluded_from_sync(db_session, _enabled_yara_rule):
    from app.grpc.services import AgentService

    _enabled_yara_rule.enabled = False
    await db_session.flush()

    svc = AgentService.__new__(AgentService)
    sync = await svc._build_rule_sync(db_session)
    names = [y.name for y in sync.yara]
    assert _enabled_yara_rule.name not in names, (
        "disabled rules must not appear in the sync — agents stop evaluating them"
    )
