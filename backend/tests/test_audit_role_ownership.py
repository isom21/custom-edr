"""M16.a (fixed): assert audit_log is INSERT-only from the runtime user.

The reviewer's CRITICAL finding was that the old M16.a migration's
``REVOKE … FROM PUBLIC`` had no effect — the runtime user ``edr`` owned
``audit_log`` and was also a superuser, so PG silently allowed every
write. The fix transfers ownership to ``vigil_audit_writer`` and the
dev compose now bootstraps as ``postgres`` so ``edr`` is no longer a
superuser. These tests prove both legs are real:

  * INSERT from the runtime DSN still works (the manager keeps writing).
  * UPDATE / DELETE / TRUNCATE from the runtime DSN raise
    ``InsufficientPrivilege`` with SQLSTATE 42501.

Skipped when the audit migration hasn't been applied (alembic head is
behind ``c41d5b7e9f02``) so the suite still passes on dev DBs that
predate the fix.
"""

from __future__ import annotations

import os
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine


def _runtime_dsn() -> str | None:
    if v := os.environ.get("VIGIL_TEST_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_PG_DSN"):
        return v
    if v := os.environ.get("VIGIL_DATABASE_URL"):
        if v.startswith("postgresql+psycopg://"):
            return v.replace("postgresql+psycopg://", "postgresql+asyncpg://", 1)
        if v.startswith("postgresql://"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v
    return None


@pytest_asyncio.fixture
async def runtime_engine() -> Any:
    dsn = _runtime_dsn()
    if dsn is None:
        pytest.skip("No PG DSN configured.")
    engine = create_async_engine(dsn, pool_pre_ping=True, echo=False)
    # Skip if the audit-ownership migration hasn't landed in this DB.
    async with AsyncSession(engine) as db:
        owner_row = (
            await db.execute(text("SELECT tableowner FROM pg_tables WHERE tablename='audit_log'"))
        ).first()
        if owner_row is None or owner_row[0] != "vigil_audit_writer":
            await engine.dispose()
            pytest.skip(
                "audit_log not owned by vigil_audit_writer — M16.a (fixed) migration "
                "hasn't been applied to this DB."
            )
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_runtime_user_is_not_superuser(runtime_engine: Any) -> None:
    """The runtime DSN must not connect as a superuser — superusers bypass
    GRANT/REVOKE and would make the rest of this file's claims vacuous."""
    async with AsyncSession(runtime_engine) as db:
        row = (await db.execute(text("SHOW is_superuser"))).first()
        assert row is not None
        assert row[0] == "off", f"runtime DSN is connected as a superuser ({row[0]!r})"


@pytest.mark.asyncio
async def test_runtime_user_can_insert(runtime_engine: Any) -> None:
    """The manager's hot path is INSERT into audit_log; that must keep
    working under the new ownership."""
    marker = f"audit-priv-test-{uuid4()}"
    async with AsyncSession(runtime_engine) as db:
        await db.execute(
            text(
                "INSERT INTO audit_log (id, actor_kind, action) "
                "VALUES (gen_random_uuid(), 'system', :marker)"
            ),
            {"marker": marker},
        )
        await db.commit()
    # We don't bother cleaning up — the row is INSERT-only by design,
    # and `vigil_audit_writer` (the only role with DELETE) isn't
    # something this test should connect as. The marker is unique
    # enough that it won't collide.


@pytest.mark.asyncio
async def test_runtime_user_cannot_update(runtime_engine: Any) -> None:
    async with AsyncSession(runtime_engine) as db:
        with pytest.raises(ProgrammingError) as exc_info:
            await db.execute(text("UPDATE audit_log SET action = action"))
            await db.commit()
        # SQLSTATE 42501 is PG's `insufficient_privilege`.
        assert "42501" in str(exc_info.value) or "permission denied" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_runtime_user_cannot_delete(runtime_engine: Any) -> None:
    async with AsyncSession(runtime_engine) as db:
        with pytest.raises(ProgrammingError) as exc_info:
            await db.execute(text("DELETE FROM audit_log"))
            await db.commit()
        assert "42501" in str(exc_info.value) or "permission denied" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_runtime_user_cannot_truncate(runtime_engine: Any) -> None:
    async with AsyncSession(runtime_engine) as db:
        with pytest.raises(ProgrammingError) as exc_info:
            await db.execute(text("TRUNCATE audit_log"))
            await db.commit()
        assert "42501" in str(exc_info.value) or "permission denied" in str(exc_info.value).lower()
