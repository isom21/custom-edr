"""Concurrency tests for `services.enrollment.consume_token`.

The previous read-then-write enrollment flow was raceable: two
`POST /api/enrollment/enroll` calls with the same token, fired in
parallel, could both pass the `used_at IS NULL` check and both proceed
to issue valid client certs. The fix collapses check + mark into a
single UPDATE…RETURNING — these tests assert it works under contention.

We can't exercise the race inside a single SAVEPOINT-wrapped session
(both calls would share one transaction and serialise in Python). The
tests therefore commit a fresh token via a dedicated engine, spawn N
parallel `consume_token` calls each in its own connection, and assert
exactly one wins.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import pytest_asyncio
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine


def _pg_dsn() -> str | None:
    """Mirror conftest's DSN resolver. Repeated here so the test can
    spin its own engine without depending on the per-test SAVEPOINT
    fixture (which would mask the race)."""
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
async def standalone_engine() -> Any:
    dsn = _pg_dsn()
    if dsn is None:
        pytest.skip("No PG DSN configured.")
    engine = create_async_engine(dsn, pool_pre_ping=True, echo=False)
    try:
        yield engine
    finally:
        await engine.dispose()


async def _seed_token(engine: Any, plaintext: str) -> Any:
    from app.core.security import hash_enrollment_token
    from app.models import EnrollmentToken

    async with AsyncSession(engine) as db:
        token = EnrollmentToken(
            token_hash=hash_enrollment_token(plaintext),
            label="race-test",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        db.add(token)
        await db.commit()
        await db.refresh(token)
        return token


async def _drop_token(engine: Any, token_id: Any) -> None:
    from app.models import EnrollmentToken

    async with AsyncSession(engine) as db:
        await db.execute(delete(EnrollmentToken).where(EnrollmentToken.id == token_id))
        await db.commit()


async def _consume_in_own_session(engine: Any, plaintext: str) -> Any:
    from app.services.enrollment import EnrollmentTokenInvalid, consume_token

    async with AsyncSession(engine) as db:
        try:
            tid = await consume_token(db, plaintext)
            await db.commit()
            return ("ok", tid)
        except EnrollmentTokenInvalid:
            await db.rollback()
            return ("invalid", None)


@pytest.mark.asyncio
async def test_concurrent_consume_exactly_one_wins(standalone_engine: Any) -> None:
    """Two parallel consume_token calls against the same token — exactly one wins."""
    from app.core.security import generate_enrollment_token

    plaintext = generate_enrollment_token()
    seeded = await _seed_token(standalone_engine, plaintext)
    try:
        results = await asyncio.gather(
            _consume_in_own_session(standalone_engine, plaintext),
            _consume_in_own_session(standalone_engine, plaintext),
        )
        outcomes = [r[0] for r in results]
        assert outcomes.count("ok") == 1, f"expected one winner, got {outcomes}"
        assert outcomes.count("invalid") == 1, f"expected one loser, got {outcomes}"
    finally:
        await _drop_token(standalone_engine, seeded.id)


@pytest.mark.asyncio
async def test_concurrent_consume_stress_50_iterations(standalone_engine: Any) -> None:
    """50 iterations × 4-way contention. Every iteration must yield exactly one ok."""
    from app.core.security import generate_enrollment_token

    for _ in range(50):
        plaintext = generate_enrollment_token()
        seeded = await _seed_token(standalone_engine, plaintext)
        try:
            results = await asyncio.gather(
                *(_consume_in_own_session(standalone_engine, plaintext) for _ in range(4))
            )
            outcomes = [r[0] for r in results]
            assert outcomes.count("ok") == 1, f"expected one winner, got {outcomes}"
            assert outcomes.count("invalid") == 3, f"expected three losers, got {outcomes}"
        finally:
            await _drop_token(standalone_engine, seeded.id)


@pytest.mark.asyncio
async def test_second_consume_after_first_succeeds_raises(standalone_engine: Any) -> None:
    """Serial second consume of an already-used token raises EnrollmentTokenInvalid."""
    from app.core.security import generate_enrollment_token
    from app.services.enrollment import EnrollmentTokenInvalid, consume_token

    plaintext = generate_enrollment_token()
    seeded = await _seed_token(standalone_engine, plaintext)
    try:
        async with AsyncSession(standalone_engine) as db:
            await consume_token(db, plaintext)
            await db.commit()
        async with AsyncSession(standalone_engine) as db:
            with pytest.raises(EnrollmentTokenInvalid):
                await consume_token(db, plaintext)
    finally:
        await _drop_token(standalone_engine, seeded.id)


@pytest.mark.asyncio
async def test_expired_token_raises(standalone_engine: Any) -> None:
    from app.core.security import generate_enrollment_token, hash_enrollment_token
    from app.models import EnrollmentToken
    from app.services.enrollment import EnrollmentTokenInvalid, consume_token

    plaintext = generate_enrollment_token()
    async with AsyncSession(standalone_engine) as db:
        token = EnrollmentToken(
            token_hash=hash_enrollment_token(plaintext),
            label="race-test-expired",
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        db.add(token)
        await db.commit()
        await db.refresh(token)
        token_id = token.id
    try:
        async with AsyncSession(standalone_engine) as db:
            with pytest.raises(EnrollmentTokenInvalid):
                await consume_token(db, plaintext)
    finally:
        await _drop_token(standalone_engine, token_id)


@pytest.mark.asyncio
async def test_unknown_token_raises(standalone_engine: Any) -> None:
    from app.core.security import generate_enrollment_token
    from app.services.enrollment import EnrollmentTokenInvalid, consume_token

    async with AsyncSession(standalone_engine) as db:
        with pytest.raises(EnrollmentTokenInvalid):
            await consume_token(db, generate_enrollment_token())
