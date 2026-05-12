"""Async SQLAlchemy engine and session factory."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import settings

# Under pytest-asyncio's per-test event loops, a QueuePool that
# retains asyncpg connections bound to loop A blows up when loop B
# either GC's the old connection ("Event loop is closed") or the
# greenlet adapter probes it ("Future attached to a different loop").
# NullPool opens + closes per checkout — no cross-loop state can
# linger. The runtime cost is negligible for the test suite and the
# behaviour difference vs prod is bounded (per-request connect/close).
if os.environ.get("VIGIL_TEST_ENV") == "1":
    engine = create_async_engine(
        settings.pg_dsn,
        poolclass=NullPool,
        echo=False,
    )
else:
    engine = create_async_engine(
        settings.pg_dsn,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        echo=False,
    )

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency: yields a per-request session, commits or rolls back at the end."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
