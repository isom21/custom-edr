"""Enrollment token consumption — race-free across REST and gRPC paths.

The previous read-then-write pattern in `api/enrollment.py` and
`grpc/services.py` was raceable under READ COMMITTED: two concurrent
enroll calls with the same token could both observe `used_at IS NULL`,
both pass the validity check, and both issue valid client certs. PG's
default isolation does not serialise the SELECT against an as-yet-
uncommitted UPDATE in another transaction.

`consume_token` collapses the check + mark to a single `UPDATE ... WHERE
used_at IS NULL AND expires_at > now() RETURNING ...`. PG resolves
concurrent writers row-by-row: the loser observes the row already
written and the WHERE clause filters it out, so RETURNING is empty
and the loser raises `EnrollmentTokenInvalid`.

The caller is responsible for setting `used_by_host_id` once the host
row exists (it doesn't at consume time).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_enrollment_token
from app.models import EnrollmentToken


class EnrollmentTokenInvalid(Exception):  # noqa: N818 — read aloud as "token-invalid", not "error"
    """Token unknown, already used, or expired.

    REST and gRPC translate this to their transport's invalid-token
    status. The single exception type keeps the two callers symmetric.
    """


async def consume_token(db: AsyncSession, raw_token: str) -> UUID:
    """Atomically mark the token as used. Returns the token's row id.

    Raises `EnrollmentTokenInvalid` if the token is unknown, already
    consumed, or past its expiry. Idempotent under retry — a second
    call with the same plaintext after a successful consume will raise
    just like a stolen-then-reused token would.
    """
    th = hash_enrollment_token(raw_token)
    now = datetime.now(UTC)
    stmt = (
        update(EnrollmentToken)
        .where(
            EnrollmentToken.token_hash == th,
            EnrollmentToken.used_at.is_(None),
            EnrollmentToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(EnrollmentToken.id)
    )
    row = (await db.execute(stmt)).first()
    if row is None:
        raise EnrollmentTokenInvalid
    return row.id


async def bind_token_to_host(db: AsyncSession, token_id: UUID, host_id: UUID) -> None:
    """Stamp the consumed token with the host it enrolled.

    Separated from `consume_token` because the host row doesn't exist
    yet at consume time. Called once the host insert has flushed.
    """
    await db.execute(
        update(EnrollmentToken)
        .where(EnrollmentToken.id == token_id)
        .values(used_by_host_id=host_id)
    )
