"""M12.f audit log HMAC chain verifier.

Walks audit_log rows in seq order, recomputes the HMAC chain, and
reports breaks. A break means one of:

  * A row was UPDATEd (the M16.a INSERT-only privileges deny this
    via REVOKE, but a sufficiently privileged DB-level attacker
    could bypass).
  * A row was DELETEd (same).
  * A row was INSERTed at the wrong sequence position.
  * The HMAC key was changed without resetting the chain (which
    would invalidate every row written under the old key).

Rows whose `row_hmac` is NULL are treated as the pre-chain era —
they're skipped silently. The chain starts at the first row with
a non-NULL row_hmac.

CLI usage:
    python -m app.services.audit_verifier
"""

from __future__ import annotations

import asyncio
import logging
import sys
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import SessionLocal
from app.models import AuditLog
from app.services.audit import canonical_row_bytes, compute_row_hmac


@dataclass
class ChainBreak:
    seq: int
    row_id: str
    reason: str
    expected_hmac: bytes | None
    actual_hmac: bytes | None


@dataclass
class VerifyResult:
    rows_examined: int
    chain_rows: int  # rows that had a row_hmac (i.e. participate in the chain)
    breaks: list[ChainBreak]

    @property
    def ok(self) -> bool:
        return not self.breaks


async def verify_chain(db: AsyncSession) -> VerifyResult:
    stmt = select(AuditLog).order_by(AuditLog.seq.asc())
    breaks: list[ChainBreak] = []
    prev_hmac: bytes | None = None
    chain_started = False
    chain_rows = 0
    rows_examined = 0
    async for row in (await db.stream(stmt)).scalars():
        rows_examined += 1
        if row.row_hmac is None:
            # Pre-chain row, or a row written while VIGIL_AUDIT_HMAC_KEY
            # was unset. Skip without breaking the chain — the chain
            # resumes at the next non-null row.
            continue
        chain_rows += 1
        # Recompute what this row's HMAC should have been.
        canonical = canonical_row_bytes(
            seq=row.seq,
            actor_kind=row.actor_kind,
            user_id=str(row.user_id) if row.user_id else None,
            api_token_id=str(row.api_token_id) if row.api_token_id else None,
            action=row.action,
            resource_type=row.resource_type,
            resource_id=row.resource_id,
            payload=row.payload,
            ip=row.ip,
            ts_iso=row.ts.isoformat() if row.ts else "",
        )
        if not chain_started:
            # First chain row — its prev_hmac should be NULL.
            if row.prev_hmac is not None:
                breaks.append(
                    ChainBreak(
                        seq=row.seq,
                        row_id=str(row.id),
                        reason="first chain row has non-NULL prev_hmac",
                        expected_hmac=None,
                        actual_hmac=row.prev_hmac,
                    )
                )
            chain_started = True
        else:
            if row.prev_hmac != prev_hmac:
                breaks.append(
                    ChainBreak(
                        seq=row.seq,
                        row_id=str(row.id),
                        reason="prev_hmac mismatch — row tampered or one missing",
                        expected_hmac=prev_hmac,
                        actual_hmac=row.prev_hmac,
                    )
                )
        try:
            expected = compute_row_hmac(row.prev_hmac, canonical)
        except RuntimeError:
            # VIGIL_AUDIT_HMAC_KEY unset — can't verify.
            return VerifyResult(rows_examined, chain_rows, breaks)
        if expected != row.row_hmac:
            breaks.append(
                ChainBreak(
                    seq=row.seq,
                    row_id=str(row.id),
                    reason="row_hmac mismatch — row content tampered",
                    expected_hmac=expected,
                    actual_hmac=row.row_hmac,
                )
            )
        prev_hmac = row.row_hmac

    return VerifyResult(rows_examined, chain_rows, breaks)


async def _cli() -> int:
    logging.basicConfig(level=logging.INFO)
    async with SessionLocal() as db:
        result = await verify_chain(db)
    print(
        f"audit chain: examined {result.rows_examined} rows, "
        f"{result.chain_rows} chain rows, breaks={len(result.breaks)}"
    )
    for b in result.breaks:
        print(f"  break at seq={b.seq} id={b.row_id}: {b.reason}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(_cli()))
