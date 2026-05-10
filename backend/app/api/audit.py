"""M12.f audit log integrity endpoint.

Admin-only. Returns the result of running the HMAC chain verifier
across the entire audit_log table. Operators can also run
`python -m app.services.audit_verifier` from the host to get the
same result over the CLI.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

from app.core.deps import DbSession, RequireAdmin
from app.services.audit_verifier import verify_chain

router = APIRouter(prefix="/api/audit", tags=["audit"])


class ChainBreakOut(BaseModel):
    seq: int
    row_id: str
    reason: str
    expected_hmac_hex: str | None
    actual_hmac_hex: str | None


class VerifyResultOut(BaseModel):
    ok: bool
    rows_examined: int
    chain_rows: int
    breaks: list[ChainBreakOut]


@router.get("/verify", response_model=VerifyResultOut)
async def verify(
    db: DbSession,
    _admin: RequireAdmin,
) -> VerifyResultOut:
    """Run the audit chain verifier and return the result.

    O(n) over the audit_log table — for very large logs this should
    be invoked from a maintenance window, not the live request
    path. Currently no incremental verification (M12.f follow-up).
    """
    result = await verify_chain(db)
    return VerifyResultOut(
        ok=result.ok,
        rows_examined=result.rows_examined,
        chain_rows=result.chain_rows,
        breaks=[
            ChainBreakOut(
                seq=b.seq,
                row_id=b.row_id,
                reason=b.reason,
                expected_hmac_hex=b.expected_hmac.hex() if b.expected_hmac else None,
                actual_hmac_hex=b.actual_hmac.hex() if b.actual_hmac else None,
            )
            for b in result.breaks
        ],
    )
