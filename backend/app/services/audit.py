"""Append-only audit log helper.

M12.f tamper-evidence: every row written through `record()` carries
an HMAC of (`prev_row_hmac` || `canonical_payload`), keyed off
`VIGIL_AUDIT_HMAC_KEY`. The chain is verifiable via the verifier in
`app.services.audit_verifier`.

If `VIGIL_AUDIT_HMAC_KEY` is unset the chain stays dormant — rows
write with NULL hmac fields, and the verifier treats them as the
pre-chain era. This keeps dev environments simple while production
deployments turn on tamper-evidence by setting the key.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Actor
from app.models import AuditLog


def _load_hmac_key() -> bytes | None:
    raw = os.environ.get("VIGIL_AUDIT_HMAC_KEY")
    if not raw:
        return None
    # Accept hex (preferred — easy to rotate as a string), otherwise
    # treat the raw bytes as the key. Reject keys shorter than 16
    # bytes — too short to provide meaningful tamper-evidence.
    try:
        decoded = bytes.fromhex(raw)
        if len(decoded) >= 16:
            return decoded
    except ValueError:
        pass
    if len(raw) >= 16:
        return raw.encode("utf-8")
    return None


# Cache the key at import time. Rotating the key requires a process
# restart, which is desired — silent rotation could mask a break.
_HMAC_KEY = _load_hmac_key()


def canonical_row_bytes(
    *,
    seq: int,
    actor_kind: str,
    user_id: str | None,
    api_token_id: str | None,
    action: str,
    resource_type: str | None,
    resource_id: str | None,
    payload: dict[str, Any] | None,
    ip: str | None,
    ts_iso: str,
) -> bytes:
    """Stable canonical encoding of an audit row for HMAC computation.

    Encoding uses sorted JSON (sort_keys=True, separators with no
    whitespace, UTF-8) so the same logical row always serialises to
    the same bytes regardless of how Python iterates the dict, what
    SQLAlchemy returns from the DB, or whether the row was just
    written or fetched back later.
    """
    obj = {
        "seq": seq,
        "actor_kind": actor_kind,
        "user_id": user_id,
        "api_token_id": api_token_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "payload": payload,
        "ip": ip,
        "ts": ts_iso,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_row_hmac(prev_hmac: bytes | None, canonical: bytes) -> bytes:
    """HMAC-SHA256 of `prev_hmac || canonical`. Empty prev for the
    chain root."""
    if _HMAC_KEY is None:
        raise RuntimeError("VIGIL_AUDIT_HMAC_KEY not set")
    h = hmac.new(_HMAC_KEY, digestmod=hashlib.sha256)
    h.update(prev_hmac if prev_hmac is not None else b"")
    h.update(canonical)
    return h.digest()


async def record(
    db: AsyncSession,
    *,
    actor: Actor | None,
    action: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    payload: dict[str, Any] | None = None,
    ip: str | None = None,
) -> None:
    user_id = actor.user.id if actor else None
    api_token_id = actor.token_id if actor and actor.kind == "api_token" else None
    actor_kind = actor.kind if actor else "system"

    row = AuditLog(
        user_id=user_id,
        api_token_id=api_token_id,
        actor_kind=actor_kind,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
        ip=ip,
    )

    if _HMAC_KEY is None:
        # Chain dormant. seq still gets assigned by the server
        # default; prev_hmac and row_hmac stay NULL.
        db.add(row)
        return

    # Chain active: serialize via SELECT FOR UPDATE on the latest
    # chained row so concurrent writers compute hmacs in a total
    # order. The lock is released on commit. We then need the
    # server to assign `seq` (via DEFAULT nextval) so we INSERT,
    # flush, and compute the hmac after.
    prev_stmt = (
        select(AuditLog.row_hmac)
        .where(AuditLog.row_hmac.is_not(None))
        .order_by(AuditLog.seq.desc())
        .limit(1)
        .with_for_update()
    )
    prev_hmac = (await db.execute(prev_stmt)).scalar_one_or_none()
    row.prev_hmac = prev_hmac
    db.add(row)
    await db.flush()  # assigns seq + ts via server defaults

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
    row.row_hmac = compute_row_hmac(prev_hmac, canonical)
