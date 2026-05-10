"""Append-only audit log helper."""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import Actor
from app.models import AuditLog


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
    db.add(
        AuditLog(
            user_id=actor.user.id if actor else None,
            # M17.c: also stamp the api_token_id when the actor came in via
            # a `Bearer edr_…` token so auditors can link actions to the
            # token (esp. after the token is later revoked).
            api_token_id=actor.token_id if actor and actor.kind == "api_token" else None,
            actor_kind=actor.kind if actor else "system",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=payload,
            ip=ip,
        )
    )
