"""Pydantic schemas for response-action commands."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import CommandKind, CommandStatus
from app.schemas.common import ORMModel


class CommandIn(BaseModel):
    kind: CommandKind
    payload: dict[str, Any] = Field(default_factory=dict)


class CommandOut(ORMModel):
    id: UUID
    host_id: UUID
    kind: CommandKind
    status: CommandStatus
    payload: dict[str, Any]
    triggered_by_alert_id: UUID | None
    triggered_by_rule_id: UUID | None
    issued_by_user_id: UUID | None
    dispatched_at: datetime | None
    completed_at: datetime | None
    error: str | None
    created_at: datetime
    updated_at: datetime
