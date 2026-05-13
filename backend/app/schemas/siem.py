"""Pydantic schemas for the SIEM destination CRUD API."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import SiemKind
from app.schemas.common import ORMModel


class SiemDestinationOut(ORMModel):
    """Outbound shape — never includes plaintext secrets.

    `config` carries the destination's connection params with secret
    fields masked to "***" (see services/siem.redact_secrets). The UI
    relies on this to display non-secret connection details (host,
    port, sourcetype, etc.) while never round-tripping the real
    credential.
    """

    id: UUID
    name: str
    kind: SiemKind
    enabled: bool
    last_send_at: datetime | None
    lag_seconds: float
    error_count: int
    config: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class SiemDestinationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: SiemKind
    enabled: bool = True
    # Free-form per-kind config dict. The API validates the per-kind
    # required fields rather than locking each variant into its own
    # schema — operators can add destination-specific fields (TLS CA,
    # facility, etc.) without a code change.
    config: dict[str, Any]


class SiemDestinationUpdate(BaseModel):
    """Partial update — only fields actually included in the request
    body are applied. `config` replaces the entire stored blob; the
    caller must round-trip the full secret value if it needs to change
    (we don't store plaintext, so we can't merge partials)."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    config: dict[str, Any] | None = None


__all__ = ["SiemDestinationCreate", "SiemDestinationOut", "SiemDestinationUpdate"]
