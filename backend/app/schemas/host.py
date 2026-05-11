"""Host payloads."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models import HostStatus, OsFamily
from app.schemas.common import ORMModel


class HostOut(ORMModel):
    id: UUID
    hostname: str
    os_family: OsFamily
    os_version: str | None
    os_platform: str | None
    os_arch: str | None
    agent_version: str | None
    status: HostStatus
    enrolled_at: datetime | None
    last_seen_at: datetime | None
    policy_id: UUID | None


class HostUpdate(BaseModel):
    policy_id: UUID | None = None
    status: HostStatus | None = None


class HostListFilter(BaseModel):
    status: HostStatus | None = None
    os_family: OsFamily | None = None
    q: str | None = Field(default=None, description="hostname substring")
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


# ----- M20.j live telemetry tab -----


class LiveTelemetryEvent(BaseModel):
    """One ECS document flattened for the live host telemetry table."""

    event_id: str
    timestamp: datetime
    category: list[str] = Field(default_factory=list)
    action: str | None = None
    outcome: str | None = None
    pid: int | None = None
    executable: str | None = None
    command_line: str | None = None
    file_path: str | None = None
    file_action: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    transport: str | None = None
    rule_name: str | None = None
    sha256: str | None = None


class LiveTelemetryPage(BaseModel):
    """A polling window of telemetry — newest doc on the right.

    Callers pass `since` (the most recent @timestamp they've seen) and
    walk forward. `latest_timestamp` is the @timestamp of the last
    event returned; clients pass that back as `since` next tick.
    """

    host_id: UUID
    events: list[LiveTelemetryEvent] = Field(default_factory=list)
    latest_timestamp: datetime | None = None
    truncated: bool = False
