"""Pydantic payloads for the Jobs API (M23.b)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from app.models import (
    JobArtifactKind,
    JobKind,
    JobRunStatus,
    JobScopeKind,
    JobStatus,
)
from app.schemas.common import ORMModel


class JobScope(BaseModel):
    """Where the job runs. Exactly one of host_ids / group_id /
    all_online may be set."""

    kind: JobScopeKind
    host_ids: list[UUID] | None = None
    group_id: UUID | None = None

    @model_validator(mode="after")
    def _check(self) -> JobScope:
        if self.kind == JobScopeKind.HOST_IDS:
            if not self.host_ids:
                raise ValueError("scope kind=host_ids requires non-empty host_ids")
            if self.group_id is not None:
                raise ValueError("scope kind=host_ids cannot also set group_id")
        elif self.kind == JobScopeKind.HOST_GROUP:
            if self.group_id is None:
                raise ValueError("scope kind=host_group requires group_id")
            if self.host_ids:
                raise ValueError("scope kind=host_group cannot also set host_ids")
        elif self.kind == JobScopeKind.ALL_ONLINE:
            if self.host_ids or self.group_id is not None:
                raise ValueError("scope kind=all_online cannot set host_ids/group_id")
        return self


class JobCreate(BaseModel):
    kind: JobKind
    parameters: dict[str, Any] = Field(default_factory=dict)
    scope: JobScope
    summary: str = ""


class JobArtifactOut(ORMModel):
    id: UUID
    job_run_id: UUID
    kind: JobArtifactKind
    bucket: str
    object_key: str
    size_bytes: int
    sha256: str | None = None
    artifact_metadata: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None
    downloaded_by_user_id: UUID | None = None
    downloaded_at: datetime | None = None
    created_at: datetime


class JobRunOut(ORMModel):
    id: UUID
    job_id: UUID
    host_id: UUID
    host_hostname: str | None = None
    command_id: UUID | None = None
    status: JobRunStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    progress_pct: int
    progress_message: str | None = None
    last_progress_at: datetime | None = None
    artifact_count: int = 0
    created_at: datetime
    updated_at: datetime


class JobOut(ORMModel):
    id: UUID
    kind: JobKind
    parameters: dict[str, Any]
    scope_kind: JobScopeKind
    scope_host_ids: list[str] | None = None
    scope_group_id: UUID | None = None
    status: JobStatus
    summary: str
    created_by_user_id: UUID | None = None
    triggered_by_alert_id: UUID | None = None
    triggered_by: str
    canceled_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    # Aggregates so list rows don't N+1 fetch.
    run_count: int = 0
    run_completed: int = 0
    run_failed: int = 0


class JobDetail(JobOut):
    """Job + its runs. Used by GET /api/jobs/{id}."""

    runs: list[JobRunOut] = Field(default_factory=list)


class JobProgressIn(BaseModel):
    """Agent-side progress ping (gRPC -> manager)."""

    run_id: UUID
    status: JobRunStatus
    progress_pct: int = Field(ge=0, le=100, default=0)
    progress_message: str | None = None
    error: str | None = None


class ArtifactDownloadOut(BaseModel):
    """Response payload for GET /api/artifacts/{id}/download — manager
    hands back the presigned GET URL rather than streaming the bytes
    itself, so MinIO does the heavy lifting."""

    url: str
    expires_at: datetime
