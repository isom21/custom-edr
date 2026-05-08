"""Sigma compile + test payloads."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SigmaCompileRequest(BaseModel):
    body: str = Field(min_length=1)


class SigmaCompileResponse(BaseModel):
    ok: bool
    query: str | None = None
    title: str | None = None
    description: str | None = None
    error: str | None = None


class SigmaTestRequest(BaseModel):
    """Body for POST /api/rules/{id}/test or /api/rules/test (ad-hoc)."""

    body: str | None = Field(
        default=None, description="Override the saved rule body for this run only."
    )
    lookback_hours: int = Field(default=24, ge=1, le=168)


class SigmaTestSampleHit(BaseModel):
    timestamp: str | None
    host_id: str | None
    event_id: str | None
    process: dict[str, Any] | None
    file: dict[str, Any] | None


class SigmaTestResponse(BaseModel):
    query: str
    total: int
    samples: list[SigmaTestSampleHit]
