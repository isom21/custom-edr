"""Auth payloads."""
from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    # Plain str — email format is enforced at user-creation time; login just needs a match.
    email: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str
