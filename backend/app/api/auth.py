"""Login, refresh, logout."""

from __future__ import annotations

import os
import time
from collections import deque
from threading import Lock
from uuid import UUID

import jwt
from fastapi import APIRouter, Cookie, Request, Response

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.deps import DbSession
from app.core.errors import unauthorized
from app.core.security import decode_jwt
from app.models import User
from app.schemas.auth import LoginRequest, RefreshRequest, TokenPair
from app.services import audit
from app.services import auth as auth_service

router = APIRouter(prefix="/api/auth", tags=["auth"])


# M-frontend-auth #10: the refresh token rides on a server-set
# HttpOnly cookie so XSS in the SPA can't read it. We also keep
# returning the refresh in the body so existing scripted clients
# (smoke tests, ops tooling) don't break — the cookie is additive.
# Frontend uses `credentials: "include"` on POST /refresh and never
# reads the body's refresh_token.
_REFRESH_COOKIE_NAME = "vigil_refresh"


def _refresh_cookie_max_age() -> int:
    return int(settings.jwt_refresh_ttl_days) * 24 * 3600


def _set_refresh_cookie(response: Response, refresh_token: str) -> None:
    """HttpOnly + SameSite=Strict; secure flag follows `settings.debug`
    so dev (HTTP localhost) doesn't drop the cookie."""
    response.set_cookie(
        key=_REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=_refresh_cookie_max_age(),
        httponly=True,
        secure=not settings.debug,
        samesite="strict",
        path="/api/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=_REFRESH_COOKIE_NAME, path="/api/auth")


# M-audit-and-auth #8: per-email failed-login throttle.
#
# The per-IP anon limiter (rate_limit.py, default 10/min) catches a
# single attacker IP; a distributed credential-stuffing run across
# residential proxies sits comfortably under that cap and the audit
# log records every miss but nothing pushes back. Add an in-memory
# sliding window keyed by the lowercase email so the same target
# account can absorb at most N failures inside T seconds before /login
# rejects with 429 regardless of source IP.
#
# In-memory is the right shape for the single-instance manager today.
# M15 multi-instance swaps in Redis (same hot path; replace this
# module's _window dict with a redis-backed equivalent).

_LOGIN_FAIL_LIMIT = int(os.environ.get("VIGIL_LOGIN_FAIL_LIMIT", 10))
_LOGIN_FAIL_WINDOW_S = int(os.environ.get("VIGIL_LOGIN_FAIL_WINDOW_S", 300))
_login_fails: dict[str, deque[float]] = {}
_login_fails_lock = Lock()


def _record_login_failure(email_key: str) -> tuple[bool, int]:
    """Append a failure timestamp for ``email_key`` (lowercase email).

    Returns ``(blocked, retry_after_s)``: if the sliding window has
    `_LOGIN_FAIL_LIMIT` or more failures inside `_LOGIN_FAIL_WINDOW_S`,
    we tell the caller to back off. The lock serialises the trim +
    append so two concurrent failing logins can't both slip through
    the gate.
    """
    now = time.monotonic()
    cutoff = now - _LOGIN_FAIL_WINDOW_S
    with _login_fails_lock:
        bucket = _login_fails.setdefault(email_key, deque())
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        bucket.append(now)
        if len(bucket) > _LOGIN_FAIL_LIMIT:
            retry_after = max(1, int(bucket[0] + _LOGIN_FAIL_WINDOW_S - now))
            return True, retry_after
        return False, 0


def _clear_login_failures(email_key: str) -> None:
    """A successful login clears the failure counter for that email so
    a legitimate user whose typo'd password tripped the gate isn't
    left with a stale strike count."""
    with _login_fails_lock:
        _login_fails.pop(email_key, None)


@router.post("/login", response_model=TokenPair)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession,
) -> TokenPair:
    ip = request.client.host if request.client else None
    email_key = payload.email.lower()

    # Pre-check the throttle. If the email is already over the
    # threshold, fail before we even hit the password verifier — that
    # closes the timing channel where a slow argon2 hash leaked which
    # accounts were under attack.
    with _login_fails_lock:
        bucket = _login_fails.get(email_key)
        if bucket and len(bucket) >= _LOGIN_FAIL_LIMIT:
            cutoff = time.monotonic() - _LOGIN_FAIL_WINDOW_S
            live = sum(1 for t in bucket if t >= cutoff)
            if live >= _LOGIN_FAIL_LIMIT:
                async with SessionLocal() as audit_db:
                    await audit.record(
                        audit_db,
                        actor=None,
                        action="user.login.throttled",
                        resource_type="user",
                        resource_id=None,
                        payload={"email": email_key, "window_s": _LOGIN_FAIL_WINDOW_S},
                        ip=ip,
                    )
                    await audit_db.commit()
                from fastapi import HTTPException

                raise HTTPException(
                    status_code=429,
                    detail="too many failed login attempts; try again later",
                    headers={"Retry-After": str(_LOGIN_FAIL_WINDOW_S)},
                )

    try:
        user = await auth_service.authenticate(db, email=payload.email, password=payload.password)
    except auth_service.InvalidCredentials as exc:
        # M-audit-and-auth #1: record failed logins so brute-force /
        # credential-stuffing has a trip-wire. We can't write through
        # `db` because the request session will rollback on the raised
        # 401 — open a fresh session that commits independently.
        async with SessionLocal() as audit_db:
            await audit.record(
                audit_db,
                actor=None,
                action="user.login.failed",
                resource_type="user",
                resource_id=exc.user_id,
                payload={"email": email_key, "reason": exc.reason},
                ip=ip,
            )
            await audit_db.commit()
        _record_login_failure(email_key)
        raise unauthorized("invalid credentials") from exc

    _clear_login_failures(email_key)
    await audit.record(
        db,
        actor=None,
        action="user.login",
        resource_type="user",
        resource_id=str(user.id),
        ip=ip,
    )
    pair = auth_service.issue_token_pair(user)
    _set_refresh_cookie(response, pair["refresh_token"])
    return TokenPair(**pair)


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    payload: RefreshRequest,
    response: Response,
    db: DbSession,
    vigil_refresh: str | None = Cookie(default=None),
) -> TokenPair:
    # M-frontend-auth #10: prefer the HttpOnly cookie. Body-shape stays
    # for scripted callers (smoke tests, ops tooling). If neither is
    # present, that's a malformed request — 401 with a clear message.
    token = payload.refresh_token or vigil_refresh
    if not token:
        raise unauthorized("missing refresh token")
    try:
        decoded = decode_jwt(token)
    except jwt.ExpiredSignatureError as exc:
        raise unauthorized("refresh token expired") from exc
    except jwt.PyJWTError as exc:
        raise unauthorized("invalid refresh token") from exc
    if decoded.get("type") != "refresh":
        raise unauthorized("not a refresh token")
    user = await db.get(User, UUID(decoded["sub"]))
    if user is None or user.disabled:
        raise unauthorized("user inactive")
    pair = auth_service.issue_token_pair(user)
    _set_refresh_cookie(response, pair["refresh_token"])
    return TokenPair(**pair)


@router.post("/logout", status_code=204)
async def logout(response: Response) -> Response:
    """Clear the refresh cookie. The access token is in-memory only
    in the SPA so the client drops it by reload. Logout doesn't
    invalidate the JWTs themselves (we don't operate a denylist) —
    they just stop being reachable. Operators who need true
    revocation should disable the user via /api/users."""
    _clear_refresh_cookie(response)
    response.status_code = 204
    return response
