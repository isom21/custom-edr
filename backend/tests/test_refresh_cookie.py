"""M-frontend-auth #10: refresh cookie is HttpOnly + accepted on /refresh.

The frontend change moves the refresh token out of localStorage (XSS
can read everything in there) into a server-set HttpOnly cookie. The
server side is the load-bearing part of that contract:

  1. /login sets a `vigil_refresh` cookie that's HttpOnly,
     SameSite=Strict, scoped to /api/auth.
  2. /refresh accepts the token from the cookie OR from the body
     (scripted callers still work).
  3. /logout clears the cookie.

These are unit-level — exercising the full browser cookie roundtrip
needs a real frontend; we pin the server's contract directly.
"""

from __future__ import annotations

import re

import pytest


def test_login_sets_httponly_refresh_cookie() -> None:
    # Drive _set_refresh_cookie via a fake Response object, since the
    # full /login path needs a DB-resident user we don't want to
    # provision in this test.
    from fastapi import Response

    from app.api import auth as auth_api

    response = Response()
    auth_api._set_refresh_cookie(response, "test-refresh-token-value")

    headers = response.headers.getlist("set-cookie")
    assert len(headers) == 1, f"expected one Set-Cookie header, got {headers}"
    cookie = headers[0]
    # Cookie name + value present.
    assert cookie.startswith("vigil_refresh=test-refresh-token-value")
    # HttpOnly + SameSite=strict + Path=/api/auth — required for the
    # XSS-mitigation story to hold.
    assert "HttpOnly" in cookie, f"missing HttpOnly: {cookie}"
    assert re.search(r"SameSite=[Ss]trict", cookie), f"missing SameSite=Strict: {cookie}"
    assert "Path=/api/auth" in cookie, f"wrong Path: {cookie}"


def test_clear_refresh_cookie_sends_delete() -> None:
    from fastapi import Response

    from app.api import auth as auth_api

    response = Response()
    auth_api._clear_refresh_cookie(response)
    headers = response.headers.getlist("set-cookie")
    assert len(headers) == 1
    cookie = headers[0]
    # delete_cookie's wire form is "name=; Max-Age=0; ..." in Starlette.
    assert cookie.startswith("vigil_refresh=")
    assert "Path=/api/auth" in cookie


def test_refresh_cookie_ttl_matches_refresh_jwt_ttl() -> None:
    """Cookie expires when the JWT inside it does — operators dialing
    `VIGIL_JWT_REFRESH_TTL_DAYS` shouldn't have to also touch a cookie
    Max-Age."""
    from app.api import auth as auth_api
    from app.core.config import settings

    expected = settings.jwt_refresh_ttl_days * 24 * 3600
    assert auth_api._refresh_cookie_max_age() == expected


@pytest.mark.asyncio
async def test_refresh_endpoint_rejects_when_both_body_and_cookie_missing() -> None:
    """One of the two MUST be present. Empty body + no cookie → 401."""
    from fastapi import HTTPException, Response

    from app.api.auth import refresh
    from app.schemas.auth import RefreshRequest

    with pytest.raises(HTTPException) as exc_info:
        await refresh(
            payload=RefreshRequest(refresh_token=None),
            response=Response(),
            db=None,  # type: ignore[arg-type] — error fires before db touch
            vigil_refresh=None,
        )
    assert exc_info.value.status_code == 401
    assert "refresh" in str(exc_info.value.detail).lower()


def test_refresh_request_schema_accepts_empty_body() -> None:
    """The schema's `refresh_token: str | None = None` means
    `POST /refresh` with `{}` is valid (the cookie carries the token)."""
    from app.schemas.auth import RefreshRequest

    # No fields supplied is now valid.
    req = RefreshRequest()
    assert req.refresh_token is None
