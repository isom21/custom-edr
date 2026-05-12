"""TOTP 2FA: opt-in self-service enrollment + two-step login.

Covers:
  * Setup → verify-setup → status flow.
  * /login returns mfa_required when the account has 2FA enabled;
    /login/2fa exchanges the pending token for a real TokenPair.
  * Recovery codes work, are one-shot, and shrink the list on use.
  * Disable requires a valid code.
  * Admin force-disable (account recovery) clears all 2FA state.
  * UserOut surfaces totp_enabled to admins.
"""

from __future__ import annotations

import pyotp
import pytest
import pytest_asyncio
from sqlalchemy import select


@pytest_asyncio.fixture
async def analyst_jwt(analyst_user) -> str:
    from tests.conftest import make_jwt

    return make_jwt(str(analyst_user.id), "analyst")


@pytest_asyncio.fixture
async def analyst_auth_headers(analyst_jwt: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {analyst_jwt}"}


async def _enroll(http_client, headers) -> tuple[str, list[str]]:
    """Run the full setup → verify flow. Returns (secret, recovery_codes)."""
    setup = await http_client.post("/api/auth/2fa/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret_base32"]
    assert setup.json()["provisioning_uri"].startswith("otpauth://totp/")

    code = pyotp.TOTP(secret).now()
    verify = await http_client.post(
        "/api/auth/2fa/verify-setup", json={"code": code}, headers=headers
    )
    assert verify.status_code == 200, verify.text
    body = verify.json()
    assert body["enabled"] is True
    assert len(body["recovery_codes"]) == 10
    return secret, body["recovery_codes"]


# ---------- enrollment ----------


@pytest.mark.asyncio
async def test_setup_then_verify_enables_2fa(http_client, analyst_user, analyst_auth_headers):
    status = await http_client.get("/api/auth/2fa/status", headers=analyst_auth_headers)
    assert status.json() == {"enabled": False, "pending": False}

    _secret, _codes = await _enroll(http_client, analyst_auth_headers)

    status = await http_client.get("/api/auth/2fa/status", headers=analyst_auth_headers)
    assert status.json() == {"enabled": True, "pending": False}


@pytest.mark.asyncio
async def test_verify_setup_rejects_wrong_code(http_client, analyst_auth_headers):
    setup = await http_client.post("/api/auth/2fa/setup", headers=analyst_auth_headers)
    assert setup.status_code == 200

    wrong = await http_client.post(
        "/api/auth/2fa/verify-setup", json={"code": "000000"}, headers=analyst_auth_headers
    )
    assert wrong.status_code == 400

    status = await http_client.get("/api/auth/2fa/status", headers=analyst_auth_headers)
    # Still pending — wrong code shouldn't have enabled anything.
    assert status.json() == {"enabled": False, "pending": True}


@pytest.mark.asyncio
async def test_setup_refused_when_already_enabled(http_client, analyst_auth_headers):
    await _enroll(http_client, analyst_auth_headers)
    again = await http_client.post("/api/auth/2fa/setup", headers=analyst_auth_headers)
    assert again.status_code == 400


# ---------- two-step login ----------


@pytest.mark.asyncio
async def test_login_without_2fa_returns_tokens_directly(http_client, db_session):
    from app.core.security import hash_password
    from app.models import User, UserRole

    user = User(
        email="login-no-2fa@test.local",
        password_hash=hash_password("test-password-123"),
        role=UserRole.ANALYST,
    )
    db_session.add(user)
    await db_session.flush()

    resp = await http_client.post(
        "/api/auth/login", json={"email": user.email, "password": "test-password-123"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["mfa_required"] is False


@pytest.mark.asyncio
async def test_login_with_2fa_returns_pending_then_exchanges_with_totp(
    http_client, db_session, analyst_user, analyst_auth_headers
):
    secret, _ = await _enroll(http_client, analyst_auth_headers)
    # Set a known password so we can sign in.
    from app.core.security import hash_password

    analyst_user.password_hash = hash_password("test-password-123")
    await db_session.flush()

    login = await http_client.post(
        "/api/auth/login", json={"email": analyst_user.email, "password": "test-password-123"}
    )
    assert login.status_code == 200
    body = login.json()
    assert body["mfa_required"] is True
    assert body["access_token"] is None
    assert body["mfa_token"]

    # Now exchange.
    code = pyotp.TOTP(secret).now()
    exchange = await http_client.post(
        "/api/auth/login/2fa", json={"mfa_token": body["mfa_token"], "code": code}
    )
    assert exchange.status_code == 200
    pair = exchange.json()
    assert pair["access_token"]
    assert pair["refresh_token"]
    assert pair["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_2fa_rejects_wrong_code(
    http_client, db_session, analyst_user, analyst_auth_headers
):
    _, _ = await _enroll(http_client, analyst_auth_headers)
    from app.core.security import hash_password

    analyst_user.password_hash = hash_password("test-password-123")
    await db_session.flush()

    login = await http_client.post(
        "/api/auth/login", json={"email": analyst_user.email, "password": "test-password-123"}
    )
    mfa_token = login.json()["mfa_token"]

    bad = await http_client.post(
        "/api/auth/login/2fa", json={"mfa_token": mfa_token, "code": "000000"}
    )
    assert bad.status_code == 401


@pytest.mark.asyncio
async def test_login_2fa_recovery_code_works_and_is_consumed(
    http_client, db_session, analyst_user, analyst_auth_headers
):
    _, recovery_codes = await _enroll(http_client, analyst_auth_headers)
    from app.core.security import hash_password
    from app.models import User

    analyst_user.password_hash = hash_password("test-password-123")
    await db_session.flush()

    login = await http_client.post(
        "/api/auth/login", json={"email": analyst_user.email, "password": "test-password-123"}
    )
    mfa_token = login.json()["mfa_token"]

    use_recovery = await http_client.post(
        "/api/auth/login/2fa", json={"mfa_token": mfa_token, "code": recovery_codes[0]}
    )
    assert use_recovery.status_code == 200
    assert use_recovery.json()["access_token"]

    # The recovery code is now consumed. Sign in again and try to
    # reuse the same code — it must be rejected.
    login2 = await http_client.post(
        "/api/auth/login", json={"email": analyst_user.email, "password": "test-password-123"}
    )
    second = await http_client.post(
        "/api/auth/login/2fa",
        json={"mfa_token": login2.json()["mfa_token"], "code": recovery_codes[0]},
    )
    assert second.status_code == 401

    # The list itself shrank by one.
    refreshed = (
        await db_session.execute(select(User).where(User.id == analyst_user.id))
    ).scalar_one()
    assert len(refreshed.totp_recovery_codes_hashed) == 9


# ---------- disable ----------


@pytest.mark.asyncio
async def test_disable_requires_valid_code(http_client, analyst_auth_headers):
    secret, _ = await _enroll(http_client, analyst_auth_headers)

    bad = await http_client.post(
        "/api/auth/2fa/disable", json={"code": "000000"}, headers=analyst_auth_headers
    )
    assert bad.status_code == 401

    code = pyotp.TOTP(secret).now()
    ok = await http_client.post(
        "/api/auth/2fa/disable", json={"code": code}, headers=analyst_auth_headers
    )
    assert ok.status_code == 204

    status = await http_client.get("/api/auth/2fa/status", headers=analyst_auth_headers)
    assert status.json() == {"enabled": False, "pending": False}


# ---------- admin force-disable ----------


@pytest.mark.asyncio
async def test_admin_can_force_disable_another_users_2fa(
    http_client, analyst_user, analyst_auth_headers, admin_headers, db_session
):
    await _enroll(http_client, analyst_auth_headers)

    resp = await http_client.post(
        f"/api/users/{analyst_user.id}/2fa/disable", headers=admin_headers
    )
    assert resp.status_code == 204

    from app.models import User

    refreshed = (
        await db_session.execute(select(User).where(User.id == analyst_user.id))
    ).scalar_one()
    assert refreshed.totp_enabled is False
    assert refreshed.totp_secret_encrypted is None
    assert refreshed.totp_recovery_codes_hashed is None


@pytest.mark.asyncio
async def test_admin_force_disable_404_for_unknown_user(http_client, admin_headers):
    import uuid

    resp = await http_client.post(f"/api/users/{uuid.uuid4()}/2fa/disable", headers=admin_headers)
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_force_disable_rejected_when_not_enrolled(
    http_client, analyst_user, admin_headers
):
    resp = await http_client.post(
        f"/api/users/{analyst_user.id}/2fa/disable", headers=admin_headers
    )
    assert resp.status_code == 400


# ---------- admin visibility ----------


@pytest.mark.asyncio
async def test_users_list_surfaces_totp_enabled_for_admin(
    http_client, analyst_user, analyst_auth_headers, admin_headers
):
    await _enroll(http_client, analyst_auth_headers)

    resp = await http_client.get("/api/users", headers=admin_headers)
    assert resp.status_code == 200
    row = next(u for u in resp.json() if u["id"] == str(analyst_user.id))
    assert row["totp_enabled"] is True


# ---------- api tokens skip the 2FA endpoints ----------


@pytest.mark.asyncio
async def test_api_token_cannot_manage_2fa(http_client, db_session, analyst_user):
    """API tokens are opaque machine credentials — 2FA setup belongs to
    interactive users only. The endpoint rejects them explicitly."""
    from datetime import UTC, datetime, timedelta

    from app.core.security import format_api_token, generate_api_token_secret, hash_api_token_secret
    from app.models import ApiToken

    secret = generate_api_token_secret()
    tok = ApiToken(
        user_id=analyst_user.id,
        name="test-tok",
        secret_hash=hash_api_token_secret(secret),
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    db_session.add(tok)
    await db_session.flush()

    full = format_api_token(tok.id, secret)
    resp = await http_client.post(
        "/api/auth/2fa/setup", headers={"Authorization": f"Bearer {full}"}
    )
    assert resp.status_code == 401
