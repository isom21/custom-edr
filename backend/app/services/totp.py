"""TOTP 2FA helpers.

Encrypts user secrets at rest with Fernet (settings.totp_encryption_key),
generates RFC 4226 / 6238 codes via pyotp, and manages bcrypt-hashed
recovery codes consumed one-shot.

The plaintext recovery codes leave this module exactly once — at the
moment they're returned from `generate_recovery_codes` — and are
never recoverable thereafter. Callers must surface them to the user
in the same response and not persist the plaintext anywhere.
"""

from __future__ import annotations

import secrets

import pyotp
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import TOTP_KEY_DEV_DEFAULT, settings
from app.core.security import hash_password, verify_password

_ISSUER = "Vigil EDR"
_RECOVERY_CODE_COUNT = 10
# 10 char Crockford-base32 minus visually-ambiguous 0/O/1/I, giving
# 27**10 ≈ 2.06e14 possible codes per user — guess-rate-limit on the
# verify path keeps brute-force impractical.
_RECOVERY_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
_RECOVERY_CODE_LEN = 10


def _fernet() -> Fernet:
    """Build a Fernet from settings.totp_encryption_key. Validates the
    key shape lazily so a missing key only fails when 2FA is exercised
    rather than at import time."""
    key = settings.totp_encryption_key or TOTP_KEY_DEV_DEFAULT
    return Fernet(key.encode("ascii"))


def encrypt_secret(secret_b32: str) -> bytes:
    return _fernet().encrypt(secret_b32.encode("ascii"))


def decrypt_secret(blob: bytes) -> str:
    try:
        return _fernet().decrypt(blob).decode("ascii")
    except InvalidToken as exc:
        raise RuntimeError(
            "stored TOTP secret could not be decrypted; "
            "VIGIL_TOTP_ENCRYPTION_KEY may have been rotated without re-enrollment"
        ) from exc


def generate_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret_b32: str, *, account_name: str) -> str:
    return pyotp.TOTP(secret_b32).provisioning_uri(name=account_name, issuer_name=_ISSUER)


def verify_code(secret_b32: str, code: str) -> bool:
    """Verify a 6-digit TOTP code. Allows ±1 step (±30s) for clock skew
    — the standard pyotp default and the same window every Google /
    Microsoft authenticator uses on the server side."""
    if not code or not code.strip().isdigit():
        return False
    return pyotp.TOTP(secret_b32).verify(code.strip(), valid_window=1)


def generate_recovery_codes() -> tuple[list[str], list[str]]:
    """Return (plaintext_codes, hashed_codes). Plaintext is shown to
    the user once; only the hashes are persisted."""
    plaintext: list[str] = []
    for _ in range(_RECOVERY_CODE_COUNT):
        chars = [secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_CODE_LEN)]
        plaintext.append("".join(chars))
    hashed = [hash_password(c) for c in plaintext]
    return plaintext, hashed


def consume_recovery_code(hashed_codes: list[str], candidate: str) -> list[str] | None:
    """If `candidate` matches one of the hashes, return the list with
    that hash removed (caller persists). Otherwise None. Comparison
    runs through every hash so a hit and a miss take similar time —
    bcrypt itself is constant-time per comparison, so total time is
    a linear function of list length regardless of which (if any)
    matched."""
    candidate = candidate.strip().upper().replace(" ", "").replace("-", "")
    if not candidate:
        return None
    match_index: int | None = None
    for idx, h in enumerate(hashed_codes):
        if verify_password(candidate, h) and match_index is None:
            match_index = idx
    if match_index is None:
        return None
    return [h for i, h in enumerate(hashed_codes) if i != match_index]
