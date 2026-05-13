"""SIEM forwarder registry + shared crypto helpers.

The forwarder worker consumes `telemetry.normalized` + `alerts.raw`,
formats each event for the destination's `kind`, and dispatches via
the per-kind sender. This module is the registry that maps
`SiemKind -> sender callable` plus the Fernet helpers used by the
API + worker to round-trip destination config.

Encryption key reuse note: per the Phase 1 plan the SIEM destinations
piggy-back on `VIGIL_NOTIFICATION_ENCRYPTION_KEY` so operators only
have to provision one Fernet secret for everything in
notifications + SIEM. If Unit 4 (alert routing) hasn't landed yet
when this PR rebases, the merge orchestrator drops `notification_*`
from `core.config.Settings` only by removing duplicates — never by
renaming, since the field name here is load-bearing for the audit
logs that callers already write under the same key.
"""

from __future__ import annotations

import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import NOTIFICATION_KEY_DEV_DEFAULT, settings
from app.models.siem_destination import SiemKind


def _fernet() -> Fernet:
    """Build the Fernet from settings.notification_encryption_key.

    Lazy so a missing key fails on first encrypt/decrypt instead of at
    import time — matters because the tests still want to import the
    module to call CEF/JSON formatters even without a real key set.
    """
    key = settings.notification_encryption_key or NOTIFICATION_KEY_DEV_DEFAULT
    return Fernet(key.encode("ascii"))


def encrypt_config(plaintext_config: dict[str, Any]) -> bytes:
    """Serialise the destination config dict to JSON and Fernet-encrypt.

    The encoder uses sort_keys so the same logical config always
    produces the same bytes — convenient when an operator updates a
    single field and we want to detect no-op updates without
    decrypting first.
    """
    payload = json.dumps(plaintext_config, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _fernet().encrypt(payload)


def decrypt_config(blob: bytes) -> dict[str, Any]:
    """Reverse `encrypt_config`. Raises RuntimeError when the key
    rotated since the row was written — the operator must re-enter the
    destination's secrets in that case."""
    try:
        plain = _fernet().decrypt(blob)
    except InvalidToken as exc:
        raise RuntimeError(
            "stored SIEM destination config could not be decrypted; "
            "VIGIL_NOTIFICATION_ENCRYPTION_KEY may have been rotated"
        ) from exc
    return json.loads(plain.decode("utf-8"))


def redact_secrets(config: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of `config` with secret fields redacted to "***".

    Used by the API surface + audit-log payload — the plaintext config
    only ever lives in process memory at send time, never on disk and
    never in audit rows.

    Conservative: anything whose key name contains "token", "key",
    "password", "secret", or "sas" gets masked. Connection-level
    fields (host, port, index, source) pass through so operators can
    see them in the UI.
    """
    out: dict[str, Any] = {}
    for k, v in config.items():
        lk = k.lower()
        if any(needle in lk for needle in ("token", "key", "password", "secret", "sas")):
            out[k] = "***" if v else ""
        else:
            out[k] = v
    return out


# ---------- registry --------------------------------------------------


class SendError(Exception):
    """Raised by senders on a transient failure — the worker re-queues
    the offset on this. Permanent / poison-pill failures should be
    swallowed at the sender (log + return) so the offset advances."""


async def send_for_kind(
    kind: SiemKind,
    config: dict[str, Any],
    event: dict[str, Any],
    *,
    event_kind: str,
) -> None:
    """Dispatch one formatted event to the right sender.

    `event_kind` is "telemetry" or "alert"; senders use it to choose a
    severity / source / sourcetype that fits the destination's
    conventions. Raises `SendError` on transient failure.
    """
    # Local imports avoid a startup-time circular when `services/siem`
    # is imported by the API while a sender module would in turn need
    # `services/siem` for the registry.
    from app.services.siem import cef, sentinel, splunk, syslog

    if kind is SiemKind.SYSLOG_CEF:
        await syslog.send(config, event, event_kind=event_kind, cef_module=cef)
        return
    if kind is SiemKind.SPLUNK_HEC:
        await splunk.send(config, event, event_kind=event_kind)
        return
    if kind is SiemKind.SENTINEL_HUB:
        await sentinel.send(config, event, event_kind=event_kind)
        return
    raise SendError(f"unknown SIEM kind: {kind}")


__all__ = [
    "SendError",
    "decrypt_config",
    "encrypt_config",
    "redact_secrets",
    "send_for_kind",
]
