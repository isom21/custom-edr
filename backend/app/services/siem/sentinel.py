"""Azure Sentinel via Event Hub — HTTP sender (no SDK).

We keep the dependency footprint minimal by hitting Event Hub's REST
API directly with a SAS-key signature. The `azure-eventhub` library
would simplify things but pulls in a heavy stack (azure-core,
azure-identity, uamqp); HTTP is fine for the per-event throughput we
expect here.

Destination config shape:

    {
      "namespace":   "myhub.servicebus.windows.net",
      "hub":         "vigil-events",
      "sas_key_name": "RootManageSharedAccessKey",
      "sas_key":     "<primary key>",
      "ttl_seconds": 3600        # SAS token lifetime, default 1h
    }

The signature is HMAC-SHA256 over `<resource-uri>\\n<expiry>` and the
Authorization header follows the Azure SAS scheme. We embed the
ECS event verbatim as the message body; downstream Sentinel uses
Event Hub forwarding into Log Analytics where the body is parsed
back into custom logs.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import quote

import httpx
import structlog

from app.services.siem import SendError

log = structlog.get_logger()

DEFAULT_TTL_S = 3600


def _sas_token(*, resource_uri: str, key_name: str, key: str, ttl_s: int) -> str:
    """Generate a Service-Bus / Event-Hub SAS token.

    Per Azure docs the canonical form is:
        SharedAccessSignature
            sr=<encoded-resource>&sig=<encoded-hmac>&se=<expiry>&skn=<key-name>
    """
    expiry = int(time.time()) + ttl_s
    encoded_uri = quote(resource_uri, safe="")
    string_to_sign = f"{encoded_uri}\n{expiry}"
    signature = base64.b64encode(
        hmac.new(key.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256).digest()
    )
    encoded_sig = quote(signature.decode("ascii"), safe="")
    return f"SharedAccessSignature sr={encoded_uri}&sig={encoded_sig}&se={expiry}&skn={key_name}"


async def send(
    config: dict[str, Any],
    event: dict[str, Any],
    *,
    event_kind: str,
) -> None:
    namespace = config.get("namespace")
    hub = config.get("hub")
    key_name = config.get("sas_key_name")
    key = config.get("sas_key")
    if not (namespace and hub and key_name and key):
        raise SendError("sentinel_hub destination missing namespace/hub/sas_key_name/sas_key")

    ttl = int(config.get("ttl_seconds") or DEFAULT_TTL_S)
    resource_uri = f"https://{namespace}/{hub}"
    token = _sas_token(resource_uri=resource_uri, key_name=key_name, key=key, ttl_s=ttl)

    # The event_kind tags every record so Sentinel can split them.
    payload = json.dumps({"vigil_event_kind": event_kind, **event}, separators=(",", ":"))
    url = f"{resource_uri}/messages?api-version=2014-01"
    headers = {
        "Authorization": token,
        "Content-Type": "application/atom+xml;type=entry;charset=utf-8",
        "Host": namespace,
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, content=payload, headers=headers)
    except httpx.HTTPError as exc:
        raise SendError(f"sentinel event hub request failed: {exc}") from exc

    if resp.status_code in (201, 204):
        return
    if resp.status_code >= 500 or resp.status_code == 429:
        raise SendError(f"sentinel event hub transient error {resp.status_code}: {resp.text[:200]}")
    log.warning(
        "siem.sentinel.permanent_error",
        status=resp.status_code,
        body=resp.text[:200],
    )


__all__ = ["DEFAULT_TTL_S", "send"]
