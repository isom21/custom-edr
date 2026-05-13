"""Splunk HTTP Event Collector (HEC) sender.

POSTs the ECS event verbatim as the HEC `event` field, with
`sourcetype` and `source` derived from the event_kind. Operators can
override sourcetype / index / source via the destination config.

Destination config shape:

    {
      "url":         "https://splunk.example.com:8088",
      "token":       "<HEC token>",
      "sourcetype":  "vigil:telemetry",   # optional
      "index":       "main",              # optional
      "source":      "vigil",             # optional
      "tls_verify":  true                 # optional, default true
    }

We use the `/services/collector/event` endpoint (not raw) so each
event keeps its structure and Splunk's automatic timestamp extraction
picks `@timestamp` out of the body when configured.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import httpx
import structlog

from app.services.siem import SendError

log = structlog.get_logger()

# Default sourcetypes — operators usually want one feed per index but
# distinct sourcetypes so detection rules can target alerts vs
# telemetry separately.
DEFAULT_TELEMETRY_SOURCETYPE = "vigil:telemetry"
DEFAULT_ALERT_SOURCETYPE = "vigil:alert"
DEFAULT_SOURCE = "vigil"
HEC_PATH = "/services/collector/event"


def _event_time(event: dict[str, Any]) -> float | None:
    """Extract a unix-seconds-with-fractions timestamp from an ECS
    event. HEC accepts float seconds; missing timestamp defers to the
    HEC ingester's own clock."""
    ts = event.get("@timestamp")
    if not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


async def send(
    config: dict[str, Any],
    event: dict[str, Any],
    *,
    event_kind: str,
) -> None:
    url = config.get("url")
    token = config.get("token")
    if not url or not token:
        raise SendError("splunk_hec destination missing url/token")

    sourcetype = config.get("sourcetype") or (
        DEFAULT_ALERT_SOURCETYPE if event_kind == "alert" else DEFAULT_TELEMETRY_SOURCETYPE
    )
    payload: dict[str, Any] = {
        "event": event,
        "sourcetype": sourcetype,
        "source": config.get("source") or DEFAULT_SOURCE,
    }
    if idx := config.get("index"):
        payload["index"] = idx
    if (ts := _event_time(event)) is not None:
        payload["time"] = ts

    # HEC accepts NDJSON (one event per line) at /event/1.0; the
    # plain `/event` endpoint expects JSON. Keep it simple: one event
    # per POST. Batching is a follow-up — the message rate per
    # destination is bounded by the upstream Kafka consumer.
    body = json.dumps(payload, separators=(",", ":"))

    full_url = url.rstrip("/") + HEC_PATH
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type": "application/json",
    }

    verify = bool(config.get("tls_verify", True))
    try:
        async with httpx.AsyncClient(timeout=10.0, verify=verify) as client:
            resp = await client.post(full_url, content=body, headers=headers)
    except httpx.HTTPError as exc:
        raise SendError(f"splunk hec request failed: {exc}") from exc

    if resp.status_code >= 500 or resp.status_code == 429:
        # 5xx + 429 are retryable: replay on the next worker poll.
        raise SendError(f"splunk hec transient error {resp.status_code}: {resp.text[:200]}")
    if resp.status_code >= 400:
        # 4xx other than 429 means the request is malformed for this
        # destination — replay won't help; log and drop so the offset
        # advances.
        log.warning(
            "siem.splunk.permanent_4xx",
            status=resp.status_code,
            body=resp.text[:200],
        )
        return


__all__ = [
    "DEFAULT_ALERT_SOURCETYPE",
    "DEFAULT_SOURCE",
    "DEFAULT_TELEMETRY_SOURCETYPE",
    "HEC_PATH",
    "send",
]
