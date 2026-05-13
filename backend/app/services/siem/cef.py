"""ArcSight CEF (Common Event Format) v1 formatter.

CEF header:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Extension is a key=value space-separated list; pipes inside header
fields are backslash-escaped, equals signs and backslashes inside the
extension are escaped per the CEF spec.

The forwarder uses ECS-aligned events from `telemetry.normalized` +
`alerts.raw`; we map the relevant ECS fields onto the CEF extension
dictionary defined by ArcSight (src, dst, suser, fname, cs1..6 etc.).
Unmapped fields land in cs1Label/cs1 custom strings — operators
configure the SIEM-side parsing to surface them.
"""

from __future__ import annotations

from typing import Any

# CEF defaults that an operator can override via destination config.
DEFAULT_VENDOR = "Vigil"
DEFAULT_PRODUCT = "EDR"
DEFAULT_VERSION = "1.0"

# Map ECS severity strings to CEF severity ints (0-10). Anything else
# falls through as "5" so operators see "medium" by default.
_SEVERITY_TO_CEF = {
    "info": 1,
    "low": 3,
    "medium": 5,
    "high": 7,
    "critical": 10,
}


def _escape_header(s: str) -> str:
    """CEF header fields escape `\\` and `|`."""
    return s.replace("\\", "\\\\").replace("|", "\\|")


def _escape_extension(s: str) -> str:
    """CEF extension values escape `\\`, `=`, and newlines."""
    return s.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")


def _flatten(d: dict[str, Any], prefix: str = "") -> dict[str, str]:
    """Flatten a nested dict to dotted-string keys with string values.

    Lists are joined with "," — CEF doesn't have a native list type
    and SIEM-side parsers cope with comma-separated tokens. Booleans
    serialise as "true" / "false"; None drops the key entirely so the
    extension doesn't carry useless `key=` markers.
    """
    out: dict[str, str] = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if v is None:
            continue
        if isinstance(v, dict):
            out.update(_flatten(v, prefix=f"{key}."))
        elif isinstance(v, list | tuple):
            if not v:
                continue
            out[key] = ",".join(str(x) for x in v if x is not None)
        elif isinstance(v, bool):
            out[key] = "true" if v else "false"
        else:
            out[key] = str(v)
    return out


def _signature_for(event: dict[str, Any], event_kind: str) -> str:
    """A short, stable identifier for this event class. SIEM-side rules
    pivot on this — keep it human-readable rather than a UUID."""
    if event_kind == "alert":
        rule = event.get("rule") or {}
        rule_id = rule.get("id") or "alert"
        return f"vigil.alert.{rule_id}"
    ecs_event = event.get("event") or {}
    category = ecs_event.get("category")
    if isinstance(category, list) and category:
        return f"vigil.telemetry.{category[0]}"
    if isinstance(category, str) and category:
        return f"vigil.telemetry.{category}"
    return "vigil.telemetry"


def _name_for(event: dict[str, Any], event_kind: str) -> str:
    if event_kind == "alert":
        alert = event.get("alert") or {}
        summary = alert.get("summary") or alert.get("name")
        if summary:
            return str(summary)
        return "Vigil alert"
    ecs_event = event.get("event") or {}
    action = ecs_event.get("action")
    if action:
        return str(action)
    return "telemetry event"


def _severity_for(event: dict[str, Any], event_kind: str) -> int:
    if event_kind == "alert":
        sev = (event.get("alert") or {}).get("severity") or (event.get("rule") or {}).get(
            "severity"
        )
        if isinstance(sev, str):
            return _SEVERITY_TO_CEF.get(sev.lower(), 5)
    ecs_event = event.get("event") or {}
    sev = ecs_event.get("severity")
    try:
        if sev is not None:
            return max(0, min(10, int(sev)))
    except (TypeError, ValueError):
        pass
    return 5


# ECS -> CEF extension key map. Lets analysts query their SIEM with
# vendor-native field names while the wire format stays ArcSight-canonical.
_ECS_TO_CEF: dict[str, str] = {
    "source.ip": "src",
    "source.port": "spt",
    "destination.ip": "dst",
    "destination.port": "dpt",
    "destination.domain": "dhost",
    "user.name": "suser",
    "process.executable": "fname",
    "process.command_line": "cs1",
    "process.pid": "spid",
    "file.path": "filePath",
    "file.hash.sha256": "fileHash",
    "host.hostname": "shost",
    "host.id": "deviceExternalId",
    "event.id": "externalId",
    "@timestamp": "rt",
}


def format(  # noqa: A001 - "format" matches the verb we're doing, fine
    event: dict[str, Any],
    *,
    event_kind: str,
    vendor: str | None = None,
    product: str | None = None,
    version: str | None = None,
) -> str:
    """Render an ECS event as a single CEF v1 line (without RFC 5424
    framing — `syslog.py` adds that)."""
    flat = _flatten(event)
    extension_pairs: list[str] = []
    used_keys: set[str] = set()
    for ecs_key, cef_key in _ECS_TO_CEF.items():
        val = flat.get(ecs_key)
        if val is None:
            continue
        extension_pairs.append(f"{cef_key}={_escape_extension(val)}")
        used_keys.add(ecs_key)

    # Spillover: any remaining flattened key gets the verbatim ECS path
    # as the CEF extension key. CEF treats unknown keys as opaque
    # strings; SIEM-side parsers like Splunk's CEF TA pick these up
    # under their literal name.
    for k, v in flat.items():
        if k in used_keys:
            continue
        # CEF extension keys must be CEF-token-safe — no spaces / equals.
        # ECS paths use dots which CEF accepts.
        safe_key = k.replace(" ", "_")
        extension_pairs.append(f"{safe_key}={_escape_extension(v)}")

    header_fields = [
        "CEF:0",
        _escape_header(vendor or DEFAULT_VENDOR),
        _escape_header(product or DEFAULT_PRODUCT),
        _escape_header(version or DEFAULT_VERSION),
        _escape_header(_signature_for(event, event_kind)),
        _escape_header(_name_for(event, event_kind)),
        str(_severity_for(event, event_kind)),
    ]
    return "|".join(header_fields) + "|" + " ".join(extension_pairs)


__all__ = ["DEFAULT_PRODUCT", "DEFAULT_VENDOR", "DEFAULT_VERSION", "format"]
