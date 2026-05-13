"""RFC 5424 syslog framing + TCP/UDP/TLS sender.

Wraps a CEF-formatted message in a syslog header:

    <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

Transport options come from the destination's encrypted_config:

    {
      "host":     "siem.example.com",
      "port":     6514,
      "protocol": "tcp" | "udp" | "tls",
      "vendor":   "Vigil",        # CEF DeviceVendor override (optional)
      "product":  "EDR",          # CEF DeviceProduct override (optional)
      "version":  "1.0",          # CEF DeviceVersion override (optional)
      "tls_verify": true,         # only meaningful for protocol=tls
      "tls_ca":    "<PEM>",       # optional pinned CA (raw PEM string)
    }

We send one message per event, RFC 6587 octet-counting framing for
TCP/TLS (`<msg-length> SP <msg>`) — the more interoperable framing
than non-transparent LF-delimited for high-throughput TCP. UDP is a
single datagram per event with no framing prefix.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

import structlog

from app.services.siem import SendError

log = structlog.get_logger()

# Default facility 16 (local0) + severity derived from event; many SIEMs
# default to local0 in their ingest filters.
DEFAULT_FACILITY = 16

_SEVERITY_NAME_TO_RFC = {
    "info": 6,  # informational
    "low": 5,  # notice
    "medium": 4,  # warning
    "high": 3,  # error
    "critical": 2,  # critical
}


def _syslog_severity(event: dict[str, Any], event_kind: str) -> int:
    """Map ECS / alert severity onto RFC 5424 numeric severity (0-7).
    Higher = less urgent. Defaults to 6 (informational)."""
    if event_kind == "alert":
        sev = (event.get("alert") or {}).get("severity") or (event.get("rule") or {}).get(
            "severity"
        )
        if isinstance(sev, str):
            return _SEVERITY_NAME_TO_RFC.get(sev.lower(), 6)
    return 6


def _pri(facility: int, severity: int) -> str:
    return f"<{(facility << 3) | severity}>"


def frame_rfc5424(
    message: str,
    *,
    facility: int,
    severity: int,
    hostname: str,
    app_name: str = "vigil",
    procid: str | int = "-",
    msgid: str = "-",
    ts: datetime | None = None,
) -> str:
    """Wrap `message` in a RFC 5424 syslog envelope. STRUCTURED-DATA is
    always NILVALUE (`-`) — we keep the structured payload inside the
    CEF body to maximise compatibility with SIEM-side parsers that
    treat the syslog header as scaffolding."""
    ts = ts or datetime.now(UTC)
    return (
        f"{_pri(facility, severity)}1 {ts.isoformat()} {hostname} "
        f"{app_name} {procid} {msgid} - {message}"
    )


def _octet_framed(line: str) -> bytes:
    """RFC 6587 octet-counting framing: `<length> SP <message>`."""
    body = line.encode("utf-8")
    return f"{len(body)} ".encode("ascii") + body


async def _send_udp(host: str, port: int, payload: bytes) -> None:
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, (host, port))
        await loop.sock_sendall(sock, payload)
    finally:
        sock.close()


async def _send_tcp(
    host: str, port: int, payload: bytes, *, ssl_ctx: ssl.SSLContext | None
) -> None:
    _, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
    try:
        writer.write(payload)
        await writer.drain()
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - close best-effort; downstream may have RST'd
            pass


def _build_ssl_context(*, verify: bool, ca_pem: str | None) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif ca_pem:
        ctx.load_verify_locations(cadata=ca_pem)
    return ctx


async def send(
    config: dict[str, Any],
    event: dict[str, Any],
    *,
    event_kind: str,
    cef_module: Any,
) -> None:
    """Format `event` via the supplied CEF module, wrap in RFC 5424, and
    ship to the destination. `cef_module` is injected so the sibling
    formatter module stays a pure-data module (no transport deps).
    """
    host = config.get("host")
    port = config.get("port")
    protocol = (config.get("protocol") or "tcp").lower()
    if not host or not port:
        raise SendError("syslog destination missing host/port")

    try:
        port_int = int(port)
    except (TypeError, ValueError) as exc:
        raise SendError(f"syslog destination port must be an int: {port!r}") from exc

    cef_line = cef_module.format(
        event,
        event_kind=event_kind,
        vendor=config.get("vendor"),
        product=config.get("product"),
        version=config.get("version"),
    )

    hostname = (event.get("host") or {}).get("hostname") or "vigil-manager"
    line = frame_rfc5424(
        cef_line,
        facility=int(config.get("facility", DEFAULT_FACILITY)),
        severity=_syslog_severity(event, event_kind),
        hostname=str(hostname),
    )

    try:
        if protocol == "udp":
            # UDP has no framing — one event = one datagram.
            await _send_udp(host, port_int, line.encode("utf-8"))
        elif protocol == "tcp":
            await _send_tcp(host, port_int, _octet_framed(line), ssl_ctx=None)
        elif protocol == "tls":
            ctx = _build_ssl_context(
                verify=bool(config.get("tls_verify", True)),
                ca_pem=config.get("tls_ca"),
            )
            await _send_tcp(host, port_int, _octet_framed(line), ssl_ctx=ctx)
        else:
            raise SendError(f"unsupported syslog protocol: {protocol!r}")
    except SendError:
        raise
    except Exception as exc:  # noqa: BLE001 - normalise to SendError for the worker
        log.warning(
            "siem.syslog.send_failed",
            host=host,
            port=port_int,
            protocol=protocol,
            error=str(exc),
        )
        raise SendError(f"syslog send to {host}:{port_int} failed: {exc}") from exc


__all__ = ["DEFAULT_FACILITY", "frame_rfc5424", "send"]
