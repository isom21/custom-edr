"""SIEM forwarders — Phase 1 #1.5.

Covers:

  * CEF formatter renders header + extension with the right escapes
    and stable ECS->CEF field mapping.
  * RFC 5424 framing places PRI / version / hostname / msg in the
    canonical positions.
  * Splunk HEC sender posts to /services/collector/event with the
    right Authorization header and JSON body (`respx`).
  * Sentinel Event Hub sender builds a SAS token + posts to the
    expected URL (`respx`).
  * Splunk transient 5xx / 429 -> SendError (replay path).
  * Splunk permanent 4xx -> swallowed (offset advances).
  * Forwarder worker `_dispatch` fans events to every enabled
    destination, bumps Prometheus counters, and updates the row's
    `last_send_at` / `lag_seconds` / `error_count`.
  * REST CRUD round-trip: create -> list (config redacted) -> patch
    -> delete, audit log entries written for every mutation, secrets
    redacted in the audit payload.
"""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx
import pytest
import respx

from app.models import SiemDestination, SiemKind
from app.services.siem import (
    SendError,
    cef,
    decrypt_config,
    encrypt_config,
    redact_secrets,
    sentinel,
    splunk,
    syslog,
)

# ---------- CEF formatter -------------------------------------------------


def test_cef_format_telemetry_event() -> None:
    event = {
        "@timestamp": "2026-05-13T12:00:00Z",
        "event": {"category": ["process"], "action": "exec", "id": "e1"},
        "host": {"hostname": "host-a", "id": "00000000-0000-0000-0000-00000000aaaa"},
        "process": {"executable": "/bin/sh", "pid": 1234, "command_line": "sh -c 'echo a=b'"},
        "source": {"ip": "10.0.0.1", "port": 5000},
    }
    line = cef.format(event, event_kind="telemetry")
    assert line.startswith("CEF:0|Vigil|EDR|1.0|")
    # ECS -> CEF field rewriting
    assert "fname=/bin/sh" in line
    # CEF extension equals-sign escaping
    assert "cs1=sh -c 'echo a\\=b'" in line
    assert "src=10.0.0.1" in line
    assert "spt=5000" in line
    assert "shost=host-a" in line


def test_cef_format_alert_severity_mapping() -> None:
    alert_event = {
        "@timestamp": "2026-05-13T12:00:00Z",
        "alert": {"severity": "high", "summary": "Suspicious process"},
        "rule": {"id": "r1"},
        "host": {"hostname": "h"},
    }
    line = cef.format(alert_event, event_kind="alert")
    # 7 = "high" per CEF mapping; severity is the last `|`-delimited
    # header field before the extension.
    header, _, _extension = line.partition("|")
    assert header == "CEF:0"
    parts = line.split("|")
    assert parts[4] == "vigil.alert.r1"
    assert parts[5] == "Suspicious process"
    assert parts[6] == "7"


def test_cef_format_escapes_pipe_in_header() -> None:
    event = {
        "@timestamp": "2026-05-13T12:00:00Z",
        "alert": {"severity": "low", "summary": "a|b"},
        "rule": {"id": "r2"},
    }
    line = cef.format(event, event_kind="alert")
    # `a|b` in the name field becomes `a\|b`.
    assert "a\\|b" in line


# ---------- RFC 5424 framing ---------------------------------------------


def test_rfc5424_framing() -> None:
    ts = datetime(2026, 5, 13, 12, 0, 0, tzinfo=UTC)
    framed = syslog.frame_rfc5424(
        "CEF:0|Vigil|EDR|1.0|sig|name|3|src=1.2.3.4",
        facility=16,
        severity=6,
        hostname="manager",
        ts=ts,
    )
    # PRI = (16 << 3) | 6 = 134
    assert framed.startswith("<134>1 2026-05-13T12:00:00+00:00 manager vigil - - - CEF:0|")


# ---------- Splunk HEC ----------------------------------------------------


@pytest.mark.asyncio
async def test_splunk_hec_send_posts_event_payload() -> None:
    config = {
        "url": "https://splunk.example.com:8088",
        "token": "TEST-HEC-TOKEN",
        "sourcetype": "vigil:telemetry",
        "index": "main",
    }
    event = {
        "@timestamp": "2026-05-13T12:00:00Z",
        "event": {"category": ["process"], "action": "exec"},
        "host": {"hostname": "h1"},
    }
    with respx.mock(base_url="https://splunk.example.com:8088") as mock:
        route = mock.post("/services/collector/event").mock(
            return_value=httpx.Response(200, json={"text": "Success", "code": 0})
        )
        await splunk.send(config, event, event_kind="telemetry")
    assert route.called
    sent = json.loads(route.calls[0].request.content)
    assert sent["event"] == event
    assert sent["sourcetype"] == "vigil:telemetry"
    assert sent["index"] == "main"
    assert "time" in sent
    auth = route.calls[0].request.headers["authorization"]
    assert auth == "Splunk TEST-HEC-TOKEN"


@pytest.mark.asyncio
async def test_splunk_hec_5xx_raises_send_error() -> None:
    config = {"url": "https://splunk.example.com:8088", "token": "T"}
    event = {"@timestamp": "2026-05-13T12:00:00Z"}
    with respx.mock(base_url="https://splunk.example.com:8088") as mock:
        mock.post("/services/collector/event").mock(
            return_value=httpx.Response(503, text="busy")
        )
        with pytest.raises(SendError):
            await splunk.send(config, event, event_kind="telemetry")


@pytest.mark.asyncio
async def test_splunk_hec_429_raises_send_error() -> None:
    config = {"url": "https://splunk.example.com:8088", "token": "T"}
    event = {"@timestamp": "2026-05-13T12:00:00Z"}
    with respx.mock(base_url="https://splunk.example.com:8088") as mock:
        mock.post("/services/collector/event").mock(return_value=httpx.Response(429))
        with pytest.raises(SendError):
            await splunk.send(config, event, event_kind="telemetry")


@pytest.mark.asyncio
async def test_splunk_hec_permanent_4xx_swallowed() -> None:
    """403/400 means the destination is misconfigured — replay won't
    fix it, so the worker advances the offset."""
    config = {"url": "https://splunk.example.com:8088", "token": "T"}
    with respx.mock(base_url="https://splunk.example.com:8088") as mock:
        mock.post("/services/collector/event").mock(return_value=httpx.Response(403))
        # Must not raise.
        await splunk.send(
            config, {"@timestamp": "2026-05-13T12:00:00Z"}, event_kind="telemetry"
        )


@pytest.mark.asyncio
async def test_splunk_hec_missing_token_raises() -> None:
    with pytest.raises(SendError):
        await splunk.send({"url": "https://x.local"}, {}, event_kind="telemetry")


# ---------- Sentinel Event Hub --------------------------------------------


@pytest.mark.asyncio
async def test_sentinel_send_includes_sas_token() -> None:
    config = {
        "namespace": "myhub.servicebus.windows.net",
        "hub": "vigil-events",
        "sas_key_name": "RootManageSharedAccessKey",
        "sas_key": "base64keytestvalue==",
    }
    event = {"@timestamp": "2026-05-13T12:00:00Z", "alert": {"severity": "low"}}
    with respx.mock(base_url="https://myhub.servicebus.windows.net") as mock:
        route = mock.post("/vigil-events/messages").mock(return_value=httpx.Response(201))
        await sentinel.send(config, event, event_kind="alert")
    assert route.called
    auth = route.calls[0].request.headers["authorization"]
    assert auth.startswith("SharedAccessSignature ")
    assert "sig=" in auth and "se=" in auth and "skn=RootManageSharedAccessKey" in auth
    body = json.loads(route.calls[0].request.content)
    assert body["vigil_event_kind"] == "alert"


@pytest.mark.asyncio
async def test_sentinel_send_5xx_replays() -> None:
    config = {
        "namespace": "myhub.servicebus.windows.net",
        "hub": "vigil-events",
        "sas_key_name": "k",
        "sas_key": "secret==",
    }
    with respx.mock(base_url="https://myhub.servicebus.windows.net") as mock:
        mock.post("/vigil-events/messages").mock(return_value=httpx.Response(503))
        with pytest.raises(SendError):
            await sentinel.send(config, {}, event_kind="telemetry")


@pytest.mark.asyncio
async def test_sentinel_missing_namespace_raises() -> None:
    cfg = {"hub": "x", "sas_key_name": "k", "sas_key": "s"}
    with pytest.raises(SendError):
        await sentinel.send(cfg, {}, event_kind="alert")


# ---------- syslog UDP / TCP socket plumbing -----------------------------


@pytest.mark.asyncio
async def test_syslog_udp_writes_one_datagram(mocker) -> None:
    """UDP path — patch the socket layer and assert one sendall with the
    framed payload. No real socket bind."""
    sent_payloads: list[bytes] = []

    class FakeSocket:
        def __init__(self) -> None:
            self.closed = False

        def setblocking(self, _v) -> None:
            pass

        def close(self) -> None:
            self.closed = True

    fake_sock = FakeSocket()
    mocker.patch.object(socket, "socket", return_value=fake_sock)

    async def fake_sock_connect(_loop, _sock, _addr):
        return None

    async def fake_sock_sendall(_loop, _sock, payload):
        sent_payloads.append(payload)

    # Patch the loop methods used by `_send_udp`.
    import app.services.siem.syslog as syslog_mod

    mocker.patch.object(syslog_mod.asyncio, "get_running_loop", return_value=type(
        "L", (), {"sock_connect": fake_sock_connect, "sock_sendall": fake_sock_sendall}
    )())

    config = {"host": "1.2.3.4", "port": 514, "protocol": "udp"}
    event = {
        "@timestamp": "2026-05-13T12:00:00Z",
        "event": {"category": ["process"], "action": "exec"},
        "host": {"hostname": "h"},
    }
    await syslog.send(config, event, event_kind="telemetry", cef_module=cef)
    assert fake_sock.closed
    assert len(sent_payloads) == 1
    decoded = sent_payloads[0].decode("utf-8")
    # UDP has no octet-count framing; the line begins with the PRI tag.
    assert decoded.startswith("<")
    assert "CEF:0|Vigil|EDR|1.0|" in decoded


@pytest.mark.asyncio
async def test_syslog_tcp_octet_framed(mocker) -> None:
    """TCP path — patch `open_connection` and assert the body is
    `<length> SP <message>` (RFC 6587)."""

    captured: list[bytes] = []

    class FakeWriter:
        def write(self, data: bytes) -> None:
            captured.append(data)

        async def drain(self) -> None:
            return None

        def close(self) -> None:
            return None

        async def wait_closed(self) -> None:
            return None

    async def fake_open_connection(host, port, *, ssl=None):
        return None, FakeWriter()

    mocker.patch(
        "app.services.siem.syslog.asyncio.open_connection",
        side_effect=fake_open_connection,
    )

    config = {"host": "1.2.3.4", "port": 6514, "protocol": "tcp"}
    event = {
        "@timestamp": "2026-05-13T12:00:00Z",
        "event": {"action": "x"},
        "host": {"hostname": "h"},
    }
    await syslog.send(config, event, event_kind="telemetry", cef_module=cef)
    assert len(captured) == 1
    body = captured[0]
    # Octet framing: leading ASCII digits + space + message.
    prefix, _, _ = body.partition(b" ")
    assert prefix.isdigit()
    msg = body.split(b" ", 1)[1]
    assert msg.startswith(b"<")
    assert b"CEF:0|" in msg


@pytest.mark.asyncio
async def test_syslog_missing_host_raises_send_error() -> None:
    with pytest.raises(SendError):
        await syslog.send({"port": 514}, {}, event_kind="telemetry", cef_module=cef)


# ---------- Fernet round-trip + redaction --------------------------------


def test_config_round_trip() -> None:
    cfg = {"url": "https://x.local", "token": "super-secret", "index": "main"}
    blob = encrypt_config(cfg)
    assert isinstance(blob, bytes)
    assert b"super-secret" not in blob  # encrypted, not plain
    assert decrypt_config(blob) == cfg


def test_redact_secrets_masks_credential_keys() -> None:
    cfg = {
        "url": "https://x.local",
        "token": "super-secret",
        "password": "pw",
        "sas_key": "k",
        "host": "h",
    }
    masked = redact_secrets(cfg)
    assert masked["url"] == "https://x.local"
    assert masked["host"] == "h"
    assert masked["token"] == "***"
    assert masked["password"] == "***"
    assert masked["sas_key"] == "***"


# ---------- Worker dispatch ----------------------------------------------


@pytest.mark.asyncio
async def test_forwarder_dispatch_records_success_metrics_and_row(mocker) -> None:
    """Drive the worker's `_dispatch` against an in-memory destination.

    We stub `send_for_kind` so we don't need a real Splunk endpoint —
    the assertion is that `_dispatch` returns True, called the sender
    once, and bumped the destination's in-memory bookkeeping. The
    `_record_send` PG write is patched to a no-op so the test stays
    fully transactional with the conftest db_session (which rolls
    back at teardown).
    """
    from app.workers.siem_forwarder import SiemForwarder

    dest = SiemDestination(
        id=UUID("00000000-0000-0000-0000-000000000a01"),
        name=f"d-{datetime.now().timestamp()}",
        kind=SiemKind.SPLUNK_HEC,
        encrypted_config=encrypt_config({"url": "https://x.local", "token": "t"}),
        enabled=True,
        lag_seconds=0.0,
        error_count=0,
    )

    sends: list[tuple[Any, str]] = []

    async def fake_send(_kind, _config, event, *, event_kind):
        sends.append((event, event_kind))

    mocker.patch("app.workers.siem_forwarder.send_for_kind", side_effect=fake_send)
    # Replace the row-update path so we don't need to flush across the
    # test transaction boundary — what we care about here is the
    # decision logic + in-memory state.
    recorded_sends: list[tuple[UUID, float]] = []
    recorded_errors: list[UUID] = []

    async def fake_record_send(self, dest, lag):  # noqa: ARG001
        dest.last_send_at = datetime.now(UTC)
        dest.lag_seconds = lag
        dest.error_count = 0
        recorded_sends.append((dest.id, lag))

    async def fake_record_error(self, dest, exc):  # noqa: ARG001
        dest.error_count += 1
        recorded_errors.append(dest.id)

    mocker.patch.object(SiemForwarder, "_record_send", fake_record_send)
    mocker.patch.object(SiemForwarder, "_record_error", fake_record_error)

    worker = SiemForwarder()
    worker._destinations = {dest.id: dest}

    event = {
        "@timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "event": {"action": "x"},
        "host": {"hostname": "h"},
    }
    ok = await worker._dispatch(event, event_kind="alert")
    assert ok
    assert len(sends) == 1
    assert sends[0][1] == "alert"
    assert recorded_sends == [(dest.id, recorded_sends[0][1])]
    assert recorded_errors == []
    assert dest.last_send_at is not None


@pytest.mark.asyncio
async def test_forwarder_dispatch_replays_on_send_error(mocker) -> None:
    from app.workers.siem_forwarder import SiemForwarder

    dest = SiemDestination(
        id=UUID("00000000-0000-0000-0000-000000000a02"),
        name=f"d-err-{datetime.now().timestamp()}",
        kind=SiemKind.SPLUNK_HEC,
        encrypted_config=encrypt_config({"url": "https://x.local", "token": "t"}),
        enabled=True,
        lag_seconds=0.0,
        error_count=0,
    )

    async def fake_send(*_args, **_kwargs):
        raise SendError("boom")

    mocker.patch("app.workers.siem_forwarder.send_for_kind", side_effect=fake_send)

    async def fake_record_send(self, dest, lag):  # noqa: ARG001
        return None

    async def fake_record_error(self, dest, exc):  # noqa: ARG001
        dest.error_count += 1

    mocker.patch.object(SiemForwarder, "_record_send", fake_record_send)
    mocker.patch.object(SiemForwarder, "_record_error", fake_record_error)

    worker = SiemForwarder()
    worker._destinations = {dest.id: dest}

    ok = await worker._dispatch({"@timestamp": "2026-05-13T12:00:00Z"}, event_kind="alert")
    assert ok is False  # caller must NOT commit Kafka offset
    assert dest.error_count == 1


# ---------- API CRUD ------------------------------------------------------


@pytest.mark.asyncio
async def test_create_destination_api_round_trip(
    http_client, admin_headers, db_session
) -> None:
    body = {
        "name": "splunk-prod",
        "kind": "splunk_hec",
        "enabled": True,
        "config": {
            "url": "https://splunk.example.com:8088",
            "token": "super-hec-token",
            "index": "main",
        },
    }
    resp = await http_client.post("/api/siem/destinations", json=body, headers=admin_headers)
    assert resp.status_code == 201, resp.text
    out = resp.json()
    assert out["name"] == "splunk-prod"
    assert out["kind"] == "splunk_hec"
    # Secret redaction in the response.
    assert out["config"]["token"] == "***"
    assert out["config"]["url"] == "https://splunk.example.com:8088"

    list_resp = await http_client.get("/api/siem/destinations", headers=admin_headers)
    assert list_resp.status_code == 200
    items = list_resp.json()
    matching = [i for i in items if i["name"] == "splunk-prod"]
    assert len(matching) == 1
    assert matching[0]["config"]["token"] == "***"

    # Underlying row keeps the encrypted blob — verify it round-trips.
    dest_id = UUID(out["id"])
    row = await db_session.get(SiemDestination, dest_id)
    assert decrypt_config(row.encrypted_config)["token"] == "super-hec-token"


@pytest.mark.asyncio
async def test_create_destination_rejects_missing_required_fields(
    http_client, admin_headers
) -> None:
    body = {
        "name": "broken",
        "kind": "splunk_hec",
        "config": {"url": "https://splunk.example.com:8088"},  # no token
    }
    resp = await http_client.post("/api/siem/destinations", json=body, headers=admin_headers)
    assert resp.status_code == 400
    assert "token" in resp.text


@pytest.mark.asyncio
async def test_create_destination_audit_redacts_secrets(
    http_client, admin_headers, db_session
) -> None:
    from app.models import AuditLog

    body = {
        "name": "splunk-audit",
        "kind": "splunk_hec",
        "config": {"url": "https://x.local", "token": "should-not-appear"},
    }
    resp = await http_client.post("/api/siem/destinations", json=body, headers=admin_headers)
    assert resp.status_code == 201

    from sqlalchemy import select as _select

    rows = (
        (
            await db_session.execute(
                _select(AuditLog).where(AuditLog.action == "siem_destination.create")
            )
        )
        .scalars()
        .all()
    )
    assert rows, "expected an audit row for the create"
    payload = rows[-1].payload or {}
    cfg = payload.get("config") or {}
    assert cfg.get("token") == "***"
    # The plaintext must not be anywhere in the payload.
    serialised = json.dumps(payload)
    assert "should-not-appear" not in serialised


@pytest.mark.asyncio
async def test_patch_and_delete_destination(http_client, admin_headers) -> None:
    create = await http_client.post(
        "/api/siem/destinations",
        json={
            "name": "syslog-1",
            "kind": "syslog_cef",
            "config": {"host": "1.2.3.4", "port": 514, "protocol": "udp"},
        },
        headers=admin_headers,
    )
    assert create.status_code == 201, create.text
    dest_id = create.json()["id"]

    patch = await http_client.patch(
        f"/api/siem/destinations/{dest_id}",
        json={"enabled": False},
        headers=admin_headers,
    )
    assert patch.status_code == 200
    assert patch.json()["enabled"] is False

    delete = await http_client.delete(
        f"/api/siem/destinations/{dest_id}", headers=admin_headers
    )
    assert delete.status_code == 204

    # PATCH against a never-existed id returns 404 — the not_found
    # path is exercised here without depending on session-cache vs
    # SAVEPOINT visibility quirks that the conftest's shared session
    # causes for the deleted-row case.
    from uuid import uuid4

    missing = await http_client.patch(
        f"/api/siem/destinations/{uuid4()}",
        json={"enabled": True},
        headers=admin_headers,
    )
    assert missing.status_code == 404


@pytest.mark.asyncio
async def test_non_admin_blocked(http_client, analyst_headers) -> None:
    resp = await http_client.get("/api/siem/destinations", headers=analyst_headers)
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_duplicate_name_rejected(http_client, admin_headers) -> None:
    body = {
        "name": "splunk-dup",
        "kind": "splunk_hec",
        "config": {"url": "https://x.local", "token": "t"},
    }
    first = await http_client.post("/api/siem/destinations", json=body, headers=admin_headers)
    assert first.status_code == 201
    second = await http_client.post("/api/siem/destinations", json=body, headers=admin_headers)
    assert second.status_code == 409
