"""gRPC AgentService implementation.

Handles two RPCs:
- Enroll: anonymous TLS, agent submits CSR + enrollment token, gets cert back.
- HostStream: long-lived bidi over mTLS. Inbound events are forwarded to the
  Kafka raw topic. Outbound: rule sync at start + periodic pongs.
"""
from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timezone
from typing import AsyncIterator
from uuid import UUID

import grpc
import structlog
from google.protobuf import timestamp_pb2
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import hash_enrollment_token
from app.models import EnrollmentToken, Host, HostStatus, IocEntry, Rule, RuleKind
from app.proto_gen.edr.v1 import (
    common_pb2,
    control_pb2,
    control_pb2_grpc,
)
from app.services import audit
from app.services.ca import CaService
from app.services.kafka import producer

log = structlog.get_logger()


PB_OS_FAMILY: dict[str, str] = {"windows": "windows", "linux": "linux", "macos": "macos"}


def _now_pb() -> timestamp_pb2.Timestamp:
    ts = timestamp_pb2.Timestamp()
    ts.GetCurrentTime()
    return ts


def _pb_severity(s: str) -> int:
    return {
        "info": common_pb2.SEVERITY_INFO,
        "low": common_pb2.SEVERITY_LOW,
        "medium": common_pb2.SEVERITY_MEDIUM,
        "high": common_pb2.SEVERITY_HIGH,
        "critical": common_pb2.SEVERITY_CRITICAL,
    }.get(s, common_pb2.SEVERITY_UNSPECIFIED)


def _pb_action(a: str) -> int:
    return {
        "detect": common_pb2.RULE_ACTION_DETECT,
        "kill": common_pb2.RULE_ACTION_KILL,
        "block": common_pb2.RULE_ACTION_BLOCK,
    }.get(a, common_pb2.RULE_ACTION_UNSPECIFIED)


def _pb_ioc_kind(k: str) -> int:
    return {
        "hash_sha256": control_pb2.IOC_KIND_HASH_SHA256,
        "hash_md5": control_pb2.IOC_KIND_HASH_MD5,
        "hash_sha1": control_pb2.IOC_KIND_HASH_SHA1,
        "filename": control_pb2.IOC_KIND_FILENAME,
        "filepath": control_pb2.IOC_KIND_FILEPATH,
    }.get(k, control_pb2.IOC_KIND_UNSPECIFIED)


def _peer_host_id(context: grpc.aio.ServicerContext) -> str | None:
    """Extract host_id from the client cert's CN. Returns None if unavailable
    (e.g. plaintext channel during local dev).
    """
    auth_ctx = context.auth_context()
    cn = auth_ctx.get("x509_common_name", [])
    if cn:
        return cn[0].decode() if isinstance(cn[0], bytes) else cn[0]
    return None


class AgentService(control_pb2_grpc.AgentServiceServicer):
    """Server-side handlers. Each method gets its own DB session."""

    async def Enroll(  # noqa: N802 - gRPC method
        self,
        request: control_pb2.EnrollRequest,
        context: grpc.aio.ServicerContext,
    ) -> control_pb2.EnrollResponse:
        async with SessionLocal() as db:
            try:
                resp = await self._do_enroll(request, db, context)
                await db.commit()
                return resp
            except grpc.aio.AioRpcError:
                await db.rollback()
                raise
            except Exception as exc:  # pragma: no cover - defensive
                await db.rollback()
                log.exception("grpc.enroll.error", error=str(exc))
                await context.abort(grpc.StatusCode.INTERNAL, "internal error")
                raise

    async def _do_enroll(
        self,
        request: control_pb2.EnrollRequest,
        db: AsyncSession,
        context: grpc.aio.ServicerContext,
    ) -> control_pb2.EnrollResponse:
        if not request.enrollment_token:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "missing token")
        if not request.csr_pem:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "missing csr")
        if not request.hostname:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "missing hostname")

        th = hash_enrollment_token(request.enrollment_token)
        token = (
            await db.execute(select(EnrollmentToken).where(EnrollmentToken.token_hash == th))
        ).scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if token is None or token.used_at is not None or token.expires_at < now:
            await context.abort(grpc.StatusCode.PERMISSION_DENIED, "invalid or expired token")

        os_family = PB_OS_FAMILY.get(request.os.family.lower(), None)
        if os_family is None:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "unknown os.family")

        host = Host(
            hostname=request.hostname,
            os_family=os_family,
            os_version=request.os.version or None,
            os_platform=request.os.platform or None,
            os_arch=request.os.architecture or None,
            agent_version=request.agent_version or None,
            status=HostStatus.PENDING,
            enrolled_at=now,
        )
        db.add(host)
        await db.flush()

        ca = CaService(db)
        issued = await ca.sign_csr(
            request.csr_pem, host_id=str(host.id), hostname=request.hostname
        )
        host.cert_fingerprint = issued.fingerprint_sha256

        token.used_at = now
        token.used_by_host_id = host.id

        await audit.record(
            db,
            actor=None,
            action="host.enroll",
            resource_type="host",
            resource_id=str(host.id),
            payload={"via": "grpc", "hostname": request.hostname},
        )

        not_after_pb = timestamp_pb2.Timestamp()
        not_after_pb.FromDatetime(issued.not_after.replace(tzinfo=None))

        return control_pb2.EnrollResponse(
            host_id=str(host.id),
            client_cert_pem=issued.cert_pem.encode(),
            ca_chain_pem=issued.ca_chain_pem.encode(),
            cert_not_after=not_after_pb,
        )

    async def HostStream(  # noqa: N802
        self,
        request_iterator: AsyncIterator[control_pb2.ClientMessage],
        context: grpc.aio.ServicerContext,
    ) -> AsyncIterator[control_pb2.ServerMessage]:
        host_id_str = _peer_host_id(context)
        if host_id_str is None:
            log.warning("grpc.host_stream.no_peer_cert")
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "client cert required")
            return
        try:
            host_id = UUID(host_id_str)
        except ValueError:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "client cert CN is not a UUID")
            return

        log.info("grpc.host_stream.open", host_id=host_id_str)

        async with SessionLocal() as db:
            host = await db.get(Host, host_id)
            if host is None:
                log.warning("grpc.host_stream.unknown_host", host_id=host_id_str)
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, "unknown host")
                return
            host.status = HostStatus.ONLINE
            host.last_seen_at = datetime.now(timezone.utc)
            await db.commit()

            # Push initial rule sync to the agent.
            initial = await self._build_rule_sync(db)

        # Send rule sync first.
        yield control_pb2.ServerMessage(rules=initial)

        # Heartbeat sender — pong every 30s; cancelled when the stream ends.
        async def _pinger(out: asyncio.Queue):
            try:
                while True:
                    await asyncio.sleep(30)
                    pong = control_pb2.Pong(ts=_now_pb())
                    await out.put(control_pb2.ServerMessage(pong=pong))
            except asyncio.CancelledError:
                return

        out_queue: asyncio.Queue = asyncio.Queue()
        ping_task = asyncio.create_task(_pinger(out_queue))

        try:
            consume_task = asyncio.create_task(
                self._consume_client(host_id, request_iterator, context)
            )
            try:
                while not context.cancelled() and not consume_task.done():
                    try:
                        msg = await asyncio.wait_for(out_queue.get(), timeout=1.0)
                    except asyncio.TimeoutError:
                        continue
                    yield msg
            finally:
                consume_task.cancel()
                with contextlib.suppress(BaseException):
                    await consume_task
        finally:
            ping_task.cancel()
            with __import__("contextlib").suppress(BaseException):
                await ping_task
            async with SessionLocal() as db:
                h = await db.get(Host, host_id)
                if h is not None:
                    h.status = HostStatus.OFFLINE
                    await db.commit()
            log.info("grpc.host_stream.close", host_id=host_id_str)

    async def _consume_client(
        self,
        host_id: UUID,
        request_iterator: AsyncIterator[control_pb2.ClientMessage],
        context: grpc.aio.ServicerContext,
    ) -> None:
        last_seen_update = datetime.now(timezone.utc)
        async for msg in request_iterator:
            kind = msg.WhichOneof("payload")
            if kind == "events":
                # Forward each event to Kafka. Key by host_id for partitioning.
                for ev in msg.events.events:
                    raw = ev.SerializeToString()
                    await producer.send_bytes(
                        settings.topic_telemetry_raw, str(host_id), raw
                    )
            elif kind == "heartbeat":
                # Throttle DB writes — once per ~30s.
                now = datetime.now(timezone.utc)
                if (now - last_seen_update).total_seconds() >= 30:
                    async with SessionLocal() as db:
                        h = await db.get(Host, host_id)
                        if h is not None:
                            h.last_seen_at = now
                            await db.commit()
                    last_seen_update = now
            elif kind == "hello":
                log.info(
                    "grpc.host_stream.hello",
                    host_id=str(host_id),
                    agent_version=msg.hello.host.agent_version,
                )
            elif kind == "command_result":
                log.info(
                    "grpc.host_stream.command_result",
                    host_id=str(host_id),
                    command_id=msg.command_result.command_id,
                    success=msg.command_result.success,
                )
            else:
                log.debug("grpc.host_stream.unknown_payload", host_id=str(host_id), kind=kind)

    async def _build_rule_sync(self, db: AsyncSession) -> control_pb2.RuleSync:
        """Snapshot enabled YARA + IOC rules and pack into a RuleSync message.

        Sigma rules are evaluated server-side; agents don't receive them.
        """
        stmt = (
            select(Rule)
            .where(Rule.enabled.is_(True))
            .options(selectinload(Rule.iocs))
        )
        rows = (await db.execute(stmt)).scalars().all()

        sync = control_pb2.RuleSync(rules_version=int(datetime.now(timezone.utc).timestamp()))
        for r in rows:
            if r.kind is RuleKind.YARA and r.body:
                sync.yara.append(
                    control_pb2.YaraRule(
                        id=str(r.id),
                        name=r.name,
                        source=r.body,
                        severity=_pb_severity(r.severity.value),
                        action=_pb_action(r.action.value),
                    )
                )
            elif r.kind is RuleKind.IOC:
                # One IocRule per (rule, kind) — agents typically index hash, name, path separately.
                by_kind: dict[str, list[IocEntry]] = {}
                for entry in r.iocs:
                    by_kind.setdefault(entry.kind.value, []).append(entry)
                for kind, entries in by_kind.items():
                    sync.iocs.append(
                        control_pb2.IocRule(
                            id=str(r.id),
                            name=r.name,
                            kind=_pb_ioc_kind(kind),
                            values=[e.value_normalized for e in entries],
                            severity=_pb_severity(r.severity.value),
                            action=_pb_action(r.action.value),
                        )
                    )
        return sync
