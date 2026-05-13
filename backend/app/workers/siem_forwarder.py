"""SIEM forwarder worker (Phase 1 #1.5).

Consumes `telemetry.normalized` + `alerts.raw` and dispatches each
record to every enabled SIEM destination. Per-destination retry +
Prometheus lag + error counters live alongside the in-row health
fields (`last_send_at`, `lag_seconds`, `error_count`) so operators
can both alert from Prometheus and triage from the UI without
correlating two systems.

Pattern mirrors `sigma_realtime`:

  * `enable_auto_commit=False` — commit only after every destination
    finished for this message.
  * Transient `SendError` on any destination -> we DON'T commit; the
    consumer replays the offset on the next poll.
  * Poison-pill / decode failures -> commit so the offset advances;
    log + counter.

The destination cache is refreshed on a 30-second timer plus on
demand whenever a send fails (operators routinely fix a SIEM
endpoint by disabling its destination, and we want that to take
effect within one poll cycle without waiting for the next 30 s tick).

Run with:
    python -m app.workers.siem_forwarder
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
from datetime import UTC, datetime
from uuid import UUID

import structlog
from aiokafka import AIOKafkaConsumer
from sqlalchemy import select, update

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.metrics import (
    siem_forwarder_lag_seconds,
    siem_forwarder_send_errors_total,
    siem_forwarder_sends_total,
)
from app.models import SiemDestination
from app.services.siem import SendError, decrypt_config, send_for_kind

log = structlog.get_logger()

# How often the worker re-reads the destinations table even if no
# send failed. A 30 s drift between the UI's "Save" and the worker
# acting on the change is acceptable and avoids hammering Postgres
# with a SELECT per message.
CACHE_REFRESH_S = 30.0


class SiemForwarder:
    def __init__(self) -> None:
        self.consumer: AIOKafkaConsumer | None = None
        self._stop = asyncio.Event()
        self._destinations: dict[UUID, SiemDestination] = {}
        self._last_cache_refresh: float = 0.0

    async def start(self) -> None:
        await self._refresh_destinations()
        self.consumer = AIOKafkaConsumer(
            settings.topic_telemetry_normalized,
            settings.topic_alerts_raw,
            bootstrap_servers=settings.kafka_brokers,
            group_id="siem_forwarder",
            enable_auto_commit=False,
            auto_offset_reset="latest",
            session_timeout_ms=15_000,
            max_poll_interval_ms=300_000,
        )
        await self.consumer.start()
        log.info(
            "siem.forwarder.start",
            telemetry_topic=settings.topic_telemetry_normalized,
            alerts_topic=settings.topic_alerts_raw,
            destinations=len(self._destinations),
        )

    async def stop(self) -> None:
        self._stop.set()
        if self.consumer is not None:
            await self.consumer.stop()
        log.info("siem.forwarder.stop")

    async def _refresh_destinations(self) -> None:
        async with SessionLocal() as db:
            stmt = select(SiemDestination).where(SiemDestination.enabled.is_(True))
            rows = list((await db.execute(stmt)).scalars().all())
        self._destinations = {d.id: d for d in rows}
        self._last_cache_refresh = asyncio.get_event_loop().time()

    def _topic_to_event_kind(self, topic: str) -> str:
        """`telemetry.normalized` -> "telemetry"; `alerts.raw` -> "alert".
        Anything else is treated as telemetry — Kafka guarantees we
        only get topics we subscribed to, so the fallback is defensive
        only."""
        if topic == settings.topic_alerts_raw:
            return "alert"
        return "telemetry"

    @staticmethod
    def _event_lag_seconds(event: dict) -> float:
        ts = event.get("@timestamp")
        if not isinstance(ts, str):
            return 0.0
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:  # noqa: BLE001 - bad timestamp falls back to 0 lag
            return 0.0
        return max(0.0, (datetime.now(UTC) - parsed).total_seconds())

    async def _record_send(self, dest: SiemDestination, lag: float) -> None:
        now = datetime.now(UTC)
        async with SessionLocal() as db:
            await db.execute(
                update(SiemDestination)
                .where(SiemDestination.id == dest.id)
                .values(last_send_at=now, lag_seconds=lag, error_count=0)
            )
            await db.commit()
        # Reflect into the cached copy so the next message uses the
        # fresh state without an extra SELECT.
        dest.last_send_at = now
        dest.lag_seconds = lag
        dest.error_count = 0
        label = str(dest.id)
        siem_forwarder_lag_seconds.labels(destination=label).set(lag)
        siem_forwarder_sends_total.labels(destination=label).inc()

    async def _record_error(self, dest: SiemDestination, exc: BaseException) -> None:
        async with SessionLocal() as db:
            await db.execute(
                update(SiemDestination)
                .where(SiemDestination.id == dest.id)
                .values(error_count=SiemDestination.error_count + 1)
            )
            await db.commit()
        dest.error_count += 1
        siem_forwarder_send_errors_total.labels(destination=str(dest.id)).inc()
        log.warning(
            "siem.forwarder.send_failed",
            destination=str(dest.id),
            destination_name=dest.name,
            kind=dest.kind.value,
            error=str(exc),
            error_count=dest.error_count,
        )

    async def _dispatch(
        self, event: dict, *, event_kind: str
    ) -> bool:
        """Fan out one event to every enabled destination.

        Returns True iff every send succeeded — the caller commits the
        Kafka offset on True and replays on False.
        """
        if not self._destinations:
            return True
        all_ok = True
        for dest in list(self._destinations.values()):
            try:
                config = decrypt_config(dest.encrypted_config)
            except RuntimeError as exc:
                # Key rotated; permanent failure for this row. Bump
                # error_count but don't fail the whole batch — operator
                # has to re-enter the destination's secrets either way.
                await self._record_error(dest, exc)
                continue
            try:
                await send_for_kind(
                    dest.kind, config, event, event_kind=event_kind
                )
            except SendError as exc:
                await self._record_error(dest, exc)
                all_ok = False
                continue
            except Exception as exc:  # noqa: BLE001 - sender contract is to raise SendError
                # Defensive: any other exception means the sender is
                # buggy — log + replay so the bug doesn't silently
                # drop events.
                await self._record_error(dest, exc)
                all_ok = False
                continue
            await self._record_send(dest, self._event_lag_seconds(event))
        return all_ok

    async def run(self) -> None:
        assert self.consumer is not None
        while not self._stop.is_set():
            now = asyncio.get_event_loop().time()
            if now - self._last_cache_refresh >= CACHE_REFRESH_S:
                await self._refresh_destinations()

            try:
                msg = await asyncio.wait_for(self.consumer.getone(), timeout=1.0)
            except TimeoutError:
                continue
            if msg.value is None:
                await self.consumer.commit()
                continue

            try:
                event = json.loads(msg.value)
            except Exception:  # noqa: BLE001 - poison pill, skip
                log.exception("siem.forwarder.decode_failed", offset=msg.offset)
                await self.consumer.commit()
                continue

            event_kind = self._topic_to_event_kind(msg.topic)
            ok = await self._dispatch(event, event_kind=event_kind)
            if ok:
                await self.consumer.commit()
            else:
                # Replay this offset on the next poll, but refresh the
                # destination cache first — chances are the operator
                # is mid-fix and we want to pick up the disable/edit
                # quickly.
                await self._refresh_destinations()


async def amain() -> None:
    worker = SiemForwarder()
    await worker.start()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(worker.stop()))
    try:
        await worker.run()
    finally:
        await worker.stop()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )
    asyncio.run(amain())


if __name__ == "__main__":
    main()
