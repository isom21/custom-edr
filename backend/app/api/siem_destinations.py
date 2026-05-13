"""SIEM destinations CRUD API.

Admin-only. Every mutation is audited; the audit payload redacts the
config's secret fields so the audit log never carries plaintext
tokens. GET responses also redact, so a viewer / analyst that's
inadvertently granted access doesn't learn the credential.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, RequireAdmin
from app.core.errors import bad_request, conflict, not_found
from app.models import SiemDestination, SiemKind
from app.schemas.siem import (
    SiemDestinationCreate,
    SiemDestinationOut,
    SiemDestinationUpdate,
)
from app.services import audit
from app.services.siem import decrypt_config, encrypt_config, redact_secrets

router = APIRouter(prefix="/api/siem/destinations", tags=["siem"])


def _kind_required_fields(kind: SiemKind) -> tuple[str, ...]:
    """Per-kind required-keys gate. We don't constrain shape beyond
    this because operators legitimately add extra fields (TLS opts,
    custom sourcetypes, etc.) that the schema shouldn't have to know
    about."""
    if kind is SiemKind.SYSLOG_CEF:
        return ("host", "port")
    if kind is SiemKind.SPLUNK_HEC:
        return ("url", "token")
    if kind is SiemKind.SENTINEL_HUB:
        return ("namespace", "hub", "sas_key_name", "sas_key")
    return ()


def _check_required(kind: SiemKind, config: dict) -> None:
    missing = [k for k in _kind_required_fields(kind) if not config.get(k)]
    if missing:
        raise bad_request(f"missing required config fields for {kind.value}: {','.join(missing)}")


def _to_out(dest: SiemDestination) -> SiemDestinationOut:
    """Build the API-safe out shape — decrypt config + redact secrets."""
    try:
        cfg = decrypt_config(dest.encrypted_config)
    except RuntimeError:
        # Key rotated since the row was written. Surface as an empty
        # config + a marker the UI can display; operator must re-enter
        # the destination's credentials.
        cfg = {"_error": "could not decrypt — encryption key rotated, re-enter destination"}
    return SiemDestinationOut(
        id=dest.id,
        name=dest.name,
        kind=dest.kind,
        enabled=dest.enabled,
        last_send_at=dest.last_send_at,
        lag_seconds=dest.lag_seconds,
        error_count=dest.error_count,
        config=redact_secrets(cfg),
        created_at=dest.created_at,
        updated_at=dest.updated_at,
    )


@router.get("", response_model=list[SiemDestinationOut])
async def list_destinations(db: DbSession, _actor: RequireAdmin) -> list[SiemDestinationOut]:
    rows = (
        (await db.execute(select(SiemDestination).order_by(SiemDestination.created_at.desc())))
        .scalars()
        .all()
    )
    return [_to_out(d) for d in rows]


@router.post("", response_model=SiemDestinationOut, status_code=status.HTTP_201_CREATED)
async def create_destination(
    payload: SiemDestinationCreate, db: DbSession, actor: RequireAdmin
) -> SiemDestinationOut:
    existing = (
        await db.execute(select(SiemDestination).where(SiemDestination.name == payload.name))
    ).scalar_one_or_none()
    if existing is not None:
        raise conflict("siem destination name already in use")

    _check_required(payload.kind, payload.config)

    dest = SiemDestination(
        name=payload.name,
        kind=payload.kind,
        encrypted_config=encrypt_config(payload.config),
        enabled=payload.enabled,
    )
    db.add(dest)
    await db.flush()

    await audit.record(
        db,
        actor=actor,
        action="siem_destination.create",
        resource_type="siem_destination",
        resource_id=str(dest.id),
        payload={
            "name": payload.name,
            "kind": payload.kind.value,
            "enabled": payload.enabled,
            "config": redact_secrets(payload.config),
        },
    )
    return _to_out(dest)


@router.patch("/{dest_id}", response_model=SiemDestinationOut)
async def update_destination(
    dest_id: UUID,
    payload: SiemDestinationUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> SiemDestinationOut:
    dest = await db.get(SiemDestination, dest_id)
    if dest is None:
        raise not_found("siem_destination", str(dest_id))

    audit_payload: dict = {}
    if payload.name is not None and payload.name != dest.name:
        # Reject on collision so operators don't accidentally clobber
        # another destination's identity by renaming into it.
        clash = (
            await db.execute(
                select(SiemDestination.id).where(
                    SiemDestination.name == payload.name, SiemDestination.id != dest_id
                )
            )
        ).scalar_one_or_none()
        if clash is not None:
            raise conflict("siem destination name already in use")
        dest.name = payload.name
        audit_payload["name"] = payload.name
    if payload.enabled is not None:
        dest.enabled = payload.enabled
        audit_payload["enabled"] = payload.enabled
    if payload.config is not None:
        _check_required(dest.kind, payload.config)
        dest.encrypted_config = encrypt_config(payload.config)
        audit_payload["config"] = redact_secrets(payload.config)

    await audit.record(
        db,
        actor=actor,
        action="siem_destination.update",
        resource_type="siem_destination",
        resource_id=str(dest.id),
        payload=audit_payload,
    )
    return _to_out(dest)


@router.delete("/{dest_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_destination(dest_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    dest = await db.get(SiemDestination, dest_id)
    if dest is None:
        raise not_found("siem_destination", str(dest_id))
    name = dest.name
    kind = dest.kind.value
    await db.delete(dest)
    await audit.record(
        db,
        actor=actor,
        action="siem_destination.delete",
        resource_type="siem_destination",
        resource_id=str(dest_id),
        payload={"name": name, "kind": kind},
    )
