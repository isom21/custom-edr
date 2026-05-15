"""Sequence-rule CRUD (Phase 2 #2.3).

Operators author YAML rules in /sequence-rules; the sequence_detector
worker consumes the rule via its periodic refresh. The Rule.body is
not exposed here — that's an internal artefact of the managed-Rule
pattern; operators see only the YAML they wrote.

Auth split mirrors the rest of the manager: viewers + analysts read;
admins write. Every mutation goes through the audit log.
"""

from __future__ import annotations

from uuid import UUID

import structlog
from fastapi import APIRouter, status
from sqlalchemy import func, select

from app.core.deps import DbSession, RequireAdmin, RequireViewer
from app.core.errors import bad_request, not_found
from app.models import SequenceRule
from app.schemas.common import Page
from app.schemas.sequence_rule import (
    SequenceRuleCreate,
    SequenceRuleOut,
    SequenceRuleUpdate,
)
from app.services import audit
from app.services.scoping import apply_tenant_scope
from app.services.sequence import SequenceParseError, parse_yaml

log = structlog.get_logger()

router = APIRouter(prefix="/api/sequence-rules", tags=["sequence-rules"])


def _to_out(srule: SequenceRule) -> SequenceRuleOut:
    return SequenceRuleOut.model_validate(srule)


def _validate_or_400(yaml_body: str, window_s: int) -> None:
    try:
        parse_yaml(yaml_body, default_window_s=window_s)
    except SequenceParseError as exc:
        raise bad_request(f"sequence rule yaml invalid: {exc}") from exc


async def _load_in_tenant(db, srule_id: UUID, actor) -> SequenceRule:
    """Fetch a SequenceRule, enforcing tenant scope. 404 (not 403) on
    cross-tenant id (CODE-9)."""
    srule = await db.get(SequenceRule, srule_id)
    if srule is None or srule.tenant_id != actor.tenant_id:
        raise not_found("sequence_rule", str(srule_id))
    return srule


@router.get("", response_model=Page[SequenceRuleOut])
async def list_sequence_rules(
    db: DbSession,
    actor: RequireViewer,
    enabled: bool | None = None,
    limit: int = 50,
    offset: int = 0,
) -> Page[SequenceRuleOut]:
    # CODE-9: scope to the actor's tenant. SequenceRule.tenant_id was
    # never being filtered, so any admin saw + mutated every tenant's
    # behavioural detections.
    stmt = apply_tenant_scope(select(SequenceRule), actor, SequenceRule.tenant_id).order_by(
        SequenceRule.name
    )
    count_stmt = apply_tenant_scope(
        select(func.count(SequenceRule.id)), actor, SequenceRule.tenant_id
    )
    if enabled is not None:
        stmt = stmt.where(SequenceRule.enabled == enabled)
        count_stmt = count_stmt.where(SequenceRule.enabled == enabled)
    stmt = stmt.limit(limit).offset(offset)
    rows = (await db.execute(stmt)).scalars().all()
    total = (await db.execute(count_stmt)).scalar_one()
    return Page(
        items=[_to_out(r) for r in rows],
        total=int(total),
        limit=limit,
        offset=offset,
    )


@router.get("/{srule_id}", response_model=SequenceRuleOut)
async def get_sequence_rule(srule_id: UUID, db: DbSession, actor: RequireViewer) -> SequenceRuleOut:
    srule = await _load_in_tenant(db, srule_id, actor)
    return _to_out(srule)


@router.post("", response_model=SequenceRuleOut, status_code=status.HTTP_201_CREATED)
async def create_sequence_rule(
    payload: SequenceRuleCreate,
    db: DbSession,
    actor: RequireAdmin,
) -> SequenceRuleOut:
    # Name uniqueness is per-tenant — two tenants can each have a
    # "powershell-encoded-command" sequence rule.
    dup = (
        await db.execute(
            select(SequenceRule)
            .where(SequenceRule.name == payload.name)
            .where(SequenceRule.tenant_id == actor.tenant_id)
        )
    ).scalar_one_or_none()
    if dup is not None:
        raise bad_request(f"sequence rule '{payload.name}' already exists")
    _validate_or_400(payload.yaml_body, payload.window_s)
    srule = SequenceRule(
        tenant_id=actor.tenant_id,
        name=payload.name,
        description=payload.description,
        yaml_body=payload.yaml_body,
        window_s=payload.window_s,
        enabled=payload.enabled,
        severity=payload.severity,
        mitre_techniques=payload.mitre_techniques,
        created_by_user_id=actor.user.id,
    )
    db.add(srule)
    await db.flush()
    await audit.record(
        db,
        actor=actor,
        action="sequence_rule.create",
        resource_type="sequence_rule",
        resource_id=str(srule.id),
        payload={
            "name": srule.name,
            "window_s": srule.window_s,
            "enabled": srule.enabled,
            "severity": srule.severity.value,
        },
    )
    await db.commit()
    await db.refresh(srule)
    return _to_out(srule)


@router.patch("/{srule_id}", response_model=SequenceRuleOut)
async def update_sequence_rule(
    srule_id: UUID,
    payload: SequenceRuleUpdate,
    db: DbSession,
    actor: RequireAdmin,
) -> SequenceRuleOut:
    srule = await _load_in_tenant(db, srule_id, actor)
    if payload.name is not None and payload.name != srule.name:
        dup = (
            await db.execute(
                select(SequenceRule)
                .where(SequenceRule.name == payload.name)
                .where(SequenceRule.tenant_id == actor.tenant_id)
            )
        ).scalar_one_or_none()
        if dup is not None:
            raise bad_request(f"sequence rule '{payload.name}' already exists")
        srule.name = payload.name
    if payload.description is not None:
        srule.description = payload.description
    if payload.window_s is not None:
        srule.window_s = payload.window_s
    if payload.yaml_body is not None:
        _validate_or_400(payload.yaml_body, payload.window_s or srule.window_s)
        srule.yaml_body = payload.yaml_body
    if payload.enabled is not None:
        srule.enabled = payload.enabled
    if payload.severity is not None:
        srule.severity = payload.severity
    if payload.mitre_techniques is not None:
        srule.mitre_techniques = payload.mitre_techniques
    await audit.record(
        db,
        actor=actor,
        action="sequence_rule.update",
        resource_type="sequence_rule",
        resource_id=str(srule.id),
        payload=payload.model_dump(exclude_none=True, mode="json"),
    )
    await db.commit()
    await db.refresh(srule)
    return _to_out(srule)


@router.delete("/{srule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_sequence_rule(srule_id: UUID, db: DbSession, actor: RequireAdmin) -> None:
    srule = await _load_in_tenant(db, srule_id, actor)
    # Don't cascade-delete the managed Rule — old Alert rows reference
    # it (Alert.rule_id is ondelete=RESTRICT). The Rule sticks around
    # as the carrier for historical alerts. SET NULL on the FK means
    # the deletion is clean even if an operator later deletes the
    # managed Rule manually.
    await db.delete(srule)
    await audit.record(
        db,
        actor=actor,
        action="sequence_rule.delete",
        resource_type="sequence_rule",
        resource_id=str(srule_id),
        payload={"name": srule.name},
    )
    await db.commit()
