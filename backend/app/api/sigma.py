"""Sigma compile + test endpoints.

Used by the rule editor to validate Sigma YAML and to dry-run a rule
against historical telemetry before saving.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

from fastapi import APIRouter
from sqlalchemy import select

from app.core.deps import DbSession, RequireAnalyst
from app.core.errors import bad_request, not_found
from app.models import Rule, RuleKind
from app.schemas.sigma import (
    SigmaCompileRequest,
    SigmaCompileResponse,
    SigmaTestRequest,
    SigmaTestResponse,
    SigmaTestSampleHit,
)
from app.services import opensearch as os_svc
from app.services.sigma import SigmaCompileError, compile_yaml

router = APIRouter(prefix="/api/sigma", tags=["sigma"])


@router.post("/compile", response_model=SigmaCompileResponse)
async def compile_endpoint(
    payload: SigmaCompileRequest, _actor: RequireAnalyst
) -> SigmaCompileResponse:
    try:
        compiled = compile_yaml(payload.body)
    except SigmaCompileError as exc:
        return SigmaCompileResponse(ok=False, error=str(exc))
    return SigmaCompileResponse(
        ok=True,
        query=compiled.query,
        title=compiled.title or None,
        description=compiled.description,
    )


@router.post("/test", response_model=SigmaTestResponse)
async def test_adhoc(payload: SigmaTestRequest, _actor: RequireAnalyst) -> SigmaTestResponse:
    if not payload.body:
        raise bad_request("body required for ad-hoc test (or use /api/rules/{id}/test)")
    return await _run_test(payload.body, payload.lookback_hours)


@router.post("/rules/{rule_id}/test", response_model=SigmaTestResponse)
async def test_saved_rule(
    rule_id: UUID,
    payload: SigmaTestRequest,
    db: DbSession,
    _actor: RequireAnalyst,
) -> SigmaTestResponse:
    rule = (
        await db.execute(select(Rule).where(Rule.id == rule_id))
    ).scalar_one_or_none()
    if rule is None:
        raise not_found("rule", str(rule_id))
    if rule.kind is not RuleKind.SIGMA:
        raise bad_request("rule is not a sigma rule")
    body = payload.body or rule.body or ""
    if not body:
        raise bad_request("rule has no body")
    return await _run_test(body, payload.lookback_hours)


async def _run_test(body: str, lookback_hours: int) -> SigmaTestResponse:
    try:
        compiled = compile_yaml(body)
    except SigmaCompileError as exc:
        raise bad_request(f"compile failed: {exc}") from exc

    upper = datetime.now(timezone.utc)
    lower = upper - timedelta(hours=lookback_hours)

    client = os_svc._client()
    try:
        resp = await client.search(
            index="telemetry-*",
            body={
                "size": 25,
                "track_total_hits": True,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": lower.isoformat(),
                                        "lte": upper.isoformat(),
                                    }
                                }
                            },
                            {"query_string": {"query": compiled.query}},
                        ]
                    }
                },
            },
            request_timeout=20,
        )
    finally:
        await client.close()

    total_obj = resp.get("hits", {}).get("total", 0)
    total = total_obj.get("value", 0) if isinstance(total_obj, dict) else int(total_obj)
    hits = resp.get("hits", {}).get("hits", [])
    samples = [
        SigmaTestSampleHit(
            timestamp=h.get("_source", {}).get("@timestamp"),
            host_id=h.get("_source", {}).get("host", {}).get("id"),
            event_id=h.get("_source", {}).get("event", {}).get("id"),
            process=h.get("_source", {}).get("process"),
            file=h.get("_source", {}).get("file"),
        )
        for h in hits
    ]
    return SigmaTestResponse(query=compiled.query, total=total, samples=samples)
