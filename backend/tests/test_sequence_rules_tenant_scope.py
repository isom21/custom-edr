"""Regression test for CODE-9.

SequenceRule has a tenant_id column, but /api/sequence-rules never
filtered or stamped it. A tenant-A admin could enumerate, edit, and
delete every tenant's behavioural detections.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio

YAML_BODY = """trigger:
  event_kind: process_started
  where: executable_basename == "rundll32.exe"
followed_by:
  within: 5s
  event_kind: network_connection
  where: dst_port == 443
then:
  emit_alert:
    severity: high
    message: "rundll32 network connect"
"""


@pytest_asyncio.fixture
async def _per_tenant_srules(db_session: Any, tenant_a: Any, tenant_b: Any) -> tuple[Any, Any]:
    from app.models import SequenceRule, Severity

    a = SequenceRule(
        tenant_id=tenant_a.id,
        name=f"seq-a-{os.urandom(2).hex()}",
        yaml_body=YAML_BODY,
        window_s=5,
        enabled=True,
        severity=Severity.HIGH,
    )
    b = SequenceRule(
        tenant_id=tenant_b.id,
        name=f"seq-b-{os.urandom(2).hex()}",
        yaml_body=YAML_BODY,
        window_s=5,
        enabled=True,
        severity=Severity.HIGH,
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest.mark.asyncio
async def test_admin_in_a_does_not_see_tenant_b_srules(
    http_client: Any, admin_in_a: Any, _per_tenant_srules: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    a, b = _per_tenant_srules
    resp = await http_client.get("/api/sequence-rules", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()["items"]}
    assert str(a.id) in ids
    assert str(b.id) not in ids


@pytest.mark.asyncio
async def test_get_returns_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_srules: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_srules
    resp = await http_client.get(f"/api/sequence-rules/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_returns_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_srules: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_srules
    resp = await http_client.patch(
        f"/api/sequence-rules/{b.id}",
        json={"enabled": False},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_returns_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_srules: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_srules
    resp = await http_client.delete(f"/api/sequence-rules/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_stamps_actor_tenant_id(
    http_client: Any, admin_in_a: Any, tenant_a: Any, db_session: Any
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import SequenceRule
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/sequence-rules",
        json={
            "name": f"new-seq-{os.urandom(2).hex()}",
            "yaml_body": YAML_BODY,
            "window_s": 5,
            "enabled": True,
            "severity": "high",
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (
        await db_session.execute(select(SequenceRule).where(SequenceRule.id == new_id))
    ).scalar_one()
    assert row.tenant_id == tenant_a.id
