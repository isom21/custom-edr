"""Regression test for CODE-8.

The /api/playbooks router operated globally pre-PR — a tenant-A admin
could enumerate, edit, and delete any tenant's playbooks; the per-
playbook run history endpoint leaked tenant B's runs.

Migration 20260515_1000_playbook_tenant_id adds the column + a
per-(tenant, name) unique constraint so two tenants can each have a
"lsass-credential-dump-response" playbook.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _per_tenant_playbooks(db_session: Any, tenant_a: Any, tenant_b: Any) -> tuple[Any, Any]:
    from app.models import Playbook

    yaml_body = "steps:\n  - isolate: {}\n"
    a = Playbook(
        tenant_id=tenant_a.id,
        name=f"pb-a-{os.urandom(2).hex()}",
        yaml_body=yaml_body,
        enabled=True,
    )
    b = Playbook(
        tenant_id=tenant_b.id,
        name=f"pb-b-{os.urandom(2).hex()}",
        yaml_body=yaml_body,
        enabled=True,
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


@pytest.mark.asyncio
async def test_admin_in_a_does_not_see_tenant_b_playbooks(
    http_client: Any, admin_in_a: Any, _per_tenant_playbooks: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    a, b = _per_tenant_playbooks
    resp = await http_client.get("/api/playbooks", headers=headers_for(admin_in_a))
    assert resp.status_code == 200
    ids = {item["id"] for item in resp.json()["items"]}
    assert str(a.id) in ids
    assert str(b.id) not in ids


@pytest.mark.asyncio
async def test_admin_in_a_cannot_get_tenant_b_playbook(
    http_client: Any, admin_in_a: Any, _per_tenant_playbooks: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_playbooks
    resp = await http_client.get(f"/api/playbooks/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_in_a_cannot_patch_tenant_b_playbook(
    http_client: Any, admin_in_a: Any, _per_tenant_playbooks: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_playbooks
    resp = await http_client.patch(
        f"/api/playbooks/{b.id}",
        json={"enabled": False},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_in_a_cannot_delete_tenant_b_playbook(
    http_client: Any, admin_in_a: Any, _per_tenant_playbooks: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b = _per_tenant_playbooks
    resp = await http_client.delete(f"/api/playbooks/{b.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_admin_in_a_cannot_list_tenant_b_runs(
    http_client: Any, admin_in_a: Any, _per_tenant_playbooks: tuple[Any, Any]
) -> None:
    """Cross-tenant runs endpoint must 404 on the playbook gate, not
    spill the run history."""
    from tests.conftest import headers_for

    _, b = _per_tenant_playbooks
    resp = await http_client.get(f"/api/playbooks/{b.id}/runs", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_playbook_stamps_actor_tenant_id(
    http_client: Any,
    admin_in_a: Any,
    tenant_a: Any,
    db_session: Any,
) -> None:
    from uuid import UUID

    from sqlalchemy import select

    from app.models import Playbook
    from tests.conftest import headers_for

    resp = await http_client.post(
        "/api/playbooks",
        json={
            "name": f"new-pb-{os.urandom(2).hex()}",
            "yaml_body": "steps:\n  - isolate: {}\n",
            "enabled": True,
        },
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 201, resp.text
    new_id = UUID(resp.json()["id"])
    row = (await db_session.execute(select(Playbook).where(Playbook.id == new_id))).scalar_one()
    assert row.tenant_id == tenant_a.id


@pytest.mark.asyncio
async def test_two_tenants_can_share_playbook_name(
    http_client: Any,
    admin_in_a: Any,
    admin_in_b: Any,
) -> None:
    """The migration's (tenant_id, name) unique replaces the global
    UNIQUE(name), so both tenants can have a 'lsass-dump-response'."""
    from tests.conftest import headers_for

    name = f"shared-{os.urandom(2).hex()}"
    yaml_body = "steps:\n  - isolate: {}\n"
    r_a = await http_client.post(
        "/api/playbooks",
        json={"name": name, "yaml_body": yaml_body, "enabled": True},
        headers=headers_for(admin_in_a),
    )
    r_b = await http_client.post(
        "/api/playbooks",
        json={"name": name, "yaml_body": yaml_body, "enabled": True},
        headers=headers_for(admin_in_b),
    )
    assert r_a.status_code == 201, r_a.text
    assert r_b.status_code == 201, r_b.text
