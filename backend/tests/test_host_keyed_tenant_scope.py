"""Regression tests for CODE-15, CODE-16, CODE-17, CODE-18.

Four endpoints touched host-keyed rows without checking
host_visible_to (which is itself tenant-scoped):

  * /api/jobs/{id} + /{id}/runs + /{id}/cancel: no Job.tenant_id
    filter at all.
  * /api/host-vulnerabilities/{id}/suppress: no host check.
  * /api/quarantine/{id}: delete didn't check host.
  * /api/hosts/{id} PATCH/DELETE: no host check; PATCH could rebind
    policy_id cross-tenant.
"""

from __future__ import annotations

import os
from typing import Any

import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def _per_tenant_hosts(db_session: Any, tenant_a: Any, tenant_b: Any) -> tuple[Any, Any]:
    from app.models import Host, HostStatus, OsFamily

    a = Host(
        tenant_id=tenant_a.id,
        hostname=f"host-a-{os.urandom(2).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    b = Host(
        tenant_id=tenant_b.id,
        hostname=f"host-b-{os.urandom(2).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add_all([a, b])
    await db_session.flush()
    return a, b


# ---------- jobs (CODE-15) ------------------------------------------------


@pytest.mark.asyncio
async def test_get_job_returns_404_cross_tenant(
    http_client: Any, admin_in_a: Any, db_session: Any, tenant_b: Any
) -> None:
    from app.models import Job, JobKind, JobStatus
    from tests.conftest import headers_for

    foreign_job = Job(
        tenant_id=tenant_b.id,
        kind=JobKind.PROCESS_SNAPSHOT,
        status=JobStatus.QUEUED,
        parameters={},
        scope_kind="all_online",
        created_by_user_id=None,
    )
    db_session.add(foreign_job)
    await db_session.flush()
    resp = await http_client.get(f"/api/jobs/{foreign_job.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_cancel_job_returns_404_cross_tenant(
    http_client: Any, admin_in_a: Any, db_session: Any, tenant_b: Any
) -> None:
    from app.models import Job, JobKind, JobStatus
    from tests.conftest import headers_for

    foreign_job = Job(
        tenant_id=tenant_b.id,
        kind=JobKind.PROCESS_SNAPSHOT,
        status=JobStatus.QUEUED,
        parameters={},
        scope_kind="all_online",
        created_by_user_id=None,
    )
    db_session.add(foreign_job)
    await db_session.flush()
    resp = await http_client.post(
        f"/api/jobs/{foreign_job.id}/cancel", headers=headers_for(admin_in_a)
    )
    assert resp.status_code == 404


# ---------- vulnerabilities (CODE-16) -------------------------------------


@pytest.mark.asyncio
async def test_suppress_vulnerability_404_cross_tenant_host(
    http_client: Any,
    admin_in_a: Any,
    db_session: Any,
    _per_tenant_hosts: tuple[Any, Any],
) -> None:
    from app.models import HostVulnerability, Vulnerability
    from tests.conftest import headers_for

    _, b_host = _per_tenant_hosts
    cve_id = f"CVE-9999-{os.urandom(2).hex()}"
    cve = Vulnerability(cve_id=cve_id, severity="high", summary="x")
    db_session.add(cve)
    await db_session.flush()
    hv = HostVulnerability(host_id=b_host.id, cve_id=cve.cve_id)
    db_session.add(hv)
    await db_session.flush()
    resp = await http_client.post(
        f"/api/host-vulnerabilities/{hv.id}/suppress",
        json={"reason": "test"},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


# ---------- quarantine (CODE-17) ------------------------------------------


@pytest.mark.asyncio
async def test_delete_quarantine_404_cross_tenant_host(
    http_client: Any,
    admin_in_a: Any,
    db_session: Any,
    _per_tenant_hosts: tuple[Any, Any],
) -> None:
    from app.models import QuarantinedFile, QuarantineStatus
    from tests.conftest import headers_for

    _, b_host = _per_tenant_hosts
    from datetime import UTC, datetime

    qf = QuarantinedFile(
        host_id=b_host.id,
        sha256="a" * 64,
        original_path="/tmp/x",
        size_bytes=1,
        quarantined_at=datetime.now(UTC),
        status=QuarantineStatus.ACTIVE,
    )
    db_session.add(qf)
    await db_session.flush()
    resp = await http_client.delete(f"/api/quarantine/{qf.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404


# ---------- hosts (CODE-18) -----------------------------------------------


@pytest.mark.asyncio
async def test_patch_host_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_hosts: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b_host = _per_tenant_hosts
    resp = await http_client.patch(
        f"/api/hosts/{b_host.id}",
        json={"status": "offline"},
        headers=headers_for(admin_in_a),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_delete_host_404_cross_tenant(
    http_client: Any, admin_in_a: Any, _per_tenant_hosts: tuple[Any, Any]
) -> None:
    from tests.conftest import headers_for

    _, b_host = _per_tenant_hosts
    resp = await http_client.delete(f"/api/hosts/{b_host.id}", headers=headers_for(admin_in_a))
    assert resp.status_code == 404
