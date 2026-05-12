"""404/403 unification on uploads + quarantine host-scope checks.

Review findings.md Top-20 #7: three sites raised `forbidden(...)`
when the actor was authenticated but the resource sat on a host
outside their groups, leaking the existence of cross-team
resources. M-audit-and-auth #7 unifies all such cases to 404 so
the response shape doesn't distinguish "doesn't exist" from
"exists but not for you".

The three sites under test:

  * GET /api/downloads/{artifact_id}                 (uploads.py)
  * GET /api/hosts/{host_id}/quarantined             (quarantine.py)
  * POST /api/quarantined/{quarantine_id}/release    (quarantine.py)
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from sqlalchemy import insert


@pytest_asyncio.fixture
async def _two_host_scope(db_session, admin_user, analyst_user):
    from app.models import (
        Host,
        HostGroup,
        HostStatus,
        OsFamily,
        host_in_group,
        user_host_group,
    )

    a = Host(
        hostname=f"host-a-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    b = Host(
        hostname=f"host-b-{os.urandom(3).hex()}",
        os_family=OsFamily.LINUX,
        status=HostStatus.ONLINE,
    )
    db_session.add_all([a, b])
    await db_session.flush()

    alpha = HostGroup(name=f"alpha-{os.urandom(3).hex()}")
    beta = HostGroup(name=f"beta-{os.urandom(3).hex()}")
    db_session.add_all([alpha, beta])
    await db_session.flush()

    await db_session.execute(insert(host_in_group).values(host_id=a.id, host_group_id=alpha.id))
    await db_session.execute(insert(host_in_group).values(host_id=b.id, host_group_id=beta.id))
    await db_session.execute(
        insert(user_host_group).values(user_id=analyst_user.id, host_group_id=alpha.id)
    )
    return {"host_a": a, "host_b": b}


@pytest.mark.asyncio
async def test_list_quarantined_for_host_returns_404_for_out_of_scope(
    http_client, _two_host_scope, analyst_headers
):
    resp = await http_client.get(
        f"/api/hosts/{_two_host_scope['host_b'].id}/quarantined", headers=analyst_headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_quarantined_for_host_in_scope_works(
    http_client, _two_host_scope, analyst_headers
):
    resp = await http_client.get(
        f"/api/hosts/{_two_host_scope['host_a'].id}/quarantined", headers=analyst_headers
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_release_quarantined_file_returns_404_for_out_of_scope(
    http_client, _two_host_scope, analyst_headers, db_session, admin_user
):
    from app.models import QuarantinedFile, QuarantineStatus

    q = QuarantinedFile(
        host_id=_two_host_scope["host_b"].id,
        original_path="/tmp/evil.bin",
        sha256="a" * 64,
        size_bytes=42,
        quarantined_at=datetime.now(UTC),
        status=QuarantineStatus.ACTIVE,
    )
    db_session.add(q)
    await db_session.flush()

    resp = await http_client.post(
        f"/api/quarantined/{q.id}/release", json={}, headers=analyst_headers
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_download_artifact_returns_404_for_out_of_scope(
    http_client, _two_host_scope, analyst_headers, db_session, admin_user
):
    from app.models import (
        Job,
        JobArtifact,
        JobArtifactKind,
        JobKind,
        JobRun,
        JobRunStatus,
        JobScopeKind,
        JobStatus,
    )

    job = Job(
        kind=JobKind.PROCESS_SNAPSHOT,
        parameters={},
        scope_kind=JobScopeKind.HOST_IDS,
        scope_host_ids=[str(_two_host_scope["host_b"].id)],
        status=JobStatus.RUNNING,
        summary="snap B",
        created_by_user_id=admin_user.id,
        triggered_by="manual",
    )
    db_session.add(job)
    await db_session.flush()
    run = JobRun(job_id=job.id, host_id=_two_host_scope["host_b"].id, status=JobRunStatus.COMPLETED)
    db_session.add(run)
    await db_session.flush()
    art = JobArtifact(
        job_run_id=run.id,
        kind=JobArtifactKind.JSON,
        bucket="vigil-artifacts",
        object_key=f"artifacts/{run.id}/snap.json",
        size_bytes=1024,
    )
    db_session.add(art)
    await db_session.flush()

    resp = await http_client.get(f"/api/downloads/{art.id}", headers=analyst_headers)
    assert resp.status_code == 404
