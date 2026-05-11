"""HostStream connect-time admission: decommission + cert pinning.

The reviewer's HIGH finding (`grpc/services.py:295-326`) was that
`HostStream` only rejected when the host row was missing. A host the
operator had explicitly decommissioned, or one whose CN matched the
row but whose cert didn't, both kept streaming until the cert hit its
90-day expiry. The fix lives in `_check_host_admission` and these
tests pin its contract.

Unit tests on the helper itself — the full HostStream path needs a
running gRPC channel + Kafka producer which is more setup than the
admission gate warrants.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.grpc.services import _check_host_admission
from app.models import Host, HostStatus


def _host(status: HostStatus, fingerprint: str | None = "abc123") -> Host:
    """Build a Host ORM instance without touching the DB. The admission
    gate only reads attributes, so a plain object is fine."""
    return Host(
        hostname="lab-host",
        os_family="linux",
        status=status,
        cert_fingerprint=fingerprint,
        enrolled_at=datetime.now(UTC),
    )


def test_admits_online_host_with_matching_fingerprint() -> None:
    admitted, reason = _check_host_admission(_host(HostStatus.ONLINE), "abc123")
    assert admitted is True
    assert reason is None


def test_admits_pending_host_with_matching_fingerprint() -> None:
    admitted, reason = _check_host_admission(_host(HostStatus.PENDING), "abc123")
    assert admitted is True
    assert reason is None


def test_rejects_decommissioned_host() -> None:
    admitted, reason = _check_host_admission(_host(HostStatus.DECOMMISSIONED), "abc123")
    assert admitted is False
    assert reason == "host decommissioned"


def test_rejects_decommissioned_host_even_without_fingerprint() -> None:
    """Mid-stream heartbeat re-check passes None for the peer fingerprint
    (the TLS handshake's cert can't change after the stream opened).
    Decommissioned must still reject."""
    admitted, reason = _check_host_admission(_host(HostStatus.DECOMMISSIONED), None)
    assert admitted is False
    assert reason == "host decommissioned"


def test_rejects_mismatched_fingerprint() -> None:
    admitted, reason = _check_host_admission(_host(HostStatus.ONLINE, "abc123"), "zzz999")
    assert admitted is False
    assert reason == "cert revoked"


def test_admits_when_host_row_has_no_fingerprint_recorded() -> None:
    """Hosts enrolled before fingerprint persistence don't get locked out."""
    admitted, reason = _check_host_admission(_host(HostStatus.ONLINE, None), "abc123")
    assert admitted is True
    assert reason is None


def test_admits_when_peer_fingerprint_unavailable() -> None:
    """Plaintext dev channel — auth_context has no x509_pem_cert. The peer
    is already gated by the CN check upstream; the fingerprint compare
    is best-effort defense in depth."""
    admitted, reason = _check_host_admission(_host(HostStatus.ONLINE, "abc123"), None)
    assert admitted is True
    assert reason is None


@pytest.mark.parametrize("status", [HostStatus.PENDING, HostStatus.ONLINE, HostStatus.OFFLINE])
def test_non_decommissioned_statuses_admit(status: HostStatus) -> None:
    admitted, _ = _check_host_admission(_host(status), "abc123")
    assert admitted is True
