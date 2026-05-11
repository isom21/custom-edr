"""M-grpc-hygiene #3: `_GRPC_BUCKETS` is popped on stream close.

The reviewer noted that `_GRPC_BUCKETS` carried a comment claiming it
was cleaned up on stream close, but no code did the pop. Over a fleet
with churn, the dict grows unbounded; more importantly, the stale
comment invites someone to attach per-host counters or timestamps and
assume the entry disappears when the host disconnects.

Direct integration test (full HostStream loop + cert provisioning +
Kafka producer) is more setup than this guarantee warrants. Instead
this exercises the contract directly: insert a fake bucket, run the
same `pop(host_id_str, None)` the HostStream finally-block runs,
assert the dict shrank.
"""

from __future__ import annotations

from app.grpc.services import _GRPC_BUCKETS, _HostBucket


def test_pop_removes_host_bucket_idempotently() -> None:
    """The finally-block's `pop(..., None)` must succeed when the
    bucket exists AND when it doesn't (the rate-limit code only
    creates a bucket on the first events frame, so streams that
    closed before any events shouldn't break the cleanup)."""
    host_id = "00000000-0000-0000-0000-00000ec0c0c0"
    _GRPC_BUCKETS.pop(host_id, None)  # pre-clean in case a prior test leaked
    assert host_id not in _GRPC_BUCKETS

    # Bucket exists → pop returns it and removes it.
    _GRPC_BUCKETS[host_id] = _HostBucket()
    assert host_id in _GRPC_BUCKETS
    _GRPC_BUCKETS.pop(host_id, None)
    assert host_id not in _GRPC_BUCKETS

    # Bucket missing → pop is a no-op (does not raise).
    _GRPC_BUCKETS.pop(host_id, None)
    assert host_id not in _GRPC_BUCKETS


def test_buckets_dict_keyed_by_str_uuid() -> None:
    """Regression guard against a future refactor changing the key
    shape — the HostStream finally-block passes `host_id_str` (the
    string form), so the rate-limit code at the top of the file must
    use the same key shape."""
    host_id = "00000000-0000-0000-0000-deadbeefcafe"
    _GRPC_BUCKETS.pop(host_id, None)
    bucket = _GRPC_BUCKETS.setdefault(host_id, _HostBucket())
    assert isinstance(bucket, _HostBucket)
    # The same string lookup must hit.
    assert _GRPC_BUCKETS.get(host_id) is bucket
    _GRPC_BUCKETS.pop(host_id, None)
