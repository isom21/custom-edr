"""Host-group scope on /api/sigma/test and /api/sigma/rules/{id}/test.

Review findings.md Top-20 #3: `_run_test` ran the OpenSearch query
unscoped, so an analyst with access to host A could find hits from
host B by writing a sigma rule whose query string matched events
they couldn't see anywhere else in the console.

The fix wraps the search body with a `terms` filter on `host.id`
when the actor is non-admin (admins are pass-through). We can't
verify the post-OpenSearch result shape in unit tests cheaply, but
the wire-shape of the request body is what matters — that's what
the OS cluster gates on. The tests pin three contracts on
`_build_search_body`:

  * Admin → no `host.id` filter appears (admins see everything).
  * Non-admin with N visible host ids → a `terms` clause on
    `host.id` with exactly those ids appears.
  * Non-admin with zero visible host ids → `_run_test` short-
    circuits with total=0 and never calls OpenSearch.

Plus one integration test that drives `/api/sigma/test` via the
ASGI client and confirms an analyst with zero hosts gets the
empty-result early path (no OS call).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest


def test_build_search_body_admin_omits_host_scope() -> None:
    from app.api.sigma import _build_search_body

    upper = datetime.now(UTC)
    lower = upper - timedelta(hours=1)
    body = _build_search_body("event.category:process", lower, upper, visible_ids=None)
    filters = body["query"]["bool"]["filter"]
    # Range + query_string, no host filter.
    assert len(filters) == 2
    assert not any("terms" in f and "host.id" in f.get("terms", {}) for f in filters)


def test_build_search_body_analyst_includes_terms_clause() -> None:
    from app.api.sigma import _build_search_body

    upper = datetime.now(UTC)
    lower = upper - timedelta(hours=1)
    visible = [uuid4(), uuid4()]
    body = _build_search_body("event.category:process", lower, upper, visible_ids=visible)
    filters = body["query"]["bool"]["filter"]
    terms = next(f for f in filters if "terms" in f)
    assert terms == {"terms": {"host.id": [str(visible[0]), str(visible[1])]}}


@pytest.mark.asyncio
async def test_run_test_short_circuits_when_visible_is_empty(monkeypatch) -> None:
    """Empty visible list means no possible hits. The short-circuit
    matters: OpenSearch rejects a `terms` clause with an empty array.
    Run the helper directly so we don't need a live OS."""
    import app.api.sigma as sigma_mod

    called = {"opensearch": False}

    def _explode(*_args, **_kwargs):
        called["opensearch"] = True
        raise AssertionError("must not hit OpenSearch when visible_ids is empty")

    monkeypatch.setattr(sigma_mod.os_svc, "_client", _explode)

    sigma_yaml = (
        "title: t\nlogsource:\n  product: linux\ndetection:\n  s:\n"
        "    event.category: process\n  condition: s\n"
    )
    resp = await sigma_mod._run_test(sigma_yaml, 1, visible_ids=[])
    assert resp.total == 0
    assert resp.samples == []
    assert called["opensearch"] is False


@pytest.mark.asyncio
async def test_sigma_test_endpoint_short_circuits_for_zero_scope_analyst(
    http_client, analyst_user, analyst_headers, monkeypatch
) -> None:
    """End-to-end shape: an analyst with no host-group membership
    should get an empty result from /api/sigma/test without the
    handler reaching OpenSearch."""
    import app.api.sigma as sigma_mod

    def _explode(*_args, **_kwargs):
        raise AssertionError("must not hit OpenSearch for a zero-scope analyst")

    monkeypatch.setattr(sigma_mod.os_svc, "_client", _explode)

    sigma_yaml = (
        "title: t\nlogsource:\n  product: linux\ndetection:\n  s:\n"
        "    event.category: process\n  condition: s\n"
    )
    resp = await http_client.post(
        "/api/sigma/test",
        json={"body": sigma_yaml, "lookback_hours": 1},
        headers=analyst_headers,
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 0
    assert body["samples"] == []
