"""OpenSearch client wrapper + index helpers.

Indices are date-rolled:
  telemetry-YYYYMMDD  - one ECS document per ingested EndpointEvent
  alerts-YYYYMMDD     - one document per generated alert (mirrors the alerts table)

Plus a single non-date index used by the realtime Sigma engine:
  sigma-rules         - one doc per registered Sigma rule, with the rule's
                        compiled Lucene query stored in a `query` field of
                        type percolator. Telemetry events are percolated
                        against this index for sub-second Sigma matching.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from opensearchpy._async.client import AsyncOpenSearch

from app.core.config import settings


def _client() -> AsyncOpenSearch:
    return AsyncOpenSearch(
        hosts=[settings.opensearch_url],
        verify_certs=False,
        ssl_show_warn=False,
    )


SIGMA_RULES_INDEX = "sigma-rules"
_TEMPLATE_NAME = "edr-telemetry"


# Field shapes that telemetry-* and sigma-rules share. Sigma rules' Lucene
# queries reference these fields; mappings must match for percolator to find
# matches against incoming ECS docs.
_SHARED_PROPERTIES: dict[str, Any] = {
    "@timestamp": {"type": "date"},
    "event": {
        "properties": {
            "id": {"type": "keyword"},
            "kind": {"type": "keyword"},
            "category": {"type": "keyword"},
            "action": {"type": "keyword"},
            "outcome": {"type": "keyword"},
            "created": {"type": "date"},
        }
    },
    "host": {
        "properties": {
            "id": {"type": "keyword"},
            "name": {"type": "keyword"},
        }
    },
    "agent": {
        "properties": {
            "id": {"type": "keyword"},
            "version": {"type": "keyword"},
        }
    },
    "process": {
        "properties": {
            "pid": {"type": "long"},
            "name": {"type": "keyword"},
            "executable": {"type": "keyword"},
            "command_line": {
                "type": "text",
                "fields": {"raw": {"type": "keyword", "ignore_above": 4096}},
            },
            "hash": {
                "properties": {
                    "sha256": {"type": "keyword"},
                    "sha1": {"type": "keyword"},
                    "md5": {"type": "keyword"},
                }
            },
            "parent": {
                "properties": {
                    "pid": {"type": "long"},
                    "executable": {"type": "keyword"},
                }
            },
        }
    },
    "file": {
        "properties": {
            "path": {"type": "keyword"},
            "name": {"type": "keyword"},
            "size": {"type": "long"},
            "hash": {
                "properties": {
                    "sha256": {"type": "keyword"},
                    "sha1": {"type": "keyword"},
                    "md5": {"type": "keyword"},
                }
            },
        }
    },
    "labels": {"type": "object", "dynamic": True},
    "rule": {
        "properties": {
            "id": {"type": "keyword"},
            "name": {"type": "keyword"},
        }
    },
}


_TEMPLATE_BODY: dict[str, Any] = {
    "index_patterns": ["telemetry-*", "alerts-*"],
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "refresh_interval": "5s",
        },
        "mappings": {
            "dynamic_templates": [
                {
                    "strings_as_keyword": {
                        "match_mapping_type": "string",
                        "mapping": {"type": "keyword", "ignore_above": 1024},
                    }
                }
            ],
            "properties": _SHARED_PROPERTIES,
        },
    },
}


# sigma-rules is created explicitly (not from the shared template) because:
# - it needs the percolator-typed `query` field
# - dynamic=strict prevents accidental field drift between rule registrations
# - tighter refresh_interval so a freshly-saved rule starts matching within ~1s
_SIGMA_INDEX_BODY: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "1s",
    },
    "mappings": {
        "dynamic": "strict",
        "properties": {
            **_SHARED_PROPERTIES,
            "query": {"type": "percolator"},
            "rule_id": {"type": "keyword"},
            "rule_name": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "enabled": {"type": "boolean"},
            "registered_at": {"type": "date"},
        },
    },
}


async def ensure_template(client: AsyncOpenSearch) -> None:
    if not await client.indices.exists_index_template(name=_TEMPLATE_NAME):
        await client.indices.put_index_template(name=_TEMPLATE_NAME, body=_TEMPLATE_BODY)


async def ensure_sigma_index(client: AsyncOpenSearch) -> None:
    if not await client.indices.exists(index=SIGMA_RULES_INDEX):
        await client.indices.create(index=SIGMA_RULES_INDEX, body=_SIGMA_INDEX_BODY)


def telemetry_index_for(ts: datetime) -> str:
    return f"telemetry-{ts.astimezone(timezone.utc):%Y%m%d}"


def alerts_index_for(ts: datetime) -> str:
    return f"alerts-{ts.astimezone(timezone.utc):%Y%m%d}"


# ----- Sigma percolator helpers -----


async def register_sigma_rule(
    client: AsyncOpenSearch,
    *,
    rule_id: UUID,
    rule_name: str,
    severity: str,
    lucene_query: str,
) -> None:
    """Index/refresh the percolator doc for a Sigma rule.

    Doc id = rule's PG UUID, so re-registering after an edit overwrites in
    place. We wrap the rule's Lucene string in a query_string query — same
    shape pySigma's OpenSearch backend produces.
    """
    body = {
        "query": {"query_string": {"query": lucene_query}},
        "rule_id": str(rule_id),
        "rule_name": rule_name,
        "severity": severity,
        "enabled": True,
        "registered_at": datetime.now(timezone.utc).isoformat(),
    }
    await client.index(
        index=SIGMA_RULES_INDEX, id=str(rule_id), body=body, refresh="wait_for"
    )


async def unregister_sigma_rule(client: AsyncOpenSearch, rule_id: UUID) -> None:
    """Remove a rule's percolator doc. Idempotent — 404 is swallowed."""
    try:
        await client.delete(
            index=SIGMA_RULES_INDEX, id=str(rule_id), refresh="wait_for"
        )
    except Exception as exc:
        status = getattr(exc, "status_code", None)
        if status not in (404, "404"):
            raise


async def percolate(
    client: AsyncOpenSearch, ecs_doc: dict[str, Any]
) -> list[dict[str, Any]]:
    """Run an ECS event against every registered Sigma rule. Returns the
    matching docs' _source (rule_id, rule_name, severity).
    """
    body = {
        "size": 100,
        "_source": ["rule_id", "rule_name", "severity"],
        "query": {
            "percolate": {
                "field": "query",
                "document": ecs_doc,
            }
        },
    }
    resp = await client.search(index=SIGMA_RULES_INDEX, body=body, request_timeout=10)
    return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]
