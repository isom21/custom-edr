"""Vigil MCP server — exposes the manager REST API as MCP tools.

Tools are grouped into three buckets:

  * Reads (always enabled): list/get for alerts, hosts, rules, groups,
    quarantined files, commands; alert context + per-pid detail; live
    host telemetry tail.
  * Mutations (off by default): change alert state, release quarantine,
    issue host commands (kill/block/quarantine/etc), bulk
    enable/disable rules. Set `VIGIL_MCP_ALLOW_MUTATIONS=1` to enable.
  * Stats (always enabled): the manager's chart aggregations.

Auth is delegated to `VigilClient.from_env()`. Run with:

  VIGIL_BASE_URL=http://localhost:8000 \
  VIGIL_API_TOKEN=edr_...  \
    python -m vigil_mcp

The stdio transport is used by default so the server slots straight
into Claude Code / Claude Desktop config blocks.
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import VigilApiError, VigilClient


_ALLOW_MUTATIONS = os.environ.get("VIGIL_MCP_ALLOW_MUTATIONS", "").lower() in {
    "1",
    "true",
    "yes",
}

_client: VigilClient | None = None


def _get() -> VigilClient:
    global _client
    if _client is None:
        _client = VigilClient.from_env()
    return _client


mcp = FastMCP(
    name="vigil",
    instructions=(
        "Vigil EDR manager. Tools cover alerts, hosts, rules, quarantine, and "
        "live telemetry. Read tools are always available; mutation tools are "
        "only registered when the operator opts in via VIGIL_MCP_ALLOW_MUTATIONS=1."
    ),
)


def _drop_none(d: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in d.items() if v is not None}


# =========================================================================
# Reads
# =========================================================================


@mcp.tool()
async def list_alerts(
    state: str | None = None,
    severity: str | None = None,
    host_hostname: str | None = None,
    rule_name: str | None = None,
    q: str | None = None,
    sort: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List alerts with optional filters.

    Args:
      state: alert state (new, investigating, false_positive, true_positive).
      severity: info/low/medium/high/critical.
      host_hostname: exact host name match.
      rule_name: exact rule name match.
      q: free-text search over alert summary.
      sort: "<field>:<asc|desc>" (e.g. "opened_at:desc").
      limit / offset: pagination.
    """
    params = _drop_none(
        dict(
            state=state,
            severity=severity,
            host_hostname=host_hostname,
            rule_name=rule_name,
            q=q,
            sort=sort,
            limit=limit,
            offset=offset,
        )
    )
    return await _get().request("GET", "/api/alerts", params=params)


@mcp.tool()
async def get_alert(alert_id: str) -> dict[str, Any]:
    """Fetch one alert by id, including its triage state history."""
    return await _get().request("GET", f"/api/alerts/{alert_id}")


@mcp.tool()
async def get_alert_context(alert_id: str, window_minutes: int = 15) -> dict[str, Any]:
    """Investigation context for an alert: process ancestry chain + telemetry events in a window around `opened_at`."""
    return await _get().request(
        "GET",
        f"/api/alerts/{alert_id}/context",
        params={"window_minutes": window_minutes},
    )


@mcp.tool()
async def get_alert_process_detail(
    alert_id: str, pid: int, window_minutes: int = 15
) -> dict[str, Any]:
    """What a specific pid did during the alert window — image loads, file ops, network."""
    return await _get().request(
        "GET",
        f"/api/alerts/{alert_id}/process/{pid}",
        params={"window_minutes": window_minutes},
    )


@mcp.tool()
async def list_hosts(
    status_: str | None = None,
    os_family: str | None = None,
    q: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List enrolled hosts, optionally filtered by status / OS family / hostname substring."""
    params = _drop_none(
        dict(status_=status_, os_family=os_family, q=q, limit=limit, offset=offset)
    )
    return await _get().request("GET", "/api/hosts", params=params)


@mcp.tool()
async def get_host(host_id: str) -> dict[str, Any]:
    """Fetch one host by id."""
    return await _get().request("GET", f"/api/hosts/{host_id}")


@mcp.tool()
async def host_live_telemetry(
    host_id: str, since: str | None = None, limit: int = 200
) -> dict[str, Any]:
    """Tail telemetry for a host. `since` is an ISO timestamp; pass back `latest_timestamp` on next call to walk forward."""
    params = _drop_none(dict(since=since, limit=limit))
    return await _get().request("GET", f"/api/hosts/{host_id}/telemetry", params=params)


@mcp.tool()
async def list_rules(
    kind: str | None = None,
    enabled: bool | None = None,
    group_id: str | None = None,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    """List detection rules. kind=yara|sigma|ioc; group_id may be a UUID or the literal 'null' to get ungrouped rules."""
    params = _drop_none(
        dict(
            kind=kind,
            enabled=enabled,
            group_id=group_id,
            q=q,
            limit=limit,
            offset=offset,
        )
    )
    return await _get().request("GET", "/api/rules", params=params)


@mcp.tool()
async def get_rule(rule_id: str) -> dict[str, Any]:
    """Fetch one rule by id (body + IOC entries)."""
    return await _get().request("GET", f"/api/rules/{rule_id}")


@mcp.tool()
async def list_rule_groups(kind: str | None = None, limit: int = 100) -> dict[str, Any]:
    """List rule groups. Each group carries a `max_action` ceiling that clamps every contained rule."""
    return await _get().request(
        "GET", "/api/rule-groups", params=_drop_none(dict(kind=kind, limit=limit))
    )


@mcp.tool()
async def list_quarantined_files(
    host_id: str, status_: str | None = None, limit: int = 50, offset: int = 0
) -> dict[str, Any]:
    """List files currently/previously quarantined on a host. status_=active|released|deleted."""
    params = _drop_none(dict(status_=status_, limit=limit, offset=offset))
    return await _get().request(
        "GET", f"/api/hosts/{host_id}/quarantined", params=params
    )


@mcp.tool()
async def list_commands(
    status_: str | None = None,
    kind: str | None = None,
    host_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List response-action commands across visible hosts."""
    params = _drop_none(
        dict(status_=status_, kind=kind, host_id=host_id, limit=limit, offset=offset)
    )
    # Commands has a flat router under /api/commands.
    return await _get().request("GET", "/api/commands", params=params)


@mcp.tool()
async def get_alert_stats(bucket: str) -> list[dict[str, Any]]:
    """Aggregations for the alert console. bucket=severity|state|host|rule|hour."""
    return await _get().request("GET", "/api/alerts/stats", params={"bucket": bucket})


@mcp.tool()
async def get_host_stats(bucket: str) -> list[dict[str, Any]]:
    """Aggregations for the fleet view. bucket=status|os_family|agent_version|last_seen."""
    return await _get().request("GET", "/api/hosts/stats", params={"bucket": bucket})


@mcp.tool()
async def get_rule_stats(bucket: str) -> list[dict[str, Any]]:
    """Aggregations for the rules page. bucket=kind|severity|enabled."""
    return await _get().request("GET", "/api/rules/stats", params={"bucket": bucket})


@mcp.tool()
async def whoami() -> dict[str, Any]:
    """Identity of the authenticated user/token (role, email, scopes)."""
    return await _get().request("GET", "/api/me")


# =========================================================================
# Mutations (gated)
# =========================================================================


def _register_mutations() -> None:
    """Add destructive tools only when explicitly enabled.

    Defined inside a function so the @mcp.tool() decorators don't run at
    module import when mutations are disabled — keeps the tool list
    minimal for read-only deployments.
    """

    @mcp.tool()
    async def change_alert_state(
        alert_id: str, to_state: str, comment: str | None = None
    ) -> dict[str, Any]:
        """Move an alert through its state machine. to_state=new|investigating|false_positive|true_positive."""
        body = _drop_none(dict(to_state=to_state, comment=comment))
        return await _get().request("POST", f"/api/alerts/{alert_id}/state", json=body)

    @mcp.tool()
    async def release_quarantine(
        quarantine_id: str, target_path: str | None = None
    ) -> dict[str, Any]:
        """Queue a RELEASE_QUARANTINE command to restore a quarantined file. Defaults to the file's recorded original_path."""
        body = _drop_none(dict(target_path=target_path))
        return await _get().request(
            "POST", f"/api/quarantined/{quarantine_id}/release", json=body
        )

    @mcp.tool()
    async def issue_host_command(
        host_id: str, kind: str, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Queue a response-action against a host.

        kind: kill_process | block_process | block_file | unblock_process |
              unblock_file | isolate | quarantine_file | release_quarantine.
        payload: kind-specific JSON, e.g.:
          - kill_process     -> {"pid": 1234}
          - block_process    -> {"pattern": "/usr/bin/foo"}
          - block_file       -> {"pattern": "/tmp/bad.sh"}
          - quarantine_file  -> {"path": "/tmp/bad.sh", "delete_original": true}
          - release_quarantine -> {"sha256": "...", "target_path": "/tmp/bad.sh"}
          - isolate          -> {"isolate": true, "allowlist_ips": ["..."]}
        """
        body = {"kind": kind, "payload": payload or {}}
        return await _get().request("POST", f"/api/hosts/{host_id}/commands", json=body)

    @mcp.tool()
    async def set_rule_enabled(rule_id: str, enabled: bool) -> dict[str, Any]:
        """Enable or disable a rule without editing its body."""
        return await _get().request(
            "PATCH", f"/api/rules/{rule_id}", json={"enabled": enabled}
        )

    @mcp.tool()
    async def assign_rule_to_group(
        rule_id: str, group_id: str | None
    ) -> dict[str, Any]:
        """Move a rule into a group, or pass null to unassign. The kinds must match."""
        # The backend uses an all-zero UUID as the "unset" sentinel on PATCH.
        body = {"group_id": group_id or "00000000-0000-0000-0000-000000000000"}
        return await _get().request("PATCH", f"/api/rules/{rule_id}", json=body)


if _ALLOW_MUTATIONS:
    _register_mutations()


# =========================================================================
# Entry point
# =========================================================================


def main() -> None:
    # Friendlier error than the SDK's default: surface config issues early.
    try:
        _get()
    except VigilApiError as exc:
        raise SystemExit(f"vigil-mcp: auth failed -> {exc}") from exc
    mcp.run()


if __name__ == "__main__":
    main()
