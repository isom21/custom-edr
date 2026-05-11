# vigil-mcp

A small [Model Context Protocol](https://modelcontextprotocol.io/) server that
lets an analyst or operator drive the Vigil manager from an MCP-aware client
(Claude Code, Claude Desktop, Cline, etc.). The MCP fronts the REST API the
web UI already uses, so anything the UI can read or do, the assistant can do
too.

## Capabilities

**Reads (always on):**
`list_alerts`, `get_alert`, `get_alert_context`, `get_alert_process_detail`,
`list_hosts`, `get_host`, `host_live_telemetry`, `list_rules`, `get_rule`,
`list_rule_groups`, `list_quarantined_files`, `list_commands`,
`get_alert_stats`, `get_host_stats`, `get_rule_stats`, `whoami`.

**Mutations (`VIGIL_MCP_ALLOW_MUTATIONS=1` required):**
`change_alert_state`, `release_quarantine`, `issue_host_command`,
`set_rule_enabled`, `assign_rule_to_group`.

Mutations are off by default so an analyst can connect Claude to the manager
without risking an accidental `kill_process` or "Move to false positive" via a
prompt-injected log line.

## Install

```bash
cd tools/vigil-mcp
pip install -e .
```

That registers a `vigil-mcp` console script and a `python -m vigil_mcp` entry
point. The package depends on `mcp`, `httpx`, `pydantic`.

## Auth

Two modes, in order of preference:

| Mode | Env vars | How |
|---|---|---|
| API token | `VIGIL_API_TOKEN` | Mint via `POST /api/tokens` (admin or analyst) or the UI's Settings → API tokens screen. Format: `edr_<uuid>_<secret>`. |
| User login | `VIGIL_EMAIL`, `VIGIL_PASSWORD` | Logs in once, refreshes JWTs lazily on 401. |

Common knobs:

- `VIGIL_BASE_URL` — defaults to `http://localhost:8000`. Point this at the
  manager you want to drive (Tailscale URL works fine for remote use).
- `VIGIL_MCP_ALLOW_MUTATIONS=1` — registers the mutation tools.

## Claude Code / Claude Desktop config

Drop this into `~/.claude.json` (Claude Code) or
`~/Library/Application Support/Claude/claude_desktop_config.json`
(Claude Desktop):

```json
{
  "mcpServers": {
    "vigil": {
      "command": "python",
      "args": ["-m", "vigil_mcp"],
      "env": {
        "VIGIL_BASE_URL": "http://localhost:8000",
        "VIGIL_API_TOKEN": "edr_xxxxxxxx_yyyyyyyy",
        "VIGIL_MCP_ALLOW_MUTATIONS": ""
      }
    }
  }
}
```

Set `VIGIL_MCP_ALLOW_MUTATIONS` to `"1"` for a "responder" profile, leave it
empty for a "read-only investigator" profile.

## Example prompts once connected

- *"Show me every high-sev open alert on lab-windows in the last 24 hours."*
- *"For alert `<id>`, walk the process chain and tell me what the triggering
  pid did."*
- *"Tail telemetry on lab-linux for one minute and flag anything touching
  /etc/passwd."*
- *"List quarantined files on lab-linux that came from the Mimikatz rule."*
- *(With mutations on)* *"Move alert `<id>` to false_positive with comment
  'curated trip from operator script'."*

## Notes

- The server uses stdio transport — no listening port. The client process
  spawns the Python interpreter, exchanges JSON-RPC on its stdin/stdout, and
  shuts it down on exit.
- Role-based scoping happens server-side in Vigil. An analyst-scoped API
  token will only see hosts in their host groups; the MCP doesn't re-implement
  RBAC.
- Audit log entries from mutation tools are attributed to the API token (or
  user) the MCP authenticated as — same as the UI.
