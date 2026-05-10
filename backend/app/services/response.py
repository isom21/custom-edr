"""Auto-trigger response actions when a rule with action=kill|block matches.

Called from both the IOC detector and the sigma_realtime worker after they
create an Alert row, before commit. Builds the corresponding Command row
keyed to the host that produced the event so the gRPC dispatcher (M5.3)
can ship it to the agent (M5.4).
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Command, CommandKind, CommandStatus, RuleAction


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    sep = max(path.rfind("/"), path.rfind("\\"))
    return path[sep + 1 :] if sep >= 0 else path


def _pick_block_pattern(ecs: dict[str, Any]) -> tuple[CommandKind, str] | None:
    """Pick a block target from an ECS event. Process events get the
    executable basename; file events get the file basename. Returns the
    kind + pattern, or None if neither is available.
    """
    process = ecs.get("process") or {}
    file_ = ecs.get("file") or {}

    proc_name = process.get("name") or _basename(process.get("executable"))
    if proc_name:
        return CommandKind.BLOCK_PROCESS, proc_name

    file_name = file_.get("name") or _basename(file_.get("path"))
    if file_name:
        return CommandKind.BLOCK_FILE, file_name

    return None


async def queue_command_for_match(
    db: AsyncSession,
    *,
    host_id: UUID,
    rule_id: UUID,
    rule_action: RuleAction,
    alert_id: UUID,
    ecs: dict[str, Any],
) -> Command | None:
    """Translate an alert match into a Command row. Returns None if the
    rule action doesn't require a command (DETECT) or the event lacks the
    fields the action needs (e.g. kill with no pid).
    """
    if rule_action == RuleAction.KILL:
        pid = (ecs.get("process") or {}).get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return None
        cmd = Command(
            host_id=host_id,
            kind=CommandKind.KILL_PROCESS,
            status=CommandStatus.PENDING,
            payload={"pid": int(pid)},
            triggered_by_alert_id=alert_id,
            triggered_by_rule_id=rule_id,
        )
    elif rule_action == RuleAction.BLOCK:
        picked = _pick_block_pattern(ecs)
        if picked is None:
            return None
        kind, pattern = picked
        cmd = Command(
            host_id=host_id,
            kind=kind,
            status=CommandStatus.PENDING,
            payload={"pattern": pattern},
            triggered_by_alert_id=alert_id,
            triggered_by_rule_id=rule_id,
        )
    else:
        return None

    db.add(cmd)
    await db.flush()
    return cmd
