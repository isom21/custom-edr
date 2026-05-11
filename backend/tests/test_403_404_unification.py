"""M-audit-and-auth #7: out-of-scope detail endpoints return 404 not 403.

Reviewer's MEDIUM #7: all alert + host detail endpoints looked the
resource up, then checked `host_visible_to`, returning 403 when the
resource existed but wasn't in the actor's groups. That let a
low-priv account distinguish "this UUID is real" from "this UUID
isn't" — useful for bug-bounty fishing in shared cross-team UUIDs
that show up in chat or ticket links.

The fix returns 404 for both. We pin the behaviour by direct unit
tests on the call sites (which all share the same pattern) rather
than a heavy ASGI smoke that depends on host-group seeding.
"""

from __future__ import annotations

import inspect


def test_alerts_detail_routes_use_not_found_for_out_of_scope() -> None:
    """Every endpoint in alerts.py that checks host_visible_to must
    raise `not_found` (not `forbidden`) when the check fails."""
    import app.api.alerts as alerts

    src = inspect.getsource(alerts)
    # Every visibility check should be paired with a not_found raise.
    # If a future refactor goes back to `forbidden(...)` after the
    # host_visible_to gate, this test catches it before deploy.
    visibility_lines = [
        i for i, line in enumerate(src.splitlines()) if "host_visible_to(actor" in line
    ]
    assert visibility_lines, "expected at least one host_visible_to call in alerts.py"
    for ln in visibility_lines:
        # The check appears as `if not await host_visible_to(...):` —
        # find the next non-comment line that raises and confirm it's
        # not_found, not forbidden.
        for j in range(ln + 1, min(ln + 8, len(src.splitlines()))):
            raise_line = src.splitlines()[j].strip()
            if raise_line.startswith("raise "):
                assert "not_found" in raise_line, (
                    f"alerts.py:{j + 1}: visibility check followed by "
                    f"{raise_line!r}; should be not_found(...) to avoid "
                    "leaking existence (MEDIUM #7)"
                )
                break


def test_hosts_detail_routes_use_not_found_for_out_of_scope() -> None:
    import app.api.hosts as hosts

    src = inspect.getsource(hosts)
    visibility_lines = [
        i for i, line in enumerate(src.splitlines()) if "host_visible_to(actor" in line
    ]
    assert visibility_lines, "expected at least one host_visible_to call in hosts.py"
    for ln in visibility_lines:
        for j in range(ln + 1, min(ln + 8, len(src.splitlines()))):
            raise_line = src.splitlines()[j].strip()
            if raise_line.startswith("raise "):
                assert "not_found" in raise_line, (
                    f"hosts.py:{j + 1}: visibility check followed by {raise_line!r}"
                )
                break


def test_commands_detail_routes_use_not_found_for_out_of_scope() -> None:
    import app.api.commands as commands

    src = inspect.getsource(commands)
    visibility_lines = [
        i for i, line in enumerate(src.splitlines()) if "host_visible_to(actor" in line
    ]
    assert visibility_lines, "expected at least one host_visible_to call in commands.py"
    for ln in visibility_lines:
        for j in range(ln + 1, min(ln + 8, len(src.splitlines()))):
            raise_line = src.splitlines()[j].strip()
            if raise_line.startswith("raise "):
                assert "not_found" in raise_line, (
                    f"commands.py:{j + 1}: visibility check followed by {raise_line!r}"
                )
                break
