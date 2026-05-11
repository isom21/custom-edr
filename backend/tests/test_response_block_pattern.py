"""`_pick_block_pattern` — prefer full path, fall back to basename.

Reviewer's HIGH finding (`services/response.py:34-49` + the BPF block
map keys in `agent-linux/ebpf/vigil.bpf.c:568-583`): the manager
auto-block path always shipped a basename, but the kernel block map
is keyed by the resolved full path. The kill-by-pid limb worked; the
preventive block silently never tripped because lookups missed.

These tests pin the new ordering: prefer `process.executable` /
`file.path`, fall back to `process.name` / `file.name` only when no
path is present.
"""

from __future__ import annotations

import pytest

from app.models import CommandKind
from app.services.response import _pick_block_pattern


def test_prefers_process_executable_over_name() -> None:
    picked = _pick_block_pattern(
        {
            "process": {
                "name": "evil.exe",
                "executable": "/usr/local/bin/evil.exe",
                "pid": 1234,
            }
        }
    )
    assert picked == (CommandKind.BLOCK_PROCESS, "/usr/local/bin/evil.exe")


def test_falls_back_to_process_name_when_no_executable() -> None:
    """ECS event from a stack that lost the path. Better to ship a
    basename than nothing — kill-by-pid still fires upstream."""
    picked = _pick_block_pattern({"process": {"name": "evil.exe", "pid": 1234}})
    assert picked == (CommandKind.BLOCK_PROCESS, "evil.exe")


def test_falls_back_to_basename_when_executable_path_empty() -> None:
    picked = _pick_block_pattern({"process": {"name": "evil.exe", "executable": "", "pid": 1234}})
    assert picked == (CommandKind.BLOCK_PROCESS, "evil.exe")


def test_prefers_file_path_over_name() -> None:
    picked = _pick_block_pattern(
        {
            "file": {
                "name": "evil.dll",
                "path": "C:\\Windows\\System32\\evil.dll",
            }
        }
    )
    assert picked == (CommandKind.BLOCK_FILE, "C:\\Windows\\System32\\evil.dll")


def test_falls_back_to_file_name_when_no_path() -> None:
    picked = _pick_block_pattern({"file": {"name": "evil.dll"}})
    assert picked == (CommandKind.BLOCK_FILE, "evil.dll")


def test_process_takes_priority_over_file_when_both_present() -> None:
    """Event with both process + file (e.g. a file_open with full
    process context): block the executing process, not the read file."""
    picked = _pick_block_pattern(
        {
            "process": {"executable": "/bin/evil"},
            "file": {"path": "/etc/passwd"},
        }
    )
    assert picked == (CommandKind.BLOCK_PROCESS, "/bin/evil")


def test_returns_none_when_no_block_target() -> None:
    assert _pick_block_pattern({"process": {"pid": 1234}}) is None
    assert _pick_block_pattern({}) is None
    assert _pick_block_pattern({"network": {"dst_ip": "1.2.3.4"}}) is None


@pytest.mark.parametrize(
    "raw_path,expected",
    [
        ("/usr/local/bin/evil", "/usr/local/bin/evil"),
        ("/tmp/x", "/tmp/x"),
        ("C:\\Windows\\System32\\evil.exe", "C:\\Windows\\System32\\evil.exe"),
        ("/path with spaces/evil", "/path with spaces/evil"),
    ],
)
def test_preserves_full_path_verbatim(raw_path: str, expected: str) -> None:
    """No truncation, no normalization — the kernel maps key on the
    exact bytes the resolver hands them. Anything else misses."""
    picked = _pick_block_pattern({"process": {"executable": raw_path}})
    assert picked == (CommandKind.BLOCK_PROCESS, expected)
