//! Command worker (M6.6) — Linux response actions.
//!
//! Mirrors `agent-windows/src/driver.rs::run_command_worker`. Receives
//! [`p::Command`] messages from the gRPC client, dispatches them to the
//! right OS primitive, and ships back a [`p::CommandResult`].
//!
//! - Kill: `kill(pid, SIGKILL)` via libc.
//! - BlockProcess / UnblockProcess: insert/remove a path into the
//!   `process_block` BPF hash map. The kernel's `lsm/bprm_check_security`
//!   then returns -EPERM on exec for matching paths.
//! - BlockFile / UnblockFile: same against the `file_block` map; kernel
//!   denies in `lsm/file_open`.
//!
//! Block lists persist to `{state_dir}/blocklist.json` and reload on
//! startup, mirroring the Windows REG_MULTI_SZ persistence.

#![cfg(target_os = "linux")]

use crate::ebpf::BlockListHandle;
use agent_core::proto as p;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::sync::mpsc;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PersistedBlockLists {
    #[serde(default)]
    pub processes: Vec<String>,
    #[serde(default)]
    pub files: Vec<String>,
}

/// Load block lists from `{state_dir}/blocklist.json` (if present), push
/// every entry into the kernel maps, and return the in-memory state for
/// future updates.
pub fn restore(state_dir: &PathBuf, blocks: &BlockListHandle) -> Result<PersistedBlockLists> {
    let path = state_dir.join("blocklist.json");
    let state: PersistedBlockLists = if path.exists() {
        let s = std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?;
        serde_json::from_str(&s).with_context(|| format!("parse {}", path.display()))?
    } else {
        PersistedBlockLists::default()
    };
    for proc in &state.processes {
        if let Err(e) = blocks.block_process(proc) {
            tracing::warn!(path = %proc, error = %e, "blocklist.restore.process_failed");
        }
    }
    for f in &state.files {
        if let Err(e) = blocks.block_file(f) {
            tracing::warn!(path = %f, error = %e, "blocklist.restore.file_failed");
        }
    }
    tracing::info!(
        processes = state.processes.len(),
        files = state.files.len(),
        "blocklist.restored"
    );
    Ok(state)
}

fn persist(state_dir: &PathBuf, state: &PersistedBlockLists) -> Result<()> {
    std::fs::create_dir_all(state_dir)
        .with_context(|| format!("mkdir -p {}", state_dir.display()))?;
    let path = state_dir.join("blocklist.json");
    let tmp = state_dir.join("blocklist.json.tmp");
    let s = serde_json::to_string_pretty(state)?;
    std::fs::write(&tmp, s).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

pub async fn run(
    state_dir: PathBuf,
    blocks: BlockListHandle,
    mut state: PersistedBlockLists,
    mut rx: mpsc::Receiver<p::Command>,
    send_tx: mpsc::Sender<p::ClientMessage>,
) {
    while let Some(cmd) = rx.recv().await {
        let result = dispatch(&cmd, &state_dir, &blocks, &mut state).await;
        let (success, error) = match &result {
            Ok(()) => (true, String::new()),
            Err(e) => (false, format!("{e:#}")),
        };
        if !success {
            tracing::warn!(command_id = %cmd.command_id, error = %error, "command.failed");
        } else {
            tracing::info!(command_id = %cmd.command_id, "command.succeeded");
        }
        let cr = p::CommandResult {
            command_id: cmd.command_id.clone(),
            success,
            error,
            payload: Vec::new(),
        };
        let msg = p::ClientMessage {
            payload: Some(p::client_message::Payload::CommandResult(cr)),
        };
        let _ = send_tx.send(msg).await;
    }
}

async fn dispatch(
    cmd: &p::Command,
    state_dir: &PathBuf,
    blocks: &BlockListHandle,
    state: &mut PersistedBlockLists,
) -> Result<()> {
    use p::command::Body;
    let body = cmd.body.as_ref().ok_or_else(|| anyhow!("command.body missing"))?;
    match body {
        Body::Kill(k) => {
            let pid = k.target.as_ref().map(|t| t.pid).unwrap_or(0);
            if pid == 0 {
                anyhow::bail!("kill.target.pid must be > 0");
            }
            kill_pid(pid)?;
        }
        Body::BlockProcess(b) => {
            let pat = b.pattern.clone();
            blocks.block_process(&pat)?;
            if !state.processes.iter().any(|p| p == &pat) {
                state.processes.push(pat);
                persist(state_dir, state)?;
            }
        }
        Body::BlockFile(b) => {
            let pat = b.pattern.clone();
            blocks.block_file(&pat)?;
            if !state.files.iter().any(|p| p == &pat) {
                state.files.push(pat);
                persist(state_dir, state)?;
            }
        }
        Body::UnblockProcess(b) => {
            let pat = b.pattern.clone();
            // Best-effort: remove from kernel even if not in our
            // persisted list; the user may be cleaning up.
            let _ = blocks.unblock_process(&pat);
            let before = state.processes.len();
            state.processes.retain(|p| p != &pat);
            if state.processes.len() != before {
                persist(state_dir, state)?;
            }
        }
        Body::UnblockFile(b) => {
            let pat = b.pattern.clone();
            let _ = blocks.unblock_file(&pat);
            let before = state.files.len();
            state.files.retain(|p| p != &pat);
            if state.files.len() != before {
                persist(state_dir, state)?;
            }
        }
        Body::ScanFile(_) | Body::ScanMemory(_) | Body::Isolate(_) | Body::Update(_) => {
            anyhow::bail!("command kind not implemented on linux yet");
        }
    }
    Ok(())
}

fn kill_pid(pid: u32) -> Result<()> {
    // libc::kill returns 0 on success, -1 on error with errno set.
    let r = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if r != 0 {
        let err = std::io::Error::last_os_error();
        anyhow::bail!("kill({pid}, SIGKILL): {err}");
    }
    Ok(())
}
