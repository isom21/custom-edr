//! M12.c: Linux capability drop after init.
//!
//! The agent runs as root because BPF program loading, LSM hook
//! attachment, kernel ringbuffer reads, and kill-signal delivery to
//! other-uid processes all require capabilities that aren't on a
//! normal user. But "needs to be root at init" doesn't mean "needs
//! every capability for the whole runtime" — once BPF is loaded and
//! the LSM hooks are attached, the agent's residual capability needs
//! shrink to:
//!
//! * **CAP_BPF** — runtime updates to block-list maps, reading the
//!   stats map.
//! * **CAP_PERFMON** — required alongside CAP_BPF to keep tracepoint
//!   programs running on kernels that gate ringbuf access on it.
//! * **CAP_NET_ADMIN** — required for some BPF map operations on
//!   pinned objects (modern kernels split this out of CAP_SYS_ADMIN).
//! * **CAP_SYS_ADMIN** — fallback for older kernels and BTF reading;
//!   we intentionally keep it because dropping it on a 5.10 kernel
//!   breaks BPF map updates. Modern split is best-effort future work.
//! * **CAP_KILL** — required for `signal(SIGKILL, target)` against
//!   other-uid processes when a kill response action runs.
//! * **CAP_DAC_READ_SEARCH** — needed to read `/proc/<pid>/exe` and
//!   similar across owners during process attribution.
//! * **CAP_SYS_PTRACE** — needed for additional `/proc` introspection
//!   on other-uid processes (older kernels gate some `/proc/<pid>/`
//!   reads on this).
//!
//! Everything else gets dropped from both the effective and the
//! permitted set. Important: the **bounding** set is also tightened
//! so even a child process the agent forks (none in normal operation,
//! but defensive) can't regain dropped capabilities via setuid-root.
//!
//! Disable with `EDR_DISABLE_CAPDROP=1` for debug runs where you
//! need full root powers (e.g. running strace against the agent).

#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use caps::{CapSet, Capability, CapsHashSet};

/// Capabilities we keep after init. Order doesn't matter — these all
/// land in both the effective and permitted sets, and everything not
/// in this list gets dropped from those plus the bounding set.
const KEEP: &[Capability] = &[
    Capability::CAP_BPF,
    Capability::CAP_PERFMON,
    Capability::CAP_NET_ADMIN,
    // Kept as a fallback for older-kernel BPF map ops + BTF reading.
    // Modern kernels (>=5.8) honour CAP_BPF/CAP_PERFMON; we don't
    // gate dropping CAP_SYS_ADMIN on kernel version because the
    // failure mode (a map update silently EPERM'ing) is much harder
    // to diagnose than the security cost of keeping it.
    Capability::CAP_SYS_ADMIN,
    Capability::CAP_KILL,
    Capability::CAP_DAC_READ_SEARCH,
    Capability::CAP_SYS_PTRACE,
];

/// Drop all capabilities not in [`KEEP`] from the bounding,
/// effective, and permitted sets. Inheritable is left alone (it's
/// already empty by default and we never exec a child).
pub fn drop_to_minimum() -> Result<DropReport> {
    let keep: CapsHashSet = KEEP.iter().copied().collect();
    let mut report = DropReport::default();

    // 1. Bounding set — drop one cap at a time. capset(2) doesn't
    //    accept a wholesale "set the bounding set to X" operation;
    //    you can only DROP from the bounding set, never add.
    let bounding_before = caps::read(None, CapSet::Bounding)
        .context("read bounding caps")?;
    for cap in bounding_before.iter() {
        if keep.contains(cap) {
            continue;
        }
        match caps::drop(None, CapSet::Bounding, *cap) {
            Ok(()) => report.bounding_dropped.push(*cap),
            Err(e) => {
                tracing::warn!(
                    cap = ?cap,
                    error = %e,
                    "capdrop.bounding.drop_failed"
                );
            }
        }
    }

    // 2. Effective + Permitted: replace wholesale with the keep set
    //    intersected with what we actually have. We can't add caps
    //    we never had; trying would EPERM.
    let permitted_before = caps::read(None, CapSet::Permitted)
        .context("read permitted caps")?;
    let target: CapsHashSet = keep.intersection(&permitted_before).copied().collect();
    caps::set(None, CapSet::Effective, &target).context("set effective caps")?;
    caps::set(None, CapSet::Permitted, &target).context("set permitted caps")?;
    report.effective_kept = target.iter().copied().collect();

    // 3. Inheritable — leave empty. Anything we exec inherits no
    //    privileges (we don't exec, but defensive).
    let empty: CapsHashSet = CapsHashSet::new();
    let _ = caps::set(None, CapSet::Inheritable, &empty);

    // 4. Set NoNewPrivs so a setuid-root binary the agent might exec
    //    (today: nothing) couldn't regain caps. Belt-and-braces.
    //    SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is a
    //    one-shot bit-set with documented arguments.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64) };
    if r != 0 {
        tracing::warn!(
            errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            "capdrop.no_new_privs.failed"
        );
    } else {
        report.no_new_privs = true;
    }

    Ok(report)
}

#[derive(Debug, Default)]
pub struct DropReport {
    pub bounding_dropped: Vec<Capability>,
    pub effective_kept: Vec<Capability>,
    pub no_new_privs: bool,
}
