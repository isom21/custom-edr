//! eBPF loader (M6).
//!
//! Loads the kernel-side programs from `agent-linux/ebpf/edr.bpf.o`,
//! attaches them to the right hooks, and exposes the user-mode handles
//! main.rs needs (ring-buffer reader, stats map). Falls back gracefully
//! when CAP_BPF / kernel features are absent — main.rs uses
//! [`proc_watcher`] in that case.
//!
//! M6.1 scope: load the program, attach the `sched_process_exec`
//! tracepoint, and surface the stats map. No event delivery yet (the ring
//! buffer is plumbed but no programs write to it). M6.2+ adds payloads.
#![cfg(target_os = "linux")]

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array, MapData};
use aya::programs::TracePoint;
use aya::Ebpf;

const EBPF_OBJECT: &[u8] = include_bytes!("../ebpf/edr.bpf.o");

/// Stat indices — must match `enum edr_stat` in `ebpf/edr.bpf.c`.
#[repr(u32)]
#[derive(Copy, Clone, Debug)]
pub enum Stat {
    ProcessExec = 0,
    ProcessExit = 1,
    FileOpen = 2,
    NetworkConnect = 3,
    ModuleLoad = 4,
    ProcessBlockHits = 5,
    FileBlockHits = 6,
    NetworkBlockHits = 7,
    KillRequests = 8,
}

/// Owns the loaded eBPF object. Drop unloads everything.
pub struct Loader {
    ebpf: Ebpf,
}

impl Loader {
    /// Load the bundled object and attach the M6.1 tracepoint.
    pub fn load_and_attach() -> Result<Self> {
        let mut ebpf = Ebpf::load(EBPF_OBJECT).context("aya::Ebpf::load(edr.bpf.o)")?;

        // sched_process_exec. Tracepoint category/name must match the SEC()
        // header in the C source.
        let prog: &mut TracePoint = ebpf
            .program_mut("handle_sched_exec")
            .ok_or_else(|| anyhow!("program handle_sched_exec missing from object"))?
            .try_into()?;
        prog.load().context("load sched_exec")?;
        prog.attach("sched", "sched_process_exec")
            .context("attach sched/sched_process_exec")?;

        tracing::info!("ebpf.loaded program=handle_sched_exec");
        Ok(Self { ebpf })
    }

    /// Read all stat counters into an array. Indices match [`Stat`].
    pub fn read_stats(&mut self) -> Result<[u64; 9]> {
        let map = self
            .ebpf
            .map_mut("stats")
            .ok_or_else(|| anyhow!("stats map missing"))?;
        let array: Array<&mut MapData, u64> = Array::try_from(map)?;
        let mut out = [0u64; 9];
        for i in 0..9u32 {
            out[i as usize] = array.get(&i, 0).unwrap_or(0);
        }
        Ok(out)
    }
}

/// Best-effort one-line summary of all stat counters.
pub fn format_stats(stats: &[u64; 9]) -> String {
    format!(
        "exec={} exit={} file_open={} net_connect={} module_load={} \
         block_hits=p:{}/f:{}/n:{} kill_requests={}",
        stats[Stat::ProcessExec as usize],
        stats[Stat::ProcessExit as usize],
        stats[Stat::FileOpen as usize],
        stats[Stat::NetworkConnect as usize],
        stats[Stat::ModuleLoad as usize],
        stats[Stat::ProcessBlockHits as usize],
        stats[Stat::FileBlockHits as usize],
        stats[Stat::NetworkBlockHits as usize],
        stats[Stat::KillRequests as usize],
    )
}
