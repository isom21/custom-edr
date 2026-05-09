// edr.bpf.c — kernel-side eBPF programs for the EDR Linux agent (M6).
//
// This file compiles to a single BTF-relocatable .bpf.o that the user-mode
// agent (agent-linux) loads via aya at startup. Each function below is a
// separate eBPF program attached to a kernel hook (tracepoint, kprobe, or
// LSM). They share one ring buffer (`events`) that user-mode drains.
//
// M6.1 skeleton: one tracepoint on sched_process_exec that increments a
// counter (visible via the EDR_GET_STATS-equivalent — the `stats` map) and
// optionally bpf_printk's. Real event payloads start in M6.2.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Counters indexed by stat kind. Easier than separate maps; user-mode reads
// the whole array.
enum edr_stat {
    EDR_STAT_PROCESS_EXEC = 0,
    EDR_STAT_PROCESS_EXIT,
    EDR_STAT_FILE_OPEN,
    EDR_STAT_NETWORK_CONNECT,
    EDR_STAT_MODULE_LOAD,
    EDR_STAT_PROCESS_BLOCK_HITS,
    EDR_STAT_FILE_BLOCK_HITS,
    EDR_STAT_NETWORK_BLOCK_HITS,
    EDR_STAT_KILL_REQUESTS,
    EDR_STAT_MAX,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, EDR_STAT_MAX);
} stats SEC(".maps");

static __always_inline void stat_inc(enum edr_stat which)
{
    __u32 key = (__u32)which;
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v)
        __sync_fetch_and_add(v, 1);
}

// Event ring buffer for streaming events to user-mode. 1 MB. M6.2+ writes
// real records here; M6.1 leaves it empty.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

// M6.1: minimal sched_process_exec tracepoint that just bumps the counter
// so user-mode can confirm the program is loaded and firing.
SEC("tracepoint/sched/sched_process_exec")
int handle_sched_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    (void)ctx;
    stat_inc(EDR_STAT_PROCESS_EXEC);
    return 0;
}
