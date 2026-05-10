#!/usr/bin/env bash
# Mutation testing harness for the BPF LSM hooks (M8.5).
#
# Mutates `agent-linux/ebpf/edr.bpf.c` in well-defined ways, rebuilds,
# deploys to lab-linux, runs the M7.1 smoke test, and reports whether
# each mutation was caught (smoke FAILS) or escaped (smoke PASSES).
#
# A "good" suite has 100% killed mutants for the hooks we care about.
# Today's mutation set covers the four high-value hooks: task_kill,
# ptrace_access_check, bpf, inode_unlink.

set -uo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
LAB="${EDR_LAB_LINUX:-lab-linux}"
BPF_C="$REPO/agent-linux/ebpf/edr.bpf.c"
ORIG_BACKUP="/tmp/edr.bpf.c.orig"
RESULTS_DIR="$REPO/target/mutation"
RESULTS_CSV="$RESULTS_DIR/results.csv"

mkdir -p "$RESULTS_DIR"
echo "mutant,description,smoke_status,killed" > "$RESULTS_CSV"

# Each mutation is applied as a sed substitution against the source.
# The key principle: each mutation must change a single behaviour the
# smoke test exercises. If the smoke still passes, the smoke is
# undertesting that behaviour and we should add a test.
#
# Format: name|description|sed_expression
#
# `sed_expression` is plain `s/old/new/` against the C source. Avoid
# special chars; use `|` as the sed delimiter so paths in matches are
# fine.
MUTATIONS=(
"task_kill_drop_init_carveout|Allow only self (drop pid 1 carve-out): systemctl stop now blocked|s|caller == self || caller == 1|caller == self|"
"task_kill_invert_self_check|Block self-signals too (invert): agent can't signal itself|s|if (caller == self || caller == 1)|if (!(caller == self || caller == 1))|"
"ptrace_skip_check|Make ptrace hook a no-op: gdb attach succeeds|s|if (target_tgid != self)|if (target_tgid == self)|"
"bpf_disable_detach_block|Drop the bpf detach block: bpftool can detach our links|s|if (cmd == BPF_PROG_DETACH || cmd == BPF_LINK_DETACH) {|if (0) {|"
"unlink_skip_check|inode_unlink no-op: rm under /sys/fs/bpf/edr succeeds|s|if (is_protected_dir_inode(dir)) {|if (0) {|"
)

cleanup() {
    if [ -f "$ORIG_BACKUP" ]; then
        cp "$ORIG_BACKUP" "$BPF_C"
        rm -f "$ORIG_BACKUP"
        echo "[mutation] restored original $BPF_C" >&2
    fi
}
trap cleanup EXIT

cp "$BPF_C" "$ORIG_BACKUP"

for entry in "${MUTATIONS[@]}"; do
    IFS='|' read -r name desc sed_expr <<< "$entry"
    echo
    echo "=== mutation: $name ==="
    echo "    $desc"
    cp "$ORIG_BACKUP" "$BPF_C"
    if ! sed -i "$sed_expr" "$BPF_C"; then
        echo "[mutation] sed failed for $name; skipping"
        echo "$name,$desc,sed-failed,no" >> "$RESULTS_CSV"
        continue
    fi
    if cmp -s "$ORIG_BACKUP" "$BPF_C"; then
        echo "[mutation] sed produced no change for $name; check the pattern"
        echo "$name,$desc,sed-noop,no" >> "$RESULTS_CSV"
        continue
    fi
    echo "[mutation] rebuilding agent..."
    if ! cargo build -p agent-linux --release 2>&1 | tail -3; then
        echo "[mutation] build failed (this is itself a kill — mutation broke compilation)"
        echo "$name,$desc,build-failed,YES" >> "$RESULTS_CSV"
        continue
    fi
    echo "[mutation] deploying to $LAB..."
    if ! scp -q "$REPO/target/release/edr-agent" "$LAB:/tmp/edr-agent.mut"; then
        echo "[mutation] scp failed; aborting"
        echo "$name,$desc,scp-failed,no" >> "$RESULTS_CSV"
        continue
    fi
    ssh "$LAB" 'sudo systemctl stop edr-agent; sudo install -m 0755 /tmp/edr-agent.mut /usr/bin/edr-agent; sudo systemctl reset-failed edr-agent; sudo systemctl start edr-agent; sleep 4'
    echo "[mutation] running smoke..."
    if ssh "$LAB" "EDR_STATE_DIR=/var/lib/edr-state bash /tmp/45-self-protection-linux.sh" > /tmp/mut-smoke.log 2>&1; then
        echo "[mutation] $name ESCAPED — smoke still passed despite mutation"
        echo "$name,$desc,smoke-passed,no" >> "$RESULTS_CSV"
    else
        echo "[mutation] $name KILLED — smoke caught it"
        echo "$name,$desc,smoke-failed,YES" >> "$RESULTS_CSV"
    fi
done

# Restore original + rebuild + redeploy so we leave the lab in good shape.
cp "$ORIG_BACKUP" "$BPF_C"
cargo build -p agent-linux --release > /dev/null 2>&1
scp -q "$REPO/target/release/edr-agent" "$LAB:/tmp/edr-agent.orig"
ssh "$LAB" 'sudo systemctl stop edr-agent; sudo install -m 0755 /tmp/edr-agent.orig /usr/bin/edr-agent; sudo systemctl reset-failed edr-agent; sudo systemctl start edr-agent'

echo
echo "=== mutation results ==="
cat "$RESULTS_CSV"
echo

KILLED=$(grep -c ',YES$' "$RESULTS_CSV" || true)
TOTAL=$(($(wc -l < "$RESULTS_CSV") - 1))
echo "killed $KILLED / $TOTAL"
if [ "$KILLED" -ne "$TOTAL" ]; then
    echo "FAIL: $((TOTAL - KILLED)) mutation(s) escaped — strengthen smoke or remove the mutation."
    exit 1
fi
echo "PASS: all mutations caught."
