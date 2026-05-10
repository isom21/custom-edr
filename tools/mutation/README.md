# Mutation testing harness

Mutation testing for the BPF LSM hooks. Why a custom harness rather
than `cargo-mutants`: the actual logic that matters lives in
`agent-linux/ebpf/edr.bpf.c`, not the Rust loader. The hooks have
two characteristics that make them especially valuable to mutate-test:

1. **Silent failures freeze the host.** The bprm-arity bug from M6.6
   is the canonical example — the hook returned `-EPERM` for every
   exec on the box. Mutations that change a hook's "allow" → "deny"
   path or vice versa must be caught by the smoke tests.
2. **Boundary conditions on the lookup keys** matter (zero-padding,
   inode dev/ino encoding from M7.1). A wrong shift, a wrong mask, or
   an off-by-one all silently let attacks through.

The harness:

1. Reads `agent-linux/ebpf/edr.bpf.c`.
2. For each `MUTANT_TARGET` block (annotated in source via
   `// MUTANT: name=...`), generates a mutated variant by applying a
   pre-defined transformation (e.g. flip `return -1` to `return 0`).
3. Rebuilds the bpf object + agent, deploys to lab-linux.
4. Runs `tools/smoke/45-self-protection-linux.sh`.
5. Reports the mutation as caught (smoke fails) or escaped (smoke
   passes despite the mutation).

This is run on demand, not in CI, because each mutation is a 30-60s
build+deploy cycle.

## Run

```bash
EDR_LAB_LINUX=lab-linux tools/mutation/run.sh
```

Output: a CSV at `target/mutation/results.csv` with columns
`mutant,description,smoke_status,killed`.

## Adding a mutation target

Annotate the source line in `edr.bpf.c`:

```c
// MUTANT: name=task_kill_allow_root, op=replace, from="caller == 1", to="0"
if (caller == self || caller == 1)
    return 0;
```

Then re-run the harness. The framework prints the patch, applies it,
rebuilds, deploys, smokes, and reports.
