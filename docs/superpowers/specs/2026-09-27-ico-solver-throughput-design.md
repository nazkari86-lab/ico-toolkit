# ICO Solver Throughput and Adapter Coverage Design

## Goal

Make the local `ico-solve` workflow finish useful evidence sooner by running
independent analyzers concurrently, reusing exact results, routing optional
tools by signals, and returning bounded derived artifacts to the static
registry. The output remains a local candidate/evidence report; it never
contacts the ICO platform or guesses a flag value.

## Runtime design

`run_adapter_profiles` creates deterministic jobs from `(input SHA-256,
classification, profile, task-context hash)`. Jobs run in three batches:
`fast`, `specialized`, and `deep`. Each batch uses a bounded thread pool and
collects evidence in stable path/profile order. A per-command timeout is
clipped by the optional global deadline. Pending jobs are cancelled after the
deadline and running subprocesses are killed through the existing process-group
boundary. `CommandRunner` log allocation is synchronized so concurrent jobs
cannot overwrite evidence.

The scanner's independent external profiles use the same bounded worker model.
Task-aware solvers and built-in decoders still run before generic profiles. A
file whose task-aware candidate is already `hash-verified` or
`checker-verified` is excluded from redundant generic adapter work.

## Cache and provenance

Adapter command results use a JSON cache key containing schema version, input
SHA-256, task-context hash, analyzer name, stage, executable path/size/mtime,
normalized arguments, and parser schema. Writes are atomic. Commands that
produce directory trees are rerun unless their tree can be safely recreated;
their text outputs are returned as bounded derived paths. Identical extracted
bytes therefore share cache entries while every source path remains in report
provenance.

## Adapter routing

The inventory remains descriptive, but safe specialists are now signal-gated:
hashID for hash-like lines, Ciphey for bounded encoded/classical-cipher text,
XORtool for explicit XOR/cipher hints, RsaCtfTool for RSA material,
bulk_extractor for disk images, one_gadget for local libc, seccomp-tools for
textual seccomp dumps, and LIEF for read-only ELF/PE/Mach-O structure. Qiling,
Unicorn execution, Frida, Objection, tracers, password crackers, and network
scanners remain manual/local-replica paths because they execute code, change
state, or require a target.

## Structured evidence and derived queue

JSON-shaped output is parsed in addition to raw text, with analyzer/source
annotations preserved. Text files emitted by carving, APK/PDF decompilation,
and other bounded collectors are content-hash deduplicated and sent through
the existing universal registry once. Candidates receive the originating task
slot explicitly when the derived path lives under a temporary report tree.

## Controls and acceptance

`ico-solve` exposes `--workers`, `--deadline`, and `--cache`; the benchmark
script reports elapsed time, adapter count, cache hits, selected candidates,
and derived solver results. The default remains file-only. Acceptance requires
the existing suite, deterministic output, the ten hash-verified
`ico_ctf_real` tasks, and no changes to the evidence-state rules.
