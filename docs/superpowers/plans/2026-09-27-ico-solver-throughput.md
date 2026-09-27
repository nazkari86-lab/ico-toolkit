# ICO Solver Throughput and Adapter Coverage Implementation Plan

> **For agentic workers:** Execute inline in this session with verification checkpoints. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `ico-solve` use relevant installed tools concurrently, reuse results safely, and feed bounded derived artifacts back into the same flag solver without weakening evidence states.

**Architecture:** Add a small execution layer around the existing adapter profiles. It schedules fast, specialized, and deep jobs in deterministic batches with worker and deadline limits; caches command results by content and task context; and normalizes adapter evidence. The existing task-aware registry remains authoritative and all network/emulation paths stay opt-in.

**Tech Stack:** Python 3.14 standard library (`concurrent.futures`, `threading`, `hashlib`, `json`), existing `CommandRunner`, `unittest`, shell launcher.

**Spec:** `docs/superpowers/specs/2026-09-27-ico-solver-throughput-design.md` and `docs/superpowers/specs/2026-09-27-ico-solve-final-design.md`.

## Global Constraints

- Inputs remain read-only; caches and derived artifacts stay under the selected debug/report directory.
- Default execution is offline and never contacts `cyberolympiad.kz`, scans remote ports, submits flags, or brute-forces flag values.
- Every subprocess and derived-artifact pass remains bounded by timeout, file count, byte count, and depth limits.
- `candidate`, `candidate-review`, `payload-ready`, `transcript-derived`, `hash-verified`, and `checker-verified` remain distinct.
- Existing public function signatures remain compatible unless new parameters are optional.
- Results must be deterministic for identical bytes, task context, tool identity, and arguments.

### Task 1: Make command logging safe for concurrent adapters

**Files:**
- Modify: `ico_scan_core.py:115-190`
- Test: `tests/test_ico_scan_core.py`

- [ ] Add a regression test that calls one `CommandRunner` from several threads and asserts every log path is unique and every JSON log is readable.
- [ ] Protect sequence allocation and log writes with a lock while keeping subprocess execution outside the lock.
- [ ] Run `python3 -m unittest tests.test_ico_scan_core -q`.

### Task 2: Add concurrent, staged adapter execution

**Files:**
- Modify: `ico_tool_adapters.py:40-710`
- Test: `tests/test_ico_tool_adapters.py`

- [ ] Add optional `workers`, `deadline_seconds`, and `cache_dir` parameters to `run_adapter_profiles`.
- [ ] Build stable `(path, profile)` jobs, group them by `fast`, `specialized`, and `deep`, and execute each batch with a bounded `ThreadPoolExecutor`.
- [ ] Return results in input/profile order, mark jobs skipped after the deadline, and bound each subprocess timeout by the remaining global deadline.
- [ ] Move profile execution and derived-text/carve collection into a single worker helper so all adapters follow identical evidence handling.
- [ ] Add tests with a sleep-based local executable proving overlapping execution, deterministic ordering, and deadline skips.
- [ ] Run `python3 -m unittest tests.test_ico_tool_adapters -q`.

### Task 3: Cache adapter commands and deduplicate identical bytes

**Files:**
- Modify: `ico_tool_adapters.py`
- Modify: `ico_solve.py:600-660`
- Test: `tests/test_ico_tool_adapters.py`, `tests/test_ico_solve.py`

- [ ] Add a content-addressed cache key containing input SHA-256, task-context hash, adapter name, resolved executable identity, normalized arguments, and parser schema.
- [ ] Rehydrate cached `CommandResult` values without rerunning the executable and record `cache_hit` in `AdapterEvidence`.
- [ ] Deduplicate paths with equal content before classification/profile scheduling while preserving every original path in provenance.
- [ ] Add tests for cache hits, invalidation after byte changes, and duplicate archive members.
- [ ] Run the focused adapter and solve tests.

### Task 4: Normalize structured evidence and rescan bounded derived files

**Files:**
- Modify: `ico_tool_adapters.py`
- Modify: `ico_solve.py`
- Create: `ico_evidence.py`
- Test: `tests/test_ico_evidence.py`, `tests/test_ico_solve.py`

- [ ] Define a JSON-safe evidence record with analyzer, artifact, parent, transform chain, state, triage, and candidate value.
- [ ] Parse JSON-like adapter output and collected text files through the shared matcher while retaining raw output paths.
- [ ] Queue each new derived file once by SHA-256 and run the existing bounded registry on it; do not recursively expand beyond the configured depth/file/byte limits.
- [ ] Add tests for a carved or decompiled text file that is discovered by a second solver and for malformed structured output.
- [ ] Run `python3 -m unittest tests.test_ico_evidence tests.test_ico_solve -q`.

### Task 5: Activate safe inventory-only specialists by signal

**Files:**
- Modify: `ico_tool_adapters.py`
- Modify: `ico_solve.py`
- Test: `tests/test_ico_tool_adapters.py`, `tests/test_ico_solve.py`

- [ ] Add hint-gated profiles/parsers for `hashid`, `xortool`, `Ciphey`, `RsaCtfTool`, `LIEF`, `bulk_extractor`, `seccomp-tools`, and `one_gadget` where the input format and local executable are present.
- [ ] Keep Qiling, Unicorn execution, Frida, Objection, tracing, password crackers, and all network scanners opt-in with explicit local-replica/emulation flags.
- [ ] Ensure missing tools produce a structured skip event and never make the whole solve fail.
- [ ] Add applicability tests for hashes, repeating-XOR-looking text, RSA key material, disk images, seccomp strings, and libc files.
- [ ] Run the adapter suite and `python3 -m py_compile ico_*.py tests/*.py`.

### Task 6: Expose controls and benchmark the result

**Files:**
- Modify: `ico_solve.py`
- Modify: `README.md`
- Modify: `verify.sh`
- Create: `scripts/benchmark_ico_solve.py`
- Test: `tests/test_ico_solve_cli.py`, `tests/test_benchmark_ico_solve.py`

- [ ] Add `--workers`, `--deadline`, and `--cache` controls with conservative defaults and JSON metadata showing effective values.
- [ ] Add a benchmark command that reports wall time, tool count, cache hits, skipped tools, and candidates without claiming platform confirmation.
- [ ] Raise the inventory assertion in `verify.sh` from the old 28-tool floor to the actual registry count and smoke-test the new CLI options.
- [ ] Document staged execution, cache invalidation, local-only gates, and evidence states.
- [ ] Run `./verify.sh`, the benchmark smoke test, and a repeated identical run to verify stable stdout.
