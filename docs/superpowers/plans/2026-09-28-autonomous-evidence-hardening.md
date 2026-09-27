# Autonomous Evidence Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Strengthen verified-result integrity, durable provenance, bounded execution, cache correctness, and blind evaluation without rewriting the stable `ico-solve` facade.

**Architecture:** Keep current task-aware solvers and adapter registry. Add focused root modules for evidence persistence and runner policy, integrate them through optional CLI arguments, and add standalone hash-only holdout tooling. Every layer has a focused regression test before production code.

**Tech Stack:** Python 3 standard library, SQLite, pytest/unittest, existing `ico-solve` and benchmark scripts.

**Spec:** `docs/superpowers/specs/2026-09-28-autonomous-evidence-hardening-design.md`

## Global Constraints

- Offline-by-default; no automatic requests to `cyberolympiad.kz` or arbitrary remote hosts.
- Do not execute challenge binaries by default.
- Holdout manifests contain SHA-256 answers only; plaintext answer fields are rejected.
- Preserve existing CLI behavior when new options are omitted.
- Keep all subprocesses shell-free and bounded by timeout/process-group cleanup.

---

### Task 1: Strict benchmark quality gate

**Files:**
- Modify: `scripts/score_final_benchmark.py:153-168`
- Modify: `scripts/run_final_benchmark_cycle.py:190-199`
- Modify: `scripts/evolve_final_benchmark.py:32-44`
- Test: `tests/test_final_benchmark_scoring.py`
- Test: `tests/test_final_benchmark_evolution.py`

**Interfaces:**
- The scorecard keeps `duplicate_count` and adds it to the exact gate.
- `next_round()` returns `None` whenever `duplicate_count != 0`.

- [ ] Write a scorecard test that supplies all correct task answers plus one duplicate and asserts `ten_out_of_ten is False`.
- [ ] Run the focused scoring test and observe the failure because the current gate ignores duplicates.
- [ ] Add `duplicate_count == 0` to the scorecard gate and cycle/evolution gates.
- [ ] Run scoring, evolution, and cycle tests; assert they pass.

### Task 2: Durable evidence store

**Files:**
- Create: `ico_evidence_store.py`
- Modify: `ico_solve.py:691-867,873-915`
- Test: `tests/test_ico_evidence_store.py`
- Test: `tests/test_ico_solve.py`

**Interfaces:**
- `EvidenceStore(path: Path)` creates the schema and supports `record_artifact`, `start_execution`, `finish_execution`, `record_finding`, `record_candidate`, `record_relationship`, `has_execution`, and `snapshot`.
- `persist_solve_report(store, report)` records slots/candidates without importing `SolveReport`.
- CLI option `--evidence-db PATH` enables persistence; omission keeps current behavior.

- [ ] Write a SQLite round-trip test covering all five tables, parent/child relationship, and resume lookup.
- [ ] Run the test and observe the missing-module failure.
- [ ] Implement schema, transactions, WAL, foreign keys, bounded JSON metadata, and SHA-256 artifact identity.
- [ ] Integrate optional persistence after `SolveReport` creation and expose the CLI option.
- [ ] Run store and solve tests and verify a reopened database returns the same candidates.

### Task 3: Resource-limited command runner

**Files:**
- Modify: `ico_scan_core.py:115-179`
- Test: `tests/test_ico_scan_core.py`

**Interfaces:**
- Add `RunnerPolicy(max_cpu_seconds: int | None = None, max_memory_bytes: int | None = None, max_output_bytes: int | None = None)` with positive-value validation.
- `CommandRunner(..., policy=None)` remains backward-compatible.

- [ ] Write policy validation and bounded-output tests.
- [ ] Run them and observe the missing `RunnerPolicy` failure.
- [ ] Implement policy validation, optional POSIX child limits, and capture-limit clamping while retaining process-group termination.
- [ ] Run core runner tests, including concurrent logging and timeout tests.

### Task 4: Cache revisioning

**Files:**
- Modify: `ico_tool_adapters.py:837-857`
- Test: `tests/test_ico_tool_adapters.py`

**Interfaces:**
- Cache invocation metadata includes a `toolkit_revision`/protocol version.
- `ICO_TOOLKIT_REVISION` may override the revision for controlled experiments.

- [ ] Write a cache test that changes the revision and asserts a cache miss.
- [ ] Run it and observe the failure because the current invocation omits the revision.
- [ ] Add the revision to the invocation hash and preserve existing cache hits for unchanged revisions.
- [ ] Run adapter cache tests.

### Task 5: Blind holdout harness

**Files:**
- Create: `scripts/holdout_benchmark.py`
- Modify: `README.md`
- Test: `tests/test_holdout_benchmark.py`

**Interfaces:**
- `load_holdout_manifest(path)` rejects plaintext keys (`answer`, `flag`, `value`, `expected`) and accepts only `answer_sha256`.
- `score_holdout(report, manifest)` returns verified/missing/false-positive/duplicate counts.
- CLI accepts `--manifest`, `--report`, and optional solver execution paths without exposing expected values.

- [ ] Write tests for hash-only scoring, duplicates, missing tasks, and plaintext rejection.
- [ ] Run them and observe the missing-module failure.
- [ ] Implement the manifest loader, independent scorer, and JSON/text output.
- [ ] Add a small offline fixture invocation to the test suite and document the protocol.

### Task 6: Integration verification and publication

**Files:**
- Modify: `verify.sh`
- Modify: `README.md`
- Modify: `benchmarks/ico_final_50_hardest_history.json`
- Add: generated hardest successor corpora from the active cycle

- [ ] Run the full focused tests and `./verify.sh`.
- [ ] Merge the measured rounds 22–26 and successor 27 into the history file.
- [ ] Run `git diff --check`, stage only source/tests/docs/history/corpora, commit, and push `main`.
- [ ] Verify remote SHA, public visibility, raw access to the new modules and round manifest, and a clean working tree.
