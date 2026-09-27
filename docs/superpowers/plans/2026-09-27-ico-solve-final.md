# ICO Final Solver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `ico-solve`, a final-facing command that accepts task files or story archives and prints the highest-confidence flag recovered by a 15-slot Web/PWN/Forensics/Reverse/Crypto solver pipeline.

**Architecture:** Reuse the existing bounded scanner, solver registry, task-aware ICO profiles, and command runner. Add a separate solve facade that discovers story/task slots, runs family-specific stages, ranks corroborated flags, and emits only copy-ready results while keeping optional evidence in a debug report.

**Tech Stack:** Python 3.14, existing `ico_solver_engine.py` registry, standard-library archive and subprocess APIs, Capstone/radare2/angr/z3/tshark/binwalk/zsteg/ffmpeg/exiftool when installed, shell launcher, `unittest`.

**Spec:** `docs/superpowers/specs/2026-09-27-ico-solve-final-design.md`

## Global Constraints

- Input files remain read-only; derived files live in a temporary or explicit debug directory.
- The default path is offline and file-driven; it never contacts `cyberolympiad.kz`, scans ports, submits flags, or guesses flag values.
- All decoders, subprocesses, archive expansion, and local replica runs are bounded by byte, file, depth, timeout, and resource limits.
- `candidate`, `payload-ready`, `transcript-derived`, local-replica output, checker output, and hash verification remain distinct internally; stdout selects only ranked flag values.
- Existing `ico-scan`, ICO task solvers, corpus reports, and `./verify.sh` behavior stay compatible.
- The workspace is not a Git repository, so implementation commits cannot be made until repository metadata exists; each task still ends with a clean diff and fresh verification.

### Task 1: Add the solve result model and input grouping

**Files:**
- Create: `ico_solve.py`
- Test: `tests/test_ico_solve.py`

**Interfaces:**
- `SolveCandidate(value: str, task_id: str, story_id: str, family: str, state: str, score: int, sources: tuple[str, ...], triage: str)`
- `SolveSlot(task_id: str, story_id: str, family: str, difficulty: str, paths: tuple[Path, ...])`
- `SolveReport(slots: tuple[SolveSlot, ...], candidates: tuple[SolveCandidate, ...], errors: tuple[str, ...])`
- `discover_solve_slots(inputs: Sequence[Path], workspace: Path, limits: SolverLimits) -> tuple[SolveSlot, ...]`

- [ ] **Step 1: Write the failing model and grouping tests.**

  Add tests that pass a single file, a task directory containing `task.txt`, a nested ZIP, and a three-story directory. Assert that related files are grouped under one slot and that story/family/difficulty metadata is read from task text and directory names.

- [ ] **Step 2: Run the focused tests and verify failure.**

  Run:

  ```sh
  cd $ICO_TOOLKIT_ROOT
  python3 -m unittest tests.test_ico_solve -v
  ```

  Expected: import or missing-interface failures before implementation.

- [ ] **Step 3: Implement bounded discovery.**

  Reuse `ico_scan_core.Artifact`, task manifest discovery, archive extraction helpers, and `SolverLimits`. Normalize paths, reject symlinks, cap extracted files and bytes, detect the nearest task root, infer family from authoritative task text before filename hints, and assign deterministic `story_XX/family` IDs when a story directory is present.

- [ ] **Step 4: Run the focused tests.**

  Run the same unittest command and require all grouping tests to pass.

- [ ] **Step 5: Record a clean diff checkpoint.**

  Run `git diff --check` if repository metadata becomes available; otherwise run `python3 -m py_compile ico_solve.py tests/test_ico_solve.py` and record the changed paths.

### Task 2: Build the solver pipeline facade

**Files:**
- Modify: `ico_solve.py`
- Modify: `ico_solver_engine.py:1-180` only if a shared result helper is needed
- Test: `tests/test_ico_solve.py`

**Interfaces:**
- `solve_inputs(inputs: Sequence[Path], *, debug_dir: Path | None = None, mode: str = "full", limits: SolverLimits = SolverLimits()) -> SolveReport`
- `run_slot(slot: SolveSlot, context: SolverContext, registry: SolverRegistry, mode: str) -> tuple[SolverResult, ...]`

- [ ] **Step 1: Add failing pipeline tests.**

  Use a temporary text fixture containing a Base64-encoded flag, an archive containing a nested flag, and a synthetic task statement. Assert that `solve_inputs` returns candidates grouped by slot and continues when one solver raises an exception.

- [ ] **Step 2: Implement stage ordering.**

  Build a `SolverContext` per slot, run the existing exact ICO task solver when the task root matches, then call `build_default_registry().solve(context)` in detection-score order. Enqueue derived inputs through the existing bounded queue logic. Preserve each `SolverResult` in memory for ranking and write JSON only when `debug_dir` is supplied.

- [ ] **Step 3: Add optional local tool stages.**

  Reuse `CommandRunner` and invoke only type-matched tools already used by the scanner: `file`, `strings`, `zsteg`, `binwalk`, `tshark`, `exiftool`, `ffmpeg`, `radare2`, `gdb`, `z3`, and `pwn`. Pass argument arrays without a shell, set per-tool timeouts, and convert missing tools to an evidence note instead of a failure.

- [ ] **Step 4: Run the pipeline tests.**

  Run `python3 -m unittest tests.test_ico_solve -v` and require the exception-isolation and derived-input tests to pass.

- [ ] **Step 5: Run the existing registry tests.**

  Run `python3 -m unittest tests.test_ico_solver_engine tests.test_ico_universal_integration -q` and require no regression.

### Task 3: Add confidence ranking and copy-ready output

**Files:**
- Modify: `ico_solve.py`
- Test: `tests/test_ico_solve.py`

**Interfaces:**
- `rank_candidates(results: Iterable[SolverResult], slots: Iterable[SolveSlot]) -> tuple[SolveCandidate, ...]`
- `select_flags(report: SolveReport) -> tuple[SolveCandidate, ...]`
- `format_stdout(report: SolveReport, *, quiet: bool = True) -> str`

- [ ] **Step 1: Write failing ranking tests.**

  Create duplicate values with states `hash-verified`, `transcript-derived`, `candidate`, `candidate-review`, and `payload-ready`, plus placeholder/noise values. Assert state precedence, independent-source corroboration, task-slot separation, deterministic tie breaking, and rejection of low-priority values.

- [ ] **Step 2: Implement ranking.**

  Assign fixed scores in the spec order, add corroboration points for distinct analyzers and source hashes, subtract placeholder/noise penalties, and sort by story, family, score, then value. Never treat a payload path without a returned flag as a flag candidate.

- [ ] **Step 3: Implement stdout contract.**

  For one slot print only the selected flag. For multiple slots print `task-id<TAB>flag`. Return exit code 0 when every slot has a selected flag, 2 when some slots have no flag, and 1 for invalid input. Keep diagnostic JSON under `--debug`.

- [ ] **Step 4: Run focused ranking tests.**

  Run `python3 -m unittest tests.test_ico_solve -v` and verify exact stdout strings and exit codes.

### Task 4: Add the final-facing CLI and launcher

**Files:**
- Modify: `ico_solve.py`
- Create: `ico-solve`
- Modify: `env.sh` only if the launcher needs an exported path
- Test: `tests/test_ico_solve_cli.py`

**Interfaces:**
- CLI: `ico-solve PATH [PATH ...] [--mode fast|full] [--debug DIR] [--family FAMILY] [--story STORY] [--timeout SECONDS]`
- `main(argv: Sequence[str] | None = None) -> int`

- [ ] **Step 1: Write failing CLI tests.**

  Invoke the launcher with a fixture directory and assert that stdout contains only the expected flag, `--debug` creates `report.json`, missing input returns code 1, and a multi-slot directory prints stable tab-separated rows.

- [ ] **Step 2: Implement argument validation and launcher dispatch.**

  Mirror the existing `ico-scan` Python selection from `env.sh`, make `full` the default, set safe limits, and avoid progress output on stdout. Keep a `--version` value independent from `ico-scan`.

- [ ] **Step 3: Run CLI tests.**

  Run `python3 -m unittest tests.test_ico_solve_cli -v` and then `./ico-solve --help`.

### Task 5: Complete Crypto family coverage

**Files:**
- Create: `ico_solve_crypto.py`
- Modify: `ico_solve.py`
- Test: `tests/test_ico_solve_crypto.py`

**Interfaces:**
- `solve_crypto(slot: SolveSlot, context: SolverContext) -> tuple[SolverResult, ...]`
- `parse_crypto_hints(task_text: str) -> CryptoHints`

- [ ] **Step 1: Add deterministic fixtures and failing tests.**

  Cover Caesar/affine, repeating-key XOR with a stated crib, Vigenere with a supplied key hint, LCG/MT19937 state recovery, RSA low exponent, AES nonce reuse, and a saved MAC/length-extension transcript. Include a negative fixture with no cryptographic evidence.

- [ ] **Step 2: Implement hint-gated handlers.**

  Parse task clues, identify supplied parameters, run bounded transforms with z3/PyCryptodome/Sage-compatible math where available, and emit a candidate only after round-trip or algebraic verification. Keep every search bound explicit and reject password/flag brute force.

- [ ] **Step 3: Run Crypto tests.**

  Run `python3 -m unittest tests.test_ico_solve_crypto tests.test_ico_universal_crypto -q`.

### Task 6: Complete Forensics and media coverage

**Files:**
- Create: `ico_solve_forensics.py`
- Modify: `ico_solve.py`
- Test: `tests/test_ico_solve_forensics.py`

**Interfaces:**
- `solve_forensics(slot: SolveSlot, context: SolverContext) -> tuple[SolverResult, ...]`
- `extract_media_views(path: Path, workspace: Path) -> tuple[Path, ...]`

- [ ] **Step 1: Add failing fixture tests.**

  Cover repaired ZIP/magic bytes, PNG RGB LSB and zTXt, JPEG metadata, WAV/AIFF LSB, DNS Base32 in PCAP, HTTP stream reassembly, SQLite browser cache extraction, and OCR with an independent text corroboration. Add malformed and oversized inputs.

- [ ] **Step 2: Implement bounded media and evidence paths.**

  Reuse existing scanner profiles where possible, add zsteg/ffmpeg/exiftool/tshark/binwalk adapters through `CommandRunner`, deduplicate derived views by SHA-256, and assign OCR a lower rank until a second source agrees.

- [ ] **Step 3: Run Forensics tests.**

  Run `python3 -m unittest tests.test_ico_solve_forensics tests.test_ico_universal_forensics -q`.

### Task 7: Complete Reverse and PWN solving paths

**Files:**
- Create: `ico_local_replica.py`
- Modify: `ico_solve.py`, `ico_universal_reverse.py`, `ico_external_ctf.py`
- Test: `tests/test_ico_solve_reverse.py`, `tests/test_ico_local_replica.py`

**Interfaces:**
- `build_static_payload(slot: SolveSlot, context: SolverContext) -> SolverResult`
- `run_local_replica(spec: ReplicaSpec, payload: bytes, limits: ReplicaLimits) -> ReplicaResult`
- `ReplicaSpec(command: tuple[str, ...], cwd: Path, network: bool = False)`

- [ ] **Step 1: Add failing static reverse/PWN tests.**

  Cover ELF XOR/checker inversion, Python/JS bytecode, ret2win, format string, ROP, integer/vector corruption, and a negative binary containing dangerous imports without a proven path. Assert payload bytes, target addresses, and input offsets.

- [ ] **Step 2: Implement static extensions.**

  Route ELF/PE/Mach-O and bytecode through existing reverse profiles, use symbols/protections/disassembly to prove offsets and targets, and emit concrete payloads only when all required values are derived from the task artifacts.

- [ ] **Step 3: Implement local replica execution.**

  Accept only a manifest that names a local executable or compose service, create a temporary cwd, disable network where the runtime supports it, apply CPU/wall-time/output limits, and parse flag-shaped output. Never use the remote active client from this path.

- [ ] **Step 4: Run Reverse/PWN tests.**

  Run `python3 -m unittest tests.test_ico_solve_reverse tests.test_ico_local_replica tests.test_ico_universal_reverse tests.test_ico_external_ctf -q`.

### Task 8: Complete Web and transcript paths

**Files:**
- Create: `ico_solve_web.py`
- Modify: `ico_solve.py`, `ico_universal_web.py`
- Test: `tests/test_ico_solve_web.py`

**Interfaces:**
- `solve_web(slot: SolveSlot, context: SolverContext) -> tuple[SolverResult, ...]`
- `parse_transcript(path: Path) -> Transcript`
- `run_local_web_recipe(recipe: WebRecipe, replica: ReplicaSpec) -> SolverResult`

- [ ] **Step 1: Add failing transcript and local-web tests.**

  Cover saved HAR/cURL/raw HTTP, WordPress REST route discovery, SQLi/auth/session/IDOR/JWT/OAuth/SSRF/SSTI/XXE/traversal/upload/GraphQL patterns, and a local replica that returns a known flag. Assert that remote URLs are never contacted by the default mode.

- [ ] **Step 2: Implement parser and recipe selection.**

  Reuse current WebSolver detections, group requests by host and route, decode task-provided fields, and create a reproducible recipe only when the task statement or saved transcript supplies the required parameter relationship.

- [ ] **Step 3: Implement local-replica execution and output parsing.**

  Start only a declared local service, run the recipe through an in-process HTTP client, stop the service on timeout, and pass returned bodies through the shared flag matcher and ranking layer.

- [ ] **Step 4: Run Web tests.**

  Run `python3 -m unittest tests.test_ico_solve_web tests.test_ico_universal_web tests.test_ico_active -q`.

### Task 9: Add the 15-slot final benchmark and task routing

**Files:**
- Create: `benchmarks/ico_solve_final15/README.md`
- Create: `benchmarks/ico_solve_final15/story_01/`, `story_02/`, `story_03/` with one Web, PWN, Forensics, Reverse, and Crypto slot per story
- Create: `benchmarks/ico_solve_final15.expected.json`
- Create: `scripts/run_ico_solve_matrix.py`
- Test: `tests/test_ico_solve_matrix.py`

**Interfaces:**
- `load_final15_manifest(root: Path) -> tuple[SolveSlot, ...]`
- `run_solve_matrix(root: Path, expected: Path) -> MatrixReport`

- [ ] **Step 1: Add the manifest and 15 deterministic positive slots.**

  Keep expected values outside the solver input roots. Assign one difficulty to each slot and include all five families in each story; add a separate negative root for each family.

- [ ] **Step 2: Add failing matrix tests.**

  Assert 15 positive slots, five negative slots, exact expected values, stable ordering, and no candidate from negative roots.

- [ ] **Step 3: Implement matrix runner and route checks.**

  Run `ico-solve` once per slot, record stdout, selected state, runtime, missing-tool events, and source hashes, then compare against expected metadata without exposing it to the solver.

- [ ] **Step 4: Run the matrix.**

  Run `python3 scripts/run_ico_solve_matrix.py benchmarks/ico_solve_final15 --expected benchmarks/ico_solve_final15.expected.json` and require all 15 positive slots to produce their expected flag.

### Task 10: Integrate ICO corpora, packaging, and full verification

**Files:**
- Modify: `verify.sh`
- Modify: `README.md`
- Test: `tests/test_ico_solve_integration.py`

**Interfaces:**
- `./ico-solve /path/to/task`
- `./ico-solve /path/to/story --mode fast`
- `./ico-solve /path/to/task --debug /tmp/ico-solve-debug`

- [ ] **Step 1: Add integration tests for existing corpora.**

  Run the solver facade over `ico_ctf_real`, `ico_quals`, `ico_story_matrix`, and one clean external corpus. Assert the existing ten exact local flags, the known qualifying task outputs, the final15 matrix, and deterministic stdout.

- [ ] **Step 2: Add the CLI smoke check to `verify.sh`.**

  Check `./ico-solve --help`, run the final15 matrix, verify that the real pack still returns ten hash-verified values, and assert that no network request is made by default.

- [ ] **Step 3: Update the README with the final workflow.**

  Document the one-command invocation, accepted input forms, output rows, `--debug`, supported local-replica manifest, limits, and the five family routing table. Keep the current `ico-scan` documentation intact.

- [ ] **Step 4: Run the complete verification gate.**

  Run:

  ```sh
  cd $ICO_TOOLKIT_ROOT
  ./verify.sh
  python3 scripts/run_ico_solve_matrix.py benchmarks/ico_solve_final15 --expected benchmarks/ico_solve_final15.expected.json
  ```

  Require exit code 0, all existing tests, 15/15 final-style positive slots, five clean negative roots, ten exact `ico_ctf_real` answers, and deterministic repeated stdout.

## Plan self-review

- The design file defines the CLI, pipeline, ranking, five family handlers,
  local replica boundary, safety limits, and acceptance criteria.
- Every plan task names concrete files, interfaces, failing tests, implementation
  steps, and a verification command.
- The plan separates the final-facing output from the existing evidence report,
  so the requested workflow remains one command while the current regression
  coverage is preserved.
- No task relies on a flag value being guessed, a remote platform request, or an
  unspecified tool. Missing optional tools produce recorded evidence and do not
  silently change the selected flag.
