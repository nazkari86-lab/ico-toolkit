# ICO Universal Solver Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand `ico-scan` into a bounded registry of deterministic CTF solvers that maximizes offline coverage across the known ICO packs and common web, crypto, reverse, pwn, forensics, stego, and misc task families.

**Architecture:** Add a small solver engine with typed contexts, detections, results, and evidence steps. Keep the existing ICO-specific solvers as trusted adapters, then add independent low-risk profiles by family and integrate them into the existing queue without changing the flat terminal output. Network work is transcript-first; an optional local allowlist adapter is isolated behind an explicit flag.

**Tech Stack:** Python 3.14 standard library first; existing `capstone`, `cryptography`/PyCryptodome, `z3`, `pwntools`, `tshark`, `binwalk`, `zsteg`, `exiftool`, Volatility, and Sleuth Kit only through bounded, recorded subprocess calls; `unittest` fixtures and `verify.sh`.

**Spec:** `docs/superpowers/specs/2026-09-24-ico-universal-solver-design.md`

## Global Constraints

- Local files and directories are the default input. Original challenge files remain read-only; derived material is written under the report directory.
- Existing `ico_ctf_starter`, `ico_ctf_real`, and `ico_quals` packs remain regression corpora.
- Generic solving never performs flag-value brute force, password dictionary guessing, platform submission, port scanning, or requests to `cyberolympiad.kz`.
- Active web/API analysis is a separate explicit mode for an allowlisted, authorized local or task-host target. The default mode never opens sockets.
- Native challenge binaries are inspected statically by default. Payloads may be generated as evidence artifacts; execution requires a separate explicit local-sandbox mode and is never implicit.
- Every solver is bounded by input size, recursion depth, derived file count, subprocess timeout, and network request budget when active mode is enabled.
- Every candidate records its solver, source, derivation chain, state, and verification metadata; absence of a solver is recorded rather than guessed.
- All existing tests and `verify.sh` must remain green after every integration task.

---

### Task 1: Solver engine model and registry

**Files:**
- Create: `ico_solver_engine.py`
- Modify: `ico_scan.py`
- Test: `tests/test_ico_solver_engine.py`

**Interfaces:**
- `SolverLimits(max_bytes: int, max_files: int, max_depth: int, timeout_seconds: float)`
- `SolverContext(input_path: Path, report_dir: Path, limits: SolverLimits, related_paths: tuple[Path, ...], task_text: str | None, classification: dict[str, object], metadata: dict[str, object])`
- `Detection(name: str, category: str, score: int, reason: str, metadata: dict[str, object])`
- `SolverResult(solver: str, category: str, status: str, steps: list[dict[str, object]], artifacts: list[str], candidates: list[dict[str, object]], error: str | None)`
- `UniversalSolver` protocol with `detect(context) -> Detection | None` and `solve(context) -> SolverResult`
- `SolverRegistry.register(solver)`, `SolverRegistry.detect(context) -> list[Detection]`, and `SolverRegistry.solve(context) -> list[SolverResult]`

- [ ] **Step 1: Write the failing model tests.**

```python
class FixtureSolver:
    def __init__(self, name: str, category: str, score: int) -> None:
        self.name = name
        self.category = category
        self.score = score

    def detect(self, _context):
        return Detection(self.name, self.category, self.score, "fixture", {"fixture": True})

    def solve(self, _context):
        return SolverResult(self.name, self.category, "unsupported", [], [], [], None)


def test_registry_orders_detections_and_keeps_metadata(tmp_path):
    context = SolverContext(
        input_path=tmp_path / "evidence.bin",
        report_dir=tmp_path / "report",
        limits=SolverLimits(1024, 10, 2, 1.0),
        related_paths=(),
        task_text=None,
        classification={"kind": "data"},
        metadata={},
    )
    registry = SolverRegistry()
    registry.register(FixtureSolver("low", "misc", 20))
    registry.register(FixtureSolver("high", "crypto", 80))
    detections = registry.detect(context)
    assert [item.name for item in detections] == ["high", "low"]
    assert detections[0].metadata["fixture"] is True
```

- [ ] **Step 2: Run the focused test and verify it fails because the engine module and fixture solver do not exist.**

Run: `python3 -m unittest tests.test_ico_solver_engine -v`

Expected: import or attribute failure for `SolverContext`/`SolverRegistry`.

- [ ] **Step 3: Implement the bounded model and registry.** Use frozen limits, JSON-safe conversion of `Path`/`bytes`, stable descending score ordering with solver-name tie breaking, per-solver exception isolation, and a result status of `failed` containing the exception type and message. The registry must never invoke a solver whose detection is `None`.

- [ ] **Step 4: Integrate the registry as an optional phase in `run_scan`.** Build a context from each queued artifact, run the registry before generic external profiles, merge candidate values through the existing evidence deduplicator, and serialize `universal_results` plus `summary.universal_solver_count`. With an empty registry, all existing behavior and output must remain unchanged.

- [ ] **Step 5: Run the focused and existing CLI tests.**

Run: `python3 -m unittest tests.test_ico_solver_engine tests.test_ico_scan_cli -q`

Expected: all tests pass and existing `ico_ctf_real`/`ico_quals` assertions remain unchanged.

### Task 2: Encodings, XOR, containers, and bounded recursive data

**Files:**
- Create: `ico_universal_data.py`
- Modify: `ico_scan.py`, `ico_solver_engine.py`
- Test: `tests/test_ico_universal_data.py`

**Interfaces:**
- `DataSolver` implementing the Task 1 protocol
- `decode_text_tokens(data: bytes, *, max_bytes: int) -> list[tuple[str, bytes, dict[str, object]]]`
- `extract_container(path: Path, output_dir: Path, limits: SolverLimits) -> list[Path]`
- `solve_data(context: SolverContext) -> SolverResult`

- [ ] **Step 1: Write failing fixtures for nested Base64/hex, crib-supported XOR, ZIP→GZIP→text, TAR/XZ, path traversal rejection, and derived-byte limits.** Assert that a string containing only the word `flag` yields no candidate and that no input file is overwritten.

- [ ] **Step 2: Run `python3 -m unittest tests.test_ico_universal_data -v` and verify the new tests fail.**

- [ ] **Step 3: Implement deterministic token decoding.** Accept only syntactically valid Base64/Base32/hex/percent tokens, cap decoded size, preserve token offset and encoding metadata, and scan each derived view with the shared flag matcher. Implement ZIP/TAR/GZIP/XZ/BZIP2 recursion with canonical path containment, member count, depth, and byte limits.

- [ ] **Step 4: Implement XOR as a condition-backed transform.** Use the supplied task text when present; otherwise require a known crib such as `CTF{`, `ico{`, or `flag{` and record key/offset. Do not enumerate candidate flag strings or password dictionaries.

- [ ] **Step 5: Register `DataSolver` and run the focused tests plus `tests.test_ico_task_solvers`.**

Expected: every fixture returns the expected value or an explicit bounded error, and the existing ten task solvers still pass.

### Task 3: Media, steganography, and document profiles

**Files:**
- Create: `ico_universal_media.py`
- Modify: `ico_scan_profiles.py`, `ico_solver_engine.py`
- Test: `tests/test_ico_universal_media.py`

**Interfaces:**
- `MediaSolver` implementing the Task 1 protocol
- `extract_png_planes(path: Path, limits: SolverLimits) -> list[bytes]`
- `extract_wav_bitstreams(path: Path, limits: SolverLimits) -> list[bytes]`
- `inspect_media(path: Path, output_dir: Path, limits: SolverLimits) -> SolverResult`

- [ ] **Step 1: Write failing fixtures for PNG RGB/RGBA bit planes, all PNG scanline filters, PNG `tEXt`/`zTXt`/`iTXt`, WAV/AIFF sample LSB/MSB streams, JPEG/PNG metadata, and an appended RIFF stream. Include an OCR fixture that must finish as `needs-review` unless a second source corroborates it.**

- [ ] **Step 2: Run the focused media tests and verify they fail.**

- [ ] **Step 3: Implement standard-library parsers first.** Reuse the existing PNG filter logic where possible, add bit-order/plane metadata, parse RIFF/WAVE safely, and write derived streams below the report directory. Invoke `zsteg`, `pngcheck`, `exiftool`, `ffprobe`, or `binwalk` only when available, with argument arrays and recorded timeouts.

- [ ] **Step 4: Add bounded OCR and spectrogram handling.** Store the rendered image and raw OCR output, normalize only documented whitespace, and set `needs-review` when the flag is supported by one uncertain OCR result.

- [ ] **Step 5: Register `MediaSolver` and run media tests, the existing quals solver tests, and `./verify.sh`.**

### Task 4: PCAP, logs, databases, and memory/disk triage

**Files:**
- Create: `ico_universal_forensics.py`
- Modify: `ico_scan.py`, `ico_solver_engine.py`
- Test: `tests/test_ico_universal_forensics.py`

**Interfaces:**
- `ForensicsSolver` implementing the Task 1 protocol
- `parse_pcap(path: Path, limits: SolverLimits) -> list[dict[str, object]]`
- `reassemble_streams(packets: list[dict[str, object]], limits: SolverLimits) -> list[bytes]`
- `inspect_database_or_logs(path: Path, limits: SolverLimits) -> list[dict[str, object]]`

- [ ] **Step 1: Write failing fixtures for little/big-endian classic PCAP, Ethernet/IPv4/TCP and UDP, DNS labels, HTTP headers/body, split TCP payloads, SQLite rows, JSON/CSV timelines, and shell/auth log correlation.**

- [ ] **Step 2: Run `python3 -m unittest tests.test_ico_universal_forensics -v` and verify failure.**

- [ ] **Step 3: Implement bounded packet parsing and stream reassembly.** Record stream direction, sequence ranges, packet count, and byte limits. Feed HTTP/DNS content into the shared decoder rather than treating arbitrary packet bytes as flags.

- [ ] **Step 4: Implement read-only SQLite and text timeline adapters.** Open SQLite using URI read-only mode, limit rows and cell sizes, and preserve the query/line evidence. Detect memory/disk formats and invoke Volatility/Sleuth Kit only through bounded profiles; unsupported plugins create a report step rather than an exception.

- [ ] **Step 5: Register `ForensicsSolver`, run the focused tests, then run all current ICO corpora.** Assert that PCAP and SQLite answers remain stable and no source file is modified.

### Task 5: Bounded cryptography profiles

**Files:**
- Create: `ico_universal_crypto.py`
- Modify: `ico_solver_engine.py`, `ico_scan.py`
- Test: `tests/test_ico_universal_crypto.py`

**Interfaces:**
- `CryptoSolver` implementing the Task 1 protocol
- `recover_lcg(text: str, limits: SolverLimits) -> dict[str, object]`
- `recover_mt19937(outputs: list[int], limits: SolverLimits) -> dict[str, object]`
- `check_rsa_patterns(values: dict[str, int], limits: SolverLimits) -> list[dict[str, object]]`
- `analyze_symmetric_transcript(text: str, limits: SolverLimits) -> list[dict[str, object]]`

- [ ] **Step 1: Write failing fixtures for ROT/affine, known-key XOR, truncated LCG, MT19937 state reconstruction from complete outputs, RSA low exponent/common modulus/Wiener-sized parameters, repeated CTR nonce, ECB block repetition, and SHA-256 length extension.**

- [ ] **Step 2: Run the focused crypto tests and verify failure.**

- [ ] **Step 3: Implement only mathematically justified recovery.** Require the task condition or explicit transcript fields before invoking a family, cap candidate parameter sets, reject ambiguous recovery, and record equations/parameters. Do not turn a flag regex into a search oracle.

- [ ] **Step 4: Add PyCryptodome/SymPy/Z3 integrations as optional adapters.** Missing dependencies produce `unsupported` with a dependency name; they never silently fall back to unbounded brute force.

- [ ] **Step 5: Register `CryptoSolver`, run focused tests, and compare PixelMart/VIP Club outputs against the current ICO regression fixtures.**

### Task 6: Static reverse engineering and pwn analysis

**Files:**
- Create: `ico_universal_reverse.py`
- Modify: `ico_solver_engine.py`, `ico_scan.py`
- Test: `tests/test_ico_universal_reverse.py`

**Interfaces:**
- `ReverseSolver` implementing the Task 1 protocol
- `inspect_native(path: Path, limits: SolverLimits) -> dict[str, object]`
- `recover_static_checker(path: Path, limits: SolverLimits) -> SolverResult`
- `build_static_pwn_report(path: Path, limits: SolverLimits) -> SolverResult`

- [ ] **Step 1: Write failing fixtures for ELF/PE/Mach-O headers, NX/PIE/RELRO/canary detection, strings/imports, a deterministic XOR checker, Python/JS bytecode, and synthetic ret2win/format-string binaries.** Assert that tests never execute a challenge binary.

- [ ] **Step 2: Run the focused reverse tests and verify failure.**

- [ ] **Step 3: Implement static inventory using standard parsing and optional Capstone/radare2.** Record architecture, entry points, protections, strings, constants, call targets, and checker transformations. Use subprocess argument arrays and timeouts.

- [ ] **Step 4: Implement payload construction as evidence only.** Emit ROP/format-string layouts when offsets and addresses are explicitly recovered; mark them `payload-ready` and never send or execute them.

- [ ] **Step 5: Register `ReverseSolver`, run focused tests, and rerun AEZAKMI, Journal Operator, Wolf Protocol, and `ico_ctf_real` reverse tests.**

### Task 7: Saved web/API transcripts and isolated active adapter

**Files:**
- Create: `ico_universal_web.py`
- Create: `ico_active.py`
- Modify: `ico_scan.py`
- Test: `tests/test_ico_universal_web.py`, `tests/test_ico_active.py`

**Interfaces:**
- `parse_http_transcript(path: Path, limits: SolverLimits) -> list[dict[str, object]]`
- `analyze_web_transcript(context: SolverContext) -> SolverResult`
- `TargetPolicy(allowed_hosts: tuple[str, ...], blocked_hosts: tuple[str, ...], max_requests: int)`
- `AuthorizedClient(policy: TargetPolicy).request(method: str, url: str, **kwargs) -> ResponseRecord`

- [ ] **Step 1: Write failing transcript fixtures for SQLi/auth/session, IDOR, JWT/OAuth, CORS/CSRF, SSRF/SSTI, upload/traversal, GraphQL, WordPress REST, and business-logic patterns.** The expected result is a request sequence or evidence note, not an exploit claim without a response.

- [ ] **Step 2: Write failing active-mode tests with a local `http.server`.** Assert that `localhost` in the allowlist is accepted, an unlisted host is rejected before socket creation, `cyberolympiad.kz` is rejected unconditionally, and request count/timeout are enforced.

- [ ] **Step 3: Implement transcript parsing.** Normalize cURL exports, HAR, raw HTTP, JSON logs, and the saved ICO transcripts into one request/response model. Extract tokens, cookies, parameters, redirects, and flag-shaped response values with source locations.

- [ ] **Step 4: Implement `TargetPolicy` and `AuthorizedClient`.** Parse and compare hostname after URL normalization, reject IP/redirect escapes unless explicitly allowlisted, cap methods and requests, and write each request/response metadata to the report. Keep active mode unreachable unless `--authorized-target` and `--allow-network` are both supplied.

- [ ] **Step 5: Register the transcript solver, add CLI flags with help text, run focused tests, and verify the blocked-host test proves no request was made.**

### Task 8: Registry integration, corpus matrix, documentation, and release verification

**Files:**
- Modify: `ico_scan.py`, `README.md`, `verify.sh`
- Create: `scripts/run_corpus_matrix.py`
- Test: `tests/test_ico_universal_integration.py`

**Interfaces:**
- `build_default_registry() -> SolverRegistry`
- `run_corpus_matrix(paths: Sequence[Path], output_dir: Path) -> dict[str, object]`
- CLI summary fields: `universal_solved_count`, `universal_review_count`, `universal_unsupported_count`, `universal_failed_count`

- [ ] **Step 1: Write failing integration tests.** Run the default registry over `ico_ctf_starter`, `ico_ctf_real`, and `ico_quals` copies, assert deterministic flat output, stable answer hashes, no source mutation, and per-state summary counts. Include a directory with no task condition and assert `unsupported` instead of a guessed flag.

- [ ] **Step 2: Run the integration test and verify failure before registry wiring.**

- [ ] **Step 3: Implement `build_default_registry` with deterministic registration order.** Keep the existing dedicated task solvers authoritative; universal profiles may corroborate them but must not overwrite a stronger `hash-verified` state.

- [ ] **Step 4: Add `scripts/run_corpus_matrix.py`.** It must run each corpus in a temporary report directory, emit JSON with corpus path, solver counts, unique answers, source hashes, durations, and errors, and exit nonzero when a previously passing corpus regresses.

- [ ] **Step 5: Update README with the registry categories, command examples, evidence states, limits, and active-mode allowlist.** Update `verify.sh` to run the unit suite, `py_compile`, the corpus matrix, and the existing binary/tool smoke checks without network access.

- [ ] **Step 6: Run the complete verification sequence.**

```sh
python3 -m unittest discover -s tests -q
python3 -m py_compile ico_*.py tests/*.py scripts/run_corpus_matrix.py
./verify.sh
python3 scripts/run_corpus_matrix.py \
  $ICO_CTF_STARTER_ROOT \
  $ICO_CTF_REAL_ROOT \
  $ICO_QUALS_ROOT \
  --out /tmp/ico-corpus-matrix
```

Expected: all tests pass, `verify.sh` exits zero, all three corpora produce stable reports, and no command contacts a network host.

- [ ] **Step 7: Record the final coverage matrix.** Include counts for solved, hash-verified, derived, needs-review, payload-ready, requires-authorized-session, unsupported, and failed results. Do not describe unsupported or historical-only values as current platform solutions.
