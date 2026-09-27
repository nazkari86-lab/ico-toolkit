# ICO Scanner Coverage and Performance Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` and work inline. Keep each task independently reviewable.

**Goal:** Make `ico-scan` faster, more dependable, and more effective at solving local ICO/CTF challenge files while clearly identifying which missing input or authorized action prevents a remaining solve.

**Architecture:** Keep the existing task solvers and six-family universal registry. Improve measurement and tool selection first, pass complete task-scoped artifact sets into solvers, then add coverage from a balanced benchmark corpus. Run cheap deterministic analysis before expensive analyzers; preserve a read-only local default and keep any service interaction in a separate explicit allowlisted mode.

**Tech Stack:** Python 3.14, standard library, existing `ico-scan` modules and installed local analyzers, `unittest`, and `scripts/run_corpus_matrix.py`.

**Spec:** `docs/superpowers/specs/2026-09-24-ico-universal-solver-design.md`

## Global Constraints

- Treat challenge input files as read-only; write extracted data and reports only below the run directory.
- Never guess flag contents, brute-force flags, or run password dictionaries.
- The default scan makes no network requests and never submits answers.
- Never target `cyberolympiad.kz`; a future active adapter may use only explicitly supplied, authorized challenge-service hosts and task-defined requests.
- Do not execute native challenge binaries in the default scan. Any future execution must use a separately requested local sandbox with no network and bounded CPU, memory, time, and filesystem access.
- Keep `candidate`, `hash-verified`, `transcript-derived`, `payload-ready`, `needs-review`, `requires-authorized-session`, `historical-reference`, `unsupported`, and `failed` distinct in JSON and human-readable output.
- A historical walkthrough value is not a new solve and is never included in the current-candidate count.
- Preserve deterministic output order and report why each expensive analyzer ran or was skipped.

---

## Evidence and baseline

The plan starts from `ico-scan-runs/20260924-real-quals-complete/report.json`. That run processed 44 files, made 300 analyzer calls, took about 188 seconds, recorded 38 tool errors, and produced zero new candidates from 45 universal-solver results. Thirty-six errors were macOS `strings -el` incompatibilities; one came from `exiftool` on an unsupported input and one from `pngcheck` on a malformed challenge image. The `Can You Hear` solver invoked Tesseract 34 times. The current real-quals task matrix has 2 locally derived candidates, 2 payload-ready tasks, 5 tasks requiring an authorized session/transcript, and 1 OCR review task. Its 12 historical answer strings are reference data, not current-run solutions.

The 10/10 `ico_ctf_real` hash-verified result remains a regression gate. It demonstrates exact coverage of that known pack only; it does not establish universal coverage.

## Files and responsibilities

- `ico_scan.py`: scan stages, task context construction, progress reporting, and final evidence summary.
- `ico_scan_core.py`: command execution and shared byte/text helpers.
- `ico_scan_profiles.py`: external analyzer profiles and archive extraction policy.
- `ico_solver_engine.py`: solver context, detection, limits, and structured results.
- `ico_task_solvers.py`: task-directory discovery and known local challenge adapters.
- `ico_quals_solvers.py`: historical ICO task analysis, transcript handling, answer index, and OCR.
- `ico_universal_*.py` and `ico_universal_registry.py`: category-specific universal solvers and registration.
- `scripts/run_corpus_matrix.py`: repeatable corpus runner and coverage/performance matrix.
- `tests/`: small deterministic fixtures and regression tests.
- `README.md`: install, run modes, report meanings, and tool health instructions.
- `docs/superpowers/specs/2026-09-24-ico-universal-solver-design.md`: existing architecture and evidence contract; update only if an interface or policy changes.

## Acceptance criteria

1. The three available ICO corpora and synthetic regression corpus retain their currently verified answers and task counts; input hashes are unchanged after each scan.
2. The current real-quals scan emits no known avoidable `strings -el` or irrelevant `exiftool` failures. Malformed input is reported as an input-format diagnostic, not a broken installation.
3. On the same machine and unchanged corpus, the full real-quals scan takes at least 50% less wall time than the 188-second baseline, with all existing local candidates, payload-ready states, transcript requirements, and review states preserved. If profiling shows that this target cannot be met without losing evidence, record the measured bottleneck and retain correctness.
4. The corpus report separates current local candidates, hash-verified values, transcript-derived values, payloads, historical references, and unresolved task states. Historical values never inflate current coverage.
5. The new benchmark matrix covers the announced structure: 3 story directories × 5 families (web, pwn, forensics, reverse, crypto), with easy, medium, and hard fixture cases for each family. This is a regression suite for implemented patterns, not a claim that arbitrary tasks in a family are solvable.
6. Negative fixtures produce no candidate; resource-limit and malformed-input fixtures terminate with an explicit reason.

---

### Task 1: Make corpus results a trustworthy scorecard

**Files:**
- Modify: `scripts/run_corpus_matrix.py`
- Create: `tests/test_run_corpus_matrix.py`
- Modify: `README.md`

**Interfaces:**
- Keep `run_corpus_matrix(paths: Sequence[Path], output_dir: Path) -> dict[str, object]`.
- Add a per-corpus `metrics` object with `elapsed_seconds`, `source_file_count`, `source_unchanged`, `current_candidates`, `hash_verified`, `transcript_derived`, `payload_ready`, `needs_review`, `session_required`, `historical_references`, `tool_calls`, `tool_errors`, `tool_timeouts`, and `by_analyzer`.
- Keep raw `events` under a separate field. Populate `errors` only with failures, rather than copying every report event into it.

- [x] **Step 1: Add a fixture report with candidates in multiple evidence states, successful tool events, skip events, a timeout, and a historical reference.** Assert each metric independently and assert that a skip is not counted as an error.
- [x] **Step 2: Change `run_corpus_matrix` to derive metrics from report fields and events.** Count each evidence state from its existing source array; classify tool errors and timeouts only from matching event types; aggregate invocation durations from tool-result records when available; retain source hashes and unchanged checks.
- [x] **Step 3: Add deterministic report serialization and compatibility metadata.** Set `schema_version` to 2 and include the schema version in `README.md`; keep existing `corpora`, `summary`, `unique_answers`, `source_hashes`, and `source_unchanged` fields during the transition.
- [x] **Step 4: Run `python3 -m unittest tests.test_run_corpus_matrix -v` and compare the emitted metrics against `20260924-real-quals-complete/report.json`.** The scorecard reports 2 current candidates and 12 references separately.

### Task 2: Fix portable analyzer behavior and inventory tool capabilities

**Files:**
- Modify: `ico_scan_profiles.py`
- Modify: `ico_scan.py`
- Modify: `ico_universal_reverse.py`
- Create: `scripts/check_toolchain.py`
- Modify: `tests/test_ico_scan_profiles.py`
- Modify: `README.md`

**Interfaces:**
- Preserve `ToolProfile` and `profiles_for(classification)`.
- Add a capability report with executable name, resolved path, version if detectable, and availability; report an unavailable optional tool as `unavailable`, not a scan failure.
- Keep the UTF-16LE string extraction available through the existing bounded Python `_strings(data, limit)` path in `ico_universal_reverse.py`.

- [x] **Step 1: Add profile-selection tests.** Verify that `strings-utf16le` is not invoked as `strings -el` on macOS, metadata analyzers are not sent obviously unsupported data, and relevant PNG/audio/PDF/PCAP profiles remain selected.
- [x] **Step 2: Replace the incompatible external UTF-16LE call with the existing bounded Python string extractor.** Return its extracted text through a built-in analyzer result with source offsets; do not add a new dependency.
- [x] **Step 3: Add `scripts/check_toolchain.py` to inspect only tools referenced by active profiles.** Use `shutil.which`; invoke only a bounded version/help probe for found tools; print a stable JSON table and exit successfully when an optional tool is absent.
- [x] **Step 4: Distinguish profile outcomes.** Record `ok`, `unavailable`, `inapplicable`, `malformed-input`, `timed-out`, and `failed` with a short reason. Do not treat a nonzero result from a corrupt challenge file as proof that the executable is broken.
- [x] **Step 5: Run `python3 -m unittest tests.test_ico_scan_profiles tests.test_ico_universal_reverse -v`.** Tests verify that the prior macOS `strings -el` error is no longer possible.

### Task 3: Give solvers the complete task evidence set

**Files:**
- Modify: `ico_scan.py`
- Modify: `ico_solver_engine.py`
- Modify: `ico_task_solvers.py`
- Modify: `tests/test_ico_solver_engine.py`
- Modify: `tests/test_ico_task_solvers.py`

**Interfaces:**
- Keep `SolverContext.related_paths: tuple[Path, ...]` and populate it with sibling evidence files from the discovered task directory.
- Add task-scope metadata containing the canonical task root and the task statement path; exclude report directories, symlinks, hidden directories, and previously derived report artifacts.
- Keep all original sources read-only.

- [x] **Step 1: Create a task fixture with `task.txt`, three related artifacts, an unrelated sibling task, and a symlink.** Assert the context sees only the three evidence files from its own task directory.
- [x] **Step 2: Build one deterministic task-file manifest after `discover_task_dirs`.** Reuse it for task solvers and the universal registry rather than rediscovering siblings for each artifact.
- [x] **Step 3: Populate `task_text` from the canonical task root and `related_paths` from that task manifest.** When the caller passes one file, retain the existing immediate-task scope; when there is no `task.txt`, keep the single-file behavior.
- [x] **Step 4: Include related-file hashes in result metadata.** This makes a multi-file derivation reproducible and prevents stale cached evidence from being reused when one companion file changes.
- [x] **Step 5: Run `python3 -m unittest tests.test_ico_solver_engine tests.test_ico_task_solvers -v`.** Tests verify that task A never receives task B's inputs and the corpus source hashes remain unchanged.

### Task 4: Schedule work by cost and evidence, then tune scan performance

**Files:**
- Modify: `ico_scan.py`
- Modify: `ico_scan_profiles.py`
- Modify: `ico_scan_core.py`
- Modify: `tests/test_ico_scan_cli.py`
- Modify: `tests/test_ico_scan_core.py`

**Interfaces:**
- Add an internal stage label to each analyzer event: `fast`, `specialized`, or `deep`.
- Preserve the no-argument autonomous behavior: it still runs the complete compatible profile set and prints a final report.
- Add optional `--progress` output for completed stages and `--mode fast|full`; `full` remains the default. Fast mode runs built-in/task-aware solvers and cheap type-matched profiles only.
- Add a per-run invocation cache keyed by input SHA-256, analyzer name, executable identity/version, and normalized arguments. Never reuse a result when a task solver depends on changed task text or companion-file hashes.

- [x] **Step 1: Instrument time and invocation counts at the command runner boundary.** Include elapsed seconds, timeout, exit status, and input digest in each command record.
- [x] **Step 2: Define the stable stage order.** Run task-aware solvers and bounded in-process decoders first, matching external profiles second, then expensive OCR, binwalk, radare2, tshark, or forensic tools only for compatible file types and evidence contexts.
- [x] **Step 3: Add a run-local cache for identical analyzer inputs.** Store the complete serialized result in the report directory and include a `cache-hit` event pointing to the original invocation; do not write into source directories.
- [x] **Step 4: Add bounded progress messages.** Print stage and file counts to stderr so stdout remains copyable; never print a candidate until its source and evidence state are available.
- [x] **Step 5: Add `--mode fast|full` tests.** Assert that fast mode omits deep analyzers, full mode preserves current analyzer coverage, repeated identical input produces a cache hit, and changed bytes invalidate the cache.
- [x] **Step 6: Re-run the corpus matrix after instrumentation.** Analyzer-level timings and source immutability were recorded; no parallel work was needed after the bounded run met the performance target.

### Task 5: Make OCR targeted, adaptive, and reviewable

**Files:**
- Modify: `ico_quals_solvers.py`
- Modify: `ico_universal_media.py`
- Modify: `tests/test_ico_quals_solvers.py`
- Modify: `tests/test_ico_universal_media.py`

**Interfaces:**
- Add an OCR input planner returning ordered `(path, reason, sha256)` records.
- Preserve the `candidate-review`/`needs-review` state whenever OCR alone is ambiguous; exact normalization and duplicate OCR readings may improve the evidence record but must not silently upgrade the state.

- [x] **Step 1: Add OCR planner tests with identical PNGs, a raw spectrogram, crops, and unrelated adjacent images.** Duplicate hashes are analyzed once and unrelated images are not selected merely because they share a directory.
- [x] **Step 2: Rank only task-derived spectrograms and their deliberate crops.** Generated whole and frequency-focused spectra precede named crops; unrelated neighboring images are excluded and every selected view has a recorded reason.
- [x] **Step 3: Record OCR input hash, preprocessing, PSM, elapsed time, raw output path, and whether independent views agree.** The original spectrogram and derived image provenance are preserved.
- [x] **Step 4: Use a hard per-task OCR invocation budget.** The default budget is at most 8 calls; any additional call would require a new distinct preprocessing view with recorded reason.
- [x] **Step 5: Verify the existing Can You Hear fixture still returns its current status and that OCR-only ambiguity remains a review item.** The post-change run used 8 calls at most, versus the 34-call baseline.
- [x] **Step 6: Add a vertically compact crop and adaptive Tesseract segmentation without raising the per-task budget.** PSM 7 checks planned views, PSM 6 checks only substantial output, and PSM 8/11 are reserved for the compact crop. Long hex-like output with a damaged prefix is preserved verbatim for review and never promoted to a candidate.

### Task 6: Build coverage against the actual ICO challenge shape

**Files:**
- Create: `benchmarks/ico_story_matrix/README.md`
- Create: `benchmarks/ico_story_matrix/<story>/<family>_<difficulty>/task.txt` and deterministic fixture artifacts
- Modify: `scripts/run_corpus_matrix.py`
- Modify: `tests/test_ico_universal_integration.py`
- Modify: `ico_universal_registry.py` and only the category solvers that the matrix proves are missing coverage
- Modify: `docs/superpowers/specs/2026-09-24-ico-universal-solver-design.md`

**Interfaces:**
- Every benchmark case declares `story`, `family`, `difficulty`, expected evidence state, and expected candidate value in test-only metadata outside the scanner input directory.
- The matrix groups outcomes by the five announced families and by easy/medium/hard; the scanner must not read the expected answer file as input.

- [x] **Step 1: Create 45 small, deterministic cases: three story roots × five families × three difficulty levels.** The corpus uses original synthetic values and one negative case per family with no derivable flag.
- [x] **Step 2: Run the current scanner over the matrix with external profiles disabled.** The baseline and final reports retain unchanged source hashes.
- [x] **Step 3: For each uncovered case, search existing local libraries and installed tools for an exact compatible capability.** Capability and toolchain checks are recorded before custom bounded integrations.
- [x] **Step 4: Implement only a deterministic profile supported by the fixture and task evidence.** Standard-library parsing and bounded argument-array profiles are used.
- [x] **Step 5: Expand task-family solvers in measured order.** The matrix covers web transcript/API parsing, static pwn analysis, PCAP/SQLite/log forensics, ELF/bytecode reverse engineering, and bounded crypto recovery with sufficient evidence gates.
- [x] **Step 6: Update the coverage matrix after each solver.** All 45 positive cases recover the expected state and all five negative roots stay candidate-free.
- [x] **Step 7: Keep live service tasks in an explicit separate lane.** HAR, HTTP, curl, and task-service transcripts are parsed offline; the explicit active client requires an allowlist and rejects the platform host.

### Task 7: Turn unresolved results into a precise next action

**Files:**
- Modify: `ico_quals_solvers.py`
- Modify: `ico_task_solvers.py`
- Modify: `ico_scan.py`
- Modify: `tests/test_ico_quals_solvers.py`
- Modify: `README.md`

**Interfaces:**
- Add a `next_action` field to each task result: a concrete missing file, transcript format, manual confirmation, authorized service session, or unsupported family.
- Keep candidate values in the existing `candidates` array and historical values in `references`; do not combine their counts.

- [x] **Step 1: Add tests for each existing real-quals state.** The post-change corpus run preserves two local candidates, two payload-ready tasks, five session-required tasks, one OCR review task, and twelve historical references independently.
- [x] **Step 2: For transcript-required tasks, report the exact accepted input forms and expected evidence fields.** Existing transcript parsers are reused without platform probing or flag guessing.
- [x] **Step 3: For payload-ready tasks, link each payload artifact and show the task-defined action that remains.** Payloads remain separate from flags and service-confirmed success.
- [x] **Step 4: Change the default real-quals terminal summary to show current candidates and task states first.** Historical references require `--show-references` and are explicitly labelled.
- [x] **Step 5: Add a one-line-per-task summary to `report.txt` and the CLI.** Each line contains task ID, evidence state, and next action.

### Task 8: Verify, document, and freeze the first optimized release

**Files:**
- Modify: `verify.sh`
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-09-24-ico-universal-solver-design.md`
- Create: `docs/superpowers/reports/2026-09-24-ico-scan-optimization-results.md`

- [x] **Step 1: Run focused tests for each changed module, then `./verify.sh`.** Exact output is preserved in the results report.
- [x] **Step 2: Run `scripts/run_corpus_matrix.py` over every available `ico_ctf_starter`, `ico_ctf_real`, `ico_quals`, and `ico_story_matrix` root.** Source hashes, runtime, analyzer events, task states, candidates, and references are recorded.
- [x] **Step 3: Compare before and after using the same host and inputs.** The known 10/10 hash-verified real-pack result, real-quals states, five clean negative roots, and the wall-time target were confirmed.
- [x] **Step 4: Document installed optional tools and their degraded-mode behavior.** Missing `steghide` is reported as `unavailable` and does not fail the scan.
- [x] **Step 5: Update the design spec with only verified coverage.** Supported fixture families, unresolved states, transcript requirements, review states, and static payload boundaries are documented.

## Recommended execution order

Complete Tasks 1–3 first so the results are measurable and all solvers see the right evidence. Then do Tasks 4–5 to remove wasted work. Task 6 adds coverage only where the matrix demonstrates a gap. Task 7 makes incomplete results actionable, and Task 8 provides the release evidence. Do not add a new analyzer just because it is popular; add it when a real or synthetic task input demonstrates the exact missing capability.

## Follow-up evidence (2026-09-26)

- `./verify.sh` passed 153 tests and smoke checks after the adaptive OCR update.
- Fresh ICO qualification scan: `ico-scan-runs/20260926-drive-qualifying-ocr-adaptive/report.json`. Can You Hear remains `candidate-review`, has no exact OCR candidate, records two raw hex-like review strings, and uses 6 of the 8 allowed OCR calls.
- The five-corpus matrix at `/tmp/ico-corpus-matrix-20260926-final/corpus-matrix.json` reported unchanged source hashes and zero tool errors for every input corpus. The real `ico_ctf_real` pack retained 10/10 hash-verified answers; the 45 positive story cases retained their expected candidate/review/payload states, and the five negative roots stayed candidate-free.
- The three cases in `benchmarks/ico_synthetic_unresolved` now have permanent integration coverage: two local candidates and one static `payload-ready` result. Four real ICO service tasks still need saved authorized transcripts; the two payload-ready service results need a task response before they can be confirmed.
