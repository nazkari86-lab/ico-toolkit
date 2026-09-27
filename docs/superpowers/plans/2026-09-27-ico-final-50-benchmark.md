# ICO Final-50 Benchmark Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic 50-task ICO-style benchmark, measure `ico-solve` with external hash/checker verification, and generate a strictly harder next round whenever a round reaches 50/50.

**Architecture:** A standard-library-only fixture generator writes one task directory per story/family and a manifest containing only answer hashes and checker metadata outside the scan root. `ico-solve` remains read-only and produces its normal evidence report; a separate scorer normalizes task identities, verifies candidate hashes/checkers, and records false positives. An evolution driver creates `round_N+1` from a higher seed only after the preceding scorecard proves 50/50 and zero false positives.

**Tech Stack:** Python 3.13+, existing `ico_solve.py`/`ico_scan.py` APIs, standard library (`base64`, `hashlib`, `json`, `sqlite3`, `struct`, `zipfile`, `wave`, `zlib`), pytest/unittest already used by `verify.sh`, and existing offline tool adapters. No network and no challenge-binary execution.

**Spec:** `docs/superpowers/specs/2026-09-27-ico-final-50-benchmark-design.md`

## Global Constraints

- Keep exactly 50 initial tasks: 10 stories × Web/Pwn/Forensics/Reverse/Crypto.
- Never place the expected manifest, cleartext answer table, or checker answers inside `benchmarks/ico_final_50/`.
- Never contact `cyberolympiad.kz`, submit flags, brute-force flags/passwords, or execute generated/native challenge binaries.
- Preserve `candidate`, `candidate-review`, `payload-ready`, `hash-verified`, `checker-verified`, `unsupported`, and `platform-confirmed` as distinct evidence states.
- Use deterministic generation and bounded file sizes/counts; rerunning a round must reproduce byte hashes exactly.
- Do not claim 10/10 until a fresh score command reports 50/50 exact hash/checker verification and zero false positives.
- This checkout has no `.git` metadata; replace commit checkpoints with an explicit hash/checkpoint file and never report a commit that was not made.

---

### Task 1: Add manifest primitives and deterministic corpus skeleton

**Files:**
- Create: `scripts/final_benchmark.py`
- Create: `scripts/generate_final_benchmark.py`
- Create: `tests/test_final_benchmark_generation.py`
- Create: `benchmarks/ico_final_50/.gitkeep`

**Interfaces:**
- `final_benchmark.py` provides `FAMILIES`, `STORIES`, `DIFFICULTIES`, `task_flag(round_id: int, story: str, family: str, difficulty: str) -> str`, `sha256_text(value: str) -> str`, `ManifestRecord` and `BenchmarkManifest` dataclasses, and `write_manifest(path: Path, manifest: BenchmarkManifest) -> None`.
- `generate_final_benchmark.py` provides `generate(round_id: int = 1, root: Path = ..., manifest_path: Path = ...) -> BenchmarkManifest` and a CLI `python3 scripts/generate_final_benchmark.py --round 1 --root ... --manifest ...`.
- The generator creates exactly 50 task roots and writes only task statements plus minimal evidence stubs in this task; family evidence is added in Tasks 2–6.

- [ ] **Step 1: Write failing tests for manifest shape and deterministic paths**

```python
def test_first_round_has_fifty_unique_records(tmp_path):
    manifest = generate(round_id=1, root=tmp_path / "corpus", manifest_path=tmp_path / "expected.json")
    assert len(manifest.records) == 50
    assert len({record.task_id for record in manifest.records}) == 50
    assert {record.family for record in manifest.records} == {"web", "pwn", "forensics", "reverse", "crypto"}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `python3 -m pytest tests/test_final_benchmark_generation.py -q`

Expected: FAIL because the module and generator do not yet exist.

- [ ] **Step 3: Implement the shared dataclasses and skeleton generator**

Use a top-level manifest object with `schema_version`, `round_id`, `seed`, and
`records`. Each record has `task_id`, `story`, `family`, `difficulty`,
`mechanism`, `answer_sha256`, and `checker`. Generate flags from a
round/story/family/difficulty domain-separation string, but write only the
hash to the manifest. Write `task.txt` with the mechanism and constraints, and
write the manifest via a temporary sibling followed by `Path.replace()`.

- [ ] **Step 4: Run the focused generation tests**

Run: `python3 -m pytest tests/test_final_benchmark_generation.py -q`

Expected: PASS for 50 records, unique IDs, stable task paths, no manifest file
under the corpus root, and identical hashes across two independent runs.

- [ ] **Step 5: Record a filesystem checkpoint**

Run: `python3 scripts/generate_final_benchmark.py --round 1 && find benchmarks/ico_final_50 -type f -print0 | sort -z | xargs -0 shasum -a 256 > benchmarks/ico_final_50.input.sha256`

Keep this checkpoint outside the corpus input tree. A Git commit is unavailable
because the checkout has no `.git` directory.

### Task 2: Implement Web fixtures and offline Web extraction

**Files:**
- Modify: `scripts/generate_final_benchmark.py`
- Modify: `ico_universal_web.py`
- Modify: `ico_task_solvers.py`
- Test: `tests/test_final_benchmark_web.py`
- Test: `tests/test_ico_universal_web.py`

**Interfaces:**
- Add `build_web_fixture(record: ManifestRecord, task_dir: Path, answer: str) -> None`.
- Add `extract_saved_web_evidence(path: Path, task_text: str) -> list[Candidate]` (or the existing project candidate shape) and route it through `WebSolver.solve()` without network access.
- The web solver must accept saved files only: `capture.http`, `capture.har`, `capture.jwt`, `graphql.json`, `websocket.frames`, `multipart.http`, or `http2.headers`.

- [ ] **Step 1: Write failing tests for all ten Web mechanisms**

Each test generates round 1 into `tmp_path`, runs the web solver for the
selected task, and asserts that exactly one candidate has the expected flag
hash. Include a negative saved transcript containing a flag-shaped decoy and
assert it remains unverified.

- [ ] **Step 2: Run the Web tests to verify the missing mechanisms**

Run: `python3 -m pytest tests/test_final_benchmark_web.py tests/test_ico_universal_web.py -q`

Expected: FAIL only for mechanisms not already implemented; the failure output
must identify the task file and transform rather than silently returning an
empty result.

- [ ] **Step 3: Generate bounded saved transcripts**

Implement chunked transfer reassembly, nested/base64 JSON, JWT payload
decoding with contradictory headers, GraphQL alias/escape normalization,
WebSocket masking reversal, multipart quoted-printable decoding, HTTP/2
pseudo-header normalization, persisted-query batches, and encoded chunk
extensions. Keep every transcript local and cap decoded fields at the shared
solver byte limit.

- [ ] **Step 4: Run Web tests and inspect provenance**

Run the command from Step 2. Assert every candidate records its source file,
transform name, and task root; assert no network adapter was invoked.

- [ ] **Step 5: Update the Web regression count**

Run: `python3 -m pytest tests/test_final_benchmark_web.py tests/test_ico_universal_web.py -q`

Expected: PASS with ten verified Web fixtures and the decoy test still
unverified.

### Task 3: Implement Crypto fixtures and bounded transforms

**Files:**
- Modify: `scripts/generate_final_benchmark.py`
- Modify: `ico_universal_crypto.py`
- Test: `tests/test_final_benchmark_crypto.py`
- Test: `tests/test_ico_universal_crypto.py`

**Interfaces:**
- Add `build_crypto_fixture(record: ManifestRecord, task_dir: Path, answer: str) -> None`.
- Add pure functions `decode_affine`, `decode_vigenere`, `recover_nonce_reuse`, `integer_nth_root`, `recover_common_modulus`, and `decode_aes_misuse_evidence` with bounded inputs and explicit failure results.

- [ ] **Step 1: Write failing transform tests**

Cover Caesar/noise, repeating-key XOR with a stated crib, RSA low exponent,
affine/permutation, Vigenere partial key, AES-ECB transcript evidence,
stream-XOR nonce reuse, RSA common modulus, rail-fence/base64, and AES-CBC IV
reuse. Include malformed ciphertext and oversized-input tests.

- [ ] **Step 2: Run the Crypto tests and capture failures**

Run: `python3 -m pytest tests/test_final_benchmark_crypto.py tests/test_ico_universal_crypto.py -q`

Expected: FAIL for each missing transform and PASS for existing transforms.

- [ ] **Step 3: Implement deterministic, non-bruteforce decoders**

Use supplied parameters/cribs, exact integer roots, modular arithmetic, and
bounded known-plaintext recovery. Reject ambiguous outputs instead of trying
arbitrary flag guesses. Emit provenance and a `candidate-review` state when
more than one decode remains.

- [ ] **Step 4: Run Crypto tests with hash assertions**

Run the command from Step 2 and assert ten expected hashes plus malformed-input
rejection.

### Task 4: Implement Forensics fixtures and parsers

**Files:**
- Modify: `scripts/generate_final_benchmark.py`
- Modify: `ico_universal_forensics.py`
- Modify: `ico_universal_media.py`
- Test: `tests/test_final_benchmark_forensics.py`

**Interfaces:**
- Add `build_forensics_fixture(record: ManifestRecord, task_dir: Path, answer: str) -> None`.
- Add bounded helpers for DNS/base32 and TCP/gzip stream reassembly, SQLite/WAL row reconstruction, PNG ancillary chunk/palette extraction, WAV/BMP bit-plane recovery, PDF incremental object streams, GIF extension order, TAR/PAX metadata, and SQLite trigger/hex fragment ordering.

- [ ] **Step 1: Write failing fixture/parser tests**

Each test uses a generated artifact and checks exactly one recovered candidate;
also include a corrupt/truncated artifact that must return `candidate-review`
or `unsupported`, never a guessed flag.

- [ ] **Step 2: Run focused Forensics tests**

Run: `python3 -m pytest tests/test_final_benchmark_forensics.py -q`

Expected: failures identify unsupported evidence types, with no process
execution and no network access.

- [ ] **Step 3: Implement parsers using existing bounded context/adapter APIs**

Reuse `SolverContext`, `SolverLimits`, and existing media decoders. Store
derived artifacts under the report directory, never inside the source task.
Preserve byte-order and fragment-order steps in the result provenance.

- [ ] **Step 4: Run the Forensics tests and verify decoy isolation**

Run the command from Step 2; assert ten verified tasks and zero candidates
originating solely from the corrupt fixture.

### Task 5: Implement static Reverse and Pwn fixtures

**Files:**
- Modify: `scripts/generate_final_benchmark.py`
- Modify: `ico_universal_reverse.py`
- Modify: `ico_task_solvers.py`
- Test: `tests/test_final_benchmark_native_static.py`

**Interfaces:**
- Add `build_reverse_fixture(record: ManifestRecord, task_dir: Path, answer: str) -> None` and `build_pwn_fixture(record: ManifestRecord, task_dir: Path, answer: str) -> None`.
- Add static-only helpers `recover_table_checker`, `recover_vm_trace`, `build_format_string_plan`, `build_rop_inventory`, and `build_seccomp_read_plan`.

- [ ] **Step 1: Write failing static-analysis tests**

Assert that encoded table/VM/checksum cases yield exact candidates. Assert
that ret2win, canary/PIE, GOT/PLT, format-string, ROP, and seccomp cases yield
`payload-ready` with offsets/targets, never an executed process or a fabricated
flag. Test ELF/PE/Mach-O fixtures as bytes and skip a native parser cleanly on
unsupported host formats.

- [ ] **Step 2: Run the static tests before implementation**

Run: `python3 -m pytest tests/test_final_benchmark_native_static.py -q`

Expected: exact reverse cases fail only for missing decoders; Pwn tests fail
with payload evidence absent rather than executing the binary.

- [ ] **Step 3: Implement deterministic static fixture encodings and analyzers**

Generate minimal portable byte fixtures with explicit symbols/data tables.
Use existing ELF/PE/Mach-O inventory helpers, printable-string extraction,
bounded disassembly, and symbol/relocation data. Do not call `subprocess` on a
challenge artifact. A payload plan is a JSON/text artifact with offset,
target, constraints, and why it is safe to review offline.

- [ ] **Step 4: Run static tests and audit execution policy**

Run the focused command, then run:

```bash
rg -n "subprocess|Popen|os\.system|execve|run\(" ico_universal_reverse.py ico_task_solvers.py
```

Only pre-existing bounded tool adapters and compiler calls in the generator
may remain; the solver path must not execute task binaries.

### Task 6: Add external scorecard and false-positive accounting

**Files:**
- Create: `scripts/score_final_benchmark.py`
- Create: `tests/test_final_benchmark_scoring.py`
- Modify: `scripts/run_corpus_matrix.py` (shared normalization only, if needed)

**Interfaces:**
- `load_manifest(path: Path) -> BenchmarkManifest`.
- `score_report(report_path: Path, manifest_path: Path, corpus_root: Path) -> dict[str, object]`.
- CLI: `python3 scripts/score_final_benchmark.py --report RUN/report.json --manifest benchmarks/ico_final_50.expected.json --corpus benchmarks/ico_final_50 --out RUN/scorecard.json`.

- [ ] **Step 1: Write failing scorer tests**

Construct a report with one verified candidate, one wrong-task candidate, one
duplicate row, one payload-ready result, and one unsupported result. Assert the
scorecard contains exact counts, false positives, duplicate suppression, and
the complete missing-task list.

- [ ] **Step 2: Run scorer tests and verify failure**

Run: `python3 -m pytest tests/test_final_benchmark_scoring.py -q`

Expected: FAIL because the scorer does not exist.

- [ ] **Step 3: Implement manifest-only verification**

Normalize task roots with `Path.resolve()`, require the 50 manifest identities,
hash each candidate value with UTF-8 SHA-256, run only declared deterministic
checkers, and count a task once. A candidate attached to another task is a
false positive even if its value hashes to a different expected answer.
Record per-family/difficulty durations from report metadata when available and
leave missing timing as `null`.

- [ ] **Step 4: Run scorer tests and inspect JSON schema**

Run the focused command. Assert `verified_score`, `verified_count`,
`false_positive_count`, `duplicate_count`, `by_family`, `by_difficulty`, and
`missing_tasks` are present and stable.

### Task 7: Integrate the 50-task end-to-end run and README instructions

**Files:**
- Create: `tests/test_final_benchmark_e2e.py`
- Modify: `README.md`
- Modify: `verify.sh` (invoke the focused tests without contacting the network)

- [ ] **Step 1: Write an end-to-end regression test**

Generate the corpus, run `ico-solve` in fast mode into a temporary report
directory, score the report, and assert the scorecard schema plus the expected
state separation. Do not require 50/50 in the first test; require that every
task is discovered once and every result is classified.

- [ ] **Step 2: Run the test before wiring docs**

Run: `python3 -m pytest tests/test_final_benchmark_e2e.py -q`

Expected: the test exposes missing task-family routing, report parsing, or
scorer integration.

- [ ] **Step 3: Wire the reproducible CLI recipe**

Document generation, solving, scoring, and the meaning of each evidence state:

```bash
python3 scripts/generate_final_benchmark.py --round 1
./ico-solve benchmarks/ico_final_50 --mode fast --debug ico-final-runs/round-01
python3 scripts/score_final_benchmark.py \
  --report ico-final-runs/round-01/report.json \
  --manifest benchmarks/ico_final_50.expected.json \
  --corpus benchmarks/ico_final_50 \
  --out ico-final-runs/round-01/scorecard.json
```

- [ ] **Step 4: Run the e2e test and full verification**

Run: `python3 -m pytest tests/test_final_benchmark_e2e.py -q && ./verify.sh`

Expected: the complete existing suite passes; the scorecard is printed as a
measured local result with no platform-confirmed claims.

### Task 8: Add the harder-round evolution loop

**Files:**
- Create: `scripts/evolve_final_benchmark.py`
- Create: `tests/test_final_benchmark_evolution.py`
- Modify: `README.md`

**Interfaces:**
- `next_round(scorecard: dict[str, object], current_round: int, output_root: Path) -> Path | None`.
- CLI: `python3 scripts/evolve_final_benchmark.py --scorecard RUN/scorecard.json --round 1 --output-root benchmarks`.

- [ ] **Step 1: Write failing evolution tests**

Assert a scorecard with `verified_count=50`, `total_tasks=50`, and
`false_positive_count=0` creates `ico_final_50_round_02` with seed `2`. Assert
any lower score, missing field, false positive, or nonzero round refuses to
create a new round and returns a nonzero CLI status.

- [ ] **Step 2: Run evolution tests and verify failure**

Run: `python3 -m pytest tests/test_final_benchmark_evolution.py -q`

Expected: FAIL because the evolution driver does not exist.

- [ ] **Step 3: Implement the fail-closed gate and difficulty escalation**

Read the scorecard as untrusted data, require exact integer counts and
`verified_score == 1.0`, then call the generator with `round_id + 1`. Round
two changes every mechanism parameter (longer fragments, extra layers,
decoys, and multi-step transforms) through the recorded round seed; it does
not change task count or evidence rules. Never loop indefinitely in one CLI
call: one invocation creates at most one successor round.

- [ ] **Step 4: Run evolution tests and a dry-run successor**

Run: `python3 -m pytest tests/test_final_benchmark_evolution.py -q` and then a
temporary successful scorecard through the CLI. Verify that only the new round
directory and its external manifest are created.

### Task 9: Final fresh audit and release scorecard

**Files:**
- Modify: `README.md` only if command/output details changed.
- Create: `ico-final-runs/round-01/scorecard.json` and `.txt` (generated output).

- [ ] **Step 1: Regenerate twice and compare input hashes**

Run the generator twice with clean temporary roots and compare sorted SHA-256
lists; they must match byte-for-byte.

- [ ] **Step 2: Run the full solver and scorer from a clean report directory**

Run the exact CLI recipe from Task 7, then open the JSON scorecard and verify
all 50 manifest task IDs, category totals, false-positive count, and missing
task list.

- [ ] **Step 3: Run the complete verification suite**

Run: `./verify.sh`

Read the exit code and full summary. If the score is below 50/50, implement
only the missing mechanism, rerun the focused regression, then repeat this
task. Do not call the result 10/10 while any task remains candidate,
payload-ready, review, unsupported, or false-positive.

- [ ] **Step 4: Trigger the evolution gate only when the score is exactly 50/50**

Run the evolution CLI. If the scorecard proves 50/50 and zero false positives,
create the next harder round and repeat Tasks 7–9 for that round. Stop the
current execution after one successor is generated; each subsequent measured
50/50 starts the next explicit cycle.
