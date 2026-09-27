# ICO CTF real task-solvers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Extend `ico-scan` with deterministic local solvers for all ten tasks in `ico_ctf_real`, hash verification, and one end-to-end report.

**Architecture:** Add `ico_task_solvers.py` with bounded standard-library decoders and an optional Capstone-backed static ELF decoder. Task directories are discovered from `task.txt`, solved before the existing queue, and their candidates are merged into the current evidence report. Generic profiles and the existing XOR analyzer continue to run for unrecognized files.

**Tech Stack:** Python 3.14 standard library (`base64`, `gzip`, `lzma`, `tarfile`, `zipfile`, `sqlite3`, `wave`, `struct`, `zlib`, `hashlib`, `re`) plus optional installed `capstone`; existing `unittest` tests and `verify.sh`.

**Spec:** `docs/superpowers/specs/2026-09-23-ico-ctf-real-task-solvers-design.md`

## Global Constraints

- Input is local files/directories supplied by the user.
- No HTTP requests, port scans, platform interaction, flag submission, password dictionaries, or flag guessing are performed.
- Original challenge files are read-only; derived artifacts are written below the report directory.
- Extracted binaries are never executed; ELF solving is static only.
- Archive and decode work is bounded by max depth, file count, and bytes.
- Candidate states remain separate from `hash-verified` results.
- Solver errors are recorded per task and do not abort other tasks.

---

### Task 1: Solver models, flag verification, and task discovery

**Files:**
- Create: `ico_task_solvers.py`
- Modify: `ico_scan_core.py`
- Test: `tests/test_ico_task_solvers.py`

**Interfaces:**
- `TaskResult(task_id: str, task_dir: Path, solver: str, status: str, steps: list[dict], candidates: list[dict], artifacts: list[str], error: str | None)` is JSON-serializable.
- `discover_task_dirs(inputs: Sequence[str]) -> list[Path]` returns deterministic directories containing `task.txt`, skipping hidden and report directories.
- `verify_flag(value: str, expected_hash: str | None) -> dict[str, object]` returns `{status: "hash-verified"|"candidate", algorithm: "sha256", expected: ..., actual: ...}`.
- `select_solver(task_text: str, artifact: Path) -> str | None` returns one registry key or `None`.

- [x] **Step 1: Write failing model and discovery tests.**

```python
def test_verify_flag_uses_exact_utf8_sha256():
    result = verify_flag("CTF{demo}", hashlib.sha256(b"CTF{demo}").hexdigest())
    assert result["status"] == "hash-verified"

def test_discover_task_dirs_skips_reports(tmp_path):
    task = tmp_path / "01_task"; task.mkdir(); (task / "task.txt").write_text("Single-byte XOR")
    report = tmp_path / "ico-scan-runs" / "nested"; report.mkdir(parents=True); (report / "task.txt").write_text("noise")
    assert discover_task_dirs([str(tmp_path)]) == [task]
```

- [x] **Step 2: Run `python3 -m unittest tests.test_ico_task_solvers -v` and verify the new tests fail because the module/interfaces are absent.**

- [x] **Step 3: Implement dataclasses, JSON conversion, task discovery, SHA-256 verification, and keyword/signature-based solver selection.** The selection table must map the exact ten task phrases to `xor`, `magic`, `png-lsb`, `pcap`, `sqlite`, `elf`, `archive`, `repair`, `wav-lsb`, and `png-ztext`.

- [x] **Step 4: Run the focused tests and verify they pass.**

### Task 2: Pure transformation helpers and solvers for file/metadata tasks

**Files:**
- Modify: `ico_task_solvers.py`
- Test: `tests/test_ico_task_solvers.py`

**Interfaces:**
- `solve_xor(path, output_dir, expected_hash) -> TaskResult`
- `solve_magic_bytes(path, output_dir, expected_hash) -> TaskResult`
- `solve_png_lsb(path, output_dir, expected_hash) -> TaskResult`
- `solve_sqlite(path, output_dir, expected_hash) -> TaskResult`
- `solve_wav_lsb(path, output_dir, expected_hash) -> TaskResult`
- `solve_png_ztext(path, output_dir, expected_hash) -> TaskResult`

- [x] **Step 1: Write failing tests using deterministic in-memory/file fixtures.** Cover XOR key/offset, gzip plus Base64, PNG RGB LSB MSB-first, ordered SQLite hex, WAV 16-bit LSB, zTXt zlib payload, malformed input errors, and exact hash verification.

- [x] **Step 2: Run the focused tests and verify they fail.**

- [x] **Step 3: Implement bounded helpers.** Use `gzip.decompress`, `base64.b64decode(validate=True)`, PNG chunk parsing plus all five scanline filters for 8-bit RGB, SQLite read-only connection with the stated query, `wave`/`struct` for PCM, and zTXt parsing with `zlib.decompress`. Never overwrite an input; write derived bytes below `output_dir` and record each step.

- [x] **Step 4: Run the focused tests and verify all six solvers pass.**

### Task 3: PCAP, archive, repair, and static ELF solvers

**Files:**
- Modify: `ico_task_solvers.py`
- Test: `tests/test_ico_task_solvers.py`

**Interfaces:**
- `solve_pcap(path, output_dir, expected_hash) -> TaskResult`
- `solve_archive_layers(path, output_dir, expected_hash) -> TaskResult`
- `solve_repair_header(path, output_dir, expected_hash) -> TaskResult`
- `solve_reverse_elf(path, output_dir, expected_hash) -> TaskResult`
- `solve_task(task_dir, *, output_dir, expected_hash) -> TaskResult`

- [x] **Step 1: Write failing tests for PCAP Bearer Base64, ZIP/XZ/TAR/XOR recursion, repaired ZIP/Base64, and the supplied ELF’s static XOR constants.** Assert that no test invokes the ELF and that traversal limits reject oversized archives.

- [x] **Step 2: Run focused tests and verify they fail.**

- [x] **Step 3: Implement the PCAP parser for classic pcap endianness, Ethernet/IPv4/TCP payloads, stream reassembly, and Bearer extraction. Implement bounded ZIP/TAR/XZ recursion with path containment, four-byte ZIP repair in a derived file, and Capstone-based x86-64 static reconstruction that records a failed solver result if the optional disassembler is unavailable.**

- [x] **Step 4: Run focused tests and verify all four solvers pass.**

### Task 4: Integrate task solving into the CLI report

**Files:**
- Modify: `ico_scan.py`
- Modify: `ico_scan_core.py`
- Test: `tests/test_ico_scan_cli.py`

**Interfaces:**
- Existing `run_scan(...)` continues to accept all existing arguments, discovers task dirs with `discover_task_dirs`, invokes `solve_task`, merges candidates and `task_results`, and adds solver errors as events before generic artifacts.

- [x] **Step 1: Write a failing CLI test that copies the ten supplied task directories, runs `run_scan([root])`, and expects `summary.solved_tasks == 10`, ten `hash-verified` candidates, and no task failure.**

- [x] **Step 2: Run the focused CLI test and verify it fails because task results are not integrated.**

- [x] **Step 3: Implement task discovery/integration.** Exclude recognized task directories and their generated reports from the generic queue during a task-aware root run, keep direct file behavior unchanged, merge candidates with task provenance, write `task_results` in `report.json`, and extend `report.txt` with task statuses.

- [x] **Step 4: Run the focused CLI test and inspect the generated JSON/text report.**

### Task 5: Documentation, fixture smoke test, and full verification

**Files:**
- Modify: `README.md`
- Modify: `verify.sh`
- Modify: `docs/superpowers/specs/2026-09-23-ico-scan-design.md`
- Test: `tests/test_ico_task_solvers.py`, `tests/test_ico_scan_cli.py`

- [x] **Step 1: Add the `ico-scan ico_ctf_real` command, solver coverage table, report fields, bounds, and local-only verification rules to README.**

- [x] **Step 2: Extend `verify.sh` to run the task pack only when `ICO_CTF_REAL_ROOT` is set, so the base toolkit verification remains portable.**

- [x] **Step 3: Run `python3 -m unittest discover -s tests -v` and `./verify.sh`.**

- [x] **Step 4: Run the real pack end-to-end and verify ten `hash-verified` results in a fresh report directory.**

- [x] **Step 5: Review the plan for spec coverage, placeholders, and signature consistency, then report exact output paths and validation results.**
