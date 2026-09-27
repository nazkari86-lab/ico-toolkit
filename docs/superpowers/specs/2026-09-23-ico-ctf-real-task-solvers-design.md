# ICO CTF real task-solvers design

## Goal

Make `ico-scan` solve the complete local `ico_ctf_real` pack in one offline run, while retaining the existing generic triage fallback for files that do not belong to a recognized task directory.

## Scope and safety

- Input is a local directory or task directory containing the supplied challenge artifacts and `task.txt`.
- Solvers use only the transformations stated by each local task condition: decompression, decoding, bit extraction, database reads, packet parsing, and bounded static analysis.
- No network requests, port scans, password dictionaries, flag guessing, platform submissions, or arbitrary challenge-binary execution are performed.
- Original challenge files are read-only. Derived artifacts and step logs are written below the per-run report directory.
- A candidate is `hash-verified` only when its exact UTF-8 bytes match the corresponding entry in the supplied `flag_hashes.json`; otherwise it remains `candidate`.

## User interface

The existing command remains the entry point:

```sh
source $ICO_TOOLKIT_ROOT/env.sh
ico-scan $ICO_CTF_REAL_ROOT
```

When a directory contains one or more child directories with `task.txt`, `ico-scan` discovers those task groups and runs a task solver before the generic file profiles. Direct single-file inputs continue to use the existing generic pipeline and XOR analyzer.

The report adds `task_results` and summary counts for solved tasks, selected task artifacts, and derived evidence (`summary.solved_tasks`, `summary.task_artifact_count`, and `summary.derived_artifact_count`). The derived-evidence count is the number of unique output paths across task, qualification, and universal solver results; repeated references count once. Each task result contains the task directory, selected solver, ordered evidence steps, derived artifact paths, candidate values, and verification status. The text report labels generic and derived artifacts separately. Existing `candidates` entries remain available and gain `task_id`/`verification` fields when produced by a task solver.

## Task solver registry

`ico_task_solvers.py` owns a standard-library-first registry. The dispatcher has the interface:

```python
solve_task(task_dir: Path, *, output_dir: Path,
           expected_hash: str | None) -> TaskResult
```

The dispatcher reads `task.txt`, selects the artifact in that task directory, and invokes the registered solver with the same output and verification context.

The registry selects by explicit task wording and artifact signatures, in this order:

1. `xor-single-byte`: scan keys `0..255` for a `CTF{` crib and preserve key/offset.
2. `magic-bytes`: identify gzip from bytes, decompress, and Base64-decode the payload.
3. `png-lsb-rgb`: parse PNG scanlines, undo filters, read RGB LSBs from the first pixel in MSB bit order.
4. `pcap-http-bearer`: parse offline PCAP frames, reassemble TCP payloads, extract `Authorization: Bearer`, and Base64-decode it.
5. `sqlite-cache-hex`: query ordered `cache_entries.value` cells and concatenate hex-decoded bytes.
6. `reverse-elf`: disassemble the supplied x86-64 ELF statically with Capstone when available, reconstruct the password XOR and output XOR buffers, and never launch the ELF.
7. `archive-layers`: safely recurse through ZIP, XZ, TAR, and final single-byte XOR, bounded by the existing archive limits.
8. `repair-header`: restore the ZIP local-header magic `PK\\x03\\x04` in a derived copy, extract it, and Base64-decode the child text.
9. `wav-lsb`: read 16-bit PCM samples, collect sequential LSBs MSB-first, and stop at NUL.
10. `png-ztext`: parse PNG `zTXt`, zlib-decompress the text, and Base64-decode the resulting value.

All decoders scan their derived text with the shared flag matcher. Solver-specific metadata (key, offset, bit order, chunk name, SQL query, packet stream, or repair bytes) is attached to the candidate and evidence log.

## Detection and fallback

Task discovery ignores report directories and hidden files. If a task condition or artifact does not match a registered solver, the result is `unsupported` with an evidence step explaining why, and the generic scanner still runs over the supplied files. A solver failure is recorded per task and does not abort other tasks.

## Verification and tests

- Unit tests cover each transformation with a small deterministic fixture, malformed-input handling, bounds, and hash verification.
- An end-to-end test copies the ten supplied task directories to a temporary workspace, runs one command, and expects ten hash-verified flags and no task failures.
- Existing 18 generic toolkit tests and `verify.sh` remain green.
