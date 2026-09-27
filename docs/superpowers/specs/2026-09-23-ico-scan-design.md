# ico-scan design

## Goal

Provide one local command that accepts one or more files and directories, identifies each artifact, selects relevant offline CTF analyzers, follows extracted child artifacts, and reports flag-shaped evidence with the exact source and command that produced it.

## Scope and safety

- Input is local files or directories supplied by the user.
- No HTTP requests, port scans, platform interaction, flag submission, password dictionaries, or flag guessing are performed.
- Installed web tools remain available for manual, explicitly authorized task endpoints; `ico-scan` never invokes them automatically.
- Password-protected stego containers are inspected for metadata only. StegSeek wordlist cracking and similar guessing modes are excluded.
- Extracted content is written below a per-run directory; extracted binaries are inspected as bytes and never executed.

## User interface

```text
ico-scan PATH [PATH ...]
ico-scan --out REPORT_DIR PATH [PATH ...]
ico-scan --flag-regex REGEX PATH [PATH ...]
```

The default report directory is `./ico-scan-runs/<timestamp>-<random>` relative to the current directory. The command prints progress, confirmed pattern matches, skipped tools, and a final report path. It supports files, directories, and repeated paths in one invocation. Limits are configurable for tool timeout, recursion depth, file count, and extracted bytes.

## Pipeline

1. Canonicalize and de-duplicate input paths.
2. Identify each item with `file --brief --mime-type` and `file --brief`, plus extension and magic-byte hints.
3. Run universal analyzers in a deterministic order: raw/Unicode strings, metadata, file signatures, and safe format checks.
4. Run class-specific analyzers:
   - PNG/BMP: `zsteg -a`, `pngcheck`.
   - JPEG/WAV/AU: `steghide info` without a password, metadata, strings.
   - Archives/documents: `7zz` listing and bounded extraction, then recurse.
   - PDF: `qpdf --check`, metadata, text extraction when present.
   - PCAP: offline `tshark` summary and strings.
   - Memory dumps: offline Volatility 3 `windows.info` and `linux.banners` probes.
   - Native/bytecode binaries: strings and read-only radare2 inspection.
   - Generic media/unknown data: `ffprobe`, metadata, binwalk signatures, strings.
5. Scan every text result and bounded raw byte view with configurable flag patterns. Each hit records artifact, analyzer, output file, line, and classification state.
6. For generic data, native binaries, and text artifacts, run a bounded single-byte XOR crib analysis for common flag prefixes; record the recovered key and offset with the candidate provenance.
7. Write `report.json`, human-readable `report.txt`, command logs, and extracted children. Continue after tool failures and record them as non-fatal events.

When the input contains child directories with `task.txt`, the task-aware registry in `ico_task_solvers.py` runs before this generic queue. It applies condition-specific offline decoders, records `task_results`, and uses a supplied `flag_hashes.json` only for local SHA-256 verification. Task directories and pack control files are excluded from the fallback queue to avoid reporting instructional placeholders as flags.

## Components

- `ico_scan.py`: CLI, queue, classification, subprocess runner, bounded extraction, match scanner, report writer.
- `env.sh`: exposes the local virtualenv and custom stego binaries.
- `verify.sh`: smoke checks for the installed toolchain.

The implementation uses only Python standard-library modules. External tools are invoked with argument arrays, never through a shell. Missing tools are skipped and recorded instead of aborting the run.

## Evidence model

Every match is marked `candidate` until an original challenge checker or explicitly authorized service confirms it. The tool never labels a string as platform-confirmed and never submits it. Identical values are de-duplicated per source artifact; when several analyzers or lines support the same value, their analyzer names, lines, and log sources are retained in `analyzers` and `evidence_sources`.

## Validation

- Unit-level checks cover classification, regex matching, command timeout/error recording, path de-duplication, and bounded extraction decisions.
- An end-to-end fixture contains a PNG with an embedded flag-like string and a nested archive; the CLI must discover both the direct and extracted evidence and produce a valid JSON report.
- A negative fixture containing ordinary text with the word `flag` but no brace-form value must produce no flag match.
