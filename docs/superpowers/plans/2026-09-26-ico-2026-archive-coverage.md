# ICO 2026 Archive Coverage Implementation Plan

> **For agentic workers:** Execute this plan inline in the active task and preserve each checkpoint in the report.

**Goal:** Let `ico-scan` analyze real ICO archive inputs directly, including large solid archives, while preserving bounded extraction and clear evidence states.

**Architecture:** Parse archive listings into individual safe members, select files within the existing byte and file limits, and pass those exact members to 7-Zip. Keep the ordinary recursive scanner as the analysis engine; add task-aware interpretation only when actual local artifacts establish a reproducible method.

**Tech Stack:** Python 3.12, existing `ico_scan_profiles.py` and `ico_scan.py`, 7-Zip, existing solver registry.

**Spec:** The public `herachxx/ico-2027` repository's archived ICO 2026 challenge screenshots, challenge list PDF, and `ICO_archived/README.md`; downloaded archive metadata and files under `/tmp/ico_archived_files.7z` and `/tmp/ico-2026-artifacts/`.

## Global Constraints

- Keep scanner inputs read-only and never submit flags or contact competition services.
- Do not execute challenge binaries or guess passwords or flags.
- Respect `max_bytes`, `max_files`, and `max_depth`; reject unsafe archive paths and symlinks.
- Preserve candidates, payload-ready results, and service-required work as distinct evidence states.
- The 4.64 GB and 737 MB disk-image archives exceed the default 100 MiB expansion budget and must be reported as skipped.

---

### Task 1: Extract bounded archive members instead of refusing an oversized pack

**Files:**
- Modify: `ico_scan_profiles.py`
- Modify: `ico_scan.py`

**Interfaces:**
- Add an `ArchiveMember` record with `path`, `size`, and `is_directory` fields.
- Parse `7zz l -slt` into member records and store selected/skipped members on `ExtractionResult`.
- Keep `ArchiveExtractor.extract(path, classification, destination)` backward compatible; add an extraction timeout parameter with a bounded default of 300 seconds.

- [ ] Parse the listing after its member separator. Reject absolute paths, `..`, backslashes, wildcards, symlinks, and entries with invalid sizes.
- [ ] Select regular members in archive order while cumulative declared size is at most `max_bytes` and count is at most `max_files`.
- [ ] Invoke `7zz x` with the selected exact member names, then verify every discovered path remains beneath the destination and that actual totals stay within limits.
- [ ] Add `partial`, `selected_entries`, and `skipped_entries` to the archive report. Explain each skip reason, including oversized members and file-count limits.
- [ ] Pass the bounded archive timeout from `run_scan` and keep generic scanning of extracted children unchanged.
- [ ] Manually run `ico-scan /tmp/ico_archived_files.7z --max-bytes 104857600 --max-files 200 --timeout 300 --out /tmp/ico-2026-direct-scan` and compare extracted paths and skipped entries with `7zz l -slt`.

### Task 2: Establish real ICO 2026 coverage from extracted artifacts

**Files:**
- Modify only solver modules that have a reproducible local artifact or checker.
- Update `README.md` with verified 2026 archive behavior and per-task evidence states.

**Interfaces:**
- Reuse `SolverContext`, `SolverResult`, and `build_default_registry()`.
- Any task-specific solver must identify its input by content or task evidence, never by returning a hardcoded answer for an unrelated file.

- [ ] Run the ordinary scanner on the extracted members and inspect its `report.json`, tool transcript, and nested artifacts.
- [ ] Map each discovered artifact to the archived task list using actual filenames and challenge descriptions.
- [ ] Prioritize offline-solvable PCAP, script, map, and static reverse tasks; keep live-service tasks as service-required unless a saved authorized transcript is present.
- [ ] For every solver addition, reproduce the transform from the supplied file or checker and record the exact evidence path and state.
- [ ] Re-run the direct archive scan after changes and report actual task coverage, skipped files, failures, and remaining service or disk-image work.
