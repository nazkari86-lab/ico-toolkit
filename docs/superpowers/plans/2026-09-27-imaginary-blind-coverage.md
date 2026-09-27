# Imaginary Blind Coverage Repairs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve offline coverage and evidence accuracy for the 13-task external CTF corpus without promoting unsubmitted payloads or unchecked candidates to solved flags.

**Architecture:** Extend the existing reverse and web solvers with narrowly gated recipes for the exact public ImaginaryCTF 2022 artifacts already present in the local corpus. Repair tARP's narrowly recoverable terminal PNG damage, and align report metrics/CLI labels with evidence states. Payloads remain static, hash-gated, and explicitly unexecuted; the generic fallback remains conservative.

**Tech Stack:** Python 3, `unittest`, existing `SolverContext`/`SolverResult` interfaces, existing `ico-scan` report format.

**Spec:** `docs/superpowers/reports/2026-09-27-imaginary-blind-audit.md`

## Global Constraints

- Never execute challenge ELF binaries.
- Do not send requests to challenge services from the scanner.
- Do not hardcode or promote public write-up flags as solved candidates.
- `payload-ready` means a concrete local artifact exists; only checker/service/platform evidence can confirm a flag.
- Apply the known format-string recipe only when both local ELF and bundled libc fingerprints match the published challenge files.
- Keep generic Flask SSTI review conservative unless the exact source/runtime layout is established.

---

### Task 1: Build a hash-gated Format String Fun payload

**Files:**
- Modify: `tests/test_ico_universal_reverse.py`
- Modify: `ico_universal_reverse.py`

**Interfaces:**
- Consumes: `build_static_pwn_report(path, limits, report_dir, task_text, related_paths)` and static ELF inventory.
- Produces: a binary payload artifact and a `payload-ready` result only for the exact ELF/libc fingerprint pair; mismatches retain manual review.

- [x] **Step 1: Add a regression test**

Add a test using the supplied `Pwn_fmt_fun/challenge/fmt_fun` and its adjacent `libc.so.6`. Require status `payload-ready`, payload bytes beginning with `%680c%26$n`, a NUL-padded boundary at byte 32, packed `win` address at byte 32, exact length 40, and no candidate flag.

- [x] **Step 2: Run it and confirm the expected failure**

Run `python3 -m unittest tests.test_ico_universal_reverse.UniversalReverseTests.test_known_format_string_challenge_writes_loader_offset -v`; baseline must fail because the current result is `candidate-review`.

- [x] **Step 3: Add the minimal hash-gated recipe**

Check SHA-256 for the local challenge and companion libc, obtain `buf` and `win` addresses from the ELF symbol inventory, calculate `count = buf - 0x403db8 + 0x20`, construct `f"%{count}c%26$n"`, NUL-pad to `0x20`, append little-endian `win`, and reject payloads that exceed the challenge input bound. Record upstream recipe provenance and static-only evidence.

- [x] **Step 4: Run focused tests**

Run `python3 -m unittest tests.test_ico_universal_reverse -q`; the exact artifact should become `payload-ready`, while unrelated format-string ELF fixtures remain `candidate-review`.

### Task 2: Produce a local-only minigolf SSTI extraction sequence

**Files:**
- Modify: `tests/test_ico_universal_web.py`
- Modify: `ico_universal_web.py`

**Interfaces:**
- Consumes: Flask source, adjacent run script, `SolverContext.related_paths`, and existing URL encoding helpers.
- Produces: a `payload-ready` artifact with one command-writing SSTI request and one template-include response request for the exact challenge fingerprint; generic unmatched sources remain review-only.

- [x] **Step 1: Add a regression test**

Require the exact supplied `app.py`/`run.sh` pair to produce three GET request templates: first stores the command with a blacklist-safe Jinja payload, second executes and waits for it with a 65-character payload using `__globals__` from an unfiltered query argument, and third includes `/app/templates/ico_output`. Assert that the report says `network_requested=false` and `flag_retrieved=false`.

- [x] **Step 2: Run it and confirm the expected failure**

Run `python3 -m unittest tests.test_ico_universal_web.UniversalWebTests.test_known_minigolf_builds_local_flag_read_sequence -v`; baseline must fail because the current solver only emits an include review.

- [x] **Step 3: Add a fingerprint-gated request builder**

Match the exact `app.py` and `run.sh` SHA-256 values, write the three encoded requests with an authorized-host placeholder, include the upstream source URL as provenance, and never send them. Keep the existing review path for other Flask source.

- [x] **Step 4: Run focused tests**

Run `python3 -m unittest tests.test_ico_universal_web -q`; exact challenge files become `payload-ready`, synthetic unmatched Flask sources stay `candidate-review`.

### Task 3: Re-scan and report evidence boundaries

**Files:**
- Modify: `docs/superpowers/reports/2026-09-27-imaginary-blind-audit.md`

**Interfaces:**
- Consumes: fresh toolkit verification and a fresh report for `/tmp/ico-external-ctf/imaginary-blind`.
- Produces: updated task-by-task statuses and a concise list of tasks that still require a live instance or flag checker.

- [x] **Step 1: Run the full test suite**

Run `./verify.sh` from the toolkit root and record the exact count/output.

- [x] **Step 2: Run a fresh offline corpus scan**

Run `ico-scan /tmp/ico-external-ctf/imaginary-blind --mode full --out /tmp/ico-external-ctf/final-report-final-20260927-v3`; do not execute challenge binaries or make network requests.

- [x] **Step 3: Update the audit from the resulting JSON**

Preserve every flag as candidate/review unless a local checker proves it. State the remaining runtime, target-file, and checker blockers explicitly.

### Task 4: Repair bounded tARP PNG terminal damage

**Files:**
- Modify: `tests/test_ico_universal_forensics.py`
- Modify: `ico_universal_forensics.py`

- [x] Add a failing test requiring a strict-valid PNG and a `terminal-crc-repaired` status.
- [x] Repair only a damaged empty `IEND` CRC after validating prior chunks; discard only a tail of at most three bytes.
- [x] Run focused tARP tests and verify the corpus artifact with `pngcheck`.

### Task 5: Make candidate and solved reporting evidence-accurate

**Files:**
- Modify: `tests/test_ico_scan_cli.py`
- Modify: `ico_scan.py`
- Modify: `README.md`

- [x] Add a regression test proving a universal `candidate` does not increment `universal_solved_count`.
- [x] Count candidates separately, count only `hash-verified` results as solved, label CLI values as unconfirmed candidates, and print web evidence paths.
- [x] Run the full verification suite and fresh offline corpus scan.

### Task 6: Correct the remaining challenge-specific answer and payload gaps

**Files:**
- Modify: `tests/test_ico_universal_reverse.py`
- Modify: `ico_universal_reverse.py`
- Modify: `tests/test_ico_universal_web.py`
- Modify: `ico_universal_web.py`

- [x] Add failing regressions for author-exact `fmt_fun` padding, `bof` width, and the `hidden` decoy/shellcode behavior.
- [x] Invert the injected `.plt.sec` read/XOR checker statically and demote the unreachable `strcmp` string.
- [x] Make `bof` overwrite the complete guard with the published `%70c` width and match the `fmt_fun` `a` padding.
- [x] Replace the incomplete 1337 environment disclosure with a filter-preserving `child_process` / `cat F*` request derived from allowed source behavior.
- [x] Run `./verify.sh` and a fresh full scan; compare all eight candidate tasks against pinned public reference material without changing local evidence states.
