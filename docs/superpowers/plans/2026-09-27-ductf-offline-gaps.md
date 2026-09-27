# DownUnderCTF Offline Coverage Gaps Implementation Plan

> **For agentic workers:** Execute this plan inline in the existing workspace. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add independently testable offline support for the two DownUnderCTF 2024 artifacts with directly recoverable local values, and give the stateful XOR challenge a bounded crib-analysis report instead of an unsupported result.

**Architecture:** Add a task-aware profile to the default registry so normal `ico-scan` runs can use task-local peer files and bounded resources. Keep VBA static-only, password cracking local and dictionary-only, and all recovered flag strings at `candidate` evidence state unless a local checker verifies them. Three Line remains review-only unless the complete key and flag can be established from local evidence.

**Tech Stack:** Python 3, existing `SolverContext`/`SolverResult`, `unittest`, `oletools` as an optional static VBA parser, Impacket local hive APIs, hashcat dictionary mode, and `tshark` when present.

**Spec:** `/tmp/ico-external-ctf/ductf2024-blind` and the saved full audit `/tmp/ico-external-ctf/ductf2024-audit-full-with-tls-20260927/report.json`.

## Global Constraints

- Read only local challenge artifacts; do not contact challenge services or submit flags.
- Never execute challenge binaries or macros.
- Use explicit file, archive, runtime, and password-wordlist bounds.
- Do not hardcode published flags, passwords, challenge answers, or challenge artifact hashes.
- Keep recovered values as unconfirmed local candidates unless an original local checker verifies them.
- Preserve existing toolkit behavior for unrelated CTFs and ICO corpora.

---

### Task 1: Add regression tests for the three observed coverage gaps

**Files:**
- Create: `tests/test_ico_external_ctf.py`

**Interfaces:**
- Consume the solver from `build_default_registry()` and its `_crack_ntlm_hash()` helper.
- Tests construct small synthetic task directories and call the registered solver interface.

- [x] Add tests showing that a static VBA source plus a captured decimal URL yields the XOR-decoded value only when the key is derived from the VBA literals.
- [x] Add a test showing that hashcat can recover a synthetic NTLM test password only from a supplied bounded local dictionary.
- [x] Add a test showing that the stateful XOR profile writes bounded crib hypotheses without inventing a flag.
- [ ] Run the three focused tests and confirm each fails because the relevant solver path is absent.

### Task 2: Implement task-local forensics recovery

**Files:**
- Create: `ico_external_ctf.py`
- Modify: `ico_universal_registry.py`
- Modify: `requirements-optional-forensics.txt`
- Modify: `README.md`

**Interfaces:**
- Add a bounded task-aware profile consumed from the default registry.
- Preserve the normal `SolverResult` schema and include evidence paths, commands, resource limits, and missing-tool notes in `steps`.

- [ ] Parse VBA source with `oletools` without opening or executing Excel; derive the XOR key only from literal macro assignments.
- [ ] Read the paired capture with `tshark` in offline mode, normalize captured request URIs, and decode only decimal-byte sequences supported by the macro transform.
- [ ] Extract `sam.bak` and `system.bak` from local containers with path and size checks; invoke Impacket's local SAM parser only.
- [ ] If an explicit local wordlist is configured or found in a standard wordlist location, run a single-user NTLM dictionary check with a strict timeout; otherwise emit a review reason naming the missing wordlist.
- [ ] Emit recovered flag-shaped strings as `candidate`; never label an unrecoverable dictionary task as solved.
- [ ] Run the focused forensics tests and the existing forensics test module.

### Task 3: Implement bounded stateful XOR crib analysis

**Files:**
- Modify: `ico_external_ctf.py`
- Modify: `tests/test_ico_external_ctf.py`
- Modify: `README.md`

**Interfaces:**
- Consume paired source and ciphertext through `SolverContext.related_paths`.
- Return no flag candidate from partial key guesses; retain the crib analysis as a review artifact.

- [ ] Recognize the state transition `key[previous_plaintext_byte % 16] XOR ciphertext_byte` only when the paired source declares the same transition.
- [x] Search repeated ciphertext word spans against a bounded common-English crib set and merge only conflict-free key-byte assignments.
- [x] Save ranked crib and key-byte hypotheses as a local review artifact; keep it `candidate-review` until a complete plaintext and flag are derived.
- [ ] Run the focused task-aware tests and both existing crypto and forensics test modules.

### Task 4: Re-audit both local public corpora and document limits

**Files:**
- Modify: `docs/superpowers/reports/2026-09-27-ductf-offline-audit.md`
- Modify: `/tmp/ico-external-ctf/ductf2024-audit-full-with-tls-20260927/audit-journal.md`

- [ ] Run `./verify.sh` and record its fresh test count and exit status.
- [ ] Run fresh full scans over `/tmp/ico-external-ctf/ductf2024-blind` and `/tmp/ico-external-ctf/imaginary-blind` with separate report directories.
- [ ] Compare task coverage before and after; report candidates, review tasks, tasks requiring live services, and missing resource gates separately.
- [ ] State explicitly that arbitrary future CTFs cannot be guaranteed solvable by a universal file-only tool.
