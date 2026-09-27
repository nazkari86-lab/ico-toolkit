# External CTF Coverage Audit Implementation Plan

> Execute inline in the current task. The user explicitly asked for a direct audit and repairs.

**Goal:** Re-run the locally available external CTF corpus through the toolkit, identify concrete misses, and repair high-confidence solver gaps with regression evidence.

**Architecture:** Use existing offline task-aware profiles and saved corpus artifacts. For each miss, compare the challenge's supplied/reference logic with the toolkit, add a failing local regression test, implement the smallest correction, and preserve evidence states. Results are limited to the checked local corpus; they do not imply universal CTF coverage or platform acceptance.

**Tech Stack:** Python, unittest/pytest, existing optional analysis tools.

**Spec:** User request in the current Codex task; repository constraints and evidence schema in `README.md`, `verify.sh`, and local CTF evidence playbook.

## Global Constraints

- Analyze local challenge artifacts and public challenge/reference source only; do not contact challenge services or submit flags.
- Do not brute-force candidate flag strings or execute challenge binaries/macros.
- Preserve `candidate`, `payload-ready`, `candidate-review`, `requires-authorized-session`, local verification, and platform confirmation as distinct states.
- Treat missing optional dependencies as an explicit coverage result, not as a solver pass.
- A solver is counted as locally solved only when its output is validated by the supplied checker/reference transformation or a known independent oracle.

---

### Task 1: Establish an honest current baseline

**Files:**
- Read: `README.md`, `verify.sh`, external corpus reports and artifacts under `/tmp/ico-external-ctf`
- Create: `docs/superpowers/plans/2026-09-27-external-ctf-audit.md` (this plan)
- Test: existing focused external CTF test modules and saved corpus scan reports

**Interfaces:**
- Consumes: current toolkit CLI, report JSON schema, local downloaded corpus roots.
- Produces: a concise per-corpus status table with run freshness and explicit unmet evidence/dependency gates.

- [ ] Inspect the configured virtual environment and run the DUCTF AES profile with that interpreter.
- [ ] Summarize only the latest report for each distinct corpus; ignore superseded repeated runs.
- [ ] Record exact task counts, local candidate states, unresolved tasks, and skipped profiles without promoting old evidence.

### Task 2: Repair one reproduced external-task miss

**Files:**
- Modify: `ico_external_aes.py` or the specific solver confirmed by Task 1
- Test: corresponding `tests/test_ico_external_aes.py` or existing profile test module
- Read: the challenge's supplied source and authoritative public reference solver

**Interfaces:**
- Consumes: parsed local task files and the reference algorithm.
- Produces: a bounded offline solver result that passes a forward/reference check, or an explicit unsupported/review result with the missing dependency stated.

- [ ] Add a regression assertion that fails against the currently observed wrong output.
- [ ] Run that test before implementation and confirm it fails for the algorithmic reason.
- [ ] Implement the smallest reference-consistent correction.
- [ ] Re-run the exact task test and ensure the output is independently checkable.

### Task 3: Retest the corpus and document remaining gaps

**Files:**
- Read/modify: `README.md` only if run behavior or coverage claims need correction
- Create: a dated audit report under `ico-scan-runs/` with source corpus, command, statuses, and verification limits
- Test: targeted module, relevant full suite, and `./verify.sh`

**Interfaces:**
- Consumes: fixed solver and baseline corpus.
- Produces: fresh measured coverage, remaining task-level misses, and exact test output.

- [ ] Run relevant task-aware corpus scans using the configured environment.
- [ ] Run the full project verification script after targeted tests.
- [ ] Report what was solved locally, what remains unresolved, and whether any external/platform confirmation exists.

---

