# Complete ICO Answer Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the existing offline ICO scanner emit a complete, evidence-labelled answer bundle that includes local candidates, authorized-transcript results, and historical walkthrough values.

**Architecture:** Keep `ico_quals_solvers.py` as the single owner of qualification task evidence and bundle generation. Add an explicit evidence state for transcript-derived values, preserve the existing separation between current candidates and walkthrough references, and verify the full output through focused unit tests plus the existing corpus integration tests.

**Tech Stack:** Python 3.14, `unittest`, `pathlib`, existing `ico-scan` CLI, JSON/Markdown/text report artifacts.

**Spec:** `docs/superpowers/specs/2026-09-24-complete-ico-answer-bundle-design.md`

## Global Constraints

- The scanner remains offline and read-only for challenge inputs.
- It must not contact `cyberolympiad.kz`, scan the platform, brute-force flags, execute challenge ELF files, or submit answers.
- Historical walkthrough values remain `historical-reference` and are never promoted to current platform proof.
- Saved authorized transcripts are parsed locally and are the only source that can produce `transcript-derived` service candidates.
- Existing limits (`MAX_BYTES`, `MAX_FILES`, recursion depth, and candidate bounds) remain in force.
- The existing ten-task `ico_ctf_real` hash-verified regression must stay unchanged.

---

### Task 1: Make transcript evidence explicit

**Files:**
- Modify: `ico_quals_solvers.py` (`_add_candidates`, `solve_service_task`, `solve_wolf_protocol`, `build_qual_answer_matrix`)
- Test: `tests/test_ico_quals_solvers.py`

**Interfaces:**
- `_add_candidates(result, values, *, evidence, state="candidate", **metadata)` keeps the existing result mutation but writes the supplied evidence state into each candidate.
- `solve_service_task` and `solve_wolf_protocol` pass `state="transcript-derived"` when values came from a saved transcript.
- `build_qual_answer_matrix` reports `answer_state="transcript-derived"` when a task has transcript values and no local or historical values, and `answer_state="local-and-transcript"` when both evidence types exist.

- [x] **Step 1: Write the failing tests for transcript evidence.**

Add to `tests/test_ico_quals_solvers.py`:

```python
def test_service_transcript_candidates_are_labelled_transcript_derived(self):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        transcript = root / "backdoor.transcript"
        transcript.write_text("response flag=ico{from_authorized_transcript}\n", encoding="utf-8")
        result = solve_service_task("backdoor", root / "report", transcript=transcript)
        matrix = build_qual_answer_matrix([result])

    self.assertEqual(result.candidates[0]["state"], "transcript-derived")
    self.assertEqual(matrix[1]["answer_state"], "transcript-derived")

def test_local_and_transcript_values_keep_both_evidence_channels(self):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        transcript = root / "backdoor.transcript"
        transcript.write_text("ico{from_authorized_transcript}\n", encoding="utf-8")
        result = solve_service_task("backdoor", root / "report", transcript=transcript)
        result.candidates.append({"value": "ico{from_local_artifact}", "state": "candidate"})
        matrix = build_qual_answer_matrix([result])

    self.assertEqual(matrix[1]["answer_state"], "local-and-transcript")
    self.assertEqual(
        {item["value"] for item in matrix[1]["local_candidates"]},
        {"ico{from_authorized_transcript}", "ico{from_local_artifact}"},
    )
```

- [x] **Step 2: Run the focused tests and verify they fail.**

Run:

```sh
python3 -m unittest tests.test_ico_quals_solvers.RealQualsSolverTests.test_service_transcript_candidates_are_labelled_transcript_derived tests.test_ico_quals_solvers.RealQualsSolverTests.test_local_and_transcript_values_keep_both_evidence_channels -v
```

Expected: FAIL because transcript values currently use the generic `candidate` state and the matrix does not distinguish them.

- [x] **Step 3: Implement the smallest evidence-state change.**

Update `_add_candidates` to accept `state: str = "candidate"`, set both the candidate `state` and its verification `status` to that state, and leave the result task status as `candidate`. Pass `state="transcript-derived"` from the two transcript branches. In `build_qual_answer_matrix`, inspect candidate states before historical references and choose `transcript-derived` or `local-and-transcript` when applicable; retain `local-candidate` and `historical-reference` for the existing paths.

- [x] **Step 4: Run the focused tests and verify they pass.**

Run the same two `unittest` selectors. Expected: PASS.

- [x] **Step 5: Run the complete qualification solver tests.**

Run:

```sh
python3 -m unittest tests.test_ico_quals_solvers -v
```

Expected: all qualification solver tests pass, including PixelMart and VIP Club transcript-derived payload generation.

### Task 2: Prove the complete answer bundle contract

**Files:**
- Modify: `tests/test_ico_quals_solvers.py`
- Modify: `tests/test_ico_scan_cli.py`
- Modify: `ico_quals_solvers.py` only if a failing contract test identifies a missing artifact or count

**Interfaces:**
- `write_qual_answer_index(results, output_dir)` continues to return `json`, `markdown`, `text`, `bundle`, `task_count`, `historical_task_count`, and `historical_answer_count`.
- The four returned paths must exist, and `answers.txt` must contain one deduplicated value per line with no evidence labels mixed into the copyable values.

- [x] **Step 1: Add a failing bundle regression test.**

Extend the answer-index test with two local/transcript values and two duplicate historical references, then assert:

```python
paths = {key: Path(index[key]) for key in ("json", "markdown", "text", "bundle")}
self.assertTrue(all(path.is_file() for path in paths.values()))
self.assertEqual(
    paths["text"].read_text(encoding="utf-8").splitlines(),
    ["ico{from_authorized_transcript}", "ico{from_local_artifact}", "ico{historical_fixture}"],
)
self.assertIn("ico{historical_fixture}", paths["bundle"].read_text(encoding="utf-8"))
self.assertIn("reference-only", paths["markdown"].read_text(encoding="utf-8"))
```

- [x] **Step 2: Run the focused regression and verify the current output contract.**

Run:

```sh
python3 -m unittest tests.test_ico_quals_solvers.RealQualsSolverTests.test_answer_matrix_keeps_local_and_historical_states_separate -v
```

Expected: PASS after the expanded assertions; if it fails, fix only the bundle writer's deterministic ordering or artifact path handling.

- [x] **Step 3: Strengthen the real-pack CLI integration assertions.**

In `tests/test_ico_scan_cli.py`, extend `test_scan_discovers_real_ico_quals_pack_and_keeps_service_statuses` to assert that the returned text and bundle paths exist, that the text file contains the two local candidates plus historical values, and that `solution-bundle.md` lists `backdoor` and `journal-operator`. Keep the existing task/status/count assertions unchanged.

- [x] **Step 4: Run the real-pack integration test.**

Run:

```sh
python3 -m unittest tests.test_ico_scan_cli.TestScanCLI.test_scan_discovers_real_ico_quals_pack_and_keeps_service_statuses -v
```

Expected: PASS with ten tasks, twelve historical references, two local candidate tasks, two payload-ready tasks, five session-required tasks, and one candidate-review task.

### Task 3: Document the copyable full-output workflow and verify the release

**Files:**
- Modify: `README.md`
- Modify: `tests/test_ico_scan_cli.py` only if CLI output needs a regression assertion

**Interfaces:**
- The documented command `ico-scan $ICO_QUALS_ROOT --show-references --out <dir>` produces the four answer-index files.
- The README explicitly states that `answers.txt` is copy-friendly but may contain historical references, while `answers.json`/`answers.md` carry evidence labels.

- [x] **Step 1: Add the workflow documentation.**

Document the four output paths, the transcript naming convention (`backdoor.transcript`, `pixelmart.log`, etc.), and the distinction between `transcript-derived`, `local-candidate`, `payload-ready`, and `historical-reference`.

- [x] **Step 2: Run the full verification suite.**

Run:

```sh
./verify.sh
```

Expected: the full unittest suite reports zero failures, the fixture smoke checks pass, and the binary stack check remains successful.

- [x] **Step 3: Run a fresh real-quals scan and inspect the emitted files.**

Run:

```sh
out_dir=$(mktemp -d /tmp/ico-all-flags.XXXXXX)
./ico-scan $ICO_QUALS_ROOT --show-references --out "$out_dir"
test -s "$out_dir/artifacts/ico-quals/answer-index/answers.json"
test -s "$out_dir/artifacts/ico-quals/answer-index/answers.md"
test -s "$out_dir/artifacts/ico-quals/answer-index/answers.txt"
test -s "$out_dir/artifacts/ico-quals/answer-index/solution-bundle.md"
```

Expected: CLI prints the complete flat values list, the report records ten tasks, and no network request or submission is made.

- [x] **Step 4: Record the final evidence boundary.**

Report the fresh output directory and distinguish local/transcript-derived values from walkthrough references. Do not claim that a historical value was accepted by the current platform.
