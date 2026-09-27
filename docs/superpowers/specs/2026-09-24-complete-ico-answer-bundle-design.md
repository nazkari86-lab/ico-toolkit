# Complete ICO Answer Bundle

## Goal

Make `ico-scan` produce a complete, copyable answer bundle for the local ICO
corpora. The bundle must combine values derived from challenge artifacts, values
extracted from saved authorized transcripts, and values copied from the supplied
historical walkthrough. It must preserve the evidence state of every value so a
historical answer cannot be mistaken for a current platform acceptance.

## Scope

The change covers the existing historical `ico_quals` pipeline and its generic
offline scanner. It includes:

- all ten known qualification task IDs;
- local solvers for Rev Zero, Can you hear, Five Shards, AEZAKMI, and Journal
  Operator;
- service-task transcript parsing for NorthStar, Backdoor, PixelMart, and VIP
  Club, plus the Wolf Protocol transcript path;
- the supplied `ICO_full_walkthrough.md` as an explicitly labelled
  `historical-reference` source;
- one machine-readable index, one human-readable index, one flat values file,
  and one solution bundle per run.

It does not add network access, platform scanning, challenge ELF execution,
password or flag guessing, or automatic submission. A service result becomes a
current local candidate only when it is present in a saved authorized transcript.

## Evidence model

Every answer value belongs to one of these states:

- `local-candidate`: derived from a supplied challenge artifact in this run;
- `transcript-derived`: extracted from a saved authorized task transcript;
- `historical-reference`: copied from the supplied walkthrough and not current
  service proof;
- `payload-ready`: a static payload exists, but no flag value has been accepted;
- `candidate-review`: an artifact was transformed but still needs manual review;
- `session-required`: the task has no local response or transcript yet.

The index keeps `local_candidates` and `historical_references` in separate
fields. The flat file remains copy-friendly with one value per line; its
historical/reference warning is recorded in `answers.md`, `solution-bundle.md`,
and the run report rather than mixed into the values.

## Processing flow

1. Discover the ICO qualification root and its ten task IDs.
2. Run the task-specific offline solver for each task.
3. Recursively locate task-named transcript files with the existing bounded
   suffix allowlist.
4. Parse flag-shaped values from transcript contents without making a request.
5. Extract walkthrough references and write one `historical-solution.md` file
   per task.
6. Deduplicate values by task and preserve first-seen evidence order.
7. Write `answers.json`, `answers.md`, `answers.txt`, and `solution-bundle.md`
   under `report/artifacts/ico-quals/answer-index/`.
8. Expose output paths and counts in the report summary and CLI output.

## Output contract

`answers.json` contains one object per task with:

- `task_id`, `status`, `solver`, and `answer_state`;
- `local_candidates` with value, evidence path, and analyzer;
- `historical_references` with value, source path, and reference-only state;
- derived artifact paths, next action, and errors.

`answers.md` presents the same matrix and the evidence-state definitions.

`answers.txt` contains one deduplicated value per line. It is a convenience
export, not a claim of current acceptance; the evidence labels remain in the
JSON/Markdown indexes.

`solution-bundle.md` lists every task, every available value, its evidence state,
and the relevant `historical-solution.md` or derived artifact.

## Failure handling

- Missing task artifacts produce `session-required` or `candidate-review`, not
  fabricated values.
- Malformed transcripts are recorded as a solver error while preserving other
  tasks' results.
- A duplicate value from local evidence and the walkthrough remains represented
  in both evidence channels.
- A parser must stay within the existing file, byte, depth, and candidate
  limits.

## Verification

Add or update tests to prove that:

- all ten task IDs are present in every answer index;
- the two Backdoor walkthrough values are retained as
  `historical-reference` values;
- a Backdoor transcript produces `transcript-derived` candidates without a
  network call;
- values are deduplicated in `answers.txt` while evidence remains separate in
  JSON/Markdown;
- malformed or missing transcripts do not create candidates;
- the real `ico_ctf_real` ten-task hash-verified regression remains unchanged;
- the full test suite and `./verify.sh` pass.

## Acceptance criteria

The feature is complete when a clean local run over `$ICO_QUALS_ROOT`
creates all four answer-bundle files, lists all ten tasks, preserves all known
walkthrough values, parses an authorized transcript offline, and makes zero
network requests or platform submissions.
