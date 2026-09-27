# ICO Final-50 benchmark design

## Goal

Create a deterministic, offline benchmark that approximates the announced ICO
final format: ten independent stories, each with one Web, Pwn, Forensics,
Reverse, and Crypto subtask. The benchmark is for improving and measuring the
local `ico-solve` pipeline. It is not a prediction of the real final and it
does not contact the ICO platform or any external service.

The primary success measure is 50/50 expected answers verified by an external
hash/checker manifest, with zero false positives. A string that merely looks
like a flag is not a solved task.

## Scope and non-goals

Included:

- 50 generated task roots under `benchmarks/ico_final_50/`.
- 10 stories × 5 families, with Easy, Medium, and Hard mechanisms distributed
  across the stories.
- A generator that is deterministic from a recorded seed and safe to rerun.
- A score script that consumes the solver report and a manifest outside the
  scan root.
- Regression tests for generation, task discovery, exact verification,
  duplicate suppression, unsupported cases, and false-positive accounting.

Excluded:

- Requests to `cyberolympiad.kz` or any live contest infrastructure.
- Automatic flag submission or interaction with a contest account.
- Brute-forcing flag values, passwords, or service state.
- Executing generated or supplied challenge binaries. Native Pwn/Reverse
  cases are static-analysis and payload-readiness cases unless a future,
  separately reviewed sandbox is added.
- Claiming that synthetic coverage predicts the real final score.

## Corpus layout

Each task has its own directory:

```text
benchmarks/ico_final_50/
  story_01/
    web_easy/
    pwn_medium/
    forensics_hard/
    reverse_medium/
    crypto_easy/
  ...
  story_10/
```

Every task contains a human-readable `task.txt` plus one or more evidence
files. `task.txt` states the objective and useful constraints but never names
the expected answer. The input root contains no expected manifest and no
cleartext answer database.

The generator writes the verification manifest to
`benchmarks/ico_final_50.expected.json`. The score script reads it only after
the scan has completed. Manifest records contain an answer SHA-256, task
identity, family, difficulty, and the checker kind; cleartext answers are not
required by the scorer.

## Challenge matrix

The following matrix is the fixed initial corpus. The mechanism names are
part of the benchmark contract, so a later regeneration cannot silently turn
an easy fixture into a different class of task.

| Story | Web | Pwn | Forensics | Reverse | Crypto |
|---|---|---|---|---|---|
| 01 Signal breach | Easy: chunked HTTP response reassembly | Medium: ret2win symbol and offset inventory | Hard: DNS PCAP with split/base32 label | Medium: XORed lookup table in ELF data | Easy: Caesar plus alphabet-preserving noise |
| 02 Vault transit | Medium: HAR nested base64 JSON | Hard: format-string write plan with GOT target | Medium: SQLite WAL fragments and row ordering | Hard: bytecode VM with bounded symbolic trace | Medium: repeating-key XOR with known crib |
| 03 Ghost archive | Hard: JWT header/payload contradiction in saved transcript | Easy: static canary/PIE/RELRO triage | Easy: PNG ancillary chunk and palette recovery | Medium: rotated UTF-16 string table | Hard: RSA low exponent with exact integer cube root |
| 04 Mesh outage | Medium: GraphQL response alias and escaped JSON | Medium: integer truncation and signed comparison | Hard: WAV spectrogram sidecar and metadata | Easy: PE string plus checksum transform | Medium: affine cipher with permutation |
| 05 Red team diary | Hard: WebSocket frame transcript and masking | Hard: ret2csu-style register plan (static only) | Medium: PDF object stream and incremental update | Hard: control-flow puzzle with opaque predicates | Easy: Vigenere with supplied partial key |
| 06 Winter relay | Easy: multipart boundary and quoted-printable body | Medium: GOT/PLT relocation map | Hard: BMP bit-plane and palette alpha | Medium: Mach-O load-command string recovery | Hard: AES-ECB cut-and-paste evidence transcript |
| 07 Broken build | Medium: encoded JSON with chunk extensions | Easy: stack-layout and `win` candidate extraction | Medium: GIF comments/extensions plus frame order | Hard: custom VM with rotate/add/xor opcodes | Medium: nonce-reuse stream XOR pair |
| 08 Museum key | Hard: JWT `kid` path evidence in a saved request | Medium: constrained ROP gadget chain inventory | Easy: TAR/PAX metadata and deleted-name carving | Easy: ARM64 constant-folded checker | Hard: RSA common-modulus recovery |
| 09 Night train | Medium: HTTP/2 pseudo-header transcript normalization | Hard: format-string positional argument map | Hard: PCAP TCP stream reconstruction with gzip | Medium: .NET metadata/string decoding | Easy: rail-fence plus URL-safe base64 |
| 10 Final switch | Hard: GraphQL persisted-query and batched response | Hard: seccomp/read syscall constraint report | Medium: SQLite trigger history and hex fragments | Hard: multi-stage table/rotation/branch checker | Medium: AES-CBC IV reuse with known prefix |

The answer for each task uses the stable form `ico{...}`. The exact values are
generated from a private deterministic seed and are represented in the
manifest only by their hashes. Fixture data uses the answer as an input to the
declared transform, so solving requires following the mechanism rather than
searching a hard-coded answer list.

## Solver and evidence contract

`ico-solve` remains a read-only orchestrator. For each task it should:

1. Discover the task root and family without treating sidecars or walkthroughs
   as separate tasks.
2. Run the narrow family solver first, followed by bounded generic profiles.
3. Preserve provenance for every candidate: source file, transform, solver,
   confidence, and evidence state.
4. Deduplicate candidates by task and value.
5. Never execute native challenge files. A static exploit analysis may emit
   `payload-ready` with the offset/target evidence, but it cannot become an
   exact flag without a supplied flag artifact.

The accepted evidence states are:

- `hash-verified`: candidate hash equals the external expected hash.
- `checker-verified`: a deterministic task checker accepts the candidate.
- `payload-ready`: a reproducible static payload plan exists, but no flag was
  recovered.
- `candidate`: a plausible value with local provenance.
- `candidate-review`: incomplete or ambiguous evidence requiring inspection.
- `unsupported`: no applicable safe solver.

`platform-confirmed` is intentionally impossible in this offline benchmark;
it is reserved for an authorized contest/service response.

## Scorecard

`scripts/score_final_benchmark.py` produces JSON and a compact text table. It
must report, at minimum:

- total tasks (50), exact hash/checker-verified tasks, and verified percentage;
- counts by family and difficulty;
- `payload-ready`, `candidate`, `candidate-review`, and `unsupported` counts;
- false positives (values attached to the wrong task or values not accepted by
  the manifest);
- duplicate rows suppressed;
- wall-clock time and per-family timing;
- a list of every task that did not reach exact verification.

The headline score is:

```text
verified_score = exact_hash_or_checker_verified / 50
```

The benchmark is called 10/10 only when `verified_score == 1.0`, false
positives are zero, and the report contains all 50 task identities exactly
once. Candidate and payload-ready counts are useful progress metrics but never
increase the headline score.

## Generation and reproducibility

`scripts/generate_final_benchmark.py` regenerates the corpus from a constant
seed recorded in the manifest. It removes only the benchmark output directory
and rewrites the manifest atomically. It must not touch other corpora,
reports, caches, or user files. Generation uses standard-library encoders and
small text/media fixtures; no network downloads are needed.

The generator validates each output immediately:

- all 50 task roots exist and have `task.txt`;
- every expected task has one manifest record;
- no input file contains the cleartext manifest or an answer table;
- binary fixtures have stable SHA-256 values;
- negative/decoy evidence does not accidentally contain a valid answer.

## Verification plan

The implementation is accepted only after these checks are run from the
toolkit root:

1. Generate the corpus twice and confirm identical input-file hashes and
   manifest hashes.
2. Run the focused generator/scorer/unit tests.
3. Run `ico-solve benchmarks/ico_final_50 --mode fast` and score the saved
   report with the external manifest.
4. Run the full `./verify.sh`, including existing real and synthetic corpora.
5. Inspect the scorecard for false positives and for any task counted twice.

The final report must distinguish local hash/checker evidence from any future
service validation and must state the measured score, not a forecast.

## Deliverables

- `scripts/generate_final_benchmark.py`
- `scripts/score_final_benchmark.py`
- `benchmarks/ico_final_50/`
- `benchmarks/ico_final_50.expected.json`
- focused tests under `tests/`
- README instructions and an example scorecard

