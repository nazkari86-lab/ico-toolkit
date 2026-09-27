# ICO Universal Solver Design

## Goal

Extend `ico-scan` from a small set of ICO-specific decoders into a bounded,
evidence-preserving CTF solver engine that covers the largest practical set of
offline task families. The engine must accept one file, a related file set, an
archive, or a task directory and produce a flat list of unique flag values
alongside a machine-readable explanation of how each value was derived.

“Universal” means broad deterministic coverage of recognizable task families;
it does not mean guessing an unknown flag, inventing a task condition, or
claiming that an arbitrary live service can be solved without its protocol and
authorized access.

## Scope and boundaries

- Local files and directories are the default input. Original challenge files
  remain read-only; derived material is written under the report directory.
- Existing `ico_ctf_starter`, `ico_ctf_real`, and `ico_quals` packs remain
  regression corpora. The briefing transcript and local ICO manuals are
  knowledge sources for categories and protocol shapes, not flag generators.
- Public or historical ICO profiles are added only when a real condition,
  artifact, or saved transcript is available. A profile must never manufacture
  an answer from a task name alone.
- Generic solving never performs flag-value brute force, password dictionary
  guessing, platform submission, port scanning, or requests to
  `cyberolympiad.kz`.
- Active web/API analysis is a separate explicit mode for an allowlisted,
  authorized local or task-host target. The default mode never opens sockets.
- Native challenge binaries are inspected statically by default. Payloads may
  be generated as evidence artifacts; execution requires a separate explicit
  local-sandbox mode and is never implicit.
- Every solver is bounded by input size, recursion depth, derived file count,
  subprocess timeout, and network request budget when active mode is enabled.

## User interface

The existing command remains the primary entry point:

```sh
ico-scan PATH [PATH ...]
ico-scan --out REPORT_DIR PATH [PATH ...]
ico-scan --mode fast --progress PATH [PATH ...]
```

The default terminal view is intentionally copy-friendly:

```text
REPORT: ...
FLAGS: N
ico{example_one}
ico{example_two}
...
```

Generic and task-aware reports keep the full evidence graph in `report.json`,
`report.txt`, derived artifacts, and per-family Markdown notes. The flat view
does not discard that evidence; it only keeps the default terminal output
short and copy-friendly.

`full` is the default bounded profile set. `fast` retains task-aware solvers,
in-process decoders, and cheap type-matched profiles; deep external analyzers
are recorded as skipped. `--progress` writes bounded stage counters to stderr
so stdout remains suitable for copying candidates.

## Pipeline

1. Canonicalize inputs, remove duplicate paths and hashes, and create a bounded
   report workspace.
2. Discover task statements, archive members, file signatures, embedded
   containers, saved HTTP transcripts, and related files. Preserve the source
   relationship for every derived artifact.
3. Run deterministic decoders and format analyzers in a stable order. A solver
   can emit derived bytes, text, metadata, a payload, or a review request, but
   it cannot silently replace the original artifact.
4. Scan each output with the shared flag matcher and attach a derivation chain,
   solver name, parameters, source offsets, and state.
5. Rank duplicate values by independent evidence. Deduplicate the terminal
   list while retaining every supporting path in JSON.
6. Continue after an individual solver failure. Record `unsupported`,
   `needs-review`, `requires-authorized-session`, or `failed` with a reason
   instead of turning an absence of a solver into a guessed flag.

## Solver registry

Each solver implements a common interface:

```python
detect(context) -> Detection | None
solve(context, output_dir) -> SolverResult
```

`Detection` contains a score, category, and reason. `SolverResult` contains
ordered evidence steps, derived artifacts, candidate values, status, and an
optional error. The registry selects the highest-confidence compatible
profiles, while allowing independent low-cost profiles to corroborate a
result.

### Encodings, containers, and data transforms

- Base64, Base32, hex, URL percent encoding, quoted-printable, UTF variants,
  and bounded nested decoding.
- Single-byte/repeating-key XOR when the condition or a strong plaintext crib
  supports it; record key and offset instead of enumerating flag values.
- ZIP, TAR, GZIP, XZ, BZIP2, 7z listings and bounded recursive extraction with
  path containment checks.
- Common compressed metadata and embedded files in PNG, PDF, Office and
  container formats.

### Cryptography

- Caesar/ROT, affine, substitution hints, Vigenere indicators and known-key
  transforms when the task evidence identifies the family.
- LCG, truncated LCG, MT19937 state/seed recovery, and weak-PRNG checks with
  explicit bounds.
- RSA textbook mistakes, low exponent, common modulus, Wiener/small-
  parameter checks, and factorization only within configured limits.
- AES ECB/CBC/CTR misuse, repeated nonce/keystream recovery, padding-oracle
  transcript parsing, and hash/MAC length-extension where the captured
  protocol supplies the required values.
- DH/ECDSA parameter and nonce failures when the task provides enough public
  material. No blind key or flag search.

### Steganography and media forensics

- PNG/BMP/GIF palette and bit-plane extraction, PNG ancillary chunks and
  compressed text, JPEG metadata/embedded streams, WAV/AIFF sample-bit and
  spectrogram paths, and PDF/Office metadata or object streams.
- Deterministic tools such as `zsteg`, `pngcheck`, `exiftool`, `ffprobe`, and
  `binwalk` are called with bounded arguments; wordlist/password cracking is
  never automatic.
- OCR results are marked `needs-review` unless the text is independently
  corroborated.

### Network, logs, and databases

- Classic PCAP and bounded PCAPNG parsing for Ethernet/SLL2 over IPv4/TCP/UDP,
  stream reassembly, DNS labels, HTTP headers/bodies, credentials in
  task-provided captures, and common encoded payloads.
- SQLite/JSON/CSV/log timelines, browser caches, shell history, auth records,
  and bounded correlation of user/process/network events.
- Memory and disk images use read-only Volatility/Sleuth Kit profiles when the
  format is detected; unsupported profiles remain explicit in the report.

### Reverse engineering and pwn

- ELF/PE/Mach-O inventory, strings, symbols, imports, protections, xrefs,
  bytecode identification, and static Capstone/radare2/Ghidra-compatible
  hints for XOR/checkers/custom VMs.
- Python/JS/.NET/JVM bytecode extraction and reversal of deterministic input
  checks.
- Stack/format-string/ROP/ret2libc/heap protection analysis and payload
  construction as a static artifact. The solver never launches a challenge
  binary in the normal path.

### Web and API

- Saved request/response and browser-export parsing for SQLi, authentication and
  session flaws, IDOR/BOLA, XSS/CSRF/CORS, JWT/OAuth/OIDC, SSRF/SSTI, XXE,
  traversal, uploads, GraphQL, WordPress and business-logic patterns.
- The solver reports a reproducible request sequence or payload only when the
  transcript or task condition supports it. It does not probe arbitrary hosts.
- An explicit active adapter may target an allowlisted local service, with
  request count, host, and method logged; platform domains remain rejected.

### ICO profiles

Keep dedicated profiles for the known ICO families: Rev Zero, Can You Hear,
Five Shards, Wolf Protocol, AEZAKMI, Journal Operator, NorthStar, Backdoor,
PixelMart, VIP Club, and the ten `ico_ctf_real` transformations. These profiles
serve as regression examples for the generic registry and may parse saved
transcripts, but historical walkthrough flags remain evidence-labelled.

## Evidence and confidence

Candidate records contain:

- `value`, `state`, `category`, `solver`, and a confidence score;
- source artifact, byte offset/line, input hash, and derived-artifact chain;
- solver parameters and independent corroboration references;
- verification metadata when a supplied `flag_hashes.json` or task checker is
  available.

States are `candidate`, `hash-verified`, `transcript-derived`,
`payload-ready`, `needs-review`, `requires-authorized-session`,
`unsupported`, or `failed`. The terminal list includes all unique values from
the answer index, but JSON preserves state and provenance so historical or
OCR-derived strings are not confused with platform confirmation.

## Testing and acceptance

- Preserve all existing tests and `verify.sh` checks.
- Add small deterministic fixtures for every new solver family and malformed or
  over-limit inputs.
- Run the three current ICO corpora end to end and assert stable task counts,
  derived artifact counts, and answer-list determinism.
- Add negative tests proving that ordinary occurrences of the word “flag”,
  arbitrary random strings, and missing task conditions do not produce a
  candidate.
- Add active-mode tests with a local test server only; assert that a non-
  allowlisted host and the olympiad domain are rejected before any request.
- Report coverage as `solved`, `derived`, `needs-review`, `unsupported`, and
  `failed` per input family. “Maximum coverage” is measured by this matrix,
  not by claiming every unknown challenge is solvable.

The checked-in synthetic story matrix instantiates that acceptance contract with
three story roots, five families (`web`, `pwn`, `forensics`, `reverse`, and
`crypto`), three difficulty levels, and one negative fixture per family. The
expected-answer metadata stays outside the scanner input root. The current
bounded profiles recover the web values as `transcript-derived`, deterministic
crypto/forensics/reverse values as `candidate`, and static pwn plus hard reverse
cases as `payload-ready`; negative roots must have no candidate. The corpus
runner records these results under schema version 2 and groups them by task
root, family, and difficulty without reading the expected-answer file.

The current implementation also records `fast`, `specialized`, and `deep` stage
labels plus actionable analyzer outcomes (`ok`, `unavailable`, `inapplicable`,
`malformed-input`, `timed-out`, or `failed`). External command results have a
run-local cache under the report directory keyed by input SHA-256, analyzer,
executable identity, normalized arguments, and task-context hashes. OCR for
`Can you hear the flag?` is planned from named task-derived views, deduplicated
by input hash, and bounded to eight Tesseract calls per task; ambiguous output
remains review-only evidence.

SQLite detection uses the `SQLite format 3` magic bytes even when a browser
cache has an arbitrary extension. DNS Base32 extraction accepts a single label
as well as split labels. Unknown `task.txt` roots stay in the universal lane;
the older task-specific adapters run only when their statement matches an
authoritative solver, preventing unsupported rows from obscuring universal
coverage.

## Rollout order

1. Extract a registry/context/result model without changing existing solver
   behavior.
2. Move current ICO and `ico_ctf_real` solvers behind the registry and add the
   corpus regression runner.
3. Add low-risk universal transforms, containers, media and PCAP/database
   profiles.
4. Add bounded crypto, reverse and pwn static profiles.
5. Add saved-transcript web/API profiles, then the opt-in allowlisted local
   adapter.
6. Tune ranking, documentation, fixtures, and performance only after every
   stage has fresh verification evidence.
