# ICO Final Solver Design

## Goal

Add a dedicated `ico-solve` command for the 29–30 September ICO final format:
three story roots with one Web, PWN, Forensics, Reverse, and Crypto subtask in
each story. A participant gives the command one file, task directory, archive,
or complete story directory and receives the strongest flag result directly.

The design optimizes the probability of recovering all 15 flags by routing each
input through task-aware profiles, category solvers, local tooling, and bounded
cross-checks. It does not turn a missing answer into a guessed flag and it does
not send requests to the olympiad platform.

## User experience

The final-facing command is:

```sh
source $ICO_TOOLKIT_ROOT/env.sh
ico-solve path/to/task-or-story
```

For one task, stdout contains the selected flag on one line. For a story or a
three-story bundle, stdout contains one `task-id<TAB>flag` row per recovered
flag, sorted by story and category. The default view does not print reports,
tool logs, or explanatory prose. `--debug` writes a JSON evidence bundle and
prints the solver path when a result needs inspection.

Supported inputs are regular files, directories, ZIP/TAR/GZIP/XZ/7z archives,
and saved HTTP/HAR/cURL/transcript files. Archives are extracted into a
temporary bounded workspace; source files are never modified.

## Architecture

`ico-solve.py` is a thin final-facing orchestrator over the existing
`SolverContext`, `SolverResult`, `SolverRegistry`, task-aware ICO solvers, and
bounded command runner. The existing `ico-scan` command remains available for
full evidence reports. The new command consumes the same solver results but
adds task-slot discovery, confidence ranking, duplicate corroboration, and a
copy-ready stdout contract.

The pipeline is:

1. Canonicalize the supplied paths, unpack nested containers within limits, and
   group related files by task root and story.
2. Read task statements, file signatures, manifests, saved transcripts, and
   metadata to assign a family (`web`, `pwn`, `forensics`, `reverse`, or
   `crypto`) and difficulty when present.
3. Run exact ICO profiles first, then the matching category profiles, then
   cheap generic decoders, then bounded external tools already available in
   the environment.
4. Feed every derived text/bytes view back through the compatible solvers while
   enforcing depth, file, byte, and timeout limits.
5. Merge identical values supported by independent paths and rank them by
   verification state, task-context match, independent evidence count, and
   flag-format fit.
6. Print the highest-ranked flag per task slot. A slot with no flag-shaped
   result exits with a nonzero status and is recorded in `--debug` output;
   arbitrary text is never printed as a flag.

## Category coverage

### Crypto

Use the current deterministic profiles first, then add bounded handlers for
Caesar/affine/substitution, repeating-key XOR with condition-derived cribs,
Vigenere, weak LCG/MT19937 state recovery, RSA low-exponent/common-modulus/
Wiener cases, AES mode/nonce mistakes, padding-oracle transcripts, and
length-extension transcripts. Every handler requires evidence from the task or
artifact before trying a transform; it never brute-forces a flag value or an
unbounded password space.

### Forensics

Run file-signature repair, nested archive extraction, PNG ancillary and bit
planes, JPEG metadata/embedded streams, WAV/AIFF sample bits and spectrograms,
PCAP/PCAPNG reassembly, DNS labels, SQLite/browser caches, JSON/log timelines,
and bounded memory/disk profiles when the required tools are present. OCR
results require a second corroborating representation before being ranked as
the final flag.

### Reverse

Inspect ELF/PE/Mach-O protections, strings, symbols, imports, bytecode, and
control/data flow with Capstone, radare2, angr, GDB, or equivalent local tools.
Use task statements to derive input checks, XOR/VM/PRNG inversions, and exact
outputs. A local sandbox runner may execute a supplied challenge replica with
network disabled and resource limits; the final platform is never targeted.

### PWN

Extend the existing static PWN profiles for stack overflow, format strings,
ret2win/ret2libc, ROP, integer and vector corruption, and simple heap paths.
Construct concrete inputs only when offset, target, and calling convention are
proven by the supplied files. If a local Docker/Podman replica is supplied,
run the input inside the replica and parse the returned flag. Static payloads
without a returned flag remain eligible evidence but cannot outrank a real
flag.

### Web

Parse source, templates, JavaScript, saved HTTP/HAR/cURL traffic, and WordPress
artifacts. Add bounded recipes for SQLi, auth/session flaws, IDOR, JWT/OAuth,
SSRF/SSTI/XXE, traversal, upload, GraphQL, CSRF/CORS, and WordPress routes.
For a supplied local service bundle, start only the declared local service and
run the task recipe against it. Saved transcripts are treated as input and are
never converted into arbitrary network probes.

## Confidence and output

The ranking order is:

1. `hash-verified` or checker-verified;
2. flag returned by a supplied local replica;
3. `transcript-derived` with a task-specific parser;
4. deterministic candidate independently reproduced by two solvers;
5. single-path candidate;
6. OCR or static payload evidence requiring review.

Placeholder and noise triage stays enabled. A value such as `dummy_flag`,
`test_flag`, a repeated template, or a non-printable match cannot become the
selected output unless the task checker independently verifies it.

## Safety and limits

The default command is file-only. It does not scan ports, contact arbitrary
hosts, submit answers, or access `cyberolympiad.kz`. An optional local-replica
mode is restricted to a declared local process/container, with no network,
bounded CPU/memory/time, and a temporary working directory. Any active remote
adapter remains separate, requires an explicit allowlist, and is not needed by
the final-facing file workflow.

## Acceptance criteria

- `ico-solve` accepts one task file, one task directory, one archive, and a
  complete three-story directory.
- The existing ten-task `ico_ctf_real` pack still produces all ten exact
  hash-verified flags.
- A final-style benchmark has 15 task slots (three stories × five families),
  with easy, medium, and hard fixtures behind the same five slot handlers; the
  solver produces the expected flag for every deterministic positive fixture
  and no flag for negative fixtures.
- The qualifying pack and external CTF corpora remain regression inputs for
  Wolf, Rev Zero, Five Shards, task-aware crypto, forensic, reverse, PWN, and
  web paths.
- A repeated run over identical input produces identical stdout and candidate
  ordering.
- `./verify.sh` includes the new CLI smoke test, the 15-slot benchmark, output
  ranking tests, malformed-archive tests, and local-replica tests.
