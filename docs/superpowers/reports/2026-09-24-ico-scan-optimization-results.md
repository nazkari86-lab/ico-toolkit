# ICO scanner optimization verification

Run date: 2026-09-24 (Asia/Almaty)

## Verification commands

```text
python3 -m unittest discover -s tests -q
Ran 116 tests in 14.195s
OK

./verify.sh
Ran 116 tests in 13.706s
OK
ico-scan fixture smoke: OK
Python CTF stack: OK
Binary stack: OK

python3 scripts/check_toolchain.py
schema_version: 1; 14 optional profiles inspected; 13 available, 1 unavailable
(`steghide`); unavailable tools are reported without turning the scan into a
failure
```

The complete corpus command was:

```text
python3 scripts/generate_story_matrix.py
python3 scripts/run_corpus_matrix.py \
  $ICO_CTF_STARTER_ROOT \
  $ICO_CTF_REAL_ROOT \
  $ICO_QUALS_ROOT \
  benchmarks/ico_story_matrix \
  --out /private/tmp/ico-scan-final-matrix.GbMz0z
```

It exited with code 0 and produced matrix schema version 2. Every source hash
was unchanged after scanning.

## Corpus results

| Corpus | Seconds | Source files | Current candidates | Hash verified | Transcript-derived | Payload-ready evidence | Review | Session required | Historical references | Tool errors/timeouts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `ico_ctf_starter` | 1.43 | 42 | 10 | 0 | 0 | 0 | 0 | 0 | 0 | 0 / 0 |
| `ico_ctf_real` | 0.09 | 24 | 0 | 10 | 0 | 0 | 0 | 0 | 0 | 0 / 0 |
| `ico_quals` | 36.59 | 40 | 2 | 0 | 5 | 1 | 5 | 12 | 0 / 0 |
| `ico_story_matrix` | 4.30 | 101 | 24 | 0 | 9 | 12 | 0 | 0 | 0 | 0 / 0 |

The `ico_quals` row's five payload-ready evidence records include three static
universal reverse analyses. Its task-aware summary remains the authoritative
task count: 2 payload-ready tasks, 5 requiring an authorized session, and 1
candidate-review task. Historical values stay in their separate reference
collection.

## Story matrix coverage

The synthetic matrix contains 45 positive roots and five negative roots. The
coverage rows show:

- 33 positive candidate values;
- 9 web values with `transcript-derived` evidence;
- 12 static pwn/reverse `payload-ready` cases;
- 5 negative roots with no candidate;
- 50 coverage rows total, grouped by story, family, and difficulty.

The integration test reads only the expected metadata outside the scanner input
root and verifies every case, the evidence state, the negative invariant, and
source immutability. It also verifies that unknown synthetic task statements do
not create legacy `unsupported` task-solver rows.

## Performance

The earlier real-quals baseline was approximately 188 seconds. The final
real-quals row measured 36.59 seconds on the same local corpus, a reduction of
approximately 81%. The portable UTF-16LE pass is in-process, OCR is bounded to
eight calls per task, duplicate inputs are hash-deduplicated, and expensive
profiles remain bounded with explicit stage and skip outcomes.

## Scope of the result

These numbers establish deterministic local coverage for the checked-in
fixtures and the available ICO packs. They do not claim arbitrary unknown
live-service tasks are solvable, and no network request, platform submission,
native challenge execution, password dictionary, or flag-value brute force was
used.
