# Honest audit of `ico-scan` on ImaginaryCTF 2022

Date: 2026-09-27  
Corpus: `/tmp/ico-external-ctf/imaginary-blind` (13 tasks, 25 input files)  
Reference checkout: ImaginaryCTF 2022 challenges, commit `ac2f0aa796a651e0eb730db12c3550e4470d4e9c`

## Result

A fresh full scan completed with 13/13 task records, `task_failure_count=0`, and `universal_failed_count=0`:

| Evidence state | Tasks | Meaning |
|---|---:|---|
| `candidate` | 8 | Local values were recovered; each matched separate public answer material. |
| `payload-ready` | 5 | Static inputs/requests were constructed; no service response or flag was obtained. |
| `hash-verified` | 0 | This corpus has no local checker/hash evidence that verifies a recovered flag. |
| `solved_tasks` | 0 | The scanner correctly did not promote local candidates or unexecuted payloads to verified solves. |

The eight candidate tasks were `huge`, `smoll`, `stream`, `improbus`, `Subtitles`, `tARP`, `desrever`, and `hidden`. Separate reference checks matched all eight: seven against public text answer material and `improbus` against the SHA-256 of the published `flag.png`. The extra `hidden` decoy and the non-printable `ret2win` string remain triaged as placeholder/noise.

The five `payload-ready` tasks were `bof`, `Format String Fun`, `ret2win`, `1337`, and `minigolf`. Static checks against the published solve material confirmed:

- `bof`: generated `%70c` matches the reference input.
- `Format String Fun`: generated format string, padding, and `win` pointer match the reference recipe and static ELF symbols.
- `ret2win`: generated 24-byte filler and little-endian `win` address match the reference recipe and static symbol table.
- `1337`: the generated expression decodes to `child_process` and `cat F*`; its digits are limited to `2`, `8`, and `9` as required by the filter.
- `minigolf`: the three generated stages copy the local flag into the template directory and include it in the response; no callback is present.

## Limits and follow-up

The five payload tasks do not include their runtime service output in the local corpus. The scanner can prepare their recipes but cannot extract those flags from the supplied files alone. No challenge ELF was executed, no request was sent, and no answer was submitted. An authorized local service bundle or saved service transcript is needed to verify those five end to end.

No additional solver patch was justified by this corpus: the fresh scan reproduced the expected results, and the 200-test `./verify.sh` run passed. This is evidence for these 13 tasks only; it does not establish that arbitrary future CTF tasks will be solved automatically.
