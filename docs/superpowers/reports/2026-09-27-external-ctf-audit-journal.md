# External CTF audit journal

Append-only log for the authorized audit of locally saved DownUnderCTF 2024 and ImaginaryCTF 2022 challenge artifacts. Public challenge source may be read for reference; challenge services are not contacted, challenge binaries are not executed, password/flag brute force is not performed, and no flags are submitted. Local candidates and prepared payloads remain distinct from checker-, service-, and platform-confirmed results.

## 2026-09-27 — resume existing audit

- Request: inspect the toolkit honestly on real task packs, identify coverage gaps, and improve the supported offline workflows.
- Scope: saved report `/tmp/ico-external-ctf/ductf2024-complete-current-20260927/report.json`, its local task pack `/tmp/ico-external-ctf/ductf2024-blind`, existing targeted report files under `/tmp/ico-external-ctf`, and the previously scanned ImaginaryCTF 2022 report.
- Commands/evidence read: current external audit report, task coverage JSON, README, `ico_external_ctf.py`, and ICO CTF evidence playbook.
- Observation: baseline DUCTF report covers 38 tasks, 8 candidate tasks, 19 review tasks, 11 without candidate; later focused profiles cover Dungeon, Number Mashing, and Vector Overflow. No checker/service/platform-confirmed flags are reported.
- Attempts/submissions/network: 0; read-only local analysis only.
- Next hypothesis: inspect each review/no-candidate task's supplied files and prior targeted results, then select a reproducible offline gap whose solution can be validated without executing challenge code or contacting services.

## 2026-09-27 — emuc2 TLS sidecar and HTTP/2 header extraction

- Request: continue the honest local audit, fix confirmed scanner gaps, and validate through the normal CLI.
- Scope: saved emuc2 task files under `/tmp/ico-external-ctf/ductf2024-blind/forensic/emuc2`, toolkit TLS/HTTP2 forensics, and the existing DUCTF/ImaginaryCTF reports.
- Root cause: direct `ForensicsSolver` tests passed the key log explicitly, but a standalone directory scan had no task manifest and supplied no related paths. `_tls_keylog_candidates()` inspected only `context.related_paths`, so it skipped the adjacent `sslkeylogfile.txt`. In addition, TShark JSON repeats the `http2.header` key for each decoded header; Python's default JSON decoder kept only one occurrence.
- RED evidence: the new parser test failed with missing `_parse_tshark_http2_headers`; the sibling-keylog test returned an empty candidate list; the first normal CLI run had no `decrypt-tls-keylog` step.
- Change: bounded discovery of non-symlink sibling sidecars with key-log names and allowed extensions; a duplicate-preserving TShark JSON parser; bounded `tls-http2-headers.jsonl` output wired into the existing evidence path; documentation and regression tests.
- Verification: all 29 tests in `test_ico_universal_forensics.py` passed. The final `./verify.sh` passed 252 tests plus compile, CLI fixture, Python CTF stack, and binary stack smoke checks. A fresh `ico-scan --mode full` on a temporary copy of the three emuc2 files completed without errors, decrypted 4 TLS streams, recorded 6 HTTP/2 DATA bodies and 8 HEADERS blocks, and found `/api/login`, `/api/env`, `/api/flag`, HTTP statuses 200 and 401, with `/api/flag` returning 401.
- Evidence report: `/tmp/ico-emuc2-cli-fixed-dzp5a6t0/report/report.json`.
- Result state: 0 local candidates and 0 confirmed solves for emuc2. The saved capture has no successful `/api/flag` response; this task remains unresolved from the supplied local files. No challenge service was contacted and no flag was submitted.
- Corpus scope: the full 38-task DUCTF scan was not repeated after this focused fix. Existing DUCTF and ImaginaryCTF counts remain the earlier saved audit results, not fresh post-change scans.

## 2026-09-27 — static review of remaining web-only packages

- Request context: identify whether additional no-candidate tasks can be solved from their supplied files alone.
- Read-only findings: the local `hah_got_em` archive contains `FAKE{actual-flag-on-instance}`; `parrot_the_emu` and `zoo_feedback_form` contain empty flag files; `sniffy` defines the placeholder `DUCTF{}` and writes it into a PHP session. These source packages reveal dynamic web challenge behavior but not the instance's actual flag.
- Attempts/network: 0; no service was launched or contacted.
- Result state: none of these placeholder values is recorded as a flag candidate. The tasks remain instance-dependent; the review supports the existing no-offline-candidate classification.

## 2026-09-27 — Average Assembly and sign-in profile validation

- Request: continue the real-task audit, find concrete scanner misses, and fix them.
- Scope: local DUCTF 2024 `average_assembly_assignment` and `sign_in` artifacts; read-only reference comparison against the published DUCTF Average Assembly helper.
- Root cause: the generated Average Assembly program jumped to `read_all_loop`, but the source tuple had no such label. The public helper places that label before `INP`.
- RED/GREEN: the strengthened regression test first failed because the generated program began with `INP` and the target label was absent. After adding the label before `INP`, the test passed and verified every generated branch target resolves.
- Change: corrected `_DUCTF_AVERAGE_ASSEMBLY_SOURCE`; added a precise leading-loop assertion; documented both profiles and updated the aggregate audit from 3 to 5 `payload-ready` tasks and from 15 to 13 `candidate-review` tasks.
- CLI evidence: `ico-scan --mode full` on each task directory produced `payload-ready`, 0 flag candidates, and 0 confirmed flags. Average Assembly wrote the encoded program; sign in wrote its hash-gated six-step session recipe and still requires an authorized session.
- Verification: `./verify.sh` passed 254 tests, Python compilation, CLI fixtures, the Python CTF stack, and the binary stack. An earlier direct test command used the system Python and failed two crypto-dependent cases because it lacked the `Crypto` namespace; `verify.sh` sources `env.sh` and uses the the configured toolkit Python environment, where those tests pass.
- Attempts/submissions: no challenge binaries executed, no challenge service contacted, and no flag submitted. One read-only public GitHub source request was used for reference.
- Result state: two additional tasks now produce locally validated `payload-ready` artifacts; neither yielded a flag. The full 38-task DUCTF corpus was not rescanned after these focused changes; the aggregate table combines the saved full report with nine targeted task reports.

## 2026-09-27 — residual crypto artifact spot-check

- Scope: local `decrypt_then_eval` source and `Poly1305_OTM` archive members under the saved DUCTF pack; no extraction to disk.
- Evidence: `decrypt_then_eval.py` generates KEY and IV with `os.urandom` and has a test-only FLAG fallback; the directory has no runtime ciphertext or instance state. `Poly1305_OTM` contains a flag-shaped placeholder marked by its test wording; its service chooses a fresh random key and the MAC path re-randomizes the key.
- Result: these files do not provide the live key/flag state needed to claim a recovered instance flag. Keep them in review; do not promote packaged test values.
- Safety: source and archive members were read only; challenge binaries and services were not run or contacted.
