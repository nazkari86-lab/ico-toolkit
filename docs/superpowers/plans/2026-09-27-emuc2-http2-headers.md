# emuc2 HTTP/2 Header Extraction Plan

> Execute inline in the current workspace. Do not contact challenge services or submit answers.

**Goal:** Make standalone scans of the emuc2 artifact folder associate its named TLS key log with the PCAP and preserve decoded HTTP/2 request and response headers.

**Architecture:** Extend the existing TShark-backed TLS forensics path to inspect a bounded set of directly named sibling key-log sidecars when no task manifest supplies related files. Use bounded TShark JSON extraction for HTTP/2 HEADERS frames, preserve duplicate JSON keys, normalize each decoded header block into a JSONL artifact, and keep body extraction unchanged.

**Tech Stack:** Python 3, TShark JSON output, unittest, existing `SolverContext` and `ForensicsSolver`.

**Spec:** `/tmp/ico-external-ctf/ductf2024-blind/forensic/emuc2` and `docs/superpowers/reports/2026-09-27-external-ctf-honest-audit.md`.

## Constraints

- Read only local challenge artifacts; make no service requests.
- Never execute challenge binaries or brute-force credentials, keys, or flags.
- Preserve the existing TLS direction and HTTP/2 DATA extraction behavior.
- Keep output bounded by the configured byte, file, and time limits.
- Report decoded values as evidence or local candidates; do not claim a solve without a checker.

---

### Task 1: Specify duplicate-preserving TShark header parsing

**Files:**
- Modify: `tests/test_ico_universal_forensics.py`
- Modify: `ico_universal_forensics.py`

- [x] Add a unit test using representative TShark JSON with repeated `http2.header` object keys; assert all headers and stream metadata survive normalization.
- [x] Run the focused test and confirm it fails because the parser is missing.

### Task 2: Integrate bounded header artifact extraction

**Files:**
- Modify: `ico_universal_forensics.py`
- Modify: `tests/test_ico_universal_forensics.py`
- Modify: `README.md`

- [x] Parse TShark JSON with a duplicate-key preserving object hook.
- [x] Discover only bounded, directly named sibling key-log files when related paths are absent.
- [x] Extract frame number, TLS stream, TCP ports, HTTP/2 stream ID, full URI, and ordered header name/value pairs.
- [x] Write one JSON record per decoded header block to a bounded `tls-http2-headers.jsonl` artifact and include it in the existing evidence outputs.
- [x] Extend the saved emuc2 integration test to assert `/api/login`, `/api/env`, `/api/flag`, and the observed `401` response while retaining HTTP/2 body assertions.
- [x] Run the focused parser and emuc2 tests and the complete forensics test module.

### Task 3: Verify and record honest coverage

**Files:**
- Modify: `docs/superpowers/reports/2026-09-27-external-ctf-honest-audit.md`
- Modify: `docs/superpowers/reports/2026-09-27-external-ctf-audit-journal.md`

- [x] Run `./verify.sh` from the configured toolkit environment.
- [x] Run a fresh targeted emuc2 scan and compare extracted HTTP/2 paths/statuses with the saved capture.
- [x] State that the saved capture has no successful `/api/flag` response and that the observed response is `401`; do not label the task solved.
- [x] Preserve the broader corpus audit counts and explicitly leave unrelated corpus-wide re-scanning out of this targeted change.
