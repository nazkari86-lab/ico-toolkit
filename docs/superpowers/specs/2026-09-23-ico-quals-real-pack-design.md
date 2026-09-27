# ICO real-quals offline solver design

## Goal

Make one `ico-scan /path/to/ico_quals` run inventory and solve every locally
available artifact from the historical ICO qualification pack, while clearly
separating service tasks that need an authorized transcript.

## Task-aware behavior

The root is detected from the real-pack marker files and does not require
`task.txt`. The runner processes service playbooks first, then the six local
artifacts: Rev Zero, Can you hear the flag?, Five Shards, Wolf Protocol,
AEZAKMI, and Journal Operator. Source files are read-only; all extraction,
payloads, OCR output, and reports go under the run directory.

The local solvers are deterministic:

- Rev Zero reverses the JavaScript Base64 check.
- Can you hear extracts a RIFF/WAVE stream after PNG `IEND`, renders a bounded
  spectrogram, and records OCR plus a manual-review state when OCR is unsure.
- Five Shards extracts DNS question labels from classic PCAP or PCAPNG, orders their sequence numbers,
  Base32-decodes them, and applies the repeating eight-byte key from the
  damaged WAV over the concatenated ciphertext stream.
- AEZAKMI and Journal Operator emit static payload files and never execute the
  supplied ELF files.
- Wolf Protocol records the static inventory and the historical differential
  inversion requirement; it remains `requires-authorized-session` because the
  challenge executable is not run.

NorthStar and Backdoor produce offline playbooks and parse nearby transcripts
for returned flag-shaped values. PixelMart transcripts are solved with the
bounded LCG recovery and produce predicted rounds; VIP Club transcripts are
solved with a local SHA-256 length-extension implementation and produce the
`S` payload. A nearby transcript (`backdoor.transcript`, `pixelmart.log`, and
similar) may be parsed, but the scanner never opens a socket, sends a request,
scans a port, or submits a value.

If the root also contains the explicitly supplied `ICO_full_walkthrough.md`,
its task-section values are exposed in a separate `reference_candidates` list
with state `reference-only`. They are useful for comparing a local derivation
with the historical notes, but are never merged into the solver candidates or
reported as current platform acceptance.

## Status contract

`candidate` is a locally derived flag-shaped value without platform
confirmation. `candidate-review` means an artifact was derived but OCR needs
human confirmation. `payload-ready` means a static request/payload artifact
was generated. `requires-authorized-session` means the task input is a service
or the historical binary needs a run that the scanner deliberately does not
perform.

## Verification

Unit tests cover the HTML reversal, PNG trailer extraction, DNS shard assembly,
payload byte layout, service status, and root discovery. The CLI smoke test
copies the real local pack and checks ten task results, two local candidates,
two payload-ready tasks, five session-required tasks, and one OCR review task.
