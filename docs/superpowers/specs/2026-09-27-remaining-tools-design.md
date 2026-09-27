# Remaining platform tools design

## Goal

Make the four previously missing entries (`qiling`, `scalpel`, `strace`, and
`ltrace`) first-class members of the local ICO toolkit without changing the
offline-only default of `ico-solve`.

## Design

`ico_platform_tools.py` owns capability detection for these platform-sensitive
tools. It returns a stable JSON-safe record with the tool name, state, backend,
path, and reason. Qiling is considered available only when the extra Python
runtime can import Qiling, Keystone, Unicorn, and Capstone. Scalpel is backed
by a locally built arm64 executable and a bundled configuration. On macOS,
`strace` and `ltrace` expose explicit compatibility wrappers over `dtruss`;
the wrapper reports that the backend is syscall-level and never runs from the
automatic solver.

`ico_tool_adapters.py` uses the capability records when calculating inventory,
so `ico-solve --tools` shows both availability and the selected backend. A
bounded `scalpel-carve` profile runs only for file-like inputs and collects
small carved text files for the existing flag matcher. Qiling and tracing stay
manual because emulation/tracing executes a supplied process and would violate
the solver's current static-analysis safety boundary.

## Error handling and portability

Missing Homebrew libraries, missing extra runtimes, unavailable `dtruss`, and
missing compiled Scalpel produce `missing` records with a reason. The wrappers
return a non-zero status with an actionable message instead of silently
pretending that a tool ran. No network endpoint, ICO platform, or flag
bruteforce path is added.

## Verification

Unit tests cover status records, inventory backend fields, and profile
selection. The full `verify.sh` suite remains the release gate, followed by
`qiling --probe`, `scalpel --help`, and wrapper help/version smoke checks.
