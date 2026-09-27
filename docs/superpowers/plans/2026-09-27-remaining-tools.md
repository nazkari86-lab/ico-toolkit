# Remaining Platform Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with review checkpoints.

**Goal:** Add working local capability records and adapters for Qiling, Scalpel, strace, and ltrace.

**Architecture:** A small Python capability module detects platform backends. Shell wrappers expose stable commands. The existing adapter registry consumes the capability records and adds bounded Scalpel carving while keeping executable emulation/tracing manual.

**Tech Stack:** Python 3.14, unittest, POSIX shell, Homebrew Keystone/TRE, C++98 Scalpel build.

**Spec:** `docs/superpowers/specs/2026-09-27-remaining-tools-design.md`

## Global Constraints

- All automatic profiles read local supplied artifacts only.
- Qiling, strace, and ltrace are never auto-run by `ico-solve`.
- Scalpel output is bounded and scanned only for candidate evidence.
- ICO hosts, ports 80/443, external submissions, and flag brute force remain out of scope.

### Task 1: Capability module and wrappers

**Files:**
- Create: `ico_platform_tools.py`
- Create: `bin/qiling`
- Create: `bin/scalpel`
- Create: `bin/strace`
- Create: `bin/ltrace`

Implement status detection, help/probe commands, the bundled Scalpel path, and
explicit dtruss compatibility behavior.

### Task 2: Registry and bounded carving

**Files:**
- Modify: `ico_tool_adapters.py`

Use capability records in `_available`/`tool_inventory` and add the
`scalpel-carve` profile with deterministic bounded output collection.

### Task 3: Build and verification wiring

**Files:**
- Create: `scripts/build_scalpel.sh`
- Modify: `env.sh`
- Modify: `README.md`
- Modify: `TOOL_CATALOG.md`
- Modify: `verify.sh`

Build the arm64 Scalpel executable reproducibly with Homebrew TRE and expose
Keystone's library path to the Qiling wrapper. Document exact smoke commands.

### Task 4: Test and release gate

Run the targeted adapter tests, wrapper smoke checks, and the complete
`verify.sh` suite. Fix any regressions before reporting completion.
