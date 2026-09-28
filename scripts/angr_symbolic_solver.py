#!/usr/bin/env python3
"""Bounded angr solver for simple stdin-driven local checker binaries.

This performs symbolic emulation inside angr; it never starts the challenge
binary as a native process. A candidate is emitted only if a path reaches a
recognized success message and the same artifact contains a failure message.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import resource
import time
from typing import Any


SUCCESS_MARKERS = (b"correct", b"success", b"accepted", b"congratulations", b"you win", b"well done")
FAILURE_MARKERS = (b"wrong", b"incorrect", b"invalid", b"try again", b"failed", b"failure")
MAX_BINARY_BYTES = 64 * 1024 * 1024


def emit(record: dict[str, Any]) -> None:
    print(json.dumps(record, ensure_ascii=True, sort_keys=True))


def limit_core_dumps() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (OSError, ValueError, AttributeError):
        pass


def _marker_matches(output: bytes, markers: tuple[bytes, ...]) -> bytes | None:
    lowered = output.lower()
    return next((marker for marker in markers if marker in lowered), None)


def _input_bytes(state: Any, claripy: Any, symbols: list[Any]) -> bytes:
    return state.solver.eval(claripy.Concat(*symbols), cast_to=bytes)


def solve(binary: Path, *, max_seconds: int = 48, max_input: int = 64, max_states: int = 256, max_steps: int = 2500) -> dict[str, Any]:
    started = time.monotonic()
    try:
        import angr
        import claripy
    except Exception as exc:
        return {"schema_version": 1, "status": "unavailable", "reason": f"angr runtime import failed: {type(exc).__name__}"}

    if binary.is_symlink() or not binary.is_file():
        return {"schema_version": 1, "status": "unsupported", "reason": "input must be a regular non-symlink file"}
    try:
        size = binary.stat().st_size
        if size <= 0 or size > MAX_BINARY_BYTES:
            return {"schema_version": 1, "status": "unsupported", "reason": "binary size is outside the 1..64 MiB bound"}
        raw = binary.read_bytes()
    except OSError as exc:
        return {"schema_version": 1, "status": "error", "reason": f"could not read binary: {type(exc).__name__}"}

    lowered = raw.lower()
    success_in_file = tuple(marker for marker in SUCCESS_MARKERS if marker in lowered)
    failure_in_file = tuple(marker for marker in FAILURE_MARKERS if marker in lowered)
    if not success_in_file or not failure_in_file:
        return {
            "schema_version": 1,
            "status": "unsupported",
            "reason": "requires a static success marker and a distinct failure marker",
            "success_markers": [item.decode("ascii") for item in success_in_file],
            "failure_markers": [item.decode("ascii") for item in failure_in_file],
        }

    max_seconds = max(1, min(int(max_seconds), 48))
    max_input = max(4, min(int(max_input), 96))
    max_states = max(8, min(int(max_states), 512))
    max_steps = max(50, min(int(max_steps), 10000))

    try:
        project = angr.Project(str(binary), auto_load_libs=False)
        # macOS Mach-O and stripped Linux inputs can leave imports unresolved
        # when system libraries are deliberately not loaded. Hook supported
        # libc calls to angr's own SimProcedures so stdin constraints actually
        # flow through scanf/strcmp/puts instead of unconstrained extern stubs.
        hooked_names: set[str] = set()
        for imported_name, imported_symbol in project.loader.main_object.imports.items():
            normalized = imported_name.lstrip("_").lower()
            procedure = angr.SIM_PROCEDURES.get("libc", {}).get(normalized)
            if procedure is not None and normalized in {"scanf", "fgets", "gets", "strcmp", "strncmp", "puts", "printf", "read"}:
                resolved = getattr(imported_symbol, "resolvedby", None)
                hook_address = resolved.rebased_addr if resolved is not None else imported_symbol.rebased_addr
                project.hook(hook_address, procedure(), replace=True)
                hooked_names.add(normalized)
        is_macho = "macho" in type(project.loader.main_object).__name__.lower()
        has_variadic_stdin = any(name.lstrip("_").lower() in {"scanf", "sscanf", "fscanf"} for name in project.loader.main_object.imports)
        if project.arch.name.upper() in {"AARCH64", "ARM64"} and is_macho and has_variadic_stdin:
            return {
                "schema_version": 1,
                "status": "unsupported",
                "reason": "angr 9.2.223 does not model Darwin arm64 variadic stdin arguments reliably",
                "hooked_imports": sorted(hooked_names),
            }
        pruned_states = 0
        completed_steps = 0
        marker: bytes | None = None
        found_state: Any | None = None
        success_without_input_dependency = False
        found_length = 0
        preferred_lengths = (37, 38, 40, 41, 42, 36, 32, 48, 24, 28, 26, 25, 27, 33, 39, 44, 56, 64, 16)
        lengths = [length for length in preferred_lengths if length <= max_input]
        lengths.extend(length for length in range(1, max_input + 1) if length not in lengths)
        deadline = started + max_seconds

        for input_length in lengths:
            if completed_steps >= max_steps or time.monotonic() >= deadline:
                break
            symbolic = [claripy.BVS(f"ico_stdin_{input_length}_{index}", 8) for index in range(input_length)]
            content = claripy.Concat(*symbolic, claripy.BVV(b"\n"))
            stdin = angr.SimFileStream(name="stdin", content=content, has_end=True)
            state = project.factory.full_init_state(stdin=stdin)
            state.options.add(angr.options.LAZY_SOLVES)
            for byte in symbolic:
                state.solver.add(claripy.And(byte >= 0x21, byte <= 0x7E))
            input_names = set().union(*(item.variables for item in symbolic))
            state.globals["ico_input_symbol_names"] = tuple(sorted(input_names))
            state.globals["ico_base_constraint_count"] = len(state.solver.constraints)
            manager = project.factory.simgr(state)
            per_length_steps = 0
            per_length_limit = min(250, max_steps - completed_steps)

            while manager.active and per_length_steps < per_length_limit and time.monotonic() < deadline:
                next_active = []
                for current in manager.active:
                    try:
                        output = current.posix.dumps(1)
                    except Exception:
                        output = b""
                    found_marker = _marker_matches(output, success_in_file)
                    failed_marker = _marker_matches(output, failure_in_file)
                    if found_marker and not failed_marker:
                        base_count = int(current.globals.get("ico_base_constraint_count", 0))
                        constrained = current.solver.constraints[base_count:]
                        path_names = set().union(*(constraint.variables for constraint in constrained)) if constrained else set()
                        if input_names.intersection(path_names):
                            found_state = current
                            marker = found_marker
                            found_length = input_length
                            break
                        success_without_input_dependency = True
                    if not failed_marker:
                        next_active.append(current)
                if found_state is not None:
                    break
                manager.stashes["active"] = next_active
                if not manager.active:
                    break
                if len(manager.active) > max_states:
                    manager.stashes["active"] = sorted(manager.active, key=lambda item: item.history.depth)[:max_states]
                    pruned_states += len(next_active) - max_states
                manager.step(num_inst=1)
                completed_steps += 1
                per_length_steps += 1
            if found_state is not None:
                break

        elapsed = round(time.monotonic() - started, 3)
        if found_state is not None:
            candidate_bytes = _input_bytes(found_state, claripy, symbolic)
            candidate = candidate_bytes.decode("ascii", errors="replace")
            return {
                "schema_version": 1,
                "status": "candidate",
                "candidate": candidate,
                "candidate_hex": candidate_bytes.hex(),
                "evidence": "angr path reached a static success output",
                "success_marker": marker.decode("ascii", errors="replace") if marker else None,
                "failure_markers": [item.decode("ascii") for item in failure_in_file],
                "input_length": found_length,
                "hooked_imports": sorted(hooked_names),
                "steps": completed_steps,
                "pruned_states": pruned_states,
                "duration_seconds": elapsed,
            }
        if success_without_input_dependency:
            reason = "success output was reachable without constraints on symbolic stdin"
        else:
            reason = "time budget exhausted" if time.monotonic() >= deadline else "no success path found within bounds"
        return {
            "schema_version": 1,
            "status": "no-candidate",
            "reason": reason,
            "steps": completed_steps,
            "pruned_states": pruned_states,
            "duration_seconds": elapsed,
        }
    except Exception as exc:
        return {
            "schema_version": 1,
            "status": "error",
            "reason": f"{type(exc).__name__}: {str(exc)[:240]}",
            "duration_seconds": round(time.monotonic() - started, 3),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--max-seconds", type=int, default=48)
    parser.add_argument("--max-input", type=int, default=64)
    parser.add_argument("--max-states", type=int, default=256)
    parser.add_argument("--max-steps", type=int, default=2500)
    args = parser.parse_args(argv)
    limit_core_dumps()
    emit(solve(args.binary.expanduser(), max_seconds=args.max_seconds, max_input=args.max_input, max_states=args.max_states, max_steps=args.max_steps))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
