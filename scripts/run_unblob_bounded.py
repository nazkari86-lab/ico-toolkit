#!/usr/bin/env python3
"""Run unblob with a wall-clock, extracted-byte, and file-count budget."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


DEFAULT_MAX_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ENTRIES = 4096
DEFAULT_MAX_SECONDS = 110.0
POLL_SECONDS = 0.05
CAPTURE_BYTES = 1024 * 1024


def tree_usage(root: Path, *, stop_entries: int = DEFAULT_MAX_ENTRIES) -> tuple[int, int]:
    """Return regular-file bytes and total entries, never following symlinks."""

    if not root.is_dir() or root.is_symlink():
        return 0, 0
    pending = [root]
    entries = 0
    total_bytes = 0
    while pending:
        directory = pending.pop()
        try:
            iterator = os.scandir(directory)
        except OSError:
            continue
        with iterator:
            for child in iterator:
                entries += 1
                if entries > stop_entries:
                    return total_bytes, entries
                try:
                    if child.is_symlink():
                        continue
                    if child.is_dir(follow_symlinks=False):
                        pending.append(Path(child.path))
                    elif child.is_file(follow_symlinks=False):
                        total_bytes += child.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
    return total_bytes, entries


def prune_tree(root: Path, *, max_bytes: int, max_entries: int) -> tuple[int, int, bool]:
    """Keep a deterministic prefix of extracted files within both budgets."""

    if not root.is_dir() or root.is_symlink():
        return 0, 0, False
    pending = [root]
    entries = 0
    total_bytes = 0
    pruned = False
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda child: child.name)
        except OSError:
            continue
        for child in children:
            try:
                if child.is_symlink():
                    Path(child.path).unlink()
                    pruned = True
                    continue
                if child.is_dir(follow_symlinks=False):
                    if entries >= max_entries:
                        shutil.rmtree(child.path, ignore_errors=True)
                        pruned = True
                        continue
                    entries += 1
                    pending.append(Path(child.path))
                    continue
                if not child.is_file(follow_symlinks=False):
                    continue
                size = child.stat(follow_symlinks=False).st_size
                if entries >= max_entries or total_bytes + size > max_bytes:
                    Path(child.path).unlink()
                    pruned = True
                    continue
                entries += 1
                total_bytes += size
            except OSError:
                continue
    return total_bytes, entries, pruned


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        process.terminate()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            process.kill()
        process.wait()


def _apply_file_limit(limit: int) -> None:
    """Cap the size of any one child-created file where POSIX supports it."""

    if os.name != "posix":
        return
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    except (ImportError, OSError, ValueError):
        return


def run(args: argparse.Namespace) -> int:
    requested_source = args.input.expanduser()
    requested_output = args.extract_dir.expanduser()
    if requested_source.is_symlink() or not requested_source.is_file():
        print("ico-unblob: input must be a regular non-symlink file", file=sys.stderr)
        return 2
    if requested_output.is_symlink():
        print("ico-unblob: extraction directory must not be a symlink", file=sys.stderr)
        return 2
    source = requested_source.resolve()
    output = requested_output.resolve()
    if source.stat().st_size > args.max_input_bytes:
        print("ico-unblob: skipped input larger than the configured limit", file=sys.stderr)
        return 0
    if output == source or source.is_relative_to(output):
        print("ico-unblob: unsafe extraction directory", file=sys.stderr)
        return 2
    output.mkdir(parents=True, exist_ok=True)

    executable = shutil.which(args.unblob)
    if executable is None:
        print(f"ico-unblob: unblob executable not found: {args.unblob}", file=sys.stderr)
        return 127

    command = [
        executable,
        "--force",
        "--extract-dir",
        str(output),
        "--depth",
        str(args.depth),
        "--process-num",
        "1",
        "--randomness-depth",
        "0",
        "--keep-extracted-chunks",
        "--report",
        str(args.report.expanduser().resolve()),
        "--log",
        str(args.log.expanduser().resolve()),
        str(source),
    ]

    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                shell=False,
                start_new_session=True,
                preexec_fn=lambda: _apply_file_limit(args.max_bytes) if os.name == "posix" else None,
            )
        except OSError as exc:
            print(f"ico-unblob: failed to start: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 127

        deadline = time.monotonic() + args.max_seconds
        stopped_reason: str | None = None
        while process.poll() is None:
            if time.monotonic() >= deadline:
                stopped_reason = "wall-clock limit"
                _terminate(process)
                break
            total_bytes, entries = tree_usage(output, stop_entries=args.max_entries)
            if total_bytes >= args.max_bytes:
                stopped_reason = "extracted-byte limit"
                _terminate(process)
                break
            if entries > args.max_entries:
                stopped_reason = "extracted-entry limit"
                _terminate(process)
                break
            time.sleep(POLL_SECONDS)

        returncode = process.wait()
        extracted_bytes, extracted_entries = tree_usage(output, stop_entries=args.max_entries)
        if stopped_reason is None:
            if extracted_bytes >= args.max_bytes:
                stopped_reason = "extracted-byte limit"
            elif extracted_entries > args.max_entries:
                stopped_reason = "extracted-entry limit"
        _kept_bytes, _kept_entries, pruned = prune_tree(
            output,
            max_bytes=args.max_bytes,
            max_entries=args.max_entries,
        )
        if pruned and stopped_reason is None:
            stopped_reason = "post-run extraction budget"
        for label, handle in (("stdout", stdout_file), ("stderr", stderr_file)):
            handle.flush()
            handle.seek(0)
            data = handle.read(CAPTURE_BYTES)
            if data:
                stream = sys.stdout.buffer if label == "stdout" else sys.stderr.buffer
                stream.write(data)
                if len(data) >= CAPTURE_BYTES:
                    stream.write(b"\n[ico-unblob: child output truncated]\n")

    if stopped_reason:
        print(
            f"ico-unblob: extraction stopped at {stopped_reason}; partial output retained",
            file=sys.stderr,
        )
        # Keep a successful adapter state so the scanner examines partial
        # artifacts; the stop reason remains visible in the preserved output.
        return 0
    return returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--extract-dir", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--log", required=True, type=Path)
    parser.add_argument("--unblob", default="unblob")
    parser.add_argument("--depth", type=int, default=3)
    parser.add_argument("--max-input-bytes", type=int, default=128 * 1024 * 1024)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--max-entries", type=int, default=DEFAULT_MAX_ENTRIES)
    parser.add_argument("--max-seconds", type=float, default=DEFAULT_MAX_SECONDS)
    args = parser.parse_args(argv)
    if min(args.depth, args.max_input_bytes, args.max_bytes, args.max_entries) <= 0 or args.max_seconds <= 0:
        parser.error("all resource limits must be positive")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
