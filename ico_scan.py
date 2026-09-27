#!/usr/bin/env python3
"""Autonomous, offline file triage for authorized CTF artifacts."""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import hashlib
import json
import os
import re
import shutil
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import urlsplit

from ico_scan_core import (
    Artifact,
    Classification,
    CommandRunner,
    CommandResult,
    FLAG_XOR_CRIBS,
    FlagMatcher,
    MAX_GENERIC_XOR_BYTES,
    as_jsonable,
    classify,
    encoded_views,
    flag_triage,
    read_text_views,
    sha256_file,
    single_byte_xor_views,
)
from ico_scan_profiles import ArchiveExtractor, ToolProfile, filter_profiles_for_mode, is_archive, profiles_for
from ico_quals_solvers import discover_ico_quals_roots, solve_ico_quals_root, write_qual_answer_index
from ico_solver_engine import SolverContext, SolverLimits, SolverRegistry
from ico_task_solvers import (
    discover_task_dirs,
    extract_task_pack,
    load_expected_hashes,
    select_solver,
    solve_task,
    task_category_label,
    task_manifest_path,
)
from ico_universal_registry import build_default_registry
from ico_universal_reverse import extract_utf16le_strings


DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_FILES = 1000
DEFAULT_MAX_BYTES = 100 * 1024 * 1024
DEFAULT_TOOL_TIMEOUT = 30.0
DEFAULT_ARCHIVE_TIMEOUT = 300.0
LARGE_BINARY_ANALYSIS_LIMIT = MAX_GENERIC_XOR_BYTES
SINGLE_BYTE_XOR_PREFIXES = FLAG_XOR_CRIBS
QUALS_DOCUMENT_NAMES = {
    "ICO_full_walkthrough.md",
    "ico_ctf_writeup.md",
    "ICO_self_solve_manual.md",
    "ICO_final_selection_prep.md",
    "ICO_learning_course.md",
}
ENCODED_SCAN_BYTES = 4 * 1024 * 1024


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return cleaned or "artifact"


def _ensure_candidate_triage(candidate: dict[str, Any]) -> dict[str, Any]:
    if "triage" not in candidate:
        triage, reason = flag_triage(str(candidate.get("value", "")))
        candidate["triage"] = triage
        if reason:
            candidate["triage_reason"] = reason
    return candidate


def _candidate_triage_suffix(candidate: dict[str, Any]) -> str:
    suffix = f"triage={candidate.get('triage', 'candidate')}"
    reason = candidate.get("triage_reason")
    return f"{suffix} ({reason})" if reason else suffix


def _is_low_priority_candidate(candidate: dict[str, Any]) -> bool:
    triage = candidate.get("triage")
    if triage is None:
        triage, _ = flag_triage(str(candidate.get("value", "")))
    return triage in {"likely-placeholder", "likely-noise"}


def _low_priority_candidates(report: dict[str, Any]) -> list[dict[str, Any]]:
    low_priority: dict[str, dict[str, Any]] = {}
    for candidate in report.get("candidates", []):
        value = str(candidate.get("value", "")).strip()
        if value and _is_low_priority_candidate(candidate):
            low_priority.setdefault(value, candidate)
    return list(low_priority.values())


def _actionable_candidate_values(report: dict[str, Any]) -> list[str]:
    values: list[str] = []
    seen: set[str] = set()
    for candidate in report.get("candidates", []):
        value = str(candidate.get("value", "")).strip()
        if value and not _is_low_priority_candidate(candidate) and value not in seen:
            seen.add(value)
            values.append(value)
    return values


def _iter_directory(path: Path) -> Iterable[Path]:
    for current, directories, files in os.walk(path, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name
            for name in directories
            if not (current_path / name).is_symlink()
            and not name.startswith(".")
            and name not in {"ico-scan-runs", "commands", "artifacts", "__pycache__"}
        ]
        for filename in sorted(files):
            candidate = current_path / filename
            if not filename.startswith(".") and not candidate.is_symlink() and candidate.is_file():
                yield candidate


def _initial_artifacts(
    inputs: Sequence[str], events: list[dict[str, Any]], *, exclude_roots: Sequence[Path] = ()
) -> list[Artifact]:
    artifacts: list[Artifact] = []
    seen: set[Path] = set()
    excluded = [root.resolve() for root in exclude_roots]

    def is_excluded(candidate: Path) -> bool:
        return any(candidate == root or root in candidate.parents for root in excluded)

    for raw in inputs:
        path = Path(raw).expanduser()
        try:
            resolved = path.resolve()
        except OSError as exc:
            events.append({"type": "input-error", "path": str(path), "error": f"{type(exc).__name__}: {exc}"})
            continue
        if not resolved.exists():
            events.append({"type": "input-error", "path": str(resolved), "error": "path does not exist"})
            continue
        candidates = [resolved] if resolved.is_file() else list(_iter_directory(resolved)) if resolved.is_dir() else []
        for candidate in candidates:
            candidate = candidate.resolve()
            if is_excluded(candidate):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            artifacts.append(Artifact(candidate, depth=0, parent=None))
    return artifacts


def _task_manifests(
    task_dirs: Sequence[Path], *, max_files: int, max_bytes: int
) -> dict[Path, tuple[Path, ...]]:
    """Build bounded, read-only evidence manifests for discovered task roots."""

    manifests: dict[Path, tuple[Path, ...]] = {}
    ignored = {"ico-scan-runs", "commands", "artifacts", "__pycache__"}
    for raw_root in task_dirs:
        root = raw_root.resolve()
        statement = task_manifest_path(root)
        files: list[Path] = []
        if not root.is_dir():
            manifests[root] = ()
            continue
        for current, directories, names in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = [
                name
                for name in directories
                if not name.startswith(".")
                and name not in ignored
                and not (current_path / name).is_symlink()
            ]
            for name in sorted(names):
                candidate = current_path / name
                if name.startswith(".") or (statement is not None and candidate.resolve() == statement.resolve()):
                    continue
                if candidate.is_symlink() or not candidate.is_file():
                    continue
                try:
                    candidate.resolve().relative_to(root)
                except (OSError, ValueError):
                    continue
                files.append(candidate.resolve())
                if len(files) >= max_files:
                    break
            if len(files) >= max_files:
                break
        manifests[root] = tuple(sorted(files))
    return manifests


def _task_for_path(path: Path, task_dirs: Sequence[Path]) -> Path | None:
    """Return the deepest discovered task root containing ``path``."""

    matches: list[Path] = []
    resolved = path.resolve()
    for raw_root in task_dirs:
        root = raw_root.resolve()
        try:
            resolved.relative_to(root)
        except (OSError, ValueError):
            continue
        matches.append(root)
    return max(matches, key=lambda item: len(item.parts)) if matches else None


def _task_coverage(
    task_dirs: Sequence[Path],
    artifacts: Sequence[dict[str, Any]],
    universal_results: Sequence[dict[str, Any]],
    task_results: Sequence[dict[str, Any]],
    candidates: Sequence[dict[str, Any]],
    *,
    max_bytes: int,
) -> list[dict[str, Any]]:
    """Summarize per-task local evidence without treating candidates as solves."""

    roots = sorted({Path(raw).expanduser().resolve() for raw in task_dirs}, key=str)
    by_root: dict[Path, list[dict[str, Any]]] = {root: [] for root in roots}
    candidate_rows: dict[Path, dict[tuple[str, str], dict[str, Any]]] = {root: {} for root in roots}

    def belongs(path_value: object, root: Path) -> bool:
        if not isinstance(path_value, (str, Path)) or not str(path_value):
            return False
        try:
            Path(path_value).expanduser().resolve().relative_to(root)
        except (OSError, ValueError):
            return False
        return True

    def row_for_candidate(
        candidate: dict[str, Any],
        *,
        fallback_artifact: str = "",
    ) -> dict[str, Any]:
        artifact = str(candidate.get("artifact") or fallback_artifact)
        return {
            "value": str(candidate.get("value", "")),
            "state": str(candidate.get("state", "candidate")),
            "triage": str(candidate.get("triage", "candidate")),
            "triage_reason": str(candidate.get("triage_reason", "")),
            "artifact": artifact,
            "analyzer": str(candidate.get("analyzer", "")),
            "source": str(candidate.get("source", "")),
            "verification": str(candidate.get("verification", "")),
            "acceptance_evidence": candidate.get("acceptance_evidence"),
        }

    def add_candidate(root: Path, candidate: dict[str, Any], *, fallback_artifact: str = "") -> None:
        row = row_for_candidate(candidate, fallback_artifact=fallback_artifact)
        value = row["value"]
        if not value:
            return
        key = (value, row["artifact"])
        candidate_rows[root].setdefault(key, row)

    def result_root(result: dict[str, Any]) -> Path | None:
        context = result.get("evidence_context")
        if isinstance(context, dict):
            metadata = context.get("metadata")
            raw_root = metadata.get("task_root") if isinstance(metadata, dict) else None
            if isinstance(raw_root, str) and raw_root:
                try:
                    resolved = Path(raw_root).expanduser().resolve()
                except OSError:
                    resolved = None
                if resolved in by_root:
                    return resolved
            input_path = context.get("input_path")
            if isinstance(input_path, str):
                try:
                    return _task_for_path(Path(input_path), roots)
                except OSError:
                    pass
        raw_task_dir = result.get("task_dir")
        if isinstance(raw_task_dir, str):
            try:
                resolved = Path(raw_task_dir).expanduser().resolve()
            except OSError:
                resolved = None
            if resolved in by_root:
                return resolved
        return None

    for result in universal_results:
        root = result_root(result)
        if root is None:
            continue
        by_root[root].append(result)
        context = result.get("evidence_context")
        input_path = context.get("input_path", "") if isinstance(context, dict) else ""
        for candidate in result.get("candidates", []):
            if isinstance(candidate, dict):
                add_candidate(root, candidate, fallback_artifact=str(input_path))

    for result in task_results:
        root = result_root(result)
        if root is None:
            continue
        by_root[root].append(result)
        for candidate in result.get("candidates", []):
            if isinstance(candidate, dict):
                add_candidate(root, candidate, fallback_artifact=str(result.get("task_dir", "")))

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        for root in roots:
            if belongs(candidate.get("artifact"), root):
                add_candidate(root, candidate)

    summaries: list[dict[str, Any]] = []
    for root in roots:
        task_file = task_manifest_path(root) or (root / "task.txt")
        task_text = ""
        try:
            with task_file.open("rb") as handle:
                task_text = handle.read(max_bytes).decode("utf-8", errors="replace")
        except OSError:
            pass

        def field(name: str) -> str:
            match = re.search(rf"(?im)^\s*(?:#+\s*)?(?:\*\*)?{re.escape(name)}(?:\*\*)?\s*:\s*(.*?)\s*$", task_text)
            return match.group(1).strip() if match else ""

        description_match = re.search(r"(?ims)^Description\s*:\s*(.*)$", task_text)
        if description_match:
            description = description_match.group(1).strip()[:4000]
        elif task_file.suffix.lower() == ".md":
            description = task_text.strip()[:4000]
        else:
            description = ""
        markdown_title = re.search(r"(?m)^#\s+(.+?)\s*#*\s*$", task_text)
        result_items = by_root[root]
        solver_statuses: dict[str, int] = {}
        solvers: set[str] = set()
        for result in result_items:
            status = str(result.get("status", "unknown"))
            solver_statuses[status] = solver_statuses.get(status, 0) + 1
            solver = str(result.get("solver") or result.get("category") or "unknown")
            solvers.add(solver)

        task_candidates = sorted(
            candidate_rows[root].values(),
            key=lambda item: (item["value"], item["artifact"], item["analyzer"]),
        )
        candidate_values = {item["value"] for item in task_candidates}
        usable_candidates = [item for item in task_candidates if item["triage"] == "candidate"]
        states = {str(item.get("status", "")) for item in result_items}
        analysis_notes: list[str] = []
        for result in result_items:
            solver_name = str(result.get("solver") or result.get("category") or "analysis")
            error = result.get("error")
            if isinstance(error, str) and error.strip():
                analysis_notes.append(f"{solver_name}: {error.strip()}")
            for step in result.get("steps", []):
                if not isinstance(step, dict):
                    continue
                details = step.get("details")
                if not isinstance(details, dict):
                    continue
                for reason in details.get("review_reasons", []):
                    if isinstance(reason, str) and reason.strip():
                        analysis_notes.append(reason.strip())
                for key in ("blocker", "reason", "error"):
                    value = details.get(key)
                    if isinstance(value, str) and value.strip():
                        analysis_notes.append(value.strip())
        analysis_notes = list(dict.fromkeys(note[:320] for note in analysis_notes))[:5]
        if any(item["state"] == "hash-verified" for item in task_candidates) or "hash-verified" in states:
            status = "hash-verified"
            confirmation = "local-hash-match"
        elif usable_candidates:
            status = "candidate"
            confirmation = "local-only"
        elif "payload-ready" in states:
            status = "payload-ready"
            confirmation = "payload-not-executed"
        elif "requires-authorized-session" in states:
            status = "requires-authorized-session"
            confirmation = "authorized-session-required"
        elif task_candidates or states.intersection({"candidate-review", "needs-review"}):
            status = "candidate-review"
            confirmation = "manual-review-required"
        elif "failed" in states:
            status = "failed"
            confirmation = "analysis-error"
        elif states - {"unsupported", "not-applicable", "skipped"}:
            status = "inspected-no-candidate"
            confirmation = "no-exact-candidate"
        elif result_items:
            status = "unsupported"
            confirmation = "no-compatible-offline-solver"
        else:
            status = "not-inspected"
            confirmation = "no-solver-result"

        artifact_paths = {
            str(item.get("path", ""))
            for item in artifacts
            if belongs(item.get("path"), root)
        }
        if task_file.is_file():
            artifact_paths.add(str(task_file.resolve()))
        summaries.append(
            {
                "task_root": str(root),
                "task_file": str(task_file) if task_file.is_file() else None,
                "title": field("Title") or (markdown_title.group(1).strip() if markdown_title else root.name),
                "category": field("Category") or task_category_label(root),
                "difficulty": field("Difficulty"),
                "description": description,
                "status": status,
                "confirmation": confirmation,
                "artifact_count": len(artifact_paths),
                "result_count": len(result_items),
                "solver_count": len(solvers),
                "solvers": sorted(solvers),
                "solver_statuses": solver_statuses,
                "analysis_notes": analysis_notes,
                "candidate_count": len(candidate_values),
                "candidates": task_candidates,
            }
        )
    return summaries


def _result_event(
    profile: ToolProfile,
    path: Path,
    result: Any,
    *,
    input_sha256: str | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    outcome = _profile_outcome(result)
    event = {
        "type": "tool",
        "analyzer": profile.name,
        "stage": profile.stage,
        "artifact": str(path),
        "result": result.to_dict(),
        "outcome": outcome,
    }
    if input_sha256 is not None:
        event["input_sha256"] = input_sha256
    if timeout_seconds is not None:
        event["timeout_seconds"] = timeout_seconds
    return event


def _profile_outcome(result: CommandResult) -> str:
    """Map a bounded command result to an actionable evidence outcome."""

    if result.missing:
        return "unavailable"
    if result.timed_out:
        return "timed-out"
    if result.returncode == 0:
        return "ok"
    text = result.combined_output().lower()
    malformed_markers = (
        "invalid",
        "malformed",
        "corrupt",
        "bad magic",
        "cannot identify",
        "not a valid",
        "unsupported format",
        "syntax error",
    )
    if any(marker in text for marker in malformed_markers):
        return "malformed-input"
    return "failed"


def _executable_identity(executable: str) -> dict[str, Any]:
    """Return a stable local identity for an analyzer executable.

    The scanner deliberately does not execute ``--version`` for every tool:
    that would add another unbounded subprocess per profile.  The resolved
    path plus inode metadata still invalidates a run-local cache when the
    installed binary is replaced, while the missing marker prevents a cached
    successful result from masking a later unavailable tool.
    """

    resolved = shutil.which(executable)
    if not resolved:
        return {"path": None, "size": None, "mtime_ns": None}
    try:
        path = Path(resolved).resolve()
        stat = path.stat()
        return {"path": str(path), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    except OSError:
        return {"path": str(resolved), "size": None, "mtime_ns": None}


def _normalized_args(args: Sequence[str], path: Path) -> list[str]:
    """Normalize input paths so identical bytes at different paths can reuse a result."""

    raw_path = str(path)
    resolved_path = str(path.resolve())
    normalized: list[str] = []
    for value in args:
        text = str(value)
        if text in {raw_path, resolved_path}:
            normalized.append("<input>")
        else:
            normalized.append(text)
    return normalized


def _command_cache_key(
    *,
    input_sha256: str,
    analyzer: str,
    executable: dict[str, Any],
    args: Sequence[str],
    path: Path,
    task_context: str = "",
) -> tuple[str, dict[str, Any]]:
    invocation = {
        "schema_version": 1,
        "input_sha256": input_sha256,
        "analyzer": analyzer,
        "executable": executable,
        "args": _normalized_args(args, path),
        "task_context": task_context,
    }
    encoded = json.dumps(invocation, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest(), invocation


def _command_result_from_dict(value: dict[str, Any]) -> CommandResult:
    """Rehydrate a bounded command result stored in the run-local cache."""

    return CommandResult(
        args=[str(item) for item in value.get("args", [])],
        returncode=value.get("returncode"),
        stdout=str(value.get("stdout", "")),
        stderr=str(value.get("stderr", "")),
        timed_out=bool(value.get("timed_out", False)),
        missing=bool(value.get("missing", False)),
        duration_seconds=float(value.get("duration_seconds", 0.0) or 0.0),
        log_path=value.get("log_path"),
    )


def _run_cached_command(
    runner: CommandRunner,
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: float,
    log_name: str,
    cache_dir: Path,
    input_sha256: str,
    analyzer: str,
    input_path: Path,
    task_context: str = "",
) -> tuple[CommandResult, bool, Path, dict[str, Any]]:
    """Run one external analyzer with a serialized, run-local cache.

    The cache is intentionally scoped to the report directory.  It is never
    consulted before the input and task-context fingerprints are part of the
    key, so changing bytes or a companion file cannot reuse stale evidence.
    """

    cache_dir.mkdir(parents=True, exist_ok=True)
    executable = _executable_identity(str(args[0]) if args else "")
    key, invocation = _command_cache_key(
        input_sha256=input_sha256,
        analyzer=analyzer,
        executable=executable,
        args=args,
        path=input_path,
        task_context=task_context,
    )
    cache_path = cache_dir / f"{key}.json"
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if cached.get("invocation") == invocation and isinstance(cached.get("result"), dict):
            return _command_result_from_dict(cached["result"]), True, cache_path, cached
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        pass

    result = runner.run(args, cwd=cwd, timeout=timeout, log_name=log_name)
    payload = {
        "schema_version": 1,
        "invocation": invocation,
        "result": result.to_dict(),
        "original": {
            "artifact": str(input_path),
            "log_path": result.log_path,
            "log_name": log_name,
        },
    }
    try:
        temporary = cache_path.with_name(f"{cache_path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, cache_path)
    except OSError:
        # Evidence collection must continue even if the optional cache cannot
        # be written (for example, a read-only report destination).
        try:
            temporary.unlink()
        except (UnboundLocalError, OSError):
            pass
    return result, False, cache_path, payload


def _run_scan_profile_batch(
    profiles: Sequence[ToolProfile],
    *,
    path: Path,
    runner: CommandRunner,
    tool_timeout: float,
    cache_dir: Path,
    input_sha256: str,
    task_context: str,
    workers: int,
) -> list[tuple[ToolProfile, CommandResult, bool, Path, dict[str, Any]]]:
    """Run independent scanner profiles concurrently, preserving order."""

    jobs = list(profiles)
    if not jobs:
        return []

    def submit_one(profile: ToolProfile) -> tuple[CommandResult, bool, Path, dict[str, Any]]:
        args = profile.args_for(path)
        return _run_cached_command(
            runner,
            args,
            cwd=path.parent,
            timeout=min(profile.timeout, tool_timeout),
            log_name=f"{_safe_name(profile.name)}-{_safe_name(path.name)}",
            cache_dir=cache_dir,
            input_sha256=input_sha256,
            analyzer=profile.name,
            input_path=path,
            task_context=task_context,
        )

    if workers <= 1 or len(jobs) == 1:
        return [(profile, *submit_one(profile)) for profile in jobs]

    executor = ThreadPoolExecutor(max_workers=min(workers, len(jobs)), thread_name_prefix="ico-scan-profile")
    futures: dict[Future[tuple[CommandResult, bool, Path, dict[str, Any]]], tuple[int, ToolProfile]] = {}
    results: dict[int, tuple[ToolProfile, CommandResult, bool, Path, dict[str, Any]]] = {}
    duplicate_of: dict[int, int] = {}
    signatures: dict[str, int] = {}
    try:
        for index, profile in enumerate(jobs):
            args = profile.args_for(path)
            signature_payload = json.dumps(
                {
                    "analyzer": profile.name,
                    "args": _normalized_args(args, path),
                    "collect": bool(getattr(profile, "collect_dir", None)),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            if signature_payload in signatures and getattr(profile, "collect_dir", None) is None:
                duplicate_of[index] = signatures[signature_payload]
                continue
            signatures[signature_payload] = index
            futures[executor.submit(submit_one, profile)] = (index, profile)
        for future in as_completed(futures):
            index, profile = futures[future]
            try:
                results[index] = (profile, *future.result())
            except Exception as exc:
                failed = CommandResult(
                    args=profile.args_for(path),
                    returncode=None,
                    stderr=f"{type(exc).__name__}: {exc}",
                )
                results[index] = (profile, failed, False, cache_dir / "unavailable.json", {})
        # A duplicate profile is intentionally replayed after its first copy
        # has populated the cache.  This preserves the old cache evidence
        # contract while allowing all distinct profiles to overlap.
        for index, original_index in duplicate_of.items():
            profile = jobs[index]
            results[index] = (profile, *submit_one(profile))
    finally:
        executor.shutdown(wait=True, cancel_futures=False)
    return [results[index] for index in range(len(jobs))]


def _builtin_result_event(
    name: str,
    path: Path,
    result: CommandResult,
    *,
    input_sha256: str | None = None,
) -> dict[str, Any]:
    event = {
        "type": "builtin",
        "analyzer": name,
        "stage": "fast",
        "artifact": str(path),
        "result": result.to_dict(),
        "outcome": _profile_outcome(result),
    }
    if input_sha256 is not None:
        event["input_sha256"] = input_sha256
    return event


def _run_single_byte_xor(path: Path, runner: CommandRunner) -> tuple[CommandResult, list[dict[str, Any]]]:
    started = time.monotonic()
    args = [
        "builtin:xor-single-byte",
        "--keys",
        "0..255",
        "--prefixes",
        ",".join(prefix.decode("ascii") for prefix in SINGLE_BYTE_XOR_PREFIXES),
        str(path),
    ]
    try:
        with path.open("rb") as handle:
            data = handle.read(8 * 1024 * 1024)
        total_size = path.stat().st_size
    except OSError as exc:
        result = CommandResult(
            args=args,
            returncode=None,
            stderr=f"{type(exc).__name__}: {exc}",
            duration_seconds=time.monotonic() - started,
        )
        return result, []

    views = single_byte_xor_views(data, prefixes=SINGLE_BYTE_XOR_PREFIXES)
    lines = [
        "algorithm=single-byte-xor",
        "keys=0..255",
        f"bytes_scanned={len(data)}",
        f"bytes_total={total_size}",
        f"truncated={total_size > len(data)}",
        f"crib_matches={len(views)}",
    ]
    for view in views:
        prefix = view["prefix"].decode("ascii", errors="replace")
        lines.append(f"key=0x{view['key']:02x} offset={view['offset']} prefix={prefix}")
    result = CommandResult(
        args=args,
        returncode=0,
        stdout="\n".join(lines),
        duration_seconds=time.monotonic() - started,
    )
    write_log = getattr(runner, "_write_log", None)
    if callable(write_log):
        write_log(f"xor-single-byte-{_safe_name(path.name)}", result)
    return result, views


def _run_utf16le_strings(path: Path, runner: CommandRunner, *, max_bytes: int) -> CommandResult:
    """Run the portable UTF-16LE string pass used on every platform."""

    started = time.monotonic()
    args = ["builtin:strings-utf16le", str(path)]
    try:
        total_size = path.stat().st_size
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        values = extract_utf16le_strings(data, limit=256)
        output = "\n".join(values)
        if truncated:
            output = (output + "\n" if output else "") + "truncated=true"
        result = CommandResult(
            args=args,
            returncode=0,
            stdout=output,
            duration_seconds=time.monotonic() - started,
        )
    except OSError as exc:
        result = CommandResult(
            args=args,
            returncode=None,
            stderr=f"{type(exc).__name__}: {exc}",
            duration_seconds=time.monotonic() - started,
        )
    write_log = getattr(runner, "_write_log", None)
    if callable(write_log):
        write_log(f"strings-utf16le-{_safe_name(path.name)}", result)
    return result


def _relative_or_absolute(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return str(path)


def _derived_artifact_paths(report: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    for result_group in ("task_results", "quals_task_results", "universal_results"):
        for result in report.get(result_group, []):
            for artifact in result.get("artifacts", []):
                if artifact is not None and str(artifact).strip():
                    paths.add(str(artifact))
    return paths


def _write_report_text(report: dict[str, Any], path: Path) -> None:
    task_results = report.get("task_results", [])
    task_coverage = report.get("task_coverage", [])
    derived_artifact_count = len(_derived_artifact_paths(report))
    lines = [
        "ico-scan offline report",
        f"Started: {report.get('started_at', '')}",
        f"Finished: {report.get('finished_at', '')}",
        f"Generic artifacts: {len(report.get('artifacts', []))}",
        f"Task artifacts: {len(task_results)}",
        f"Challenge tasks: {len(task_coverage)}",
        f"Derived artifacts: {derived_artifact_count}",
        f"Candidates: {len(report.get('candidates', []))}",
        "",
    ]
    if task_results:
        lines.append("Task solvers:")
        for task in task_results:
            lines.append(
                f"- {task.get('task_id')} | solver={task.get('solver')} | "
                f"status={task.get('status')} | candidates={len(task.get('candidates', []))}"
            )
        lines.append("")
    if task_coverage:
        lines.extend(["Challenge task coverage (local evidence; not platform confirmation):"])
        for task in task_coverage:
            notes = [str(note) for note in task.get("analysis_notes", []) if str(note).strip()]
            note_suffix = f"; notes={' | '.join(notes)}" if notes else ""
            lines.append(
                f"- {task.get('title')} | category={task.get('category') or 'unknown'} | "
                f"difficulty={task.get('difficulty') or 'unknown'} | status={task.get('status')} | "
                f"artifacts={task.get('artifact_count')} | candidates={task.get('candidate_count')} | "
                f"solvers={','.join(task.get('solvers', []))}{note_suffix}"
            )
        lines.append("")
    candidates = report.get("candidates", [])
    if candidates:
        lines.append("Candidates and local verification results:")
        for candidate in candidates:
            lines.append(
                f"- {candidate['value']} | artifact={candidate['artifact']} | "
                f"state={candidate.get('state', 'candidate')} | triage={candidate.get('triage', 'candidate')} | "
                f"triage_reason={candidate.get('triage_reason', '')} | analyzer={candidate['analyzer']} | "
                f"source={candidate.get('source', '')}:{candidate.get('line', 1)}"
            )
        low_priority = _low_priority_candidates(report)
        if low_priority:
            lines.extend(["", "Low-priority flag-shaped values (retained as candidates):"])
            for candidate in low_priority:
                lines.append(
                    f"- {candidate.get('triage')}: {candidate.get('value')} | "
                    f"reason={candidate.get('triage_reason', '')} | artifact={candidate.get('artifact', '')}"
                )
    else:
        lines.append("No flag-shaped candidates found.")
    references = report.get("reference_candidates", [])
    if references:
        lines.extend(["", "Historical walkthrough references (not current-run proof):"])
        for reference in references:
            lines.append(
                f"- {reference['value']} | task={reference.get('task_id', '')} | "
                f"state={reference.get('state', 'reference-only')} | source={reference.get('source', '')}"
            )
    answer_indexes = report.get("quals_answer_indexes", [])
    if answer_indexes:
        lines.extend(["", "Complete quals answer indexes:"])
        for index in answer_indexes:
            lines.append(
                f"- tasks={index.get('task_count', 0)} | historical_tasks={index.get('historical_task_count', 0)} | "
                f"historical_answers={index.get('historical_answer_count', 0)} | "
                f"json={index.get('json', '')} | markdown={index.get('markdown', '')} | "
                f"bundle={index.get('bundle', '')}"
            )
    lines.extend(["", "Artifacts:"])
    for artifact in report.get("artifacts", []):
        classification = artifact.get("classification", {})
        lines.append(
            f"- {artifact.get('path')} | kind={classification.get('kind')} | "
            f"mime={classification.get('mime')} | depth={artifact.get('depth')}"
        )
    if report.get("events"):
        lines.extend(["", f"Events recorded: {len(report['events'])}"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_scan(
    inputs: list[str],
    *,
    out_dir: Path,
    patterns: list[str] | None = None,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_files: int = DEFAULT_MAX_FILES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    tool_timeout: float = DEFAULT_TOOL_TIMEOUT,
    archive_timeout: float = DEFAULT_ARCHIVE_TIMEOUT,
    allow_stegseek_seed: bool = False,
    allow_network: bool = False,
    authorized_targets: Sequence[str] = (),
    verbose: bool = True,
    solver_registry: SolverRegistry | None = None,
    runner: CommandRunner | None = None,
    profile_selector: Callable[[Classification], list[ToolProfile]] = profiles_for,
    mode: str = "full",
    progress: bool = False,
    profile_workers: int = 4,
    deadline_seconds: float | None = None,
) -> dict[str, Any]:
    if mode not in {"fast", "full"}:
        raise ValueError(f"unsupported scan mode: {mode}")
    profile_workers = max(1, min(int(profile_workers), 32))
    scan_started = time.monotonic()
    deadline_at = None if deadline_seconds is None else scan_started + max(0.0, deadline_seconds)

    def remaining_budget() -> float | None:
        return None if deadline_at is None else max(0.0, deadline_at - time.monotonic())
    out_dir = out_dir.expanduser().resolve()
    events: list[dict[str, Any]] = []
    command_dir = out_dir / "commands"
    artifact_dir = out_dir / "artifacts"
    cache_dir = out_dir / "cache"
    command_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)
    runner = runner or CommandRunner(command_dir)

    # A downloaded pack is often supplied as one ZIP rather than an already
    # extracted directory. Materialize only ZIPs that visibly contain task
    # statements, then run the normal task-aware solvers against that source.
    # The original pack archive is excluded from the generic queue so README
    # prose and duplicate extracted copies cannot become noisy candidates.
    task_pack_roots: list[Path] = []
    task_pack_archives: set[Path] = set()
    prepared_inputs = list(inputs)
    for raw in inputs:
        candidate = Path(raw).expanduser()
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if not resolved.is_file() or resolved.suffix.lower() not in {".zip", ".pk3"}:
            continue
        try:
            digest = sha256_file(resolved)
            destination = out_dir / "sources" / "task-packs" / digest[:12]
            extracted = extract_task_pack(resolved, destination)
        except Exception as exc:
            events.append(
                {
                    "type": "task-pack-error",
                    "path": str(resolved),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        if extracted is not None:
            task_pack_roots.append(extracted)
            task_pack_archives.add(resolved)
            prepared_inputs.append(str(extracted))
            events.append(
                {
                    "type": "task-pack-extracted",
                    "archive": str(resolved),
                    "source": str(extracted),
                }
            )

    task_dirs = discover_task_dirs(prepared_inputs)
    task_manifests = _task_manifests(task_dirs, max_files=max_files, max_bytes=max_bytes)
    quals_roots = discover_ico_quals_roots(inputs)
    # Known task families have dedicated authoritative solvers.  Unknown task
    # statements remain in the generic queue so the universal registry can
    # still inspect their evidence instead of stopping at dispatcher failure.
    authoritative_task_roots: list[Path] = []
    for task_dir in task_dirs:
        try:
            statement = task_manifest_path(task_dir)
            if statement is None:
                continue
            task_text = statement.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if select_solver(task_text, task_dir / "artifact") is not None:
            authoritative_task_roots.append(task_dir)
    excluded_roots = [out_dir, *authoritative_task_roots, *task_pack_roots]
    if quals_roots and mode == "fast":
        # The dedicated quals dispatcher has already inspected every known
        # task.  Re-queuing all of its PNG/WAV/PCAP sidecars through the
        # generic media stack creates thousands of derivative files while
        # adding no flag evidence.  Keep full mode exhaustive; fast mode is
        # deliberately task-first for this recognized pack.
        excluded_roots.extend(quals_roots)
        events.append(
            {
                "type": "quals-generic-skip",
                "roots": [str(root) for root in quals_roots],
                "reason": "fast mode uses the dedicated ICO-quals solvers first",
            }
        )
    generic_inputs: list[str] = []
    for raw in inputs:
        try:
            resolved = Path(raw).expanduser().resolve()
        except OSError:
            continue
        if resolved not in task_pack_archives:
            generic_inputs.append(raw)
    initial_queue = _initial_artifacts(generic_inputs, events, exclude_roots=excluded_roots)
    if quals_roots:
        # Task-aware solvers handle the known ten tasks, while the bounded
        # generic pass still examines every supplied challenge artifact.  The
        # walkthrough/course documents are excluded so their printed answers
        # remain reference-only instead of becoming fresh candidates.
        quals_rules_docs = {
            (root / "RULES.md").resolve()
            for root in quals_roots
            if (root / "RULES.md").is_file()
        }
        initial_queue = [
            artifact
            for artifact in initial_queue
            if artifact.path.name not in QUALS_DOCUMENT_NAMES
            and artifact.path.resolve() not in quals_rules_docs
        ]
    if task_dirs:
        pack_control_files = {"README.md", "CHEATSHEET.md", "flag_hashes.json"}
        task_manifest_paths = {
            statement.resolve()
            for task_dir in task_dirs
            if (statement := task_manifest_path(task_dir)) is not None
        }
        initial_queue = [
            artifact
            for artifact in initial_queue
            if artifact.path.name not in pack_control_files and artifact.path.resolve() not in task_manifest_paths
        ]
    matcher = FlagMatcher(patterns)
    started_at = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "schema_version": 2,
        "started_at": started_at,
        "inputs": [str(Path(item).expanduser()) for item in inputs],
        "limits": {
            "max_depth": max_depth,
            "max_files": max_files,
            "max_bytes": max_bytes,
            "tool_timeout": tool_timeout,
            "archive_timeout": archive_timeout,
            "allow_stegseek_seed": allow_stegseek_seed,
            "allow_network": allow_network,
            "authorized_targets": list(authorized_targets),
            "mode": mode,
            "profile_workers": profile_workers,
            "deadline_seconds": deadline_seconds,
        },
        "artifacts": [],
        "candidates": [],
        "reference_candidates": [],
        "quals_answer_indexes": [],
        "task_results": [],
        "task_coverage": [],
        "quals_task_results": [],
        "universal_results": [],
        "events": events,
    }
    if allow_network:
        if not authorized_targets:
            raise ValueError("active mode requires at least one --authorized-target")
        blocked_target = next(
            (
                target
                for target in authorized_targets
                if (urlsplit(str(target)).hostname or str(target).split(":", 1)[0]).lower().rstrip(".") == "cyberolympiad.kz"
                or (urlsplit(str(target)).hostname or str(target).split(":", 1)[0]).lower().rstrip(".").endswith(".cyberolympiad.kz")
            ),
            None,
        )
        if blocked_target is not None:
            raise ValueError(f"platform host is always blocked: {blocked_target}")
        events.append(
            {
                "type": "active-mode-policy",
                "status": "configured",
                "targets": list(authorized_targets),
                "note": "No active request is made by the offline scanner; use ico_active.AuthorizedClient explicitly.",
            }
        )
    queue: deque[Artifact] = deque(initial_queue)
    queued_paths: set[Path] = set()
    for queued_artifact in queue:
        try:
            queued_paths.add(queued_artifact.path.resolve())
        except OSError:
            continue
    seen_paths: set[Path] = set()
    seen_hashes: set[str] = set()
    candidate_keys: dict[tuple[str, str], int] = {}
    processed = 0

    def emit_progress(stage: str, path: Path | None = None) -> None:
        if not progress:
            return
        suffix = f" path={path}" if path is not None else ""
        print(
            f"[ico-scan] stage={stage} processed={processed} queued={len(queue)}{suffix}",
            file=sys.stderr,
        )

    emit_progress("start")

    def enqueue_derived_inputs(
        result: Any,
        *,
        source: Path,
        depth: int,
        task_root: Path | None,
    ) -> None:
        derived_inputs = list(getattr(result, "derived_inputs", []) or [])
        if not derived_inputs:
            return
        if depth >= max_depth:
            events.append(
                {
                    "type": "derived-input-skip",
                    "source": str(source),
                    "solver": getattr(result, "solver", "unknown"),
                    "reason": "max_depth reached",
                    "count": len(derived_inputs),
                }
            )
            return
        accepted: list[Artifact] = []
        for raw_input in derived_inputs:
            try:
                raw_path = Path(str(raw_input)).expanduser()
                if raw_path.is_symlink():
                    raise ValueError("symbolic links are not accepted")
                derived_path = raw_path.resolve()
                derived_path.relative_to(artifact_dir.resolve())
                if not derived_path.is_file():
                    raise ValueError("not a regular file")
                if derived_path.stat().st_size > max_bytes:
                    raise ValueError("input exceeds byte limit")
            except (OSError, ValueError) as exc:
                events.append(
                    {
                        "type": "derived-input-skip",
                        "source": str(source),
                        "path": str(raw_input),
                        "solver": getattr(result, "solver", "unknown"),
                        "reason": str(exc),
                    }
                )
                continue
            if derived_path in queued_paths or derived_path in seen_paths:
                continue
            if processed + len(queue) + len(accepted) >= max_files:
                events.append(
                    {
                        "type": "derived-input-skip",
                        "source": str(source),
                        "path": str(derived_path),
                        "solver": getattr(result, "solver", "unknown"),
                        "reason": "max_files reached",
                    }
                )
                continue
            accepted.append(Artifact(derived_path, depth + 1, str(source), task_root))
        for derived_artifact in reversed(accepted):
            queue.appendleft(derived_artifact)
            queued_paths.add(derived_artifact.path)
            events.append(
                {
                    "type": "derived-input-queued",
                    "source": str(source),
                    "path": str(derived_artifact.path),
                    "solver": getattr(result, "solver", "unknown"),
                    "depth": derived_artifact.depth,
                }
            )

    def record_hits(hits: list[dict[str, Any]], artifact_path: Path, analyzer: str) -> None:
        for hit in hits:
            candidate = _ensure_candidate_triage(dict(hit))
            candidate["artifact"] = str(artifact_path)
            candidate["analyzer"] = analyzer
            key = (candidate["value"], candidate["artifact"])
            if key in candidate_keys:
                existing = report["candidates"][candidate_keys[key]]
                analyzers = existing.setdefault("analyzers", [existing["analyzer"]])
                if candidate["analyzer"] not in analyzers:
                    analyzers.append(candidate["analyzer"])
                existing.setdefault("evidence_sources", []).append(
                    {"analyzer": candidate["analyzer"], "source": candidate["source"], "line": candidate["line"]}
                )
                continue
            candidate["analyzers"] = [candidate["analyzer"]]
            candidate["evidence_sources"] = [
                {"analyzer": candidate["analyzer"], "source": candidate["source"], "line": candidate["line"]}
            ]
            candidate_keys[key] = len(report["candidates"])
            report["candidates"].append(candidate)
            if verbose:
                print(
                    f"{'LOW-PRIORITY FLAG-LIKE VALUE' if _is_low_priority_candidate(candidate) else 'FOUND CANDIDATE'}: {candidate['value']} "
                    f"[artifact={candidate['artifact']} analyzer={candidate['analyzer']} "
                    f"{_candidate_triage_suffix(candidate)}]"
                )

    def record_task_result(result: Any) -> None:
        serialized = result.to_dict()
        for hit in serialized.get("candidates", []):
            _ensure_candidate_triage(hit)
        report["task_results"].append(serialized)
        for hit in serialized.get("candidates", []):
            candidate = _ensure_candidate_triage(dict(hit))
            candidate.setdefault("source", candidate.get("evidence", candidate.get("artifact", str(result.task_dir))))
            candidate.setdefault("line", 1)
            candidate.setdefault("analyzer", f"task-solver:{result.solver}")
            candidate.setdefault("artifact", str(result.task_dir))
            candidate.setdefault("task_id", result.task_id)
            key = (candidate["value"], candidate["artifact"])
            if key in candidate_keys:
                existing = report["candidates"][candidate_keys[key]]
                if candidate.get("state") == "hash-verified":
                    existing["state"] = "hash-verified"
                    existing["verification"] = candidate.get("verification", existing.get("verification"))
                existing.setdefault("evidence_sources", []).append(
                    {"analyzer": candidate["analyzer"], "source": candidate["source"], "line": candidate["line"]}
                )
                continue
            candidate["analyzers"] = [candidate["analyzer"]]
            candidate["evidence_sources"] = [
                {"analyzer": candidate["analyzer"], "source": candidate["source"], "line": candidate["line"]}
            ]
            candidate_keys[key] = len(report["candidates"])
            report["candidates"].append(candidate)
            if verbose:
                print(
                    f"{'LOW-PRIORITY FLAG-LIKE VALUE' if _is_low_priority_candidate(candidate) else 'FOUND CANDIDATE'}: {candidate['value']} "
                    f"[artifact={candidate['artifact']} analyzer={candidate['analyzer']} "
                    f"state={candidate.get('state', 'candidate')} {_candidate_triage_suffix(candidate)}]"
                )

    def record_quals_result(result: Any) -> None:
        serialized = result.to_dict()
        for hit in serialized.get("candidates", []):
            _ensure_candidate_triage(hit)
        report["task_results"].append(serialized)
        report["quals_task_results"].append(serialized)
        report["reference_candidates"].extend(dict(reference) for reference in result.references)
        for hit in serialized.get("candidates", []):
            candidate = _ensure_candidate_triage(dict(hit))
            candidate.setdefault("source", candidate.get("evidence", str(result.task_dir)))
            candidate.setdefault("line", 1)
            candidate.setdefault("analyzer", f"quals-solver:{result.solver}")
            candidate.setdefault("artifact", str(result.task_dir))
            candidate.setdefault("task_id", result.task_id)
            key = (candidate["value"], candidate["artifact"])
            if key in candidate_keys:
                existing = report["candidates"][candidate_keys[key]]
                if candidate.get("state") == "hash-verified":
                    existing["state"] = "hash-verified"
                    existing["verification"] = candidate.get("verification", existing.get("verification"))
                existing.setdefault("evidence_sources", []).append(
                    {"analyzer": candidate["analyzer"], "source": candidate["source"], "line": candidate["line"]}
                )
                continue
            candidate["analyzers"] = [candidate["analyzer"]]
            candidate["evidence_sources"] = [
                {"analyzer": candidate["analyzer"], "source": candidate["source"], "line": candidate["line"]}
            ]
            candidate_keys[key] = len(report["candidates"])
            report["candidates"].append(candidate)
            if verbose:
                print(
                    f"{'LOW-PRIORITY FLAG-LIKE VALUE' if _is_low_priority_candidate(candidate) else 'FOUND CANDIDATE'}: {candidate['value']} "
                    f"[artifact={candidate['artifact']} analyzer={candidate['analyzer']} "
                    f"state={candidate.get('state', 'candidate')} {_candidate_triage_suffix(candidate)}]"
                )

    processed_quals_roots: set[Path] = set()

    def process_quals_root(root: Path) -> None:
        resolved_root = root.resolve()
        if resolved_root in processed_quals_roots:
            return
        processed_quals_roots.add(resolved_root)
        quals_results = solve_ico_quals_root(resolved_root, out_dir)
        report["quals_answer_indexes"].append(write_qual_answer_index(quals_results, out_dir))
        for quals_result in quals_results:
            record_quals_result(quals_result)

    def record_universal_result(result: Any, artifact_path: Path, context: SolverContext | None = None) -> None:
        serialized = result.to_dict()
        for hit in serialized.get("candidates", []):
            _ensure_candidate_triage(hit)
        if context is not None:
            serialized["evidence_context"] = {
                "input_path": str(context.input_path),
                "task_text": context.task_text,
                "related_paths": [str(item) for item in context.related_paths],
                "metadata": context.metadata,
            }
        report["universal_results"].append(serialized)
        hits: list[dict[str, Any]] = []
        for hit in serialized.get("candidates", []):
            candidate = _ensure_candidate_triage(dict(hit))
            candidate.setdefault("source", candidate.get("evidence", str(artifact_path)))
            candidate.setdefault("line", 1)
            candidate.setdefault("state", "candidate")
            hits.append(candidate)
        if hits:
            record_hits(hits, artifact_path, f"universal:{result.solver}")

    for quals_root in quals_roots:
        process_quals_root(quals_root)

    if task_dirs:
        expected_hashes: dict[str, str] = {}
        for task_dir in task_dirs:
            # Each task directory may come from a different selected pack.
            # Search from that directory so a ZIP input finds its sibling
            # flag_hashes.json in the extracted source tree.
            for key, value in load_expected_hashes(task_dir).items():
                expected_hashes.setdefault(key, value)
        for task_dir in authoritative_task_roots:
            if deadline_at is not None and remaining_budget() <= 0:
                events.append({"type": "deadline", "stage": "task-aware", "reason": "scan deadline reached"})
                break
            task_id = task_dir.name.split("_", 1)[0].lstrip("0") or "0"
            task_result = solve_task(
                task_dir,
                output_dir=out_dir,
                expected_hash=expected_hashes.get(task_id),
            )
            record_task_result(task_result)
            if task_result.error:
                events.append(
                    {
                        "type": "task-solver-error",
                        "task_id": task_result.task_id,
                        "solver": task_result.solver,
                        "error": task_result.error,
                    }
                )
            emit_progress("task-aware", task_dir)

    while queue and processed < max_files:
        if deadline_at is not None and remaining_budget() <= 0:
            events.append({"type": "deadline", "stage": "artifact-queue", "reason": "scan deadline reached"})
            break
        artifact = queue.popleft()
        path = artifact.path.resolve()
        queued_paths.discard(path)
        if path in seen_paths:
            continue
        seen_paths.add(path)
        if not path.is_file() or path.is_symlink():
            events.append({"type": "skip", "path": str(path), "reason": "not a regular file"})
            continue
        processed += 1
        try:
            digest = sha256_file(path)
        except OSError as exc:
            events.append({"type": "file-error", "path": str(path), "error": f"{type(exc).__name__}: {exc}"})
            continue
        if digest in seen_hashes:
            events.append({"type": "skip", "path": str(path), "reason": "duplicate SHA-256", "sha256": digest})
            continue
        seen_hashes.add(digest)
        classification = classify(path, runner)
        item: dict[str, Any] = {
            "path": str(path),
            "sha256": digest,
            "size": path.stat().st_size,
            "depth": artifact.depth,
            "parent": artifact.parent,
            "classification": classification.to_dict(),
            "tools": [],
        }
        if verbose:
            print(f"[{processed}] {path} -> {classification.kind} ({classification.mime})")
        task_context = ""
        task_root = artifact.task_root or _task_for_path(path, task_dirs)
        task_text: str | None = None
        fast_task_candidate = False
        if solver_registry is not None:
            task_file = path.parent / "task.txt"
            if task_root is not None:
                task_file = task_manifest_path(task_root) or (task_root / "task.txt")
            elif task_manifest_path(path.parent) is not None:
                task_file = task_manifest_path(path.parent) or task_file
            try:
                if task_file.is_file() and task_file.stat().st_size <= max_bytes:
                    task_text = task_file.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                events.append(
                    {
                        "type": "universal-task-text-error",
                        "artifact": str(path),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
            related_paths: tuple[Path, ...] = ()
            context_metadata: dict[str, object] = {"sha256": digest, "size": item["size"], "depth": artifact.depth}
            if task_root is not None:
                related_paths = tuple(item_path for item_path in task_manifests.get(task_root, ()) if item_path != path)
                related_hashes: dict[str, str] = {}
                for related_path in related_paths:
                    try:
                        related_hashes[str(related_path)] = sha256_file(related_path, limit=max_bytes)
                    except OSError as exc:
                        events.append(
                            {
                                "type": "task-related-file-error",
                                "artifact": str(path),
                                "related": str(related_path),
                                "error": f"{type(exc).__name__}: {exc}",
                            }
                        )
                context_metadata.update(
                    {
                        "task_root": str(task_root),
                        "task_text_path": str(task_file) if task_file.is_file() else None,
                        "related_sha256": related_hashes,
                    }
                )
            context = SolverContext(
                input_path=path,
                report_dir=out_dir,
                limits=SolverLimits(
                    max_bytes=max_bytes,
                    max_files=max_files,
                    max_depth=max_depth,
                    timeout_seconds=tool_timeout,
                ),
                related_paths=related_paths,
                task_text=task_text,
                classification=classification.to_dict(),
                metadata=context_metadata,
            )
            task_context_payload = {
                "task_text": task_text or "",
                "task_root": context_metadata.get("task_root"),
                "related_sha256": context_metadata.get("related_sha256", {}),
            }
            task_context = hashlib.sha256(
                json.dumps(task_context_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ).hexdigest()
            try:
                universal_results = solver_registry.solve(context)
            except Exception as exc:
                universal_results = []
                events.append(
                    {
                        "type": "universal-registry-error",
                        "artifact": str(path),
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )
            fast_task_candidate = (
                mode == "fast"
                and (task_root or path.parent).name.casefold() == "macro_magic"
                and path.suffix.casefold() == ".zip"
                and any(
                    result.solver == "external-ctf-offline"
                    and result.status == "candidate"
                    and result.candidates
                    for result in universal_results
                )
            )
            for universal_result in universal_results:
                record_universal_result(universal_result, path, context)
                derived_inputs = list(getattr(universal_result, "derived_inputs", []) or [])
                if fast_task_candidate and derived_inputs:
                    events.append(
                        {
                            "type": "derived-input-skip",
                            "source": str(path),
                            "solver": getattr(universal_result, "solver", "unknown"),
                            "reason": "fast mode stopped generic expansion after a task-aware candidate",
                            "count": len(derived_inputs),
                        }
                    )
                else:
                    enqueue_derived_inputs(
                        universal_result,
                        source=path,
                        depth=artifact.depth,
                        task_root=task_root,
                    )
        record_hits(matcher.scan(read_text_views(path), source=str(path), analyzer="raw-bytes"), path, "raw-bytes")

        # GNU ``strings -el`` is unavailable on the macOS toolchain.  Keep
        # the same evidence pass in-process so UTF-16LE data is portable and
        # never appears as a false external-tool failure.
        utf16_result = _run_utf16le_strings(path, runner, max_bytes=max_bytes)
        item["tools"].append(_builtin_result_event("strings-utf16le", path, utf16_result, input_sha256=digest))
        if utf16_result.stdout:
            record_hits(
                matcher.scan(
                    utf16_result.stdout,
                    source=utf16_result.log_path or str(path),
                    analyzer="strings-utf16le",
                ),
                path,
                "strings-utf16le",
            )

        # Unknown tasks often wrap the flag in a textual encoding without a
        # task-specific statement. Decode only bounded, syntactically valid
        # views and persist a derived file when one contains a flag-shaped hit.
        try:
            with path.open("rb") as handle:
                encoded_input = handle.read(ENCODED_SCAN_BYTES + 1)
            encoded_views_found = encoded_views(encoded_input[:ENCODED_SCAN_BYTES], max_bytes=ENCODED_SCAN_BYTES)
            for view_index, view in enumerate(encoded_views_found):
                decoded = view["decoded"]
                decoded_text = decoded.decode("utf-8", errors="replace")
                source = f"{path}#encoding={view['encoding']}@offset={view['offset']}"
                hits = matcher.scan(decoded_text, source=source, analyzer=f"decode-{view['encoding']}")
                if not hits:
                    continue
                derived_path = artifact_dir / (
                    f"decoded-{digest[:12]}-{_safe_name(view['encoding'])}-{view_index}.bin"
                )
                derived_path.write_bytes(decoded)
                for hit in hits:
                    hit["encoding"] = view["encoding"]
                    hit["token"] = view["token"]
                    hit["offset"] = view["offset"]
                    hit["evidence"] = str(derived_path)
                record_hits(hits, path, f"decode-{view['encoding']}")
                events.append(
                    {
                        "type": "decoded-view",
                        "artifact": str(path),
                        "encoding": view["encoding"],
                        "offset": view["offset"],
                        "derived": str(derived_path),
                    }
                )
        except OSError as exc:
            events.append(
                {
                    "type": "decode-error",
                    "artifact": str(path),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )

        if classification.kind in {"data", "binary", "text"}:
            task_requests_xor = bool(
                task_text
                and ("xor" in task_text.casefold() or "exclusive or" in task_text.casefold())
            )
            skip_large_binary_xor = (
                classification.kind in {"binary", "data"}
                and item["size"] > LARGE_BINARY_ANALYSIS_LIMIT
                and not task_requests_xor
            )
            if skip_large_binary_xor:
                xor_result = CommandResult(
                    args=["builtin:xor-single-byte", str(path)],
                    returncode=None,
                    stderr="large binary without an explicit XOR task hint; generic XOR pass skipped",
                )
                xor_views = []
                events.append(
                    {
                        "type": "tool-skip",
                        "artifact": str(path),
                        "analyzer": "xor-single-byte",
                        "stage": "fast",
                        "outcome": "inapplicable",
                        "reason": xor_result.stderr,
                    }
                )
            else:
                xor_result, xor_views = _run_single_byte_xor(path, runner)
            item["tools"].append(_builtin_result_event("xor-single-byte", path, xor_result, input_sha256=digest))
            for view in xor_views:
                # Preserve the supported CTF-prefix context so CTF{ cannot be
                # mistaken for the suffix of a value such as DUCTF{.
                context_start = max(0, int(view["offset"]) - 19)
                decoded = view["plaintext"][context_start:].decode("utf-8", errors="replace")
                source = (
                    f"{xor_result.log_path or path}"
                    f"#key=0x{view['key']:02x}@offset={view['offset']}"
                )
                hits = matcher.scan(decoded, source=source, analyzer="xor-single-byte")
                for hit in hits:
                    hit["key"] = view["key"]
                    hit["offset"] = view["offset"]
                    hit["crib"] = view["prefix"].decode("ascii", errors="replace")
                record_hits(hits, path, "xor-single-byte")

        all_profiles = profile_selector(classification)
        profiles = filter_profiles_for_mode(all_profiles, mode)
        profile_skip_reasons: list[tuple[str, str]] = []
        if mode == "fast":
            selected_names = {profile.name for profile in profiles}
            for profile in all_profiles:
                if profile.name not in selected_names:
                    profile_skip_reasons.append((profile.name, "deep profile omitted by fast mode"))
        source_archive_name = Path(artifact.parent).name.casefold() if artifact.parent else ""
        is_can_you_hear_artifact = (
            path.parent.name.casefold() == "can_you_hear"
            or source_archive_name in {"can_you_hear.zip", "can_you_hear_the_flag.zip"}
        )
        if quals_roots and is_can_you_hear_artifact:
            kept_profiles: list[ToolProfile] = []
            for profile in profiles:
                if profile.name in {"zsteg", "pngcheck"}:
                    profile_skip_reasons.append(
                        (profile.name, "real-quals spectrogram inputs are handled by the bounded OCR solver")
                    )
                else:
                    kept_profiles.append(profile)
            profiles = kept_profiles
        if quals_roots and item["size"] > LARGE_BINARY_ANALYSIS_LIMIT:
            # radare2's string database can spend minutes on a packed Nuitka
            # one-file ELF.  The task-aware solver already records a static
            # review, while strings/binwalk still cover the generic evidence.
            original_profile_count = len(profiles)
            profiles = [profile for profile in profiles if profile.name != "radare2-strings"]
            if len(profiles) != original_profile_count:
                profile_skip_reasons.append(
                    ("radare2-strings", "large real-quals binary; bounded generic pass skipped r2")
                )
        for analyzer, reason in profile_skip_reasons:
            skipped_profile = next((profile for profile in all_profiles if profile.name == analyzer), None)
            events.append(
                {
                    "type": "tool-skip",
                    "artifact": str(path),
                    "analyzer": analyzer,
                    "stage": skipped_profile.stage if skipped_profile is not None else "specialized",
                    "outcome": "inapplicable",
                    "reason": reason,
                }
            )
        profile_budget = remaining_budget()
        if profile_budget is not None and profile_budget <= 0:
            events.append({"type": "deadline", "artifact": str(path), "stage": "profiles", "reason": "scan deadline reached"})
            profile_results = []
        else:
            profile_results = _run_scan_profile_batch(
            profiles,
            path=path,
            runner=runner,
            tool_timeout=tool_timeout if profile_budget is None else min(tool_timeout, profile_budget),
            cache_dir=cache_dir,
            input_sha256=digest,
            task_context=task_context,
            workers=profile_workers,
            )
        for profile, result, cache_hit, cache_path, cache_record in profile_results:
            tool_event = _result_event(
                profile,
                path,
                result,
                input_sha256=digest,
                timeout_seconds=min(profile.timeout, tool_timeout),
            )
            tool_event["cache"] = {"hit": cache_hit, "path": str(cache_path)}
            item["tools"].append(tool_event)
            if cache_hit:
                original = cache_record.get("original", {}) if isinstance(cache_record, dict) else {}
                events.append(
                    {
                        "type": "cache-hit",
                        "artifact": str(path),
                        "analyzer": profile.name,
                        "stage": profile.stage,
                        "cache": str(cache_path),
                        "original_artifact": original.get("artifact"),
                        "original_log_path": original.get("log_path"),
                    }
                )
            output = result.combined_output()
            if output:
                record_hits(matcher.scan(output, source=result.log_path or str(path), analyzer=profile.name), path, profile.name)
            if result.missing:
                events.append(
                    {
                        "type": "tool-skip",
                        "artifact": str(path),
                        "analyzer": profile.name,
                        "stage": profile.stage,
                        "outcome": "unavailable",
                        "reason": result.stderr,
                    }
                )
            elif result.timed_out or (result.returncode not in (0, None)):
                events.append(
                    {
                        "type": "tool-error",
                        "artifact": str(path),
                        "analyzer": profile.name,
                        "stage": profile.stage,
                        "outcome": _profile_outcome(result),
                        "returncode": result.returncode,
                        "timed_out": result.timed_out,
                    }
                )

        if allow_stegseek_seed and classification.kind == "jpeg":
            if deadline_at is not None and remaining_budget() <= 0:
                events.append({"type": "deadline", "artifact": str(path), "stage": "stegseek", "reason": "scan deadline reached"})
                continue
            extracted_path = artifact_dir / f"stegseek-{digest[:12]}.bin"
            seed_profile = ToolProfile(
                "stegseek-seed",
                "stegseek",
                lambda candidate, output=extracted_path: ["stegseek", "--seed", str(candidate), str(output)],
                timeout=60.0,
            )
            seed_timeout = min(seed_profile.timeout, tool_timeout)
            remaining = remaining_budget()
            if remaining is not None:
                seed_timeout = min(seed_timeout, remaining)
            result = runner.run(
                seed_profile.args_for(path),
                cwd=path.parent,
                timeout=max(0.1, seed_timeout),
                log_name=f"stegseek-seed-{_safe_name(path.name)}",
            )
            item["tools"].append(_result_event(seed_profile, path, result, input_sha256=digest, timeout_seconds=seed_timeout))
            if result.missing:
                events.append(
                    {
                        "type": "tool-skip",
                        "artifact": str(path),
                        "analyzer": seed_profile.name,
                        "stage": seed_profile.stage,
                        "outcome": "unavailable",
                        "reason": result.stderr,
                    }
                )
            elif result.timed_out or result.returncode not in (0, None):
                events.append(
                    {
                        "type": "tool-error",
                        "artifact": str(path),
                        "analyzer": seed_profile.name,
                        "stage": seed_profile.stage,
                        "outcome": _profile_outcome(result),
                        "returncode": result.returncode,
                        "timed_out": result.timed_out,
                    }
                )
            if extracted_path.is_file() and extracted_path.stat().st_size <= max_bytes:
                queue.append(Artifact(extracted_path, artifact.depth + 1, str(path), task_root))
                events.append({"type": "extracted", "path": str(extracted_path), "parent": str(path), "method": "stegseek-seed"})

        if fast_task_candidate and is_archive(classification):
            events.append(
                {
                    "type": "archive-skip",
                    "path": str(path),
                    "reason": "fast mode stopped generic expansion after a task-aware candidate",
                }
            )
        elif is_archive(classification) and artifact.depth < max_depth:
            archive_budget = remaining_budget()
            if archive_budget is not None and archive_budget <= 0:
                events.append({"type": "deadline", "artifact": str(path), "stage": "archive", "reason": "scan deadline reached"})
                continue
            extraction_root = artifact_dir / f"archive-{digest[:12]}"
            extractor = ArchiveExtractor(runner, max_bytes=max_bytes, max_files=max_files)
            extraction = extractor.extract(
                path,
                classification,
                extraction_root,
                timeout=archive_timeout if archive_budget is None else min(archive_timeout, archive_budget),
            )
            item["archive"] = {
                **extraction.archive_report(),
                "destination": str(extraction_root),
            }
            if extraction.refused_reason:
                events.append({"type": "archive-skip", "path": str(path), "reason": extraction.refused_reason})
            if extraction.partial:
                events.append(
                    {
                        "type": "archive-partial",
                        "path": str(path),
                        "selected_entries": len(extraction.selected_entries),
                        "skipped_entries": len(extraction.skipped_entries),
                    }
                )
            if extraction.extracted:
                for discovered_root in discover_ico_quals_roots([str(extraction_root)]):
                    if discovered_root in processed_quals_roots:
                        continue
                    quals_roots.append(discovered_root)
                    verbose = False
                    events.append(
                        {
                            "type": "quals-root-discovered",
                            "root": str(discovered_root),
                            "source_archive": str(path),
                        }
                    )
                    process_quals_root(discovered_root)
            for child in extraction.discovered:
                queue.append(Artifact(child, artifact.depth + 1, str(path), task_root))
                events.append({"type": "extracted", "path": str(child), "parent": str(path), "method": "7zz"})
        report["artifacts"].append(item)
        emit_progress("file-complete", path)

    if queue:
        events.append({"type": "limit", "reason": "max_files reached", "remaining": len(queue)})
    if processed >= max_files:
        events.append({"type": "limit", "reason": "max_files reached", "max_files": max_files})
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    quals_values = {
        value
        for item in report["quals_task_results"]
        for collection in (item.get("candidates", []), item.get("references", []))
        for entry in collection
        for value in [entry.get("value")]
        if value
    }
    quals_solution_tasks = sum(
        1
        for item in report["quals_task_results"]
        if item.get("candidates") or item.get("references") or item.get("status") == "payload-ready"
    )
    triage_by_value = {
        str(candidate.get("value", "")): candidate.get("triage", "candidate")
        for candidate in report["candidates"]
        if candidate.get("value")
    }
    report["task_coverage"] = _task_coverage(
        task_dirs,
        report["artifacts"],
        report["universal_results"],
        report["task_results"],
        report["candidates"],
        max_bytes=max_bytes,
    )
    report["summary"] = {
        "processed_files": processed,
        "unique_files": len(report["artifacts"]),
        "candidate_count": len(report["candidates"]),
        "likely_placeholder_count": sum(value == "likely-placeholder" for value in triage_by_value.values()),
        "likely_noise_count": sum(value == "likely-noise" for value in triage_by_value.values()),
        "reference_candidate_count": len(report["reference_candidates"]),
        "solved_tasks": sum(1 for item in report["task_results"] if item.get("status") == "hash-verified"),
        "task_failure_count": sum(1 for item in report["task_results"] if item.get("status") == "failed"),
        "task_artifact_count": len(report["task_results"]),
        "challenge_task_count": len(report["task_coverage"]),
        "challenge_candidate_task_count": sum(
            1 for item in report["task_coverage"] if item.get("status") == "candidate"
        ),
        "challenge_hash_verified_task_count": sum(
            1 for item in report["task_coverage"] if item.get("status") == "hash-verified"
        ),
        "challenge_payload_ready_task_count": sum(
            1 for item in report["task_coverage"] if item.get("status") == "payload-ready"
        ),
        "challenge_review_task_count": sum(
            1 for item in report["task_coverage"] if item.get("status") == "candidate-review"
        ),
        "challenge_requires_authorized_session_task_count": sum(
            1 for item in report["task_coverage"] if item.get("status") == "requires-authorized-session"
        ),
        "challenge_uninspected_task_count": sum(
            1 for item in report["task_coverage"] if item.get("status") == "not-inspected"
        ),
        "derived_artifact_count": len(_derived_artifact_paths(report)),
        "quals_task_count": len(report["quals_task_results"]),
        "quals_candidate_task_count": sum(
            1 for item in report["quals_task_results"] if item.get("status") == "candidate"
        ),
        "quals_payload_ready_count": sum(
            1 for item in report["quals_task_results"] if item.get("status") == "payload-ready"
        ),
        "quals_requires_session_count": sum(
            1
            for item in report["quals_task_results"]
            if item.get("status") == "requires-authorized-session"
        ),
        "quals_review_count": sum(
            1 for item in report["quals_task_results"] if item.get("status") == "candidate-review"
        ),
        "quals_historical_task_count": sum(
            int(index.get("historical_task_count", 0)) for index in report["quals_answer_indexes"]
        ),
        "quals_historical_answer_count": sum(
            int(index.get("historical_answer_count", 0)) for index in report["quals_answer_indexes"]
        ),
        "quals_solution_task_count": quals_solution_tasks,
        "quals_solution_answer_count": len(quals_values),
        "quals_historical_artifact_count": sum(
            sum(Path(artifact).name == "historical-solution.md" for artifact in item.get("artifacts", []))
            for item in report["quals_task_results"]
        ),
        "event_count": len(events),
        "universal_solver_count": len(report["universal_results"]),
        "universal_candidate_count": sum(
            len(item.get("candidates", [])) for item in report["universal_results"]
        ),
        "universal_failed_count": sum(
            1 for item in report["universal_results"] if item.get("status") == "failed"
        ),
        "universal_review_count": sum(
            1
            for item in report["universal_results"]
            if item.get("status") in {"candidate-review", "needs-review"}
        ),
        "universal_unsupported_count": sum(
            1 for item in report["universal_results"] if item.get("status") == "unsupported"
        ),
        "universal_candidate_result_count": sum(
            1 for item in report["universal_results"] if item.get("status") == "candidate"
        ),
        "universal_hash_verified_result_count": sum(
            1 for item in report["universal_results"] if item.get("status") == "hash-verified"
        ),
        "universal_solved_count": sum(
            1 for item in report["universal_results"] if item.get("status") == "hash-verified"
        ),
    }
    report["report_dir"] = str(out_dir)
    report_path = out_dir / "report.json"
    report_path.write_text(json.dumps(as_jsonable(report), ensure_ascii=False, indent=2), encoding="utf-8")
    _write_report_text(report, out_dir / "report.txt")
    return report


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ico-scan",
        description="Offline, evidence-preserving CTF file triage; never submits or guesses flags.",
    )
    parser.add_argument("paths", nargs="+", help="one or more local files or directories")
    parser.add_argument("--out", type=Path, help="report directory; defaults to ./ico-scan-runs/<timestamp>")
    parser.add_argument("--flag-regex", action="append", dest="patterns", help="additional flag regex; can be repeated")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, help="maximum declared archive expansion")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TOOL_TIMEOUT, help="maximum seconds per analyzer")
    parser.add_argument(
        "--archive-timeout",
        type=float,
        default=DEFAULT_ARCHIVE_TIMEOUT,
        help="maximum seconds to list or selectively extract an archive",
    )
    parser.add_argument(
        "--mode",
        choices=("fast", "full"),
        default="full",
        help="fast runs built-in and cheap profiles; full runs every compatible bounded profile",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="print bounded stage progress to stderr",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="parallel independent external profiles per artifact (1-32)",
    )
    parser.add_argument(
        "--deadline",
        type=float,
        help="global scan deadline in seconds",
    )
    parser.add_argument(
        "--allow-stegseek-seed",
        action="store_true",
        help="allow deterministic StegSeek seed extraction for JPEGs; no wordlist/password guessing",
    )
    parser.add_argument(
        "--show-references",
        action="store_true",
        help="print historical walkthrough values with an explicit reference-only label",
    )
    parser.add_argument(
        "--authorized-target",
        action="append",
        default=[],
        help="explicit host allowlist for a separately driven local active client; no request is made by ico-scan",
    )
    parser.add_argument(
        "--allow-network",
        action="store_true",
        help="record an explicit active-mode policy; requires --authorized-target and never probes automatically",
    )
    parser.add_argument("--version", action="version", version="ico-scan 0.5.0")
    return parser


def _qual_flags_from_report(report: dict[str, Any]) -> list[str]:
    """Return one flat, stable flag list for the real-quals CLI view.

    Only current-run candidates belong in the copy-ready default view.
    Historical walkthrough values stay in the answer index and are printed
    separately only when ``--show-references`` is requested.
    """

    values: list[str] = []
    seen: set[str] = set()

    def add(value: Any) -> None:
        text = str(value).strip() if value is not None else ""
        if text and text not in seen:
            seen.add(text)
            values.append(text)

    for candidate in report.get("candidates", []):
        if not _is_low_priority_candidate(candidate):
            add(candidate.get("value"))
    if values:
        return values

    for task in report.get("quals_task_results", []):
        for entry in task.get("candidates", []):
            if not _is_low_priority_candidate(entry):
                add(entry.get("value"))
    return values


def _print_low_priority_candidates(report: dict[str, Any]) -> None:
    candidates = _low_priority_candidates(report)
    if not candidates:
        return
    print("LOW-PRIORITY FLAG-LIKE CANDIDATE VALUES (kept in candidates and report.json):")
    for candidate in candidates:
        print(
            f"{candidate.get('triage')}: {candidate.get('value')} "
            f"[{candidate.get('triage_reason', '')}; artifact={candidate.get('artifact', '')}]"
        )


def _actionable_result_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    task_actionable_statuses = {
        "payload-ready",
        "requires-authorized-session",
        "candidate-review",
        "needs-review",
        "failed",
        "unsupported",
    }
    universal_actionable_statuses = task_actionable_statuses - {"unsupported"}
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, tuple[str, ...]]] = set()

    def add(status: str, title: str, source: str, outputs: list[str], note: str) -> None:
        key = (status, title, source, tuple(outputs))
        if key in seen:
            return
        seen.add(key)
        rows.append({"status": status, "title": title, "source": source, "outputs": outputs, "note": note})

    for result in report.get("task_results", []):
        status = str(result.get("status", ""))
        if status not in task_actionable_statuses:
            continue
        title = str(result.get("task_id") or result.get("solver") or "task")
        source = str(result.get("task_dir") or "")
        outputs = [str(item) for item in result.get("artifacts", []) if isinstance(item, str)]
        note = str(result.get("next_action") or result.get("error") or "")
        add(status, title, source, outputs, note)

    for result in report.get("universal_results", []):
        status = str(result.get("status", ""))
        if status not in universal_actionable_statuses:
            continue
        context = result.get("evidence_context", {})
        source = str(context.get("input_path", "")) if isinstance(context, dict) else ""
        source_name = Path(source).name if source else "unknown artifact"
        solver = str(result.get("solver") or result.get("category") or "solver")
        outputs: list[str] = []
        for step in result.get("steps", []):
            details = step.get("details", {}) if isinstance(step, dict) else {}
            if not isinstance(details, dict):
                continue
            for key in ("payload", "format_probe", "output", "output_path", "rendered_image", "evidence"):
                value = details.get(key)
                if isinstance(value, str) and value not in outputs:
                    outputs.append(value)
        note = str(result.get("next_action") or result.get("error") or "")
        if status == "payload-ready" and not note:
            note = "Review the generated static artifact; no service interaction was performed."
        add(status, f"{solver} ({source_name})", source, outputs, note)
    return rows


def _print_actionable_results(report: dict[str, Any]) -> None:
    rows = _actionable_result_rows(report)
    if not rows:
        return
    print("ACTIONABLE RESULTS:")
    for row in rows:
        print(f"{row['status'].upper()}: {row['title']}")
        if row["source"]:
            print(f"  source: {row['source']}")
        for output in row["outputs"]:
            print(f"  artifact: {output}")
        if row["note"]:
            print(f"  next: {row['note']}")


def _print_task_coverage(report: dict[str, Any]) -> None:
    tasks = report.get("task_coverage", [])
    if not tasks:
        return
    print("TASK COVERAGE (local evidence; candidates are not platform-confirmed):")
    for task in tasks:
        category = str(task.get("category") or "unknown")
        difficulty = str(task.get("difficulty") or "unknown")
        task_candidates = [item for item in task.get("candidates", []) if item.get("value")]
        candidates = [
            str(item.get("value")) for item in task_candidates if not _is_low_priority_candidate(item)
        ]
        low_priority_values = {
            str(item.get("value")) for item in task_candidates if _is_low_priority_candidate(item)
        }
        suffix = f"; candidates={', '.join(candidates)}" if candidates else ""
        if low_priority_values:
            suffix += f"; low-priority values={len(low_priority_values)}"
        notes = [str(note) for note in task.get("analysis_notes", []) if str(note).strip()]
        note_suffix = f"; notes={' | '.join(notes)}" if notes else ""
        print(
            f"{task.get('title', Path(str(task.get('task_root', 'task'))).name)} "
            f"[{category}/{difficulty}]: {task.get('status')}; "
            f"artifacts={task.get('artifact_count')}; solvers={task.get('solver_count')}{suffix}{note_suffix}"
        )


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if (
        args.max_depth < 0
        or args.max_files < 1
        or args.max_bytes < 1
        or args.timeout <= 0
        or args.archive_timeout <= 0
        or args.workers < 1
        or args.workers > 32
        or (args.deadline is not None and args.deadline <= 0)
    ):
        parser.error("limits must be positive; max-depth may be zero")
    if args.allow_network and not args.authorized_target:
        parser.error("--allow-network requires at least one --authorized-target")
    missing = [path for path in args.paths if not Path(path).expanduser().exists()]
    if missing:
        parser.error(f"input path does not exist: {missing[0]}")
    out_dir = args.out or Path.cwd() / "ico-scan-runs" / f"{_utc_stamp()}-{uuid.uuid4().hex[:8]}"
    quals_mode = bool(discover_ico_quals_roots(args.paths))
    report = run_scan(
        args.paths,
        out_dir=out_dir,
        patterns=args.patterns,
        max_depth=args.max_depth,
        max_files=args.max_files,
        max_bytes=args.max_bytes,
        tool_timeout=args.timeout,
        archive_timeout=args.archive_timeout,
        allow_stegseek_seed=args.allow_stegseek_seed,
        allow_network=args.allow_network,
        authorized_targets=tuple(args.authorized_target),
        verbose=not quals_mode,
        solver_registry=build_default_registry(),
        mode=args.mode,
        progress=args.progress,
        profile_workers=args.workers,
        deadline_seconds=args.deadline,
    )
    quals_mode = quals_mode or bool(report.get("summary", {}).get("quals_task_count"))
    print(f"REPORT: {report['report_dir']}")
    if quals_mode and report["summary"].get("quals_task_count"):
        flags = _qual_flags_from_report(report)
        print(f"CANDIDATE VALUES: {len(flags)} (local evidence; not platform-confirmed)")
        for flag in flags:
            print(flag)
        _print_low_priority_candidates(report)
        _print_actionable_results(report)
        _print_task_coverage(report)
        if report.get("quals_task_results"):
            print("TASK STATUS:")
            for task in report["quals_task_results"]:
                task_id = str(task.get("task_id", "unknown"))
                status = str(task.get("status", "unknown"))
                action = str(task.get("next_action", "Inspect the recorded evidence."))
                print(f"{task_id}: {status}; next: {action}")
        if args.show_references:
            for index in report.get("quals_answer_indexes", []):
                try:
                    matrix = json.loads(Path(index["json"]).read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError, KeyError):
                    matrix = []
                for task in matrix:
                    for reference in task.get("historical_references", []):
                        value = reference.get("value")
                        if value:
                            print(f"HISTORICAL-REFERENCE: {task.get('task_id', '')}: {value}")
        return 0
    low_priority_count = len(_low_priority_candidates(report))
    print(
        f"CANDIDATE RECORDS: {report['summary']['candidate_count']} "
        f"(local-run evidence; includes {low_priority_count} low-priority record(s))"
    )
    flat_values = _actionable_candidate_values(report)
    print(f"CANDIDATE VALUES: {len(flat_values)} (actionable local evidence; not platform-confirmed)")
    for value in flat_values:
        print(value)
    _print_low_priority_candidates(report)
    _print_actionable_results(report)
    _print_task_coverage(report)
    if report["summary"].get("quals_task_count"):
        print(
            "QUALS-SOLUTIONS: "
            f"{report['summary']['quals_solution_task_count']} tasks / "
            f"{report['summary']['quals_solution_answer_count']} answers "
            f"(derived={report['summary']['quals_candidate_task_count']}, "
            f"reference-only={report['summary']['quals_historical_answer_count']})"
        )
    if report["summary"].get("reference_candidate_count"):
        print(f"REFERENCE-ONLY: {report['summary']['reference_candidate_count']}")
    for index in report.get("quals_answer_indexes", []):
        print(
            f"ANSWER-INDEX: {index['markdown']} "
            f"(tasks={index['task_count']}, historical_answers={index['historical_answer_count']})"
        )
        if args.show_references:
            try:
                matrix = json.loads(Path(index["json"]).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                matrix = []
            for task in matrix:
                for reference in task.get("historical_references", []):
                    value = reference.get("value")
                    if value:
                        print(f"HISTORICAL-REFERENCE: {task.get('task_id', '')}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
