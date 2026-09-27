#!/usr/bin/env python3
"""Run deterministic offline scans over the local ICO regression corpora."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Sequence

# When invoked as ``python scripts/run_corpus_matrix.py`` Python places the
# scripts directory first on sys.path; make the toolkit root explicit without
# requiring installation as a package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ico_scan import run_scan
from ico_scan_core import sha256_file
from ico_universal_registry import build_default_registry


def _unique_values(items: object, *, state: str) -> set[str]:
    """Return non-empty candidate values in one evidence state."""

    if not isinstance(items, list):
        return set()
    values: set[str] = set()
    for item in items:
        if not isinstance(item, dict) or item.get("state") != state:
            continue
        value = str(item.get("value", "")).strip()
        if value:
            values.add(value)
    return values


def _unique_task_ids(items: object, *, statuses: set[str]) -> set[str]:
    """Count task states once even when a report contains duplicate rows."""

    if not isinstance(items, list):
        return set()
    result: set[str] = set()
    for index, item in enumerate(items):
        if not isinstance(item, dict) or item.get("status") not in statuses:
            continue
        task_id = str(item.get("task_id", f"row-{index}")).strip()
        if task_id:
            result.add(task_id)
    return result


def _task_result_key(item: dict[str, object], index: int, *, prefix: str) -> str:
    """Return a stable task key for task-aware and universal result rows."""

    task_dir = str(item.get("task_dir", "")).strip()
    if task_dir:
        return f"root:{Path(task_dir).expanduser().resolve()}"
    task_id = str(item.get("task_id", "")).strip()
    if task_id:
        return f"{prefix}:id:{task_id}"
    context = item.get("evidence_context", {})
    if isinstance(context, dict):
        metadata = context.get("metadata", {})
        if isinstance(metadata, dict):
            task_root = str(metadata.get("task_root", "")).strip()
            if task_root:
                return f"root:{Path(task_root).expanduser().resolve()}"
        input_path = str(context.get("input_path", "")).strip()
        if input_path:
            return f"{prefix}:input:{Path(input_path).expanduser().resolve()}"
    return f"{prefix}:row:{index}"


def _universal_status_keys(items: object, *, statuses: set[str]) -> set[str]:
    if not isinstance(items, list):
        return set()
    return {
        _task_result_key(item, index, prefix="universal")
        for index, item in enumerate(items)
        if isinstance(item, dict) and item.get("status") in statuses
    }


def _coverage_rows(report: dict[str, object]) -> list[dict[str, object]]:
    """Group universal outcomes by task root, family, and difficulty.

    The grouping is derived only from evidence context and never reads the
    benchmark's expected-answer file.  It remains useful for arbitrary task
    packs because unknown directory names are retained as ``case``.
    """

    grouped: dict[str, dict[str, object]] = {}
    items = report.get("universal_results", [])
    if not isinstance(items, list):
        return []
    for item in items:
        if not isinstance(item, dict):
            continue
        context = item.get("evidence_context", {})
        metadata = context.get("metadata", {}) if isinstance(context, dict) else {}
        task_root = str(metadata.get("task_root", "")).strip() if isinstance(metadata, dict) else ""
        if not task_root:
            continue
        root = Path(task_root)
        case = root.name
        parent = root.parent.name
        if "_" in case:
            family, difficulty = case.rsplit("_", 1)
        else:
            family, difficulty = parent, "unknown"
        key = str(root.resolve())
        row = grouped.setdefault(
            key,
            {
                "task_root": key,
                "story": root.parent.name,
                "case": case,
                "family": family,
                "difficulty": difficulty,
                "statuses": set(),
                "candidates": set(),
                "solvers": set(),
            },
        )
        row["statuses"].add(str(item.get("status", "")))
        row["solvers"].add(str(item.get("solver", "")))
        for candidate in item.get("candidates", []):
            if isinstance(candidate, dict) and candidate.get("value"):
                row["candidates"].add(str(candidate["value"]))
    output: list[dict[str, object]] = []
    for row in grouped.values():
        output.append(
            {
                **row,
                "statuses": sorted(value for value in row["statuses"] if value),
                "candidates": sorted(row["candidates"]),
                "solvers": sorted(value for value in row["solvers"] if value),
            }
        )
    return sorted(output, key=lambda row: str(row["task_root"]))


def _report_tools(report: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    """Flatten serialized command records while tolerating older reports."""

    flattened: list[tuple[str, dict[str, object]]] = []
    artifacts = report.get("artifacts", [])
    if not isinstance(artifacts, list):
        return flattened
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        tools = artifact.get("tools", [])
        if not isinstance(tools, list):
            continue
        for entry in tools:
            if not isinstance(entry, dict):
                continue
            analyzer = str(entry.get("analyzer", "unknown"))
            result = entry.get("result", {})
            if isinstance(result, dict):
                flattened.append((analyzer, result))
    return flattened


def _report_metrics(
    report: dict[str, object],
    *,
    elapsed_seconds: float,
    source_file_count: int,
    source_unchanged: bool,
) -> dict[str, object]:
    """Build a stable scorecard without conflating evidence states.

    Candidate values are deduplicated within their state. Task status counts
    are keyed by task id. Raw events stay in the matrix row; only explicit
    ``tool-error`` and ``tool-skip`` events affect the failure counters.
    """

    candidates = report.get("candidates", [])
    task_results = report.get("quals_task_results", [])
    references = report.get("reference_candidates", [])
    events = report.get("events", [])
    if not isinstance(events, list):
        events = []

    by_analyzer: dict[str, dict[str, object]] = {}

    def analyzer_row(name: str) -> dict[str, object]:
        return by_analyzer.setdefault(
            name,
            {"calls": 0, "seconds": 0.0, "errors": 0, "timeouts": 0, "skips": 0},
        )

    tools = _report_tools(report)
    for analyzer, result in tools:
        row = analyzer_row(analyzer)
        row["calls"] = int(row["calls"]) + 1
        row["seconds"] = round(float(row["seconds"]) + float(result.get("duration_seconds", 0.0) or 0.0), 6)
        if bool(result.get("timed_out")):
            row["timeouts"] = int(row["timeouts"]) + 1
        elif result.get("ok") is False:
            row["errors"] = int(row["errors"]) + 1

    failure_events: list[dict[str, object]] = []
    error_count = 0
    timeout_count = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        event_type = str(event.get("type", ""))
        analyzer = str(event.get("analyzer", "unknown"))
        if event_type == "tool-error":
            failure_events.append(event)
            error_count += 1
            timed_out = bool(event.get("timed_out"))
            timeout_count += int(timed_out)
            row = analyzer_row(analyzer)
            row["errors"] = int(row["errors"]) + 1
            row["timeouts"] = int(row["timeouts"]) + int(timed_out)
        elif event_type == "tool-skip":
            row = analyzer_row(analyzer)
            row["skips"] = int(row["skips"]) + 1

    historical_values: set[tuple[str, str]] = set()
    if isinstance(references, list):
        for item in references:
            if not isinstance(item, dict):
                continue
            value = str(item.get("value", "")).strip()
            task_id = str(item.get("task_id", "")).strip()
            if value:
                historical_values.add((task_id, value))

    review_values = _unique_values(candidates, state="needs-review") | _unique_values(candidates, state="candidate-review")
    review_tasks = _unique_task_ids(task_results, statuses={"needs-review", "candidate-review"})
    review_tasks |= _universal_status_keys(report.get("universal_results", []), statuses={"needs-review", "candidate-review"})
    payload_tasks = _unique_task_ids(task_results, statuses={"payload-ready"})
    payload_tasks |= _universal_status_keys(report.get("universal_results", []), statuses={"payload-ready"})
    session_tasks = _unique_task_ids(task_results, statuses={"requires-authorized-session"})
    session_tasks |= _universal_status_keys(report.get("universal_results", []), statuses={"requires-authorized-session"})
    return {
        "elapsed_seconds": round(float(elapsed_seconds), 6),
        "source_file_count": int(source_file_count),
        "source_unchanged": bool(source_unchanged),
        "current_candidates": len(_unique_values(candidates, state="candidate")),
        "hash_verified": len(_unique_values(candidates, state="hash-verified")),
        "transcript_derived": len(_unique_values(candidates, state="transcript-derived")),
        "payload_ready": len(payload_tasks),
        "needs_review": len(review_values) + len(review_tasks),
        "session_required": len(session_tasks),
        "historical_references": len(historical_values),
        "tool_calls": len(tools),
        "tool_errors": error_count,
        "tool_timeouts": timeout_count,
        "by_analyzer": dict(sorted(by_analyzer.items())),
        "failure_events": failure_events,
        "coverage": _coverage_rows(report),
    }


def _files(root: Path) -> list[Path]:
    if root.is_file():
        return [root.resolve()]
    output: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or any(part in {"ico-scan-runs", "__pycache__", "commands", "artifacts"} for part in path.parts):
            continue
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        output.append(path.resolve())
    return output


def _source_hashes(path: Path) -> dict[str, str]:
    return {str(item): sha256_file(item) for item in _files(path)}


def _safe(value: str) -> str:
    return "".join(char if char.isalnum() or char in "_.-" else "_" for char in value).strip("_") or "corpus"


def run_corpus_matrix(paths: Sequence[Path], output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for source in paths:
        source = source.expanduser().resolve()
        before = _source_hashes(source)
        report_dir = output_dir / "corpora" / _safe(source.name)
        if report_dir.exists():
            # Keep repeated runs deterministic and avoid scanning an earlier
            # report as an input artifact.
            for child in sorted(report_dir.rglob("*"), reverse=True):
                if child.is_file() or child.is_symlink():
                    child.unlink()
                elif child.is_dir():
                    child.rmdir()
        started = time.monotonic()
        errors: list[object] = []
        report: dict[str, object] = {}
        try:
            report = run_scan(
                [str(source)],
                out_dir=report_dir,
                verbose=False,
                solver_registry=build_default_registry(),
                profile_selector=lambda _classification: [],
            )
            raw_events = report.get("events", [])
            if isinstance(raw_events, list):
                errors.extend(
                    event
                    for event in raw_events
                    if isinstance(event, dict) and event.get("type") == "tool-error"
                )
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
        after = _source_hashes(source)
        summary = report.get("summary", {}) if isinstance(report, dict) else {}
        candidates = report.get("candidates", []) if isinstance(report, dict) else []
        unique_answers = sorted({str(item.get("value")) for item in candidates if isinstance(item, dict) and item.get("value")})
        rows.append(
            {
                "corpus": str(source),
                "report_dir": str(report_dir),
                "duration_seconds": round(time.monotonic() - started, 6),
                "summary": summary,
                "unique_answers": unique_answers,
                "source_file_count": len(before),
                "source_hashes": before,
                "source_unchanged": before == after,
                "errors": errors,
                "events": report.get("events", []) if isinstance(report, dict) else [],
                "metrics": _report_metrics(
                    report,
                    elapsed_seconds=time.monotonic() - started,
                    source_file_count=len(before),
                    source_unchanged=before == after,
                ),
            }
        )
    matrix = {"schema_version": 2, "corpora": rows, "source_unchanged": all(bool(row["source_unchanged"]) for row in rows)}
    (output_dir / "corpus-matrix.json").write_text(json.dumps(matrix, ensure_ascii=False, indent=2), encoding="utf-8")
    return matrix


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run offline ICO corpus regression scans")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    missing = [str(path) for path in args.paths if not path.expanduser().exists()]
    if missing:
        parser.error(f"input path does not exist: {missing[0]}")
    matrix = run_corpus_matrix(args.paths, args.out)
    print(json.dumps(matrix, ensure_ascii=False, indent=2))
    if not matrix["source_unchanged"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
