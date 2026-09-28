#!/usr/bin/env python3
"""Score a blind, hash-only holdout without exposing plaintext answers.

The final benchmark generator is useful for regression testing, but a solver
should also be evaluated against a manifest that contains only SHA-256 answer
digests.  This module keeps that evaluator intentionally small and
fail-closed: plaintext answer fields, malformed digests, unknown task IDs,
wrong values, and duplicate submissions are all visible in the scorecard.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


SCHEMA_VERSION = 1
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_FLAG_RE = re.compile(r"(?i)(?:ico|ctf|flag|picoctf|htb|seccon|ductf)\{[^{}]+\}")
_PLAINTEXT_KEYS = {
    "answer",
    "answer_plaintext",
    "expected",
    "expected_answer",
    "flag",
    "flag_value",
    "plaintext",
    "secret",
    "solution",
    "value",
}


@dataclass(frozen=True)
class HoldoutRecord:
    task_id: str
    answer_sha256: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class HoldoutManifest:
    schema_version: int
    name: str
    records: tuple[HoldoutRecord, ...]
    manifest_sha256: str
    metadata: dict[str, Any] = field(default_factory=dict)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _reject_plaintext_fields(value: Any, *, path: str = "manifest") -> None:
    """Reject answer-like fields and flag-shaped plaintext anywhere in JSON."""

    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            if key.casefold() in _PLAINTEXT_KEYS:
                raise ValueError(f"holdout manifest contains plaintext answer field: {path}.{key}")
            _reject_plaintext_fields(child, path=f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _reject_plaintext_fields(child, path=f"{path}[{index}]")
        return
    if isinstance(value, str) and _FLAG_RE.search(value):
        raise ValueError(f"holdout manifest contains plaintext flag-shaped value at {path}")


def _manifest_payload(document: Mapping[str, Any]) -> bytes:
    # Exclude a caller-supplied identity so the identity always describes the
    # locked content rather than a mutable self-referential field.
    payload = {str(key): value for key, value in document.items() if str(key) != "manifest_sha256"}
    return _canonical_json(payload)


def load_manifest(path: Path | str) -> HoldoutManifest:
    source = Path(path).expanduser().resolve()
    document = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise ValueError("holdout manifest must be a JSON object")
    _reject_plaintext_fields(document)
    metadata_value = document.get("metadata", {})
    if not isinstance(metadata_value, Mapping):
        raise ValueError("holdout manifest metadata must be an object")
    manifest_metadata = {str(key): value for key, value in metadata_value.items()}
    records_value = document.get("records")
    if not isinstance(records_value, list) or not records_value:
        raise ValueError("holdout manifest records must be a non-empty list")
    records: list[HoldoutRecord] = []
    seen: set[str] = set()
    for index, raw in enumerate(records_value):
        if not isinstance(raw, Mapping):
            raise ValueError(f"holdout record {index} must be an object")
        task_id = str(raw.get("task_id", "")).strip()
        digest = str(raw.get("answer_sha256", "")).strip()
        if not task_id:
            raise ValueError(f"holdout record {index} has an empty task_id")
        if task_id in seen:
            raise ValueError(f"duplicate task_id in holdout manifest: {task_id}")
        if not _SHA256_RE.fullmatch(digest):
            raise ValueError(f"invalid answer_sha256 for {task_id}")
        seen.add(task_id)
        record_metadata = {
            str(key): value
            for key, value in raw.items()
            if str(key) not in {"task_id", "answer_sha256"}
        }
        records.append(HoldoutRecord(task_id, digest.casefold(), record_metadata))
    normalized = {
        "schema_version": int(document.get("schema_version", SCHEMA_VERSION)),
        "name": str(document.get("name", source.stem)),
        "records": [
            {"task_id": record.task_id, "answer_sha256": record.answer_sha256, **record.metadata}
            for record in records
        ],
    }
    if "metadata" in document:
        normalized["metadata"] = manifest_metadata
    manifest_sha256 = hashlib.sha256(_manifest_payload(normalized)).hexdigest()
    declared = str(document.get("manifest_sha256", "")).strip()
    if declared and declared.casefold() != manifest_sha256:
        raise ValueError("holdout manifest_sha256 does not match manifest contents")
    return HoldoutManifest(
        schema_version=int(normalized["schema_version"]),
        name=str(normalized["name"]),
        records=tuple(records),
        manifest_sha256=manifest_sha256,
        metadata=manifest_metadata,
    )


def write_manifest(
    path: Path | str,
    records: Iterable[HoldoutRecord],
    *,
    name: str = "blind-holdout",
    metadata: Mapping[str, Any] | None = None,
) -> HoldoutManifest:
    """Write a digest-only manifest without accepting plaintext answers."""

    normalized_records = tuple(records)
    if not normalized_records:
        raise ValueError("at least one holdout record is required")
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "name": str(name),
        "records": [
            {"task_id": item.task_id, "answer_sha256": item.answer_sha256.casefold(), **item.metadata}
            for item in normalized_records
        ],
    }
    if metadata is not None:
        document["metadata"] = {str(key): value for key, value in metadata.items()}
    # Validate before writing so an accidental plaintext field cannot enter a
    # locked manifest through this helper.
    _reject_plaintext_fields(document)
    loaded_payload = _manifest_payload(document)
    manifest_sha256 = hashlib.sha256(loaded_payload).hexdigest()
    document["manifest_sha256"] = manifest_sha256
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return load_manifest(destination)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _wilson_interval(successes: int, total: int, *, z: float = 1.959963984540054) -> dict[str, float | None]:
    if total <= 0:
        return {"lower": None, "upper": None}
    proportion = successes / total
    z_squared = z * z
    denominator = 1.0 + z_squared / total
    center = (proportion + z_squared / (2.0 * total)) / denominator
    margin = z * math.sqrt(
        proportion * (1.0 - proportion) / total + z_squared / (4.0 * total * total)
    ) / denominator
    return {"lower": max(0.0, center - margin), "upper": min(1.0, center + margin)}


def _group_score(records: Mapping[str, HoldoutRecord], verified: set[str], field_name: str) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[str]] = {}
    for task_id, record in records.items():
        label = str(record.metadata.get(field_name, "unclassified")).strip() or "unclassified"
        groups.setdefault(label, []).append(task_id)
    result: dict[str, dict[str, Any]] = {}
    for label, task_ids in sorted(groups.items()):
        hits = sum(task_id in verified for task_id in task_ids)
        total = len(task_ids)
        result[label] = {
            "verified": hits,
            "total": total,
            "score": round(hits / total, 6) if total else 0.0,
            "wilson_95": _wilson_interval(hits, total),
        }
    return result


def score_report(
    report_path: Path | str,
    manifest_path: Path | str,
    *,
    solver_revision: str | None = None,
    corpus_revision: str | None = None,
) -> dict[str, Any]:
    """Return an independent scorecard for a solver report."""

    manifest = load_manifest(manifest_path)
    report_source = Path(report_path).expanduser().resolve()
    report = json.loads(report_source.read_text(encoding="utf-8"))
    if not isinstance(report, Mapping):
        raise ValueError("solver report must be a JSON object")
    records = {record.task_id: record for record in manifest.records}
    verified: set[str] = set()
    seen: set[tuple[str, str]] = set()
    duplicate_count = 0
    false_positive_keys: set[tuple[str, str]] = set()
    candidate_counts: dict[str, int] = {}
    raw_candidates = report.get("candidates", [])
    if not isinstance(raw_candidates, list):
        raw_candidates = []
    for raw in raw_candidates:
        if not isinstance(raw, Mapping):
            continue
        task_id = str(raw.get("task_id", "")).strip()
        value = str(raw.get("value", "")).strip()
        if not value:
            continue
        candidate_counts[task_id] = candidate_counts.get(task_id, 0) + 1
        key = (task_id, value)
        if key in seen:
            duplicate_count += 1
        else:
            seen.add(key)
        record = records.get(task_id)
        if record is None or _hash(value).casefold() != record.answer_sha256:
            false_positive_keys.add(key)
        else:
            verified.add(task_id)

    missing = sorted(set(records) - verified)
    false_positive_task_ids = sorted({task_id for task_id, _value in false_positive_keys})
    total = len(records)
    report_metadata_value = report.get("metadata", {})
    report_metadata = report_metadata_value if isinstance(report_metadata_value, Mapping) else {}
    duration_value = report_metadata.get("wall_clock_seconds", report_metadata.get("duration_seconds"))
    try:
        duration_seconds = float(duration_value) if duration_value is not None else None
    except (TypeError, ValueError):
        duration_seconds = None
    if duration_seconds is not None and (not math.isfinite(duration_seconds) or duration_seconds < 0):
        duration_seconds = None
    resolved_solver_revision = str(
        solver_revision or report_metadata.get("solver_revision") or "unknown"
    )
    resolved_corpus_revision = str(
        corpus_revision or manifest.metadata.get("corpus_revision") or "unknown"
    )
    false_positive_analyzer_keys: set[tuple[str, str, str]] = set()
    for raw in raw_candidates:
        if not isinstance(raw, Mapping):
            continue
        task_id = str(raw.get("task_id", "")).strip()
        value = str(raw.get("value", "")).strip()
        if not value or (task_id, value) not in false_positive_keys:
            continue
        analyzer = str(raw.get("analyzer", "unknown"))
        false_positive_analyzer_keys.add((analyzer, task_id, value))
    false_positive_analyzers: dict[str, int] = {}
    for analyzer, _task_id, _value in false_positive_analyzer_keys:
        false_positive_analyzers[analyzer] = false_positive_analyzers.get(analyzer, 0) + 1
    holdout_pass = len(verified) == total and not false_positive_keys and duplicate_count == 0
    task_outcomes = []
    for task_id, record in sorted(records.items()):
        task_outcomes.append({
            "task_id": task_id,
            "family": str(record.metadata.get("family", "unclassified")),
            "difficulty": str(record.metadata.get("difficulty", "unclassified")),
            "verified": task_id in verified,
            "candidate_count": candidate_counts.get(task_id, 0),
        })
    return {
        "schema_version": 2,
        "manifest": manifest.name,
        "manifest_sha256": manifest.manifest_sha256,
        "solver_revision": resolved_solver_revision,
        "corpus_revision": resolved_corpus_revision,
        "duration_seconds": duration_seconds,
        "total_tasks": total,
        "verified_count": len(verified),
        "verified_score": round(len(verified) / total, 6) if total else 0.0,
        "wilson_95": _wilson_interval(len(verified), total),
        "by_family": _group_score(records, verified, "family"),
        "by_difficulty": _group_score(records, verified, "difficulty"),
        "task_outcomes": task_outcomes,
        "missing_tasks": missing,
        "false_positive_count": len(false_positive_keys),
        "false_positive_task_ids": false_positive_task_ids,
        "false_positive_analyzers": dict(sorted(false_positive_analyzers.items())),
        "duplicate_count": duplicate_count,
        "holdout_pass": holdout_pass,
        "report_candidate_count": sum(candidate_counts.values()),
        "report_slot_count": len(report.get("slots", [])) if isinstance(report.get("slots", []), list) else 0,
    }


def format_scorecard(score: Mapping[str, Any]) -> str:
    interval = score.get("wilson_95", {})
    lower, upper = interval.get("lower"), interval.get("upper")
    ci = "unavailable" if lower is None or upper is None else f"{float(lower):.1%}-{float(upper):.1%}"
    lines = [
        f"holdout={score['verified_count']}/{score['total_tasks']} "
        f"({float(score['verified_score']):.2%})\n"
        f"wilson_95={ci}\n"
        f"pass={score['holdout_pass']}\n"
        f"false_positives={score['false_positive_count']}\n"
        f"duplicates={score['duplicate_count']}\n"
    ]
    for label, bucket in score.get("by_family", {}).items():
        lines.append(f"family:{label}={bucket['verified']}/{bucket['total']}\n")
    for label, bucket in score.get("by_difficulty", {}).items():
        lines.append(f"difficulty:{label}={bucket['verified']}/{bucket['total']}\n")
    return "".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score an ICO solver report against a blind hash-only holdout")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--solver-revision")
    parser.add_argument("--corpus-revision")
    args = parser.parse_args(argv)
    score = score_report(
        args.report,
        args.manifest,
        solver_revision=args.solver_revision,
        corpus_revision=args.corpus_revision,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(score, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(format_scorecard(score), end="")
    return 0 if score["holdout_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
