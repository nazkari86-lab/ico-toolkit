#!/usr/bin/env python3
"""Independently score an ``ico-solve`` report against an external manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.final_benchmark import BenchmarkManifest, ManifestRecord, load_manifest


VERIFIED_STATES = {"hash-verified", "checker-verified"}
PROGRESS_STATES = {"payload-ready", "candidate", "candidate-review", "unsupported", "needs-review"}
HARDEST_COMPLEXITY_FIELDS = ("complexity", "fragment_count", "decoy_count", "cycle_count")


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _check(value: str, record: ManifestRecord) -> bool:
    if record.checker == "sha256":
        return _hash(value).casefold() == record.answer_sha256.casefold()
    raise ValueError(f"unsupported benchmark checker: {record.checker}")


def _empty_bucket() -> dict[str, Any]:
    return {"total": 0, "verified": 0, "missing": 0, "payload_ready": 0, "candidate": 0, "candidate_review": 0, "unsupported": 0}


def _hardest_complexity(records: dict[str, ManifestRecord], root: Path) -> dict[str, int]:
    """Read and validate the generated chain metrics for a hardest corpus.

    The metrics are deliberately read from the task evidence rather than
    inferred from the round number.  This makes the scorecard an independent
    record of the corpus that was actually scored and gives evolution a
    fail-closed input when a fixture is malformed or mixed.
    """

    observed: set[tuple[int, int, int, int]] = set()
    for record in records.values():
        chain_path = root / record.story / f"{record.family}_{record.difficulty}" / "chain.json"
        try:
            chain = json.loads(chain_path.read_text(encoding="utf-8"))
            metrics = (
                int(chain["complexity"]),
                int(chain["fragment_count"]),
                int(chain["decoys"]),
                int(chain["cycle_count"]),
            )
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid hardest chain metadata: {chain_path}") from exc
        if any(value < 0 for value in metrics):
            raise ValueError(f"negative hardest chain metadata: {chain_path}")
        observed.add(metrics)
    if len(observed) != 1:
        raise ValueError("hardest corpus has inconsistent chain complexity metrics")
    return dict(zip(HARDEST_COMPLEXITY_FIELDS, observed.pop()))


def score_report(report_path: Path, manifest_path: Path, corpus_root: Path) -> dict[str, Any]:
    report = json.loads(report_path.read_text(encoding="utf-8"))
    manifest = load_manifest(manifest_path)
    records = {record.task_id: record for record in manifest.records}
    root = corpus_root.expanduser().resolve()
    for record in manifest.records:
        task_root = root / record.story / f"{record.family}_{record.difficulty}"
        if not task_root.is_dir():
            raise ValueError(f"manifest task root is missing: {task_root}")

    outcomes: dict[str, dict[str, Any]] = {
        task_id: {"task_id": task_id, "family": record.family, "difficulty": record.difficulty, "verified": False, "states": set(), "candidate_count": 0}
        for task_id, record in records.items()
    }
    seen_values: set[tuple[str, str]] = set()
    duplicate_count = 0
    false_positive_keys: set[tuple[str, str]] = set()
    candidates = report.get("candidates", []) if isinstance(report, dict) else []
    if not isinstance(candidates, list):
        candidates = []
    for raw in candidates:
        if not isinstance(raw, dict):
            continue
        task_id = str(raw.get("task_id", "")).strip()
        value = str(raw.get("value", "")).strip()
        state = str(raw.get("state", "candidate")).strip() or "candidate"
        if task_id not in records:
            if value:
                false_positive_keys.add((task_id, value))
            continue
        outcome = outcomes[task_id]
        outcome["states"].add(state)
        if state in PROGRESS_STATES or state in VERIFIED_STATES:
            outcome["candidate_count"] += 1
        if not value:
            continue
        key = (task_id, value)
        if key in seen_values:
            duplicate_count += 1
        else:
            seen_values.add(key)
        if _check(value, records[task_id]):
            outcome["verified"] = True
        else:
            false_positive_keys.add(key)

    by_family: dict[str, dict[str, Any]] = defaultdict(_empty_bucket)
    by_difficulty: dict[str, dict[str, Any]] = defaultdict(_empty_bucket)
    missing_tasks: list[str] = []
    task_outcomes: list[dict[str, Any]] = []
    for task_id in sorted(records):
        outcome = outcomes[task_id]
        record = records[task_id]
        states = sorted(str(item) for item in outcome["states"])
        if outcome["verified"]:
            final_state = "hash-verified"
        elif "payload-ready" in states:
            final_state = "payload-ready"
        elif "candidate-review" in states or "needs-review" in states:
            final_state = "candidate-review"
        elif "candidate" in states:
            final_state = "candidate"
        else:
            final_state = "unsupported"
        if not outcome["verified"]:
            missing_tasks.append(task_id)
        task_outcomes.append({"task_id": task_id, "family": record.family, "difficulty": record.difficulty, "verified": outcome["verified"], "state": final_state, "states": states, "candidate_count": outcome["candidate_count"]})
        for bucket, key in ((by_family[record.family], record.family), (by_difficulty[record.difficulty], record.difficulty)):
            bucket["total"] += 1
            if outcome["verified"]:
                bucket["verified"] += 1
            else:
                bucket["missing"] += 1
            if "payload-ready" in states:
                bucket["payload_ready"] += 1
            if "candidate" in states:
                bucket["candidate"] += 1
            if "candidate-review" in states or "needs-review" in states:
                bucket["candidate_review"] += 1
            if final_state == "unsupported":
                bucket["unsupported"] += 1

    total_tasks = len(records)
    verified_count = sum(1 for outcome in outcomes.values() if outcome["verified"])
    metadata = report.get("metadata", {}) if isinstance(report, dict) else {}
    report_slots = report.get("slots", []) if isinstance(report, dict) else []
    report_task_ids = {str(item.get("task_id", "")) for item in report_slots if isinstance(item, dict)}
    score: dict[str, Any] = {
        "schema_version": 1,
        "round_id": manifest.round_id,
        "profile": manifest.profile,
        "total_tasks": total_tasks,
        "verified_count": verified_count,
        "verified_score": round(verified_count / total_tasks, 6) if total_tasks else 0.0,
        "ten_out_of_ten": verified_count == total_tasks and not false_positive_keys and len(report_task_ids) == total_tasks,
        "false_positive_count": len(false_positive_keys),
        "false_positives": [{"task_id": task_id, "value": value} for task_id, value in sorted(false_positive_keys)],
        "duplicate_count": duplicate_count,
        "report_slot_count": len(report_task_ids),
        "report_task_ids_complete": report_task_ids == set(records),
        "by_family": dict(sorted(by_family.items())),
        "by_difficulty": dict(sorted(by_difficulty.items())),
        "missing_tasks": missing_tasks,
        "task_outcomes": task_outcomes,
        "wall_clock_seconds": metadata.get("wall_clock_seconds"),
    }
    if manifest.profile == "hardest":
        score.update(_hardest_complexity(records, root))
    return score


def format_scorecard(score: dict[str, Any]) -> str:
    lines = [
        f"round={score['round_id']}",
        f"verified={score['verified_count']}/{score['total_tasks']} ({score['verified_score']:.2%})",
        f"10/10={score['ten_out_of_ten']}",
        f"false_positives={score['false_positive_count']}",
        f"duplicates={score['duplicate_count']}",
    ]
    for family, bucket in score["by_family"].items():
        lines.append(f"{family}: {bucket['verified']}/{bucket['total']}")
    if score["missing_tasks"]:
        lines.append("missing:")
        lines.extend(f"  - {task_id}" for task_id in score["missing_tasks"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Score an offline ICO final benchmark report")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    score = score_report(args.report, args.manifest, args.corpus)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(score, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(format_scorecard(score), end="")
    return 0 if score["ten_out_of_ten"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
