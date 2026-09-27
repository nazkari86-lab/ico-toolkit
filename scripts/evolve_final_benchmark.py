#!/usr/bin/env python3
"""Create one harder benchmark round after a proven 50/50 score."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.generate_final_benchmark import generate


def _hardest_metrics_for_round(round_id: int) -> dict[str, int]:
    """Return the complexity contract encoded by the hardest generator."""

    return {
        "complexity": max(1, round_id),
        "fragment_count": 7 + 2 * max(0, round_id - 1),
        "decoy_count": 6 + 2 * max(0, round_id - 1),
        "cycle_count": max(0, round_id - 1),
    }


def next_round(scorecard_path: Path, current_round: int, output_root: Path, *, profile: str = "default") -> Path | None:
    score = json.loads(scorecard_path.read_text(encoding="utf-8"))
    required = {"round_id", "total_tasks", "verified_count", "verified_score", "false_positive_count"}
    if not required.issubset(score):
        return None
    if str(score.get("profile", "default")) != profile:
        return None
    if int(score["round_id"]) != int(current_round):
        return None
    if int(score["total_tasks"]) != 50 or int(score["verified_count"]) != 50:
        return None
    if float(score["verified_score"]) != 1.0 or int(score["false_positive_count"]) != 0:
        return None
    successor_round = int(current_round) + 1
    if profile == "hardest":
        required_complexity = _hardest_metrics_for_round(current_round)
        successor_complexity = _hardest_metrics_for_round(successor_round)
        try:
            current_complexity = {key: int(score[key]) for key in required_complexity}
        except (KeyError, TypeError, ValueError):
            return None
        if current_complexity != required_complexity:
            return None
        if not all(successor_complexity[key] > current_complexity[key] for key in required_complexity):
            return None
    output_root = output_root.expanduser().resolve()
    if profile == "hardest":
        stem = f"ico_final_50_hardest_round_{successor_round:02d}"
    else:
        stem = f"ico_final_50_round_{successor_round:02d}"
    corpus = output_root / stem
    manifest_path = output_root / f"{stem}.expected.json"
    generate(successor_round, corpus, manifest_path, profile=profile)
    return corpus


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate one harder ICO benchmark successor after 50/50")
    parser.add_argument("--scorecard", type=Path, required=True)
    parser.add_argument("--round", type=int, required=True, dest="current_round")
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--profile", choices=("default", "hardest"), default="default")
    args = parser.parse_args()
    successor = next_round(args.scorecard, args.current_round, args.output_root, profile=args.profile)
    if successor is None:
        print("successor not created: current score is not an exact 50/50 with zero false positives")
        return 2
    print(f"generated successor: {successor}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
