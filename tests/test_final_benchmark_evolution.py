from __future__ import annotations

import json
from pathlib import Path

from scripts.evolve_final_benchmark import next_round
from scripts.generate_final_benchmark import generate


def test_successful_score_creates_one_harder_successor(tmp_path: Path) -> None:
    current = tmp_path / "round-01"
    generate(1, current / "corpus", current / "expected.json")
    scorecard = {"round_id": 1, "total_tasks": 50, "verified_count": 50, "verified_score": 1.0, "false_positive_count": 0, "duplicate_count": 0}
    score_path = tmp_path / "score.json"
    score_path.write_text(json.dumps(scorecard), encoding="utf-8")
    successor = next_round(score_path, 1, tmp_path / "benchmarks")
    assert successor == (tmp_path / "benchmarks" / "ico_final_50_round_02").resolve()
    assert len(list(successor.glob("story_*/*/task.txt"))) == 50
    assert (tmp_path / "benchmarks" / "ico_final_50_round_02.expected.json").is_file()


def test_failed_score_does_not_create_successor(tmp_path: Path) -> None:
    score_path = tmp_path / "score.json"
    score_path.write_text(json.dumps({"round_id": 1, "total_tasks": 50, "verified_count": 49, "verified_score": 0.98, "false_positive_count": 0}), encoding="utf-8")
    assert next_round(score_path, 1, tmp_path / "benchmarks") is None
    assert not (tmp_path / "benchmarks").exists()


def test_duplicate_score_does_not_create_successor(tmp_path: Path) -> None:
    score_path = tmp_path / "score.json"
    score_path.write_text(
        json.dumps(
            {
                "round_id": 1,
                "total_tasks": 50,
                "verified_count": 50,
                "verified_score": 1.0,
                "false_positive_count": 0,
                "duplicate_count": 1,
            }
        ),
        encoding="utf-8",
    )
    assert next_round(score_path, 1, tmp_path / "benchmarks") is None
    assert not (tmp_path / "benchmarks").exists()


def test_hardest_score_creates_hardest_successor(tmp_path: Path) -> None:
    score_path = tmp_path / "score.json"
    score_path.write_text(
        json.dumps(
            {
                "round_id": 1,
                "profile": "hardest",
                "total_tasks": 50,
                "verified_count": 50,
                "verified_score": 1.0,
                "false_positive_count": 0,
                "duplicate_count": 0,
                "complexity": 1,
                "fragment_count": 7,
                "decoy_count": 6,
                "cycle_count": 0,
            }
        ),
        encoding="utf-8",
    )
    successor = next_round(score_path, 1, tmp_path / "benchmarks", profile="hardest")
    assert successor == (tmp_path / "benchmarks" / "ico_final_50_hardest_round_02").resolve()
    assert len(list(successor.glob("story_*/*/task.txt"))) == 50
