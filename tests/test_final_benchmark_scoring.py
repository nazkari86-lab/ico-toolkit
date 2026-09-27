from __future__ import annotations

import json
from pathlib import Path

from scripts.generate_final_benchmark import generate
from scripts.score_final_benchmark import score_report


def test_scorecard_verifies_hashes_and_counts_false_positives(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    manifest_path = tmp_path / "expected.json"
    manifest = generate(round_id=1, root=corpus, manifest_path=manifest_path)
    first = manifest.records[0]
    second = manifest.records[1]
    report = {
        "slots": [{"task_id": first.task_id}, {"task_id": second.task_id}],
        "candidates": [
            {"task_id": first.task_id, "value": "ico{final_r01_01_web_1d1c7b2b9a1f0f7c1c8d}", "state": "candidate"},
            {"task_id": first.task_id, "value": "ico{final_r01_01_web_1d1c7b2b9a1f0f7c1c8d}", "state": "candidate"},
            {"task_id": second.task_id, "value": "ico{wrong_value}", "state": "candidate"},
            {"task_id": "story_99/web_easy", "value": "ico{foreign_task}", "state": "candidate"},
            {"task_id": second.task_id, "value": "", "state": "payload-ready"},
        ],
        "metadata": {"wall_clock_seconds": 1.25},
    }
    # Replace the first value with the real generated answer while preserving
    # the duplicate/false-positive structure of the fixture.
    import scripts.final_benchmark as common

    report["candidates"][0]["value"] = common.task_flag(1, first.story, first.family, first.difficulty)
    report["candidates"][1]["value"] = report["candidates"][0]["value"]
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    score = score_report(report_path, manifest_path, corpus)
    assert score["total_tasks"] == 50
    assert score["verified_count"] == 1
    assert score["verified_score"] == 0.02
    assert score["duplicate_count"] == 1
    assert score["false_positive_count"] == 2
    assert first.task_id not in score["missing_tasks"]
    assert second.task_id in score["missing_tasks"]


def test_scorecard_is_fail_closed_for_missing_manifest_tasks(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    manifest_path = tmp_path / "expected.json"
    generate(round_id=1, root=corpus, manifest_path=manifest_path)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"slots": [], "candidates": []}), encoding="utf-8")
    score = score_report(report_path, manifest_path, corpus)
    assert score["verified_count"] == 0
    assert score["false_positive_count"] == 0
    assert len(score["missing_tasks"]) == 50


def test_scorecard_duplicate_prevents_exact_gate(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    manifest_path = tmp_path / "expected.json"
    manifest = generate(round_id=1, root=corpus, manifest_path=manifest_path)
    import scripts.final_benchmark as common

    candidates = [
        {
            "task_id": record.task_id,
            "value": common.task_flag(1, record.story, record.family, record.difficulty),
            "state": "candidate",
        }
        for record in manifest.records
    ]
    candidates.append(dict(candidates[0]))
    report_path = tmp_path / "report.json"
    report_path.write_text(
        json.dumps(
            {
                "slots": [{"task_id": record.task_id} for record in manifest.records],
                "candidates": candidates,
            }
        ),
        encoding="utf-8",
    )
    score = score_report(report_path, manifest_path, corpus)
    assert score["verified_count"] == 50
    assert score["duplicate_count"] == 1
    assert score["ten_out_of_ten"] is False


def test_hardest_scorecard_records_chain_complexity(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    manifest_path = tmp_path / "expected.json"
    generate(round_id=3, profile="hardest", root=corpus, manifest_path=manifest_path)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps({"slots": [], "candidates": []}), encoding="utf-8")
    score = score_report(report_path, manifest_path, corpus)
    assert score["profile"] == "hardest"
    assert score["complexity"] == 3
    assert score["fragment_count"] == 11
    assert score["decoy_count"] == 10
    assert score["cycle_count"] == 2
