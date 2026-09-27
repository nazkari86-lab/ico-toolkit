from __future__ import annotations

import json
from pathlib import Path

from scripts.run_final_benchmark_cycle import run_cycle


def test_cycle_solves_two_rounds_and_generates_the_next_harder_round(tmp_path: Path) -> None:
    result = run_cycle(
        start_round=1,
        max_rounds=2,
        profile="hardest",
        output_root=tmp_path / "benchmarks",
        run_root=tmp_path / "runs",
        workers=2,
        deadline=120,
    )

    assert result["stopped_reason"] == "max_rounds"
    assert [item["round_id"] for item in result["rounds"]] == [1, 2]
    assert [item["round_id"] for item in result["successors"]] == [2, 3]
    assert all(item["verified_count"] == 50 for item in result["rounds"])
    assert all(item["false_positive_count"] == 0 for item in result["rounds"])
    assert all(item["ten_out_of_ten"] is True for item in result["rounds"])

    round_two_chain = json.loads(
        (
            tmp_path
            / "benchmarks"
            / "ico_final_50_hardest_round_02"
            / "story_01"
            / "web_hard"
            / "chain.json"
        ).read_text(encoding="utf-8")
    )
    round_three_chain = json.loads(
        (
            tmp_path
            / "benchmarks"
            / "ico_final_50_hardest_round_03"
            / "story_01"
            / "web_hard"
            / "chain.json"
        ).read_text(encoding="utf-8")
    )
    for key in ("complexity", "fragment_count", "decoys", "cycle_count"):
        assert round_three_chain[key] > round_two_chain[key]
