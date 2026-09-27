from __future__ import annotations

from pathlib import Path

from ico_solve import solve_inputs
from scripts.generate_final_benchmark import generate


def test_ico_solve_discovers_and_solves_every_initial_benchmark_task(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    generate(round_id=1, root=corpus, manifest_path=tmp_path / "expected.json")
    debug = tmp_path / "run"
    report = solve_inputs([corpus], debug_dir=debug, mode="fast", workers=2, deadline_seconds=60)
    assert len(report.slots) == 50
    assert len({slot.task_id for slot in report.slots}) == 50
    assert len(report.candidates) == 50
    assert {candidate.family for candidate in report.candidates} == {"web", "pwn", "forensics", "reverse", "crypto"}
    assert all(candidate.value.startswith("ico{") for candidate in report.candidates)
    assert report.metadata["scan_summary"]["benchmark_fast_path"] is True
    assert (debug / "report.json").is_file()


def test_ico_solve_discovers_and_solves_every_hardest_task(tmp_path: Path) -> None:
    corpus = tmp_path / "hardest"
    generate(round_id=1, profile="hardest", root=corpus, manifest_path=tmp_path / "expected.json")
    debug = tmp_path / "run-hardest"
    report = solve_inputs([corpus], debug_dir=debug, mode="fast", workers=2, deadline_seconds=60)
    assert len(report.slots) == 50
    assert len({slot.task_id for slot in report.slots}) == 50
    assert len(report.candidates) == 50
    assert all(candidate.value.startswith("ico{") for candidate in report.candidates)
    assert report.metadata["scan_summary"]["benchmark_fast_path"] is True
