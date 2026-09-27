from __future__ import annotations

import hashlib
from pathlib import Path

from ico_final_benchmark_solver import solve_final_task
from scripts.final_benchmark import task_flag
from scripts.generate_final_benchmark import generate


def test_round_one_solver_recovers_all_fifty_values(tmp_path: Path) -> None:
    generate(round_id=1, root=tmp_path / "corpus", manifest_path=tmp_path / "expected.json")
    roots = sorted((tmp_path / "corpus").glob("story_*/*"))
    assert len(roots) == 50
    failures: list[str] = []
    for root in roots:
        task_text = (root / "task.txt").read_text(encoding="utf-8")
        fields = dict(line.split(": ", 1) for line in task_text.splitlines() if ": " in line)
        result = solve_final_task(root, fields["Task ID"], fields["Family"].lower(), fields["Mechanism"], task_text)
        candidates = [] if result is None else result.get("candidates", [])
        expected = task_flag(1, fields["Task ID"].split("/", 1)[0], fields["Family"].lower(), fields["Difficulty"].lower())
        if len(candidates) != 1 or candidates[0].get("value") != expected:
            failures.append(f"{fields['Task ID']}: {result}")
    assert not failures, "\n".join(failures)


def test_solver_does_not_activate_without_explicit_marker(tmp_path: Path) -> None:
    root = tmp_path / "task"
    root.mkdir()
    (root / "task.txt").write_text("Family: crypto\nMechanism: caesar_noise\n", encoding="utf-8")
    assert solve_final_task(root, "task", "crypto", "caesar_noise", (root / "task.txt").read_text()) is None


def test_hardest_profile_solver_recovers_all_fifty_values(tmp_path: Path) -> None:
    generate(round_id=1, profile="hardest", root=tmp_path / "corpus", manifest_path=tmp_path / "expected.json")
    failures: list[str] = []
    roots = sorted((tmp_path / "corpus").glob("story_*/*"))
    assert len(roots) == 50
    for root in roots:
        task_text = (root / "task.txt").read_text(encoding="utf-8")
        fields = dict(line.split(": ", 1) for line in task_text.splitlines() if ": " in line)
        result = solve_final_task(root, fields["Task ID"], fields["Family"].lower(), fields["Mechanism"], task_text)
        candidates = [] if result is None else result.get("candidates", [])
        expected = task_flag(
            1,
            fields["Task ID"].split("/", 1)[0],
            fields["Family"].lower(),
            fields["Difficulty"].lower(),
            profile="hardest",
        )
        if len(candidates) != 1 or candidates[0].get("value") != expected:
            failures.append(f"{fields['Task ID']}: {result}")
    assert not failures, "\n".join(failures)


def test_hardest_profile_solver_handles_growing_fragment_counts(tmp_path: Path) -> None:
    for round_id in (2, 3):
        corpus = tmp_path / f"round-{round_id}"
        generate(round_id=round_id, profile="hardest", root=corpus, manifest_path=tmp_path / f"{round_id}.json")
        failures: list[str] = []
        for root in sorted(corpus.glob("story_*/*")):
            task_text = (root / "task.txt").read_text(encoding="utf-8")
            fields = dict(line.split(": ", 1) for line in task_text.splitlines() if ": " in line)
            result = solve_final_task(root, fields["Task ID"], fields["Family"].lower(), fields["Mechanism"], task_text)
            candidates = [] if result is None else result.get("candidates", [])
            expected = task_flag(
                round_id,
                fields["Task ID"].split("/", 1)[0],
                fields["Family"].lower(),
                fields["Difficulty"].lower(),
                profile="hardest",
            )
            if len(candidates) != 1 or candidates[0].get("value") != expected:
                failures.append(f"{fields['Task ID']}: {result}")
        assert not failures, f"round {round_id}:\n" + "\n".join(failures)
