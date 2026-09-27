#!/usr/bin/env python3
"""Run repeated solve/score/evolve cycles for the deterministic final benchmark.

Each measured round is solved and scored independently.  A successor is
created only after the scorecard proves an exact 50/50 with no false
positives; the next iteration then measures that successor.  ``max_rounds``
keeps an invocation bounded while still creating the next harder corpus after
the final successful round, so a caller can resume the cycle later.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.evolve_final_benchmark import next_round
from scripts.generate_final_benchmark import generate


def _stem(round_id: int, profile: str) -> str:
    if profile == "hardest":
        return f"ico_final_50_hardest_round_{round_id:02d}"
    return f"ico_final_50_round_{round_id:02d}"


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _run(command: Sequence[str], *, cwd: Path, stdout_path: Path, stderr_path: Path) -> int:
    completed = subprocess.run(
        list(command),
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    stdout_path.write_text(completed.stdout or "", encoding="utf-8")
    stderr_path.write_text(completed.stderr or "", encoding="utf-8")
    return int(completed.returncode)


def _score_entry(round_id: int, scorecard_path: Path, score: dict[str, Any], solver_code: int, scorer_code: int) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "round_id": round_id,
        "scorecard": str(scorecard_path),
        "solver_exit_code": solver_code,
        "scorer_exit_code": scorer_code,
    }
    for key in (
        "profile",
        "total_tasks",
        "verified_count",
        "verified_score",
        "ten_out_of_ten",
        "false_positive_count",
        "duplicate_count",
        "complexity",
        "fragment_count",
        "decoy_count",
        "cycle_count",
    ):
        if key in score:
            entry[key] = score[key]
    return entry


def run_cycle(
    *,
    start_round: int,
    max_rounds: int,
    profile: str,
    output_root: Path,
    run_root: Path,
    mode: str = "fast",
    workers: int = 2,
    deadline: int = 120,
) -> dict[str, Any]:
    """Measure a bounded sequence of rounds and create each proven successor.

    The returned dictionary is also written to ``run_root/cycle-summary.json``.
    ``stopped_reason`` is ``max_rounds`` only when every measured round passed
    the exact score gate; all other reasons indicate that no successor was
    created after the failing stage.
    """

    if start_round < 1:
        raise ValueError("start_round must be positive")
    if max_rounds < 1:
        raise ValueError("max_rounds must be positive")
    if workers < 1:
        raise ValueError("workers must be positive")
    if deadline <= 0:
        raise ValueError("deadline must be positive")
    if profile not in {"default", "hardest"}:
        raise ValueError(f"unsupported profile: {profile}")

    output_root = output_root.expanduser().resolve()
    run_root = run_root.expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)
    run_root.mkdir(parents=True, exist_ok=True)
    result: dict[str, Any] = {
        "schema_version": 1,
        "profile": profile,
        "start_round": start_round,
        "max_rounds": max_rounds,
        "rounds": [],
        "successors": [],
        "stopped_reason": None,
    }
    corpus: Path | None = None

    for offset in range(max_rounds):
        round_id = start_round + offset
        stem = _stem(round_id, profile)
        if corpus is None:
            corpus = output_root / stem
            manifest_path = output_root / f"{stem}.expected.json"
            generate(round_id, corpus, manifest_path, profile=profile)
        else:
            manifest_path = output_root / f"{stem}.expected.json"
            if corpus != output_root / stem:
                raise RuntimeError("successor path does not match the requested round")

        run_dir = run_root / stem
        if run_dir.exists():
            shutil.rmtree(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        report_path = run_dir / "report.json"
        scorecard_path = run_dir / "scorecard.json"
        solver_code = _run(
            (
                str(ROOT / "ico-solve"),
                str(corpus),
                "--mode",
                mode,
                "--workers",
                str(workers),
                "--deadline",
                str(deadline),
                "--debug",
                str(run_dir),
            ),
            cwd=ROOT,
            stdout_path=run_dir / "solver.stdout",
            stderr_path=run_dir / "solver.stderr",
        )
        if not report_path.is_file():
            result["stopped_reason"] = "solver-report-missing"
            break

        scorer_code = _run(
            (
                sys.executable,
                str(ROOT / "scripts" / "score_final_benchmark.py"),
                "--report",
                str(report_path),
                "--manifest",
                str(manifest_path),
                "--corpus",
                str(corpus),
                "--out",
                str(scorecard_path),
            ),
            cwd=ROOT,
            stdout_path=run_dir / "scorecard.txt",
            stderr_path=run_dir / "scorer.stderr",
        )
        if not scorecard_path.is_file():
            result["stopped_reason"] = "scorecard-missing"
            break
        score = json.loads(scorecard_path.read_text(encoding="utf-8"))
        entry = _score_entry(round_id, scorecard_path, score, solver_code, scorer_code)
        result["rounds"].append(entry)
        _write_json(run_root / "cycle-summary.json", result)

        exact = (
            score.get("round_id") == round_id
            and score.get("profile", "default") == profile
            and score.get("total_tasks") == 50
            and score.get("verified_count") == 50
            and score.get("verified_score") == 1.0
            and score.get("false_positive_count") == 0
            and score.get("duplicate_count") == 0
            and score.get("ten_out_of_ten") is True
        )
        if not exact:
            result["stopped_reason"] = "score-gate"
            break

        successor = next_round(scorecard_path, round_id, output_root, profile=profile)
        if successor is None:
            result["stopped_reason"] = "evolution-gate"
            break
        successor_round = round_id + 1
        result["successors"].append(
            {
                "round_id": successor_round,
                "corpus": str(successor),
                "manifest": str(output_root / f"{_stem(successor_round, profile)}.expected.json"),
            }
        )
        corpus = successor
        _write_json(run_root / "cycle-summary.json", result)

    if result["stopped_reason"] is None:
        result["stopped_reason"] = "max_rounds"
    _write_json(run_root / "cycle-summary.json", result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run repeated ICO final benchmark solve/score/evolve cycles")
    parser.add_argument("--start-round", type=int, default=1)
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--profile", choices=("default", "hardest"), default="hardest")
    parser.add_argument("--output-root", type=Path, default=ROOT / "benchmarks")
    parser.add_argument("--run-root", type=Path, default=ROOT / "ico-final-runs" / "cycle")
    parser.add_argument("--mode", choices=("fast", "full"), default="fast")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--deadline", type=int, default=120)
    args = parser.parse_args(argv)
    result = run_cycle(
        start_round=args.start_round,
        max_rounds=args.max_rounds,
        profile=args.profile,
        output_root=args.output_root,
        run_root=args.run_root,
        mode=args.mode,
        workers=args.workers,
        deadline=args.deadline,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["stopped_reason"] == "max_rounds" and len(result["rounds"]) == args.max_rounds else 2


if __name__ == "__main__":
    raise SystemExit(main())
