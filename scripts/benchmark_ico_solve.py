#!/usr/bin/env python3
"""Measure local ico-solve throughput without contacting any service."""

from __future__ import annotations

import argparse
import json
import tempfile
import time
import sys
from pathlib import Path

# Running a script by path places ``scripts`` first on sys.path.  Make the
# toolkit root explicit without requiring an installation step.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ico_solve import select_flags, solve_inputs
from ico_solver_engine import SolverLimits


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Benchmark the offline ico-solve pipeline")
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--mode", choices=("fast", "full"), default="fast")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--deadline", type=float)
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument("--out", type=Path, help="persistent debug/cache directory")
    args = parser.parse_args(argv)
    if args.workers < 1 or args.workers > 32 or args.repeat < 1:
        parser.error("workers must be 1..32 and repeat must be positive")
    missing = [str(path) for path in args.paths if not path.expanduser().exists()]
    if missing:
        parser.error(f"input path does not exist: {missing[0]}")

    def run_once(debug: Path, cache: Path) -> dict[str, object]:
        started = time.monotonic()
        report = solve_inputs(
            args.paths,
            debug_dir=debug,
            mode=args.mode,
            workers=args.workers,
            deadline_seconds=args.deadline,
            cache_dir=cache,
            limits=SolverLimits(),
        )
        metadata = report.metadata
        return {
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "slots": len(report.slots),
            "selected_flags": len(select_flags(report)),
            "candidates": len(report.candidates),
            "adapter_count": metadata.get("adapter_count", 0),
            "adapter_cache_hits": metadata.get("adapter_cache_hits", 0),
            "derived_solver_results": metadata.get("derived_solver_result_count", 0),
            "errors": len(report.errors),
        }

    with tempfile.TemporaryDirectory(prefix="ico-solve-benchmark-") as temporary:
        root = args.out.expanduser().resolve() if args.out else Path(temporary)
        root.mkdir(parents=True, exist_ok=True)
        cache = root / "cache"
        runs = [run_once(root / f"run-{index:02d}", cache) for index in range(args.repeat)]
    print(json.dumps({"mode": args.mode, "workers": args.workers, "repeat": args.repeat, "runs": runs}, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
