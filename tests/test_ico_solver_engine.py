from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ico_scan import _derived_artifact_paths, run_scan
from ico_scan_core import CommandRunner
from ico_quals_solvers import QualsTaskResult
from ico_task_solvers import TaskResult
from ico_solver_engine import (
    Detection,
    SolverContext,
    SolverLimits,
    SolverRegistry,
    SolverResult,
)


class FixtureSolver:
    def __init__(self, name: str, category: str, score: int, *, detects: bool = True) -> None:
        self.name = name
        self.category = category
        self.score = score
        self.detects = detects

    def detect(self, _context: SolverContext) -> Detection | None:
        if not self.detects:
            return None
        return Detection(self.name, self.category, self.score, "fixture", {"fixture": True})

    def solve(self, _context: SolverContext) -> SolverResult:
        return SolverResult(self.name, self.category, "unsupported", [], [], [], None)


class ExplodingSolver(FixtureSolver):
    def solve(self, _context: SolverContext) -> SolverResult:
        raise RuntimeError("fixture failure")


class CandidateSolver(FixtureSolver):
    def solve(self, context: SolverContext) -> SolverResult:
        artifact = context.report_dir / "fixture-derived.txt"
        artifact.write_text("derived fixture evidence", encoding="utf-8")
        return SolverResult(
            self.name,
            self.category,
            "candidate",
            steps=[{"name": "fixture-candidate", "status": "ok"}],
            artifacts=[str(artifact)],
            candidates=[{"value": "ico{registry_fixture}", "source": str(context.input_path)}],
        )


class DerivedInputSolver(FixtureSolver):
    def __init__(self) -> None:
        super().__init__("derived-input", "forensics", 90)
        self.contexts: list[SolverContext] = []

    def solve(self, context: SolverContext) -> SolverResult:
        self.contexts.append(context)
        if context.input_path.name == "seed.bin":
            child = context.report_dir / "artifacts" / "recovered" / "secret.txt"
            child.parent.mkdir(parents=True, exist_ok=True)
            child.write_text("ico{derived_input_scanned}", encoding="utf-8")
            return SolverResult(
                self.name,
                self.category,
                "derived",
                artifacts=[str(child)],
                derived_inputs=[str(child)],
            )
        return SolverResult(
            self.name,
            self.category,
            "candidate",
            candidates=[{"value": "ico{derived_input_scanned}", "source": str(context.input_path)}],
        )


class DerivedCandidateSolver(FixtureSolver):
    def solve(self, context: SolverContext) -> SolverResult:
        if context.input_path.name == "task-derived.txt":
            return SolverResult(
                self.name,
                self.category,
                "candidate",
                candidates=[{"value": "ico{task_aware_derived}", "source": str(context.input_path)}],
            )
        return SolverResult(self.name, self.category, "unsupported")


class ContextCaptureSolver(FixtureSolver):
    def __init__(self) -> None:
        super().__init__("context-capture", "misc", 90)
        self.contexts: list[SolverContext] = []

    def solve(self, context: SolverContext) -> SolverResult:
        self.contexts.append(context)
        return SolverResult(self.name, self.category, "unsupported")


class SolverEngineTests(unittest.TestCase):
    def test_derived_artifact_paths_count_task_quals_and_universal_outputs_once(self):
        shared_path = "/report/shared.bin"
        report = {
            "task_results": [{"artifacts": ["/report/task.bin", shared_path]}],
            "quals_task_results": [{"artifacts": [shared_path, "/report/quals.bin"]}],
            "universal_results": [{"artifacts": [shared_path, "/report/universal.bin"]}],
        }

        self.assertEqual(
            _derived_artifact_paths(report),
            {
                "/report/task.bin",
                shared_path,
                "/report/quals.bin",
                "/report/universal.bin",
            },
        )

    def _context(self, root: Path) -> SolverContext:
        return SolverContext(
            input_path=root / "evidence.bin",
            report_dir=root / "report",
            limits=SolverLimits(1024, 10, 2, 1.0),
            related_paths=(),
            task_text=None,
            classification={"kind": "data"},
            metadata={},
        )

    def test_registry_orders_detections_and_keeps_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = SolverRegistry()
            registry.register(FixtureSolver("low", "misc", 20))
            registry.register(FixtureSolver("high", "crypto", 80))

            detections = registry.detect(self._context(root))

        self.assertEqual([item.name for item in detections], ["high", "low"])
        self.assertEqual(detections[0].metadata["fixture"], True)

    def test_registry_does_not_run_undetected_solver(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = SolverRegistry()
            registry.register(FixtureSolver("skip", "misc", 100, detects=False))
            results = registry.solve(self._context(Path(directory)))
        self.assertEqual(results, [])

    def test_registry_isolates_solver_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = SolverRegistry()
            registry.register(ExplodingSolver("broken", "reverse", 50))
            results = registry.solve(self._context(Path(directory)))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "failed")
        self.assertIn("RuntimeError", results[0].error or "")

    def test_registry_records_solver_duration(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = SolverRegistry([FixtureSolver("timed", "misc", 50)])
            results = registry.solve(self._context(Path(directory)))
        self.assertEqual(len(results), 1)
        self.assertGreaterEqual(results[0].duration_seconds, 0.0)

    def test_run_scan_merges_universal_result_into_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence.txt"
            source.write_text("universal fixture", encoding="utf-8")
            registry = SolverRegistry([CandidateSolver("fixture", "misc", 90)])
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                solver_registry=registry,
            )
            report_text = (root / "report" / "report.txt").read_text(encoding="utf-8")

        self.assertEqual(report["summary"]["universal_solver_count"], 1)
        self.assertEqual(report["summary"]["universal_candidate_count"], 1)
        self.assertEqual(report["summary"]["derived_artifact_count"], 1)
        self.assertEqual(report["candidates"][0]["value"], "ico{registry_fixture}")
        self.assertEqual(report["universal_results"][0]["status"], "candidate")
        self.assertIn("Derived artifacts: 1", report_text)

    def test_run_scan_queues_safe_universal_derived_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task"
            task.mkdir()
            (task / "task.txt").write_text("story clue", encoding="utf-8")
            source = task / "seed.bin"
            source.write_bytes(b"seed")
            solver = DerivedInputSolver()
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                solver_registry=SolverRegistry([solver]),
                runner=CommandRunner(),
                verbose=False,
            )

        scanned = {
            Path(item["evidence_context"]["input_path"]).name
            for item in report["universal_results"]
        }
        self.assertEqual(scanned, {"seed.bin", "secret.txt"})
        self.assertIn("ico{derived_input_scanned}", {item["value"] for item in report["candidates"]})
        self.assertTrue(any(event.get("type") == "derived-input-queued" for event in report["events"]))
        self.assertEqual(solver.contexts[1].task_text, "story clue")
        self.assertEqual(solver.contexts[1].metadata["task_root"], str(task.resolve()))

    def test_run_scan_queues_task_solver_derived_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task"
            task.mkdir()
            statement = task / "task.txt"
            statement.write_text("Family: Forensics\n", encoding="utf-8")

            def fake_task_solver(task_dir, output_dir, expected_hash=None):
                derived = output_dir / "artifacts" / "task-solvers" / "task-derived.txt"
                derived.parent.mkdir(parents=True, exist_ok=True)
                derived.write_text("decoded evidence", encoding="utf-8")
                return TaskResult(
                    "1", task_dir, "fixture-task", "candidate",
                    artifacts=[str(derived)], derived_inputs=[str(derived)],
                )

            with (
                patch("ico_scan.discover_task_dirs", return_value=[task]),
                patch("ico_scan.task_manifest_path", return_value=statement),
                patch("ico_scan.select_solver", return_value=SimpleNamespace(name="fixture-task")),
                patch("ico_scan.solve_task", side_effect=fake_task_solver),
            ):
                report = run_scan(
                    [str(task)],
                    out_dir=root / "report",
                    profile_selector=lambda _classification: [],
                    solver_registry=SolverRegistry([DerivedCandidateSolver("derived-check", "misc", 90)]),
                    verbose=False,
                )

        self.assertIn("ico{task_aware_derived}", {item["value"] for item in report["candidates"]})
        self.assertTrue(
            any(event.get("type") == "derived-input-queued" and event.get("solver") == "fixture-task" for event in report["events"])
        )

    def test_run_scan_queues_quals_solver_derived_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            quals = root / "quals"
            quals.mkdir()

            def fake_quals_solver(task_root, output_dir):
                derived = output_dir / "artifacts" / "ico-quals" / "fixture" / "task-derived.txt"
                derived.parent.mkdir(parents=True, exist_ok=True)
                derived.write_text("decoded evidence", encoding="utf-8")
                return [QualsTaskResult(
                    "fixture-quals", task_root, "fixture-quals", "candidate",
                    artifacts=[str(derived)], derived_inputs=[str(derived)],
                )]

            with (
                patch("ico_scan.discover_task_dirs", return_value=[]),
                patch("ico_scan.discover_ico_quals_roots", return_value=[quals]),
                patch("ico_scan.solve_ico_quals_root", side_effect=fake_quals_solver),
                patch("ico_scan.write_qual_answer_index", return_value={}),
            ):
                report = run_scan(
                    [],
                    out_dir=root / "report",
                    profile_selector=lambda _classification: [],
                    solver_registry=SolverRegistry([DerivedCandidateSolver("derived-check", "misc", 90)]),
                    verbose=False,
                )

        self.assertIn("ico{task_aware_derived}", {item["value"] for item in report["candidates"]})
        self.assertTrue(
            any(event.get("type") == "derived-input-queued" and event.get("solver") == "fixture-quals" for event in report["events"])
        )

    def test_task_context_contains_only_related_evidence_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task"
            task.mkdir()
            (task / "task.txt").write_text("custom multi-file task", encoding="utf-8")
            evidence = task / "evidence.bin"
            sibling = task / "companion.dat"
            evidence.write_bytes(b"evidence")
            sibling.write_bytes(b"companion")
            hidden = task / ".hidden"
            hidden.write_bytes(b"hidden")
            other = root / "other"
            other.mkdir()
            (other / "unrelated.bin").write_bytes(b"unrelated")
            capture = ContextCaptureSolver()
            run_scan(
                [str(evidence)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                solver_registry=SolverRegistry([capture]),
                runner=CommandRunner(),
            )

        self.assertEqual(len(capture.contexts), 1)
        context = capture.contexts[0]
        self.assertEqual(context.task_text, "custom multi-file task")
        self.assertEqual({path.name for path in context.related_paths}, {"companion.dat"})
        self.assertNotIn(hidden, context.related_paths)
        self.assertNotIn(other / "unrelated.bin", context.related_paths)
        self.assertEqual(context.metadata["task_root"], str(task.resolve()))
        self.assertEqual(context.metadata["related_sha256"][str(sibling.resolve())], __import__("hashlib").sha256(b"companion").hexdigest())


if __name__ == "__main__":
    unittest.main()
