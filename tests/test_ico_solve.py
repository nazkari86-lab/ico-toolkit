from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from ico_solve import (
    SolveCandidate,
    SolveReport,
    SolveSlot,
    _slot_for_artifact,
    discover_solve_slots,
    format_stdout,
    rank_candidates,
    select_flags,
    solve_inputs,
)
from ico_solver_engine import SolverLimits
from ico_tool_adapters import AdapterProfile
from ico_evidence_store import EvidenceStore


class IcoSolveModelTests(unittest.TestCase):
    def test_discovery_excludes_walkthrough_and_generated_control_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ico_quals"
            root.mkdir()
            (root / "ICO_full_walkthrough.md").write_text("ico{historical_only}", encoding="utf-8")
            (root / "ICO_self_solve_manual.md").write_text("ico{manual_only}", encoding="utf-8")
            evidence = root / "evidence.bin"
            evidence.write_bytes(b"opaque")

            slots = discover_solve_slots([root], Path(directory) / "workspace", SolverLimits())

        self.assertEqual(len(slots), 1)
        self.assertEqual([path.name for path in slots[0].paths], ["evidence.bin"])

    def test_artifact_slot_prefers_sibling_task_directory_over_story_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "quals"
            task_root = root / "rev_zero"
            task_root.mkdir(parents=True)
            archive = root / "rev_zero.zip"
            archive.write_bytes(b"archive fixture")
            broad = SolveSlot("story_01/misc", "story_01", "misc", "unknown", (archive,), root=root)
            task = SolveSlot("story_02/reverse", "story_02", "reverse", "unknown", (task_root / "rev_zero.html",), root=task_root)

            selected = _slot_for_artifact(archive, (broad, task))

        self.assertIsNotNone(selected)
        self.assertEqual(selected.task_id, "story_02/reverse")

    def test_discovery_reads_story_family_and_difficulty(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "story_01" / "crypto_medium"
            root.mkdir(parents=True)
            (root / "task.txt").write_text(
                "Family: Crypto\nDifficulty: Medium\nDecode the supplied value.\n",
                encoding="utf-8",
            )
            (root / "cipher.txt").write_text("ico{fixture}", encoding="utf-8")
            slots = discover_solve_slots([root], Path(directory) / "workspace", SolverLimits())

        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0].story_id, "story_01")
        self.assertEqual(slots[0].family, "crypto")
        self.assertEqual(slots[0].difficulty, "medium")
        self.assertIn((root / "cipher.txt").resolve(), slots[0].paths)

    def test_nested_archive_is_discovered_as_one_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "story_02_web.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("web/task.txt", "Web\nEasy\n")
                handle.writestr("web/response.txt", "ico{nested_fixture}")
            slots = discover_solve_slots([archive], root / "workspace", SolverLimits())

        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0].family, "web")
        self.assertEqual(slots[0].story_id, "story_02")
        self.assertTrue(any(path.name == "response.txt" for path in slots[0].paths))

    def test_rank_prefers_verified_and_corroborated_values(self):
        slot = SolveSlot("story_01/crypto", "story_01", "crypto", "easy", ())
        result = type(
            "Result",
            (),
            {
                "candidates": [
                    {"value": "ico{same}", "state": "candidate", "triage": "candidate", "analyzer": "a"},
                    {"value": "ico{same}", "state": "candidate", "triage": "candidate", "analyzer": "b"},
                    {"value": "ico{verified}", "state": "hash-verified", "triage": "candidate", "analyzer": "c"},
                    {"value": "ico{dummy_flag}", "state": "hash-verified", "triage": "likely-placeholder", "analyzer": "d"},
                ],
                "solver": "fixture",
                "category": "crypto",
            },
        )()
        ranked = rank_candidates([result], [slot])
        self.assertEqual(ranked[0].value, "ico{verified}")
        self.assertNotIn("ico{dummy_flag}", {item.value for item in ranked})

    def test_format_stdout_is_copy_ready(self):
        candidates = (
            SolveCandidate("ico{a}", "story_01/crypto", "story_01", "crypto", "candidate", 100, ("a",), "candidate"),
            SolveCandidate("ico{b}", "story_01/web", "story_01", "web", "candidate", 100, ("b",), "candidate"),
        )
        report = SolveReport((), candidates, ())
        self.assertEqual(format_stdout(report), "story_01/web\tico{b}\nstory_01/crypto\tico{a}\n")


class IcoSolvePipelineTests(unittest.TestCase):
    def test_solve_inputs_recovers_nested_base64_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "crypto"
            root.mkdir()
            (root / "task.txt").write_text("Crypto\nDecode base64\n", encoding="utf-8")
            value = base64.b64encode(b"ico{base64_fixture}").decode()
            (root / "cipher.txt").write_text(value, encoding="ascii")
            debug = Path(directory) / "debug"
            report = solve_inputs([root], debug_dir=debug, mode="fast")
            self.assertIn("ico{base64_fixture}", {candidate.value for candidate in select_flags(report)})
            self.assertTrue((debug / "report.json").is_file())
            self.assertEqual(json.loads((debug / "report.json").read_text(encoding="utf-8"))["schema_version"], 1)
            self.assertEqual(report.metadata["runner_policy"]["max_output_bytes"], 1_048_576)

    def test_collected_adapter_file_is_reprocessed_by_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "story_01" / "forensics"
            root.mkdir(parents=True)
            (root / "task.txt").write_text("Family: Forensics\nDifficulty: Easy\n", encoding="utf-8")
            source = root / "evidence.bin"
            source.write_bytes(b"opaque")
            code = (
                "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(parents=True,exist_ok=True); "
                "(p/'derived.txt').write_text('ico{derived_registry}', encoding='utf-8')"
            )
            profile = AdapterProfile(
                "fixture-collector",
                sys.executable,
                lambda _path, out: [sys.executable, "-c", code, str(out / "derived-tree")],
                timeout=5,
                stage="specialized",
                collect_dir=lambda _path, out: out / "derived-tree",
            )
            debug = Path(directory) / "debug"
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                report = solve_inputs([root], debug_dir=debug, mode="full")
            self.assertEqual({candidate.value for candidate in select_flags(report)}, {"ico{derived_registry}"})
            self.assertGreaterEqual(report.metadata["derived_solver_result_count"], 1)

    def test_solve_inputs_persists_optional_evidence_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "crypto"
            root.mkdir()
            (root / "task.txt").write_text("Crypto\nDecode base64\n", encoding="utf-8")
            (root / "cipher.txt").write_text(base64.b64encode(b"ico{stored_fixture}").decode(), encoding="ascii")
            database = Path(directory) / "evidence.sqlite3"
            report = solve_inputs([root], debug_dir=Path(directory) / "debug", mode="fast", evidence_db=database)
            self.assertIn("ico{stored_fixture}", {candidate.value for candidate in select_flags(report)})
            with EvidenceStore(database) as store:
                snapshot = store.snapshot()
            self.assertGreaterEqual(snapshot["counts"]["artifacts"], 1)
            self.assertGreaterEqual(snapshot["counts"]["executions"], 1)
            self.assertGreaterEqual(snapshot["counts"]["candidates"], 1)


if __name__ == "__main__":
    unittest.main()
