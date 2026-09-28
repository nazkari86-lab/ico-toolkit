from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from scripts.holdout_benchmark import HoldoutRecord, load_manifest, score_report, write_manifest


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class HoldoutBenchmarkTests(unittest.TestCase):
    def test_hash_only_manifest_and_score_gate(self) -> None:
        with self.subTest("score"):
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as directory:
                tmp_path = Path(directory)
                manifest_path = tmp_path / "holdout.json"
                write_manifest(
                    manifest_path,
                    (
                        HoldoutRecord("task-a", _digest("ico{alpha}"), {"family": "web"}),
                        HoldoutRecord("task-b", _digest("ico{beta}"), {"family": "crypto", "difficulty": "hard"}),
                    ),
                    metadata={"corpus_revision": "fixture-commit"},
                )
                document = json.loads(manifest_path.read_text(encoding="utf-8"))
                self.assertNotIn("ico{alpha}", manifest_path.read_text(encoding="utf-8"))
                self.assertEqual(document["manifest_sha256"], load_manifest(manifest_path).manifest_sha256)

                report = tmp_path / "report.json"
                report.write_text(
                    json.dumps(
                        {
                            "metadata": {"solver_revision": "solver-abc", "wall_clock_seconds": 12.5},
                            "slots": [{"task_id": "task-a"}, {"task_id": "task-b"}],
                            "candidates": [
                                {"task_id": "task-a", "value": "ico{alpha}"},
                                {"task_id": "task-b", "value": "ico{wrong}", "analyzer": "generic"},
                                {"task_id": "task-b", "value": "ico{wrong}", "analyzer": "generic"},
                                {"task_id": "task-b", "value": "ico{beta}"},
                                {"task_id": "task-b", "value": "ico{beta}"},
                                {"task_id": "unknown", "value": "ico{noise}"},
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                score = score_report(report, manifest_path)
                self.assertEqual(score["verified_count"], 2)
                self.assertEqual(score["missing_tasks"], [])
                self.assertEqual(score["false_positive_count"], 2)
                self.assertEqual(score["duplicate_count"], 2)
                self.assertEqual(score["false_positive_analyzers"], {"generic": 1, "unknown": 1})
                self.assertFalse(score["holdout_pass"])
                self.assertEqual(score["solver_revision"], "solver-abc")
                self.assertEqual(score["corpus_revision"], "fixture-commit")
                self.assertEqual(score["duration_seconds"], 12.5)
                self.assertEqual(score["by_family"]["web"]["verified"], 1)
                self.assertEqual(score["by_difficulty"]["hard"]["total"], 1)
                self.assertLessEqual(score["wilson_95"]["lower"], score["verified_score"])
                self.assertGreaterEqual(score["wilson_95"]["upper"], score["verified_score"])
                score_text = json.dumps(score, ensure_ascii=False)
                self.assertNotIn("ico{wrong}", score_text)
                self.assertNotIn("ico{noise}", score_text)
                self.assertNotIn("value", score_text)

    def test_plaintext_answer_fields_are_rejected(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            manifest = Path(directory) / "bad.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "records": [{"task_id": "task-a", "answer": "ico{secret}"}],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "plaintext"):
                load_manifest(manifest)

    def test_manifest_rejects_bad_digest_and_duplicate_task(self) -> None:
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as directory:
            root = Path(directory)
            bad_digest = root / "bad-digest.json"
            bad_digest.write_text(
                json.dumps({"records": [{"task_id": "a", "answer_sha256": "not-a-hash"}]}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "invalid answer_sha256"):
                load_manifest(bad_digest)

            duplicate = root / "duplicate.json"
            duplicate.write_text(
                json.dumps(
                    {
                        "records": [
                            {"task_id": "a", "answer_sha256": _digest("a")},
                            {"task_id": "a", "answer_sha256": _digest("b")},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate task_id"):
                load_manifest(duplicate)
