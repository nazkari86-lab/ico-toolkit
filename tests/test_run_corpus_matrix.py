from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.run_corpus_matrix import _report_metrics


class CorpusMetricTests(unittest.TestCase):
    def test_metrics_separate_current_evidence_and_tool_failures(self):
        report = {
            "candidates": [
                {"value": "ico{local}", "state": "candidate"},
                {"value": "ico{verified}", "state": "hash-verified"},
                {"value": "ico{session}", "state": "transcript-derived"},
                {"value": "ico{review}", "state": "needs-review"},
            ],
            "reference_candidates": [
                {"task_id": "old", "value": "ico{historical}", "state": "reference-only"}
            ],
            "quals_task_results": [
                {"task_id": "one", "status": "payload-ready"},
                {"task_id": "two", "status": "requires-authorized-session"},
                {"task_id": "three", "status": "candidate-review"},
            ],
            "artifacts": [
                {
                    "tools": [
                        {
                            "type": "tool",
                            "analyzer": "strings-ascii",
                            "result": {"ok": True, "duration_seconds": 0.25},
                        },
                        {
                            "type": "tool",
                            "analyzer": "pngcheck",
                            "result": {"ok": False, "timed_out": False, "duration_seconds": 0.5},
                        },
                        {
                            "type": "builtin",
                            "analyzer": "xor-single-byte",
                            "result": {"ok": True, "duration_seconds": 0.1},
                        },
                    ]
                }
            ],
            "events": [
                {"type": "tool-skip", "analyzer": "optional-tool", "reason": "not installed"},
                {"type": "tool-error", "analyzer": "pngcheck", "timed_out": False},
                {"type": "tool-error", "analyzer": "slow-tool", "timed_out": True},
            ],
        }

        metrics = _report_metrics(report, elapsed_seconds=3.5, source_file_count=4, source_unchanged=True)

        self.assertEqual(metrics["elapsed_seconds"], 3.5)
        self.assertEqual(metrics["source_file_count"], 4)
        self.assertTrue(metrics["source_unchanged"])
        self.assertEqual(metrics["current_candidates"], 1)
        self.assertEqual(metrics["hash_verified"], 1)
        self.assertEqual(metrics["transcript_derived"], 1)
        self.assertEqual(metrics["needs_review"], 2)
        self.assertEqual(metrics["payload_ready"], 1)
        self.assertEqual(metrics["session_required"], 1)
        self.assertEqual(metrics["historical_references"], 1)
        self.assertEqual(metrics["tool_calls"], 3)
        self.assertEqual(metrics["tool_errors"], 2)
        self.assertEqual(metrics["tool_timeouts"], 1)
        self.assertEqual(metrics["by_analyzer"]["strings-ascii"]["calls"], 1)
        self.assertEqual(metrics["by_analyzer"]["optional-tool"]["skips"], 1)

    def test_duplicate_values_count_once_in_each_evidence_state(self):
        report = {
            "candidates": [
                {"value": "ico{same}", "state": "candidate"},
                {"value": "ico{same}", "state": "candidate"},
            ],
            "events": [],
            "artifacts": [],
        }
        metrics = _report_metrics(report, elapsed_seconds=1, source_file_count=1, source_unchanged=True)
        self.assertEqual(metrics["current_candidates"], 1)

    def test_universal_payloads_and_case_groups_are_counted_once(self):
        report = {
            "candidates": [],
            "quals_task_results": [],
            "universal_results": [
                {
                    "solver": "universal-reverse",
                    "status": "payload-ready",
                    "candidates": [],
                    "evidence_context": {
                        "input_path": "/tmp/story/pwn_easy/challenge.bin",
                        "metadata": {"task_root": "/tmp/story/pwn_easy"},
                    },
                },
                {
                    "solver": "universal-reverse",
                    "status": "payload-ready",
                    "candidates": [],
                    "evidence_context": {
                        "input_path": "/tmp/story/pwn_easy/task.txt",
                        "metadata": {"task_root": "/tmp/story/pwn_easy"},
                    },
                },
            ],
            "events": [],
            "artifacts": [],
        }
        metrics = _report_metrics(report, elapsed_seconds=1, source_file_count=2, source_unchanged=True)
        self.assertEqual(metrics["payload_ready"], 1)
        self.assertEqual(len(metrics["coverage"]), 1)
        self.assertEqual(metrics["coverage"][0]["story"], "story")
        self.assertEqual(metrics["coverage"][0]["family"], "pwn")
        self.assertEqual(metrics["coverage"][0]["difficulty"], "easy")


if __name__ == "__main__":
    unittest.main()
