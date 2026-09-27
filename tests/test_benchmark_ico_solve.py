from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class BenchmarkTests(unittest.TestCase):
    def test_benchmark_reports_repeat_and_cache_metrics(self):
        toolkit = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "evidence.txt"
            source.write_text("ico{benchmark_fixture}\n", encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, str(toolkit / "scripts" / "benchmark_ico_solve.py"), str(source), "--repeat", "2", "--mode", "fast"],
                cwd=toolkit,
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["repeat"], 2)
        self.assertEqual(len(report["runs"]), 2)
        self.assertGreaterEqual(report["runs"][0]["selected_flags"], 1)
        self.assertGreaterEqual(report["runs"][1]["adapter_cache_hits"], 1)


if __name__ == "__main__":
    unittest.main()
