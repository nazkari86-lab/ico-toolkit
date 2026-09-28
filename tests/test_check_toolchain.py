from __future__ import annotations

import unittest
import subprocess
import io
import json
from contextlib import redirect_stdout
from unittest.mock import patch

from ico_tool_adapters import TOOL_SPECS, tool_inventory
from scripts.check_toolchain import inspect_tool, main, report_tools


class ToolchainTests(unittest.TestCase):
    def test_missing_optional_tool_is_reported_without_failure(self):
        result = inspect_tool("ico-tool-that-does-not-exist")
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["path"])

    def test_present_python_tool_reports_a_path(self):
        result = inspect_tool("python3")
        self.assertEqual(result["status"], "available")
        self.assertTrue(result["path"])

    def test_default_report_covers_the_complete_solver_registry(self):
        expected = tool_inventory()
        report = report_tools()

        self.assertEqual([item["name"] for item in report], [item["name"] for item in expected])
        self.assertEqual(len(report), len(TOOL_SPECS))
        for actual, registered in zip(report, expected):
            self.assertEqual(actual["state"], registered["state"])
            self.assertEqual(actual["available"], registered["available"])
            self.assertEqual(actual["offline_default"], registered["offline_default"])
            self.assertEqual(actual["local_only"], registered["local_only"])

    def test_generic_inspection_does_not_execute_the_binary(self):
        with patch("subprocess.run", side_effect=AssertionError("must not execute")):
            result = inspect_tool("python3")

        self.assertEqual(result["status"], "available")
        self.assertIsNone(result["version"])

    def test_cli_without_arguments_prints_the_complete_registry(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([]), 0)

        record = json.loads(output.getvalue())
        self.assertEqual([item["name"] for item in record["tools"]], [spec.name for spec in TOOL_SPECS])


if __name__ == "__main__":
    unittest.main()
