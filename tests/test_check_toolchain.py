from __future__ import annotations

import unittest

from scripts.check_toolchain import inspect_tool


class ToolchainTests(unittest.TestCase):
    def test_missing_optional_tool_is_reported_without_failure(self):
        result = inspect_tool("ico-tool-that-does-not-exist")
        self.assertEqual(result["status"], "unavailable")
        self.assertIsNone(result["path"])

    def test_present_python_tool_reports_a_path(self):
        result = inspect_tool("python3")
        self.assertEqual(result["status"], "available")
        self.assertTrue(result["path"])


if __name__ == "__main__":
    unittest.main()
