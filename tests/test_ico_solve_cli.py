from __future__ import annotations

import base64
import subprocess
import tempfile
import unittest
from pathlib import Path


class IcoSolveCliTests(unittest.TestCase):
    def test_launcher_emits_only_flag_and_debug_report(self):
        toolkit = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "story_01" / "crypto"
            root.mkdir(parents=True)
            (root / "task.txt").write_text("Family: Crypto\nDifficulty: Easy\n", encoding="utf-8")
            (root / "cipher.txt").write_text(base64.b64encode(b"ico{cli_fixture}").decode(), encoding="ascii")
            debug = Path(directory) / "debug"
            completed = subprocess.run(
                [str(toolkit / "ico-solve"), str(root), "--mode", "fast", "--debug", str(debug)],
                cwd=toolkit,
                text=True,
                capture_output=True,
                check=False,
            )
            handoff_dir = debug / "gpt-handoffs" / "story_01_crypto"
            self.assertTrue((handoff_dir / "gpt-4.1-handoff.md").is_file())
            self.assertTrue((handoff_dir / "gpt-4.1-evidence.zip").is_file())
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "ico{cli_fixture}\n")
        self.assertIn("GPT-4.1 HANDOFF: story_01/crypto", completed.stderr)
        self.assertIn("gpt-4.1-handoff.md", completed.stderr)
        self.assertIn("gpt-4.1-evidence.zip", completed.stderr)

    def test_tools_inventory_is_available_without_input(self):
        toolkit = Path(__file__).resolve().parents[1]
        completed = subprocess.run([str(toolkit / "ico-solve"), "--tools"], cwd=toolkit, text=True, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0)
        self.assertIn("cyberchef\t", completed.stdout)
        self.assertIn("zsteg\t", completed.stdout)


if __name__ == "__main__":
    unittest.main()
