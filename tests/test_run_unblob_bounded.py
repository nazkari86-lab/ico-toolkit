from __future__ import annotations

import argparse
from contextlib import redirect_stderr
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_unblob_bounded.py"
SPEC = importlib.util.spec_from_file_location("run_unblob_bounded", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BoundedUnblobTests(unittest.TestCase):
    def test_tree_usage_counts_regular_files_and_does_not_follow_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            extracted = root / "extracted"
            extracted.mkdir()
            (extracted / "payload.txt").write_bytes(b"12345")
            external = root / "external.txt"
            external.write_bytes(b"outside")
            (extracted / "link.txt").symlink_to(external)

            total_bytes, entries = MODULE.tree_usage(extracted)

        self.assertEqual(total_bytes, 5)
        self.assertEqual(entries, 2)

    def test_oversized_input_is_skipped_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "large.bin"
            source.write_bytes(b"too large")
            output = root / "out"
            args = argparse.Namespace(
                input=source,
                extract_dir=output,
                max_input_bytes=1,
                max_bytes=1024,
                max_entries=20,
                max_seconds=1.0,
                depth=1,
                report=root / "report.json",
                log=root / "unblob.log",
                unblob="unblob-that-must-not-run",
            )

            with redirect_stderr(io.StringIO()):
                result = MODULE.run(args)

        self.assertEqual(result, 0)
        self.assertFalse(output.exists())

    def test_extraction_symlink_is_rejected_before_unblob_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "small.bin"
            source.write_bytes(b"small")
            outside = root / "outside"
            outside.mkdir()
            output_link = root / "extract"
            output_link.symlink_to(outside, target_is_directory=True)
            args = argparse.Namespace(
                input=source,
                extract_dir=output_link,
                max_input_bytes=1024,
                max_bytes=1024,
                max_entries=20,
                max_seconds=1.0,
                depth=1,
                report=root / "report.json",
                log=root / "unblob.log",
                unblob="unblob-that-must-not-run",
            )

            with redirect_stderr(io.StringIO()):
                result = MODULE.run(args)
            outside_contents = list(outside.iterdir())

        self.assertEqual(result, 2)
        self.assertEqual(outside_contents, [])

    def test_prune_tree_keeps_extracted_output_within_byte_and_entry_budgets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.txt").write_bytes(b"12345678")
            (root / "b.txt").write_bytes(b"abcdefgh")
            nested = root / "nested"
            nested.mkdir()
            (nested / "c.txt").write_bytes(b"more")

            total_bytes, entries, pruned = MODULE.prune_tree(root, max_bytes=10, max_entries=2)

            self.assertLessEqual(total_bytes, 10)
            self.assertLessEqual(entries, 2)
            self.assertTrue(pruned)
            self.assertEqual(sorted(path.name for path in root.iterdir()), ["a.txt", "nested"])


if __name__ == "__main__":
    unittest.main()
