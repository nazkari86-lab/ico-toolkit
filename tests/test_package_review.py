from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path


BUILDER = Path(__file__).resolve().parents[1] / "scripts" / "package_review.py"


class ReviewPackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        self.root.mkdir()
        self.out = Path(self.temporary.name) / "export"
        self.git("init", "-q")

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], text=True).strip()

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def commit(self):
        self.git("add", ".")
        self.git("-c", "user.name=Reader Test", "-c", "user.email=reader@example.test", "commit", "-qm", "fixture")
        return self.git("rev-parse", "HEAD")

    def build(self):
        self.assertTrue(BUILDER.is_file(), "The offline review packager is missing")
        return subprocess.run(
            ["python3", str(BUILDER), "--repo", str(self.root), "--out", str(self.out)],
            text=True, capture_output=True, check=False,
        )

    def test_publishes_only_committed_first_party_text(self):
        self.write("README.md", "Reader fixture\n")
        self.write("ico_solve.py", "print('committed source')\n")
        self.write("tests/test_fixture.py", "pass\n")
        self.write("pdf-parser", "#!/bin/sh\nexec python3 parser.py \"$@\"\n").chmod(0o755)
        self.write("vendor/huge.py", "vendored content\n")
        self.write("benchmarks/answers.txt", "answer fixture\n")
        self.write(".env", "PRIVATE_FIXTURE=excluded\n")
        self.write("ico_binary.py", b"\x00\xff")
        (self.root / "ico_link.py").symlink_to(self.root / ".env")
        revision = self.commit()
        self.write("ico_solve.py", "uncommitted content must stay local\n")
        self.write("ico_untracked.py", "untracked content must stay local\n")
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.out / "manifest.json").read_text())
        self.assertEqual(manifest["revision"], revision)
        self.assertEqual({item["path"] for item in manifest["files"]},
                         {"README.md", "ico_solve.py", "tests/test_fixture.py", "pdf-parser"})
        with zipfile.ZipFile(self.out / "ico-src.zip") as archive:
            self.assertEqual(archive.read("ico-toolkit/ico_solve.py"), b"print('committed source')\n")
            self.assertFalse(any(".env" in name or "vendor" in name for name in archive.namelist()))
            self.assertEqual(archive.getinfo("ico-toolkit/pdf-parser").external_attr >> 16, 0o100755)

    def test_all_exported_files_have_matching_hashes_and_priority_text(self):
        content = ("строка🙂" * 500 + "\nlast line\n").encode("utf-8")
        self.write("ico_solve.py", content)
        self.commit()
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = json.loads((self.out / "manifest.json").read_text())
        with zipfile.ZipFile(self.out / "ico-src.zip") as archive:
            self.assertIsNone(archive.testzip())
            for entry in manifest["files"]:
                payload = archive.read("ico-toolkit/" + entry["path"])
                self.assertEqual(entry["sha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual(entry["bytes"], len(payload))
        with zipfile.ZipFile(self.out / "ico-priority.zip") as archive:
            self.assertEqual(archive.read("ico-toolkit/ico_solve.py"), content)
        self.assertIn(content.decode("utf-8"), (self.out / "ico-priority.txt").read_text())
        guide = (self.out / "REVIEW_FIRST.md").read_text()
        self.assertIn(manifest["revision"], guide)
        self.assertIn(f'https://raw.githubusercontent.com/nazkari86-lab/ico-toolkit/{manifest["revision"]}/ico_solve.py', guide)

    def test_existing_output_is_not_overwritten(self):
        self.write("README.md", "fixture\n")
        self.commit()
        self.out.mkdir()
        sentinel = self.out / "keep.txt"
        sentinel.write_text("keep")
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("empty", result.stderr)
        self.assertEqual(sentinel.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
