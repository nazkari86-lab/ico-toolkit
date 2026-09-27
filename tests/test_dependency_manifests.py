from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DependencyManifestTests(unittest.TestCase):
    def test_aes_solver_groups_install_pycryptodome(self):
        for manifest_name in (
            "requirements-optional-forensics.txt",
            "requirements-optional-reverse.txt",
        ):
            with self.subTest(manifest=manifest_name):
                manifest = ROOT / manifest_name
                packages = {
                    re.split(r"[<>=!~;\[]", line.strip(), maxsplit=1)[0]
                    .strip()
                    .casefold()
                    .replace("_", "-")
                    for line in manifest.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                }
                self.assertIn("pycryptodome", packages)


if __name__ == "__main__":
    unittest.main()
