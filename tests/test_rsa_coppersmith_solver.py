from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from Crypto.Util.number import getPrime


ROOT = Path(__file__).resolve().parents[1]
ANALYSIS_VENV = Path(os.environ.get("ICO_ANALYSIS_VENV", ROOT.parent / "ico-analysis-venv312"))
ANALYSIS_PYTHON = ANALYSIS_VENV / "bin" / "python"
RUNNER = ROOT / "bin" / "ico-rsa-coppersmith"


def _has_analysis_runtime() -> bool:
    if not ANALYSIS_PYTHON.is_file() or not RUNNER.is_file():
        return False
    try:
        check = subprocess.run(
            [str(ANALYSIS_PYTHON), "-c", "import fpylll, sympy"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return check.returncode == 0


@unittest.skipUnless(_has_analysis_runtime(), "isolated fpylll runtime is optional")
class RsaCoppersmithIntegrationTests(unittest.TestCase):
    def _run(self, content: str, root: Path) -> dict[str, object]:
        source = root / "rsa-parameters.txt"
        source.write_text(content, encoding="ascii")
        completed = subprocess.run(
            [str(RUNNER), "--input", str(source), "--max-seconds", "30"],
            capture_output=True,
            check=False,
            text=True,
            timeout=45,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return json.loads(completed.stdout)

    def test_recovers_known_prefix_low_exponent_rsa_and_reencrypts_exactly(self):
        p, q = getPrime(191), getPrime(191)
        modulus = p * q
        exponent = 3
        prefix = b"ico{"
        unknown = b"Q4a7cP9x2mN0"
        suffix = b"}"
        plaintext = int.from_bytes(prefix + unknown + suffix, "big")
        ciphertext = pow(plaintext, exponent, modulus)
        self.assertGreater(plaintext**exponent, modulus, "fixture must require a modular small-root attack")

        content = (
            f"n={modulus}\ne={exponent}\nc={ciphertext}\n"
            f"known_prefix={prefix.decode()}\nunknown_suffix_bytes={len(unknown)}\n"
            f"known_suffix={suffix.decode()}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(content, Path(directory))

        self.assertEqual(result["status"], "candidate", result)
        self.assertEqual(result["method"], "rsa-coppersmith-known-prefix")
        self.assertEqual(result["plaintext"], (prefix + unknown + suffix).decode())
        self.assertEqual(result["verification"], "exact-rsa-reencryption")

    def test_refuses_instances_outside_the_small_root_bound(self):
        p, q = getPrime(191), getPrime(191)
        modulus = p * q
        plaintext = int.from_bytes(b"ico{Q4a7cP9x2mN0}", "big")
        ciphertext = pow(plaintext, 3, modulus)
        content = (
            f"n={modulus}\ne=3\nc={ciphertext}\nknown_prefix=ico{{\n"
            "unknown_suffix_bytes=60\nknown_suffix=}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            result = self._run(content, Path(directory))
        self.assertEqual(result["status"], "unsupported", result)

    def test_requires_explicit_rsa_prefix_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self._run("n=3233\ne=3\nc=42\n", Path(directory))
        self.assertEqual(result["status"], "not-applicable", result)


if __name__ == "__main__":
    unittest.main()
