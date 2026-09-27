from __future__ import annotations

import unittest
from pathlib import Path

from ico_external_aes import _minkwitz_factorization, parse_output
from ico_solver_engine import SolverContext, SolverLimits
from ico_universal_registry import build_default_registry


AES_TASK = Path("/tmp/ico-external-ctf/ductf2024-blind/crypto/AES")


class DuctfAesTests(unittest.TestCase):
    def test_minkwitz_uses_the_permutations_actual_degree(self):
        swap = (1, 0) + tuple(range(2, 16))

        factors = _minkwitz_factorization((swap,), swap)

        self.assertEqual(factors, [(0, 1)])

    def test_parser_evaluates_sage_power_precedence_without_executing_source(self):
        output = AES_TASK / "output.sage"
        if not output.is_file():
            self.skipTest("local DUCTF AES artifact is unavailable")

        parsed = parse_output(output)

        self.assertEqual(len(parsed.tau), 16)
        self.assertEqual(len(parsed.braid_matrices), 64)
        self.assertEqual(len(parsed.braid_matrices[0]), 15)
        self.assertEqual(len(parsed.ciphertext), 44)

    def test_real_aes_public_permutation_factorizes(self):
        output = AES_TASK / "output.sage"
        if not output.is_file():
            self.skipTest("local DUCTF AES artifact is unavailable")
        parsed = parse_output(output)

        factors = _minkwitz_factorization(parsed.braid_permutations, parsed.alice_permutation)

        self.assertGreater(len(factors), 0)

    def test_official_output_selects_a_task_aware_aes_profile(self):
        output = AES_TASK / "output.sage"
        if not output.is_file():
            self.skipTest("local DUCTF AES artifact is unavailable")
        peers = tuple(path for path in AES_TASK.iterdir() if path != output)
        context = SolverContext(
            input_path=output,
            report_dir=AES_TASK / "test-report",
            limits=SolverLimits(max_bytes=1_000_000, max_files=100, max_depth=3, timeout_seconds=30.0),
            related_paths=peers,
            task_text=(AES_TASK / "README.md").read_text(encoding="utf-8"),
            classification={"kind": "text", "mime": "text/plain"},
            metadata={"task_root": str(AES_TASK)},
        )
        solver = next(item for item in build_default_registry().solvers if item.name == "external-ctf-offline")

        detection = solver.detect(context)

        self.assertIsNotNone(detection)
        self.assertEqual(detection.metadata.get("profile"), "ductf-aes")


if __name__ == "__main__":
    unittest.main()
