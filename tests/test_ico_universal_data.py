from __future__ import annotations

import base64
import bz2
import gzip
import io
import lzma
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from ico_solver_engine import SolverContext, SolverLimits
from ico_universal_data import DataSolver, decode_text_tokens, extract_container


class UniversalDataTests(unittest.TestCase):
    def _context(
        self,
        root: Path,
        source: Path,
        *,
        kind: str = "data",
        task_text: str | None = None,
        max_bytes: int = 1024 * 1024,
    ):
        return SolverContext(
            input_path=source,
            report_dir=root / "report",
            limits=SolverLimits(max_bytes=max_bytes, max_files=20, max_depth=3, timeout_seconds=1.0),
            task_text=task_text,
            classification={"kind": kind, "mime": "application/octet-stream"},
        )

    def test_decode_text_tokens_finds_nested_base64_and_hex(self):
        flag = b"ico{nested_universal_data}"
        source = base64.b64encode(base64.b64encode(flag)) + b" " + flag.hex().encode()
        views = decode_text_tokens(source, max_bytes=1024)
        decoded = {item[1] for item in views}
        self.assertIn(flag, decoded)
        self.assertTrue(any(item[2]["depth"] == 1 for item in views))

    def test_data_solver_recovers_crib_xor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{universal_xor}"
            source = root / "cipher.bin"
            source.write_bytes(bytes(value ^ 0x37 for value in b"prefix " + flag))
            result = DataSolver().solve(
                self._context(root, source, task_text="Single-byte XOR with a known flag prefix")
            )
        self.assertEqual({item["value"] for item in result.candidates}, {flag.decode()})
        self.assertEqual(result.status, "candidate")
        self.assertEqual(result.candidates[0]["key"], 0x37)

    def test_data_solver_skips_generic_xor_for_large_binary_without_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "large.bin"
            source.write_bytes(b"\x00" * (2 * 1024 * 1024 + 1))
            context = self._context(root, source, kind="binary", max_bytes=3 * 1024 * 1024)

            with patch("ico_universal_data.single_byte_xor_views") as xor_search:
                result = DataSolver().solve(context)

        xor_search.assert_not_called()
        skip = next(step for step in result.steps if step["name"] == "single-byte-xor")
        self.assertEqual(skip["status"], "skipped")
        self.assertEqual(result.candidates, [])

    def test_data_solver_runs_xor_for_large_binary_with_explicit_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "large.bin"
            source.write_bytes(b"\x00" * (2 * 1024 * 1024 + 1))
            context = self._context(
                root,
                source,
                kind="binary",
                task_text="Recover the plaintext using single-byte XOR",
                max_bytes=3 * 1024 * 1024,
            )

            with patch("ico_universal_data.single_byte_xor_views", return_value=[]) as xor_search:
                result = DataSolver().solve(context)

        xor_search.assert_called_once()
        self.assertEqual(result.candidates, [])

    def test_data_solver_decodes_nested_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ico{universal_encoding}"
            source = root / "message.txt"
            source.write_bytes(b"payload=" + base64.b64encode(base64.b64encode(flag)))
            result = DataSolver().solve(self._context(root, source, kind="text", task_text="Decode Base64"))
        self.assertEqual({item["value"] for item in result.candidates}, {flag.decode()})
        self.assertTrue(any("decoded" in path for path in result.artifacts))

    def test_data_solver_decodes_rot13_flag_marker_in_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reversed-checker.py"
            source.write_text('expected = "vpgs{ebg13_grkg_gbxra}"\n', encoding="utf-8")
            result = DataSolver().solve(
                self._context(root, source, kind="text", task_text="reversed checker")
            )

        self.assertEqual(
            {item["value"] for item in result.candidates},
            {"ictf{rot13_text_token}"},
        )

    def test_data_solver_decodes_reversed_python_literal_then_rot13(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "static-checker.py"
            source.write_text("exec('}avnup_31gbe_rferire{sgpv'[::-1])\n", encoding="utf-8")
            result = DataSolver().solve(
                self._context(root, source, kind="binary", task_text="reversing checker")
            )

        self.assertEqual(
            {item["value"] for item in result.candidates},
            {"ictf{reverse_rot13_chain}"},
        )

    def test_extract_container_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evil.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("../outside.txt", b"ico{escape}")
            with self.assertRaises(ValueError):
                extract_container(source, root / "report", SolverLimits(max_bytes=1024, max_files=4, max_depth=2, timeout_seconds=1.0))

    def test_extract_container_writes_bounded_zip_and_gzip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "outer.zip"
            inner = gzip.compress(b"ico{nested_archive}")
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("inner.gz", inner)
            paths = extract_container(
                source,
                root / "report",
                SolverLimits(max_bytes=1024 * 1024, max_files=4, max_depth=2, timeout_seconds=1.0),
            )
            self.assertEqual(len(paths), 1)
            self.assertEqual(paths[0].read_bytes(), inner)

    def test_data_solver_exposes_top_level_xz_member_for_follow_on_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"\xd4\xc3\xb2\xa1bounded-pcap-fixture"
            source = root / "capture.pcap.xz"
            source.write_bytes(lzma.compress(payload))
            result = DataSolver().solve(self._context(root, source, kind="archive"))

            derived_paths = [Path(path) for path in result.derived_inputs]
            derived_bytes = [path.read_bytes() for path in derived_paths]

        self.assertEqual(derived_bytes, [payload])

    def test_extract_container_streams_compressed_files_with_an_output_limit(self):
        payload = b"A" * (256 * 1024)
        cases = (
            (".gz", gzip.compress, "ico_universal_data.gzip.decompress"),
            (".bz2", bz2.compress, "ico_universal_data.bz2.decompress"),
            (".xz", lzma.compress, "ico_universal_data.lzma.decompress"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for suffix, compress, unbounded_api in cases:
                with self.subTest(suffix=suffix):
                    source = root / f"bomb{suffix}"
                    source.write_bytes(compress(payload))
                    with patch(unbounded_api, side_effect=AssertionError("unbounded decompressor used")):
                        with self.assertRaisesRegex(ValueError, "byte limit"):
                            extract_container(
                                source,
                                root / f"report-{suffix[1:]}",
                                SolverLimits(max_bytes=64 * 1024, max_files=4, max_depth=2, timeout_seconds=1.0),
                            )

    def test_extract_container_streams_zip_members_with_an_output_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "bomb.zip"
            with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("large.txt", b"A" * (256 * 1024))

            with patch("zipfile.ZipFile.read", side_effect=AssertionError("unbounded ZIP read used")):
                with self.assertRaisesRegex(ValueError, "byte limit"):
                    extract_container(
                        source,
                        root / "report",
                        SolverLimits(max_bytes=64 * 1024, max_files=4, max_depth=2, timeout_seconds=1.0),
                    )

    def test_plain_flag_word_does_not_make_a_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plain.txt"
            source.write_text("the word flag appears without braces", encoding="utf-8")
            result = DataSolver().solve(self._context(root, source, kind="text", task_text="Decode Base64"))
        self.assertEqual(result.candidates, [])


if __name__ == "__main__":
    unittest.main()
