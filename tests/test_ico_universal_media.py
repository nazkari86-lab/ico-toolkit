from __future__ import annotations

import io
import importlib.util
import json
import struct
import tempfile
import unittest
import wave
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ico_solver_engine import SolverContext, SolverLimits
from ico_universal_media import (
    MediaSolver,
    _bits_to_bytes,
    _normalize_vision_flag_prefix,
    extract_png_planes,
    extract_wav_bitstreams,
    decode_blurred_qr,
)


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def _png(rows: bytes, width: int, height: int, *, color_type: int = 2, extra: bytes = b"") -> bytes:
    channels = 3 if color_type == 2 else 4
    header = struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + extra
        + _chunk(b"IDAT", zlib.compress(rows))
        + _chunk(b"IEND", b"")
    )


def _context(root: Path, source: Path, kind: str, task_text: str | None = None) -> SolverContext:
    return SolverContext(
        input_path=source,
        report_dir=root / "report",
        limits=SolverLimits(max_bytes=1024 * 1024, max_files=20, max_depth=3, timeout_seconds=1.0),
        task_text=task_text,
        classification={"kind": kind, "mime": "image/png" if kind == "image" else "audio/x-wav"},
    )


class UniversalMediaTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec("cv2") and importlib.util.find_spec("numpy"), "QR backend unavailable")
    def test_inverse_gaussian_qr_recovers_blurred_code(self):
        import cv2

        original = cv2.QRCodeEncoder_create().encode("ico{blurred_qr_fixture}")
        scaled = cv2.resize(original, (250, 250), interpolation=cv2.INTER_NEAREST)
        blurred = cv2.GaussianBlur(scaled, (0, 0), 6)
        encoded, png = cv2.imencode(".png", blurred)
        self.assertTrue(encoded)
        decoded = decode_blurred_qr(png.tobytes(), hint="blurry QR code")
        self.assertEqual(decoded["payload"], "ico{blurred_qr_fixture}")
        self.assertEqual(decoded["method"], "inverse-gaussian-qr")

    def test_qr_solver_skips_unhinted_image(self):
        self.assertEqual(decode_blurred_qr(b"not an image", hint="PNG metadata")["status"], "not-applicable")

    def test_bit_decoder_stops_at_nul_without_materializing_all_bits(self):
        bits = [bit for value in b"ABC\x00unused" for bit in ((value >> shift) & 1 for shift in range(7, -1, -1))]

        def bounded_bits():
            yield from bits[:32]
            raise AssertionError("decoder consumed bits after the terminator")

        self.assertEqual(_bits_to_bytes(bounded_bits()), b"ABC")

    def test_png_lsb_plane_recovers_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ico{media_plane}"
            bits = [bit for value in flag + b"\x00" for bit in ((value >> shift) & 1 for shift in range(7, -1, -1))]
            pixels = bytearray([0x40] * (len(bits) + 2))
            for index, bit in enumerate(bits):
                pixels[index] = (pixels[index] & 0xFE) | bit
            width = len(pixels) // 3
            source = root / "plane.png"
            source.write_bytes(_png(b"\x00" + bytes(pixels), width, 1))
            result = MediaSolver().solve(_context(root, source, "image", "LSB steganography"))
        self.assertIn("ico{media_plane}", {item["value"] for item in result.candidates})

    def test_png_filters_and_ztxt_are_decoded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{compressed_media}"
            ztxt = b"Comment\x00\x00" + zlib.compress(flag)
            row = b"\x00\x20\x30\x40" + b"\x00\x00\x00"
            source = root / "metadata.png"
            source.write_bytes(_png(row, 2, 1, extra=_chunk(b"zTXt", ztxt)))
            result = MediaSolver().solve(_context(root, source, "image", "PNG zTXt metadata"))
        self.assertIn("CTF{compressed_media}", {item["value"] for item in result.candidates})

    def test_png_ocr_recovers_ictf_flag_with_recognizer_whitespace(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "printed-flag.png"
            source.write_bytes(_png(b"\x00\xff\xff\xff", 1, 1))
            context = _context(root, source, "image", "forensics image")
            mocked = SimpleNamespace(returncode=0, stdout="Flag:\nictf {h1 dd3n_1n_th3_n3twork_layer_1b21e349}\n", stderr="")
            with patch("ico_universal_media.shutil.which", return_value="/fake/tesseract"), patch(
                "ico_universal_media.subprocess.run", return_value=mocked
            ) as run:
                result = MediaSolver().solve(context)

        self.assertIn("ictf{h1dd3n_1n_th3_n3twork_layer_1b21e349}", {item["value"] for item in result.candidates})
        self.assertTrue(any(path.endswith("ocr-input.ppm") for path in result.artifacts))
        run.assert_called_once()

    def test_png_ocr_tries_fallback_page_modes_until_a_flag_is_found(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "handwritten-flag.png"
            source.write_bytes(_png(b"\x00\xff\xff\xff", 1, 1))
            context = _context(root, source, "image", "handwritten CTF flag")
            partial = SimpleNamespace(returncode=0, stdout="icAf fixed! 5PSce 751}\n", stderr="")
            complete = SimpleNamespace(returncode=0, stdout="ictf{fallback_ocr}\n", stderr="")
            with patch("ico_universal_media.shutil.which", return_value="/fake/tesseract"), patch(
                "ico_universal_media.subprocess.run", side_effect=[partial, complete]
            ) as run:
                result = MediaSolver().solve(context)

        self.assertIn("ictf{fallback_ocr}", {item["value"] for item in result.candidates})
        self.assertEqual([call.args[0][-1] for call in run.call_args_list], ["6", "7"])

    def test_png_ocr_preserves_partial_flag_text_for_manual_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "handwritten-flag.png"
            source.write_bytes(_png(b"\x00\xff\xff\xff", 1, 1))
            context = _context(root, source, "image", "handwritten CTF flag")
            partial = SimpleNamespace(returncode=0, stdout="ctf fixed! 3PSce 751}\n", stderr="")
            with patch("sys.platform", "linux"), patch(
                "ico_universal_media.shutil.which", return_value="/fake/tesseract"
            ), patch(
                "ico_universal_media.subprocess.run", side_effect=[partial, partial, partial]
            ):
                result = MediaSolver().solve(context)

        ocr = next(step for step in result.steps if step["name"] == "ocr-image-text")
        self.assertEqual(result.status, "candidate-review")
        self.assertEqual(ocr["details"]["review_text"], "ctf fixed! 3PSce 751}")
        self.assertEqual(ocr["details"]["ocr_calls"], 3)

    def test_macos_vision_ocr_surfaces_brace_confusion_as_an_unverified_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "caesar-recovered.png"
            source.write_bytes(_png(b"\x00\xff\xff\xff", 1, 1))
            context = _context(root, source, "image", "Did Caesar like PNG files?")
            partial = SimpleNamespace(returncode=0, stdout="icAf fixed! 5PSce 751}\n", stderr="")
            vision = SimpleNamespace(
                returncode=0,
                stdout=json.dumps(
                    [{"candidates": [{"text": "ictfEfixed!_3f5ce751}", "confidence": 1.0}]}]
                ),
                stderr="",
            )
            with patch("sys.platform", "darwin"), patch(
                "ico_universal_media.shutil.which", side_effect=lambda name: f"/fake/{name}"
            ), patch("ico_universal_media.subprocess.run", side_effect=[partial, partial, partial, vision]):
                result = MediaSolver().solve(context)

        candidate = next((item for item in result.candidates if item["value"] == "ictf{fixed!_3f5ce751}"), None)
        self.assertIsNotNone(candidate)
        assert candidate is not None
        self.assertEqual(candidate["verification"], "vision-ocr-corrected")
        self.assertEqual(candidate["ocr_raw"], "ictfEfixed!_3f5ce751}")
        self.assertEqual(candidate["ocr_confidence"], 1.0)

    def test_vision_prefix_repair_is_limited_to_ictf_open_brace_confusion(self):
        self.assertEqual(
            _normalize_vision_flag_prefix("ictfEfixed!_3f5ce751}"),
            ("ictf{fixed!_3f5ce751}", "Vision OCR read the opening brace after ictf as E"),
        )
        self.assertEqual(_normalize_vision_flag_prefix("jctfEkeep_this_reviewing}"), ("jctfEkeep_this_reviewing}", None))

    def test_wav_lsb_recovers_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ico{wav_bits}"
            bits = [bit for value in flag + b"\x00" for bit in ((value >> shift) & 1 for shift in range(7, -1, -1))]
            samples = [(0x201 if bit else 0x202) for bit in bits]
            stream = io.BytesIO()
            with wave.open(stream, "wb") as audio:
                audio.setnchannels(1)
                audio.setsampwidth(2)
                audio.setframerate(8000)
                audio.writeframes(struct.pack("<" + "h" * len(samples), *samples))
            source = root / "recording.wav"
            source.write_bytes(stream.getvalue())
            result = MediaSolver().solve(_context(root, source, "audio", "16-bit PCM LSB"))
        self.assertIn("ico{wav_bits}", {item["value"] for item in result.candidates})

    def test_plane_and_wav_helpers_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            png_path = root / "tiny.png"
            png_path.write_bytes(_png(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09", 3, 1))
            wav_path = root / "tiny.wav"
            stream = io.BytesIO()
            with wave.open(stream, "wb") as audio:
                audio.setnchannels(1)
                audio.setsampwidth(2)
                audio.setframerate(8000)
                audio.writeframes(struct.pack("<hhhhhhhh", 1, 0, 1, 0, 1, 0, 1, 0))
            wav_path.write_bytes(stream.getvalue())
            self.assertTrue(extract_png_planes(png_path, SolverLimits(max_bytes=1024, max_files=2, max_depth=1, timeout_seconds=1.0)))
            self.assertTrue(extract_wav_bitstreams(wav_path, SolverLimits(max_bytes=1024, max_files=2, max_depth=1, timeout_seconds=1.0)))

    def test_quals_spectrogram_derivatives_skip_duplicate_media_solver(self):
        with tempfile.TemporaryDirectory() as directory:
            task = Path(directory) / "can_you_hear"
            task.mkdir()
            source = task / "spectrum.png"
            source.write_bytes(b"not a real png")
            context = _context(Path(directory), source, "image")
        self.assertIsNone(MediaSolver().detect(context))


if __name__ == "__main__":
    unittest.main()
