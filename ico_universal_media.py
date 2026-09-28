#!/usr/bin/env python3
"""Deterministic media and steganography profiles for local CTF artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import time
import wave
import zlib
from pathlib import Path
from typing import Iterable

from ico_scan_core import FlagMatcher
from ico_solver_engine import Detection, SolverContext, SolverLimits, SolverResult


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
OCR_MAX_PIXELS = 15_000_000
OCR_FLAG_PATTERN = re.compile(r"(?i)\b(ictf|ico|ctf|flag)\s*\{\s*([^{}\r\n]*)\}")
OCR_PARTIAL_PREFIX_PATTERN = re.compile(r"(?i)\b(?:ictf|ico|ctf|flag|icaf)\b")


def _read_limited(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds byte limit: {size} > {limit}")
    return path.read_bytes()


def _chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("expected PNG signature")
    output: list[tuple[bytes, bytes]] = []
    offset = len(PNG_SIGNATURE)
    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(data):
            raise ValueError("truncated PNG chunk")
        payload = data[offset + 8 : offset + 8 + length]
        output.append((kind, payload))
        offset = end
        if kind == b"IEND":
            break
    return output


def _paeth(a: int, b: int, c: int) -> int:
    estimate = a + b - c
    pa = abs(estimate - a)
    pb = abs(estimate - b)
    pc = abs(estimate - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _png_pixels(data: bytes) -> tuple[int, int, int, bytes, list[tuple[bytes, bytes]]]:
    chunks = _chunks(data)
    try:
        ihdr = next(payload for kind, payload in chunks if kind == b"IHDR")
    except StopIteration as exc:
        raise ValueError("PNG has no IHDR") from exc
    width, height, depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", ihdr)
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type)
    if not channels or depth != 8 or compression != 0 or filtering != 0 or interlace != 0:
        raise ValueError("only non-interlaced 8-bit PNG color types are supported")
    compressed = b"".join(payload for kind, payload in chunks if kind == b"IDAT")
    raw = zlib.decompress(compressed)
    row_size = width * channels
    rows: list[bytes] = []
    offset = 0
    previous = bytes(row_size)
    for _ in range(height):
        if offset + row_size + 1 > len(raw):
            raise ValueError("truncated PNG scanline")
        filter_type = raw[offset]
        encoded = raw[offset + 1 : offset + 1 + row_size]
        offset += row_size + 1
        row = bytearray(row_size)
        for index, value in enumerate(encoded):
            left = row[index - channels] if index >= channels else 0
            up = previous[index]
            up_left = previous[index - channels] if index >= channels else 0
            if filter_type == 0:
                predictor = 0
            elif filter_type == 1:
                predictor = left
            elif filter_type == 2:
                predictor = up
            elif filter_type == 3:
                predictor = (left + up) // 2
            elif filter_type == 4:
                predictor = _paeth(left, up, up_left)
            else:
                raise ValueError(f"unsupported PNG filter {filter_type}")
            row[index] = (value + predictor) & 0xFF
        rows.append(bytes(row))
        previous = bytes(row)
    return width, height, channels, b"".join(rows), chunks


def _bits_to_bytes(bits: Iterable[int], *, msb_first: bool = True) -> bytes:
    output = bytearray()
    value = 0
    count = 0
    for bit in bits:
        if msb_first:
            value = (value << 1) | (int(bit) & 1)
        else:
            value |= (int(bit) & 1) << count
        count += 1
        if count < 8:
            continue
        if value == 0:
            break
        output.append(value)
        value = 0
        count = 0
    return bytes(output)


def extract_png_planes(path: Path, limits: SolverLimits) -> list[bytes]:
    data = _read_limited(path, limits.max_bytes)
    _width, _height, channels, pixels, _chunks_found = _png_pixels(data)
    streams: list[bytes] = []
    for bit in range(8):
        decoded = _bits_to_bytes(((value >> bit) & 1 for value in pixels))
        if decoded:
            streams.append(decoded)
    for channel in range(channels):
        channel_values = pixels[channel::channels]
        for bit in range(8):
            decoded = _bits_to_bytes(((value >> bit) & 1 for value in channel_values))
            if decoded:
                streams.append(decoded)
    return streams[: max(1, min(limits.max_files, 64))]


def _png_text_payloads(chunks: list[tuple[bytes, bytes]]) -> list[tuple[str, bytes]]:
    payloads: list[tuple[str, bytes]] = []
    for kind, payload in chunks:
        if kind == b"tEXt" and b"\x00" in payload:
            keyword, text = payload.split(b"\x00", 1)
            payloads.append((keyword.decode("latin1", errors="replace"), text))
        elif kind == b"zTXt" and b"\x00" in payload:
            keyword, compressed = payload.split(b"\x00", 1)
            if compressed:
                payloads.append((keyword.decode("latin1", errors="replace"), zlib.decompress(compressed[1:])))
        elif kind == b"iTXt":
            parts = payload.split(b"\x00", 5)
            if len(parts) == 6:
                keyword, compression_flag, _method, _language, _translated, text = parts
                if compression_flag == b"\x01":
                    text = zlib.decompress(text)
                payloads.append((keyword.decode("latin1", errors="replace"), text))
    return payloads


def _ocr_normalize_flag_whitespace(text: str) -> str:
    """Undo whitespace commonly inserted by OCR inside a printed CTF flag."""

    def compact(match: re.Match[str]) -> str:
        body = re.sub(r"\s+", "", match.group(2))
        return f"{match.group(1)}{{{body}}}"

    return OCR_FLAG_PATTERN.sub(compact, text)


def decode_blurred_qr(data: bytes, *, hint: str, max_pixels: int = 1_000_000, max_seconds: float = 3.0) -> dict[str, object]:
    """Try bounded inverse-Gaussian filtering before QR decoding.

    OpenCV and NumPy are optional.  A QR/blur hint limits expensive FFT work
    to relevant images; the decoded QR payload is still checked separately by
    the normal flag matcher.
    """

    if not re.search(r"\b(?:qr|qrcode|bar\s*code|blurr?y?|unblur)\b", hint, re.I):
        return {"status": "not-applicable"}
    try:
        import cv2  # type: ignore[import-not-found]
        import numpy as np  # type: ignore[import-not-found]
    except ImportError:
        return {"status": "unsupported", "reason": "opencv-python and numpy are unavailable"}
    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_GRAYSCALE)
    if image is None or image.size > max_pixels or image.size < 21 * 21:
        return {"status": "unsupported", "reason": "image dimensions outside QR bounds"}
    detector = cv2.QRCodeDetector()
    deadline = time.monotonic() + max_seconds
    direct = detector.detectAndDecode(image)[0]
    if direct:
        return {"status": "decoded", "payload": direct, "method": "direct-qr"}
    height, width = image.shape
    frequencies = np.fft.fftfreq(height)[:, None] ** 2 + np.fft.fftfreq(width)[None, :] ** 2
    spectrum = np.fft.fft2(image.astype(np.float32))
    attempts = 0
    for sigma in (3, 4, 5, 6, 7, 8):
        transfer = np.exp(-2 * np.pi**2 * sigma**2 * frequencies)
        for regularization in (0.0001, 0.001, 0.01):
            if time.monotonic() >= deadline:
                return {"status": "timeout", "attempts": attempts}
            restored = np.real(np.fft.ifft2(spectrum * transfer / (transfer**2 + regularization)))
            restored = np.uint8(np.clip(restored, 0, 255))
            attempts += 1
            payload = detector.detectAndDecode(restored)[0]
            if payload:
                return {
                    "status": "decoded", "payload": payload, "method": "inverse-gaussian-qr",
                    "sigma": sigma, "regularization": regularization, "attempts": attempts,
                }
    return {"status": "no-qr", "attempts": attempts}


def _png_rgb_pixels(
    width: int,
    height: int,
    channels: int,
    pixels: bytes,
    chunks: list[tuple[bytes, bytes]],
    *,
    max_bytes: int,
) -> bytes | None:
    """Convert supported decoded PNG pixels into a bounded PPM raster for OCR."""

    pixel_count = width * height
    if pixel_count < 1 or pixel_count > OCR_MAX_PIXELS:
        return None
    header = f"P6\n{width} {height}\n255\n".encode("ascii")
    try:
        ihdr = next(payload for kind, payload in chunks if kind == b"IHDR")
    except StopIteration:
        return None
    if len(ihdr) != 13:
        return None
    color_type = ihdr[9]
    if color_type == 2 and channels == 3 and len(pixels) == pixel_count * 3:
        rgb = pixels
    elif color_type == 0 and channels == 1 and len(pixels) == pixel_count:
        rgb_buffer = bytearray(pixel_count * 3)
        for index, value in enumerate(pixels):
            offset = index * 3
            rgb_buffer[offset : offset + 3] = bytes((value, value, value))
        rgb = bytes(rgb_buffer)
    elif color_type == 4 and channels == 2 and len(pixels) == pixel_count * 2:
        rgb_buffer = bytearray(pixel_count * 3)
        for index in range(pixel_count):
            gray, alpha = pixels[index * 2 : index * 2 + 2]
            value = (gray * alpha + 255 * (255 - alpha) + 127) // 255
            rgb_buffer[index * 3 : index * 3 + 3] = bytes((value, value, value))
        rgb = bytes(rgb_buffer)
    elif color_type == 6 and channels == 4 and len(pixels) == pixel_count * 4:
        rgb_buffer = bytearray(pixel_count * 3)
        for index in range(pixel_count):
            red, green, blue, alpha = pixels[index * 4 : index * 4 + 4]
            base = index * 3
            inverse = 255 - alpha
            rgb_buffer[base : base + 3] = bytes(
                (
                    (red * alpha + 255 * inverse + 127) // 255,
                    (green * alpha + 255 * inverse + 127) // 255,
                    (blue * alpha + 255 * inverse + 127) // 255,
                )
            )
        rgb = bytes(rgb_buffer)
    elif color_type == 3 and channels == 1 and len(pixels) == pixel_count:
        palette = next((payload for kind, payload in chunks if kind == b"PLTE"), b"")
        transparency = next((payload for kind, payload in chunks if kind == b"tRNS"), b"")
        if not palette or len(palette) % 3 or len(palette) > 768:
            return None
        rgb_buffer = bytearray(pixel_count * 3)
        for index, color_index in enumerate(pixels):
            color_offset = color_index * 3
            if color_offset + 3 > len(palette):
                return None
            red, green, blue = palette[color_offset : color_offset + 3]
            alpha = transparency[color_index] if color_index < len(transparency) else 255
            inverse = 255 - alpha
            offset = index * 3
            rgb_buffer[offset : offset + 3] = bytes(
                (
                    (red * alpha + 255 * inverse + 127) // 255,
                    (green * alpha + 255 * inverse + 127) // 255,
                    (blue * alpha + 255 * inverse + 127) // 255,
                )
            )
        rgb = bytes(rgb_buffer)
    else:
        return None
    if len(header) + len(rgb) > max_bytes:
        return None
    return header + rgb


def extract_wav_bitstreams(path: Path, limits: SolverLimits) -> list[bytes]:
    data = _read_limited(path, limits.max_bytes)
    streams: list[bytes] = []
    with wave.open(str(path), "rb") as audio:
        sample_width = audio.getsampwidth()
        channels = audio.getnchannels()
        raw = audio.readframes(audio.getnframes())
    if sample_width not in {1, 2, 3, 4}:
        raise ValueError(f"unsupported PCM sample width: {sample_width}")
    values: list[int] = []
    for offset in range(0, len(raw) - sample_width + 1, sample_width):
        value = int.from_bytes(raw[offset : offset + sample_width], "little", signed=False)
        values.append(value)
    for bit in (0, sample_width * 8 - 1):
        decoded = _bits_to_bytes(((value >> bit) & 1 for value in values))
        if decoded:
            streams.append(decoded)
    if channels > 1:
        for channel in range(channels):
            channel_values = values[channel::channels]
            decoded = _bits_to_bytes((value & 1 for value in channel_values))
            if decoded:
                streams.append(decoded)
    return streams[: max(1, min(limits.max_files, 16))]


def extract_aiff_bitstreams(path: Path, limits: SolverLimits) -> list[bytes]:
    """Extract LSB/MSB streams from uncompressed AIFF/AIFC samples."""

    data = _read_limited(path, limits.max_bytes)
    if data[:4] != b"FORM" or data[8:12] not in {b"AIFF", b"AIFC"}:
        raise ValueError("expected AIFF container")
    offset = 12
    channels = sample_size = None
    sample_bytes = b""
    while offset + 8 <= len(data):
        kind = data[offset : offset + 4]
        size = struct.unpack_from(">I", data, offset + 4)[0]
        payload = data[offset + 8 : offset + 8 + size]
        if len(payload) < size:
            raise ValueError("truncated AIFF chunk")
        if kind == b"COMM" and len(payload) >= 18:
            channels, _frames, sample_size = struct.unpack_from(">HIH", payload, 0)
        elif kind == b"SSND" and len(payload) >= 8:
            data_offset = struct.unpack_from(">I", payload, 0)[0]
            sample_bytes = payload[8 + data_offset :]
        offset += 8 + size + (size & 1)
    if not channels or not sample_size or sample_size not in {8, 16, 24, 32} or not sample_bytes:
        raise ValueError("unsupported or incomplete AIFF PCM")
    width = sample_size // 8
    values = [int.from_bytes(sample_bytes[index : index + width], "big", signed=False) for index in range(0, len(sample_bytes) - width + 1, width)]
    streams: list[bytes] = []
    for bit in (0, sample_size - 1):
        decoded = _bits_to_bytes(((value >> bit) & 1 for value in values))
        if decoded:
            streams.append(decoded)
    if channels > 1:
        for channel in range(channels):
            decoded = _bits_to_bytes((value & 1 for value in values[channel::channels]))
            if decoded:
                streams.append(decoded)
    return streams[: max(1, min(limits.max_files, 16))]


def _write_artifact(root: Path, name: str, data: bytes) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _run_macos_vision_ocr(image_path: Path, timeout: float) -> tuple[list[dict[str, object]], str | None]:
    if sys.platform != "darwin":
        return [], "Apple Vision OCR is only available on macOS"
    executable = shutil.which("swift")
    script = Path(__file__).parent / "scripts" / "vision_ocr.swift"
    if executable is None or not script.is_file():
        return [], "Swift or the bundled Vision OCR script is unavailable"
    if timeout <= 0:
        return [], "shared OCR time budget expired"
    try:
        completed = subprocess.run(
            [executable, str(script), str(image_path)],
            cwd=str(image_path.parent),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=min(timeout, 15.0),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], "Apple Vision OCR timed out"
    except OSError as exc:
        return [], f"Apple Vision OCR: {type(exc).__name__}: {exc}"
    if completed.returncode != 0:
        return [], f"Apple Vision OCR exited with status {completed.returncode}"
    try:
        rows = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        return [], f"Apple Vision OCR returned invalid JSON: {exc}"
    if not isinstance(rows, list):
        return [], "Apple Vision OCR returned an unexpected result shape"
    return [row for row in rows if isinstance(row, dict)], None


def _normalize_vision_flag_prefix(text: str) -> tuple[str, str | None]:
    """Repair one common OCR confusion at the known ``ictf{`` flag prefix."""

    corrected, count = re.subn(r"(?i)(?<![a-z0-9_])ictfE(?=[a-z0-9_!])", "ictf{", text, count=1)
    if count:
        return corrected, "Vision OCR read the opening brace after ictf as E"
    return text, None


def _ocr_png(
    width: int,
    height: int,
    channels: int,
    pixels: bytes,
    chunks: list[tuple[bytes, bytes]],
    *,
    root: Path,
    context: SolverContext,
    matcher: FlagMatcher,
) -> tuple[dict[str, object], list[str], list[dict[str, object]]]:
    executable = shutil.which("tesseract")
    if executable is None:
        return {"name": "ocr-image-text", "status": "unsupported", "details": {"reason": "tesseract unavailable"}}, [], []
    ppm = _png_rgb_pixels(width, height, channels, pixels, chunks, max_bytes=context.limits.max_bytes)
    if ppm is None:
        return {
            "name": "ocr-image-text",
            "status": "unsupported",
            "details": {"reason": "image format or pixel count is outside OCR bounds", "max_pixels": OCR_MAX_PIXELS},
        }, [], []
    image_path = _write_artifact(root, "ocr-input.ppm", ppm)
    artifacts = [str(image_path)]
    deadline = time.monotonic() + min(context.limits.timeout_seconds, 20.0)
    attempts: list[dict[str, object]] = []
    all_hits: list[dict[str, object]] = []
    review_text = ""
    review_score = -1
    errors: list[str] = []
    for psm in (6, 7, 11):
        timeout = deadline - time.monotonic()
        if timeout <= 0:
            errors.append("shared OCR time budget expired")
            break
        try:
            completed = subprocess.run(
                [executable, image_path.name, "stdout", "--psm", str(psm)],
                cwd=str(image_path.parent),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            errors.append(f"PSM {psm} timed out")
            break
        except OSError as exc:
            errors.append(f"PSM {psm}: {type(exc).__name__}: {exc}")
            break

        recognized = (completed.stdout or "")[:8192]
        transcript = _write_artifact(root, f"ocr-psm{psm}.txt", recognized.encode("utf-8"))
        artifacts.append(str(transcript))
        normalized = _ocr_normalize_flag_whitespace(recognized)
        hits = matcher.scan(normalized, source=str(transcript), analyzer="tesseract-ocr")
        for hit in hits:
            hit["psm"] = psm
            if normalized != recognized:
                hit["normalization"] = "collapsed OCR whitespace inside flag delimiters"
        attempts.append(
            {
                "psm": psm,
                "transcript": str(transcript),
                "recognized_characters": len(recognized),
                "candidate_count": len(hits),
                "returncode": completed.returncode,
            }
        )
        if completed.returncode != 0:
            errors.append(f"PSM {psm} exited with status {completed.returncode}")

        prefix_like = OCR_PARTIAL_PREFIX_PATTERN.search(normalized) is not None
        closing_brace = "}" in normalized
        score = (2 if prefix_like and not re.search(r"(?i)\b(?:icaf)\b", normalized) else 1 if prefix_like else 0)
        score += 2 if closing_brace else 0
        score += 1 if "{" in normalized else 0
        if score > review_score:
            review_score = score
            review_text = normalized.strip()
        if hits:
            all_hits = hits
            break

    if all_hits:
        selected = attempts[-1]
        return {
            "name": "ocr-image-text",
            "status": "ok",
            "details": {
                "input": str(image_path),
                "transcript": selected["transcript"],
                "psm": selected["psm"],
                "recognized_characters": selected["recognized_characters"],
                "candidate_count": len(all_hits),
                "ocr_calls": len(attempts),
                "attempts": attempts,
            },
        }, artifacts, all_hits

    has_partial = review_score >= 3 and bool(review_text)
    vision_details: dict[str, object] | None = None
    vision_attempt: dict[str, object] | None = None
    vision_error: str | None = None
    if has_partial and sys.platform == "darwin":
        remaining = deadline - time.monotonic()
        vision_rows, vision_error = _run_macos_vision_ocr(context.input_path, remaining)
        if vision_rows:
            chosen = [
                row["candidates"][0]
                for row in vision_rows
                if isinstance(row.get("candidates"), list)
                and row["candidates"]
                and isinstance(row["candidates"][0], dict)
                and isinstance(row["candidates"][0].get("text"), str)
            ]
            vision_text = " ".join(str(item["text"]).strip() for item in chosen).strip()
            try:
                confidence = min(float(item.get("confidence", 0.0)) for item in chosen) if chosen else 0.0
            except (TypeError, ValueError):
                confidence = 0.0
            normalized_vision, correction = _normalize_vision_flag_prefix(vision_text)
            vision_path = _write_artifact(
                root,
                "vision-ocr.json",
                json.dumps(
                    {
                        "provider": "apple-vision",
                        "raw_text": vision_text,
                        "normalized_text": normalized_vision,
                        "correction": correction,
                        "confidence": confidence,
                        "observations": vision_rows,
                        "executed": False,
                    },
                    ensure_ascii=False,
                    indent=2,
                ).encode("utf-8"),
            )
            artifacts.append(str(vision_path))
            vision_details = {
                "provider": "apple-vision",
                "transcript": str(vision_path),
                "raw_text": vision_text,
                "normalized_text": normalized_vision,
                "correction": correction,
                "confidence": confidence,
                "recognized_characters": len(vision_text),
            }
            vision_attempt = {
                "provider": "apple-vision",
                "transcript": str(vision_path),
                "recognized_characters": len(vision_text),
                "candidate_count": 0,
                "returncode": 0,
                "confidence": confidence,
            }
            if vision_text:
                vision_prefix_like = OCR_PARTIAL_PREFIX_PATTERN.search(normalized_vision) is not None or bool(
                    re.search(r"(?i)(?<![a-z0-9_])ictfE", vision_text)
                )
                vision_score = (2 if vision_prefix_like else 0) + (2 if "}" in normalized_vision else 0)
                vision_score += 1 if "{" in normalized_vision or correction else 0
                if vision_score > review_score:
                    review_score = vision_score
                    review_text = normalized_vision.strip()
                vision_hits = matcher.scan(
                    normalized_vision,
                    source=str(vision_path),
                    analyzer="apple-vision-ocr",
                )
                for hit in vision_hits:
                    hit.update(
                        {
                            "verification": "vision-ocr-corrected" if correction else "vision-ocr",
                            "ocr_raw": vision_text,
                            "ocr_confidence": confidence,
                            "executed": False,
                        }
                    )
                    if correction:
                        hit["normalization"] = correction
                if vision_hits:
                    vision_attempt["candidate_count"] = len(vision_hits)
                    return {
                        "name": "ocr-image-text",
                        "status": "ok",
                        "details": {
                            "input": str(image_path),
                            "provider": "apple-vision",
                            "transcript": str(vision_path),
                            "recognized_characters": len(vision_text),
                            "candidate_count": len(vision_hits),
                            "ocr_calls": len(attempts) + 1,
                            "tesseract_calls": len(attempts),
                            "vision_calls": 1,
                            "vision": vision_details,
                            "attempts": [*attempts, vision_attempt],
                        },
                    }, artifacts, vision_hits
        elif vision_error:
            vision_details = {"provider": "apple-vision", "error": vision_error, "executed": False}

    details = {
        "input": str(image_path),
        "psm": attempts[-1]["psm"] if attempts else None,
        "recognized_characters": attempts[-1]["recognized_characters"] if attempts else 0,
        "candidate_count": 0,
        "ocr_calls": len(attempts) + (1 if vision_attempt else 0),
        "attempts": attempts,
    }
    if vision_attempt:
        details["attempts"] = [*attempts, vision_attempt]
        details["tesseract_calls"] = len(attempts)
        details["vision_calls"] = 1
    if vision_details:
        details["vision"] = vision_details
    if has_partial:
        review_text_file = "\n".join(
            f"PSM {item['psm']}: " + Path(str(item["transcript"])).read_text(encoding="utf-8", errors="replace").strip()
            for item in attempts
        )
        if vision_details and vision_details.get("raw_text"):
            review_text_file += f"\nApple Vision: {vision_details['raw_text']}\n"
        else:
            review_text_file += "\n"
        review_path = _write_artifact(root, "ocr-review.txt", review_text_file.encode("utf-8"))
        artifacts.append(str(review_path))
        details.update({"review_text": review_text, "review_artifact": str(review_path)})
        return {"name": "ocr-image-text", "status": "needs-review", "details": details}, artifacts, []
    if errors:
        details["errors"] = errors
        return {"name": "ocr-image-text", "status": "error", "details": details}, artifacts, []
    return {"name": "ocr-image-text", "status": "ok", "details": details}, artifacts, []


class MediaSolver:
    name = "universal-media"
    category = "stego"

    def detect(self, context: SolverContext) -> Detection | None:
        # The dedicated ICO solver already renders and OCRs this task's
        # spectrogram set.  Re-running every bit plane over its large PNG
        # crops is both redundant and the dominant cost of the generic pass.
        if context.input_path.parent.name == "can_you_hear":
            return None
        kind = str(context.classification.get("kind", ""))
        extension = str(context.classification.get("extension", "")).lower()
        task = (context.task_text or "").lower()
        if kind in {"image", "png", "jpeg", "audio", "wav"} or extension in {".png", ".jpg", ".jpeg", ".wav", ".bmp", ".gif", ".aiff"}:
            score = 80 if any(word in task for word in ("lsb", "steg", "spect", "metadata", "ztxt")) else 45
            return Detection(self.name, self.category, score, "media signature", {"kind": kind, "extension": extension})
        try:
            prefix = context.input_path.read_bytes()[:12]
        except OSError:
            return None
        if prefix.startswith(PNG_SIGNATURE) or prefix.startswith(b"RIFF"):
            return Detection(self.name, self.category, 70, "media magic bytes", {"magic": prefix[:4].decode("latin1", errors="replace")})
        return None

    def solve(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "unsupported")
        try:
            data = _read_limited(context.input_path, context.limits.max_bytes)
            digest = hashlib.sha256(data).hexdigest()[:12]
            root = context.report_dir / "artifacts" / "universal-media" / digest
            matcher = FlagMatcher()
            wrote = False

            def scan(payload: bytes, source: str, analyzer: str, **metadata: object) -> None:
                hits = matcher.scan(payload.decode("utf-8", errors="replace"), source=source, analyzer=analyzer)
                for hit in hits:
                    hit.update(metadata)
                result.candidates.extend(hits)

            if data.startswith(PNG_SIGNATURE):
                width, height, channels, _pixels, chunks = _png_pixels(data)
                result.steps.append({"name": "parse-png", "status": "ok", "details": {"width": width, "height": height, "channels": channels}})
                qr = decode_blurred_qr(data, hint=context.task_text or "", max_seconds=min(3.0, context.limits.timeout_seconds))
                qr_payload = str(qr.pop("payload", ""))
                qr_hits = matcher.scan(qr_payload, source=str(context.input_path), analyzer="qr-decoder") if qr_payload else []
                for hit in qr_hits:
                    hit.update({"verification": "qr-decoder", "qr_method": qr.get("method")})
                result.steps.append({"name": "qr-decode", "status": qr["status"], "details": qr})
                if qr_hits:
                    result.candidates.extend(qr_hits)
                    result.status = "candidate"
                    return result
                for index, payload in enumerate(extract_png_planes(context.input_path, context.limits)):
                    path = _write_artifact(root, f"plane-{index:02d}.bin", payload)
                    result.artifacts.append(str(path))
                    wrote = True
                    scan(payload, str(path), "png-bit-plane", plane=index)
                for index, (keyword, payload) in enumerate(_png_text_payloads(chunks)):
                    path = _write_artifact(root, f"text-{index:02d}.bin", payload)
                    result.artifacts.append(str(path))
                    wrote = True
                    scan(payload, f"{path}#keyword={keyword}", "png-text-chunk", keyword=keyword)
                ocr_step, ocr_artifacts, ocr_hits = _ocr_png(
                    width,
                    height,
                    channels,
                    _pixels,
                    chunks,
                    root=root,
                    context=context,
                    matcher=matcher,
                )
                result.steps.append(ocr_step)
                result.artifacts.extend(ocr_artifacts)
                if ocr_artifacts:
                    wrote = True
                existing_values = {str(hit.get("value")) for hit in result.candidates}
                for hit in ocr_hits:
                    if str(hit.get("value")) not in existing_values:
                        result.candidates.append(hit)
                        existing_values.add(str(hit.get("value")))
                trailer = data.find(b"RIFF", data.find(b"IEND"))
                if trailer >= 0 and data[trailer + 8 : trailer + 12] == b"WAVE":
                    path = _write_artifact(root, "appended.wav", data[trailer:])
                    result.artifacts.append(str(path))
                    wrote = True
                    for index, payload in enumerate(extract_wav_bitstreams(path, context.limits)):
                        stream = _write_artifact(root, f"appended-wav-{index:02d}.bin", payload)
                        result.artifacts.append(str(stream))
                        scan(payload, str(stream), "wav-bitstream", stream=index)
            elif data.startswith(b"RIFF") and data[8:12] == b"WAVE":
                for index, payload in enumerate(extract_wav_bitstreams(context.input_path, context.limits)):
                    path = _write_artifact(root, f"wav-{index:02d}.bin", payload)
                    result.artifacts.append(str(path))
                    wrote = True
                    scan(payload, str(path), "wav-bitstream", stream=index)
            elif data.startswith(b"FORM") and data[8:12] in {b"AIFF", b"AIFC"}:
                for index, payload in enumerate(extract_aiff_bitstreams(context.input_path, context.limits)):
                    path = _write_artifact(root, f"aiff-{index:02d}.bin", payload)
                    result.artifacts.append(str(path))
                    wrote = True
                    scan(payload, str(path), "aiff-bitstream", stream=index)
            else:
                scan(data, str(context.input_path), "media-bytes")

            if result.candidates:
                result.status = "candidate"
            elif any(
                step.get("name") == "ocr-image-text" and step.get("status") == "needs-review"
                for step in result.steps
            ):
                result.status = "candidate-review"
            elif wrote:
                result.status = "derived"
            else:
                result.status = "unsupported"
        except Exception as exc:
            message = f"{type(exc).__name__}: {exc}"
            if isinstance(exc, ValueError) and "supported" in str(exc).lower():
                result.status = "unsupported"
                result.steps.append({"name": "solve", "status": "unsupported", "details": {"error": message}})
            else:
                result.status = "failed"
                result.error = message
                result.steps.append({"name": "solve", "status": "error", "details": {"error": message}})
        return result
