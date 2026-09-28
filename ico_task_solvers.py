#!/usr/bin/env python3
"""Deterministic, offline solvers for the supplied ICO CTF file pack."""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import json
import lzma
import os
import re
import sqlite3
import struct
import tarfile
import wave
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from ico_scan_core import single_byte_xor_views


MAX_SOLVER_BYTES = 100 * 1024 * 1024
MAX_SOLVER_FILES = 200
MAX_SOLVER_DEPTH = 8
FLAG_RE = re.compile(r"(?i)(?:ico|ctf|flag)\{[^{}\r\n]{1,256}\}")
BASE64_RE = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/])")


@dataclass
class TaskResult:
    task_id: str
    task_dir: Path
    solver: str
    status: str = "failed"
    steps: list[dict[str, Any]] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    error: str | None = None
    derived_inputs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["task_dir"] = str(self.task_dir)
        return value


def _task_id(task_dir: Path) -> str:
    match = re.match(r"(\d+)", task_dir.name)
    return match.group(1).lstrip("0") or "0" if match else task_dir.name


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def verify_flag(value: str, expected_hash: str | None) -> dict[str, Any]:
    actual = hashlib.sha256(value.encode("utf-8")).hexdigest()
    status = "hash-verified" if expected_hash and actual.lower() == expected_hash.lower() else "candidate"
    return {
        "status": status,
        "algorithm": "sha256",
        "expected": expected_hash,
        "actual": actual,
    }


def _is_ignored_dir(path: Path) -> bool:
    return path.name.startswith(".") or path.name in {"ico-scan-runs", "commands", "artifacts", "__pycache__"}


_TASK_CATEGORY_LABELS = {
    "crypto": "Crypto",
    "cryptography": "Crypto",
    "forensic": "Forensics",
    "forensics": "Forensics",
    "pwn": "Pwn",
    "pwnable": "Pwn",
    "pwnables": "Pwn",
    "rev": "Reversing",
    "reverse": "Reversing",
    "reversing": "Reversing",
    "web": "Web",
    "misc": "Misc",
    "osint": "OSINT",
    "mobile": "Mobile",
    "hardware": "Hardware",
    "blockchain": "Blockchain",
    "stego": "Steganography",
    "network": "Networking",
    "networking": "Networking",
    "jail": "Jail",
    "ai": "AI",
}


def task_category_label(task_dir: Path) -> str:
    """Return a normalized category when a task follows a CTF archive layout."""

    return _TASK_CATEGORY_LABELS.get(task_dir.parent.name.strip().lower(), "")


def task_manifest_path(task_dir: Path) -> Path | None:
    """Find a supported statement file, including README manifests by category path."""

    for name in ("task.txt", "task.md", "challenge.md"):
        candidate = task_dir / name
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    readme = task_dir / "README.md"
    if readme.is_file() and not readme.is_symlink() and task_category_label(task_dir):
        return readme
    return None


def discover_task_dirs(inputs: Sequence[str]) -> list[Path]:
    found: set[Path] = set()
    for raw in inputs:
        candidate = Path(raw).expanduser()
        try:
            path = candidate.resolve()
        except OSError:
            continue
        if path.is_file():
            # A single artifact is scoped to its immediate task directory.
            # Walking the whole parent tree would unexpectedly pick up
            # unrelated packs when the caller passes e.g. Downloads/foo.bin.
            parent = path.parent
            if task_manifest_path(parent) is not None and not _is_ignored_dir(parent):
                found.add(parent.resolve())
            continue
        if not path.is_dir():
            continue
        if task_manifest_path(path) is not None and not _is_ignored_dir(path):
            found.add(path)
            continue
        for current, directories, _files in os.walk(path, followlinks=False):
            current_path = Path(current)
            if _is_ignored_dir(current_path) and current_path != path:
                directories[:] = []
                continue
            directories[:] = [name for name in directories if not _is_ignored_dir(current_path / name)]
            if task_manifest_path(current_path) is not None and not _is_ignored_dir(current_path):
                found.add(current_path.resolve())
                directories[:] = []
    return sorted(found)


def extract_task_pack(archive_path: Path, destination: Path) -> Path | None:
    """Safely materialize a ZIP that contains one or more ``task.txt`` files.

    This keeps the task-aware path usable when the user supplies only the
    downloaded pack archive. Ordinary ZIPs return ``None`` and remain handled
    by the generic archive scanner. Members are bounded and path-checked; no
    extracted file is executed.
    """

    archive_path = archive_path.expanduser().resolve()
    if archive_path.suffix.lower() not in {".zip", ".pk3"} or not archive_path.is_file():
        return None
    with zipfile.ZipFile(archive_path) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if not any(Path(info.filename).name == "task.txt" for info in infos):
            return None
        if len(infos) > MAX_SOLVER_FILES:
            raise ValueError("task-pack file-count limit exceeded")
        total = 0
        destination = destination.expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)
        for info in infos:
            name = _safe_member_name(info.filename)
            if not name:
                raise ValueError(f"unsafe task-pack member: {info.filename!r}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and (mode & 0o170000) == 0o120000:
                raise ValueError(f"symlink task-pack member refused: {info.filename!r}")
            total += info.file_size
            if total > MAX_SOLVER_BYTES:
                raise ValueError("task-pack byte limit exceeded")
            target = (destination / name).resolve()
            target.relative_to(destination)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(info))
    return destination


def select_solver(task_text: str, artifact: Path) -> str | None:
    text = task_text.lower()
    # Specific phrases must precede generic XOR/archive words.
    if "ztxt" in text or "compressed textual metadata" in text:
        return "png-ztext"
    if "lsb rgb" in text or "rgb-канал" in text:
        return "png-lsb-rgb"
    if "dns" in text and "base32" in text:
        return "pcap-dns-base32"
    if "pcap" in text or "authorization: bearer" in text:
        return "pcap-http-bearer"
    if "sqlite" in text or "cache_entries" in text:
        return "sqlite-cache-hex"
    if "linux elf" in text or "strcmp" in text or "xor-цик" in text:
        return "reverse-elf"
    if "backup.zip" in text or "layers" in text or "каждый новый файл" in text:
        return "archive-layers"
    if "повреждены первые 4 байта" in text or "magic header" in text:
        return "repair-header"
    if "16-bit pcm" in text or "последовательных 16-bit" in text:
        return "wav-lsb"
    if "расширение врёт" in text or "magic bytes" in text:
        return "magic-bytes"
    if "single-byte xor" in text or "ключ 0..255" in text:
        return "xor-single-byte"
    suffix = artifact.suffix.lower()
    return {
        ".pcap": "pcap-http-bearer",
        ".db": "sqlite-cache-hex",
        ".wav": "wav-lsb",
    }.get(suffix)


def _step(result: TaskResult, name: str, status: str = "ok", **details: Any) -> None:
    result.steps.append({"name": name, "status": status, "details": _jsonable(details)})


def _write_artifact(result: TaskResult, output_dir: Path, name: str, data: bytes) -> Path:
    root = (output_dir / "artifacts" / result.task_id).resolve()
    root.mkdir(parents=True, exist_ok=True)
    path = (root / name).resolve()
    path.relative_to(root)
    path.write_bytes(data)
    result.artifacts.append(str(path))
    result.derived_inputs.append(str(path))
    return path


def _flag_values(data: bytes | str) -> list[str]:
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    return list(dict.fromkeys(match.group(0) for match in FLAG_RE.finditer(text)))


def _add_candidates(result: TaskResult, values: Iterable[str], expected_hash: str | None, **metadata: Any) -> None:
    for value in values:
        verification = verify_flag(value, expected_hash)
        result.candidates.append(
            {
                "value": value,
                "state": verification["status"],
                "verification": verification,
                **_jsonable(metadata),
            }
        )
    if any(item["state"] == "hash-verified" for item in result.candidates):
        result.status = "hash-verified"
    elif result.candidates:
        result.status = "candidate"


def _finish(result: TaskResult) -> TaskResult:
    if result.error:
        result.status = "failed"
    elif not result.candidates and result.status == "failed":
        result.status = "no-candidate"
    return result


def _safe_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _read_limited(path: Path, limit: int = MAX_SOLVER_BYTES) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds solver byte limit: {size} > {limit}")
    return path.read_bytes()


def _decode_b64_candidates(data: bytes) -> list[tuple[str, bytes]]:
    results: list[tuple[str, bytes]] = []
    for match in BASE64_RE.finditer(data):
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        results.append((token.decode("ascii"), decoded))
    return results


def _preferred_artifact(task_dir: Path, solver: str) -> Path:
    preferred = {
        "xor-single-byte": ["evidence.bin"],
        "magic-bytes": ["holiday_photo.jpg", "output"],
        "png-lsb-rgb": ["noise.png"],
        "pcap-http-bearer": ["traffic.pcap"],
        "sqlite-cache-hex": ["browser_cache.db"],
        "reverse-elf": ["chall"],
        "archive-layers": ["backup.zip"],
        "repair-header": ["broken.bin"],
        "wav-lsb": ["recording.wav"],
        "png-ztext": ["evidence.png"],
    }
    for name in preferred.get(solver, []):
        path = task_dir / name
        if path.is_file():
            return path
    files = [
        path
        for path in sorted(task_dir.rglob("*"))
        if path.is_file()
        and path.name != "task.txt"
        and not path.name.startswith(".")
        and not any(part in {"ico-scan-runs", "commands", "artifacts", "__pycache__"} for part in path.relative_to(task_dir).parts)
    ]
    if not files:
        raise FileNotFoundError(f"no challenge artifact in {task_dir}")
    return files[0]


def _new_result(task_dir: Path, solver: str) -> TaskResult:
    return TaskResult(task_id=_task_id(task_dir), task_dir=task_dir, solver=solver)


def solve_xor(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "xor-single-byte")
    try:
        data = _read_limited(path)
        views = single_byte_xor_views(data, prefix=b"CTF{")
        _step(result, "read-bytes", bytes=len(data))
        for view in views:
            decoded_path = _write_artifact(result, output_dir, "xor-key-%02x.bin" % view["key"], view["plaintext"])
            values = _flag_values(view["plaintext"])
            _add_candidates(
                result,
                values,
                expected_hash,
                key=view["key"],
                offset=view["offset"],
                crib=view["prefix"].decode("ascii", errors="replace"),
                evidence=str(decoded_path),
            )
            _step(result, "single-byte-xor", key=view["key"], offset=view["offset"], output=str(decoded_path))
        if not views:
            _step(result, "single-byte-xor", "no-match", keys="0..255", crib="CTF{")
    except Exception as exc:  # pragma: no cover - defensive boundary
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    return _finish(result)


def solve_magic_bytes(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "magic-bytes")
    try:
        data = _read_limited(path)
        if not data.startswith(b"\x1f\x8b"):
            raise ValueError("expected gzip magic bytes")
        decompressed = gzip.decompress(data)
        unpacked = _write_artifact(result, output_dir, "gzip-decoded.txt", decompressed)
        _step(result, "identify-format", format="gzip")
        _step(result, "gzip-decompress", output=str(unpacked), bytes=len(decompressed))
        decoded_items = _decode_b64_candidates(decompressed)
        for token, decoded in decoded_items:
            decoded_path = _write_artifact(result, output_dir, "base64-decoded.bin", decoded)
            _add_candidates(result, _flag_values(decoded), expected_hash, encoding="base64", token=token, evidence=str(decoded_path))
            _step(result, "base64-decode", output=str(decoded_path), token_length=len(token))
        if not decoded_items:
            _step(result, "base64-decode", "no-match")
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    return _finish(result)


def _png_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("not a PNG")
    chunks: list[tuple[bytes, bytes]] = []
    offset = 8
    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4 : offset + 8]
        start = offset + 8
        end = start + length
        if end + 4 > len(data):
            raise ValueError("truncated PNG chunk")
        chunks.append((kind, data[start:end]))
        offset = end + 4
        if kind == b"IEND":
            break
    return chunks


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


def _png_rgb_pixels(data: bytes) -> tuple[int, int, bytes]:
    chunks = _png_chunks(data)
    ihdr = next(payload for kind, payload in chunks if kind == b"IHDR")
    width, height, depth, color_type, compression, filtering, interlace = struct.unpack(">IIBBBBB", ihdr)
    if depth != 8 or color_type != 2 or compression != 0 or filtering != 0 or interlace != 0:
        raise ValueError("only non-interlaced 8-bit RGB PNG is supported")
    compressed = b"".join(payload for kind, payload in chunks if kind == b"IDAT")
    raw = zlib.decompress(compressed)
    row_size = width * 3
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
            left = row[index - 3] if index >= 3 else 0
            up = previous[index]
            up_left = previous[index - 3] if index >= 3 else 0
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
    return width, height, b"".join(rows)


def _bits_to_bytes(bits: Iterable[int], *, msb_first: bool = True, stop_at_nul: bool = True) -> bytes:
    values = list(bits)
    output = bytearray()
    for offset in range(0, len(values) - 7, 8):
        group = values[offset : offset + 8]
        value = sum(bit << (7 - index if msb_first else index) for index, bit in enumerate(group))
        if stop_at_nul and value == 0:
            break
        output.append(value)
    return bytes(output)


def solve_png_lsb(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "png-lsb-rgb")
    try:
        width, height, pixels = _png_rgb_pixels(_read_limited(path))
        bits = (value & 1 for value in pixels)
        decoded = _bits_to_bytes(bits, msb_first=True)
        decoded_path = _write_artifact(result, output_dir, "rgb-lsb-msb.txt", decoded)
        _step(result, "decode-png", width=width, height=height, channel_order="RGB")
        _step(result, "read-lsb", bit_order="MSB-first", output=str(decoded_path))
        _add_candidates(result, _flag_values(decoded), expected_hash, channel_order="RGB", bit_order="MSB-first", evidence=str(decoded_path))
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    return _finish(result)


def solve_sqlite(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "sqlite-cache-hex")
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
        rows = connection.execute("SELECT seq, value FROM cache_entries ORDER BY seq").fetchall()
        decoded = b"".join(bytes.fromhex(str(value).strip()) for _seq, value in rows)
        decoded_path = _write_artifact(result, output_dir, "cache-hex-decoded.bin", decoded)
        _step(result, "sqlite-query", query="SELECT seq, value FROM cache_entries ORDER BY seq", rows=len(rows))
        _step(result, "hex-decode", output=str(decoded_path), bytes=len(decoded))
        _add_candidates(result, _flag_values(decoded), expected_hash, encoding="hex", rows=len(rows), evidence=str(decoded_path))
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    finally:
        if connection is not None:
            connection.close()
    return _finish(result)


def solve_wav_lsb(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "wav-lsb")
    try:
        if path.stat().st_size > MAX_SOLVER_BYTES:
            raise ValueError("input exceeds solver byte limit")
        with wave.open(str(path), "rb") as audio:
            if audio.getsampwidth() != 2:
                raise ValueError("expected 16-bit PCM")
            raw = audio.readframes(audio.getnframes())
            samples = struct.unpack("<" + "h" * (len(raw) // 2), raw)
        decoded = _bits_to_bytes((sample & 1 for sample in samples), msb_first=True)
        decoded_path = _write_artifact(result, output_dir, "wav-lsb.txt", decoded)
        _step(result, "read-pcm", samples=len(samples), sample_width=2)
        _step(result, "read-lsb", bit_order="MSB-first", stop_byte="0x00", output=str(decoded_path))
        _add_candidates(result, _flag_values(decoded), expected_hash, bit_order="MSB-first", evidence=str(decoded_path))
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    return _finish(result)


def solve_png_ztext(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "png-ztext")
    try:
        chunks = _png_chunks(_read_limited(path))
        found = False
        for index, (kind, payload) in enumerate(chunks):
            if kind != b"zTXt":
                continue
            found = True
            keyword, compressed = payload.split(b"\x00", 1)
            if not compressed or compressed[0] != 0:
                raise ValueError("unsupported zTXt compression method")
            text = zlib.decompress(compressed[1:])
            raw_path = _write_artifact(result, output_dir, f"ztxt-{index}-text.txt", text)
            _step(result, "read-ztxt", keyword=keyword.decode("latin1"), output=str(raw_path))
            for token, decoded in _decode_b64_candidates(text):
                decoded_path = _write_artifact(result, output_dir, f"ztxt-{index}-decoded.bin", decoded)
                _add_candidates(result, _flag_values(decoded), expected_hash, keyword=keyword.decode("latin1"), encoding="base64", evidence=str(decoded_path))
                _step(result, "base64-decode", token_length=len(token), output=str(decoded_path))
        if not found:
            _step(result, "read-ztxt", "no-match")
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    return _finish(result)


def _pcap_payloads(data: bytes) -> list[tuple[tuple[str, int, str, int], int, bytes]]:
    if len(data) < 24:
        raise ValueError("truncated pcap global header")
    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
    else:
        raise ValueError("unsupported pcap magic")
    network = struct.unpack_from(endian + "I", data, 20)[0]
    if network != 1:
        raise ValueError("only Ethernet pcap is supported")
    streams: list[tuple[tuple[str, int, str, int], int, bytes]] = []
    offset = 24
    while offset + 16 <= len(data):
        _ts_sec, _ts_usec, captured, _original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        packet = data[offset : offset + captured]
        offset += captured
        if len(packet) < 14 or struct.unpack_from(">H", packet, 12)[0] != 0x0800:
            continue
        ip_start = 14
        version_ihl = packet[ip_start]
        if version_ihl >> 4 != 4:
            continue
        ihl = (version_ihl & 0x0F) * 4
        if len(packet) < ip_start + ihl + 20 or packet[ip_start + 9] != 6:
            continue
        source_ip = ".".join(str(value) for value in packet[ip_start + 12 : ip_start + 16])
        target_ip = ".".join(str(value) for value in packet[ip_start + 16 : ip_start + 20])
        tcp = ip_start + ihl
        source_port, target_port, sequence = struct.unpack_from(">HHI", packet, tcp)
        tcp_header = ((packet[tcp + 12] >> 4) & 0x0F) * 4
        payload = packet[tcp + tcp_header :]
        if payload:
            streams.append(((source_ip, source_port, target_ip, target_port), sequence, payload))
    return streams


def _pcap_dns_labels(data: bytes) -> list[list[str]]:
    """Extract DNS question labels from classic Ethernet PCAP packets."""

    if len(data) < 24:
        raise ValueError("truncated pcap global header")
    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        endian = "<"
    elif magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        endian = ">"
    else:
        raise ValueError("unsupported pcap magic")
    if struct.unpack_from(endian + "I", data, 20)[0] != 1:
        raise ValueError("only Ethernet pcap is supported")
    output: list[list[str]] = []
    offset = 24
    while offset + 16 <= len(data) and len(output) < MAX_SOLVER_FILES:
        _seconds, _microseconds, captured, _original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured > MAX_SOLVER_BYTES or offset + captured > len(data):
            raise ValueError("pcap packet exceeds solver bounds")
        frame = data[offset : offset + captured]
        offset += captured
        if len(frame) < 14 + 20 or struct.unpack_from(">H", frame, 12)[0] != 0x0800:
            continue
        ip_offset = 14
        if frame[ip_offset] >> 4 != 4:
            continue
        ihl = (frame[ip_offset] & 0x0F) * 4
        transport = ip_offset + ihl
        if ihl < 20 or len(frame) < transport + 8 or frame[ip_offset + 9] != 17:
            continue
        source_port, target_port, length = struct.unpack_from(">HHH", frame, transport)
        if source_port != 53 and target_port != 53:
            continue
        payload = frame[transport + 8 : transport + max(8, min(length, len(frame) - transport))]
        if len(payload) < 13:
            continue
        cursor = 12
        labels: list[str] = []
        while cursor < len(payload):
            size = payload[cursor]
            cursor += 1
            if size == 0:
                if labels:
                    output.append(labels)
                break
            if size & 0xC0 or cursor + size > len(payload):
                break
            labels.append(payload[cursor : cursor + size].decode("ascii", errors="replace"))
            cursor += size
    return output


def _dns_base32_views(labels: list[str]) -> list[tuple[bytes, dict[str, object]]]:
    alphabet = re.compile(r"[A-Z2-7=]+", re.IGNORECASE)
    views: list[tuple[bytes, dict[str, object]]] = []
    seen: set[bytes] = set()
    start = 0
    while start < len(labels) and len(views) < MAX_SOLVER_FILES:
        if not alphabet.fullmatch(labels[start]) or len(labels[start]) < 2:
            start += 1
            continue
        end = start
        while end < len(labels) and alphabet.fullmatch(labels[end]) and len(labels[end]) >= 2:
            end += 1
        for left in range(start, end):
            for right in range(end, left, -1):
                token = "".join(labels[left:right]).encode("ascii", errors="ignore")
                if len(token) < 8:
                    continue
                try:
                    decoded = base64.b32decode(token + b"=" * (-len(token) % 8), casefold=True)
                except (ValueError, binascii.Error):
                    continue
                if not decoded or decoded in seen:
                    continue
                seen.add(decoded)
                views.append((decoded, {"labels": labels[left:right], "label_start": left, "label_end": right, "encoding": "base32-dns-labels"}))
                if len(views) >= MAX_SOLVER_FILES:
                    break
            if len(views) >= MAX_SOLVER_FILES:
                break
        start = end
    return views


def solve_dns_base32(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "pcap-dns-base32")
    try:
        labels_sets = _pcap_dns_labels(_read_limited(path))
        views = 0
        for packet_index, labels in enumerate(labels_sets):
            for view_index, (decoded, metadata) in enumerate(_dns_base32_views(labels)):
                values = _flag_values(decoded)
                if not values:
                    continue
                evidence = _write_artifact(result, output_dir, f"dns-{packet_index:03d}-{view_index:03d}.bin", decoded)
                _step(result, "decode-dns-base32", packet=packet_index, output=str(evidence), **metadata)
                _add_candidates(result, values, expected_hash, evidence=str(evidence), **metadata)
                views += 1
        if not views:
            _step(result, "decode-dns-base32", "no-match")
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    return _finish(result)


def solve_pcap(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "pcap-http-bearer")
    try:
        streams = _pcap_payloads(_read_limited(path))
        grouped: dict[tuple[str, int, str, int], list[tuple[int, bytes]]] = {}
        for key, sequence, payload in streams:
            grouped.setdefault(key, []).append((sequence, payload))
        bearer_re = re.compile(rb"authorization:\s*bearer\s+([^\s\r\n]+)", re.IGNORECASE)
        found = False
        for index, (key, pieces) in enumerate(sorted(grouped.items())):
            pieces.sort(key=lambda item: item[0])
            stream = b"".join(payload for _sequence, payload in pieces)
            stream_path = _write_artifact(result, output_dir, f"tcp-stream-{index}.bin", stream)
            _step(result, "reassemble-tcp", stream=key, segments=len(pieces), output=str(stream_path))
            match = bearer_re.search(stream)
            if not match:
                continue
            found = True
            token = match.group(1)
            try:
                decoded = base64.b64decode(token + b"=" * (-len(token) % 4), validate=True)
            except binascii.Error as exc:
                raise ValueError(f"invalid bearer base64: {exc}") from exc
            decoded_path = _write_artifact(result, output_dir, f"bearer-{index}.txt", decoded)
            _step(result, "extract-bearer", stream=key, output=str(decoded_path))
            _add_candidates(result, _flag_values(decoded), expected_hash, encoding="base64", stream=key, evidence=str(decoded_path))
        if not found:
            _step(result, "extract-bearer", "no-match")
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    return _finish(result)


def _safe_member_name(name: str) -> str | None:
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        return None
    clean = "/".join(part for part in path.parts if part not in {"", "."})
    return clean or None


def _archive_children(data: bytes) -> list[tuple[str, bytes]]:
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):
        children: list[tuple[str, bytes]] = []
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_SOLVER_FILES:
                raise ValueError("archive file-count limit exceeded")
            total = 0
            for info in infos:
                name = _safe_member_name(info.filename)
                if not name or info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0xFFFF
                if mode and (mode & 0o170000) == 0o120000:
                    continue
                total += info.file_size
                if total > MAX_SOLVER_BYTES:
                    raise ValueError("archive byte limit exceeded")
                children.append((name, archive.read(info)))
        return children
    if data.startswith(b"\xfd7zXZ\x00"):
        return [("decompressed.xz", lzma.decompress(data))]
    if data.startswith(b"\x1f\x8b"):
        return [("decompressed.gz", gzip.decompress(data))]
    if len(data) >= 512 and data[257:262] == b"ustar":
        children = []
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) > MAX_SOLVER_FILES:
                raise ValueError("archive file-count limit exceeded")
            total = 0
            for member in members:
                name = _safe_member_name(member.name)
                if not name or not member.isfile():
                    continue
                total += member.size
                if total > MAX_SOLVER_BYTES:
                    raise ValueError("archive byte limit exceeded")
                extracted = archive.extractfile(member)
                if extracted is not None:
                    children.append((name, extracted.read(MAX_SOLVER_BYTES + 1)))
        return children
    return []


def solve_archive_layers(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "archive-layers")
    try:
        current = _read_limited(path)
        current_name = path.name
        for depth in range(MAX_SOLVER_DEPTH):
            if len(current) > MAX_SOLVER_BYTES:
                raise ValueError("solver byte limit exceeded")
            children = _archive_children(current)
            if children:
                name, current = children[0]
                current_name = name
                output = _write_artifact(result, output_dir, f"layer-{depth}-{Path(name).name}", current)
                _step(result, "extract-layer", depth=depth, member=name, output=str(output), siblings=len(children))
                continue
            if current.startswith(b"CTF{") or b"CTF{" in current:
                _add_candidates(result, _flag_values(current), expected_hash, evidence=current_name)
                break
            views = single_byte_xor_views(current, prefix=b"CTF{")
            if views:
                view = views[0]
                output = _write_artifact(result, output_dir, f"layer-{depth}-xor-{view['key']:02x}.bin", view["plaintext"])
                _step(result, "single-byte-xor", depth=depth, key=view["key"], offset=view["offset"], output=str(output))
                _add_candidates(result, _flag_values(view["plaintext"]), expected_hash, key=view["key"], offset=view["offset"], evidence=str(output))
            else:
                _step(result, "inspect-layer", "no-match", depth=depth, member=current_name)
            break
        else:
            raise ValueError("archive depth limit exceeded")
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    return _finish(result)


def solve_repair_header(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "repair-header")
    try:
        data = _read_limited(path)
        if len(data) < 4:
            raise ValueError("input shorter than four-byte header")
        repaired = b"PK\x03\x04" + data[4:]
        repaired_path = _write_artifact(result, output_dir, "repaired.zip", repaired)
        _step(result, "repair-header", original=data[:4], replacement=b"PK\x03\x04", output=str(repaired_path))
        with zipfile.ZipFile(io.BytesIO(repaired)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_SOLVER_FILES:
                raise ValueError("archive file-count limit exceeded")
            for info in infos:
                name = _safe_member_name(info.filename)
                if not name or info.is_dir():
                    continue
                child = archive.read(info)
                child_path = _write_artifact(result, output_dir, Path(name).name, child)
                _step(result, "extract-child", member=name, output=str(child_path))
                for token, decoded in _decode_b64_candidates(child):
                    decoded_path = _write_artifact(result, output_dir, f"{Path(name).stem}-decoded.bin", decoded)
                    _add_candidates(result, _flag_values(decoded), expected_hash, encoding="base64", token=token, evidence=str(decoded_path))
                    _step(result, "base64-decode", output=str(decoded_path))
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    return _finish(result)


def _elf_text(data: bytes) -> tuple[int, bytes]:
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("expected little-endian ELF64")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_entry_size, section_count, names_index = struct.unpack_from("<HHH", data, 58)
    if section_entry_size == 0 or section_offset + section_entry_size * section_count > len(data):
        raise ValueError("invalid ELF section table")
    name_header = section_offset + section_entry_size * names_index
    names_offset, names_size = struct.unpack_from("<QQ", data, name_header + 24)[0:2]
    names = data[names_offset : names_offset + names_size]
    for index in range(section_count):
        header = section_offset + section_entry_size * index
        name_offset = struct.unpack_from("<I", data, header)[0]
        section_name = names[name_offset : names.find(b"\x00", name_offset)]
        if section_name != b".text":
            continue
        address, file_offset, size = struct.unpack_from("<QQQ", data, header + 16)
        return address, data[file_offset : file_offset + size]
    raise ValueError("ELF .text section not found")


def _static_elf_buffers(data: bytes) -> tuple[bytes, bytes, int, int, str]:
    address, text = _elf_text(data)
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    except ImportError as exc:
        raise RuntimeError("capstone is required for static ELF decoding") from exc
    engine = Cs(CS_ARCH_X86, CS_MODE_64)
    engine.detail = True
    registers: dict[str, bytes] = {}
    memory: dict[int, int] = {}
    xor_keys: list[int] = []
    for instruction in engine.disasm(text, address):
        mnemonic = instruction.mnemonic
        operands = instruction.op_str
        if mnemonic in {"mov", "movabs"} and operands.startswith(("rax, 0x", "rdx, 0x")):
            register, literal = operands.split(",", 1)
            registers[register.strip()] = int(literal.strip(), 16).to_bytes(8, "little")
        elif mnemonic == "mov" and operands.startswith("byte ptr [rbp - "):
            match = re.match(r"byte ptr \[rbp - (0x[0-9a-f]+|[0-9]+)\], (0x[0-9a-f]+|[0-9]+)", operands)
            if match:
                memory[-int(match.group(1), 0)] = int(match.group(2), 0) & 0xFF
        elif mnemonic == "mov" and operands.startswith("qword ptr [rbp - "):
            match = re.match(r"qword ptr \[rbp - (0x[0-9a-f]+)\], (rax|rdx)$", operands)
            if match and match.group(2) in registers:
                start = -int(match.group(1), 16)
                for index, value in enumerate(registers[match.group(2)]):
                    memory[start + index] = value
        elif mnemonic == "xor":
            match = re.search(r", (0x[0-9a-f]+)$", operands)
            if match:
                xor_keys.append(int(match.group(1), 16) & 0xFF)
    if len(xor_keys) < 2:
        raise ValueError("could not recover two XOR keys")
    password = bytes(memory[offset] for offset in range(-0x11, -0x11 + 9))
    encrypted_flag = bytes(memory[offset] for offset in range(-0x30, -0x30 + 25))
    return password, encrypted_flag, xor_keys[0], xor_keys[1], "capstone"


def solve_reverse_elf(path: Path, output_dir: Path, expected_hash: str | None) -> TaskResult:
    result = _new_result(path.parent, "reverse-elf")
    try:
        password, encrypted_flag, password_key, output_key, engine = _static_elf_buffers(_read_limited(path))
        recovered_password = bytes(value ^ password_key for value in password)
        decoded = bytes(value ^ output_key for value in encrypted_flag)
        decoded_path = _write_artifact(result, output_dir, "static-xor-output.txt", decoded)
        _step(result, "static-disassembly", engine=engine, executed=False)
        _step(result, "recover-password", xor_key=password_key, length=len(recovered_password))
        _step(result, "decode-output", xor_key=output_key, output=str(decoded_path))
        _add_candidates(result, _flag_values(decoded), expected_hash, password_key=password_key, output_key=output_key, evidence=str(decoded_path))
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error, executed=False)
    return _finish(result)


SOLVERS: dict[str, Callable[[Path, Path, str | None], TaskResult]] = {
    "xor-single-byte": solve_xor,
    "magic-bytes": solve_magic_bytes,
    "png-lsb-rgb": solve_png_lsb,
    "pcap-http-bearer": solve_pcap,
    "pcap-dns-base32": solve_dns_base32,
    "sqlite-cache-hex": solve_sqlite,
    "reverse-elf": solve_reverse_elf,
    "archive-layers": solve_archive_layers,
    "repair-header": solve_repair_header,
    "wav-lsb": solve_wav_lsb,
    "png-ztext": solve_png_ztext,
}


def solve_task(task_dir: Path, *, output_dir: Path, expected_hash: str | None = None) -> TaskResult:
    task_dir = task_dir.expanduser().resolve()
    try:
        task_text = (task_dir / "task.txt").read_text(encoding="utf-8")
        artifact = _preferred_artifact(task_dir, select_solver(task_text, task_dir / "artifact") or "")
        solver_name = select_solver(task_text, artifact)
        if solver_name is None or solver_name not in SOLVERS:
            result = _new_result(task_dir, solver_name or "unsupported")
            result.status = "unsupported"
            _step(result, "select-solver", "no-match", artifact=str(artifact))
            return result
        result = SOLVERS[solver_name](artifact, output_dir, expected_hash)
        result.task_dir = task_dir
        result.task_id = _task_id(task_dir)
        for candidate in result.candidates:
            candidate.setdefault("task_id", result.task_id)
            candidate.setdefault("artifact", str(artifact))
            candidate.setdefault("analyzer", f"task-solver:{solver_name}")
            candidate.setdefault("source", candidate.get("evidence", str(artifact)))
            candidate.setdefault("line", 1)
            candidate.setdefault("evidence", candidate.get("value", ""))
        return result
    except Exception as exc:
        result = _new_result(task_dir, "dispatcher")
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "dispatch", "error", error=result.error)
        return _finish(result)


def load_expected_hashes(root: Path) -> dict[str, str]:
    for parent in [root.resolve(), *root.resolve().parents]:
        path = parent / "flag_hashes.json"
        if path.is_file():
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                return {str(key): str(item) for key, item in value.items()}
            except (OSError, ValueError, TypeError):
                return {}
    return {}
