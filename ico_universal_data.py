#!/usr/bin/env python3
"""Bounded encoding, XOR, and container solvers for local CTF artifacts."""

from __future__ import annotations

import bz2
import ast
import gzip
import hashlib
import io
import lzma
import os
import quopri
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from ico_scan_core import MAX_GENERIC_XOR_BYTES, FlagMatcher, encoded_views, single_byte_xor_views
from ico_solver_engine import Detection, SolverContext, SolverLimits, SolverResult


SINGLE_BYTE_PREFIXES = (b"CTF{", b"ico{", b"ICO{", b"flag{", b"FLAG{")
_CONTAINER_MAGICS = (b"PK\x03\x04", b"\x1f\x8b", b"\xfd7zXZ\x00", b"BZh", b"ustar")
_ENCODING_WORDS = ("base64", "base32", "hex", "percent", "url", "encoding", "decode", "xor")
_ROT13_FLAG_MARKER_RE = re.compile(rb"(?i)(?<![a-z0-9])(?:vpgs|pgs|synt|vpb)\{")
_ROT13_TABLE = bytes.maketrans(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)
_STREAM_CHUNK_SIZE = 64 * 1024


def _safe_name(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return clean or "artifact"


def _read_limited(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds byte limit: {size} > {limit}")
    return path.read_bytes()


def decode_text_tokens(
    data: bytes,
    *,
    max_bytes: int,
    max_depth: int = 2,
    max_tokens: int = 256,
) -> list[tuple[str, bytes, dict[str, object]]]:
    """Decode syntactically valid bounded tokens, including nested views."""

    if max_bytes < 1 or max_depth < 0 or max_tokens < 1:
        raise ValueError("decode limits must be positive; max_depth may be zero")
    queue: list[tuple[bytes, int, str]] = [(data[:max_bytes], 0, "raw")]
    seen: set[tuple[str, bytes]] = set()
    output: list[tuple[str, bytes, dict[str, object]]] = []
    while queue and len(output) < max_tokens:
        current, depth, parent = queue.pop(0)
        views = encoded_views(current, max_bytes=max_bytes)
        for view in views:
            decoded = bytes(view["decoded"])
            if len(decoded) > max_bytes:
                continue
            encoding = str(view["encoding"])
            key = (encoding, decoded)
            if key in seen:
                continue
            seen.add(key)
            metadata = {
                "depth": depth,
                "parent": parent,
                "offset": int(view.get("offset", 0)),
                "token": str(view.get("token", "")),
            }
            output.append((encoding, decoded, metadata))
            if depth < max_depth and len(output) < max_tokens:
                queue.append((decoded, depth + 1, encoding))
        # Quoted-printable is only considered when the marker syntax is
        # present; decoding arbitrary binary as QP creates too many accidental
        # views and is not useful evidence.
        if len(output) < max_tokens and (b"=" in current or b"=\n" in current):
            decoded = quopri.decodestring(current)
            if decoded != current and len(decoded) <= max_bytes:
                key = ("quoted-printable", decoded)
                if key not in seen:
                    seen.add(key)
                    output.append(("quoted-printable", decoded, {"depth": depth, "parent": parent, "offset": 0, "token": current[:128].decode("ascii", errors="replace")}))
                    if depth < max_depth and len(output) < max_tokens:
                        queue.append((decoded, depth + 1, "quoted-printable"))
    return output


def _member_destination(root: Path, name: str, index: int) -> Path:
    root = root.resolve()
    relative = Path(name)
    if relative.is_absolute():
        raise ValueError(f"absolute archive member rejected: {name}")
    target = (root / relative).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"archive path traversal rejected: {name}") from exc
    suffix = target.suffix or ".bin"
    return root / f"{index:04d}-{_safe_name(target.stem)}{suffix}"


def _write_bounded(path: Path, data: bytes, *, max_bytes: int) -> Path:
    if len(data) > max_bytes:
        raise ValueError(f"derived artifact exceeds byte limit: {len(data)} > {max_bytes}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _read_stream_bounded(stream: Any, limit: int, *, description: str) -> bytes:
    """Read a potentially expanding stream without exceeding its byte budget."""

    if limit < 0:
        raise ValueError("stream byte limit cannot be negative")
    output = bytearray()
    while True:
        remaining_with_overflow_probe = limit - len(output) + 1
        chunk = stream.read(min(_STREAM_CHUNK_SIZE, remaining_with_overflow_probe))
        if not chunk:
            return bytes(output)
        output.extend(chunk)
        if len(output) > limit:
            raise ValueError(f"{description} exceeds byte limit: > {limit}")


def _reversed_python_literal_views(data: bytes, *, max_bytes: int) -> list[bytes]:
    """Read string literals reversed with ``[::-1]`` without executing source."""

    if len(data) > min(max_bytes, 4 * 1024 * 1024) or not re.search(rb"\[\s*:\s*:\s*-\s*1\s*\]", data):
        return []
    try:
        tree = ast.parse(data.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError):
        return []
    views: list[bytes] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Subscript) or not isinstance(node.value, ast.Constant):
            continue
        if not isinstance(node.value.value, str) or not isinstance(node.slice, ast.Slice):
            continue
        step = node.slice.step
        if not (
            node.slice.lower is None
            and node.slice.upper is None
            and isinstance(step, ast.UnaryOp)
            and isinstance(step.op, ast.USub)
            and isinstance(step.operand, ast.Constant)
            and step.operand.value == 1
        ):
            continue
        decoded = node.value.value[::-1].encode("utf-8")
        if decoded and len(decoded) <= max_bytes:
            views.append(decoded)
            if len(views) >= 64:
                break
    return views


def extract_container(path: Path, output_dir: Path, limits: SolverLimits) -> list[Path]:
    """Extract one bounded container layer without following unsafe paths."""

    data = _read_limited(path, limits.max_bytes)
    digest = hashlib.sha256(data).hexdigest()[:12]
    root = (output_dir / "artifacts" / "universal-data" / f"{_safe_name(path.stem)}-{digest}").resolve()
    root.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    total = 0

    def add(name: str, payload: bytes) -> None:
        nonlocal total
        if len(extracted) >= limits.max_files:
            raise ValueError(f"container member limit exceeded: {limits.max_files}")
        total += len(payload)
        if total > limits.max_bytes:
            raise ValueError(f"container expansion exceeds byte limit: {total} > {limits.max_bytes}")
        target = _member_destination(root, name, len(extracted))
        extracted.append(_write_bounded(target, payload, max_bytes=limits.max_bytes))

    if data.startswith(b"PK\x03\x04") or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            members = [item for item in archive.infolist() if not item.is_dir()]
            if len(members) > limits.max_files:
                raise ValueError(f"container member limit exceeded: {len(members)} > {limits.max_files}")
            for item in members:
                remaining = limits.max_bytes - total
                with archive.open(item) as stream:
                    payload = _read_stream_bounded(
                        stream,
                        remaining,
                        description=f"ZIP member {item.filename}",
                    )
                add(item.filename, payload)
        return extracted

    if data.startswith(b"ustar") or tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as archive:
            members = [item for item in archive.getmembers() if item.isfile()]
            if len(members) > limits.max_files:
                raise ValueError(f"container member limit exceeded: {len(members)} > {limits.max_files}")
            for item in members:
                stream = archive.extractfile(item)
                if stream is None:
                    continue
                with stream:
                    payload = _read_stream_bounded(
                        stream,
                        limits.max_bytes - total,
                        description=f"TAR member {item.name}",
                    )
                add(item.name, payload)
        return extracted

    if data.startswith(b"\x1f\x8b") or path.suffix.lower() == ".gz":
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            payload = _read_stream_bounded(
                stream,
                limits.max_bytes - total,
                description="gzip expansion",
            )
        add(path.stem or "decompressed", payload)
        return extracted
    if data.startswith(b"\xfd7zXZ\x00") or path.suffix.lower() in {".xz", ".lzma"}:
        with lzma.LZMAFile(io.BytesIO(data), mode="rb") as stream:
            payload = _read_stream_bounded(
                stream,
                limits.max_bytes - total,
                description="XZ/LZMA expansion",
            )
        add(path.stem or "decompressed", payload)
        return extracted
    if data.startswith(b"BZh") or path.suffix.lower() == ".bz2":
        with bz2.BZ2File(io.BytesIO(data), mode="rb") as stream:
            payload = _read_stream_bounded(
                stream,
                limits.max_bytes - total,
                description="bzip2 expansion",
            )
        add(path.stem or "decompressed", payload)
        return extracted
    return extracted


def _flag_hits(data: bytes, *, source: str, analyzer: str) -> list[dict[str, object]]:
    text = data.decode("utf-8", errors="replace")
    return FlagMatcher().scan(text, source=source, analyzer=analyzer)


class DataSolver:
    name = "universal-data"
    category = "data"

    def detect(self, context: SolverContext) -> Detection | None:
        kind = str(context.classification.get("kind", ""))
        task = (context.task_text or "").lower()
        try:
            prefix = context.input_path.read_bytes()[:16]
        except OSError:
            return Detection(self.name, self.category, 10, "input-read-failed")
        has_container = any(prefix.startswith(magic) for magic in _CONTAINER_MAGICS)
        has_transform_hint = any(word in task for word in _ENCODING_WORDS)
        if kind in {"data", "binary", "text", "archive"} or has_container or has_transform_hint:
            score = 80 if has_transform_hint or has_container else 35
            return Detection(
                self.name,
                self.category,
                score,
                "generic data/encoding/container evidence",
                {"kind": kind, "container": has_container, "task_hint": has_transform_hint},
            )
        return None

    def solve(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "unsupported")
        try:
            data = _read_limited(context.input_path, context.limits.max_bytes)
            task = (context.task_text or "").lower()
            output_root = context.report_dir / "artifacts" / "universal-data"
            wrote_derived = False

            def scan_view(payload: bytes, source: str, analyzer: str, **metadata: object) -> None:
                nonlocal wrote_derived
                hits = _flag_hits(payload, source=source, analyzer=analyzer)
                for hit in hits:
                    hit.update(metadata)
                if hits:
                    result.candidates.extend(hits)

            if _ROT13_FLAG_MARKER_RE.search(data):
                rot13_view = data.translate(_ROT13_TABLE)
                hits = _flag_hits(rot13_view, source=str(context.input_path), analyzer="rot13-flag-marker")
                if hits:
                    path = output_root / f"rot13-{hashlib.sha256(rot13_view).hexdigest()[:12]}.txt"
                    _write_bounded(path, rot13_view, max_bytes=context.limits.max_bytes)
                    result.artifacts.append(str(path))
                    result.candidates.extend(hits)
                    result.steps.append(
                        {
                            "name": "decode-rot13-flag-marker",
                            "status": "ok",
                            "details": {"marker_count": len(_ROT13_FLAG_MARKER_RE.findall(data)), "output": str(path)},
                        }
                    )
                    wrote_derived = True

            reverse_views = _reversed_python_literal_views(data, max_bytes=context.limits.max_bytes)
            for index, reversed_view in enumerate(reverse_views):
                if not _ROT13_FLAG_MARKER_RE.search(reversed_view):
                    continue
                rot13_view = reversed_view.translate(_ROT13_TABLE)
                source = f"{context.input_path}#python-literal-reverse={index}+rot13"
                hits = _flag_hits(rot13_view, source=source, analyzer="reverse-python-literal-rot13")
                if not hits:
                    continue
                path = output_root / f"reverse-rot13-{hashlib.sha256(rot13_view).hexdigest()[:12]}.txt"
                _write_bounded(path, rot13_view, max_bytes=context.limits.max_bytes)
                result.artifacts.append(str(path))
                for hit in hits:
                    hit["transform_chain"] = ["python-string-slice[::-1]", "rot13"]
                result.candidates.extend(hits)
                result.steps.append(
                    {
                        "name": "decode-reversed-python-literal-rot13",
                        "status": "ok",
                        "details": {"literal_index": index, "output": str(path)},
                    }
                )
                wrote_derived = True

            views = decode_text_tokens(data, max_bytes=context.limits.max_bytes)
            for index, (encoding, decoded, metadata) in enumerate(views):
                path = output_root / f"decoded-{hashlib.sha256(decoded).hexdigest()[:12]}-{index:03d}.bin"
                _write_bounded(path, decoded, max_bytes=context.limits.max_bytes)
                result.artifacts.append(str(path))
                wrote_derived = True
                scan_view(decoded, f"{path}#encoding={encoding}", f"decode-{encoding}", **metadata)
            if views:
                result.steps.append({"name": "decode-tokens", "status": "ok", "details": {"count": len(views)}})

            task_requests_xor = "xor" in task or "exclusive or" in task
            should_try_xor = task_requests_xor or (
                context.classification.get("kind") in {"data", "binary"} and not views
            )
            if should_try_xor and not task_requests_xor and len(data) > MAX_GENERIC_XOR_BYTES:
                result.steps.append(
                    {
                        "name": "single-byte-xor",
                        "status": "skipped",
                        "details": {
                            "reason": "large binary without an explicit XOR task hint; generic XOR pass skipped",
                            "input_bytes": len(data),
                            "limit_bytes": MAX_GENERIC_XOR_BYTES,
                        },
                    }
                )
            elif should_try_xor:
                xor_views = single_byte_xor_views(data, prefixes=SINGLE_BYTE_PREFIXES)
                for view in xor_views:
                    decoded = bytes(view["plaintext"])
                    scan_view(
                        decoded[int(view["offset"]) :],
                        f"{context.input_path}#xor-key=0x{int(view['key']):02x}",
                        "single-byte-xor",
                        key=int(view["key"]),
                        offset=int(view["offset"]),
                        crib=bytes(view["prefix"]).decode("ascii", errors="replace"),
                    )
                if xor_views:
                    result.steps.append(
                        {"name": "single-byte-xor", "status": "ok", "details": {"matches": len(xor_views)}}
                    )

            try:
                # Walk nested layers in a small FIFO.  Each layer still goes
                # through the same member/path/byte limits and every derived
                # file remains below the report directory.
                pending: list[tuple[Path, int]] = [(context.input_path, 0)]
                seen_containers: set[Path] = set()
                extracted_count = 0
                while pending:
                    current, depth = pending.pop(0)
                    if depth >= context.limits.max_depth or current in seen_containers:
                        continue
                    seen_containers.add(current)
                    current_data = _read_limited(current, context.limits.max_bytes)
                    if not (
                        current_data.startswith(b"PK\x03\x04")
                        or zipfile.is_zipfile(current)
                        or any(current_data.startswith(magic) for magic in _CONTAINER_MAGICS[1:])
                    ):
                        continue
                    children = extract_container(current, context.report_dir, context.limits)
                    for child in children:
                        result.artifacts.append(str(child))
                        if depth == 0:
                            result.derived_inputs.append(str(child))
                        child_data = _read_limited(child, context.limits.max_bytes)
                        scan_view(child_data, str(child), "container-member")
                        pending.append((child, depth + 1))
                    if children:
                        wrote_derived = True
                        extracted_count += len(children)
                if extracted_count:
                    result.steps.append(
                        {"name": "extract-container", "status": "ok", "details": {"count": extracted_count, "depth": context.limits.max_depth}}
                    )
            except (OSError, ValueError, gzip.BadGzipFile, lzma.LZMAError, tarfile.TarError, zipfile.BadZipFile) as exc:
                result.steps.append(
                    {"name": "extract-container", "status": "error", "details": {"error": f"{type(exc).__name__}: {exc}"}}
                )

            if result.candidates:
                result.status = "candidate"
            elif wrote_derived:
                result.status = "derived"
            else:
                result.status = "unsupported"
        except Exception as exc:
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
            result.steps.append({"name": "solve", "status": "error", "details": {"error": result.error}})
        return result
