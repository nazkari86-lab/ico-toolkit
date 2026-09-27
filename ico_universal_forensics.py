#!/usr/bin/env python3
"""Bounded PCAP, database, and log triage for local CTF artifacts."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import os
import re
import selectors
import shutil
import sqlite3
import struct
import subprocess
import time
import xml.etree.ElementTree as ET
import zlib
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ico_scan_core import FlagMatcher, encoded_views
from ico_solver_engine import Detection, SolverContext, SolverLimits, SolverResult

MAX_PCAP_PACKETS = 100_000
EWF_MAGICS = {b"EVF\x09\x0d\x0a\xff\x00", b"LVF\x09\x0d\x0a\xff\x00"}
EWF_SUFFIXES = {".e01", ".ex01", ".l01", ".s01"}
_PRINTABLE_BYTES = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0B, 0x0C, 0x0D}
MNIST_MODEL_SHA256 = "2f06e72de813a8635c9bc0397ac447a601bdbfa7df4bebc278723b958831c9bf"
MAX_SUBTITLE_FRAMES = 5_000


def _read_limited(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds byte limit: {size} > {limit}")
    return path.read_bytes()


def _read_prefix(path: Path, length: int = 8) -> bytes:
    try:
        with path.open("rb") as handle:
            return handle.read(length)
    except OSError:
        return b""


def _ewf_magic(path: Path) -> bytes:
    return _read_prefix(path, 8)


def _ewf_info_fields(text: str) -> dict[str, object]:
    labels = {
        "File format": "file_format",
        "Media type": "media_type",
        "Bytes per sector": "bytes_per_sector",
        "Number of sectors": "number_of_sectors",
        "Media size": "media_size",
        "Sectors per chunk": "sectors_per_chunk",
        "Compression method": "compression_method",
    }
    fields: dict[str, object] = {}
    for line in text.splitlines():
        label, separator, value = line.partition(":")
        key = labels.get(label.strip()) if separator else None
        if key is None:
            continue
        value = value.strip()
        if key in {"bytes_per_sector", "number_of_sectors", "sectors_per_chunk"}:
            match = re.search(r"\d+", value)
            if match:
                fields[key] = int(match.group())
        elif key == "media_size":
            size_match = re.search(r"\((\d+)\s+bytes\)", value)
            fields[key] = value
            if size_match:
                fields["media_size_bytes"] = int(size_match.group(1))
        else:
            fields[key] = value
    return fields


def _ewf_partition_count(text: str) -> int:
    return len(_ewf_partition_entries(text))


def _ewf_partition_entries(text: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    row = re.compile(r"^\s*(\d+):\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$")
    for line in text.splitlines():
        match = row.match(line)
        if not match:
            continue
        slot, slot_type, start, end, length, description = match.groups()
        if slot_type in {"Meta", "-------"} or description.lower().startswith("unallocated"):
            continue
        entries.append(
            {
                "slot": slot,
                "start_sector": int(start),
                "end_sector": int(end),
                "length_sectors": int(length),
                "description": description,
            }
        )
    return entries


def _parse_fls_entries(text: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    header = re.compile(r"^([A-Za-z]/[A-Za-z])\s+(\*)?\s*(\d+(?:-\d+)*):$")
    for line in text.splitlines():
        columns = line.split("\t")
        match = header.match(columns[0].strip())
        if not match:
            continue
        file_type, deleted, inode = match.groups()
        name = columns[1].strip() if len(columns) > 1 else ""
        if not name or name in {".", ".."}:
            continue
        size = None
        if len(columns) >= 7 and columns[-3].strip().isdigit():
            size = int(columns[-3].strip())
        entries.append(
            {
                "type": file_type,
                "deleted": bool(deleted),
                "inode": inode,
                "name": name,
                "size_bytes": size,
            }
        )
    return entries


def _run_capped(
    command: list[str], *, timeout_seconds: float, max_output_bytes: int
) -> tuple[int, bytes, bool, bool]:
    """Run a trusted local parser while bounding time and captured output."""

    limit = max(1, max_output_bytes)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    assert process.stdout is not None
    output = bytearray()
    timed_out = False
    truncated = False
    deadline = time.monotonic() + timeout_seconds
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = process.poll() is None
                break
            if not selector.select(remaining):
                timed_out = process.poll() is None
                break
            chunk = os.read(process.stdout.fileno(), min(65536, limit - len(output) + 1))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > limit:
                del output[limit:]
                truncated = True
                break
    if timed_out or truncated:
        process.terminate()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    else:
        try:
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            timed_out = True
    process.stdout.close()
    return int(process.returncode or 0), bytes(output), timed_out, truncated


def _ewf_remaining(deadline: float) -> float:
    return max(0.0, deadline - time.monotonic())


def _scan_ewf_files(
    context: SolverContext,
    image: Path,
    output_dir: Path,
    partitions: list[dict[str, object]],
    result: SolverResult,
    deadline: float,
) -> dict[str, object]:
    fls_tool = shutil.which("fls")
    icat_tool = shutil.which("icat")
    if not fls_tool or not icat_tool:
        missing = [name for name, tool in (("fls", fls_tool), ("icat", icat_tool)) if not tool]
        scan_error = f"missing Sleuth Kit tool(s): {', '.join(missing)}"
        result.error = result.error or scan_error
        result.steps.append({"name": "scan-ewf-files", "status": "unsupported", "details": {"error": scan_error}})
        return {"files_listed": 0, "files_read": 0, "bytes_read": 0, "candidates": 0}

    if not partitions:
        partitions = [{"start_sector": 0, "description": "whole EWF media"}]
    file_limit = context.limits.max_files
    content_budget = context.limits.max_bytes
    listing_budget = min(context.limits.max_bytes, max(4096, file_limit * 1024))
    max_file_bytes = min(4 * 1024 * 1024, context.limits.max_bytes)
    index: list[dict[str, object]] = []
    files_read = 0
    bytes_read = 0
    skipped_large = 0
    command_errors = 0
    truncated_outputs = 0
    matcher = FlagMatcher()
    file_queue: deque[tuple[dict[str, object], str | None, str, int]] = deque()
    for partition in partitions:
        file_queue.append((partition, None, "", 0))

    while file_queue and len(index) < file_limit and _ewf_remaining(deadline) > 0:
        partition, directory_inode, parent, depth = file_queue.popleft()
        partition_start = int(partition["start_sector"])
        command = [fls_tool, "-i", "ewf", "-o", str(partition_start), "-l", str(image)]
        if directory_inode is not None:
            command.append(directory_inode)
        output_limit = min(listing_budget, max(1, context.limits.max_bytes - bytes_read))
        if output_limit <= 0:
            break
        try:
            returncode, listing_bytes, timed_out, was_truncated = _run_capped(
                command,
                timeout_seconds=_ewf_remaining(deadline),
                max_output_bytes=output_limit,
            )
        except OSError as exc:
            command_errors += 1
            index.append({"partition_start": partition_start, "directory": parent or "/", "status": f"{type(exc).__name__}: {exc}"})
            continue
        listing_budget -= len(listing_bytes)
        if was_truncated:
            truncated_outputs += 1
        if timed_out:
            command_errors += 1
            index.append({"partition_start": partition_start, "directory": parent or "/", "status": "fls-timeout"})
            break
        if returncode != 0:
            command_errors += 1
            index.append({"partition_start": partition_start, "directory": parent or "/", "status": f"fls-exit-{returncode}"})
            continue

        for entry in _parse_fls_entries(listing_bytes.decode("utf-8", errors="replace")):
            if len(index) >= file_limit or _ewf_remaining(deadline) <= 0:
                break
            name = str(entry["name"])
            relative_path = f"{parent}/{name}".strip("/")
            file_type = str(entry["type"])
            row: dict[str, object] = {
                "partition_start": partition_start,
                "path": relative_path,
                "inode": entry["inode"],
                "type": file_type,
                "deleted": entry["deleted"],
                "size_bytes": entry["size_bytes"],
                "status": "listed",
            }
            index.append(row)
            if file_type.lower().startswith("d/") and depth < context.limits.max_depth:
                file_queue.append((partition, str(entry["inode"]), relative_path, depth + 1))
                continue
            if not file_type.lower().startswith("r/"):
                continue
            remaining_content = content_budget - bytes_read
            if remaining_content <= 0:
                row["status"] = "content-budget-reached"
                continue
            cap = min(max_file_bytes, remaining_content)
            known_size = entry.get("size_bytes")
            if isinstance(known_size, int) and known_size == 0:
                row["status"] = "empty-file"
                continue
            icat_command = [icat_tool, "-i", "ewf", "-o", str(partition_start)]
            if entry["deleted"]:
                icat_command.append("-r")
            icat_command.extend([str(image), str(entry["inode"])])
            try:
                icat_code, payload, icat_timeout, payload_truncated = _run_capped(
                    icat_command,
                    timeout_seconds=_ewf_remaining(deadline),
                    max_output_bytes=cap,
                )
            except OSError as exc:
                command_errors += 1
                row["status"] = f"{type(exc).__name__}: {exc}"
                continue
            if icat_timeout:
                command_errors += 1
                row["status"] = "icat-timeout"
                break
            if icat_code != 0:
                command_errors += 1
                row["status"] = f"icat-exit-{icat_code}"
                continue
            files_read += 1
            bytes_read += len(payload)
            row["status"] = "read-truncated" if payload_truncated else "read"
            if payload_truncated or (isinstance(known_size, int) and known_size > len(payload)):
                row["truncated"] = True

            source_label = f"{image}#partition={partition_start}/{relative_path}"
            views: list[tuple[bytes, str]] = [(payload, "identity")]
            for view in encoded_views(payload, max_bytes=max(1, len(payload))):
                decoded = bytes(view["decoded"])
                if decoded:
                    views.append((decoded, str(view.get("encoding", "decoded"))))
            for view_bytes, transform in views:
                matches = matcher.scan(
                    view_bytes.decode("utf-8", errors="replace"),
                    source=source_label,
                    analyzer="ewf-icat",
                )
                for hit in matches:
                    value = str(hit["value"])
                    if any(candidate.get("value") == value for candidate in result.candidates):
                        continue
                    evidence_name = f"file-{len(result.candidates):03d}-{str(entry['inode']).replace('-', '_')}.bin"
                    evidence_path = output_dir / evidence_name
                    evidence_path.write_bytes(payload)
                    hit.update(
                        {
                            "evidence_excerpt": hit.get("evidence"),
                            "evidence": str(evidence_path),
                            "file_path": relative_path,
                            "inode": entry["inode"],
                            "partition_start": partition_start,
                            "file_size_bytes": known_size,
                            "truncated": bool(row.get("truncated", False)),
                            "transform": transform,
                        }
                    )
                    result.candidates.append(hit)
                    result.artifacts.append(str(evidence_path))

    index_path = output_dir / "file-index.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result.artifacts.append(str(index_path))
    summary = {
        "files_listed": len(index),
        "files_read": files_read,
        "bytes_read": bytes_read,
        "content_budget_bytes": content_budget,
        "max_depth": context.limits.max_depth,
        "max_files": file_limit,
        "skipped_large_files": skipped_large,
        "command_errors": command_errors,
        "truncated_listings": truncated_outputs,
        "output": str(index_path),
        "candidate_count": len(result.candidates),
    }
    result.steps.append(
        {
            "name": "scan-ewf-files",
            "status": "ok" if not command_errors and not truncated_outputs else "needs-review",
            "details": summary,
        }
    )
    return summary


def _triage_ewf(context: SolverContext) -> SolverResult:
    """Collect EWF metadata and scan bounded regular-file contents read-only."""

    result = SolverResult("universal-forensics", "forensics", "needs-review")
    path = context.input_path
    deadline = time.monotonic() + context.limits.timeout_seconds
    try:
        stat = path.stat()
        fingerprint = hashlib.sha256(
            f"{path.resolve()}:{stat.st_size}:{stat.st_mtime_ns}".encode("utf-8")
        ).hexdigest()[:12]
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append({"name": "inspect-ewf", "status": "error", "details": {"error": result.error}})
        return result

    output_dir = context.report_dir / "artifacts" / "universal-forensics" / fingerprint
    info_tool = shutil.which("ewfinfo")
    mmls_tool = shutil.which("mmls")
    if not info_tool:
        result.error = "ewfinfo is unavailable; install libewf tools to inspect this image"
        result.steps.append({"name": "ewfinfo", "status": "unsupported", "details": {"error": result.error}})
        return result

    try:
        info_code, info_bytes, info_timeout, info_truncated = _run_capped(
            [info_tool, "-m", str(path)],
            timeout_seconds=_ewf_remaining(deadline),
            max_output_bytes=min(context.limits.max_bytes, 1024 * 1024),
        )
        info_text = info_bytes.decode("utf-8", errors="replace")
        info_path = output_dir / "ewfinfo.txt"
        info_path.parent.mkdir(parents=True, exist_ok=True)
        info_path.write_text(info_text, encoding="utf-8")
        result.artifacts.append(str(info_path))
        details: dict[str, object] = {
            "input_bytes": stat.st_size,
            "input_read_fully": False,
            "output": str(info_path),
            "output_truncated": info_truncated,
            **_ewf_info_fields(info_text),
        }
        result.steps.append(
            {
                "name": "ewfinfo",
                "status": "timeout" if info_timeout else "ok" if info_code == 0 else "error",
                "details": details if info_code == 0 and not info_timeout else {**details, "returncode": info_code},
            }
        )
        result.candidates.extend(FlagMatcher().scan(info_text, source=str(info_path), analyzer="ewf-metadata"))
        if info_timeout:
            result.error = f"ewfinfo timed out after {context.limits.timeout_seconds:g}s"
            return result
        if info_code != 0:
            result.error = f"ewfinfo exited with status {info_code}; inspect the saved output"
            return result
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append({"name": "ewfinfo", "status": "error", "details": {"error": result.error}})
        return result

    if not mmls_tool:
        result.error = "mmls is unavailable; install Sleuth Kit to inspect partitions"
        result.steps.append({"name": "mmls", "status": "unsupported", "details": {"error": result.error}})
        return result
    partition_code = -1
    partitions: list[dict[str, object]] = []
    try:
        partition_code, partition_bytes, partition_timeout, partition_truncated = _run_capped(
            [mmls_tool, "-i", "ewf", str(path)],
            timeout_seconds=_ewf_remaining(deadline),
            max_output_bytes=min(context.limits.max_bytes, max(4096, context.limits.max_files * 1024)),
        )
        partition_text = partition_bytes.decode("utf-8", errors="replace")
        partition_path = output_dir / "partitions.txt"
        partition_path.write_text(partition_text, encoding="utf-8")
        result.artifacts.append(str(partition_path))
        partitions = _ewf_partition_entries(partition_text)
        result.steps.append(
            {
                "name": "mmls",
                "status": "timeout" if partition_timeout else "needs-review" if partition_truncated else "ok" if partition_code == 0 else "error",
                "details": {
                    "output": str(partition_path),
                    "partition_count": len(partitions),
                    "output_truncated": partition_truncated,
                    **({} if partition_code == 0 and not partition_timeout else {"returncode": partition_code}),
                },
            }
        )
        if partition_timeout:
            result.error = f"mmls timed out after {context.limits.timeout_seconds:g}s"
        elif partition_code != 0:
            result.error = f"mmls exited with status {partition_code}; inspect the saved output"
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append({"name": "mmls", "status": "error", "details": {"error": result.error}})
    _scan_ewf_files(context, path, output_dir, partitions if partition_code == 0 else [], result, deadline)
    if result.candidates:
        result.status = "candidate"
    elif result.error or any(step.get("status") in {"needs-review", "timeout", "unsupported"} for step in result.steps):
        result.status = "needs-review"
    else:
        result.status = "needs-review"
    return result


def _pcap_endian(data: bytes) -> str:
    if len(data) < 4:
        raise ValueError("pcap header is truncated")
    magic = data[:4]
    if magic in {b"\xd4\xc3\xb2\xa1", b"M\x3c\xb2\xa1"}:
        return "<"
    if magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2<M"}:
        return ">"
    raise ValueError("unsupported pcap magic")


PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"


def _pcapng_endian(data: bytes) -> str:
    if len(data) < 12:
        raise ValueError("pcapng section header is truncated")
    if data[:4] != PCAPNG_MAGIC:
        raise ValueError("unsupported pcapng magic")
    byte_order_magic = data[8:12]
    if byte_order_magic == b"M<+\x1a":
        return "<"
    if byte_order_magic == b"\x1a+<M":
        return ">"
    raise ValueError("unsupported pcapng byte order")


def _ip_text(data: bytes) -> str:
    return str(ipaddress.IPv4Address(data))


def _dns_name(payload: bytes) -> str | None:
    labels = _dns_labels(payload)
    return ".".join(labels) if labels else None


def _dns_labels(payload: bytes) -> list[str]:
    """Read the first DNS question name from a UDP payload."""

    if len(payload) < 13:
        return []
    offset = 12
    labels: list[str] = []
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            return labels
        if length & 0xC0 or offset + length > len(payload):
            return []
        labels.append(payload[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return []


def _dns_base32_views(labels: list[str], *, max_views: int = 64) -> list[tuple[bytes, dict[str, object]]]:
    """Decode bounded Base32 sequences assembled from DNS labels.

    DNS exfiltration commonly splits one Base32 token across labels.  We try
    contiguous Base32-looking runs and keep the transform evidence-labelled;
    callers still require a flag-shaped result before treating a view as a
    candidate.  The small limit prevents ordinary DNS traffic from creating a
    combinatorial decode pass.
    """

    alphabet = re.compile(r"[A-Z2-7=]+", re.IGNORECASE)
    views: list[tuple[bytes, dict[str, object]]] = []
    seen: set[bytes] = set()
    start = 0
    while start < len(labels) and len(views) < max_views:
        if not alphabet.fullmatch(labels[start]) or len(labels[start]) < 2:
            start += 1
            continue
        end = start
        while end < len(labels) and alphabet.fullmatch(labels[end]) and len(labels[end]) >= 2:
            end += 1
        # Prefer the longest join first, then shorter suffix-trimmed joins so
        # a real token followed by a Base32-looking domain still has a chance.
        for left in range(start, end):
            # ``right`` is an exclusive slice bound.  Include ``end`` even
            # when the run consists of one DNS label; the previous lower
            # bound skipped that valid one-label token entirely.
            for right in range(end, left, -1):
                if len(views) >= max_views:
                    break
                token = "".join(labels[left:right]).encode("ascii", errors="ignore")
                if len(token) < 8:
                    continue
                padded = token + b"=" * (-len(token) % 8)
                try:
                    decoded = base64.b32decode(padded, casefold=True)
                except (ValueError, binascii.Error):
                    continue
                if not decoded or decoded in seen:
                    continue
                seen.add(decoded)
                views.append(
                    (
                        decoded,
                        {
                            "labels": labels[left:right],
                            "label_start": left,
                            "label_end": right,
                            "encoding": "base32-dns-labels",
                        },
                    )
                )
        start = end
    return views


def _decode_capture_frame(frame: bytes, link_type: int, original: int) -> dict[str, object] | None:
    if link_type == 1:
        if len(frame) < 14:
            return None
        ethertype = struct.unpack_from(">H", frame, 12)[0]
        if ethertype == 0x0806:
            # ARP frames do not have an IPv4 header. Keep only ordinary
            # Ethernet/IPv4 ARP packets and expose the target protocol address
            # for explicitly signalled tARP challenges.
            if len(frame) < 42:
                return None
            hardware_type, protocol_type, hardware_size, protocol_size, opcode = struct.unpack_from(">HHBBH", frame, 14)
            if (hardware_type, protocol_type, hardware_size, protocol_size) != (1, 0x0800, 6, 4):
                return None
            if opcode not in {1, 2}:
                return None
            target_protocol_address = frame[38:42]
            return {
                "source": _ip_text(frame[28:32]),
                "target": _ip_text(target_protocol_address),
                "protocol": 0x0806,
                "protocol_name": "arp",
                "target_protocol_address": target_protocol_address,
                "payload": b"",
                "captured": len(frame),
                "original": original,
                "link_type": link_type,
            }
        if ethertype != 0x0800:
            return None
        ip_offset = 14
    elif link_type == 276:
        if len(frame) < 20 or struct.unpack_from(">H", frame, 0)[0] != 0x0800:
            return None
        ip_offset = 20
    else:
        raise ValueError(f"unsupported pcap link type: {link_type}")
    if len(frame) < ip_offset + 20 or frame[ip_offset] >> 4 != 4:
        return None
    ihl = (frame[ip_offset] & 0x0F) * 4
    if ihl < 20 or len(frame) < ip_offset + ihl:
        return None
    source = _ip_text(frame[ip_offset + 12 : ip_offset + 16])
    target = _ip_text(frame[ip_offset + 16 : ip_offset + 20])
    protocol = frame[ip_offset + 9]
    transport = ip_offset + ihl
    record: dict[str, object] = {
        "source": source,
        "target": target,
        "protocol": protocol,
        "payload": b"",
        "captured": len(frame),
        "original": original,
        "link_type": link_type,
    }
    if protocol == 6 and len(frame) >= transport + 20:
        source_port, target_port = struct.unpack_from(">HH", frame, transport)
        sequence = struct.unpack_from(">I", frame, transport + 4)[0]
        data_offset = (frame[transport + 12] >> 4) * 4
        payload_offset = transport + data_offset
        payload = frame[payload_offset:] if payload_offset <= len(frame) else b""
        record.update(
            {
                "protocol_name": "tcp",
                "source_port": source_port,
                "target_port": target_port,
                "sequence": sequence,
                "payload": payload,
            }
        )
    elif protocol == 17 and len(frame) >= transport + 8:
        source_port, target_port, length = struct.unpack_from(">HHH", frame, transport)
        payload = frame[transport + 8 :]
        if length >= 8:
            payload = payload[: max(0, length - 8)]
        record.update(
            {
                "protocol_name": "udp",
                "source_port": source_port,
                "target_port": target_port,
                "payload": payload,
            }
        )
        if source_port == 53 or target_port == 53:
            labels = _dns_labels(payload)
            if labels:
                record["dns_labels"] = labels
                record["dns_name"] = ".".join(labels)
    else:
        return None
    return record


def _parse_classic_pcap_data(data: bytes, limits: SolverLimits) -> list[dict[str, object]]:
    endian = _pcap_endian(data)
    if len(data) < 24:
        raise ValueError("pcap global header is truncated")
    link_type = struct.unpack_from(endian + "I", data, 20)[0]
    if link_type not in {1, 276}:
        raise ValueError(f"unsupported pcap link type: {link_type}")
    offset = 24
    packets: list[dict[str, object]] = []
    total_payload = 0
    while offset + 16 <= len(data):
        _seconds, _microseconds, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured > limits.max_bytes or offset + captured > len(data):
            raise ValueError("pcap packet exceeds capture bounds")
        frame = data[offset : offset + captured]
        offset += captured
        record = _decode_capture_frame(frame, link_type, original)
        if record is None:
            continue
        total_payload += len(record["payload"])
        if total_payload > limits.max_bytes:
            raise ValueError("pcap payload limit exceeded")
        packets.append(record)
        if len(packets) >= MAX_PCAP_PACKETS:
            if offset < len(data):
                packets[-1]["packet_limit_reached"] = True
            break
    return packets


def _parse_pcapng_data(data: bytes, limits: SolverLimits) -> list[dict[str, object]]:
    if data[:4] != PCAPNG_MAGIC:
        raise ValueError("unsupported pcapng magic")
    offset = 0
    endian: str | None = None
    interfaces: dict[int, int] = {}
    packets: list[dict[str, object]] = []
    total_payload = 0
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("pcapng block header is truncated")
        if data[offset : offset + 4] == PCAPNG_MAGIC:
            endian = _pcapng_endian(data[offset:])
        if endian is None:
            raise ValueError("pcapng section header is missing")
        block_type, block_length = struct.unpack_from(endian + "II", data, offset)
        if block_length < 12 or block_length % 4 or offset + block_length > len(data):
            raise ValueError("pcapng block exceeds capture bounds")
        trailing_length = struct.unpack_from(endian + "I", data, offset + block_length - 4)[0]
        if trailing_length != block_length:
            raise ValueError("pcapng block lengths do not match")
        body_start = offset + 8
        body_end = offset + block_length - 4
        if block_type == 0x0A0D0D0A:
            endian = _pcapng_endian(data[offset:])
            interfaces = {}
        elif block_type == 1:
            if body_end - body_start < 8:
                raise ValueError("pcapng interface block is truncated")
            link_type = struct.unpack_from(endian + "H", data, body_start)[0]
            interfaces[len(interfaces)] = link_type
        elif block_type in {2, 6}:
            if body_end - body_start < 20:
                raise ValueError("pcapng packet block is truncated")
            interface_id, _timestamp_high, _timestamp_low, captured, original = struct.unpack_from(
                endian + "IIIII", data, body_start
            )
            packet_start = body_start + 20
            if captured > limits.max_bytes or packet_start + captured > body_end:
                raise ValueError("pcapng packet exceeds capture bounds")
            link_type = interfaces.get(interface_id)
            if link_type is None:
                raise ValueError(f"pcapng packet references unknown interface: {interface_id}")
            record = _decode_capture_frame(data[packet_start : packet_start + captured], link_type, original)
            if record is not None:
                total_payload += len(record["payload"])
                if total_payload > limits.max_bytes:
                    raise ValueError("pcap payload limit exceeded")
                packets.append(record)
        elif block_type == 3:
            if body_end - body_start < 4:
                raise ValueError("pcapng simple packet block is truncated")
            original = struct.unpack_from(endian + "I", data, body_start)[0]
            packet_start = body_start + 4
            captured = body_end - packet_start
            link_type = interfaces.get(0)
            if link_type is None:
                raise ValueError("pcapng simple packet references unknown interface")
            record = _decode_capture_frame(data[packet_start : packet_start + captured], link_type, original)
            if record is not None:
                total_payload += len(record["payload"])
                if total_payload > limits.max_bytes:
                    raise ValueError("pcap payload limit exceeded")
                packets.append(record)
        offset += block_length
        if len(packets) >= MAX_PCAP_PACKETS:
            if offset < len(data):
                packets[-1]["packet_limit_reached"] = True
            break
    if not packets and not interfaces:
        raise ValueError("pcapng contains no interface or packet blocks")
    return packets


def parse_pcap_bytes(data: bytes, limits: SolverLimits) -> list[dict[str, object]]:
    if data[:4] == PCAPNG_MAGIC:
        return _parse_pcapng_data(data, limits)
    return _parse_classic_pcap_data(data, limits)


def parse_pcap(path: Path, limits: SolverLimits) -> list[dict[str, object]]:
    return parse_pcap_bytes(_read_limited(path, limits.max_bytes), limits)


_TLS_KEYLOG_LABEL_RE = re.compile(rb"^[A-Z0-9_]{3,64}$")
_TLS_KEYLOG_HEX_RE = re.compile(rb"^[0-9a-fA-F]+$")


def _tls_keylog_randoms(data: bytes, *, max_entries: int) -> set[str]:
    """Return client-random identifiers from a bounded NSS/Wireshark key log."""

    randoms: set[str] = set()
    for index, line in enumerate(data.splitlines()):
        if index >= max_entries:
            break
        fields = line.strip().split()
        if len(fields) != 3 or fields[0].startswith(b"#"):
            continue
        label, client_random, secret = fields
        if (
            not _TLS_KEYLOG_LABEL_RE.fullmatch(label)
            or len(client_random) != 64
            or not _TLS_KEYLOG_HEX_RE.fullmatch(client_random)
            or not secret
            or len(secret) % 2
            or not _TLS_KEYLOG_HEX_RE.fullmatch(secret)
        ):
            continue
        randoms.add(client_random.decode("ascii").lower())
    return randoms


def _tls_keylog_candidates(context: SolverContext) -> list[tuple[Path, set[str]]]:
    """Inspect related files and named sibling sidecars for NSS key-log rows."""

    name_hints = ("keylog", "key-log", "tlskey", "tls-key")
    allowed_suffixes = {".txt", ".log", ".keys", ".keylog"}
    paths = list(dict.fromkeys(path for path in context.related_paths if path != context.input_path))
    known_paths = set(paths)
    try:
        sibling_scan_limit = min(max(context.limits.max_files, 0) * 64, 4096)
        for index, path in enumerate(context.input_path.parent.iterdir()):
            if index >= sibling_scan_limit:
                break
            if (
                path == context.input_path
                or path in known_paths
                or path.is_symlink()
                or path.suffix.lower() not in allowed_suffixes
                or not any(hint in path.name.lower() for hint in name_hints)
            ):
                continue
            try:
                if path.is_file():
                    paths.append(path)
                    known_paths.add(path)
            except OSError:
                continue
    except OSError:
        pass
    paths.sort(
        key=lambda path: (
            not any(hint in path.name.lower() for hint in name_hints),
            str(path).lower(),
        )
    )
    candidates: list[tuple[Path, set[str]]] = []
    inspection_budget = min(context.limits.max_bytes, 4 * 1024 * 1024)
    for path in paths[: min(context.limits.max_files, 64)]:
        if inspection_budget <= 0 or path.suffix.lower() not in allowed_suffixes:
            continue
        try:
            if not path.is_file():
                continue
            with path.open("rb") as handle:
                contents = handle.read(min(inspection_budget, 1024 * 1024) + 1)
        except OSError:
            continue
        if len(contents) > inspection_budget:
            contents = contents[:inspection_budget]
        inspection_budget -= len(contents)
        randoms = _tls_keylog_randoms(contents, max_entries=min(context.limits.max_files * 32, 8192))
        if randoms:
            candidates.append((path, randoms))
    return candidates


def _tls_follow_directions(output: bytes) -> dict[int, bytes]:
    """Parse tshark's follow,tls,raw output into separate directional byte streams."""

    directions: dict[int, bytearray] = defaultdict(bytearray)
    current_node: int | None = None
    for line in output.decode("ascii", errors="replace").splitlines():
        node = re.match(r"^Node\s+(\d+):", line)
        if node:
            current_node = int(node.group(1))
            continue
        if current_node is None:
            continue
        encoded = line.strip()
        if len(encoded) < 2 or len(encoded) % 2 or not _TLS_KEYLOG_HEX_RE.fullmatch(encoded.encode("ascii", errors="ignore")):
            continue
        try:
            directions[current_node].extend(bytes.fromhex(encoded))
        except ValueError:
            continue
    return {node: bytes(payload) for node, payload in directions.items() if payload}


class _TsharkRepeatedJsonValues(list[object]):
    """Keep repeated object keys distinct when decoding TShark's JSON tree."""


def _tshark_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name not in result:
            result[name] = value
            continue
        repeated = result[name]
        if not isinstance(repeated, _TsharkRepeatedJsonValues):
            repeated = _TsharkRepeatedJsonValues([repeated])
            result[name] = repeated
        repeated.append(value)
    return result


def _walk_tshark_json_objects(value: object):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk_tshark_json_objects(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_tshark_json_objects(nested)


def _tshark_json_string(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        for nested in value:
            candidate = _tshark_json_string(nested)
            if candidate is not None:
                return candidate
    return None


def _find_tshark_json_field(value: object, field: str) -> str | None:
    for item in _walk_tshark_json_objects(value):
        if field in item:
            result = _tshark_json_string(item[field])
            if result is not None:
                return result
    return None


def _parse_tshark_http2_headers(output: bytes) -> list[dict[str, object]]:
    """Normalize decoded TShark HTTP/2 header blocks without dropping duplicate keys."""

    try:
        packets = json.loads(output, object_pairs_hook=_tshark_json_object)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []
    if not isinstance(packets, list):
        return []

    records: list[dict[str, object]] = []
    for packet in packets:
        if not isinstance(packet, dict):
            continue
        source = packet.get("_source")
        layers = source.get("layers") if isinstance(source, dict) else None
        if not isinstance(layers, dict):
            continue
        http2 = layers.get("http2")
        for stream in _walk_tshark_json_objects(http2):
            stream_id = _tshark_json_string(stream.get("http2.streamid"))
            if stream_id is None:
                continue
            headers: list[dict[str, str]] = []
            for header in _walk_tshark_json_objects(stream):
                name = _tshark_json_string(header.get("http2.header.name"))
                value = _tshark_json_string(header.get("http2.header.value"))
                if name is not None and value is not None:
                    headers.append({"name": name, "value": value})
            if not headers:
                continue
            records.append(
                {
                    "frame": _find_tshark_json_field(layers.get("frame"), "frame.number"),
                    "tls_stream": _find_tshark_json_field(layers.get("tls"), "tls.stream"),
                    "source_port": _find_tshark_json_field(layers.get("tcp"), "tcp.srcport"),
                    "destination_port": _find_tshark_json_field(layers.get("tcp"), "tcp.dstport"),
                    "http2_stream": stream_id,
                    "uri": _find_tshark_json_field(stream, "http2.request.full_uri"),
                    "headers": headers,
                }
            )
    return records


def _decrypt_tls_with_related_keylog(
    context: SolverContext, artifact_root: Path
) -> tuple[dict[str, object] | None, list[dict[str, object]]]:
    """Decrypt TLS streams only when a related, structurally valid key log matches the capture."""

    keylogs = _tls_keylog_candidates(context)
    if not keylogs:
        return None, []
    tshark = shutil.which("tshark")
    if tshark is None:
        return (
            {
                "name": "decrypt-tls-keylog",
                "status": "needs-review",
                "details": {"error": "tshark is unavailable", "keylog_files": len(keylogs)},
            },
            [],
        )

    deadline = time.monotonic() + context.limits.timeout_seconds
    query_limit = min(context.limits.max_bytes, 2 * 1024 * 1024)
    query_command = [
        tshark,
        "-r",
        str(context.input_path),
        "-Y",
        "tls.handshake.type == 1",
        "-T",
        "fields",
        "-E",
        "separator=,",
        "-E",
        "occurrence=f",
        "-e",
        "tcp.stream",
        "-e",
        "tls.stream",
        "-e",
        "tls.handshake.random",
    ]
    try:
        return_code, query_output, timed_out, truncated = _run_capped(
            query_command,
            timeout_seconds=max(0.1, deadline - time.monotonic()),
            max_output_bytes=query_limit,
        )
    except OSError as exc:
        return (
            {
                "name": "decrypt-tls-keylog",
                "status": "needs-review",
                "details": {"error": f"could not start tshark: {type(exc).__name__}"},
            },
            [],
        )
    if timed_out or truncated or return_code != 0:
        return (
            {
                "name": "decrypt-tls-keylog",
                "status": "needs-review",
                "details": {
                    "error": "TLS stream discovery did not complete",
                    "return_code": return_code,
                    "timed_out": timed_out,
                    "output_truncated": truncated,
                },
            },
            [],
        )

    client_hello_streams: dict[str, set[int]] = defaultdict(set)
    for line in query_output.decode("ascii", errors="replace").splitlines():
        fields = line.split(",", 2)
        if len(fields) != 3 or not fields[0].isdigit() or not fields[1].isdigit():
            continue
        normalized_random = re.sub(r"[^0-9a-fA-F]", "", fields[2]).lower()
        if len(normalized_random) == 64:
            client_hello_streams[normalized_random].add(int(fields[1]))
    matches = [
        (path, randoms, {stream for random in randoms for stream in client_hello_streams.get(random, set())})
        for path, randoms in keylogs
    ]
    matches = [item for item in matches if item[2]]
    if not matches:
        return (
            {
                "name": "decrypt-tls-keylog",
                "status": "needs-review",
                "details": {
                    "error": "no related key log has a client-random match in the capture",
                    "keylog_files": len(keylogs),
                    "client_hello_streams": len(client_hello_streams),
                },
            },
            [],
        )
    query_keylog, keylog_randoms, stream_ids = max(
        matches,
        key=lambda item: (len(item[2]), len(item[1]), item[0].name.lower()),
    )
    stream_ids = set(sorted(stream_ids)[: min(context.limits.max_files, 64)])

    output_budget = context.limits.max_bytes
    direction_outputs: list[dict[str, object]] = []
    partial = False
    for stream_id in sorted(stream_ids):
        if output_budget < 1024 or time.monotonic() >= deadline:
            partial = True
            break
        command = [
            tshark,
            "-r",
            str(context.input_path),
            "-o",
            f"tls.keylog_file:{query_keylog}",
            "-q",
            "-z",
            f"follow,tls,raw,{stream_id}",
        ]
        try:
            return_code, raw_output, timed_out, truncated = _run_capped(
                command,
                timeout_seconds=max(0.1, deadline - time.monotonic()),
                max_output_bytes=min(output_budget, 4 * 1024 * 1024),
            )
        except OSError:
            partial = True
            continue
        output_budget -= len(raw_output)
        if timed_out or truncated or return_code != 0:
            partial = True
        for node, payload in _tls_follow_directions(raw_output).items():
            output = artifact_root / f"tls-stream-{stream_id:03d}-node-{node}.bin"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(payload)
            direction_outputs.append(
                {
                    "stream": stream_id,
                    "node": node,
                    "kind": "tls-direction",
                    "path": str(output),
                    "payload": payload,
                }
            )

    http2_outputs: list[dict[str, object]] = []
    http2_header_outputs: list[dict[str, object]] = []
    http2_header_blocks = 0
    if output_budget >= 1024 and time.monotonic() < deadline:
        tls_filter = " || ".join(f"tls.stream == {stream_id}" for stream_id in sorted(stream_ids))
        http2_command = [
            tshark,
            "-r",
            str(context.input_path),
            "-o",
            f"tls.keylog_file:{query_keylog}",
            "-Y",
            f"http2.data.data && ({tls_filter})",
            "-T",
            "fields",
            "-E",
            "separator=,",
            "-E",
            "aggregator=;",
            "-E",
            "occurrence=a",
            "-e",
            "tls.stream",
            "-e",
            "http2.streamid",
            "-e",
            "tcp.srcport",
            "-e",
            "http2.data.data",
        ]
        try:
            return_code, http2_output, timed_out, truncated = _run_capped(
                http2_command,
                timeout_seconds=max(0.1, deadline - time.monotonic()),
                max_output_bytes=min(output_budget, 4 * 1024 * 1024),
            )
            output_budget -= len(http2_output)
            if timed_out or truncated or return_code != 0:
                partial = True
            grouped_bodies: dict[tuple[int, int, int], bytearray] = defaultdict(bytearray)
            for line in http2_output.decode("ascii", errors="replace").splitlines():
                fields = line.split(",", 3)
                if len(fields) != 4 or not all(field.isdigit() for field in fields[:3]):
                    continue
                tls_stream, h2_stream, source_port = (int(field) for field in fields[:3])
                for encoded in fields[3].split(";"):
                    if not encoded or len(encoded) % 2 or not _TLS_KEYLOG_HEX_RE.fullmatch(encoded.encode("ascii", errors="ignore")):
                        continue
                    try:
                        grouped_bodies[(tls_stream, h2_stream, source_port)].extend(bytes.fromhex(encoded))
                    except ValueError:
                        continue
            for (tls_stream, h2_stream, source_port), body in sorted(grouped_bodies.items()):
                if not body or len(http2_outputs) >= min(context.limits.max_files, 128):
                    continue
                if len(body) > output_budget:
                    partial = True
                    continue
                output = artifact_root / f"tls-http2-{tls_stream:03d}-stream-{h2_stream:04d}-src-{source_port}.bin"
                output.parent.mkdir(parents=True, exist_ok=True)
                payload = bytes(body)
                output.write_bytes(payload)
                output_budget -= len(payload)
                http2_outputs.append(
                    {
                        "stream": tls_stream,
                        "node": source_port,
                        "http2_stream": h2_stream,
                        "kind": "http2-data",
                        "path": str(output),
                        "payload": payload,
                    }
                )
        except OSError:
            partial = True

    if output_budget >= 1024 and time.monotonic() < deadline:
        tls_filter = " || ".join(f"tls.stream == {stream_id}" for stream_id in sorted(stream_ids))
        http2_header_command = [
            tshark,
            "-r",
            str(context.input_path),
            "-o",
            f"tls.keylog_file:{query_keylog}",
            "-Y",
            f"http2.type == 1 && ({tls_filter})",
            "-T",
            "json",
            "-J",
            "frame tcp tls http2",
        ]
        try:
            return_code, header_output, timed_out, truncated = _run_capped(
                http2_header_command,
                timeout_seconds=max(0.1, deadline - time.monotonic()),
                max_output_bytes=min(output_budget, 4 * 1024 * 1024),
            )
            output_budget -= len(header_output)
            if timed_out or truncated or return_code != 0:
                partial = True
            header_records = _parse_tshark_http2_headers(header_output)
            if len(header_records) > min(context.limits.max_files, 512):
                header_records = header_records[: min(context.limits.max_files, 512)]
                partial = True
            http2_header_blocks = len(header_records)
            if not header_records:
                partial = True
            header_payload = bytearray()
            for record in header_records:
                line = json.dumps(record, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
                if len(line) > output_budget - len(header_payload):
                    partial = True
                    break
                header_payload.extend(line)
            if header_payload:
                output = artifact_root / "tls-http2-headers.jsonl"
                output.parent.mkdir(parents=True, exist_ok=True)
                payload = bytes(header_payload)
                output.write_bytes(payload)
                output_budget -= len(payload)
                http2_header_outputs.append(
                    {
                        "kind": "http2-headers",
                        "path": str(output),
                        "payload": payload,
                        "header_blocks": len(header_payload.splitlines()),
                        "tls_streams": sorted(
                            {record["tls_stream"] for record in header_records if record["tls_stream"] is not None}
                        ),
                    }
                )
        except OSError:
            partial = True
    elif time.monotonic() < deadline:
        partial = True

    outputs = direction_outputs + http2_outputs + http2_header_outputs
    decrypted_streams = {item["stream"] for item in direction_outputs + http2_outputs}
    if not outputs:
        status = "needs-review"
    elif partial or len(decrypted_streams) < len(stream_ids):
        status = "partial"
    else:
        status = "ok"
    step = {
        "name": "decrypt-tls-keylog",
        "status": status,
        "details": {
            "keylog_file": str(query_keylog),
            "keylog_entries": len(keylog_randoms),
            "streams": len(decrypted_streams),
            "matched_streams": len(stream_ids),
            "decrypted_directions": len(direction_outputs),
            "http2_data_bodies": len(http2_outputs),
            "http2_header_blocks": http2_header_blocks,
            "http2_header_artifacts": len(http2_header_outputs),
            "outputs": [str(item["path"]) for item in outputs],
            "bytes": sum(len(item["payload"]) for item in outputs),
            "output_limit": context.limits.max_bytes,
        },
    }
    return step, outputs


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png_integrity(data: bytes, *, max_bytes: int, allow_tarp_terminal_damage: bool = False) -> str | None:
    """Validate PNG chunks, with a narrow recoverable terminal case for tARP captures."""

    if len(data) > max_bytes or not data.startswith(PNG_SIGNATURE):
        return None
    offset = len(PNG_SIGNATURE)
    saw_header = False
    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        end = offset + 12 + length
        if length > max_bytes or end > len(data):
            return None
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + length]
        crc = struct.unpack_from(">I", data, offset + 8 + length)[0]
        crc_valid = zlib.crc32(kind + payload) & 0xFFFFFFFF == crc
        terminal_crc_warning = False
        if not crc_valid:
            if allow_tarp_terminal_damage and kind == b"IEND" and length == 0:
                terminal_crc_warning = True
            else:
                return None
        if not saw_header:
            if kind != b"IHDR" or length != 13:
                return None
            saw_header = True
        if kind == b"IEND":
            trailing = data[end:]
            if not saw_header or length != 0:
                return None
            if not trailing:
                return "terminal-crc-warning" if terminal_crc_warning else "valid"
            if len(trailing) <= 3 and trailing == b"\x00" * len(trailing):
                return "valid-with-padding" if not terminal_crc_warning else "terminal-crc-warning"
            if allow_tarp_terminal_damage and terminal_crc_warning and len(trailing) <= 3:
                return "terminal-crc-warning"
            return None
        offset = end
    return None


def _valid_png(data: bytes, *, max_bytes: int) -> bool:
    return _png_integrity(data, max_bytes=max_bytes) is not None


def _repair_tarp_terminal_crc(data: bytes, *, max_bytes: int) -> bytes | None:
    """Repair only a validated PNG's damaged final IEND CRC and short capture tail."""

    if _png_integrity(data, max_bytes=max_bytes, allow_tarp_terminal_damage=True) != "terminal-crc-warning":
        return None
    offset = len(PNG_SIGNATURE)
    while offset + 12 <= len(data):
        length = struct.unpack_from(">I", data, offset)[0]
        end = offset + 12 + length
        if length > max_bytes or end > len(data):
            return None
        kind = data[offset + 4 : offset + 8]
        if kind == b"IEND":
            if length != 0 or len(data[end:]) > 3:
                return None
            expected_crc = zlib.crc32(kind) & 0xFFFFFFFF
            actual_crc = struct.unpack_from(">I", data, offset + 8)[0]
            if actual_crc == expected_crc:
                return None
            repaired = data[: offset + 8] + struct.pack(">I", expected_crc)
            return repaired if _png_integrity(repaired, max_bytes=max_bytes) == "valid" else None
        offset = end
    return None


def _recover_tarp_png(packets: list[dict[str, object]], *, max_bytes: int) -> tuple[bytes, int, str] | None:
    """Find a recoverable PNG embedded in IPv4 ARP target addresses for tARP tasks."""

    output = bytearray()
    ignored_noise = ipaddress.IPv4Network("10.42.10.0/24")
    ignored_addresses = 0
    for packet in packets:
        if packet.get("protocol_name") != "arp":
            continue
        address = bytes(packet.get("target_protocol_address", b""))
        if len(address) != 4:
            continue
        if ipaddress.IPv4Address(address) in ignored_noise:
            ignored_addresses += 1
            continue
        if len(output) + len(address) > max_bytes:
            return None
        output.extend(address)
    stream = bytes(output)
    start = stream.find(PNG_SIGNATURE)
    while start >= 0:
        recovered = stream[start:]
        integrity = _png_integrity(recovered, max_bytes=max_bytes, allow_tarp_terminal_damage=True)
        if integrity is not None:
            if integrity == "terminal-crc-warning":
                repaired = _repair_tarp_terminal_crc(recovered, max_bytes=max_bytes)
                if repaired is None:
                    start = stream.find(PNG_SIGNATURE, start + 1)
                    continue
                return repaired, ignored_addresses, "terminal-crc-repaired"
            return recovered, ignored_addresses, integrity
        start = stream.find(PNG_SIGNATURE, start + 1)
    return None


def _repair_caesar_mojibake_png(data: bytes) -> bytes:
    """Undo UTF-8 mojibake that split original high PNG bytes into C2/C3 pairs."""

    output = bytearray()
    offset = 0
    while offset < len(data):
        current = data[offset]
        if current in {0xC2, 0xC3} and offset + 1 < len(data) and 0x80 <= data[offset + 1] <= 0xBF:
            following = data[offset + 1]
            output.append(following + 64 if current == 0xC3 else following)
            offset += 2
        else:
            output.append(current)
            offset += 1
    return bytes(output)


def _parse_srt_digit_cues(data: bytes) -> list[int]:
    """Read SRT cues whose entire caption is one handwritten digit."""

    text = data.decode("utf-8-sig", errors="replace")
    timestamp = re.compile(
        r"^\d{1,2}:\d{1,2}:\d{1,2}[,.]\d{3}\s+-->\s+\d{1,2}:\d{1,2}:\d{1,2}[,.]\d{3}$"
    )
    values: list[int] = []
    for block in re.split(r"\r?\n\s*\r?\n", text.strip()):
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if len(lines) != 3 or not lines[0].isdigit() or not timestamp.fullmatch(lines[1]):
            continue
        if re.fullmatch(r"[0-9]", lines[2]):
            values.append(int(lines[2]))
    return values


def _decode_subtitle_mismatch_groups(
    subtitle_digits: list[int], video_digits: list[int]
) -> tuple[str, list[dict[str, object]], int]:
    """Decode ASCII bytes from runs where numeric subtitles disagree with video digits."""

    decoded: list[str] = []
    groups: list[dict[str, object]] = []
    current = ""
    mismatch_count = 0

    def finish_group() -> None:
        nonlocal current
        if len(current) > 1:
            value = int(current)
            if 32 <= value <= 126:
                character = chr(value)
                decoded.append(character)
                groups.append({"digits": current, "ascii": value, "character": character})
            else:
                groups.append({"digits": current, "ascii": value, "character": None})
        current = ""

    for subtitle, video in zip(subtitle_digits, video_digits):
        if subtitle != video:
            current += str(subtitle)
            mismatch_count += 1
        elif current:
            finish_group()
    if current:
        finish_group()
    return "".join(decoded), groups, mismatch_count


def _mnist_model_path() -> Path:
    return Path(__file__).resolve().parent / "models" / "mnist-8.onnx"


def _mnist_video_digit_views(frame_bytes: bytes, frame_count: int) -> tuple[str, list[list[dict[str, object]]]]:
    """Classify bounded 28x28 frames with the pinned MNIST model in both polarities."""

    expected_bytes = frame_count * 28 * 28
    if frame_count < 1 or frame_count > MAX_SUBTITLE_FRAMES or len(frame_bytes) != expected_bytes:
        raise ValueError("video frame bytes do not match the bounded 28x28 frame count")
    model_path = _mnist_model_path()
    if not model_path.is_file() or model_path.stat().st_size > 1024 * 1024:
        raise ValueError("pinned MNIST ONNX model is missing or outside size bounds")
    if hashlib.sha256(model_path.read_bytes()).hexdigest() != MNIST_MODEL_SHA256:
        raise ValueError("pinned MNIST ONNX model checksum mismatch")
    try:
        import numpy as np
    except ImportError as exc:
        raise ValueError("NumPy is required for the optional MNIST subtitle solver") from exc

    predict = None
    backend = ""
    try:
        import onnxruntime as ort

        session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
        input_name = session.get_inputs()[0].name

        def predict(image: object) -> object:
            return session.run(None, {input_name: image})[0]

        backend = "onnxruntime"
    except ImportError:
        try:
            import cv2

            network = cv2.dnn.readNetFromONNX(str(model_path))

            def predict(image: object) -> object:
                network.setInput(image)
                return network.forward()

            backend = "opencv-dnn"
        except ImportError as exc:
            raise ValueError("onnxruntime or OpenCV is required for the optional MNIST subtitle solver") from exc

    frames = np.frombuffer(frame_bytes, dtype=np.uint8).reshape(frame_count, 28, 28)
    views: list[list[dict[str, object]]] = []
    for invert in (False, True):
        view: list[dict[str, object]] = []
        for frame in frames:
            image = (255 - frame if invert else frame).astype(np.float32).reshape(1, 1, 28, 28) / 255.0
            logits = np.asarray(predict(image), dtype=np.float32).reshape(-1)
            if logits.size != 10 or not np.isfinite(logits).all():
                raise ValueError("MNIST model returned an invalid digit score vector")
            exponentials = np.exp(logits - logits.max())
            probabilities = exponentials / exponentials.sum()
            digit = int(probabilities.argmax())
            view.append({"digit": digit, "confidence": float(probabilities[digit])})
        views.append(view)
    return backend, views


_SUBTITLE_VIDEO_SUFFIXES = (".mp4", ".mkv", ".mov", ".webm", ".avi", ".m4v")


def _subtitle_video_peer(subtitle_path: Path) -> Path | None:
    """Find a same-stem sibling video for a numeric SRT challenge."""

    for suffix in _SUBTITLE_VIDEO_SUFFIXES:
        candidate = subtitle_path.with_suffix(suffix)
        if candidate.is_file():
            return candidate
    return None


def _extract_subtitle_video_frames(
    video_path: Path, frame_count: int, timeout_seconds: float
) -> tuple[bytes, bytes, int]:
    """Decode a fixed, bounded number of 28x28 grayscale frames with FFmpeg."""

    if frame_count < 1 or frame_count > MAX_SUBTITLE_FRAMES:
        raise ValueError("numeric subtitle frame count is outside the configured bound")
    command = [
        "ffmpeg",
        "-nostdin",
        "-v",
        "error",
        "-threads",
        "1",
        "-i",
        str(video_path),
        "-vf",
        "fps=1,scale=28:28:flags=area",
        "-frames:v",
        str(frame_count),
        "-pix_fmt",
        "gray",
        "-f",
        "rawvideo",
        "pipe:1",
    ]
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
    )
    return completed.stdout, completed.stderr[:65536], int(completed.returncode)


def _solve_numeric_subtitle_video(context: SolverContext) -> SolverResult:
    """Recover text encoded by differences between numeric subtitles and video digits."""

    result = SolverResult("universal-forensics", "forensics", "needs-review")
    subtitle_path = context.input_path
    video_path = _subtitle_video_peer(subtitle_path)
    try:
        subtitle_data = _read_limited(subtitle_path, context.limits.max_bytes)
        subtitle_digits = _parse_srt_digit_cues(subtitle_data)
    except (OSError, ValueError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append({"name": "parse-numeric-subtitles", "status": "error", "details": {"error": result.error}})
        return result

    result.steps.append(
        {
            "name": "parse-numeric-subtitles",
            "status": "ok" if subtitle_digits else "needs-review",
            "details": {"cue_count": len(subtitle_digits), "max_frames": MAX_SUBTITLE_FRAMES},
        }
    )
    if video_path is None:
        result.error = "no same-stem sibling video was found for the numeric SRT file"
        result.steps.append({"name": "match-subtitle-video", "status": "unsupported", "details": {"error": result.error}})
        return result
    if not subtitle_digits or len(subtitle_digits) > MAX_SUBTITLE_FRAMES:
        result.error = "numeric subtitle cue count is empty or exceeds the configured frame limit"
        result.steps.append({"name": "match-subtitle-video", "status": "needs-review", "details": {"error": result.error}})
        return result
    try:
        video_size = video_path.stat().st_size
    except OSError as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append({"name": "match-subtitle-video", "status": "error", "details": {"error": result.error}})
        return result
    if video_size > context.limits.max_bytes:
        result.error = f"video exceeds byte limit: {video_size} > {context.limits.max_bytes}"
        result.steps.append({"name": "match-subtitle-video", "status": "needs-review", "details": {"error": result.error, "video_bytes": video_size}})
        return result

    try:
        frame_bytes, ffmpeg_stderr, ffmpeg_returncode = _extract_subtitle_video_frames(
            video_path, len(subtitle_digits), context.limits.timeout_seconds
        )
    except FileNotFoundError:
        result.error = "ffmpeg is required for the numeric subtitle/video solver"
        result.steps.append({"name": "extract-subtitle-video-frames", "status": "unsupported", "details": {"error": result.error}})
        return result
    except subprocess.TimeoutExpired:
        result.error = f"ffmpeg timed out after {context.limits.timeout_seconds:g}s"
        result.steps.append({"name": "extract-subtitle-video-frames", "status": "timeout", "details": {"error": result.error}})
        return result
    if ffmpeg_returncode != 0:
        result.error = ffmpeg_stderr.decode("utf-8", errors="replace")[-2000:] or f"ffmpeg exited with status {ffmpeg_returncode}"
        result.steps.append({"name": "extract-subtitle-video-frames", "status": "error", "details": {"returncode": ffmpeg_returncode, "error": result.error}})
        return result
    expected_bytes = len(subtitle_digits) * 28 * 28
    if len(frame_bytes) != expected_bytes:
        result.error = f"ffmpeg produced {len(frame_bytes)} bytes; expected {expected_bytes} for {len(subtitle_digits)} frames"
        result.steps.append({"name": "extract-subtitle-video-frames", "status": "needs-review", "details": {"error": result.error, "frames": len(frame_bytes) // (28 * 28), "expected_frames": len(subtitle_digits)}})
        return result

    try:
        backend, digit_views = _mnist_video_digit_views(frame_bytes, len(subtitle_digits))
    except (ImportError, ValueError) as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.steps.append({"name": "classify-video-digits", "status": "unsupported", "details": {"error": result.error}})
        return result

    orientation_records: list[dict[str, object]] = []
    candidate_values: dict[str, dict[str, object]] = {}
    matcher = FlagMatcher()
    for inverted, predictions in zip((False, True), digit_views):
        video_digits = [int(item["digit"]) for item in predictions]
        decoded, groups, mismatch_count = _decode_subtitle_mismatch_groups(subtitle_digits, video_digits)
        equal_count = sum(left == right for left, right in zip(subtitle_digits, video_digits))
        confidence_values = [float(item["confidence"]) for item in predictions]
        orientation = "inverted" if inverted else "normal"
        hits = matcher.scan(
            decoded,
            source=f"{subtitle_path}#video={video_path.name}&polarity={orientation}",
            analyzer="subtitle-video-digit-differential",
        )
        for hit in hits:
            hit.update(
                {
                    "orientation": orientation,
                    "matching_cues": equal_count,
                    "mismatching_cues": mismatch_count,
                    "total_cues": len(subtitle_digits),
                    "video": str(video_path),
                }
            )
            candidate_values.setdefault(str(hit["value"]), hit)
        orientation_records.append(
            {
                "orientation": orientation,
                "subtitle_video_equal_count": equal_count,
                "mismatch_count": mismatch_count,
                "decoded_text": decoded,
                "video_digits": "".join(str(digit) for digit in video_digits),
                "mismatch_groups": groups,
                "mean_digit_confidence": sum(confidence_values) / len(confidence_values) if confidence_values else 0.0,
                "flag_candidates": [str(hit["value"]) for hit in hits],
            }
        )

    result.candidates.extend(candidate_values.values())
    digest = hashlib.sha256(subtitle_data).hexdigest()[:12]
    evidence_path = context.report_dir / "artifacts" / "universal-forensics" / digest / "numeric-subtitles.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_srt": str(subtitle_path),
                "source_srt_sha256": hashlib.sha256(subtitle_data).hexdigest(),
                "source_video": str(video_path),
                "source_video_sha256": hashlib.sha256(video_path.read_bytes()).hexdigest(),
                "mnist_model_sha256": MNIST_MODEL_SHA256,
                "backend": backend,
                "cue_count": len(subtitle_digits),
                "subtitle_digits": "".join(str(digit) for digit in subtitle_digits),
                "orientations": orientation_records,
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    result.artifacts.append(str(evidence_path))
    result.steps.extend(
        [
            {
                "name": "extract-subtitle-video-frames",
                "status": "ok",
                "details": {"video": str(video_path), "frames": len(subtitle_digits), "frame_width": 28, "frame_height": 28, "pixel_format": "gray"},
            },
            {
                "name": "classify-video-digits",
                "status": "ok",
                "details": {"backend": backend, "model_sha256": MNIST_MODEL_SHA256, "polarities": len(digit_views)},
            },
            {
                "name": "decode-subtitle-video-differences",
                "status": "candidate" if len(candidate_values) == 1 else "candidate-review" if candidate_values else "needs-review",
                "details": {"orientations": orientation_records, "evidence": str(evidence_path)},
            },
        ]
    )
    result.status = "candidate" if len(candidate_values) == 1 else "candidate-review" if candidate_values else "needs-review"
    return result


def _extract_json_file_records(
    streams: list[bytes], root: Path, limits: SolverLimits
) -> tuple[list[dict[str, object]], int]:
    """Recover bounded base64 file records from JSONL TCP streams."""

    extracted: list[dict[str, object]] = []
    seen_digests: set[str] = set()
    total_bytes = 0
    skipped = 0
    max_records = min(limits.max_files, 256)
    max_encoded_bytes = ((limits.max_bytes + 2) // 3) * 4 + 4

    for stream_index, stream in enumerate(streams):
        for line_number, line in enumerate(stream.splitlines(), 1):
            if len(extracted) >= max_records or total_bytes >= limits.max_bytes:
                skipped += 1
                continue
            if len(line) > max_encoded_bytes:
                skipped += 1
                continue
            try:
                record = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if not isinstance(record, dict) or record.get("type") != "file":
                continue
            guest_path = record.get("path")
            encoded_value = record.get("data")
            if not isinstance(guest_path, str) or not guest_path or len(guest_path) > 4096 or "\x00" in guest_path:
                skipped += 1
                continue
            if not isinstance(encoded_value, str) or len(encoded_value) > max_encoded_bytes:
                skipped += 1
                continue
            try:
                encoded = encoded_value.encode("ascii")
            except UnicodeEncodeError:
                skipped += 1
                continue
            unpadded = encoded.rstrip(b"=")
            if len(encoded) - len(unpadded) > 2 or b"=" in unpadded:
                skipped += 1
                continue
            normalized = unpadded.replace(b"-", b"+").replace(b"_", b"/")
            padded = normalized + b"=" * (-len(normalized) % 4)
            try:
                payload = base64.b64decode(padded, validate=True)
            except (ValueError, binascii.Error):
                skipped += 1
                continue
            if base64.b64encode(payload).rstrip(b"=") != normalized:
                skipped += 1
                continue
            if not payload or len(payload) > limits.max_bytes or total_bytes + len(payload) > limits.max_bytes:
                skipped += 1
                continue
            digest = hashlib.sha256(payload).hexdigest()
            if digest in seen_digests:
                continue
            seen_digests.add(digest)

            leaf = PurePosixPath(guest_path.replace("\\", "/")).name
            safe_leaf = re.sub(r"[^A-Za-z0-9_.-]+", "_", leaf).strip("._")[:120] or "file.bin"
            output = root / f"stream-{stream_index:03d}-file-{len(extracted):03d}-{safe_leaf}"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(payload)
            total_bytes += len(payload)
            extracted.append(
                {
                    "stream": stream_index,
                    "line": line_number,
                    "guest_path": guest_path,
                    "output": str(output),
                    "bytes": len(payload),
                    "sha256": digest,
                }
            )
    return extracted, skipped


def reassemble_streams(packets: list[dict[str, object]], limits: SolverLimits) -> list[bytes]:
    groups: dict[tuple[object, ...], list[tuple[int, bytes]]] = defaultdict(list)
    for packet in packets:
        if packet.get("protocol_name") != "tcp":
            continue
        payload = bytes(packet.get("payload", b""))
        if not payload:
            continue
        key = (
            packet.get("source"),
            packet.get("source_port"),
            packet.get("target"),
            packet.get("target_port"),
        )
        groups[key].append((int(packet.get("sequence", 0)), payload))
    streams: list[bytes] = []
    for segments in groups.values():
        output = bytearray()
        end = None
        for sequence, payload in sorted(segments):
            if end is None:
                output.extend(payload)
                end = sequence + len(payload)
                continue
            if sequence >= end:
                output.extend(payload)
                end = sequence + len(payload)
            else:
                overlap = end - sequence
                if overlap < len(payload):
                    output.extend(payload[overlap:])
                    end += len(payload) - overlap
            if len(output) > limits.max_bytes:
                raise ValueError("reassembled stream exceeds byte limit")
        streams.append(bytes(output))
        if len(streams) >= limits.max_files:
            break
    return streams


def _flag_hits(data: bytes, source: str, analyzer: str) -> list[dict[str, object]]:
    return FlagMatcher().scan(data.decode("utf-8", errors="replace"), source=source, analyzer=analyzer)


def _http_messages(stream: bytes) -> list[tuple[bytes, dict[bytes, bytes], bytes]]:
    messages: list[tuple[bytes, dict[bytes, bytes], bytes]] = []
    offset = 0
    while offset < len(stream):
        header_end = stream.find(b"\r\n\r\n", offset)
        if header_end < 0:
            break
        lines = stream[offset:header_end].split(b"\r\n")
        if not lines or not re.match(rb"(?:[A-Z]+ \S+ HTTP/1\.[01]|HTTP/1\.[01] \d{3})$", lines[0]):
            break
        headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            if b":" in line:
                key, value = line.split(b":", 1)
                headers[key.strip().lower()] = value.strip()
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            break
        body_start = header_end + 4
        body_end = body_start + content_length
        if body_end > len(stream):
            break
        messages.append((lines[0], headers, stream[body_start:body_end]))
        if body_end <= offset:
            break
        offset = body_end
    return messages


_HTTP_UA_PRODUCT_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])([A-Za-z][A-Za-z0-9_.+-]*)/([0-9][A-Za-z0-9.+_-]*)"
)
_HTTP_UA_GENERIC_PRODUCTS = {
    "applewebkit",
    "chrome",
    "chromium",
    "compatible",
    "edge",
    "edg",
    "firefox",
    "gecko",
    "mozilla",
    "opr",
    "opera",
    "rv",
    "safari",
    "trident",
    "version",
}


def _http_user_agent_tool_version_answer(
    task_text: str,
    streams: list[bytes],
) -> dict[str, object] | None:
    """Build a local answer candidate only for prompts requesting a wrapped tool/version."""
    if not re.search(r"\btool\b.{0,200}\bversion\b", task_text, flags=re.IGNORECASE | re.DOTALL):
        return None
    if not re.search(r"\bwrap\b.{0,100}\banswer\b", task_text, flags=re.IGNORECASE | re.DOTALL):
        return None
    example = re.search(
        r"\b([A-Za-z][A-Za-z0-9_]*)\s*\{\s*[A-Za-z][A-Za-z0-9_.-]*_[0-9][A-Za-z0-9_.-]*\s*\}",
        task_text,
    )
    if example is None:
        return None

    observations: dict[tuple[str, str], dict[str, object]] = {}
    for stream_index, stream in enumerate(streams):
        for message_index, (_start, headers, _body) in enumerate(_http_messages(stream)):
            raw_user_agent = headers.get(b"user-agent")
            if not raw_user_agent:
                continue
            user_agent = raw_user_agent.decode("latin-1", errors="replace")
            products = {
                (match.group(1), match.group(2))
                for match in _HTTP_UA_PRODUCT_RE.finditer(user_agent)
                if match.group(1).casefold() not in _HTTP_UA_GENERIC_PRODUCTS
            }
            for product, version in products:
                key = (product.casefold(), version)
                observation = observations.setdefault(
                    key,
                    {"product": product, "version": version, "count": 0, "samples": []},
                )
                observation["count"] = int(observation["count"]) + 1
                samples = observation["samples"]
                if isinstance(samples, list) and user_agent not in samples and len(samples) < 3:
                    samples.append(user_agent)
                observation["last_stream"] = stream_index
                observation["last_message"] = message_index

    if not observations:
        return None
    ranked = sorted(observations.values(), key=lambda item: (-int(item["count"]), str(item["product"]).casefold(), str(item["version"])))
    if len(ranked) > 1 and int(ranked[0]["count"]) == int(ranked[1]["count"]):
        return None

    winner = ranked[0]
    product = str(winner["product"])
    version = str(winner["version"])
    token = re.sub(r"[^A-Za-z0-9]+", "_", product).strip("_").lower()
    if not token:
        return None
    prefix = example.group(1)
    return {
        "value": f"{prefix}{{{token}_{version}}}",
        "product": product,
        "version": version,
        "observations": int(winner["count"]),
        "samples": list(winner["samples"]),
        "stream": winner.get("last_stream"),
        "message": winner.get("last_message"),
        "other_product_versions": [
            {"product": item["product"], "version": item["version"], "observations": item["count"]}
            for item in ranked[1:6]
        ],
    }


def _http_base64_query_views(
    streams: list[bytes], limits: SolverLimits
) -> list[dict[str, object]]:
    views: list[dict[str, object]] = []
    decoded_bytes = 0
    max_views = min(limits.max_files, 128)
    max_token_bytes = min(limits.max_bytes, 1024 * 1024)
    if max_views <= 0 or max_token_bytes < 8:
        return views

    for stream_index, stream in enumerate(streams):
        if len(views) >= max_views or decoded_bytes >= limits.max_bytes:
            break
        for message_index, (start_line, _headers, _body) in enumerate(_http_messages(stream)):
            parts = start_line.split(b" ", 2)
            if len(parts) < 2 or not re.fullmatch(rb"[A-Z]+", parts[0]):
                continue
            try:
                query = urlsplit(parts[1].decode("ascii")).query
                fields = parse_qs(query, keep_blank_values=False, max_num_fields=64)
            except (UnicodeDecodeError, ValueError):
                continue

            for parameter, values in fields.items():
                for value in values:
                    if len(views) >= max_views or decoded_bytes >= limits.max_bytes:
                        break
                    if len(value) < 8 or len(value) > max_token_bytes:
                        continue
                    try:
                        token = value.encode("ascii")
                    except UnicodeEncodeError:
                        continue
                    if re.fullmatch(rb"[A-Za-z0-9+/_-]+={0,2}", token) is None:
                        continue

                    standard_token = token.replace(b"-", b"+").replace(b"_", b"/")
                    unpadded = standard_token.rstrip(b"=")
                    supplied_padding = len(standard_token) - len(unpadded)
                    if b"=" in unpadded or supplied_padding > 2 or len(unpadded) % 4 == 1:
                        continue
                    required_padding = -len(unpadded) % 4
                    if supplied_padding and (
                        len(standard_token) % 4 != 0 or supplied_padding != required_padding
                    ):
                        continue
                    padded = unpadded + b"=" * required_padding
                    try:
                        decoded = base64.b64decode(padded, validate=True)
                    except (ValueError, binascii.Error):
                        continue
                    if not decoded or base64.b64encode(decoded).rstrip(b"=") != unpadded:
                        continue
                    if decoded_bytes + len(decoded) > limits.max_bytes:
                        continue

                    views.append(
                        {
                            "stream": stream_index,
                            "message": message_index,
                            "parameter": parameter,
                            "decoded": decoded,
                        }
                    )
                    decoded_bytes += len(decoded)
                if len(views) >= max_views or decoded_bytes >= limits.max_bytes:
                    break
    return views


def _recover_positioned_note_value(streams: list[bytes]) -> dict[str, object] | None:
    observations: dict[int, list[dict[str, object]]] = defaultdict(list)
    position_pattern = re.compile(r"\bflag(?:\s+\d+)?\b.*?\bcharacter\b.*?\bposition\s*[:#]?\s*(\d+)\b", re.IGNORECASE)
    for stream_index, stream in enumerate(streams):
        for start_line, headers, body in _http_messages(stream):
            if not start_line.startswith(b"POST "):
                continue
            content_type = headers.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
            if content_type != b"application/x-www-form-urlencoded":
                continue
            try:
                fields = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True, max_num_fields=64)
            except ValueError:
                continue
            names = fields.get("name", [])
            descriptions = fields.get("desc", [])
            if not names or not descriptions:
                continue
            match = position_pattern.search(names[0])
            description = descriptions[0]
            if match is None or len(description) < 4 or len(set(description)) != 1 or not description[0].isprintable():
                continue
            position = int(match.group(1))
            if position > 4096:
                continue
            observations[position].append({"character": description[0], "stream": stream_index})

    if len(observations) < 5:
        return None
    max_position = max(observations)
    if set(observations) != set(range(max_position + 1)):
        return None
    rows: list[dict[str, object]] = []
    characters: list[str] = []
    for position in range(max_position + 1):
        unique = {str(item["character"]) for item in observations[position]}
        if len(unique) != 1:
            return None
        character = next(iter(unique))
        characters.append(character)
        rows.append(
            {
                "position": position,
                "character": character,
                "observations": len(observations[position]),
                "streams": sorted({int(item["stream"]) for item in observations[position]}),
            }
        )
    return {"value": "".join(characters), "positions": rows}


def inspect_database_or_logs(path: Path, limits: SolverLimits) -> list[dict[str, object]]:
    data = _read_limited(path, limits.max_bytes)
    if data.startswith(b"SQLite format 3\x00") or path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
        connection: sqlite3.Connection | None = None
        records: list[dict[str, object]] = []
        try:
            connection = sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
            tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").fetchall()
            for (table_name,) in tables[:limits.max_files]:
                safe_table = '"' + str(table_name).replace('"', '""') + '"'
                columns = connection.execute(f"PRAGMA table_info({safe_table})").fetchall()
                column_names = [str(row[1]) for row in columns]
                order = " ORDER BY seq" if "seq" in column_names else ""
                rows = connection.execute(f"SELECT * FROM {safe_table}{order} LIMIT ?", (limits.max_files,)).fetchall()
                if "seq" in column_names and "value" in column_names:
                    seq_index = column_names.index("seq")
                    value_index = column_names.index("value")
                    pieces: list[str] = []
                    for row in rows:
                        value = str(row[value_index]).strip()
                        if value and len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
                            pieces.append(value)
                    if pieces:
                        try:
                            records.append(
                                {
                                    "table": table_name,
                                    "column": "value",
                                    "value": bytes.fromhex("".join(pieces)),
                                    "encoding": "hex-concat",
                                }
                            )
                        except ValueError:
                            pass
                for row in rows:
                    for column, value in zip(column_names, row):
                        if value is None:
                            continue
                        if isinstance(value, bytes):
                            records.append({"table": table_name, "column": column, "value": value})
                        else:
                            text = str(value)
                            records.append({"table": table_name, "column": column, "value": text.encode("utf-8")})
                            if len(text) % 2 == 0 and len(text) >= 8 and re.fullmatch(r"[0-9a-fA-F]+", text):
                                try:
                                    records.append({"table": table_name, "column": column, "value": bytes.fromhex(text), "encoding": "hex"})
                                except ValueError:
                                    pass
            return records[: limits.max_files * 8]
        finally:
            if connection is not None:
                connection.close()

    records = [{"source": str(path), "value": data}]
    for view in encoded_views(data, max_bytes=limits.max_bytes):
        records.append({"source": f"{path}#encoding={view['encoding']}", "value": bytes(view["decoded"]), "encoding": view["encoding"]})
    return records[: limits.max_files * 4]


_GPP_CPASSWORD_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"
)
_GPP_CPASSWORD_ATTR_RE = re.compile(rb"(?i)\bcpassword\s*=")


def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt one bounded AES-CBC value using an installed Python backend."""

    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        try:
            from Crypto.Cipher import AES
        except ImportError as exc:
            raise ImportError("install requirements-optional-forensics.txt for AES support") from exc
        return AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _gpp_cpassword_records(data: bytes, *, max_records: int) -> list[dict[str, str]]:
    """Extract and decrypt Group Policy Preferences cpassword attributes."""

    document = ET.fromstring(data)
    records: list[dict[str, str]] = []
    stack: list[tuple[ET.Element, str]] = [(document, "")]
    visited = 0
    while stack and len(records) < max_records and visited < max_records * 64:
        element, account = stack.pop()
        visited += 1
        tag = str(element.tag).rsplit("}", 1)[-1].casefold()
        if tag in {"user", "computer"}:
            account = element.attrib.get("name") or element.attrib.get("username") or account
        encoded = element.attrib.get("cpassword")
        if encoded:
            compact = re.sub(r"\s+", "", encoded)
            ciphertext = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
            if not ciphertext or len(ciphertext) % 16:
                raise ValueError("cpassword is not a non-empty AES block sequence")
            plaintext = _aes_cbc_decrypt(ciphertext, _GPP_CPASSWORD_KEY, bytes(16))
            padding = plaintext[-1]
            if not 1 <= padding <= 16 or plaintext[-padding:] != bytes([padding]) * padding:
                raise ValueError("cpassword has invalid PKCS#7 padding")
            password = plaintext[:-padding].decode("utf-16-le").rstrip("\x00")
            records.append({"account": account, "password": password})
        stack.extend((child, account) for child in reversed(list(element)))
    return records


class ForensicsSolver:
    name = "universal-forensics"
    category = "forensics"

    def detect(self, context: SolverContext) -> Detection | None:
        kind = str(context.classification.get("kind", ""))
        suffix = context.input_path.suffix.lower()
        task = (context.task_text or "").lower()
        prefix = _read_prefix(context.input_path, 16)
        magic = prefix[:8]
        is_ewf = magic in EWF_MAGICS or suffix in EWF_SUFFIXES
        if is_ewf:
            return Detection(
                self.name,
                self.category,
                85,
                "EWF disk image signature or segment suffix",
                {"kind": "ewf", "ewf_magic": magic in EWF_MAGICS, "suffix": suffix},
            )
        if suffix in {".xml", ".cmtx"} or kind == "text":
            try:
                text_sample = _read_limited(context.input_path, min(context.limits.max_bytes, 4 * 1024 * 1024))
            except (OSError, ValueError):
                text_sample = b""
            if _GPP_CPASSWORD_ATTR_RE.search(text_sample):
                return Detection(
                    self.name,
                    self.category,
                    100,
                    "Group Policy Preferences cpassword attribute",
                    {"kind": "gpp-cpassword", "suffix": suffix},
                )
        if suffix == ".srt":
            try:
                subtitle_count = len(_parse_srt_digit_cues(_read_limited(context.input_path, context.limits.max_bytes)))
            except (OSError, ValueError):
                subtitle_count = 0
            video_path = _subtitle_video_peer(context.input_path)
            if subtitle_count >= 2 and video_path is not None:
                return Detection(
                    self.name,
                    self.category,
                    90,
                    "numeric SRT cues are paired with a same-stem video",
                    {
                        "kind": "numeric-subtitle-video",
                        "subtitle_cues": subtitle_count,
                        "video_path": str(video_path),
                    },
                )
        if suffix == ".png" and not magic.startswith(PNG_SIGNATURE) and "caesar" in task and "png" in task:
            return Detection(
                self.name,
                self.category,
                85,
                "task describes a Caesar-corrupted PNG",
                {"kind": "caesar-mojibake-png", "suffix": suffix},
            )
        is_sqlite = prefix.startswith(b"SQLite format 3\x00")
        is_pcap = prefix[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"M\x3c\xb2\xa1", b"\xa1\xb2<M"}
        is_pcapng = prefix[:4] == PCAPNG_MAGIC
        if is_sqlite or is_pcap or is_pcapng or kind in {"pcap", "network", "memory", "database", "text"} or suffix in {".pcap", ".pcapng", ".cap", ".db", ".sqlite", ".sqlite3", ".log"} or any(word in task for word in ("pcap", "sqlite", "memory dump", "log")):
            score = 80 if kind in {"pcap", "database"} or "pcap" in task or "sqlite" in task else 35
            return Detection(self.name, self.category, score, "forensics signature", {"kind": kind, "suffix": suffix, "sqlite_magic": is_sqlite, "pcap_magic": is_pcap, "pcapng_magic": is_pcapng})
        return None

    def solve(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "unsupported")
        if context.input_path.suffix.lower() == ".srt" and _subtitle_video_peer(context.input_path) is not None:
            try:
                subtitle_bytes = _read_limited(context.input_path, context.limits.max_bytes)
                if len(_parse_srt_digit_cues(subtitle_bytes)) >= 2:
                    return _solve_numeric_subtitle_video(context)
            except (OSError, ValueError):
                pass
        if _ewf_magic(context.input_path) in EWF_MAGICS or context.input_path.suffix.lower() in EWF_SUFFIXES:
            return _triage_ewf(context)
        try:
            data = _read_limited(context.input_path, context.limits.max_bytes)
            digest = hashlib.sha256(data).hexdigest()[:12]
            root = context.report_dir / "artifacts" / "universal-forensics" / digest
            matcher = FlagMatcher()
            wrote = False

            def add_hits(payload: bytes, source: str, analyzer: str, **metadata: object) -> None:
                for hit in matcher.scan(payload.decode("utf-8", errors="replace"), source=source, analyzer=analyzer):
                    hit.update(metadata)
                    if not any(existing.get("value") == hit.get("value") for existing in result.candidates):
                        result.candidates.append(hit)

            if _GPP_CPASSWORD_ATTR_RE.search(data):
                try:
                    credentials = _gpp_cpassword_records(
                        data,
                        max_records=min(context.limits.max_files, 256),
                    )
                except ImportError as exc:
                    result.status = "needs-review"
                    result.steps.append(
                        {
                            "name": "decrypt-gpp-cpassword",
                            "status": "needs-review",
                            "details": {"executed": False, "reason": str(exc)},
                        }
                    )
                    return result
                except (ET.ParseError, ValueError, UnicodeDecodeError) as exc:
                    result.status = "needs-review"
                    result.steps.append(
                        {
                            "name": "decrypt-gpp-cpassword",
                            "status": "needs-review",
                            "details": {"executed": False, "reason": f"{type(exc).__name__}: {exc}"},
                        }
                    )
                    return result

                credential_paths: list[str] = []
                accounts: list[str] = []
                for index, credential in enumerate(credentials):
                    account = credential["account"]
                    password = credential["password"]
                    accounts.append(account)
                    output_path = root / f"gpp-cpassword-{index:03d}.txt"
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text(f"account={account}\npassword={password}\n", encoding="utf-8")
                    credential_paths.append(str(output_path))
                    result.artifacts.append(str(output_path))
                    for hit in matcher.scan(
                        password,
                        source=str(output_path),
                        analyzer="gpp-cpassword",
                    ):
                        hit["account"] = account
                        if not any(existing.get("value") == hit.get("value") for existing in result.candidates):
                            result.candidates.append(hit)
                result.steps.append(
                    {
                        "name": "decrypt-gpp-cpassword",
                        "status": "candidate" if result.candidates else "needs-review",
                        "details": {
                            "executed": False,
                            "algorithm": "AES-256-CBC",
                            "records": len(credentials),
                            "accounts": accounts,
                            "credential_artifacts": credential_paths,
                        },
                    }
                )
                result.status = "candidate" if result.candidates else "needs-review"
                return result

            task_text = (context.task_text or "").lower()
            is_caesar_png = (
                context.input_path.suffix.lower() == ".png"
                and not data.startswith(PNG_SIGNATURE)
                and "caesar" in task_text
                and "png" in task_text
            )
            if is_caesar_png:
                repaired = _repair_caesar_mojibake_png(data)
                integrity = _png_integrity(repaired, max_bytes=context.limits.max_bytes)
                if integrity is not None:
                    repaired_path = root / "caesar-recovered.png"
                    repaired_path.parent.mkdir(parents=True, exist_ok=True)
                    repaired_path.write_bytes(repaired)
                    result.artifacts.append(str(repaired_path))
                    result.derived_inputs.append(str(repaired_path))
                    add_hits(repaired, str(repaired_path), "caesar-mojibake-png", integrity=integrity)
                    result.steps.append(
                        {
                            "name": "repair-caesar-mojibake-png",
                            "status": "ok",
                            "details": {
                                "output": str(repaired_path),
                                "bytes": len(repaired),
                                "integrity": integrity,
                            },
                        }
                    )
                    wrote = True
                else:
                    result.steps.append(
                        {
                            "name": "repair-caesar-mojibake-png",
                            "status": "needs-review",
                            "details": {"error": "repaired data did not pass PNG chunk and CRC checks"},
                        }
                    )
            elif data[:4] in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"M\x3c\xb2\xa1", b"\xa1\xb2<M", PCAPNG_MAGIC} or context.input_path.suffix.lower() in {".pcap", ".pcapng", ".cap"}:
                packets = parse_pcap(context.input_path, context.limits)
                task_text = (context.task_text or "").lower()
                if "tarp" in task_text:
                    arp_packets = sum(packet.get("protocol_name") == "arp" for packet in packets)
                    tarp_recovery = _recover_tarp_png(packets, max_bytes=context.limits.max_bytes)
                    recovered_png = tarp_recovery[0] if tarp_recovery is not None else None
                    ignored_addresses = tarp_recovery[1] if tarp_recovery is not None else 0
                    integrity = tarp_recovery[2] if tarp_recovery is not None else "not-recovered"
                    tarp_step: dict[str, object] = {
                        "name": "recover-tarp-png",
                        "status": "needs-review" if integrity == "terminal-crc-warning" else "ok" if recovered_png is not None else "needs-review",
                        "details": {
                            "arp_packets": arp_packets,
                            "ignored_local_target_addresses": ignored_addresses,
                            "integrity": integrity,
                        },
                    }
                    if recovered_png is not None:
                        tarp_path = root / "tarp-recovered.png"
                        tarp_path.parent.mkdir(parents=True, exist_ok=True)
                        tarp_path.write_bytes(recovered_png)
                        result.artifacts.append(str(tarp_path))
                        result.derived_inputs.append(str(tarp_path))
                        add_hits(recovered_png, str(tarp_path), "pcap-tarp-png", arp_packets=arp_packets)
                        tarp_step["details"].update({"output": str(tarp_path), "bytes": len(recovered_png)})
                        wrote = True
                    result.steps.append(tarp_step)
                streams = reassemble_streams(packets, context.limits)
                tls_step, tls_outputs = _decrypt_tls_with_related_keylog(context, root)
                if tls_step is not None:
                    result.steps.append(tls_step)
                    for decrypted in tls_outputs:
                        output_path = str(decrypted["path"])
                        payload = bytes(decrypted["payload"])
                        result.artifacts.append(output_path)
                        result.derived_inputs.append(output_path)
                        evidence = {
                            "transport_view": str(decrypted["kind"]),
                        }
                        if decrypted["kind"] == "http2-data":
                            evidence["tls_stream"] = decrypted["stream"]
                            evidence["http2_stream"] = decrypted["http2_stream"]
                            evidence["source_port"] = decrypted["node"]
                        elif decrypted["kind"] == "http2-headers":
                            evidence["http2_header_blocks"] = decrypted["header_blocks"]
                            evidence["tls_streams"] = decrypted["tls_streams"]
                        else:
                            evidence["tls_stream"] = decrypted["stream"]
                            evidence["direction"] = decrypted["node"]
                        add_hits(
                            payload,
                            output_path,
                            "pcap-tls-decrypted",
                            **evidence,
                        )
                        wrote = True
                tool_answer = _http_user_agent_tool_version_answer(context.task_text or "", streams)
                if tool_answer is not None:
                    answer_path = root / "http-user-agent-tool-version.json"
                    answer_path.parent.mkdir(parents=True, exist_ok=True)
                    answer_path.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "source": str(context.input_path),
                                "source_sha256": hashlib.sha256(data).hexdigest(),
                                **tool_answer,
                            },
                            ensure_ascii=False,
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    result.artifacts.append(str(answer_path))
                    wrote = True
                    add_hits(
                        str(tool_answer["value"]).encode("utf-8"),
                        str(answer_path),
                        "pcap-http-user-agent-answer",
                        product=tool_answer["product"],
                        version=tool_answer["version"],
                        observations=tool_answer["observations"],
                    )
                    result.steps.append(
                        {
                            "name": "derive-tool-version-from-http-user-agent",
                            "status": "candidate",
                            "details": {
                                "output": str(answer_path),
                                "product": tool_answer["product"],
                                "version": tool_answer["version"],
                                "observations": tool_answer["observations"],
                                "samples": tool_answer["samples"],
                                "other_product_versions": tool_answer["other_product_versions"],
                            },
                        }
                    )
                file_records, skipped_file_records = _extract_json_file_records(
                    streams, root / "recovered-files", context.limits
                )
                extracted_file_bytes = 0
                for record in file_records:
                    output = Path(str(record["output"]))
                    result.artifacts.append(str(output))
                    result.derived_inputs.append(str(output))
                    extracted_file_bytes += int(record["bytes"])
                    add_hits(
                        output.read_bytes(),
                        str(output),
                        "pcap-json-file-record",
                        stream=record["stream"],
                        line=record["line"],
                        guest_path=record["guest_path"],
                    )
                result.steps.append(
                    {
                        "name": "extract-jsonl-file-records",
                        "status": "partial" if skipped_file_records else "ok",
                        "details": {
                            "extracted_files": len(file_records),
                            "extracted_bytes": extracted_file_bytes,
                            "skipped_records": skipped_file_records,
                            "max_files": min(context.limits.max_files, 256),
                            "max_bytes": context.limits.max_bytes,
                        },
                    }
                )
                http_query_views = _http_base64_query_views(streams, context.limits)
                http_query_bytes = 0
                http_query_index: list[dict[str, object]] = []
                for index, view in enumerate(http_query_views):
                    decoded = bytes(view["decoded"])
                    query_path = root / f"http-query-{index:03d}.bin"
                    query_path.parent.mkdir(parents=True, exist_ok=True)
                    query_path.write_bytes(decoded)
                    result.artifacts.append(str(query_path))
                    wrote = True
                    http_query_bytes += len(decoded)
                    http_query_index.append(
                        {
                            "stream": view["stream"],
                            "stream_artifact": str(root / f"stream-{int(view['stream']):03d}.bin"),
                            "http_message": view["message"],
                            "query_parameter": view["parameter"],
                            "encoding": "base64",
                            "output": str(query_path),
                            "bytes": len(decoded),
                        }
                    )
                    add_hits(
                        decoded,
                        str(query_path),
                        "pcap-http-query-base64",
                        stream=view["stream"],
                        http_message=view["message"],
                        query_parameter=view["parameter"],
                    )
                query_step: dict[str, object] = {
                    "name": "decode-http-query-base64",
                    "status": "ok",
                    "details": {
                        "decoded_values": len(http_query_views),
                        "decoded_bytes": http_query_bytes,
                        "max_values": min(context.limits.max_files, 128),
                        "max_bytes": context.limits.max_bytes,
                    },
                }
                result.steps.append(query_step)
                for index, stream in enumerate(streams):
                    stream_path = root / f"stream-{index:03d}.bin"
                    stream_path.parent.mkdir(parents=True, exist_ok=True)
                    stream_path.write_bytes(stream)
                    result.artifacts.append(str(stream_path))
                    wrote = True
                    add_hits(stream, str(stream_path), "pcap-tcp-stream", stream=index)
                    for token in re.findall(rb"Bearer\s+([A-Za-z0-9+/=_-]{8,})", stream, flags=re.IGNORECASE):
                        padded = token + b"=" * (-len(token) % 4)
                        try:
                            decoded = base64.urlsafe_b64decode(padded)
                        except (ValueError, TypeError):
                            continue
                        add_hits(decoded, f"{stream_path}#bearer", "pcap-bearer", stream=index)
                if http_query_index:
                    index_path = root / "http-query-index.json"
                    index_path.write_text(
                        json.dumps(
                            {
                                "schema_version": 1,
                                "source": str(context.input_path),
                                "source_sha256": hashlib.sha256(data).hexdigest(),
                                "values": http_query_index,
                            },
                            ensure_ascii=False,
                            indent=2,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    result.artifacts.append(str(index_path))
                    query_step["details"]["index"] = str(index_path)
                positioned = _recover_positioned_note_value(streams)
                if positioned is not None:
                    recovered_text = str(positioned["value"])
                    hits = matcher.scan(recovered_text, source=str(context.input_path), analyzer="pcap-http-positioned-form")
                    if hits:
                        position_path = root / "http-positioned-characters.json"
                        position_path.parent.mkdir(parents=True, exist_ok=True)
                        position_path.write_text(json.dumps(positioned, indent=2) + "\n", encoding="utf-8")
                        result.artifacts.append(str(position_path))
                        wrote = True
                        result.steps.append(
                            {
                                "name": "reassemble-positioned-note-characters",
                                "status": "ok",
                                "details": {"positions": len(positioned["positions"]), "output": str(position_path)},
                            }
                        )
                        add_hits(recovered_text.encode("utf-8"), str(position_path), "pcap-http-positioned-form")
                for packet in packets:
                    payload = bytes(packet.get("payload", b""))
                    if payload:
                        add_hits(payload, str(context.input_path), "pcap-payload")
                    if packet.get("dns_name"):
                        add_hits(str(packet["dns_name"]).encode(), str(context.input_path), "pcap-dns")
                    labels = packet.get("dns_labels")
                    if isinstance(labels, list):
                        for index, (decoded, metadata) in enumerate(_dns_base32_views([str(item) for item in labels], max_views=context.limits.max_files)):
                            path = root / f"dns-base32-{index:03d}.bin"
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_bytes(decoded)
                            result.artifacts.append(str(path))
                            wrote = True
                            add_hits(decoded, f"{path}#labels", "pcap-dns-base32", **metadata)
                packet_limit_reached = any(packet.get("packet_limit_reached") for packet in packets)
                result.steps.append(
                    {
                        "name": "parse-pcap",
                        "status": "partial" if packet_limit_reached else "ok",
                        "details": {
                            "format": "pcapng" if data[:4] == PCAPNG_MAGIC else "pcap",
                            "packets": len(packets),
                            "streams": len(streams),
                            "packet_limit_reached": packet_limit_reached,
                            "packet_limit": MAX_PCAP_PACKETS,
                        },
                    }
                )
            elif data.startswith(b"SQLite format 3\x00") or context.input_path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}:
                records = inspect_database_or_logs(context.input_path, context.limits)
                for index, record in enumerate(records):
                    payload = bytes(record["value"])
                    add_hits(payload, str(context.input_path), "sqlite-cell", table=record.get("table"), column=record.get("column"), encoding=record.get("encoding"))
                    if index < context.limits.max_files:
                        path = root / f"cell-{index:03d}.bin"
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(payload)
                        result.artifacts.append(str(path))
                        wrote = True
                result.steps.append({"name": "inspect-sqlite", "status": "ok", "details": {"records": len(records)}})
            else:
                records = inspect_database_or_logs(context.input_path, context.limits)
                for record in records:
                    add_hits(bytes(record["value"]), str(record.get("source", context.input_path)), "log-or-encoded")
                result.steps.append({"name": "inspect-text", "status": "ok", "details": {"records": len(records)}})

            if result.candidates:
                result.status = "candidate"
            elif wrote:
                result.status = "derived"
            else:
                result.status = "unsupported"
        except Exception as exc:
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
            result.steps.append({"name": "solve", "status": "error", "details": {"error": result.error}})
        return result
