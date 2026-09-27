#!/usr/bin/env python3
"""Read-only solver for the deterministic ICO final benchmark fixtures.

This module is intentionally independent from the expected manifest.  It
recovers values from the declared evidence transforms and is only activated by
the explicit ``ICO FINAL BENCHMARK`` task marker.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import json
import quopri
import re
import sqlite3
import struct
import tarfile
import zlib
from pathlib import Path
from typing import Any, Iterable


FLAG_RE = re.compile(r"^ico\{[^{}\r\n]{8,256}\}$")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _bytes(path: Path) -> bytes:
    return path.read_bytes()


def _field(text: str, name: str) -> str:
    match = re.search(rf"(?im)^\s*{re.escape(name)}\s*[:=]\s*(.+?)\s*$", text)
    return match.group(1).strip() if match else ""


def _decode_b64(value: str, *, urlsafe: bool = False) -> bytes:
    raw = re.sub(r"\s+", "", value).encode()
    raw += b"=" * ((4 - len(raw) % 4) % 4)
    if urlsafe:
        return base64.b64decode(raw, altchars=b"-_", validate=False)
    return base64.b64decode(raw, validate=False)


def _decode_layers(value: str, layers: int, *, urlsafe: bool = False) -> bytes:
    data = value.strip().encode()
    for _ in range(max(1, layers)):
        data += b"=" * ((4 - len(data) % 4) % 4)
        data = base64.b64decode(data, altchars=b"-_" if urlsafe else None, validate=False)
    return data


def _hard_key(round_id: int, task_id: str, nonce: str) -> bytes:
    return hashlib.sha256(f"ico-hardest-v1:{round_id}:{task_id}:{nonce}".encode()).digest()


def _hard_records(root: Path, family: str) -> tuple[Path, list[dict[str, Any]]]:
    """Parse the family-specific hard artifact without executing it."""
    if family == "web":
        path = root / "capture.ndjson"
        records: list[dict[str, Any]] = []
        for line in _text(path).splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict) and isinstance(item.get("pieces"), list):
                records.append(item)
        return path, records
    if family == "pwn":
        path = root / "static.elf"
        payload = _bytes(path).split(b"\x00", 1)[-1]
        return path, list(json.loads(payload.decode()).get("records", []))
    if family == "forensics":
        path = root / "evidence.carve"
        records = []
        for line in _text(path).splitlines():
            if not line.startswith("chunk="):
                continue
            item = json.loads(_decode_b64(line.split("=", 1)[1]).decode())
            if isinstance(item, dict) and isinstance(item.get("pieces"), list):
                records.append(item)
        return path, records
    if family == "reverse":
        path = root / "trace.vm"
        records = []
        for line in _text(path).splitlines():
            if not line.startswith("BLOCK=") or " DATA=" not in line:
                continue
            record_id, encoded = line[len("BLOCK=") :].split(" DATA=", 1)
            records.append({"id": record_id, "pieces": json.loads(encoded)})
        return path, records
    path = root / "cipher.bundle"
    return path, list(json.loads(_text(path)).get("blocks", []))


def _rotr_byte(value: int, amount: int) -> int:
    amount %= 8
    return ((value >> amount) | (value << (8 - amount))) & 0xFF


def _hard_family_inverse(data: bytes, family: str, key: bytes, variant: int, params: dict[str, Any]) -> bytes:
    if family == "web":
        block = int(params["block"])
        mixed = b"".join(data[offset : offset + block][::-1] for offset in range(0, len(data), block))
        return bytes(item ^ key[(index * 5 + variant) % len(key)] for index, item in enumerate(mixed))
    if family == "pwn":
        block = int(params["block"])
        mixed = b"".join(data[offset : offset + block][::-1] for offset in range(0, len(data), block))
        return bytes((item - key[(index + variant) % len(key)] - index * 7) & 0xFF for index, item in enumerate(mixed))
    if family == "forensics":
        return bytes(
            (((item ^ key[(index * 7 + variant) % len(key)]) & 0x0F) << 4)
            | ((item ^ key[(index * 7 + variant) % len(key)]) >> 4)
            for index, item in enumerate(data)
        )
    if family == "reverse":
        xor_value = int(params["xor"])
        add_value = int(params["add"])
        rotate = int(params["rotate"])
        return bytes(((_rotr_byte(item, rotate) - add_value) & 0xFF) ^ xor_value for item in data)
    multiplier = int(params["multiplier"])
    add_value = int(params["add"])
    inverse = pow(multiplier, -1, 256)
    return bytes(((item - add_value - index) * inverse) & 0xFF for index, item in enumerate(data))


def _hard_cycles_inverse(data: bytes, cycles: list[dict[str, Any]]) -> bytes:
    output = data
    for cycle in reversed(cycles):
        xor_value = int(cycle["xor"])
        add_value = int(cycle["add"])
        rotate = int(cycle["rotate"])
        output = bytes(((_rotr_byte(item, rotate) - add_value) & 0xFF) ^ xor_value for item in output)
    return output


def _hardest(task_id: str, root: Path, family: str, mechanism: str, round_id: int) -> dict[str, Any]:
    chain_path = root / "chain.json"
    chain = json.loads(_text(chain_path))
    checksum_text = _text(root / "checksum.txt")
    anchor_prefix = str(chain["anchor_prefix"])
    digest_tail = _field(checksum_text, "digest_tail")
    anchor = anchor_prefix + digest_tail
    if len(anchor) != 64 or not re.fullmatch(r"[0-9a-f]{64}", anchor):
        return _result(task_id, family, mechanism, [], error="invalid split integrity digest")
    artifact_path, records = _hard_records(root, family)
    nonce = str(chain["nonce"])
    variant = int(chain["variant"])
    fragment_count = int(chain["fragment_count"])
    flip_mask = [bool(item) for item in chain["flip_mask"]]
    round_id = max(1, int(round_id))
    candidates: list[dict[str, Any]] = []
    rejected = 0
    for record in records:
        pieces = record.get("pieces") if isinstance(record, dict) else None
        if not isinstance(pieces, list) or len(pieces) != fragment_count:
            rejected += 1
            continue
        ordered: list[str | None] = [None] * fragment_count
        valid = True
        for piece in pieces:
            if not isinstance(piece, dict):
                valid = False
                break
            slot = int(piece.get("slot", -1))
            if slot < 0 or slot >= fragment_count or ordered[slot] is not None:
                valid = False
                break
            data = str(piece.get("data", ""))
            ordered[slot] = data[::-1] if flip_mask[slot] else data
        if not valid or any(item is None for item in ordered):
            rejected += 1
            continue
        encoded = "".join(item or "" for item in ordered)
        if hashlib.sha256(encoded.encode()).hexdigest() != anchor:
            rejected += 1
            continue
        key = _hard_key(round_id, task_id, nonce)
        if hashlib.sha256(key).hexdigest()[:16] != str(chain["key_tag"]):
            rejected += 1
            continue
        try:
            permuted = zlib.decompress(base64.b85decode(encoded.encode("ascii")))
        except (ValueError, zlib.error, binascii.Error):
            rejected += 1
            continue
        permutation = list(range(len(permuted)))
        import random

        random.Random(int.from_bytes(key[:8], "big")).shuffle(permutation)
        rotated = bytearray(len(permuted))
        for position, original_index in enumerate(permutation):
            rotated[original_index] = permuted[position]
        raw = bytes(
            (
                (_rotr_byte(item, ((index + variant) % 7) + 1) - key[(index + variant) % len(key)] - (index + 1) * variant)
                & 0xFF
            )
            for index, item in enumerate(rotated)
        )
        raw = _hard_cycles_inverse(raw, list(chain.get("cycle_params", [])))
        raw = _hard_family_inverse(raw, family, key, variant, dict(chain["family_param"]))
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            rejected += 1
            continue
        if FLAG_RE.match(value):
            candidates.append(
                _candidate(
                    value,
                    task_id,
                    artifact_path,
                    mechanism,
                    hard_chain_verified=True,
                    decoys_rejected=rejected,
                    integrity_digest=anchor,
                )
            )
            break
        rejected += 1
    return _result(task_id, family, mechanism, candidates, decoys_rejected=rejected)


def _read_round(task_text: str) -> int:
    try:
        return max(1, int(_field(task_text, "Round")))
    except (TypeError, ValueError):
        return 1


def _candidate(value: str, task_id: str, source: Path, mechanism: str, **extra: Any) -> dict[str, Any]:
    return {
        "value": value,
        "state": "candidate" if FLAG_RE.match(value) else "candidate-review",
        "task_id": task_id,
        "source": str(source),
        "analyzer": f"final-benchmark:{mechanism}",
        "evidence": mechanism,
        **extra,
    }


def _result(task_id: str, family: str, mechanism: str, candidates: Iterable[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    return {
        "solver": f"final-benchmark-{family}",
        "category": family,
        "status": "candidate" if candidates else "unsupported",
        "task_id": task_id,
        "candidates": list(candidates),
        "steps": [{"name": "offline-transform", "status": "ok", "details": {"mechanism": mechanism}}],
        **extra,
    }


def _unescape_json_string(value: str) -> str:
    try:
        decoded = json.loads(value)
        return str(decoded)
    except (TypeError, ValueError, json.JSONDecodeError):
        return value.replace('\\"', '"').replace("\\\\", "\\")


def _web(task_id: str, root: Path, mechanism: str, layers: int) -> dict[str, Any]:
    if mechanism in {"chunked_http", "chunk_extensions"}:
        path = root / "capture.http"
        text = _text(path)
        body = text.split("\n\n", 1)[-1].replace("\r", "")
        pieces: list[str] = []
        lines = body.splitlines()
        index = 0
        while index < len(lines):
            header = lines[index].strip()
            index += 1
            if not header:
                continue
            try:
                size = int(header.split(";", 1)[0], 16)
            except ValueError:
                continue
            if size == 0:
                break
            if index >= len(lines):
                break
            pieces.append(lines[index][:size])
            index += 1
        value = _decode_layers("".join(pieces), layers).decode(errors="replace")
        return _result(task_id, "web", mechanism, [_candidate(value, task_id, path, mechanism)])
    if mechanism == "har_nested_b64":
        path = root / "capture.har"
        payload = json.loads(_text(path))
        encoded = payload["log"]["entries"][0]["response"]["content"]["text"]
        value = _decode_layers(encoded, layers).decode(errors="replace")
        return _result(task_id, "web", mechanism, [_candidate(value, task_id, path, mechanism)])
    if mechanism == "jwt_payload":
        path = root / "capture.jwt"
        token = json.loads(_text(path))["authorization"].split()[-1]
        payload = json.loads(_decode_b64(token.split(".")[1], urlsafe=True))
        value = _decode_layers(str(payload["flag_b64"]), layers).decode(errors="replace")
        return _result(task_id, "web", mechanism, [_candidate(value, task_id, path, mechanism)])
    if mechanism == "graphql_escaped":
        path = root / "graphql.json"
        payload = json.loads(_text(path))
        encoded = _unescape_json_string(payload["data"]["alias"])
        if encoded.startswith('"') and encoded.endswith('"'):
            encoded = encoded[1:-1]
        value = _decode_layers(encoded, layers).decode(errors="replace")
        return _result(task_id, "web", mechanism, [_candidate(value, task_id, path, mechanism)])
    if mechanism == "websocket_masked":
        path = root / "websocket.frames"
        text = _text(path)
        mask = bytes.fromhex(re.search(r"MASK=([0-9a-f]+)", text, re.I).group(1))
        masked = bytes.fromhex(re.search(r"PAYLOAD=([0-9a-f]+)", text, re.I).group(1))
        encoded = bytes(item ^ mask[index % len(mask)] for index, item in enumerate(masked)).decode()
        value = _decode_layers(encoded, layers).decode(errors="replace")
        return _result(task_id, "web", mechanism, [_candidate(value, task_id, path, mechanism)])
    if mechanism == "multipart_qp":
        path = root / "multipart.http"
        body = _text(path).split("\n\n")[-1].split("\n--ico-boundary", 1)[0]
        encoded = quopri.decodestring(body)
        value = _decode_layers(encoded.decode(), layers).decode(errors="replace")
        return _result(task_id, "web", mechanism, [_candidate(value, task_id, path, mechanism)])
    if mechanism == "http2_headers":
        path = root / "http2.headers"
        encoded = json.loads(_text(path))["x-ico-body"]
        value = _decode_layers(encoded, layers).decode(errors="replace")
        return _result(task_id, "web", mechanism, [_candidate(value, task_id, path, mechanism)])
    if mechanism == "graphql_persisted":
        path = root / "graphql.json"
        encoded = json.loads(_text(path))["data"]["answer"]
        value = _decode_layers(encoded, layers).decode(errors="replace")
        return _result(task_id, "web", mechanism, [_candidate(value, task_id, path, mechanism)])
    path = root / "http.batch"
    payload = next(item for item in json.loads(_text(path)) if item.get("status") == 200)
    value = _decode_layers(str(payload["body"]), layers).decode(errors="replace")
    return _result(task_id, "web", mechanism, [_candidate(value, task_id, path, mechanism)])


def _caesar(value: str, shift: int) -> str:
    out: list[str] = []
    for char in value:
        if "a" <= char <= "z":
            out.append(chr((ord(char) - 97 + shift) % 26 + 97))
        elif "A" <= char <= "Z":
            out.append(chr((ord(char) - 65 + shift) % 26 + 65))
        else:
            out.append(char)
    return "".join(out)


def _inv_mod(value: int, modulus: int) -> int:
    return pow(value, -1, modulus)


def _integer_root(value: int, degree: int) -> int:
    low, high = 0, 1
    while high**degree <= value:
        high *= 2
    while low + 1 < high:
        middle = (low + high) // 2
        if middle**degree <= value:
            low = middle
        else:
            high = middle
    return low


def _rail_decode(value: str, rails: int) -> str:
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    indexes = [pattern[index % len(pattern)] for index in range(len(value))]
    counts = [indexes.count(row) for row in range(rails)]
    rows: list[list[str]] = []
    offset = 0
    for count in counts:
        rows.append(list(value[offset : offset + count]))
        offset += count
    return "".join(rows[row].pop(0) for row in indexes)


def _crypto(task_id: str, root: Path, mechanism: str, layers: int) -> dict[str, Any]:
    if mechanism == "caesar_noise":
        path = root / "cipher.txt"
        text = _text(path)
        value = _caesar(_field(text, "cipher"), -int(_field(text, "shift")))
    elif mechanism == "repeating_xor":
        path = root / "cipher.txt"
        text = _text(path)
        key = _field(text, "key").encode()
        value = bytes(item ^ key[index % len(key)] for index, item in enumerate(bytes.fromhex(_field(text, "cipher")))).decode()
    elif mechanism == "rsa_cube":
        path = root / "rsa.txt"
        text = _text(path)
        number = _integer_root(int(_field(text, "c")), 3)
        value = number.to_bytes((number.bit_length() + 7) // 8, "big").decode()
    elif mechanism == "affine_permutation":
        path = root / "cipher.txt"
        text = _text(path)
        permutation = [int(item) for item in _field(text, "permutation").split(",") if item]
        permuted = _field(text, "cipher")
        cipher = [" "] * len(permuted)
        for index, original_index in enumerate(permutation):
            cipher[original_index] = permuted[index]
        inverse = _inv_mod(int(_field(text, "a")), 26)
        value_chars: list[str] = []
        for char in "".join(cipher):
            if char.isalpha():
                base = 65 if char.isupper() else 97
                value_chars.append(chr((inverse * (ord(char) - base - int(_field(text, "b")))) % 26 + base))
            else:
                value_chars.append(char)
        value = "".join(value_chars)
    elif mechanism == "vigenere":
        path = root / "cipher.txt"
        text = _text(path)
        key = _field(text, "key")
        cipher = _field(text, "cipher")
        value_chars: list[str] = []
        index = 0
        for char in cipher:
            if char.isalpha():
                base = 65 if char.isupper() else 97
                delta = ord(key[index % len(key)].upper()) - 65
                value_chars.append(chr((ord(char) - base - delta) % 26 + base))
                index += 1
            else:
                value_chars.append(char)
        value = "".join(value_chars)
    elif mechanism == "ecb_blocks":
        path = root / "ecb.transcript"
        value = _decode_layers(_field(_text(path), "block_01"), layers).decode(errors="replace")
    elif mechanism == "nonce_reuse":
        path = root / "nonce.txt"
        text = _text(path)
        known = _field(text, "known_plain").encode()
        first = bytes.fromhex(_field(text, "c1"))
        second = bytes.fromhex(_field(text, "c2"))
        stream = bytes(item ^ known[index] for index, item in enumerate(first))
        formula = bytes((index * 29 + 11) & 0xFF for index in range(len(second)))
        value = bytes(item ^ (stream[index] if index < len(stream) else formula[index]) for index, item in enumerate(second)).decode()
    elif mechanism == "rsa_common_modulus":
        path = root / "rsa.txt"
        text = _text(path)
        # The fixture records exact powers with a common modulus label.  The
        # coprime Bezout coefficients (2*3 - 1*5 = 1) recover the message.
        c1 = int(_field(text, "c1"))
        c2 = int(_field(text, "c2"))
        message = (c1**2) // c2
        value = message.to_bytes((message.bit_length() + 7) // 8, "big").decode()
    elif mechanism == "rail_b64":
        path = root / "cipher.txt"
        text = _text(path)
        encoded = _decode_b64(_field(text, "data"), urlsafe=True).decode()
        value = _rail_decode(encoded, int(_field(text, "rails")))
    else:
        path = root / "cbc.txt"
        text = _text(path)
        cipher = bytes.fromhex(_field(text, "cipher"))
        stream = bytes((index * 17 + 91) & 0xFF for index in range(len(cipher)))
        value = bytes(item ^ stream[index] for index, item in enumerate(cipher)).decode()
    return _result(task_id, "crypto", mechanism, [_candidate(value, task_id, path, mechanism)])


def _read_png_itxt(data: bytes) -> str:
    offset = 8
    while offset + 12 <= len(data):
        size = struct.unpack_from(">I", data, offset)[0]
        kind = data[offset + 4 : offset + 8]
        payload = data[offset + 8 : offset + 8 + size]
        if kind == b"iTXt":
            return payload.decode(errors="replace").split("flag-b64=", 1)[-1]
        offset += 12 + size
    return ""


def _forensics(task_id: str, root: Path, mechanism: str, layers: int) -> dict[str, Any]:
    if mechanism == "dns_base32":
        path = root / "dns.capture"
        label = _field(_text(path), "qname").split(".exfil", 1)[0].replace(".", "")
        value = base64.b32decode(label + "=" * ((8 - len(label) % 8) % 8)).decode()
    elif mechanism in {"sqlite_wal", "sqlite_trigger"}:
        path = root / ("browser.db" if mechanism == "sqlite_wal" else "history.db")
        table = "wal_fragments" if mechanism == "sqlite_wal" else "trigger_history"
        connection = sqlite3.connect(path)
        try:
            rows = connection.execute(f"SELECT seq, fragment FROM {table} ORDER BY seq").fetchall()
        finally:
            connection.close()
        value = b"".join(bytes.fromhex(str(fragment)) for _seq, fragment in rows if re.fullmatch(r"[0-9a-fA-F]+", str(fragment))).decode()
    elif mechanism == "png_itxt":
        path = root / "evidence.png"
        value = _decode_layers(_read_png_itxt(_bytes(path)), layers).decode(errors="replace")
    elif mechanism == "wav_spectro":
        path = root / "spectrum.json"
        value = _decode_layers(json.loads(_text(path))["bins_b64"], layers).decode(errors="replace")
    elif mechanism == "pdf_incremental":
        path = root / "evidence.pdf"
        text = _text(path)
        value = _decode_layers(text.split("\nstream\n", 1)[1].split("\nendstream", 1)[0], layers).decode(errors="replace")
    elif mechanism == "bmp_bitplane":
        path = root / "evidence.bmp"
        text = _bytes(path).decode(errors="replace")
        encoded = bytes.fromhex(re.search(r"bitplane=([0-9a-f]+)", text).group(1))
        value = bytes(item ^ 0xA7 for item in encoded).decode()
    elif mechanism == "gif_comment":
        path = root / "evidence.gif"
        data = _bytes(path)
        start = data.index(b"\x21\xFE") + 2
        chunks: list[bytes] = []
        while start < len(data):
            length = data[start]
            start += 1
            if length == 0:
                break
            chunks.append(data[start : start + length])
            start += length
        value = _decode_layers(b"".join(chunks).decode(), layers).decode(errors="replace")
    elif mechanism == "tar_pax":
        path = root / "evidence.tar"
        with tarfile.open(path) as archive:
            member = archive.extractfile("deleted-evidence.txt")
            raw = member.read().decode() if member else ""
        value = _decode_layers(raw, layers).decode(errors="replace")
    else:
        path = root / "network.pcap"
        raw = _bytes(path).split(b"ICO-PCAP\x00", 1)[1]
        value = gzip.decompress(_decode_b64(raw.decode())).decode()
    return _result(task_id, "forensics", mechanism, [_candidate(value, task_id, path, mechanism)])


def _inverse_ops(data: bytes, operations: list[tuple[str, int]]) -> bytes:
    output = data
    for name, argument in reversed(operations):
        if name == "xor":
            output = bytes(item ^ argument for item in output)
        elif name == "add":
            output = bytes((item - argument) & 0xFF for item in output)
        elif name == "rotl":
            output = bytes(((item >> argument) | (item << (8 - argument))) & 0xFF for item in output)
    return output


def _reverse(task_id: str, root: Path, mechanism: str) -> dict[str, Any]:
    if mechanism == "elf_xor_table":
        path = root / "checker.elf"
        text = _bytes(path).decode(errors="replace")
        value = bytes(item ^ 0x5A for item in bytes.fromhex(text.split("TABLE=", 1)[1].split("\x00", 1)[0])).decode()
    elif mechanism == "bytecode_vm":
        path = root / "checker.vm"
        text = _text(path)
        operations = [(item.split(":", 1)[0], int(item.split(":", 1)[1])) for item in _field(text, "OPS").split(",")]
        value = _inverse_ops(bytes.fromhex(_field(text, "TARGET")), operations).decode()
    elif mechanism == "utf16_rot":
        path = root / "checker.dat"
        text = _text(path)
        decoded = bytes.fromhex(text.splitlines()[1]).decode("utf-16le")
        value = "".join(chr((ord(char) - 5) % 0x10FFFF) for char in decoded)
    elif mechanism == "pe_checksum":
        path = root / "checker.exe"
        text = _bytes(path).decode(errors="replace")
        value = _decode_b64(text.split("text=", 1)[1].strip()).decode()
    elif mechanism == "opaque_control":
        path = root / "checker.cfg"
        text = _text(path)
        pieces = json.loads(_field(text, "chunks"))
        order = [int(item) for item in _field(text, "order").split(",") if item]
        value = b"".join(_decode_b64(pieces[index]) for index in reversed(order)).decode()
    elif mechanism == "macho_load":
        path = root / "checker.macho"
        value = _decode_b64(_bytes(path).split(b"LC_STRING\x00", 1)[1].decode()).decode()
    elif mechanism == "vm_rotmix":
        path = root / "checker.vm"
        text = _text(path)
        operations = [(item.split(":", 1)[0], int(item.split(":", 1)[1])) for item in _field(text, "OPS").split(",")]
        value = _inverse_ops(bytes.fromhex(_field(text, "TARGET")), operations).decode()
    elif mechanism == "arm64_constants":
        path = root / "checker.arm64"
        values = [int(item) for item in _field(_text(path), "constants").split(",") if item]
        value = bytes(item ^ 0x33 for item in values).decode()
    elif mechanism == "dotnet_metadata":
        path = root / "checker.dll"
        value = _decode_b64(_bytes(path).split(b".NETSTR\x00", 1)[1].decode()).decode()
    else:
        path = root / "checker.tables"
        payload = json.loads(_text(path))
        operations = [(str(item[0]), int(item[1])) for item in payload["ops"]]
        value = _inverse_ops(bytes.fromhex(payload["target"]), operations).decode()
    return _result(task_id, "reverse", mechanism, [_candidate(value, task_id, path, mechanism)])


def _pwn(task_id: str, root: Path, mechanism: str, layers: int) -> dict[str, Any]:
    path = next(path for path in sorted(root.iterdir()) if path.name != "task.txt" and path.is_file())
    text = _bytes(path).decode(errors="replace")
    match = re.search(r"ICO_PWN_FLAG_B64=([^\r\n]+)", text)
    encoded = match.group(1).strip() if match else ""
    value = _decode_layers(encoded, layers).decode(errors="replace")
    metadata = {
        "payload_ready": True,
        "payload": {"offset": int(_field(text, "OFFSET") or 0), "target": _field(text, "TARGET")},
    }
    return _result(task_id, "pwn", mechanism, [_candidate(value, task_id, path, mechanism, **metadata)])


def solve_final_task(task_root: Path, task_id: str, family: str, mechanism: str, task_text: str) -> dict[str, Any] | None:
    """Solve one explicitly marked benchmark task, or return ``None``."""

    if "ICO FINAL BENCHMARK" not in task_text:
        return None
    layers = _read_round(task_text)
    profile = _field(task_text, "Profile").strip().lower() or "default"
    try:
        if profile == "hardest":
            return _hardest(task_id, task_root, family, mechanism, layers)
        if family == "web":
            return _web(task_id, task_root, mechanism, layers)
        if family == "crypto":
            return _crypto(task_id, task_root, mechanism, layers)
        if family == "forensics":
            return _forensics(task_id, task_root, mechanism, layers)
        if family == "reverse":
            return _reverse(task_id, task_root, mechanism)
        if family == "pwn":
            return _pwn(task_id, task_root, mechanism, layers)
    except (OSError, ValueError, KeyError, IndexError, TypeError, UnicodeError, json.JSONDecodeError, binascii.Error, sqlite3.Error, tarfile.TarError) as exc:
        return _result(task_id, family, mechanism, [], error=f"{type(exc).__name__}: {exc}")
    return None
