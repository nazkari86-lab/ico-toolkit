#!/usr/bin/env python3
"""Generate the deterministic ICO final benchmark without network access."""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import json
import quopri
import random
import sqlite3
import struct
import sys
import tarfile
import zlib
from pathlib import Path
from urllib.parse import quote

# When invoked as ``python scripts/generate_final_benchmark.py`` Python puts
# ``scripts`` first on sys.path; make the toolkit root importable explicitly.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.final_benchmark import (
    BenchmarkManifest,
    FAMILIES,
    ManifestRecord,
    default_manifest,
    default_root,
    records_for_round,
    seed_for,
    task_flag,
    write_manifest,
)


def _b64(value: bytes | str) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return base64.b64encode(raw).decode()


def _b64url(value: bytes | str) -> str:
    raw = value.encode() if isinstance(value, str) else value
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _layers(value: str, round_id: int, *, urlsafe: bool = False) -> str:
    encoded = value.encode()
    for _ in range(max(1, round_id)):
        encoded = (base64.urlsafe_b64encode if urlsafe else base64.b64encode)(encoded).rstrip(b"=")
    return encoded.decode()


def _unlayered_payload(value: str, round_id: int) -> str:
    # The generator and solver deliberately agree on the number of layers via
    # the task statement.  This is challenge data, not the expected manifest.
    return _layers(value, round_id)


def _write(path: Path, data: bytes | str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_bytes(data)


def _write_task(record: ManifestRecord, task_dir: Path, round_id: int, evidence: str, *, profile: str = "default") -> None:
    text = (
        "ICO FINAL BENCHMARK\n"
        f"Round: {round_id}\n"
        f"Profile: {profile}\n"
        f"Task ID: {record.task_id}\n"
        f"Family: {record.family}\n"
        f"Difficulty: {record.difficulty}\n"
        f"Mechanism: {record.mechanism}\n"
        f"Layers: {max(1, round_id)}\n"
        f"Evidence: {evidence}\n"
        "Objective: recover the single ico{...} value from the supplied evidence.\n"
        "The solver must use the declared transform and must not guess values.\n"
    )
    if profile == "hardest":
        text += (
            "Pipeline: nonce-derived key -> rolling byte transform -> per-byte rotation -> "
            "seeded permutation -> zlib -> base85 -> fragment reassembly\n"
            "Integrity: the SHA-256 of the base85 stage is split across chain.json and checksum.txt; "
            "decoys must be rejected by that digest\n"
            "The artifact contains multiple records and no record is trusted by position alone.\n"
        )
    _write(task_dir / "task.txt", text)


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


def _vigenere(value: str, key: str, decrypt: bool = False) -> str:
    out: list[str] = []
    index = 0
    sign = -1 if decrypt else 1
    for char in value:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            delta = ord(key[index % len(key)].upper()) - 65
            out.append(chr((ord(char) - base + sign * delta) % 26 + base))
            index += 1
        else:
            out.append(char)
    return "".join(out)


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _rotl(value: int, amount: int) -> int:
    amount %= 8
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def _rotr(value: int, amount: int) -> int:
    amount %= 8
    return ((value >> amount) | (value << (8 - amount))) & 0xFF


def _affine(value: str, a: int, b: int) -> str:
    out: list[str] = []
    for char in value:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            out.append(chr((a * (ord(char) - base) + b) % 26 + base))
        else:
            out.append(char)
    return "".join(out)


def _rail_encode(value: str, rails: int) -> str:
    rows = [[] for _ in range(rails)]
    row = 0
    direction = 1
    for char in value:
        rows[row].append(char)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    return "".join("".join(items) for items in rows)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def _make_png(value: str, round_id: int) -> bytes:
    payload = f"flag-b64={_unlayered_payload(value, round_id)}".encode()
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 3, 0, 0, 0)) + _png_chunk(b"PLTE", b"\x00\x00\x00") + _png_chunk(b"iTXt", payload) + _png_chunk(b"IEND", b"")


def _make_wav(value: str, round_id: int) -> bytes:
    meta = json.dumps({"sample_rate": 44100, "bins": _unlayered_payload(value, round_id), "carrier": "spectrogram"}).encode()
    data = b"\x00\x00" * 32
    fmt = struct.pack("<HHIIHH", 1, 1, 44100, 88200, 2, 16)
    body = b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", len(data)) + data + b"LIST" + struct.pack("<I", len(meta)) + meta
    return b"RIFF" + struct.pack("<I", len(body) + 4) + b"WAVE" + body


def _make_bmp(value: str, round_id: int) -> bytes:
    bits = _xor(value.encode(), b"\xA7")
    return b"BM" + b"ICO-BITPLANE\x00" + f"bitplane={bits.hex()}\npalette_alpha=0xA7\n".encode()


def _make_gif(value: str, round_id: int) -> bytes:
    comment = _unlayered_payload(value, round_id).encode()
    blocks = bytearray()
    for offset in range(0, len(comment), 255):
        chunk = comment[offset : offset + 255]
        blocks.extend(bytes([len(chunk)]))
        blocks.extend(chunk)
    blocks.append(0)
    return b"GIF89a" + b"\x21\xFE" + bytes(blocks) + b"\x3B"


def _make_tar(value: str, round_id: int, path: Path) -> None:
    with tarfile.open(path, "w") as archive:
        payload = _unlayered_payload(value, round_id).encode()
        info = tarfile.TarInfo("deleted-evidence.txt")
        info.size = len(payload)
        archive.addfile(info, __import__("io").BytesIO(payload))
        pax = tarfile.TarInfo("pax-note.txt")
        pax_payload = f"PAX comment={_unlayered_payload(value, round_id)}".encode()
        pax.size = len(pax_payload)
        pax.pax_headers = {"comment": "carved"}
        archive.addfile(pax, __import__("io").BytesIO(pax_payload))


def _make_sqlite(path: Path, table: str, fragments: list[tuple[int, str]]) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(f"CREATE TABLE {table}(seq INTEGER, fragment TEXT)")
        connection.executemany(f"INSERT INTO {table}(seq, fragment) VALUES (?, ?)", fragments)
        connection.commit()
    finally:
        connection.close()


def _hard_key(round_id: int, task_id: str, nonce: str) -> bytes:
    return hashlib.sha256(f"ico-hardest-v1:{round_id}:{task_id}:{nonce}".encode()).digest()


def _hard_family_forward(data: bytes, family: str, key: bytes, variant: int) -> tuple[bytes, str, dict[str, int]]:
    if family == "web":
        mixed = bytes(item ^ key[(index * 5 + variant) % len(key)] for index, item in enumerate(data))
        block = 3
        return b"".join(mixed[offset : offset + block][::-1] for offset in range(0, len(mixed), block)), "web-block-xor", {"block": block}
    if family == "pwn":
        mixed = bytes((item + key[(index + variant) % len(key)] + index * 7) & 0xFF for index, item in enumerate(data))
        block = 4
        return b"".join(mixed[offset : offset + block][::-1] for offset in range(0, len(mixed), block)), "pwn-endian-delta", {"block": block}
    if family == "forensics":
        return bytes((((item & 0x0F) << 4) | (item >> 4)) ^ key[(index * 7 + variant) % len(key)] for index, item in enumerate(data)), "forensics-nibble-mask", {"stride": 7}
    if family == "reverse":
        xor_value = key[0]
        add_value = variant * 3 + 5
        rotate = variant % 7 + 1
        output = bytes(_rotl((item ^ xor_value) + add_value & 0xFF, rotate) for item in data)
        return output, "reverse-vm", {"xor": xor_value, "add": add_value, "rotate": rotate}
    multiplier = 3 + 2 * (variant % 5)
    add_value = key[1]
    return bytes((item * multiplier + add_value + index) & 0xFF for index, item in enumerate(data)), "crypto-affine", {"multiplier": multiplier, "add": add_value}


def _hard_cycle_params(key: bytes, variant: int, round_id: int) -> list[dict[str, int]]:
    return [
        {
            "xor": key[(index + variant) % len(key)],
            "add": (key[(index + 7 + variant) % len(key)] + index * 13 + variant) & 0xFF,
            "rotate": ((key[(index + 17 + variant) % len(key)] + index + variant) % 7) + 1,
        }
        for index in range(max(0, round_id - 1))
    ]


def _hard_apply_cycles(data: bytes, cycles: list[dict[str, int]]) -> bytes:
    output = data
    for cycle in cycles:
        xor_value = int(cycle["xor"])
        add_value = int(cycle["add"])
        rotate = int(cycle["rotate"])
        output = bytes(_rotl(((item ^ xor_value) + add_value) & 0xFF, rotate) for item in output)
    return output


def _hard_material(value: str, family: str, round_id: int, task_id: str, nonce: str, variant: int) -> dict[str, object]:
    """Encode one hard-profile record through a reversible multi-stage chain.

    The intermediate base85 string is what the integrity ledger authenticates;
    the raw flag is never written to an evidence artifact.  Decoy records use
    the same shape and different task scopes, so a solver must select by the
    cross-file digest before attempting the inverse transform.
    """
    key = _hard_key(round_id, task_id, nonce)
    family_data, family_stage, family_param = _hard_family_forward(value.encode(), family, key, variant)
    cycles = _hard_cycle_params(key, variant, round_id)
    family_data = _hard_apply_cycles(family_data, cycles)
    shifted = bytes(
        (item + key[(index + variant) % len(key)] + (index + 1) * variant) & 0xFF
        for index, item in enumerate(family_data)
    )
    rotated = bytes(_rotl(item, ((index + variant) % 7) + 1) for index, item in enumerate(shifted))
    permutation = list(range(len(rotated)))
    random.Random(int.from_bytes(key[:8], "big")).shuffle(permutation)
    permuted = bytes(rotated[index] for index in permutation)
    encoded = base64.b85encode(zlib.compress(permuted, level=9)).decode("ascii")
    fragment_count = 7 + 2 * max(0, round_id - 1)
    width = max(1, (len(encoded) + fragment_count - 1) // fragment_count)
    flip_mask = [((variant + index) % 3) == 0 for index in range(fragment_count)]
    pieces: list[dict[str, object]] = []
    for slot in range(fragment_count):
        piece = encoded[slot * width : (slot + 1) * width]
        if flip_mask[slot]:
            piece = piece[::-1]
        pieces.append({"slot": slot, "data": piece})
    random.Random(int.from_bytes(key[8:16], "big")).shuffle(pieces)
    return {
        "pieces": pieces,
        "anchor": hashlib.sha256(encoded.encode()).hexdigest(),
        "key_tag": hashlib.sha256(key).hexdigest()[:16],
        "flip_mask": flip_mask,
        "fragment_count": fragment_count,
        "family_stage": family_stage,
        "family_param": family_param,
        "cycle_params": cycles,
    }


def _hard_record_json(record_id: str, material: dict[str, object]) -> dict[str, object]:
    return {"id": record_id, "pieces": material["pieces"]}


def _hard_artifact_path(family: str) -> str:
    return {
        "web": "capture.ndjson",
        "pwn": "static.elf",
        "forensics": "evidence.carve",
        "reverse": "trace.vm",
        "crypto": "cipher.bundle",
    }[family]


def _write_hard_artifact(path: Path, family: str, records: list[dict[str, object]]) -> None:
    """Write the same record set in five deliberately different containers."""
    if family == "web":
        lines = [json.dumps({"stream": "h2", "header": "x-ico-indexed"}, separators=(",", ":"))]
        lines.extend(json.dumps(record, separators=(",", ":")) for record in records)
        _write(path, "\n".join(lines) + "\n")
    elif family == "pwn":
        payload = json.dumps({"section": ".ico.hard", "records": records}, separators=(",", ":")).encode()
        _write(path, b"\x7fELF\x02ICO-HARD-STATIC\x00" + payload)
    elif family == "forensics":
        lines = ["CARVEv3"]
        for record in records:
            encoded = _b64(json.dumps(record, separators=(",", ":")).encode())
            lines.append(f"chunk={encoded}")
        _write(path, "\n".join(lines) + "\n")
    elif family == "reverse":
        lines = ["VMTRACE v9", "OP=LOAD_TABLE"]
        lines.extend(f"BLOCK={record['id']} DATA={json.dumps(record['pieces'], separators=(',', ':'))}" for record in records)
        _write(path, "\n".join(lines) + "\n")
    else:
        _write(path, json.dumps({"mode": "hybrid-transcript", "blocks": records}, separators=(",", ":")))


def _build_hardest(record: ManifestRecord, task_dir: Path, value: str, round_id: int) -> None:
    nonce = hashlib.sha256(f"{seed_for(round_id)}:{record.task_id}:nonce".encode()).hexdigest()[:24]
    variant = (int(record.story[-2:]) * 3 + len(record.family) + len(record.mechanism)) % 17 + 1
    target = _hard_material(value, record.family, round_id, record.task_id, nonce, variant)
    records = [_hard_record_json(record.task_id, target)]
    decoy_count = 6 + 2 * max(0, round_id - 1)
    for index in range(decoy_count):
        decoy_id = f"decoy-{index}-{hashlib.sha256(f'{record.task_id}:{index}'.encode()).hexdigest()[:8]}"
        decoy_value = hashlib.sha256(f"decoy-value:{round_id}:{record.task_id}:{index}".encode()).hexdigest()
        decoy = _hard_material(decoy_value, record.family, round_id, decoy_id, nonce, variant)
        records.append(_hard_record_json(decoy_id, decoy))
    random.Random(int.from_bytes(hashlib.sha256(f"records:{record.task_id}".encode()).digest()[:8], "big")).shuffle(records)

    anchor = str(target["anchor"])
    _write(
        task_dir / "chain.json",
        json.dumps(
            {
                "version": 1,
                "family": record.family,
                "mechanism": record.mechanism,
                "nonce": nonce,
                "variant": variant,
                "anchor_prefix": anchor[:16],
                "key_tag": target["key_tag"],
                "fragment_count": target["fragment_count"],
                "flip_mask": target["flip_mask"],
                "decoys": len(records) - 1,
                "family_stage": target["family_stage"],
                "family_param": target["family_param"],
                "complexity": max(1, round_id),
                "cycle_count": len(target["cycle_params"]),
                "cycle_params": target["cycle_params"],
            },
            separators=(",", ":"),
        ),
    )
    _write(
        task_dir / "checksum.txt",
        "decoy_tail=000000000000000000000000000000000000000000000000\n"
        f"digest_tail={anchor[16:]}\n"
        "rule=sha256(base85-stage)\n",
    )
    _write_hard_artifact(task_dir / _hard_artifact_path(record.family), record.family, records)


def _build_web(record: ManifestRecord, task_dir: Path, value: str, round_id: int) -> None:
    payload = _unlayered_payload(value, round_id)
    mechanism = record.mechanism
    if mechanism == "chunked_http":
        split = max(1, len(payload) // 2)
        body = payload[:split] + payload[split:]
        evidence = f"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{split:x};part=one\r\n{body[:split]}\r\n{len(body)-split:x};part=two\r\n{body[split:]}\r\n0\r\n\r\n"
        _write(task_dir / "capture.http", evidence)
    elif mechanism == "har_nested_b64":
        content = {"entries": [{"response": {"content": {"text": payload, "encoding": "base64"}}}]}
        _write(task_dir / "capture.har", json.dumps({"log": content}, ensure_ascii=False))
    elif mechanism == "jwt_payload":
        token = f"eyJhbGciOiJub25lIn0.{_b64url(json.dumps({'kid': '../cache', 'flag_b64': payload}).encode())}.signature"
        _write(task_dir / "capture.jwt", json.dumps({"authorization": f"Bearer {token}", "header_hint": "none"}))
    elif mechanism == "graphql_escaped":
        escaped = json.dumps(payload).replace("\\", "\\\\")
        _write(task_dir / "graphql.json", json.dumps({"data": {"alias": escaped, "errors": []}}))
    elif mechanism == "websocket_masked":
        mask = bytes.fromhex("a1b2c3d4")
        masked = bytes(ord(char) ^ mask[index % 4] for index, char in enumerate(payload))
        _write(task_dir / "websocket.frames", f"FIN=1 OPCODE=1 MASK=a1b2c3d4 PAYLOAD={masked.hex()}\n")
    elif mechanism == "multipart_qp":
        encoded = quopri.encodestring(payload.encode()).decode()
        _write(task_dir / "multipart.http", f"Content-Type: multipart/form-data; boundary=ico-boundary\n\n--ico-boundary\nContent-Disposition: form-data; name=answer\nContent-Transfer-Encoding: quoted-printable\n\n{encoded}\n--ico-boundary--\n")
    elif mechanism == "chunk_extensions":
        split = max(1, len(payload) // 3)
        pieces = [payload[:split], payload[split : 2 * split], payload[2 * split :]]
        text = "HTTP/1.1 200 OK\nTransfer-Encoding: chunked\n\n" + "".join(f"{len(piece):x};trace={index}\n{piece}\n" for index, piece in enumerate(pieces) if piece) + "0\n\n"
        _write(task_dir / "capture.http", text)
    elif mechanism == "http2_headers":
        _write(task_dir / "http2.headers", json.dumps({":status": "200", ":path": "/v2/data", "x-ico-body": payload, "encoding": "base64"}))
    elif mechanism == "graphql_persisted":
        _write(task_dir / "graphql.json", json.dumps({"extensions": {"persistedQuery": {"version": 1, "sha256Hash": hashlib.sha256(payload.encode()).hexdigest()}}, "data": {"answer": payload}}))
    else:
        _write(task_dir / "http.batch", json.dumps([{"status": 404, "body": "decoy"}, {"status": 200, "body": payload, "encoding": "base64"}]))


def _build_crypto(record: ManifestRecord, task_dir: Path, value: str, round_id: int) -> None:
    mechanism = record.mechanism
    if mechanism == "caesar_noise":
        _write(task_dir / "cipher.txt", f"shift=7\nnoise=__--__\ncipher={_caesar(value, 7)}\n")
    elif mechanism == "repeating_xor":
        key = b"K3Y"
        _write(task_dir / "cipher.txt", f"key={key.decode()}\ncrib=ico{{\ncipher={_xor(value.encode(), key).hex()}\n")
    elif mechanism == "rsa_cube":
        message = int.from_bytes(value.encode(), "big")
        cipher = message**3
        _write(task_dir / "rsa.txt", f"e=3\nn={cipher + 17}\nc={cipher}\nencoding=big-endian\n")
    elif mechanism == "affine_permutation":
        cipher = _affine(value, 5, 8)
        permutation = list(range(len(cipher)))[::-1]
        permuted = "".join(cipher[index] for index in permutation)
        _write(task_dir / "cipher.txt", f"a=5\nb=8\npermutation={','.join(map(str, permutation))}\ncipher={permuted}\n")
    elif mechanism == "vigenere":
        key = "ICO"
        _write(task_dir / "cipher.txt", f"key_prefix=IC\nkey={key}\ncipher={_vigenere(value, key)}\n")
    elif mechanism == "ecb_blocks":
        payload = _unlayered_payload(value, round_id)
        _write(task_dir / "ecb.transcript", f"block_00={_b64(b'decoy')}\nblock_01={payload}\nmode=AES-ECB\nsplice=block_01\n")
    elif mechanism == "nonce_reuse":
        stream = bytes((index * 29 + 11) & 0xFF for index in range(len(value)))
        first = (b"known-plaintext-" * ((len(value) // 16) + 2))[: len(value)]
        _write(task_dir / "nonce.txt", f"known_plain={first.decode(errors='replace')}\nc1={_xor(first, stream).hex()}\nc2={_xor(value.encode(), stream).hex()}\n")
    elif mechanism == "rsa_common_modulus":
        message = int.from_bytes(value.encode(), "big")
        # A deliberately oversized common modulus keeps the fixture fully
        # deterministic while allowing the Bezout relation 2*3-1*5=1 to
        # recover the exact message without factoring or brute force.
        n = message**5 + 123
        _write(task_dir / "rsa.txt", f"n={n}\ne1=3\ne2=5\nc1={message**3}\nc2={message**5}\n")
    elif mechanism == "rail_b64":
        _write(task_dir / "cipher.txt", f"rails=3\ndata={_b64url(_rail_encode(value, 3).encode())}\n")
    else:
        known = "ico{"
        stream = bytes((index * 17 + 91) & 0xFF for index in range(len(value)))
        _write(task_dir / "cbc.txt", f"mode=AES-CBC\nknown_prefix={known}\niv_reused=true\ncipher={_xor(value.encode(), stream).hex()}\n")


def _build_forensics(record: ManifestRecord, task_dir: Path, value: str, round_id: int) -> None:
    payload = _unlayered_payload(value, round_id)
    mechanism = record.mechanism
    if mechanism == "dns_base32":
        encoded = base64.b32encode(value.encode()).decode().rstrip("=")
        split = max(1, len(encoded) // 2)
        _write(task_dir / "dns.capture", f"pcap-record=udp53\nqname={encoded[:split]}.{encoded[split:]}.exfil.invalid\nencoding=base32\n")
    elif mechanism == "sqlite_wal":
        parts = [value[: len(value) // 2], value[len(value) // 2 :]]
        _make_sqlite(task_dir / "browser.db", "wal_fragments", [(2, parts[1].encode().hex()), (1, parts[0].encode().hex()), (99, "decoy")])
    elif mechanism == "png_itxt":
        _write(task_dir / "evidence.png", _make_png(value, round_id))
    elif mechanism == "wav_spectro":
        _write(task_dir / "evidence.wav", _make_wav(value, round_id))
        _write(task_dir / "spectrum.json", json.dumps({"crop": "2k-5k", "bins_b64": payload, "units": "hz"}))
    elif mechanism == "pdf_incremental":
        _write(task_dir / "evidence.pdf", f"%PDF-1.7\n1 0 obj\n<< /Length {len(payload)} >>\nstream\n{payload}\nendstream\nendobj\n%%EOF\n")
    elif mechanism == "bmp_bitplane":
        _write(task_dir / "evidence.bmp", _make_bmp(value, round_id))
    elif mechanism == "gif_comment":
        _write(task_dir / "evidence.gif", _make_gif(value, round_id))
    elif mechanism == "tar_pax":
        _make_tar(value, round_id, task_dir / "evidence.tar")
    elif mechanism == "pcap_gzip":
        compressed = gzip.compress(value.encode(), mtime=0)
        _write(task_dir / "network.pcap", b"\xd4\xc3\xb2\xa1" + b"ICO-PCAP\x00" + _b64(compressed).encode())
    else:
        parts = [value[: len(value) // 3], value[len(value) // 3 : 2 * len(value) // 3], value[2 * len(value) // 3 :]]
        _make_sqlite(task_dir / "history.db", "trigger_history", [(3, parts[2].encode().hex()), (1, parts[0].encode().hex()), (2, parts[1].encode().hex())])


def _transform_bytes(value: bytes, operations: list[tuple[str, int]]) -> bytes:
    data = value
    for name, argument in operations:
        if name == "xor":
            data = bytes(item ^ argument for item in data)
        elif name == "add":
            data = bytes((item + argument) & 0xFF for item in data)
        elif name == "rotl":
            data = bytes(_rotl(item, argument) for item in data)
    return data


def _build_reverse(record: ManifestRecord, task_dir: Path, value: str, round_id: int) -> None:
    mechanism = record.mechanism
    raw = value.encode()
    if mechanism == "elf_xor_table":
        _write(task_dir / "checker.elf", b"\x7fELF\x02ICO_REV_XOR\x00KEY=0x5a\x00TABLE=" + _xor(raw, b"\x5a").hex().encode())
    elif mechanism == "bytecode_vm":
        operations = [("xor", 0x41), ("add", 9)]
        _write(task_dir / "checker.vm", "VM v2\nOPS=xor:65,add:9\nTARGET=" + _transform_bytes(raw, operations).hex() + "\n")
    elif mechanism == "utf16_rot":
        rotated = "".join(chr((ord(char) + 5) % 0x10FFFF) for char in value)
        _write(task_dir / "checker.dat", "UTF16_ROT=5\n" + rotated.encode("utf-16le").hex() + "\n")
    elif mechanism == "pe_checksum":
        checksum = sum(raw) & 0xFFFF
        _write(task_dir / "checker.exe", b"MZ\x90\x00ICO_PE_CHECK\x00" + f"checksum={checksum}\ntext={_b64(raw)}\n".encode())
    elif mechanism == "opaque_control":
        pieces = [_b64(raw[index : index + 5]) for index in range(0, len(raw), 5)]
        order = list(range(len(pieces)))[::-1]
        _write(task_dir / "checker.cfg", f"order={','.join(map(str, order))}\nchunks={json.dumps(pieces)}\nbranch=(x*x+1)>0\n")
    elif mechanism == "macho_load":
        _write(task_dir / "checker.macho", b"\xcf\xfa\xed\xfeLC_STRING\x00" + _b64(raw).encode())
    elif mechanism == "vm_rotmix":
        operations = [("rotl", 3), ("xor", 0x27), ("add", 11)]
        _write(task_dir / "checker.vm", "OPS=rotl:3,xor:39,add:11\nTARGET=" + _transform_bytes(raw, operations).hex() + "\n")
    elif mechanism == "arm64_constants":
        constants = [item ^ 0x33 for item in raw]
        _write(task_dir / "checker.arm64", "ARM64\nEOR key=0x33\nconstants=" + ",".join(map(str, constants)) + "\n")
    elif mechanism == "dotnet_metadata":
        _write(task_dir / "checker.dll", b"MZBSJB\x00.NETSTR\x00" + _b64(raw).encode())
    else:
        operations = [("xor", 0x19), ("rotl", 1), ("add", 3)]
        _write(task_dir / "checker.tables", json.dumps({"ops": operations, "target": _transform_bytes(raw, operations).hex(), "branches": [2, 0, 1]}))


def _build_pwn(record: ManifestRecord, task_dir: Path, value: str, round_id: int) -> None:
    payload = _unlayered_payload(value, round_id)
    metadata = {
        "ret2win_static": ("chall", 40, "0x401176"),
        "format_got": ("format.txt", 24, "puts@GOT=0x404018"),
        "hardening_static": ("hardening.elf", 56, "win=0x4011a6"),
        "integer_trunc": ("vuln.c", 32, "win=0x401210"),
        "ret2csu_plan": ("ret2csu.txt", 72, "csu=0x401320"),
        "got_plt": ("relocs.elf", 48, "read@plt=0x401050"),
        "stack_win": ("stack.txt", 40, "win=0x401196"),
        "rop_constraints": ("rop.txt", 88, "syscall=0x40142b"),
        "format_positional": ("fmt.txt", 16, "arg=11"),
        "seccomp_read": ("seccomp.txt", 64, "read(fd=3)"),
    }
    filename, offset, target = metadata[record.mechanism]
    magic = b"\x7fELF\x02" if filename.endswith(".elf") else b"ICO-PWN\x00"
    text = f"ICO_PWN_FLAG_B64={payload}\nOFFSET={offset}\nTARGET={target}\nSTATIC_ONLY=true\n"
    _write(task_dir / filename, magic + text.encode())


def build_fixture(record: ManifestRecord, task_dir: Path, value: str, round_id: int, *, profile: str = "default") -> None:
    task_dir.mkdir(parents=True, exist_ok=True)
    if profile == "hardest":
        _build_hardest(record, task_dir, value, round_id)
        return
    if record.family == "web":
        _build_web(record, task_dir, value, round_id)
    elif record.family == "crypto":
        _build_crypto(record, task_dir, value, round_id)
    elif record.family == "forensics":
        _build_forensics(record, task_dir, value, round_id)
    elif record.family == "reverse":
        _build_reverse(record, task_dir, value, round_id)
    elif record.family == "pwn":
        _build_pwn(record, task_dir, value, round_id)
    else:
        raise ValueError(f"unsupported family: {record.family}")


def generate(
    round_id: int = 1,
    root: Path | None = None,
    manifest_path: Path | None = None,
    *,
    profile: str = "default",
) -> BenchmarkManifest:
    if round_id < 1:
        raise ValueError("round_id must be positive")
    if profile not in {"default", "hardest"}:
        raise ValueError(f"unsupported benchmark profile: {profile}")
    root = (root or default_root(ROOT, round_id, profile=profile)).expanduser().resolve()
    manifest_path = (manifest_path or default_manifest(ROOT, round_id, profile=profile)).expanduser().resolve()
    if root.exists():
        import shutil

        shutil.rmtree(root)
    root.mkdir(parents=True, exist_ok=True)
    records = records_for_round(round_id, profile=profile)
    for record in records:
        value = task_flag(round_id, record.story, record.family, record.difficulty, profile=profile)
        task_dir = root / record.story / f"{record.family}_{record.difficulty}"
        _write_task(record, task_dir, round_id, _evidence_name(record), profile=profile)
        build_fixture(record, task_dir, value, round_id, profile=profile)
    manifest = BenchmarkManifest(2, round_id, seed_for(round_id), records, profile)
    write_manifest(manifest_path, manifest)
    return manifest


def _evidence_name(record: ManifestRecord) -> str:
    names = {
        "web": "capture.http or structured transcript",
        "pwn": "static challenge artifact",
        "forensics": "media/network/archive artifact",
        "reverse": "static checker artifact",
        "crypto": "cipher evidence",
    }
    return names[record.family]


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the offline ICO final benchmark")
    parser.add_argument("--round", type=int, default=1, dest="round_id")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--profile", choices=("default", "hardest"), default="default")
    args = parser.parse_args()
    manifest = generate(args.round_id, args.root, args.manifest, profile=args.profile)
    print(f"generated {manifest.profile} round {manifest.round_id}: {len(manifest.records)} tasks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
