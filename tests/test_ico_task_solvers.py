from __future__ import annotations

import hashlib
import base64
import gzip
import io
import lzma
import os
import sqlite3
import struct
import tempfile
import unittest
import wave
import tarfile
import zipfile
import zlib
from pathlib import Path

from ico_task_solvers import (
    discover_task_dirs,
    select_solver,
    solve_magic_bytes,
    solve_archive_layers,
    solve_pcap,
    solve_dns_base32,
    solve_repair_header,
    solve_png_lsb,
    solve_png_ztext,
    solve_sqlite,
    solve_wav_lsb,
    solve_xor,
    verify_flag,
)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def _make_rgb_png(pixels: bytes, width: int, height: int) -> bytes:
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    rows = b"".join(b"\x00" + pixels[row * width * 3 : (row + 1) * width * 3] for row in range(height))
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", header) + _png_chunk(b"IDAT", zlib.compress(rows)) + _png_chunk(b"IEND", b"")


def _embed_rgb_lsb(text: bytes) -> bytes:
    payload = text + b"\x00"
    bits = [bit for value in payload for bit in ((value >> shift) & 1 for shift in range(7, -1, -1))]
    pixels = bytearray([0x20] * (len(bits) + 2))
    for index, bit in enumerate(bits):
        pixels[index] = (pixels[index] & 0xFE) | bit
    return _make_rgb_png(bytes(pixels), len(pixels) // 3, 1)


def _make_ztxt_png(text: bytes) -> bytes:
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ztxt = b"Comment\x00\x00" + zlib.compress(text)
    rows = zlib.compress(b"\x00\x00\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", header) + _png_chunk(b"zTXt", ztxt) + _png_chunk(b"IDAT", rows) + _png_chunk(b"IEND", b"")


class TaskSolverModelTests(unittest.TestCase):
    def test_verify_flag_uses_exact_utf8_sha256(self):
        result = verify_flag("CTF{demo}", hashlib.sha256(b"CTF{demo}").hexdigest())
        self.assertEqual(result["status"], "hash-verified")
        self.assertEqual(result["algorithm"], "sha256")

    def test_discover_task_dirs_skips_reports_and_hidden(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "01_task"
            task.mkdir()
            (task / "task.txt").write_text("Single-byte XOR", encoding="utf-8")
            report = root / "ico-scan-runs" / "nested"
            report.mkdir(parents=True)
            (report / "task.txt").write_text("noise", encoding="utf-8")
            hidden = root / ".hidden"
            hidden.mkdir()
            (hidden / "task.txt").write_text("noise", encoding="utf-8")
            self.assertEqual(discover_task_dirs([str(root)]), [task.resolve()])

    def test_discover_task_dirs_recognizes_ctf_readme_under_category(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ctfs" / "DownUnderCTF" / "2024"
            task = root / "crypto" / "v_for_vieta"
            task.mkdir(parents=True)
            (root / "README.md").write_text("Archive overview", encoding="utf-8")
            (root / "repository.py").write_text("print('not a task')", encoding="utf-8")
            (task / "README.md").write_text("Have this on loop while you solve.\nAuthor: wednesday\n", encoding="utf-8")
            (task / "server.py").write_text("print('challenge service')", encoding="utf-8")

            self.assertEqual(discover_task_dirs([str(root)]), [task.resolve()])
            self.assertEqual(discover_task_dirs([str(task / "server.py")]), [task.resolve()])

    def test_discover_task_dirs_scopes_single_file_to_its_task_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "01_first"
            first.mkdir()
            (first / "task.txt").write_text("Single-byte XOR", encoding="utf-8")
            (first / "evidence.bin").write_bytes(b"data")
            sibling = root / "02_sibling"
            sibling.mkdir()
            (sibling / "task.txt").write_text("SQLite database", encoding="utf-8")
            (sibling / "browser_cache.db").write_bytes(b"data")

            self.assertEqual(discover_task_dirs([str(first / "evidence.bin")]), [first.resolve()])
            outside = root / "unrelated.bin"
            outside.write_bytes(b"data")
            self.assertEqual(discover_task_dirs([str(outside)]), [])

    def test_solver_selection_uses_task_text(self):
        cases = {
            "Single-byte XOR. Ключ 0..255.": "xor-single-byte",
            "Расширение врёт. Определи настоящий формат": "magic-bytes",
            "Флаг спрятан в LSB RGB-каналов": "png-lsb-rgb",
            "Открой PCAP. Authorization: Bearer": "pcap-http-bearer",
            "DNS trace contains split Base32 labels": "pcap-dns-base32",
            "Это SQLite database. Поле value хранит данные в hex": "sqlite-cache-hex",
            "Linux ELF. Ищи main, strcmp и XOR-циклы": "reverse-elf",
            "Распакуй backup.zip. Каждый новый файл": "archive-layers",
            "Повреждены первые 4 байта. magic header": "repair-header",
            "LSB последовательных 16-bit PCM samples": "wav-lsb",
            "PNG compressed textual metadata (zTXt)": "png-ztext",
        }
        for text, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertEqual(select_solver(text, Path("artifact")), expected)


class TaskSolverTransformationTests(unittest.TestCase):
    def test_xor_solver_recovers_key_and_verifies_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = "CTF{xor_task_test}"
            source = root / "evidence.bin"
            source.write_bytes(bytes(value ^ 0x5A for value in b"noise " + flag.encode() + b" tail"))
            result = solve_xor(source, root / "report", hashlib.sha256(flag.encode()).hexdigest())
        self.assertEqual(result.status, "hash-verified")
        self.assertEqual(result.candidates[0]["key"], 0x5A)

    def test_magic_solver_decompresses_and_decodes_base64(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{magic_task_test}"
            source = root / "holiday_photo.jpg"
            source.write_bytes(gzip.compress(b"archived:" + base64.b64encode(flag)))
            result = solve_magic_bytes(source, root / "report", hashlib.sha256(flag).hexdigest())
        self.assertEqual(result.status, "hash-verified")

    def test_png_lsb_solver_reads_rgb_bits_msb_first(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{png_lsb_task_test}"
            source = root / "noise.png"
            source.write_bytes(_embed_rgb_lsb(flag))
            result = solve_png_lsb(source, root / "report", hashlib.sha256(flag).hexdigest())
        self.assertEqual(result.status, "hash-verified")

    def test_sqlite_solver_orders_hex_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{sqlite_task_test}"
            source = root / "browser_cache.db"
            db = sqlite3.connect(source)
            db.execute("CREATE TABLE cache_entries(id integer primary key, seq integer, value text)")
            split = len(flag) // 2
            db.executemany("INSERT INTO cache_entries(seq, value) VALUES (?, ?)", [(2, flag[split:].hex()), (1, flag[:split].hex())])
            db.commit(); db.close()
            result = solve_sqlite(source, root / "report", hashlib.sha256(flag).hexdigest())
        self.assertEqual(result.status, "hash-verified")

    def test_wav_lsb_solver_reads_16bit_samples(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{wav_lsb_task_test}"
            bits = [bit for value in flag + b"\x00" for bit in ((value >> shift) & 1 for shift in range(7, -1, -1))]
            samples = [(100 + bit) for bit in bits]
            source = root / "recording.wav"
            with wave.open(str(source), "wb") as audio:
                audio.setnchannels(1); audio.setsampwidth(2); audio.setframerate(8000)
                audio.writeframes(struct.pack("<" + "h" * len(samples), *samples))
            result = solve_wav_lsb(source, root / "report", hashlib.sha256(flag).hexdigest())
        self.assertEqual(result.status, "hash-verified")

    def test_png_ztxt_solver_decompresses_metadata_and_base64(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{ztxt_task_test}"
            source = root / "evidence.png"
            source.write_bytes(_make_ztxt_png(base64.b64encode(flag)))
            result = solve_png_ztext(source, root / "report", hashlib.sha256(flag).hexdigest())
        self.assertEqual(result.status, "hash-verified")


def _make_pcap(payload: bytes) -> bytes:
    ethernet = b"\x00" * 12 + b"\x08\x00"
    ip = bytes.fromhex("45000000") + b"\x00\x01\x00\x00\x40\x06\x00\x00" + bytes([10, 0, 0, 2, 10, 0, 0, 5])
    tcp = struct.pack(">HHII", 12345, 80, 1, 0) + bytes([0x50, 0x18, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00])
    packet = ethernet + ip[:2] + struct.pack(">H", 20 + 20 + len(payload)) + ip[4:] + tcp + payload
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 0, len(packet), len(packet))
    return global_header + record + packet


def _make_dns_pcap(labels: list[str]) -> bytes:
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 53000, 53, 8 + len(dns), 0) + dns
    ethernet = b"\x00" * 12 + b"\x08\x00"
    source = bytes([10, 0, 0, 1])
    target = bytes([10, 0, 0, 2])
    ip = bytes([0x45, 0]) + struct.pack(">H", 20 + len(udp)) + b"\x00\x01\x00\x00\x40\x11\x00\x00" + source + target
    packet = ethernet + ip + udp
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 0, len(packet), len(packet))
    return global_header + record + packet


class TaskSolverBinaryAndContainerTests(unittest.TestCase):
    def test_pcap_solver_reassembles_and_decodes_bearer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{pcap_task_test}"
            payload = b"GET / HTTP/1.1\r\nAuthorization: Bearer " + base64.b64encode(flag) + b"\r\n\r\n"
            source = root / "traffic.pcap"
            source.write_bytes(_make_pcap(payload))
            result = solve_pcap(source, root / "report", hashlib.sha256(flag).hexdigest())
        self.assertEqual(result.status, "hash-verified")

    def test_dns_solver_joins_split_base32_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ico{dns_task_test}"
            token = base64.b32encode(flag).decode("ascii").rstrip("=")
            labels = [token[index : index + 8] for index in range(0, len(token), 8)] + ["ex", "local"]
            source = root / "dns_trace.pcap"
            source.write_bytes(_make_dns_pcap(labels))
            result = solve_dns_base32(source, root / "report", hashlib.sha256(flag).hexdigest())
        self.assertEqual(result.status, "hash-verified")

    def test_archive_solver_recurses_zip_xz_tar_and_xor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{archive_task_test}"
            note = bytes(value ^ 0x37 for value in flag)
            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
                info = tarfile.TarInfo("docs/note.bin")
                info.size = len(note)
                archive.addfile(info, io.BytesIO(note))
            xz = lzma.compress(tar_buffer.getvalue())
            source = root / "backup.zip"
            with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("old/report.jpg", xz)
            result = solve_archive_layers(source, root / "report", hashlib.sha256(flag).hexdigest())
        self.assertEqual(result.status, "hash-verified")

    def test_repair_solver_restores_zip_header_and_decodes_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{repair_task_test}"
            good = io.BytesIO()
            with zipfile.ZipFile(good, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("note.dat", base64.b64encode(flag))
            damaged = b"\x00\x00\x00\x00" + good.getvalue()[4:]
            source = root / "broken.bin"
            source.write_bytes(damaged)
            result = solve_repair_header(source, root / "report", hashlib.sha256(flag).hexdigest())
        self.assertEqual(result.status, "hash-verified")

    def test_reverse_elf_is_static_only(self):
        source = Path(os.environ.get("ICO_CTF_REAL_ROOT", str(Path.home() / "Downloads" / "ico_ctf_real"))) / "06_reverse_elf" / "chall"
        if not source.is_file():
            self.skipTest("local ELF fixture is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            flag = "CTF{decompile_dont_guess}"
            result = __import__("ico_task_solvers").solve_reverse_elf(
                source,
                Path(directory),
                hashlib.sha256(flag.encode()).hexdigest(),
            )
        self.assertEqual(result.status, "hash-verified")
        self.assertTrue(all(step.get("details", {}).get("executed") is False for step in result.steps if step["name"] in {"static-disassembly", "solve"}))


if __name__ == "__main__":
    unittest.main()
