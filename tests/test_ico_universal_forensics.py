from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import lzma
import shutil
import sqlite3
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import patch

from ico_solver_engine import SolverContext, SolverLimits
from ico_universal_forensics import (
    ForensicsSolver,
    _png_integrity,
    _repair_caesar_mojibake_png,
    parse_pcap,
    reassemble_streams,
)


def _tcp_packet(seq: int, payload: bytes, *, src_port: int = 40000, dst_port: int = 8080) -> bytes:
    tcp = struct.pack(">HHII", src_port, dst_port, seq, 0) + bytes([0x50, 0x18]) + struct.pack(">HHH", 65535, 0, 0)
    source = ipaddress.IPv4Address("10.0.0.1").packed
    target = ipaddress.IPv4Address("10.0.0.2").packed
    total_length = 20 + len(tcp) + len(payload)
    ip = bytes([0x45, 0]) + struct.pack(">H", total_length) + b"\x00\x00\x40\x00\x40\x06\x00\x00" + source + target
    ethernet = b"\x00" * 12 + struct.pack(">H", 0x0800)
    return ethernet + ip + tcp + payload


def _pcap(packets: list[bytes]) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = b"".join(struct.pack("<IIII", index, 0, len(packet), len(packet)) + packet for index, packet in enumerate(packets, 1))
    return header + records


def _pcap_linux_sll2(packets: list[bytes]) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 276)
    records = b"".join(struct.pack("<IIII", index, 0, len(packet), len(packet)) + packet for index, packet in enumerate(packets, 1))
    return header + records


def _pcapng_ethernet(packets: list[bytes], *, link_type: int = 1) -> bytes:
    def block(block_type: int, body: bytes) -> bytes:
        total = 12 + len(body)
        padded_total = (total + 3) & ~3
        padding = b"\x00" * (padded_total - total)
        return struct.pack("<II", block_type, padded_total) + body + padding + struct.pack("<I", padded_total)

    section = struct.pack("<I H H q", 0x1A2B3C4D, 1, 0, -1)
    interface = struct.pack("<H H I", link_type, 0, 65535)
    enhanced = []
    for index, packet in enumerate(packets, 1):
        enhanced.append(struct.pack("<I I I I I", 0, 0, index, len(packet), len(packet)) + packet)
    return block(0x0A0D0D0A, section) + block(1, interface) + b"".join(block(6, body) for body in enhanced)


def _arp_frame(target_protocol_address: bytes) -> bytes:
    ethernet = b"\x00" * 12 + struct.pack(">H", 0x0806)
    arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)
    arp += b"\x00" * 6 + ipaddress.IPv4Address("10.0.0.1").packed
    arp += b"\x00" * 6 + target_protocol_address
    return ethernet + arp


def _png_with_text(text: str) -> bytes:
    def chunk(kind: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))

    header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    pixels = zlib.compress(b"\x00\x10\x20\x30\xff")
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"tEXt", b"Comment\x00" + text.encode())
        + chunk(b"IDAT", pixels)
        + chunk(b"IEND", b"")
    )


def _caesar_corrupt_png(data: bytes) -> bytes:
    output = bytearray()
    for value in data:
        if value < 0x80:
            output.append(value)
        elif value < 0xC0:
            output.extend((0xC2, value))
        else:
            output.extend((0xC3, value - 64))
    return bytes(output)


def _linux_sll2_frame(ip_packet: bytes) -> bytes:
    cooked = struct.pack(">HHI HBB", 0x0800, 0, 1, 1, 0, 6) + b"\x00" * 8
    return cooked + ip_packet


def _dns_packet(labels: list[str]) -> bytes:
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    dns = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 53000, 53, 8 + len(dns), 0) + dns
    source = ipaddress.IPv4Address("10.0.0.1").packed
    target = ipaddress.IPv4Address("10.0.0.2").packed
    ip = bytes([0x45, 0]) + struct.pack(">H", 20 + len(udp)) + b"\x00\x01\x00\x00\x40\x11\x00\x00" + source + target
    ethernet = b"\x00" * 12 + struct.pack(">H", 0x0800)
    return ethernet + ip + udp


def _context(
    root: Path,
    source: Path,
    kind: str,
    task_text: str | None = None,
    *,
    related_paths: tuple[Path, ...] = (),
    max_bytes: int = 1024 * 1024,
    timeout_seconds: float = 1.0,
) -> SolverContext:
    return SolverContext(
        input_path=source,
        report_dir=root / "report",
        limits=SolverLimits(max_bytes=max_bytes, max_files=50, max_depth=3, timeout_seconds=timeout_seconds),
        related_paths=related_paths,
        task_text=task_text,
        classification={"kind": kind, "mime": "application/vnd.tcpdump.pcap" if kind == "pcap" else "application/octet-stream"},
    )


class UniversalForensicsTests(unittest.TestCase):
    def test_numeric_subtitle_solver_decodes_flag_from_video_mismatches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "subtitles.srt"
            video = root / "subtitles.mp4"
            video.write_bytes(b"bounded video fixture")
            subtitles: list[int] = []
            for character in "ictf{A}":
                subtitles.extend(int(digit) for digit in str(ord(character)))
                subtitles.append(8)
            blocks = []
            for index, digit in enumerate(subtitles):
                blocks.append(
                    f"{index + 1}\n00:00:{index:02d},000 --> 00:00:{index + 1:02d},000\n{digit}"
                )
            source.write_text("\n\n".join(blocks), encoding="utf-8")
            context = _context(root, source, "text", "numeric subtitles")
            normal = [{"digit": 8, "confidence": 1.0} for _ in subtitles]
            inverted = [{"digit": 0, "confidence": 1.0} for _ in subtitles]
            with patch(
                "ico_universal_forensics._extract_subtitle_video_frames",
                return_value=(b"\x00" * (len(subtitles) * 28 * 28), b"", 0),
            ), patch(
                "ico_universal_forensics._mnist_video_digit_views",
                return_value=("test-backend", [normal, inverted]),
            ):
                result = ForensicsSolver().solve(context)

        self.assertIn("ictf{A}", {item["value"] for item in result.candidates})
        self.assertEqual(result.status, "candidate")

    def test_numeric_srt_with_sibling_video_gets_subtitle_detection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "subtitles.srt"
            source.write_text(
                "1\n00:00:00,000 --> 00:00:01,000\n1\n\n"
                "2\n00:00:01,000 --> 00:00:02,000\n0\n",
                encoding="utf-8",
            )
            (root / "subtitles.mp4").write_bytes(b"paired video")
            detection = ForensicsSolver().detect(
                _context(root, source, "text", "numeric subtitles")
            )

        self.assertIsNotNone(detection)
        self.assertEqual(detection.metadata.get("kind"), "numeric-subtitle-video")

    def test_caesar_mojibake_png_is_repaired_and_sent_to_media_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = "ictf{caesar_png_fixture}"
            source = root / "corrupted.png"
            source.write_bytes(_caesar_corrupt_png(_png_with_text(flag)))
            context = _context(root, source, "data", "Did Caesar like PNG files?")
            result = ForensicsSolver().solve(context)

        self.assertIn(flag, {item["value"] for item in result.candidates})
        self.assertTrue(any("caesar-recovered.png" in path for path in result.artifacts))
        self.assertTrue(any("caesar-recovered.png" in path for path in result.derived_inputs))

    def test_valid_recovered_png_is_not_repaired_a_second_time(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "recovered.png"
            source.write_bytes(_png_with_text("ictf{already_valid_png}"))
            result = ForensicsSolver().solve(
                _context(root, source, "data", "Did Caesar like PNG files?")
            )

        self.assertNotEqual(result.status, "failed")
        self.assertFalse(any(step["name"] == "repair-caesar-mojibake-png" for step in result.steps))

    def test_caesar_repair_preserves_invalid_utf8_pairs_without_overflow(self):
        repaired = _repair_caesar_mojibake_png(b"\xc3\xc2\x80")

        self.assertEqual(repaired, b"\xc3\x80")

    def test_pcapng_arp_target_addresses_reassemble_a_tarp_png(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = "ICO{tarp_arp_fixture}"
            image = _png_with_text(flag)
            padded = image + b"\x00" * (-len(image) % 4)
            target_addresses = [padded[index : index + 4] for index in range(0, len(padded), 4)]
            target_addresses.insert(2, ipaddress.IPv4Address("10.42.10.99").packed)
            source = root / "tarp.pcapng"
            source.write_bytes(_pcapng_ethernet([_arp_frame(address) for address in target_addresses]))
            result = ForensicsSolver().solve(_context(root, source, "pcap", "Title: tARP"))

        self.assertIn(flag, {item["value"] for item in result.candidates})
        self.assertTrue(any("tarp-recovered.png" in path for path in result.artifacts))

    def test_tarp_repairs_terminal_crc_and_trims_short_capture_tail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = "ICO{tarp_embedded_file}"
            image = bytearray(_png_with_text(flag))
            iend = image.rfind(b"IEND")
            image[iend + 4] ^= 1
            encoded = b"root:x:0:0:root:/root:/bin/bash\n" + bytes(image) + b"\x00\x00\x82"
            padded = encoded + b"\x00" * (-len(encoded) % 4)
            target_addresses = [padded[index : index + 4] for index in range(0, len(padded), 4)]
            target_addresses.insert(0, ipaddress.IPv4Address("10.42.10.21").packed)
            source = root / "tarp.pcapng"
            source.write_bytes(_pcapng_ethernet([_arp_frame(address) for address in target_addresses]))
            result = ForensicsSolver().solve(_context(root, source, "pcap", "Title: tARP"))
            recovered_path = next(Path(path) for path in result.artifacts if "tarp-recovered.png" in path)
            recovered = recovered_path.read_bytes()
            step = next(step for step in result.steps if step["name"] == "recover-tarp-png")

        self.assertIn(flag, {item["value"] for item in result.candidates})
        self.assertEqual(_png_integrity(recovered, max_bytes=1024 * 1024), "valid")
        self.assertEqual(recovered[-12:-8], b"\x00\x00\x00\x00")
        self.assertEqual(recovered[-8:-4], b"IEND")
        self.assertEqual(len(recovered[-4:]), 4)
        self.assertEqual(step["status"], "ok")
        self.assertEqual(step["details"]["integrity"], "terminal-crc-repaired")

    def test_tarp_recovery_rejects_arbitrary_arp_address_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            noise = b"ordinary arp noise that is not a PNG" 
            padded = noise + b"\x00" * (-len(noise) % 4)
            addresses = [padded[index : index + 4] for index in range(0, len(padded), 4)]
            source = root / "noise.pcapng"
            source.write_bytes(_pcapng_ethernet([_arp_frame(address) for address in addresses]))
            result = ForensicsSolver().solve(_context(root, source, "pcap", "Title: tARP"))

        self.assertFalse(any("tarp-recovered.png" in path for path in result.artifacts))
        self.assertFalse(any(item.get("analyzer") == "pcap-tarp-png" for item in result.candidates))

    def test_ewf_mmls_launch_error_is_reported_without_crashing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "broken.E01"
            source.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + b"\x00" * 32)
            context = _context(root, source, "data", "EWF disk image")

            def fake_run(command, **_kwargs):
                if command[0] == "/fake/ewfinfo":
                    return 0, b"File format: Encase 6\n", False, False
                raise OSError("mmls could not be started")

            with patch(
                "ico_universal_forensics.shutil.which",
                side_effect=lambda name: {
                    "ewfinfo": "/fake/ewfinfo",
                    "mmls": "/fake/mmls",
                    "fls": None,
                    "icat": None,
                }.get(name),
            ), patch("ico_universal_forensics._run_capped", side_effect=fake_run):
                result = ForensicsSolver().solve(context)

        steps = {step["name"]: step for step in result.steps}
        self.assertEqual(result.status, "needs-review")
        self.assertIn("mmls could not be started", result.error or "")
        self.assertEqual(steps["mmls"]["status"], "error")
        self.assertEqual(steps["scan-ewf-files"]["status"], "unsupported")

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("ewfacquire", "ewfinfo", "mmls")),
        "libewf and Sleuth Kit command-line tools are required",
    )
    def test_ewf_image_reports_metadata_and_partitions_without_modifying_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = bytearray(65536)
            partition = struct.pack(
                "<B3sB3sII", 0x80, b"\x00\x02\x00", 0x83, b"\xfe\xff\xff", 1, 127
            )
            raw[446:462] = partition
            raw[510:512] = b"\x55\xaa"
            raw_path = root / "disk.raw"
            raw_path.write_bytes(raw)
            image_prefix = root / "synthetic-disk"
            subprocess.run(
                [
                    "ewfacquire",
                    "-q",
                    "-u",
                    "-f",
                    "encase6",
                    "-m",
                    "fixed",
                    "-M",
                    "logical",
                    "-P",
                    "512",
                    "-B",
                    str(len(raw)),
                    "-t",
                    str(image_prefix),
                    str(raw_path),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
            )
            source = root / "synthetic-disk.E01"
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            context = _context(root, source, "data", "EWF disk image")
            detection = ForensicsSolver().detect(context)
            result = ForensicsSolver().solve(context)
            after = hashlib.sha256(source.read_bytes()).hexdigest()
            partition_report = next(Path(path) for path in result.artifacts if path.endswith("partitions.txt"))
            partition_text = partition_report.read_text(encoding="utf-8")

        self.assertIsNotNone(detection)
        self.assertEqual(detection.metadata["ewf_magic"], True)
        self.assertEqual(result.status, "needs-review")
        self.assertEqual(result.candidates, [])
        steps = {step["name"]: step for step in result.steps}
        self.assertEqual(steps["ewfinfo"]["status"], "ok")
        self.assertEqual(steps["mmls"]["status"], "ok")
        self.assertEqual(steps["ewfinfo"]["details"]["bytes_per_sector"], 512)
        self.assertIn("Linux (0x83)", partition_text)
        self.assertEqual(before, after)

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ("mke2fs", "ewfacquire", "ewfinfo", "mmls", "fls", "icat")),
        "e2fsprogs, libewf, and Sleuth Kit command-line tools are required",
    )
    def test_ewf_scans_small_files_and_saves_flag_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = root / "files"
            tree.mkdir()
            (tree / "secrets.txt").write_text("Recovered value: ICO{ewf_file_flag}\n", encoding="utf-8")
            partition_path = root / "partition.img"
            subprocess.run(
                ["mke2fs", "-q", "-t", "ext4", "-F", "-d", str(tree), str(partition_path), "16384"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
            )
            partition = partition_path.read_bytes()
            raw = bytearray(512 + len(partition))
            raw[446:462] = struct.pack(
                "<B3sB3sII", 0x80, b"\x00\x02\x00", 0x83, b"\xfe\xff\xff", 1, len(partition) // 512
            )
            raw[510:512] = b"\x55\xaa"
            raw[512:] = partition
            raw_path = root / "disk.raw"
            raw_path.write_bytes(raw)
            image_prefix = root / "evidence"
            subprocess.run(
                [
                    "ewfacquire",
                    "-q",
                    "-u",
                    "-f",
                    "encase6",
                    "-m",
                    "fixed",
                    "-M",
                    "logical",
                    "-P",
                    "512",
                    "-B",
                    str(len(raw)),
                    "-t",
                    str(image_prefix),
                    str(raw_path),
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
            )
            source = root / "evidence.E01"
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            result = ForensicsSolver().solve(_context(root, source, "data", "EWF ext4 disk image"))
            after = hashlib.sha256(source.read_bytes()).hexdigest()
            candidate = next(item for item in result.candidates if item["value"] == "ICO{ewf_file_flag}")
            evidence = Path(candidate["evidence"]).read_bytes()

        self.assertEqual(result.status, "candidate")
        self.assertEqual(candidate["file_path"], "secrets.txt")
        self.assertEqual(candidate["partition_start"], 1)
        self.assertIn(b"ICO{ewf_file_flag}", evidence)
        self.assertEqual(before, after)

    def test_pcap_packet_limit_is_independent_of_file_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "many-packets.pcap"
            packet_list = [_tcp_packet(index, b"") for index in range(210)]
            source.write_bytes(_pcap(packet_list))
            context = _context(root, source, "pcap")
            packets = parse_pcap(source, context.limits)
        self.assertEqual(len(packets), len(packet_list))

    def test_pcap_recovers_flag_from_positioned_note_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = "ICO{network_flag}"
            packets = [_tcp_packet(index, b"") for index in range(210)]
            sequence = 1000
            for position, character in enumerate(flag):
                body = urlencode(
                    {
                        "name": f"Flag 2 character at position {position}",
                        "desc": character * 8,
                    }
                ).encode()
                request = (
                    b"POST /add_note HTTP/1.1\r\n"
                    b"Host: notes.local\r\n"
                    b"Content-Type: application/x-www-form-urlencoded\r\n"
                    + f"Content-Length: {len(body)}\r\n\r\n".encode()
                    + body
                )
                packets.append(_tcp_packet(sequence, request))
                sequence += len(request)
            source = root / "positioned-notes.pcap"
            source.write_bytes(_pcap(packets))
            result = ForensicsSolver().solve(
                _context(root, source, "pcap", "HTTP form note character positions")
            )
        self.assertIn(flag, {item["value"] for item in result.candidates})

    def test_pcap_reassembles_split_http_bearer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ico{pcap_stream}"
            token = base64.b64encode(flag)
            body = b"GET /flag HTTP/1.1\r\nAuthorization: Bearer " + token + b"\r\n\r\n"
            source = root / "traffic.pcap"
            source.write_bytes(_pcap([_tcp_packet(100, body[:22]), _tcp_packet(122, body[22:])]))
            packets = parse_pcap(source, _context(root, source, "pcap").limits)
            streams = reassemble_streams(packets, _context(root, source, "pcap").limits)
            result = ForensicsSolver().solve(_context(root, source, "pcap", "HTTP Authorization Bearer"))
        self.assertEqual(len(packets), 2)
        self.assertTrue(any(body in stream for stream in streams))
        self.assertIn("ico{pcap_stream}", {item["value"] for item in result.candidates})

    def test_pcap_derives_wrapped_tool_version_answer_from_http_user_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = (
                b"GET / HTTP/1.1\r\n"
                b"Host: target.local\r\n"
                b"User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)\r\n\r\n"
            )
            source = root / "capture.pcap"
            source.write_bytes(_pcap([_tcp_packet(100, request)]))
            task_text = (
                "We captured traffic of attackers. Tell us what tool they were using and its version. "
                "Wrap your answer in the DUCTF{}, e.g. DUCTF{nmap_7.25}."
            )
            result = ForensicsSolver().solve(_context(root, source, "pcap", task_text))

        values = {item["value"] for item in result.candidates}
        self.assertIn("DUCTF{nikto_2.1.6}", values)

    def test_pcap_does_not_wrap_user_agent_without_matching_task_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = (
                b"GET / HTTP/1.1\r\n"
                b"Host: target.local\r\n"
                b"User-Agent: Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:000001)\r\n\r\n"
            )
            source = root / "capture.pcap"
            source.write_bytes(_pcap([_tcp_packet(100, request)]))
            result = ForensicsSolver().solve(_context(root, source, "pcap"))

        self.assertFalse(result.candidates)
        self.assertFalse(any(step["name"] == "derive-tool-version-from-http-user-agent" for step in result.steps))

    def test_pcapng_reassembles_http_bearer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ico{pcapng_stream}"
            body = b"GET / HTTP/1.1\r\nAuthorization: Bearer " + base64.b64encode(flag) + b"\r\n\r\n"
            source = root / "traffic.pcapng"
            source.write_bytes(_pcapng_ethernet([_tcp_packet(100, body[:18]), _tcp_packet(118, body[18:])]))
            packets = parse_pcap(source, _context(root, source, "pcap").limits)
            result = ForensicsSolver().solve(_context(root, source, "pcap", "HTTP Authorization Bearer"))

        self.assertEqual(len(packets), 2)
        self.assertIn("ico{pcapng_stream}", {item["value"] for item in result.candidates})
        parse_step = next(step for step in result.steps if step["name"] == "parse-pcap")
        self.assertEqual(parse_step["details"]["format"], "pcapng")

    def test_pcapng_linux_sll2_dns_base32_labels_are_joined(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ico{pcapng_sll2_dns}"
            token = base64.b32encode(flag).decode("ascii").rstrip("=")
            labels = [token[index : index + 8] for index in range(0, len(token), 8)] + ["ex", "local"]
            ethernet_frame = _dns_packet(labels)
            source = root / "dns.pcapng"
            source.write_bytes(
                _pcapng_ethernet(
                    [_linux_sll2_frame(ethernet_frame[14:])],
                    link_type=276,
                )
            )
            result = ForensicsSolver().solve(_context(root, source, "pcap", "DNS Base32 label stream"))

        self.assertIn(flag.decode(), {item["value"] for item in result.candidates})

    def test_external_emuc2_pcap_uses_associated_tls_keylog(self):
        task_root = Path("/tmp/ico-external-ctf/ductf2024-blind/forensic/emuc2")
        compressed = task_root / "challenge.pcap.xz"
        keylog = task_root / "sslkeylogfile.txt"
        if not compressed.is_file() or not keylog.is_file() or shutil.which("tshark") is None:
            self.skipTest("external emuc2 capture, key log, or tshark is unavailable")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.pcap"
            source.write_bytes(lzma.decompress(compressed.read_bytes()))
            context = _context(
                root,
                source,
                "pcap",
                "Decrypt TLS sessions using the supplied key log",
                related_paths=(),
                max_bytes=64 * 1024 * 1024,
                timeout_seconds=15.0,
            )
            shutil.copy2(keylog, root / keylog.name)
            result = ForensicsSolver().solve(context)
            stream_paths = [Path(path) for path in result.derived_inputs if "tls-stream-" in path]
            decrypted = b"\n".join(path.read_bytes() for path in stream_paths)
            header_paths = [Path(path) for path in result.derived_inputs if path.endswith("tls-http2-headers.jsonl")]
            header_records = (
                [json.loads(line) for line in header_paths[0].read_text(encoding="utf-8").splitlines()]
                if header_paths
                else []
            )

        self.assertIsNone(result.error, result.steps)
        step = next((step for step in result.steps if step["name"] == "decrypt-tls-keylog"), None)
        self.assertIsNotNone(step, result.steps)
        self.assertEqual(step["status"], "ok")
        self.assertEqual(step["details"]["streams"], 4)
        self.assertGreater(step["details"]["http2_data_bodies"], 0)
        self.assertIn(b"HTTP/2.0", decrypted)
        self.assertTrue(any("tls-http2-" in path for path in result.derived_inputs))
        self.assertEqual(len(header_paths), 1)
        routes = {
            header["value"]
            for record in header_records
            for header in record["headers"]
            if header["name"] == ":path"
        }
        self.assertTrue({"/api/login", "/api/env", "/api/flag"}.issubset(routes), routes)
        by_stream = {}
        for record in header_records:
            key = (record["tls_stream"], record["http2_stream"])
            by_stream.setdefault(key, {}).update(
                {header["name"]: header["value"] for header in record["headers"]}
            )
        self.assertTrue(
            any(headers.get(":path") == "/api/flag" and headers.get(":status") == "401" for headers in by_stream.values()),
            by_stream,
        )

    def test_tls_decryption_discovers_sibling_keylog_without_manifest_context(self):
        from ico_universal_forensics import _tls_keylog_candidates

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.pcap"
            source.write_bytes(b"pcap placeholder")
            keylog = root / "sslkeylogfile.txt"
            keylog.write_text(f"CLIENT_RANDOM {'a' * 64} {'b' * 64}\n", encoding="ascii")

            candidates = _tls_keylog_candidates(_context(root, source, "pcap", related_paths=()))

        self.assertEqual(candidates, [(keylog, {"a" * 64})])

    def test_tshark_json_parser_preserves_duplicate_http2_header_keys(self):
        from ico_universal_forensics import _parse_tshark_http2_headers

        raw = b'''[
          {"_source":{"layers":{
            "frame":{"frame.number":"1232"},
            "tls":{"tls.stream":"7"},
            "tcp":{"tcp.srcport":"40000","tcp.dstport":"443"},
            "http2":{"http2.stream":{
              "http2.type":"1",
              "http2.streamid":"3",
              "http2.header":{"http2.header.name":":method","http2.header.value":"GET"},
              "http2.header":{"http2.header.name":":path","http2.header.value":"/api/flag"},
              "http2.header":{"http2.header.name":":status","http2.header.value":"401"},
              "http2.request.full_uri":"https://challenge.local/api/flag"
            }}
          }}}
        ]'''

        records = _parse_tshark_http2_headers(raw)

        self.assertEqual(
            records,
            [
                {
                    "frame": "1232",
                    "tls_stream": "7",
                    "source_port": "40000",
                    "destination_port": "443",
                    "http2_stream": "3",
                    "uri": "https://challenge.local/api/flag",
                    "headers": [
                        {"name": ":method", "value": "GET"},
                        {"name": ":path", "value": "/api/flag"},
                        {"name": ":status", "value": "401"},
                    ],
                }
            ],
        )

    def test_pcap_decodes_base64_http_query_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = "ICO{query_parameter_evidence}"
            token = base64.b64encode(flag.encode()).decode()
            target = "/api/checkin?" + urlencode({"data": token})
            request = (
                f"GET {target} HTTP/1.1\r\n"
                "Host: updates.local\r\n"
                "Connection: keep-alive\r\n\r\n"
            ).encode()
            source = root / "query-exfil.pcap"
            source.write_bytes(_pcap([_tcp_packet(100, request)]))
            result = ForensicsSolver().solve(
                _context(root, source, "pcap", "HTTP Base64 query exfiltration")
            )
            candidate = next(item for item in result.candidates if item["value"] == flag)
            index_path = next(Path(path) for path in result.artifacts if path.endswith("http-query-index.json"))
            index = json.loads(index_path.read_text(encoding="utf-8"))
            output_exists = Path(index["values"][0]["output"]).is_file()

        self.assertEqual(candidate["analyzer"], "pcap-http-query-base64")
        self.assertEqual(candidate["query_parameter"], "data")
        self.assertTrue(any(Path(path).name.startswith("http-query-") for path in result.artifacts))
        self.assertEqual(index["values"][0]["query_parameter"], "data")
        self.assertEqual(index["values"][0]["stream"], 0)
        self.assertTrue(output_exists)

    def test_pcap_extracts_base64_json_file_records_as_safe_derived_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ICO{pcap_file_record_payload}"
            records = [
                {"type": "file", "path": "/home/ico/flag.txt", "data": base64.b64encode(flag).decode()},
                {"type": "file", "path": "../../outside.txt", "data": base64.b64encode(b"safe").decode()},
            ]
            stream = b"\n".join(json.dumps(record).encode() for record in records) + b"\n"
            source = root / "file-records.pcap"
            source.write_bytes(_pcap([_tcp_packet(100, stream)]))

            result = ForensicsSolver().solve(_context(root, source, "pcap", "JSONL file export"))
            outputs = [Path(path) for path in result.derived_inputs]
            output_bytes = [path.read_bytes() for path in outputs]
            outputs_are_safe = all(
                path.resolve().is_relative_to((root / "report" / "artifacts").resolve()) for path in outputs
            )
            values = {item["value"] for item in result.candidates}
            outside_exists = (root / "outside.txt").exists()

        self.assertEqual(len(outputs), 2)
        self.assertTrue(outputs_are_safe)
        self.assertEqual(output_bytes[0], flag)
        self.assertIn("ICO{pcap_file_record_payload}", values)
        self.assertFalse(outside_exists)

    def test_sqlite_hex_cells_are_decoded_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "cache.db"
            connection = sqlite3.connect(source)
            connection.execute("CREATE TABLE cache_entries(seq INTEGER, value TEXT)")
            flag = "CTF{sqlite_forensics}"
            connection.executemany("INSERT INTO cache_entries VALUES (?, ?)", [(2, flag.encode().hex()[6:]), (1, flag.encode().hex()[:6])])
            connection.commit()
            connection.close()
            before = hashlib.sha256(source.read_bytes()).hexdigest()
            result = ForensicsSolver().solve(_context(root, source, "data", "SQLite database hex cache"))
            after = hashlib.sha256(source.read_bytes()).hexdigest()
        self.assertIn(flag, {item["value"] for item in result.candidates})
        self.assertEqual(before, after)

    def test_sqlite_magic_detects_extensionless_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "browser.data"
            connection = sqlite3.connect(source)
            connection.execute("CREATE TABLE cache_entries(seq INTEGER, value TEXT)")
            flag = "ico{sqlite_magic_extensionless}"
            connection.execute("INSERT INTO cache_entries VALUES (?, ?)", (1, flag.encode().hex()))
            connection.commit()
            connection.close()
            context = _context(root, source, "data")
            detection = ForensicsSolver().detect(context)
            result = ForensicsSolver().solve(context)
        self.assertIsNotNone(detection)
        self.assertTrue(detection.metadata["sqlite_magic"])
        self.assertIn(flag, {item["value"] for item in result.candidates})

    def test_gpp_cpassword_is_decrypted_and_flag_is_extracted_without_execution(self):
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher  # noqa: F401
        except ImportError:
            try:
                from Crypto.Cipher import AES  # noqa: F401
            except ImportError:
                self.skipTest("install requirements-optional-forensics.txt for AES support")

        encrypted = (
            "B+iL/dnbBHSlVf66R8HOuAiGHAtFOVLZwXu0FYf+jQ6553UUgGNwSZucgdz98klz"
            "BuFqKtTpO1bRZIsrF8b4Hu5n6KccA7SBWlbLBWnLXAkPquHFwdC70HXBcRlz38q2"
        )
        expected = "DUCTF{D0n7_Us3_P4s5w0rds_1n_Gr0up_P0l1cy}"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Groups.xml"
            source.write_text(
                f'<Groups><User name="Backup"><Properties cpassword="{encrypted}" />'
                "</User></Groups>",
                encoding="utf-8",
            )
            context = _context(root, source, "text", "Group Policy Preferences cpassword")
            detection = ForensicsSolver().detect(context)
            result = ForensicsSolver().solve(context)

        self.assertIsNotNone(detection)
        self.assertEqual(detection.metadata.get("kind"), "gpp-cpassword")
        candidate = next(item for item in result.candidates if item["value"] == expected)
        self.assertEqual(candidate["triage"], "candidate")
        step = next(item for item in result.steps if item["name"] == "decrypt-gpp-cpassword")
        self.assertFalse(step["details"]["executed"])
        self.assertEqual(step["details"]["accounts"], ["Backup"])

    def test_pcap_dns_base32_labels_are_joined(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ico{dns_label_stream}"
            token = base64.b32encode(flag).decode("ascii").rstrip("=")
            labels = [token[index : index + 8] for index in range(0, len(token), 8)] + ["ex", "local"]
            source = root / "dns.pcap"
            source.write_bytes(_pcap([_dns_packet(labels)]))
            result = ForensicsSolver().solve(_context(root, source, "pcap", "DNS Base32 label stream"))
        self.assertIn(flag.decode(), {item["value"] for item in result.candidates})

    def test_pcap_linux_sll2_dns_base32_labels_are_joined(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"ico{sll2_dns_capture}"
            token = base64.b32encode(flag).decode("ascii").rstrip("=")
            labels = [token[index : index + 8] for index in range(0, len(token), 8)] + ["ex", "local"]
            ethernet_frame = _dns_packet(labels)
            source = root / "linux-cooked-v2.pcap"
            source.write_bytes(_pcap_linux_sll2([_linux_sll2_frame(ethernet_frame[14:])]))
            result = ForensicsSolver().solve(_context(root, source, "pcap", "DNS Base32 label stream"))
        self.assertIn(flag.decode(), {item["value"] for item in result.candidates})

    def test_log_text_is_scanned_without_treating_word_flag_as_answer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "auth.log"
            source.write_text("login failed: flag word only\nuser got ico{log_forensics}\n", encoding="utf-8")
            result = ForensicsSolver().solve(_context(root, source, "text", "auth log"))
        self.assertEqual({item["value"] for item in result.candidates}, {"ico{log_forensics}"})

    def test_malformed_pcap_is_recorded_as_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "broken.pcap"
            source.write_bytes(b"not a pcap")
            result = ForensicsSolver().solve(_context(root, source, "pcap"))
        self.assertEqual(result.status, "failed")
        self.assertIn("pcap", (result.error or "").lower())


if __name__ == "__main__":
    unittest.main()
