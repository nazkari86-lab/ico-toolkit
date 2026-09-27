#!/usr/bin/env python3
"""Create deterministic, synthetic ICO-family coverage fixtures.

The generated directory contains no real contest answers.  It is a regression
corpus for the offline solver and deliberately keeps expected answers outside
the scanner input root.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sqlite3
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmarks" / "ico_story_matrix"
EXPECTED = ROOT / "benchmarks" / "ico_story_matrix.expected.json"
STORIES = ("story_01", "story_02", "story_03")
DIFFICULTIES = ("easy", "medium", "hard")
FAMILIES = ("web", "pwn", "forensics", "reverse", "crypto")


def flag(story: str, family: str, difficulty: str) -> str:
    return f"ico{{matrix_{story[-2:]}_{family}_{difficulty}}}"


def _caesar_encrypt(value: str, shift: int) -> str:
    """Encrypt alphabetic characters with the same bounded transform we test."""

    output: list[str] = []
    for char in value:
        if char.isupper():
            output.append(chr((ord(char) - ord("A") + shift) % 26 + ord("A")))
        elif char.islower():
            output.append(chr((ord(char) - ord("a") + shift) % 26 + ord("a")))
        else:
            output.append(char)
    return "".join(output)


def _pcap_dns(label: str) -> bytes:
    qname = bytes([len(label)]) + label.encode() + b"\x00"
    dns = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
    udp = struct.pack(">HHHH", 53000, 53, 8 + len(dns), 0) + dns
    ip = bytes.fromhex("45000000") + struct.pack(">H", 1) + b"\x00\x00\x40\x11\x00\x00" + bytes.fromhex("c0a8012a08080808")
    ip = ip[:2] + struct.pack(">H", 20 + len(udp)) + ip[4:]
    frame = b"\x00" * 12 + b"\x08\x00" + ip + udp
    packet = struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + packet


def _pwn_binary(destination: Path) -> None:
    source = r'''
#include <stdio.h>
void win(void) { puts("review target"); }
int main(void) { char input[64]; gets(input); puts(input); return 0; }
'''
    with tempfile.TemporaryDirectory() as directory:
        c_path = Path(directory) / "fixture.c"
        c_path.write_text(source, encoding="utf-8")
        attempts = [
            ["cc", "-O0", "-fno-stack-protector", "-no-pie", str(c_path), "-o", str(destination)],
            ["clang", "-O0", "-fno-stack-protector", "-Wno-deprecated-non-prototype", "-Wno-implicit-function-declaration", "-no-pie", str(c_path), "-o", str(destination)],
        ]
        for command in attempts:
            try:
                subprocess.run(command, check=True, capture_output=True, timeout=20)
                return
            except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
                continue
    raise RuntimeError("a C compiler is required to generate the static pwn fixture")


def _case(story: str, family: str, difficulty: str, expected: dict[str, object]) -> None:
    directory = CORPUS / story / f"{family}_{difficulty}"
    directory.mkdir(parents=True, exist_ok=True)
    value = flag(story, family, difficulty)
    (directory / "task.txt").write_text(
        f"Synthetic {family} {difficulty} evidence for story {story}.\n",
        encoding="utf-8",
    )
    if family == "web":
        if difficulty == "easy":
            payload = f"HTTP/1.1 200 OK\nContent-Type: text/plain\n\n{value}\n"
            name = "capture.http"
        elif difficulty == "medium":
            encoded = base64.b64encode(value.encode()).decode()
            payload = json.dumps({"log": {"entries": [{"request": {"url": "https://task.invalid/api", "method": "GET"}, "response": {"status": 200, "content": {"text": encoded, "encoding": "base64"}}}]}})
            name = "capture.har"
        else:
            token_payload = base64.urlsafe_b64encode(json.dumps({"flag": value}).encode()).rstrip(b"=").decode()
            payload = f"HTTP/1.1 200 OK\n\n{{\"token\": \"eyJhbGciOiJub25lIn0.{token_payload}.x\"}}\n"
            name = "capture.http"
        (directory / name).write_text(payload, encoding="utf-8")
        expected.update({"status": "candidate", "evidence_state": "transcript-derived", "value": value, "family": family, "difficulty": difficulty})
    elif family == "crypto":
        if difficulty == "easy":
            shift = 3
            cipher = _caesar_encrypt(value, shift)
            payload = f"cipher: {cipher}\n"
        elif difficulty == "medium":
            key = 0x5A
            cipher = bytes(ord(char) ^ key for char in value).hex()
            payload = f"key=0x{key:02x}\ncipher={cipher}\n"
        else:
            message = int.from_bytes(value.encode(), "big")
            ciphertext = message**3
            payload = f"n={ciphertext + 1}\ne=3\nc={ciphertext}\n"
        task_method = {
            "easy": "Caesar shift 3",
            "medium": "known-key XOR",
            "hard": "RSA low exponent",
        }[difficulty]
        (directory / "task.txt").write_text(
            f"Synthetic crypto {difficulty} evidence for story {story}; {task_method}.\n",
            encoding="utf-8",
        )
        (directory / "evidence.cipher").write_text(payload, encoding="utf-8")
        expected.update({"status": "candidate", "evidence_state": "candidate", "value": value, "family": family, "difficulty": difficulty})
    elif family == "forensics":
        if difficulty == "easy":
            (directory / "timeline.log").write_text(f"2026-01-01 process=analyst result={value}\n", encoding="utf-8")
        elif difficulty == "medium":
            database = directory / "browser.data"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE cache_entries(seq INTEGER, value TEXT)")
            split = len(value) // 2
            connection.executemany("INSERT INTO cache_entries VALUES (?, ?)", [(2, value[split:].encode().hex()), (1, value[:split].encode().hex())])
            connection.commit()
            connection.close()
        else:
            token = base64.b32encode(value.encode()).decode().rstrip("=")
            (directory / "dns.capture").write_bytes(_pcap_dns(token))
        expected.update({"status": "candidate", "evidence_state": "candidate", "value": value, "family": family, "difficulty": difficulty})
    elif family == "reverse":
        if difficulty == "easy":
            key = 0x33
            payload = bytes(char ^ key for char in value.encode())
            (directory / "checker.revbin").write_bytes(payload)
        elif difficulty == "medium":
            (directory / "checker.revbin").write_bytes(base64.b64encode(value.encode()))
        else:
            binary = directory / "checker.revbin"
            _pwn_binary(binary)
            (directory / "task.txt").write_text(
                "Synthetic reverse hard ret2win review; discover the stack offset "
                "and win target statically; these parameters are not supplied.\n",
                encoding="utf-8",
            )
        expected.update(
            {
                "status": "candidate" if difficulty != "hard" else "candidate-review",
                "evidence_state": "candidate" if difficulty != "hard" else "candidate-review",
                "value": value if difficulty != "hard" else None,
                "family": family,
                "difficulty": difficulty,
            }
        )
    elif family == "pwn":
        binary = directory / "challenge.pwnbin"
        _pwn_binary(binary)
        (directory / "task.txt").write_text(
            f"Synthetic pwn {difficulty} ret2win review; static payload only; offset={40 + len(difficulty)} target=0x401136.\n",
            encoding="utf-8",
        )
        expected.update({"status": "payload-ready", "evidence_state": "payload-ready", "value": None, "family": family, "difficulty": difficulty})


def main() -> int:
    # Regeneration is deliberately deterministic and idempotent.  In
    # particular, SQLite fixtures otherwise retain tables from a previous run.
    if CORPUS.exists():
        shutil.rmtree(CORPUS)
    CORPUS.mkdir(parents=True, exist_ok=True)
    expected: dict[str, object] = {"schema_version": 2, "cases": []}
    for story in STORIES:
        for family in FAMILIES:
            for difficulty in DIFFICULTIES:
                item: dict[str, object] = {"story": story, "case": f"{family}_{difficulty}"}
                _case(story, family, difficulty, item)
                expected["cases"].append(item)
    for family in FAMILIES:
        directory = CORPUS / "negative" / f"{family}_negative"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "task.txt").write_text(f"Synthetic negative {family} case with no derivable answer.\n", encoding="utf-8")
        (directory / "evidence.bin").write_bytes(hashlib.sha256(f"negative-{family}".encode()).digest())
        expected["cases"].append({"story": "negative", "case": f"{family}_negative", "status": "unsupported", "evidence_state": "unsupported", "value": None, "family": family, "difficulty": "negative"})
    EXPECTED.write_text(json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
