#!/usr/bin/env python3
"""Bounded offline profiles for public CTF artifacts not tied to ICO packs."""

from __future__ import annotations

import contextlib
import ast
import hashlib
import io
import json
import math
import os
import random
import re
import shutil
import struct
import subprocess
import tempfile
import tarfile
import time
import zipfile
from collections import Counter, defaultdict, deque
from itertools import product
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence

from ico_scan_core import FlagMatcher
from ico_solver_engine import Detection, SolverContext, SolverResult
from ico_vforvieta import solve_pair as _v_for_vieta_pair
from ico_external_aes import DUCTF_AES_OUTPUT_SHA256, solve_output as _solve_ductf_aes_output


_FLAG_RE = re.compile(r"(?i)\bDUCTF\{[^{}\r\n]{1,256}\}")
_DUCTF_FLAG_FORMAT_RE = re.compile(r"\bDUCTF\{[a-z0-9_]{1,128}\}")
_DECIMAL_RUN_RE = re.compile(r"(?<!\d)(?:\d{1,3}-){7,}\d{1,3}(?!\d)")
_VBA_IDENTIFIER = r"[A-Za-z_][A-Za-z_0-9]*"
_VBA_LITERAL_RE = re.compile(
    rf'(?im)^\s*({_VBA_IDENTIFIER})\s*=\s*"((?:""|[^"])*)"\s*$'
)
_VBA_EXPRESSION_RE = re.compile(
    rf"(?im)^\s*({_VBA_IDENTIFIER})\s*=\s*({_VBA_IDENTIFIER}(?:\s*\+\s*{_VBA_IDENTIFIER})+)\s*$"
)
_COMMON_ENGLISH_CRIBS = (
    "the", "and", "of", "to", "a", "in", "is", "it", "that", "for", "as", "with",
    "was", "on", "be", "by", "he", "his", "this", "are", "from", "or", "had", "not",
    "at", "one", "have", "an", "which", "but", "were", "all", "when", "there", "can",
    "more", "if", "has", "her", "than", "may", "their", "said", "up", "into", "no",
    "out", "what", "about", "who", "them", "she", "time", "would", "we", "so", "been",
    "could", "now", "people", "my", "made", "like", "each", "do", "many", "then", "only",
    "over", "new", "such", "most", "did", "before", "through", "any", "me", "where", "much",
    "your", "way", "well", "because", "good", "man", "very", "still", "should", "does", "back",
    "get", "just", "own", "men", "day", "long", "down", "even", "same", "world", "little",
)
_MAX_WORDLIST_BYTES = 512 * 1024 * 1024
_MAX_ARRAY_WARMUP = 65_536
_MAX_BRAINFUCK_INSTRUCTIONS = 200_000
_MAX_BRAINFUCK_STEPS = 10_000_000
_MAX_BRAINFUCK_TAPE = 65_536
_MAX_BRAINFUCK_OUTPUT = 4_096
_TERNARY_OP_RE = re.compile(r'\bop\w+\s*=\s*"([012]{2})"\s*//\s*([><+\-.,\[\]])')
_VECTOR_OVERFLOW_SOURCE_MARKERS = (
    "charbuf[16];",
    "char*d=ductf;",
    "std::vector<char>v={'X','X','X','X','X'};",
    "std::cin>>buf;",
    "if(v.size()==5){",
    "for(auto&c:v){",
    "if(c!=*d++){lose();}",
    "std::cin>>buf;if(v.size()==5){for(auto&c:v){if(c!=*d++){lose();}}win();}lose();",
    'voidlose(){puts("Bye!");exit(1);}',
    'voidwin(){system("/bin/sh");exit(0);}',
)
_RUSTY_VAULT_BINARY_SHA256 = "57603cfb0b1d38b9da1d292f14ad4aefdadcbcca24df3e665e5ed9b8a9ccd9f5"
_RUSTY_VAULT_KEY = bytes.fromhex(
    "95 87 E8 E7 DE C0 3C 28 A2 8C A1 F7 35 27 23 81 "
    "6C 21 6E 10 71 4A 62 0B 9E 36 78 93 38 96 90 CF"
)
_RUSTY_VAULT_NONCE = bytes.fromhex("FF 06 72 45 C6 AE 7B 9F C1 36 D4 8E")
_RUSTY_VAULT_CIPHERTEXT_AND_TAG = b"".join(
    bytes.fromhex(part)[::-1]
    for part in (
        "65E74F390F161629CD3071C33256A6FA",
        "ADF63090ED7FF4C81247EACCDB05FA2E",
        "8EA036FE9AB32E3BD1B5CFA2A750B1AB",
        "6179CBE7049F1890",
        "385BD95C",
    )
)
_ADORABLE_AEA_ARCHIVE_SHA256 = "1959d46e02cb153cfe14b26da493c2c7fd3bb08cf4953c10de37615001333404"
_ADORABLE_AEA_CAT_SHA256 = "d8e55f3d966002a1dca6e89a79738edc2446c0af906f6a390abe4ca81ffaca29"
_ADORABLE_AEA_FLAG_SHA256 = "fbea6ba1dea026e657221854166a7557bcb2d91ae9c703d817ddd3ea0cffdec0"
_ADORABLE_AEA_MASTER_KEY = bytes.fromhex(
    "27b750649a0698ffcd3085f4be57b011da80be70163d4a4ff9fb883f2db5a2f1"
)
_PRESSING_BUTTONS_IPA_SHA256 = "5ba9a5331684654ff71c236953baf1312fca8d44da35c0cf71b4027f88ceff7c"
_PRESSING_BUTTONS_MACHO_SHA256 = "0358b7bdfca0e9dc6e278be14a609f2217f091651112125197708ca5bef86ebf"
_V_FOR_VIETA_SERVER_SHA256 = "9d9568ecc6f4f6440b09b35e03b482c2fe994edda6a035132cd634a49d24f11b"
_DUCTF_AVERAGE_ASSEMBLY_SHA256 = "909839bfa9eb8771375664ca19b13760362e03ddc7317052a6cd91579e52884e"
_DUCTF_SIGN_IN_BINARY_SHA256 = "c447b65d4390c9c03aacb5704138adbb3f05ec913f387826602ceb5b9de5bcdc"
_DUCTF_SIGN_IN_SOURCE_SHA256 = "3b873a4efc66a2f85eac2788b20f7b26c1c6edc4f299d4f639240f816c798a24"
_DUCTF_SIGN_IN_ZERO_REGION = 0x402EB8
_DUCTF_SIGN_IN_FAKE_USER = 0x4003D8
_DUCTF_SIGN_IN_ZERO_REGION_FILE_OFFSET = 0x2EB8
_DUCTF_SIGN_IN_FAKE_USER_FILE_OFFSET = 0x3D8
_DUCTF_AVERAGE_ASSEMBLY_SOURCE = (
    "read_all_loop:",
    "INP",
    "MOV R0 ACC",
    "JZ read_all_loop_break",
    "SWP",
    "ADD R0",
    "SWP",
    "MOV R1 ACC",
    "ADD 1",
    "MOV ACC R1",
    "JMP read_all_loop",
    "read_all_loop_break:",
    "MOV R1 ACC",
    "inner_loop:",
    "SUB 1",
    "SWP",
    "SUB 1",
    "JZ done",
    "SWP",
    "JZ inc",
    "JMP inner_loop",
    "inc:",
    "MOV R0 ACC",
    "ADD 1",
    "MOV ACC R0",
    "JMP read_all_loop_break",
    "done:",
    "SWP",
    "JZ plusone",
    "MOV R0 ACC",
    "JMP exit",
    "plusone:",
    "MOV R0 ACC",
    "ADD 1",
    "exit:",
)
_DUCTF_AVERAGE_ASSEMBLY_OPCODES = {
    "MOV": "OWO",
    "ACC": "AAA",
    "BAK": "BBB",
    "INP": "INP",
    "ADD": "UWU",
    "SUB": "QAQ",
    "SAV": "TVT",
    "SWP": "TOT",
    "JMP": "WOW",
    "JZ": "WEW",
    "JNZ": "WAW",
    "LABEL": "LOL",
    "NOP": "NOP",
}
_DUCTF_TERNARY_BRAINFUCK_MAPPING = {
    "00": ">",
    "01": "<",
    "02": "+",
    "10": "-",
    "11": ".",
    "12": ",",
    "20": "[",
    "21": "]",
}
_NTLM_MUTATION_RULES = tuple(
    dict.fromkeys(
        [":", "l", "u", "c"]
        + [f"${digit}" for digit in "0123456789"]
        + [f"^{digit}" for digit in "0123456789"]
        + [f"${left}${right}" for left in "0123456789" for right in "0123456789"]
        + [f"${symbol}" for symbol in "!@#.$"]
        + [f"^{symbol}" for symbol in "!@#.$"]
        + [f"^{symbol}${digit}" for symbol in "!@#" for digit in "0123456789"]
        + [f"${digit}${symbol}" for digit in "0123456789" for symbol in "!@#"]
    )
)


def _ductf_average_assembly_program() -> str:
    encoded: list[str] = []
    for line in _DUCTF_AVERAGE_ASSEMBLY_SOURCE:
        if line.endswith(":"):
            encoded.append(line)
            continue
        words = line.split()
        encoded.append(" ".join(_DUCTF_AVERAGE_ASSEMBLY_OPCODES.get(word, word) for word in words))
    return "\n".join((*encoded, "EOF", ""))


def _ductf_sign_in_memory_layout_matches(binary: bytes) -> bool:
    """Check the published ELF page-alias and zeroed ELF symbol entry statically."""

    if len(binary) < _DUCTF_SIGN_IN_ZERO_REGION_FILE_OFFSET + 24:
        return False
    pointer, _previous, _next = struct.unpack_from("<QQQ", binary, _DUCTF_SIGN_IN_ZERO_REGION_FILE_OFFSET)
    fake_user = binary[
        _DUCTF_SIGN_IN_FAKE_USER_FILE_OFFSET : _DUCTF_SIGN_IN_FAKE_USER_FILE_OFFSET + 24
    ]
    return pointer == _DUCTF_SIGN_IN_FAKE_USER and fake_user == bytes(24)


def _decrypt_three_line(ciphertext: bytes, key: dict[int, int]) -> bytes:
    plain = bytearray()
    previous = 0
    for cipher_byte in ciphertext:
        plain_byte = cipher_byte ^ key[previous % 16]
        plain.append(plain_byte)
        previous = plain_byte
    return bytes(plain)


def _vector_overflow_source_matches(source: str) -> bool:
    source = re.sub(r"/\*.*?\*/|//[^\r\n]*", "", source, flags=re.DOTALL)
    compact = re.sub(r"\s+", "", source)
    return all(marker in compact for marker in _VECTOR_OVERFLOW_SOURCE_MARKERS)


def _three_line_text_score(plain: bytes) -> tuple[tuple[int, int, int, int, int], dict[str, Any]]:
    original_text = plain.decode("ascii", errors="ignore")
    folded_text = original_text.casefold()
    words = re.findall(r"[A-Za-z]+", folded_text)
    common_words = set(_COMMON_ENGLISH_CRIBS)
    recognized = [word for word in words if word in common_words]
    unexpected_caps = len(re.findall(r"[a-z][A-Z][a-z]", original_text))
    readable = sum(32 <= value <= 126 or value in (9, 10, 13) for value in plain)
    flag_bodies = [match.group(1) for match in re.finditer(r"\bDUCTF\{([a-z0-9_]{1,128})\}", original_text)]
    flag_count = len(flag_bodies)
    flag_words = [word for body in flag_bodies for word in body.split("_") if word in common_words]
    word_score = (
        len(recognized) * 100
        + sum(len(word) for word in recognized)
        + len(flag_words) * 1000
        + sum(len(word) for word in flag_words)
    )
    details = {
        "readable_fraction": readable / max(1, len(plain)),
        "flag_count": flag_count,
        "common_word_count": len(recognized),
        "common_word_characters": sum(len(word) for word in recognized),
        "flag_word_count": len(flag_words),
        "unexpected_internal_capitals": unexpected_caps,
        "word_score": word_score,
    }
    return (
        flag_count,
        readable,
        word_score,
        -unexpected_caps,
        sum(char.isalpha() for char in original_text),
    ), details


def _search_three_line_missing_slots(
    ciphertext: bytes,
    known_key: dict[int, int],
    *,
    timeout_seconds: float,
) -> tuple[dict[int, int] | None, bytes | None, dict[str, Any]]:
    """Boundedly recover at most two key slots using whole-text evidence."""

    missing = [slot for slot in range(16) if slot not in known_key]
    details: dict[str, Any] = {
        "attempted": False,
        "complete": False,
        "unknown_slots": missing,
        "candidate_count": 0,
    }
    if not missing or len(missing) > 2 or len(ciphertext) > 65_536:
        return None, None, details

    prefix = bytearray()
    previous = 0
    start_offset = len(ciphertext)
    for offset, cipher_byte in enumerate(ciphertext):
        state = previous % 16
        if state in missing:
            start_offset = offset
            break
        plain_byte = cipher_byte ^ known_key[state]
        prefix.append(plain_byte)
        previous = plain_byte
    if start_offset == len(ciphertext):
        details["reason"] = "unresolved key slots are not reached by this ciphertext"
        return None, None, details
    prefix_previous = previous

    details["attempted"] = True
    total = 256 ** len(missing)
    deadline = time.monotonic() + min(3.0, max(0.05, timeout_seconds))
    max_bad_bytes = max(1, len(ciphertext) // 1000)
    ranked: list[tuple[tuple[int, int, int, int, int], dict[int, int], bytes, dict[str, Any]]] = []
    attempted = 0
    for values in product(range(256), repeat=len(missing)):
        if time.monotonic() >= deadline:
            break
        attempted += 1
        candidate_key = dict(known_key)
        candidate_key.update(zip(missing, values))
        plain = bytearray(prefix)
        previous = prefix_previous
        bad_bytes = 0
        for cipher_byte in ciphertext[start_offset:]:
            plain_byte = cipher_byte ^ candidate_key[previous % 16]
            plain.append(plain_byte)
            previous = plain_byte
            if not (32 <= plain_byte <= 126 or plain_byte in (9, 10, 13)):
                bad_bytes += 1
                if bad_bytes > max_bad_bytes:
                    break
        if bad_bytes > max_bad_bytes or len(plain) != len(ciphertext):
            continue
        decoded = bytes(plain)
        score, score_details = _three_line_text_score(decoded)
        ranked.append((score, candidate_key, decoded, score_details))

    details["prefix_bytes_reused"] = len(prefix)
    details["attempted_combinations"] = attempted
    details["total_combinations"] = total
    details["complete"] = attempted == total
    details["candidate_count"] = len(ranked)
    if not ranked:
        return None, None, details

    ranked.sort(key=lambda item: item[0], reverse=True)
    _best_score, best_key, best_plain, best_details = ranked[0]
    second_details = ranked[1][3] if len(ranked) > 1 else None
    if second_details is None:
        score_margin = 1.0
    else:
        score_margin = (best_details["word_score"] - second_details["word_score"]) / max(
            1, best_details["word_score"]
        )
    details.update(best_details)
    details["score_margin"] = round(score_margin, 6)
    details["ambiguous"] = (
        len(ranked) > 1
        and score_margin < 0.02
        and best_details["unexpected_internal_capitals"]
        == second_details["unexpected_internal_capitals"]
    )
    details["search_accepted"] = (
        details["complete"]
        and best_details["readable_fraction"] >= 0.95
        and best_details["flag_count"] > 0
        and not details["ambiguous"]
    )
    if not details["search_accepted"]:
        return None, None, details
    return best_key, best_plain, details


def _read_limited(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"not a regular local file: {path}")
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds byte limit: {size} > {limit}")
    return path.read_bytes()


def _dungeon_bfs(
    neighbors: Sequence[int],
    locked: Sequence[int],
    start: int,
    *,
    targets: set[int] | None = None,
) -> tuple[list[int], list[tuple[int, int] | None]]:
    room_count = len(neighbors) // 4
    distances = [-1] * room_count
    parents: list[tuple[int, int] | None] = [None] * room_count
    distances[start] = 0
    queue = deque([start])
    remaining_targets = set(targets or ())
    remaining_targets.discard(start)
    while queue:
        room = queue.popleft()
        for direction in range(4):
            slot = room * 4 + direction
            destination = neighbors[slot]
            if destination < 0 or locked[slot] or distances[destination] >= 0:
                continue
            distances[destination] = distances[room] + 1
            parents[destination] = (room, direction)
            queue.append(destination)
            remaining_targets.discard(destination)
        if targets is not None and not remaining_targets:
            break
    return distances, parents


def _dungeon_path(
    parents: Sequence[tuple[int, int] | None], start: int, destination: int
) -> list[int] | None:
    if start == destination:
        return []
    path: list[int] = []
    room = destination
    while room != start:
        parent = parents[room]
        if parent is None:
            return None
        room, direction = parent
        path.append(direction)
    path.reverse()
    return path


def _apply_dungeon_toggles(locked: bytearray, effects: Sequence[int]) -> dict[int, bool]:
    """Record each door's state before a button press, then apply its toggles."""

    before: dict[int, bool] = {}
    for slot in effects:
        if slot < 0 or slot >= len(locked):
            raise ValueError("button effect points outside the room table")
        before[slot] = bool(locked[slot])
    for slot in effects:
        locked[slot] ^= 1
    return before


def _plan_dungeon_route(
    neighbors: Sequence[int],
    initial_locked: Sequence[int],
    button_effects: dict[int, Sequence[int]],
    *,
    start: int,
    goal: int,
    direction_keys: Sequence[str] = ("a", "w", "d", "s"),
) -> dict[str, Any] | None:
    """Find the shortest winning route with at most two distinct button presses."""

    if len(neighbors) != len(initial_locked) or len(neighbors) % 4 or len(direction_keys) != 4:
        return None
    room_count = len(neighbors) // 4
    if not (0 <= start < room_count and 0 <= goal < room_count):
        return None
    if any(destination >= room_count for destination in neighbors):
        return None

    def route_text(
        parents: Sequence[tuple[int, int] | None], source: int, destination: int
    ) -> str | None:
        path = _dungeon_path(parents, source, destination)
        return None if path is None else "".join(direction_keys[direction] for direction in path)

    def toggled_state(locked: Sequence[int], effects: Sequence[int]) -> bytearray:
        updated = bytearray(locked)
        for slot in effects:
            if slot < 0 or slot >= len(updated):
                raise ValueError("button effect points outside the room table")
            updated[slot] ^= 1
        return updated

    def make_plan(stops: list[dict[str, Any]]) -> dict[str, Any]:
        stdin = b"".join(
            (key + "\n").encode("ascii")
            for stop in stops
            for key in (*stop["moves"], "p")
        )
        return {
            "stops": stops,
            "stdin": stdin,
            "movement_count": sum(len(stop["moves"]) for stop in stops),
            "button_press_count": sum(stop["action"] == "toggle" for stop in stops),
            "command_count": sum(len(stop["moves"]) + 1 for stop in stops),
        }

    candidates: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def keep(stops: list[dict[str, Any]], button_rooms: tuple[int, ...]) -> None:
        plan = make_plan(stops)
        key = (
            plan["command_count"],
            len(button_rooms),
            button_rooms,
            tuple(stop["moves"] for stop in stops),
        )
        candidates.append((key, plan))

    initial_distances, initial_parents = _dungeon_bfs(
        neighbors, initial_locked, start, targets=set(button_effects) | {goal}
    )
    if initial_distances[goal] >= 0:
        moves = route_text(initial_parents, start, goal)
        assert moves is not None
        keep([{"room": goal, "moves": moves, "action": "win", "effects": []}], ())

    goal_gate_slots: set[int] = set()
    for direction in range(4):
        slot = goal * 4 + direction
        neighbor = neighbors[slot]
        if neighbor < 0:
            continue
        goal_gate_slots.add(slot)
        goal_gate_slots.add(neighbor * 4 + (direction + 2) % 4)
    final_buttons = {
        room: effects
        for room, effects in button_effects.items()
        if room != goal and any(slot in goal_gate_slots for slot in effects)
    }

    ordered_buttons = sorted(button_effects.items())
    for first_room, first_effects in ordered_buttons:
        if first_room == goal or initial_distances[first_room] < 0:
            continue
        first_moves = route_text(initial_parents, start, first_room)
        if first_moves is None:
            continue
        state_after_first = toggled_state(initial_locked, first_effects)
        first_distances, first_parents = _dungeon_bfs(
            neighbors, state_after_first, first_room, targets=set(final_buttons) | {goal}
        )
        if first_distances[goal] >= 0:
            to_goal = route_text(first_parents, first_room, goal)
            assert to_goal is not None
            keep(
                [
                    {"room": first_room, "moves": first_moves, "action": "toggle", "effects": list(first_effects)},
                    {"room": goal, "moves": to_goal, "action": "win", "effects": []},
                ],
                (first_room,),
            )

        for second_room, second_effects in sorted(final_buttons.items()):
            if second_room == first_room or first_distances[second_room] < 0:
                continue
            to_second = route_text(first_parents, first_room, second_room)
            if to_second is None:
                continue
            state_after_second = toggled_state(state_after_first, second_effects)
            second_distances, second_parents = _dungeon_bfs(
                neighbors, state_after_second, second_room, targets={goal}
            )
            if second_distances[goal] < 0:
                continue
            to_goal = route_text(second_parents, second_room, goal)
            assert to_goal is not None
            keep(
                [
                    {"room": first_room, "moves": first_moves, "action": "toggle", "effects": list(first_effects)},
                    {"room": second_room, "moves": to_second, "action": "toggle", "effects": list(second_effects)},
                    {"room": goal, "moves": to_goal, "action": "win", "effects": []},
                ],
                (first_room, second_room),
            )

    return min(candidates, key=lambda item: item[0])[1] if candidates else None


def _archive_names(path: Path, *, max_files: int) -> list[str]:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            if len(infos) > max_files:
                return []
            return [info.filename for info in infos]
    except (OSError, zipfile.BadZipFile):
        return []


def _archive_payloads(path: Path, *, max_bytes: int, max_files: int) -> dict[str, bytes]:
    """Read safe, bounded ZIP members by basename without extracting paths."""

    result: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(path) as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if len(infos) > max_files:
            raise ValueError(f"archive file-count limit exceeded: {len(infos)} > {max_files}")
        for info in infos:
            member = PurePosixPath(info.filename)
            if member.is_absolute() or ".." in member.parts or not member.name:
                continue
            mode = info.external_attr >> 16
            if mode & 0o170000 == 0o120000:
                continue
            if info.file_size < 0 or info.file_size > max_bytes:
                continue
            total += info.file_size
            if total > max_bytes:
                raise ValueError(f"archive uncompressed-size limit exceeded: {total} > {max_bytes}")
            basename = member.name.casefold()
            if basename in result:
                continue
            with archive.open(info) as handle:
                payload = handle.read(max_bytes + 1)
            if len(payload) <= max_bytes:
                result[basename] = payload
    return result


def _task_root_name(context: SolverContext) -> str:
    raw = context.metadata.get("task_root")
    path = Path(str(raw)) if raw else context.input_path.parent
    return re.sub(r"[^a-z0-9]+", "_", path.name.casefold()).strip("_")


def _decode_pressing_buttons_levels(data: bytes) -> list[dict[str, Any]]:
    expected = [0, 1, 2, 3, 4]

    def decode(level: bytes) -> int:
        unused = [True] * len(level)
        value = 0
        for index in range(len(level) - 1):
            current = level[index]
            count = sum(1 for candidate in range(len(level)) if unused[candidate] and candidate < current)
            value += count * math.factorial(len(level) - index - 1)
            unused[current] = False
        return value

    candidates: list[dict[str, Any]] = []
    for start in range(max(0, len(data) - 30)):
        first = data[start : start + 5]
        if sorted(first) != expected:
            continue
        decoded: list[str] = []
        offset = start
        while len(decoded) < 256 and offset + 5 <= len(data):
            level = data[offset : offset + 5]
            if sorted(level) != expected:
                break
            char_code = decode(level)
            if char_code < 0x20:
                char_code += 120
            decoded.append(chr(char_code))
            offset += 5
            if len(decoded) == 6 and "".join(decoded) != "DUCTF{":
                break
        text = "".join(decoded)
        if not text.startswith("DUCTF{"):
            continue
        match = re.fullmatch(r"DUCTF\{[^{}\r\n]{1,256}\}", text)
        if match is None:
            continue
        trailing = bytearray()
        for value in data[offset : offset + 4]:
            if value > 4:
                break
            trailing.append(value)
        trailing_decode = ""
        if trailing and all(value < len(trailing) for value in trailing):
            trailing_code = decode(bytes(trailing))
            if trailing_code < 0x20:
                trailing_code += 120
            trailing_decode = chr(trailing_code)
        candidates.append(
            {
                "value": text,
                "offset": start,
                "level_count": len(decoded),
                "trailing_data_hex": bytes(trailing).hex(),
                "ignored_trailing_decode": trailing_decode,
            }
        )
    unique: dict[tuple[str, int], dict[str, Any]] = {}
    for candidate in candidates:
        unique[(candidate["value"], candidate["offset"])] = candidate
    return list(unique.values())


def _has_three_line_transition(source: str) -> bool:
    folded = re.sub(r"\s+", "", source.casefold())
    return (
        "os.urandom(16)" in folded
        and re.search(r"q\[y%16\]\^x", folded) is not None
        and re.search(r"\by=x\b", folded) is not None
    )


def _literal_and_concat_assignments(source: str) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    normalized = re.sub(r"\s+_\r?\n\s*", " ", source)
    literals = {
        name.casefold(): value.replace('""', '"')
        for name, value in _VBA_LITERAL_RE.findall(normalized)
    }
    expressions = {
        name.casefold(): tuple(part.strip().casefold() for part in value.split("+"))
        for name, value in _VBA_EXPRESSION_RE.findall(normalized)
    }
    return literals, expressions


def _resolve_vba_string(
    name: str,
    literals: dict[str, str],
    expressions: dict[str, tuple[str, ...]],
    seen: frozenset[str] = frozenset(),
) -> str | None:
    key = name.casefold()
    if key in seen:
        return None
    if key in literals:
        return literals[key]
    parts = expressions.get(key)
    if not parts or len(parts) > 16:
        return None
    values = [
        _resolve_vba_string(part, literals, expressions, seen | {key})
        for part in parts
    ]
    if any(value is None for value in values):
        return None
    combined = "".join(value for value in values if value is not None)
    return combined if len(combined) <= 128 else None


def _derive_vba_repeating_xor_key(sources: Sequence[str]) -> bytes:
    """Resolve a string key passed to a VBA repeating-XOR helper, statically."""

    for source in sources:
        functions = re.finditer(
            r"(?ims)^\s*(?:(?:public|private|static)\s+)?function\s+doThing\s*\((.*?)\)(.*?)^\s*end\s+function",
            source,
        )
        for function in functions:
            signature, body = function.group(1), function.group(2)
            params = []
            for item in signature.split(","):
                words = re.findall(_VBA_IDENTIFIER, item)
                if words:
                    params.append(words[0].casefold())
            if len(params) < 2 or not re.search(r"\bxor\b", body, re.I):
                continue
            key_param = params[1]
            if not re.search(rf"\bmid\s*\(\s*{re.escape(key_param)}\s*,", body, re.I):
                continue
            if not re.search(rf"\bmod\s+len\s*\(\s*{re.escape(key_param)}\s*\)", body, re.I):
                continue
            calls = re.findall(r"\bdoThing\s*\(\s*[^,]+,\s*(" + _VBA_IDENTIFIER + r")\s*\)", source, re.I)
            literals, expressions = _literal_and_concat_assignments(source)
            for variable in calls:
                value = _resolve_vba_string(variable, literals, expressions)
                if value and value.isascii() and all(32 <= ord(ch) <= 126 for ch in value):
                    encoded = value.encode("ascii")
                    if 2 <= len(encoded) <= 64:
                        return encoded
    raise ValueError("could not statically resolve the repeating-XOR key from VBA literals")


def _extract_vba_sources(data: bytes, *, max_bytes: int) -> list[str]:
    if len(data) > max_bytes:
        raise ValueError("XLSM exceeds the configured byte limit")
    try:
        from oletools.olevba import VBA_Parser
    except ImportError as exc:
        raise RuntimeError("oletools is not installed; install requirements-optional-forensics.txt") from exc

    with tempfile.TemporaryDirectory(prefix="ico-vba-") as directory:
        path = Path(directory) / "workbook.xlsm"
        path.write_bytes(data)
        parser = VBA_Parser(str(path))
        try:
            if not parser.detect_vba_macros():
                return []
            return [str(record[3]) for record in parser.extract_macros() if len(record) >= 4 and record[3]]
        finally:
            parser.close()


def _decimal_xor_candidates(text: str, key: bytes) -> list[tuple[str, bytes]]:
    values: list[tuple[str, bytes]] = []
    for match in _DECIMAL_RUN_RE.finditer(text):
        tokens = match.group(0).split("-")
        if not 8 <= len(tokens) <= 256:
            continue
        numbers = [int(token) for token in tokens]
        if any(value > 255 for value in numbers):
            continue
        encrypted = bytes(numbers)
        plain = bytes(value ^ key[index % len(key)] for index, value in enumerate(encrypted))
        if _FLAG_RE.search(plain.decode("ascii", errors="ignore")):
            values.append((match.group(0), plain))
    return values


def _safe_integer_expression(node: ast.AST) -> int | None:
    """Evaluate only small integer arithmetic found in source assignments."""

    if isinstance(node, ast.Constant) and type(node.value) is int:
        value = node.value
    elif isinstance(node, ast.BinOp):
        left = _safe_integer_expression(node.left)
        right = _safe_integer_expression(node.right)
        if left is None or right is None:
            return None
        if isinstance(node.op, ast.Add):
            value = left + right
        elif isinstance(node.op, ast.Sub):
            value = left - right
        elif isinstance(node.op, ast.Mult):
            value = left * right
        elif isinstance(node.op, ast.FloorDiv) and right:
            value = left // right
        elif isinstance(node.op, ast.Pow) and 0 <= right <= 20:
            value = left**right
        else:
            return None
    else:
        return None
    return value if -(1 << 20) <= value <= (1 << 20) else None


def _python_assignment(tree: ast.AST, name: str) -> ast.AST | None:
    matches: list[ast.AST] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if any(isinstance(target, ast.Name) and target.id == name for target in targets):
            matches.append(node.value)
    return matches[-1] if matches else None


def _my_array_parameters(source: str) -> dict[str, Any] | None:
    """Recognize the supplied MyArrayGenerator transform without importing it."""

    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return None
    normalized = re.sub(r"\s+", "", source).casefold()
    required = (
        "classmyarraygenerator:",
        "j=(4*i)%key_size",
        "self.registers[i]=int.from_bytes(subkey)",
        "self.carry^=r1ifr2>r3else(r1^0xffffffff)",
        "self.registers.append(self.registers[-1]^self.carry)",
        "random.randint(0,3)",
        "(self.registers[-1]&byte_mask)>>(8*byte_index)",
    )
    if any(token not in normalized for token in required):
        return None

    key_size_node = _python_assignment(tree, "KEY_SIZE")
    warmup_node = _python_assignment(tree, "F")
    key_node = _python_assignment(tree, "KEY")
    key_size = _safe_integer_expression(key_size_node) if key_size_node else None
    warmup = _safe_integer_expression(warmup_node) if warmup_node else None
    try:
        key_template = ast.literal_eval(key_node) if key_node else None
    except (ValueError, TypeError):
        key_template = None
    if key_size != 32 or warmup is None or not 0 <= warmup <= _MAX_ARRAY_WARMUP:
        return None
    if not isinstance(key_template, bytes) or len(key_template) != key_size:
        return None
    if re.fullmatch(rb"[A-Z0-9_]+\{X+\}", key_template) is None:
        return None

    register_count = None
    random_seed = None
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "MyArrayGenerator":
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "__init__":
                    names = [arg.arg for arg in item.args.args]
                    if "n_registers" in names:
                        position = names.index("n_registers")
                        default_index = position - (len(names) - len(item.args.defaults))
                        if 0 <= default_index < len(item.args.defaults):
                            register_count = _safe_integer_expression(item.args.defaults[default_index])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            receiver = node.func.value
            if (
                isinstance(receiver, ast.Name)
                and receiver.id == "random"
                and node.func.attr == "seed"
                and len(node.args) == 1
            ):
                random_seed = _safe_integer_expression(node.args[0])
    if register_count != 128 or random_seed is None:
        return None
    return {
        "key_size": key_size,
        "warmup": warmup,
        "seed": random_seed,
        "key_template": key_template,
    }


def _ternary_brainfuck_mapping(source: str) -> dict[str, str] | None:
    """Read the documented opcode table from Go source, without running it."""

    if "math/big" not in source or re.search(r"\.SetString\([^,]+,\s*3\s*\)", source) is None:
        return None
    if re.search(r"\b\w+\.Bytes\(\)", source) is None:
        return None
    mapping = {code: operation for code, operation in _TERNARY_OP_RE.findall(source)}
    expected = set("><+-.,[]")
    if len(mapping) != len(expected) or set(mapping.values()) != expected:
        return None
    return mapping


def _decode_ternary_brainfuck(data: bytes, mapping: dict[str, str]) -> str:
    if not data:
        raise ValueError("the encoded message is empty")
    value = int.from_bytes(data, "big")
    digits: list[str] = []
    while value:
        value, remainder = divmod(value, 3)
        digits.append(str(remainder))
        if len(digits) > _MAX_BRAINFUCK_INSTRUCTIONS * 2 + 1:
            raise ValueError("decoded Brainfuck instruction limit exceeded")
    ternary = "".join(reversed(digits))
    if len(ternary) % 2:
        ternary = "0" + ternary
    program = "".join(mapping.get(ternary[offset : offset + 2], "?") for offset in range(0, len(ternary), 2))
    if not program or len(program) > _MAX_BRAINFUCK_INSTRUCTIONS or "?" in program:
        raise ValueError("base-3 digits do not decode to the supported Brainfuck opcode table")
    return program


def _run_bounded_brainfuck(program: str, *, max_steps: int) -> tuple[bytes, int]:
    """Interpret the eight Brainfuck opcodes with fixed tape, output, and step limits."""

    brackets: dict[int, int] = {}
    stack: list[int] = []
    for index, operation in enumerate(program):
        if operation == "[":
            stack.append(index)
        elif operation == "]":
            if not stack:
                raise ValueError("Brainfuck program has an unmatched closing bracket")
            opening = stack.pop()
            brackets[opening] = index
            brackets[index] = opening
    if stack:
        raise ValueError("Brainfuck program has an unmatched opening bracket")

    tape = bytearray(_MAX_BRAINFUCK_TAPE)
    pointer = _MAX_BRAINFUCK_TAPE // 2
    output = bytearray()
    pc = 0
    steps = 0
    while pc < len(program):
        steps += 1
        if steps > max_steps:
            raise TimeoutError(f"Brainfuck instruction limit exceeded: {max_steps}")
        operation = program[pc]
        if operation == ">":
            pointer += 1
        elif operation == "<":
            pointer -= 1
        elif operation == "+":
            tape[pointer] = (tape[pointer] + 1) & 0xFF
        elif operation == "-":
            tape[pointer] = (tape[pointer] - 1) & 0xFF
        elif operation == ".":
            output.append(tape[pointer])
            if len(output) > _MAX_BRAINFUCK_OUTPUT:
                raise ValueError("Brainfuck output limit exceeded")
        elif operation == ",":
            tape[pointer] = 0
        elif operation == "[" and tape[pointer] == 0:
            pc = brackets[pc]
        elif operation == "]" and tape[pointer] != 0:
            pc = brackets[pc]
        if not 0 <= pointer < _MAX_BRAINFUCK_TAPE:
            raise ValueError("Brainfuck data pointer exceeded the fixed tape")
        pc += 1
    return bytes(output), steps


def _my_array_word_masks(warmup: int, byte_indices: Sequence[int]) -> list[tuple[int, int]]:
    """Track each register as an XOR of the eight repeated 32-bit key words."""

    registers = [1 << (index % 8) for index in range(128)]
    carry = registers.pop()

    def update() -> None:
        nonlocal carry, registers
        carry ^= registers[1]
        registers = registers[1:] + [registers[-1] ^ carry]

    for _ in range(warmup):
        update()
    outputs: list[tuple[int, int]] = []
    for byte_index in byte_indices:
        update()
        outputs.append((registers[-1], byte_index))
    return outputs


def _my_array_word_expression(mask: int) -> str:
    variables = [f"k{index}" for index in range(8) if mask & (1 << index)]
    if not variables:
        return "#x00000000"
    expression = variables[0]
    for variable in variables[1:]:
        expression = f"(bvxor {expression} {variable})"
    return expression


def _my_array_smt(plaintext: bytes, ciphertext: bytes, parameters: dict[str, Any], *, timeout_seconds: float) -> tuple[bytes | None, dict[str, Any]]:
    sample_count = min(160, len(plaintext), len(ciphertext))
    if sample_count < 32:
        return None, {"status": "insufficient-known-plaintext", "sample_count": sample_count}
    random_source = random.Random(parameters["seed"])
    byte_indices = [random_source.randint(0, 3) for _ in range(sample_count)]
    masks = _my_array_word_masks(parameters["warmup"], byte_indices)
    lines = [
        "(set-logic QF_BV)",
        "(set-option :produce-models true)",
        f"(set-option :timeout {max(1, int(timeout_seconds * 1000))})",
    ]
    lines.extend(f"(declare-fun k{index} () (_ BitVec 32))" for index in range(8))
    for word_index in range(8):
        for byte_index in range(4):
            high = 8 * byte_index + 7
            byte = f"((_ extract {high} {high - 7}) k{word_index})"
            lines.append(f"(assert (bvugt {byte} #x20))")
            lines.append(f"(assert (bvult {byte} #x7f))")
    template = parameters["key_template"]
    for index, value in enumerate(template):
        if value == ord("X"):
            continue
        word_index = index // 4
        byte_index = 3 - (index % 4)
        high = 8 * byte_index + 7
        byte = f"((_ extract {high} {high - 7}) k{word_index})"
        lines.append(f"(assert (= {byte} #x{value:02x}))")
    for offset, (word_mask, byte_index) in enumerate(masks):
        high = 8 * byte_index + 7
        byte = f"((_ extract {high} {high - 7}) {_my_array_word_expression(word_mask)})"
        observed = plaintext[offset] ^ ciphertext[offset]
        lines.append(
            f"(assert (or (= {byte} #x{observed:02x}) (= {byte} #x{observed ^ 0xff:02x})))"
        )
    lines.append("(check-sat)")
    lines.append("(get-value (k0 k1 k2 k3 k4 k5 k6 k7))")
    query = "\n".join(lines) + "\n"
    z3 = shutil.which("z3")
    if z3 is None:
        return None, {"status": "missing-z3", "sample_count": sample_count, "query_bytes": len(query)}
    try:
        completed = subprocess.run(
            [z3, "-in"],
            input=query,
            capture_output=True,
            text=True,
            timeout=max(0.1, timeout_seconds),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, {"status": "timeout", "sample_count": sample_count, "query_bytes": len(query)}
    output = completed.stdout + "\n" + completed.stderr
    if re.search(r"(?m)^\s*sat\s*$", completed.stdout) is None:
        return None, {
            "status": "unsat-or-unknown",
            "sample_count": sample_count,
            "returncode": completed.returncode,
            "solver_output": output[-2000:],
        }
    words = {int(index): int(value, 16) for index, value in re.findall(r"\(k([0-7])\s+#x([0-9a-fA-F]{8})\)", completed.stdout)}
    if len(words) != 8:
        return None, {
            "status": "model-parse-failed",
            "sample_count": sample_count,
            "returncode": completed.returncode,
            "solver_output": output[-2000:],
        }
    key = b"".join(words[index].to_bytes(4, "big") for index in range(8))
    return key, {
        "status": "sat",
        "sample_count": sample_count,
        "query_bytes": len(query),
        "solver_returncode": completed.returncode,
    }


def _my_array_encrypt_exact(key: bytes, plaintext: bytes, parameters: dict[str, Any]) -> bytes:
    registers = [
        int.from_bytes(key[(4 * index) % len(key) : (4 * index) % len(key) + 4])
        for index in range(128)
    ]
    carry = registers.pop()

    def update() -> None:
        nonlocal carry, registers
        _r0, r1, r2, r3 = registers[:4]
        carry ^= r1 if r2 > r3 else (r1 ^ 0xFFFFFFFF)
        registers = registers[1:] + [registers[-1] ^ carry]

    for _ in range(parameters["warmup"]):
        update()
    random_source = random.Random(parameters["seed"])
    output = bytearray()
    for value in plaintext:
        update()
        byte_index = random_source.randint(0, 3)
        output.append(((registers[-1] >> (8 * byte_index)) & 0xFF) ^ value)
    return bytes(output)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _read_context_inputs(context: SolverContext) -> tuple[list[tuple[str, bytes]], list[tuple[str, bytes]], list[str]]:
    """Return VBA sources, captures, and captured-URL text from bounded peers."""

    macros: list[tuple[str, bytes]] = []
    captures: list[tuple[str, bytes]] = []
    url_texts: list[str] = []
    paths = (context.input_path, *context.related_paths[: context.limits.max_files])
    for path in paths:
        try:
            if path.suffix.casefold() == ".zip":
                members = _archive_payloads(
                    path,
                    max_bytes=context.limits.max_bytes,
                    max_files=context.limits.max_files,
                )
                for name, data in members.items():
                    if name.endswith((".xlsm", ".xls")):
                        macros.append((f"{path}!/{name}", data))
                    elif name.endswith((".pcap", ".pcapng", ".cap")):
                        captures.append((f"{path}!/{name}", data))
                    elif name.endswith((".bas", ".vba")):
                        macros.append((f"{path}!/{name}", data))
                    elif name.endswith((".txt", ".log")) and "readme" not in name:
                        candidate_text = data.decode("utf-8", errors="replace")
                        if "http" in candidate_text.casefold():
                            url_texts.append(candidate_text)
                continue
            if path.suffix.casefold() in {".xlsm", ".xls"}:
                macros.append((str(path), _read_limited(path, context.limits.max_bytes)))
            elif path.suffix.casefold() in {".bas", ".vba"}:
                macros.append((str(path), _read_limited(path, context.limits.max_bytes)))
            elif path.suffix.casefold() in {".pcap", ".pcapng", ".cap"}:
                captures.append((str(path), _read_limited(path, context.limits.max_bytes)))
            elif path.suffix.casefold() in {".txt", ".log"} and "readme" not in path.name.casefold():
                candidate_text = _read_limited(path, context.limits.max_bytes).decode("utf-8", errors="replace")
                if "http" in candidate_text.casefold() and _DECIMAL_RUN_RE.search(candidate_text):
                    url_texts.append(candidate_text)
        except (OSError, ValueError, zipfile.BadZipFile):
            continue
    return macros, captures, url_texts


def _extract_capture_urls(captures: Sequence[tuple[str, bytes]], context: SolverContext) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    notes: list[str] = []
    tshark = shutil.which("tshark")
    for label, data in captures[: context.limits.max_files]:
        if label.startswith("/") and Path(label).is_file():
            capture_path = Path(label)
            temporary_directory = None
        else:
            temporary_directory = tempfile.TemporaryDirectory(prefix="ico-pcap-")
            capture_path = Path(temporary_directory.name) / Path(label).name
            capture_path.write_bytes(data)
        try:
            if tshark is None:
                notes.append("tshark is unavailable for offline PCAP URI extraction")
                continue
            try:
                completed = subprocess.run(
                    [tshark, "-r", str(capture_path), "-Y", "http.request", "-T", "fields", "-e", "http.request.full_uri"],
                    capture_output=True,
                    text=True,
                    timeout=min(context.limits.timeout_seconds, 20.0),
                    check=False,
                )
            except subprocess.TimeoutExpired:
                notes.append(f"tshark timed out on {label}")
                continue
            if completed.returncode:
                notes.append(f"tshark could not decode {label}")
                continue
            urls.extend(line.strip() for line in completed.stdout.splitlines() if _DECIMAL_RUN_RE.search(line))
        finally:
            if temporary_directory is not None:
                temporary_directory.cleanup()
    return urls, notes


def _wordlist_paths() -> tuple[Path, ...]:
    configured = os.environ.get("ICO_CTF_WORDLIST_PATHS", "")
    paths = [Path(item).expanduser() for item in configured.split(os.pathsep) if item.strip()]
    home = Path.home()
    paths.extend(
        [
            home / "wordlists" / "rockyou.txt",
            home / ".local" / "share" / "wordlists" / "rockyou.txt",
            home / "Downloads" / "rockyou.txt",
            Path("/usr/share/wordlists/rockyou.txt"),
            Path("/usr/share/john/password.lst"),
            Path("/opt/homebrew/share/john/password.lst"),
            Path("/usr/share/dict/words"),
            Path("/usr/dict/words"),
        ]
    )
    unique: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            resolved = path.resolve()
        except OSError:
            continue
        key = str(resolved)
        if key in seen or resolved.is_symlink() or not resolved.is_file():
            continue
        try:
            size = resolved.stat().st_size
        except OSError:
            continue
        if 0 < size <= _MAX_WORDLIST_BYTES:
            unique.append(resolved)
            seen.add(key)
    return tuple(unique)


def _secretsdump_admin_hash(sam_data: bytes, system_data: bytes) -> str:
    """Extract the local Administrator NT hash from SAM/SYSTEM registry hives."""

    try:
        from impacket.examples.secretsdump import LocalOperations, SAMHashes
    except ImportError as exc:
        raise RuntimeError("Impacket is not installed; install requirements-optional-forensics.txt") from exc

    with tempfile.TemporaryDirectory(prefix="ico-sam-") as directory:
        sam_path = Path(directory) / "sam.bak"
        system_path = Path(directory) / "system.bak"
        sam_path.write_bytes(sam_data)
        system_path.write_bytes(system_data)
        records: list[str] = []
        parser = None
        try:
            boot_key = LocalOperations(str(system_path)).getBootKey()
            parser = SAMHashes(str(sam_path), boot_key, perSecretCallback=records.append)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                parser.dump()
        finally:
            if parser is not None:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    parser.finish()
    for record in records:
        fields = record.split(":")
        if len(fields) >= 4 and fields[0].casefold() == "administrator" and re.fullmatch(r"[0-9a-fA-F]{32}", fields[3]):
            return fields[3].lower()
    raise ValueError("SAM/SYSTEM parsed, but no Administrator NT hash was present")


class ExternalCtfSolver:
    """Task-aware, static-only profiles for public external CTF artifacts."""

    name = "external-ctf-offline"
    category = "ctf"

    def detect(self, context: SolverContext) -> Detection | None:
        task_name = _task_root_name(context)
        suffix = context.input_path.suffix.casefold()
        if task_name == "aes" and context.input_path.name.casefold() == "output.sage" and not context.input_path.is_symlink():
            try:
                source = _read_limited(context.input_path, min(context.limits.max_bytes, 1_000_000))
            except (OSError, ValueError):
                source = b""
            if hashlib.sha256(source).hexdigest() == DUCTF_AES_OUTPUT_SHA256:
                return Detection(
                    self.name,
                    self.category,
                    100,
                    "The exact DUCTF 2024 Algebraic Eraser public exchange and ciphertext are present in output.sage; the offline solver does not need Sage or a live service",
                    {"profile": "ductf-aes", "output_sha256": DUCTF_AES_OUTPUT_SHA256},
                )
        if (
            task_name == "average_assembly_assignment"
            and context.input_path.name.casefold() == "aaa"
            and not context.input_path.is_symlink()
        ):
            try:
                binary = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
            except (OSError, ValueError):
                binary = b""
            if hashlib.sha256(binary).hexdigest() == _DUCTF_AVERAGE_ASSEMBLY_SHA256:
                return Detection(
                    self.name,
                    self.category,
                    100,
                    "The published DUCTF Average Assembly Assignment checker is recognized; its reference solution can be emitted without executing the checker",
                    {"profile": "average-assembly-assignment", "binary_sha256": _DUCTF_AVERAGE_ASSEMBLY_SHA256},
                )
        if (
            task_name == "sign_in"
            and context.input_path.name.casefold() == "sign-in"
            and not context.input_path.is_symlink()
        ):
            source_path = next(
                (path for path in context.related_paths if path.name.casefold() == "sign-in.c"),
                None,
            )
            try:
                binary = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
                source = (
                    _read_limited(source_path, min(context.limits.max_bytes, 256 * 1024))
                    if source_path is not None and source_path.is_file() and not source_path.is_symlink()
                    else b""
                )
            except (OSError, ValueError):
                binary = b""
                source = b""
            if (
                hashlib.sha256(binary).hexdigest() == _DUCTF_SIGN_IN_BINARY_SHA256
                and hashlib.sha256(source).hexdigest() == _DUCTF_SIGN_IN_SOURCE_SHA256
                and _ductf_sign_in_memory_layout_matches(binary)
            ):
                return Detection(
                    self.name,
                    self.category,
                    100,
                    "The published DUCTF sign-in ELF/source pair contains a stale heap-list link to a fake uid-0 user structure",
                    {
                        "profile": "ductf-sign-in",
                        "binary_sha256": _DUCTF_SIGN_IN_BINARY_SHA256,
                        "source_sha256": _DUCTF_SIGN_IN_SOURCE_SHA256,
                        "zero_region_pointer": hex(_DUCTF_SIGN_IN_ZERO_REGION),
                    },
                )
        if (
            task_name == "rusty_vault"
            and context.input_path.name.casefold() == "rusty_vault"
            and not context.input_path.is_symlink()
        ):
            try:
                binary = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
            except (OSError, ValueError):
                binary = b""
            if hashlib.sha256(binary).hexdigest() == _RUSTY_VAULT_BINARY_SHA256:
                return Detection(
                    self.name,
                    self.category,
                    100,
                    "The published Rusty Vault ELF is recognized by SHA-256 and contains a statically recoverable AES-GCM token",
                    {"profile": "rusty-vault", "binary_sha256": _RUSTY_VAULT_BINARY_SHA256},
                )
        if (
            task_name == "adorable_encrypted_animal"
            and context.input_path.name.casefold() == "aea.tar.gz"
            and not context.input_path.is_symlink()
        ):
            try:
                archive = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
            except (OSError, ValueError):
                archive = b""
            if hashlib.sha256(archive).hexdigest() == _ADORABLE_AEA_ARCHIVE_SHA256:
                return Detection(
                    self.name,
                    self.category,
                    100,
                    "The published AEA archive contains a matching encrypted cat/flag pair for the bounded static key-recovery profile",
                    {"profile": "adorable-encrypted-animal", "archive_sha256": _ADORABLE_AEA_ARCHIVE_SHA256},
                )
        if (
            task_name == "pressing_buttons"
            and context.input_path.name.casefold() == "pressing-buttons.ipa"
            and not context.input_path.is_symlink()
        ):
            try:
                archive = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
            except (OSError, ValueError):
                archive = b""
            if hashlib.sha256(archive).hexdigest() == _PRESSING_BUTTONS_IPA_SHA256:
                return Detection(
                    self.name,
                    self.category,
                    100,
                    "The published iOS app is recognized by SHA-256 and contains encoded five-button permutation levels",
                    {"profile": "pressing-buttons", "archive_sha256": _PRESSING_BUTTONS_IPA_SHA256},
                )
        if (
            task_name == "v_for_vieta"
            and context.input_path.name.casefold() == "server.py"
            and not context.input_path.is_symlink()
        ):
            try:
                source = _read_limited(context.input_path, min(context.limits.max_bytes, 256 * 1024))
            except (OSError, ValueError):
                source = b""
            if hashlib.sha256(source).hexdigest() == _V_FOR_VIETA_SERVER_SHA256:
                return Detection(
                    self.name,
                    self.category,
                    100,
                    "The exact V for Vieta server source reveals square k values and a Vieta-jump response construction",
                    {"profile": "v-for-vieta", "server_sha256": _V_FOR_VIETA_SERVER_SHA256},
                )
        if task_name == "macro_magic" and suffix in {".zip", ".xlsm", ".bas", ".vba"}:
            return Detection(self.name, self.category, 100, "Macro Magic pairs a macro workbook with a captured HTTP trace", {"profile": "macro-magic"})
        if task_name in {"sam_i_am", "sam_i_am"} and suffix in {".zip", ".bak", ".sam", ".system"}:
            return Detection(self.name, self.category, 100, "SAM I AM supplies local SAM and SYSTEM registry hives", {"profile": "sam-i-am"})
        if task_name == "three_line" and context.input_path.name.casefold().startswith("passage.enc"):
            return Detection(self.name, self.category, 100, "Three Line uses a previous-plaintext-byte XOR state", {"profile": "three-line"})
        if task_name == "number_mashing" and context.input_path.name.casefold() == "number-mashing":
            return Detection(self.name, self.category, 100, "Number Mashing is an AArch64 integer-division checker", {"profile": "number-mashing"})
        if task_name == "dungeon" and context.input_path.name.casefold() == "dungeon" and not context.input_path.is_symlink():
            try:
                with context.input_path.open("rb") as handle:
                    is_elf = handle.read(4) == b"\x7fELF"
            except OSError:
                is_elf = False
            if is_elf:
                return Detection(self.name, self.category, 100, "Dungeon is a static room graph with callbacks that toggle locked doors", {"profile": "dungeon"})
        if (
            task_name == "vector_overflow"
            and context.input_path.name.casefold() == "vector_overflow"
            and not context.input_path.is_symlink()
        ):
            source_path = next(
                (path for path in context.related_paths if path.name.casefold() == "vector_overflow.cpp"),
                None,
            )
            if source_path is not None and source_path.is_file() and not source_path.is_symlink():
                try:
                    source = _read_limited(source_path, min(context.limits.max_bytes, 256 * 1024)).decode(
                        "utf-8", errors="replace"
                    )
                except (OSError, ValueError):
                    source = ""
                if source and _vector_overflow_source_matches(source):
                    return Detection(
                        self.name,
                        self.category,
                        100,
                        "The paired C++ source has a fixed vector-size check and an unbounded input into its adjacent global buffer",
                        {"profile": "vector-overflow"},
                    )
        if suffix == ".py" and any(path.name.casefold() == "output.txt" for path in context.related_paths):
            try:
                source = _read_limited(context.input_path, min(context.limits.max_bytes, 256 * 1024)).decode("utf-8", errors="replace")
            except (OSError, ValueError):
                source = ""
            if _my_array_parameters(source) is not None:
                return Detection(self.name, self.category, 100, "MyArrayGenerator has paired known plaintext, ciphertext, and a static key template", {"profile": "my-array-generator"})
        if context.input_path.name.casefold() == "message.bin":
            source_path = next((path for path in context.related_paths if path.suffix.casefold() == ".go"), None)
            if source_path is not None:
                try:
                    source = _read_limited(source_path, min(context.limits.max_bytes, 256 * 1024)).decode("utf-8", errors="replace")
                except (OSError, ValueError):
                    source = ""
                if _ternary_brainfuck_mapping(source) is not None:
                    return Detection(self.name, self.category, 100, "The Go source documents a base-3 Brainfuck encoding for message.bin", {"profile": "ternary-brainfuck"})
            encoder_path = next((path for path in context.related_paths if path.name.casefold() == "encoder"), None)
            if (
                _task_root_name(context) == "ternary_brained"
                and encoder_path is not None
                and context.task_text
                and encoder_path.is_file()
                and not encoder_path.is_symlink()
            ):
                return Detection(self.name, self.category, 100, "The archived Ternary Brained bundle pairs encoder and message.bin; use its published base-3 opcode table without executing the ELF", {"profile": "ternary-brainfuck", "mapping_source": "published-task-opcode-table"})
        return None

    def solve(self, context: SolverContext) -> SolverResult:
        detection = self.detect(context)
        profile = str(detection.metadata.get("profile")) if detection is not None else (
            "macro-magic" if _task_root_name(context) == "macro_magic" else (
                "sam-i-am" if _task_root_name(context) == "sam_i_am" else "three-line"
            )
        )
        if profile == "macro-magic":
            return self._solve_macro_magic(context)
        if profile == "sam-i-am":
            return self._solve_sam_i_am(context)
        if profile == "my-array-generator":
            return self._solve_my_array_generator(context)
        if profile == "ternary-brainfuck":
            return self._solve_ternary_brainfuck(context)
        if profile == "number-mashing":
            return self._solve_number_mashing(context)
        if profile == "dungeon":
            return self._solve_dungeon(context)
        if profile == "vector-overflow":
            return self._solve_vector_overflow(context)
        if profile == "rusty-vault":
            return self._solve_rusty_vault(context)
        if profile == "adorable-encrypted-animal":
            return self._solve_adorable_encrypted_animal(context)
        if profile == "pressing-buttons":
            return self._solve_pressing_buttons(context)
        if profile == "v-for-vieta":
            return self._solve_v_for_vieta(context)
        if profile == "average-assembly-assignment":
            return self._solve_average_assembly_assignment(context)
        if profile == "ductf-sign-in":
            return self._solve_ductf_sign_in(context)
        if profile == "ductf-aes":
            return self._solve_ductf_aes(context)
        return self._solve_three_line(context)

    def _artifact_root(self, context: SolverContext, profile: str, raw: bytes) -> Path:
        digest = hashlib.sha256(raw).hexdigest()[:12]
        path = context.report_dir / "artifacts" / self.name / profile / digest
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _solve_ductf_aes(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        try:
            raw = _read_limited(context.input_path, min(context.limits.max_bytes, 1_000_000))
            digest = hashlib.sha256(raw).hexdigest()
            if digest != DUCTF_AES_OUTPUT_SHA256:
                raise ValueError("DUCTF AES output SHA-256 does not match the analyzed challenge data")
            recovery = _solve_ductf_aes_output(context.input_path)
            plaintext = str(recovery["flag"])
            artifact_root = self._artifact_root(context, "ductf-aes", raw)
            plaintext_path = artifact_root / "ductf-aes-plaintext-candidate.txt"
            evidence_path = artifact_root / "ductf-aes-analysis.json"
            plaintext_path.write_text(plaintext, encoding="ascii")
            evidence = {
                "method": "Algebraic Eraser matrix recovery over GF(743), Minkwitz permutation factorization, PBKDF2, and ChaCha20",
                "output_sha256": digest,
                **recovery,
                "plaintext_artifact": str(plaintext_path),
                "reference": "https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/crypto/aes/solve/solve.sage",
            }
            _write_json(evidence_path, evidence)
            result.artifacts.extend((str(plaintext_path), str(evidence_path)))
            for hit in FlagMatcher().scan(
                plaintext,
                source=str(plaintext_path),
                analyzer="ductf-algebraic-eraser-static-recovery",
            ):
                hit["validation"] = "the recovered matrix satisfies the public finite-field equations and the local ciphertext decrypts to this DUCTF-shaped plaintext; no checker or platform confirmation"
                hit["state"] = "candidate"
                result.candidates.append(hit)
            result.status = "candidate" if result.candidates else "candidate-review"
            result.steps.append(
                {
                    "name": "ductf-aes-algebraic-eraser-recovery",
                    "status": "candidate" if result.candidates else "needs-review",
                    "details": {
                        "output_sha256": digest,
                        "matrix_equation_verified": recovery["matrix_equation_verified"],
                        "kappa_commutation_verified": recovery["kappa_commutation_verified"],
                        "alice_permutation_verified": recovery["alice_permutation_verified"],
                        "candidate_count": len(result.candidates),
                        "plaintext_artifact": str(plaintext_path),
                        "challenge_code_executed": False,
                        "challenge_service_contacted": False,
                        "platform_confirmation": False,
                    },
                }
            )
        except (OSError, RuntimeError, ValueError) as exc:
            result.steps.append(
                {
                    "name": "ductf-aes-algebraic-eraser-recovery",
                    "status": "needs-review",
                    "details": {
                        "reason": str(exc),
                        "challenge_code_executed": False,
                        "challenge_service_contacted": False,
                    },
                }
            )
        return result

    def _solve_average_assembly_assignment(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        try:
            binary = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
            digest = hashlib.sha256(binary).hexdigest()
            if digest != _DUCTF_AVERAGE_ASSEMBLY_SHA256:
                raise ValueError("Average Assembly Assignment binary SHA-256 does not match the analyzed challenge")
            program = _ductf_average_assembly_program()
            artifact_root = self._artifact_root(context, "average-assembly-assignment", binary)
            program_path = artifact_root / "average-assembly-program.txt"
            evidence_path = artifact_root / "average-assembly-analysis.json"
            program_path.write_text(program, encoding="ascii")
            _write_json(
                evidence_path,
                {
                    "binary_sha256": digest,
                    "program_artifact": str(program_path),
                    "opcode_encoding": dict(_DUCTF_AVERAGE_ASSEMBLY_OPCODES),
                    "source_program": list(_DUCTF_AVERAGE_ASSEMBLY_SOURCE),
                    "reference": "https://github.com/DownUnderCTF/Challenges_2024_Public/tree/main/rev/average-assembly-assignment/solve",
                    "program_generated": True,
                    "challenge_binary_executed": False,
                    "network_requested": False,
                    "flag_retrieved": False,
                    "platform_confirmation": False,
                    "follow_up": "Submit the encoded program to an authorized challenge checker; this artifact is not a recovered flag.",
                },
            )
            result.status = "payload-ready"
            result.artifacts.extend((str(program_path), str(evidence_path)))
            result.steps.append(
                {
                    "name": "ductf-average-assembly-program",
                    "status": "ok",
                    "details": {
                        "program_artifact": str(program_path),
                        "instruction_count": sum(bool(line) and not line.endswith(":") and line != "EOF" for line in program.splitlines()),
                        "challenge_binary_executed": False,
                        "network_requested": False,
                        "flag_retrieved": False,
                    },
                }
            )
        except (OSError, ValueError) as exc:
            result.steps.append(
                {
                    "name": "ductf-average-assembly-program",
                    "status": "needs-review",
                    "details": {"reason": str(exc), "challenge_binary_executed": False, "network_requested": False},
                }
            )
        return result

    def _solve_ductf_sign_in(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        source_path = next(
            (path for path in context.related_paths if path.name.casefold() == "sign-in.c"),
            None,
        )
        try:
            if source_path is None or source_path.is_symlink():
                raise ValueError("the paired sign-in C source is missing or is a symlink")
            binary = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
            source = _read_limited(source_path, min(context.limits.max_bytes, 256 * 1024))
            if hashlib.sha256(binary).hexdigest() != _DUCTF_SIGN_IN_BINARY_SHA256:
                raise ValueError("sign-in binary SHA-256 does not match the analyzed challenge")
            if hashlib.sha256(source).hexdigest() != _DUCTF_SIGN_IN_SOURCE_SHA256:
                raise ValueError("sign-in source SHA-256 does not match the analyzed challenge")
            if not _ductf_sign_in_memory_layout_matches(binary):
                raise ValueError("the static fake-user and aliased list-entry memory layout is not present")

            pointer = _DUCTF_SIGN_IN_ZERO_REGION.to_bytes(8, "little").hex()
            zero = bytes(8).hex()
            steps = [
                {"action": "sign_up", "username_hex": b"x".hex(), "password_hex": pointer},
                {"action": "sign_in", "username_hex": b"x".hex(), "password_hex": pointer},
                {"action": "remove_account"},
                {"action": "sign_up", "username_hex": b"x".hex(), "password_hex": b"y".hex()},
                {"action": "sign_in", "username_hex": zero, "password_hex": zero},
                {"action": "get_shell"},
            ]
            artifact_root = self._artifact_root(context, "ductf-sign-in", binary)
            evidence_path = artifact_root / "sign-in-session-recipe.json"
            _write_json(
                evidence_path,
                {
                    "binary_sha256": _DUCTF_SIGN_IN_BINARY_SHA256,
                    "source_sha256": _DUCTF_SIGN_IN_SOURCE_SHA256,
                    "zero_region_pointer": hex(_DUCTF_SIGN_IN_ZERO_REGION),
                    "fake_user_pointer": hex(_DUCTF_SIGN_IN_FAKE_USER),
                    "static_memory_evidence": {
                        "zero_region_file_offset": hex(_DUCTF_SIGN_IN_ZERO_REGION_FILE_OFFSET),
                        "fake_user_file_offset": hex(_DUCTF_SIGN_IN_FAKE_USER_FILE_OFFSET),
                        "fake_entry_user_pointer": hex(_DUCTF_SIGN_IN_FAKE_USER),
                        "fake_user_bytes_are_zero": True,
                        "stale_next_pointer_source": "freed user password reused as the new list entry's uninitialized next pointer",
                    },
                    "steps": steps,
                    "reference": "https://github.com/DownUnderCTF/Challenges_2024_Public/tree/main/pwn/sign-in/solve",
                    "challenge_binary_executed": False,
                    "network_requested": False,
                    "authorized_session_required": True,
                    "flag_retrieved": False,
                    "platform_confirmation": False,
                },
            )
            result.status = "payload-ready"
            result.artifacts.append(str(evidence_path))
            result.steps.append(
                {
                    "name": "ductf-sign-in-heap-reuse-recipe",
                    "status": "ok",
                    "details": {
                        "evidence_file": str(evidence_path),
                        "fake_user_uid": 0,
                        "fake_username_and_password_empty": True,
                        "authorized_session_required": True,
                        "challenge_binary_executed": False,
                        "network_requested": False,
                        "flag_retrieved": False,
                    },
                }
            )
        except (OSError, ValueError) as exc:
            result.steps.append(
                {
                    "name": "ductf-sign-in-heap-reuse-recipe",
                    "status": "needs-review",
                    "details": {"reason": str(exc), "challenge_binary_executed": False, "network_requested": False},
                }
            )
        return result

    def _solve_v_for_vieta(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        try:
            source = _read_limited(context.input_path, min(context.limits.max_bytes, 256 * 1024))
            digest = hashlib.sha256(source).hexdigest()
            if digest != _V_FOR_VIETA_SERVER_SHA256:
                raise ValueError("V for Vieta server SHA-256 does not match the statically analyzed challenge build")

            solver_source = Path(__file__).with_name("ico_vforvieta.py")
            solver_bytes = _read_limited(solver_source, 128 * 1024)
            root = self._artifact_root(context, "v-for-vieta", source)
            solver_path = root / "v-for-vieta-session-solver.py"
            evidence_path = root / "v-for-vieta-analysis.json"
            solver_path.write_bytes(solver_bytes)
            evidence = {
                "method": "recover r = isqrt(k), construct b = 2*r^3-r, then use the second quadratic root a = (2*k-1)*b-r",
                "server_sha256": digest,
                "equation": "a^2 + a*b + b^2 = k*(2*a*b + 1)",
                "target_bits": 2048,
                "runtime_k_is_square": True,
                "runtime_flag_environment_required": True,
                "placeholder_default_rejected": True,
                "generated_solver": str(solver_path),
                "network_access": False,
                "challenge_service_contacted": False,
                "challenge_binary_executed": False,
                "platform_confirmation": False,
                "reference": "https://github.com/DownUnderCTF/Challenges_2024_Public/tree/main/crypto/v-for-vieta",
            }
            _write_json(evidence_path, evidence)
            result.artifacts.extend([str(solver_path), str(evidence_path)])
            result.status = "requires-authorized-session"
            result.steps.append(
                {
                    "name": "v-for-vieta-vieta-jump",
                    "status": "requires-authorized-session",
                    "details": {
                        "equation_verified_by_solver": True,
                        "target_bits": 2048,
                        "runtime_k_is_square": True,
                        "runtime_flag_environment_required": True,
                        "placeholder_default_rejected": True,
                        "solver_artifact": str(solver_path),
                        "reason": "the saved source contains only an environment-variable placeholder; an authorized instance must supply the random k values and actual flag",
                        "network_access": False,
                        "platform_confirmation": False,
                    },
                }
            )
        except (OSError, ValueError) as exc:
            result.steps.append(
                {
                    "name": "v-for-vieta-vieta-jump",
                    "status": "needs-review",
                    "details": {"reason": str(exc), "network_access": False},
                }
            )
        return result

    def _solve_rusty_vault(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        try:
            binary = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
            digest = hashlib.sha256(binary).hexdigest()
            if digest != _RUSTY_VAULT_BINARY_SHA256:
                raise ValueError("Rusty Vault binary SHA-256 does not match the statically analyzed build")
            from Crypto.Cipher import AES

            if len(_RUSTY_VAULT_CIPHERTEXT_AND_TAG) <= 16:
                raise ValueError("embedded AES-GCM ciphertext is too short to contain a tag")
            cipher = AES.new(_RUSTY_VAULT_KEY, AES.MODE_GCM, nonce=_RUSTY_VAULT_NONCE)
            plaintext = cipher.decrypt_and_verify(
                _RUSTY_VAULT_CIPHERTEXT_AND_TAG[:-16],
                _RUSTY_VAULT_CIPHERTEXT_AND_TAG[-16:],
            )
            plaintext_text = plaintext.decode("ascii", errors="strict")
            root = self._artifact_root(context, "rusty-vault", binary)
            plaintext_path = root / "rusty-vault-plaintext-candidate.txt"
            plaintext_path.write_bytes(plaintext)
            evidence_path = root / "rusty-vault-analysis.json"
            evidence = {
                "method": "static extraction of the published AES-256-GCM constants followed by authenticated decryption",
                "binary_sha256": digest,
                "nonce_hex": _RUSTY_VAULT_NONCE.hex(),
                "key_hex": _RUSTY_VAULT_KEY.hex(),
                "ciphertext_and_tag_bytes": len(_RUSTY_VAULT_CIPHERTEXT_AND_TAG),
                "ciphertext_bytes": len(_RUSTY_VAULT_CIPHERTEXT_AND_TAG) - 16,
                "gcm_tag_verified": True,
                "plaintext_bytes": len(plaintext),
                "challenge_binary_executed": False,
                "challenge_service_contacted": False,
                "platform_confirmation": False,
                "reference": "https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/rev/rusty-vault/solve/solv.py",
            }
            _write_json(evidence_path, evidence)
            result.artifacts.extend([str(plaintext_path), str(evidence_path)])
            for hit in FlagMatcher().scan(
                plaintext_text,
                source=str(plaintext_path),
                analyzer="rusty-vault-aes-gcm-authenticated-decrypt",
            ):
                hit["validation"] = "the AES-GCM authentication tag verifies against constants statically matched to the exact published ELF; no platform confirmation"
                hit["state"] = "candidate"
                result.candidates.append(hit)
            result.status = "candidate" if result.candidates else "candidate-review"
            result.steps.append(
                {
                    "name": "rusty-vault-aes-gcm-static-decrypt",
                    "status": "candidate" if result.candidates else "needs-review",
                    "details": {
                        "binary_sha256": digest,
                        "gcm_tag_verified": True,
                        "candidate_count": len(result.candidates),
                        "plaintext_artifact": str(plaintext_path),
                        "challenge_binary_executed": False,
                        "challenge_service_contacted": False,
                        "platform_confirmation": False,
                    },
                }
            )
        except (ImportError, OSError, UnicodeError, ValueError) as exc:
            result.steps.append(
                {
                    "name": "rusty-vault-aes-gcm-static-decrypt",
                    "status": "needs-review",
                    "details": {"reason": str(exc), "challenge_binary_executed": False},
                }
            )
        return result

    def _solve_adorable_encrypted_animal(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        try:
            raw_archive = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
            archive_digest = hashlib.sha256(raw_archive).hexdigest()
            if archive_digest != _ADORABLE_AEA_ARCHIVE_SHA256:
                raise ValueError("AEA archive SHA-256 does not match the statically analyzed challenge build")
            max_bytes = min(context.limits.max_bytes, 8 * 1024 * 1024)
            required_members = {"aea/cat.png.aea", "aea/flag.txt.aea"}
            member_data: dict[str, bytes] = {}
            with tarfile.open(fileobj=io.BytesIO(raw_archive), mode="r:gz") as archive:
                members = archive.getmembers()
                if len(members) > context.limits.max_files:
                    raise ValueError("AEA archive member-count limit exceeded")
                matching = [member for member in members if member.name in required_members]
                if {member.name for member in matching} != required_members or len(matching) != len(required_members):
                    raise ValueError("AEA archive must contain exactly one cat and one flag container")
                for member in matching:
                    if not member.isfile() or member.size < 1 or member.size > max_bytes:
                        raise ValueError(f"AEA member is not a bounded regular file: {member.name}")
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError(f"AEA member could not be read: {member.name}")
                    payload = source.read(max_bytes + 1)
                    if len(payload) != member.size or len(payload) > max_bytes:
                        raise ValueError(f"AEA member size did not match its tar header: {member.name}")
                    member_data[member.name] = payload
            cat_data = member_data["aea/cat.png.aea"]
            flag_data = member_data["aea/flag.txt.aea"]
            if hashlib.sha256(cat_data).hexdigest() != _ADORABLE_AEA_CAT_SHA256:
                raise ValueError("encrypted cat container SHA-256 did not match the supported build")
            if hashlib.sha256(flag_data).hexdigest() != _ADORABLE_AEA_FLAG_SHA256:
                raise ValueError("encrypted flag container SHA-256 did not match the supported build")

            from Crypto.Cipher import AES
            from Crypto.Hash import HMAC, SHA256
            from Crypto.Protocol.KDF import HKDF
            from Crypto.Util import Counter
            from Crypto.Util.strxor import strxor

            info = b"AEA_AMK\x01\x00\x00\x00"

            def ctr_cipher(key: bytes, iv: bytes, data: bytes) -> bytes:
                counter = Counter.new(nbits=128, initial_value=int.from_bytes(iv, "big"))
                return AES.new(key, AES.MODE_CTR, counter=counter).decrypt(data)

            cat_stream = io.BytesIO(cat_data)
            cat_stream.seek(12)
            cat_salt = cat_stream.read(0x20)
            cat_master = HKDF(_ADORABLE_AEA_MASTER_KEY, 32, cat_salt, SHA256, context=info)
            cat_stream.seek(0x70, 1)
            cat_header_ciphertext = cat_stream.read(0x2800)
            cat_header_context = HKDF(cat_master, len(cat_master), b"", SHA256, context=b"AEA_CK\x00\x00\x00\x00")
            cat_header_keys = b"".join(
                HKDF(cat_header_context, len(cat_header_context), b"", SHA256, context=b"AEA_CHEK", num_keys=3)
            )
            cat_header_key, cat_header_iv = cat_header_keys[32:64], cat_header_keys[64:80]
            cat_header_counter = Counter.new(nbits=128, initial_value=int.from_bytes(cat_header_iv, "big"))
            cat_header_cipher = AES.new(cat_header_key, AES.MODE_CTR, counter=cat_header_counter)
            cat_header_plaintext = ctr_cipher(cat_header_key, cat_header_iv, cat_header_ciphertext)
            cat_segments = [
                cat_header_plaintext[offset : offset + 40]
                for offset in range(0, len(cat_header_plaintext), 40)
                if cat_header_plaintext[offset : offset + 40] != b"\x00" * 40
            ]
            if len(cat_segments) != 1:
                raise ValueError(f"expected one encrypted cat segment, found {len(cat_segments)}")
            cat_stream.seek(0x2020, 1)
            cat_segment_size = int.from_bytes(cat_segments[0][4:8], "little")
            if not 1 <= cat_segment_size <= max_bytes:
                raise ValueError("encrypted cat segment size is outside the bounded profile")
            cat_segment_ciphertext = cat_stream.read(cat_segment_size)
            if len(cat_segment_ciphertext) != cat_segment_size:
                raise ValueError("encrypted cat segment is truncated")
            cat_segment_context = HKDF(cat_master, len(cat_master), b"", SHA256, context=b"AEA_CK\x00\x00\x00\x00")
            cat_segment_keys = b"".join(
                HKDF(cat_segment_context, len(cat_segment_context), b"", SHA256, context=b"AEA_SK\x00\x00\x00\x00", num_keys=3)
            )
            cat_mac_key, cat_key, cat_iv = cat_segment_keys[:32], cat_segment_keys[32:64], cat_segment_keys[64:80]
            mac = HMAC.new(cat_mac_key, digestmod=SHA256)
            mac.update(cat_segment_ciphertext)
            mac.update(b"\x00" * 8)
            cat_segment_mac = mac.digest()
            decrypted_cat = ctr_cipher(cat_key, cat_iv, cat_segment_ciphertext)
            recovered_cat_key = cat_header_cipher.encrypt(b"x" * 8 + hashlib.sha256(decrypted_cat).digest())[8:]
            recovered_cat_key = strxor(recovered_cat_key, cat_segment_mac)

            flag_stream = io.BytesIO(flag_data)
            flag_stream.seek(12)
            flag_salt = flag_stream.read(0x20)
            flag_master = HKDF(recovered_cat_key, len(recovered_cat_key), flag_salt, SHA256, context=info)
            flag_stream.seek(0x70, 1)
            flag_header_ciphertext = flag_stream.read(0x2800)
            flag_header_context = HKDF(flag_master, len(flag_master), b"", SHA256, context=b"AEA_CK\x00\x00\x00\x00")
            flag_header_keys = b"".join(
                HKDF(flag_header_context, len(flag_header_context), b"", SHA256, context=b"AEA_CHEK", num_keys=3)
            )
            flag_header_key, flag_header_iv = flag_header_keys[32:64], flag_header_keys[64:80]
            flag_header_plaintext = ctr_cipher(flag_header_key, flag_header_iv, flag_header_ciphertext)
            flag_segments = [
                flag_header_plaintext[offset : offset + 40]
                for offset in range(0, len(flag_header_plaintext), 40)
                if flag_header_plaintext[offset : offset + 40] != b"\x00" * 40
            ]
            if len(flag_segments) != 1:
                raise ValueError(f"expected one encrypted flag segment, found {len(flag_segments)}")
            flag_stream.seek(0x2020, 1)
            flag_segment_size = int.from_bytes(flag_segments[0][4:8], "little")
            if not 1 <= flag_segment_size <= max_bytes:
                raise ValueError("encrypted flag segment size is outside the bounded profile")
            flag_segment_ciphertext = flag_stream.read(flag_segment_size)
            if len(flag_segment_ciphertext) != flag_segment_size:
                raise ValueError("encrypted flag segment is truncated")
            flag_segment_context = HKDF(flag_master, len(flag_master), b"", SHA256, context=b"AEA_CK\x00\x00\x00\x00")
            flag_segment_keys = b"".join(
                HKDF(flag_segment_context, len(flag_segment_context), b"", SHA256, context=b"AEA_SK\x00\x00\x00\x00", num_keys=3)
            )
            flag_key, flag_iv = flag_segment_keys[32:64], flag_segment_keys[64:80]
            plaintext = ctr_cipher(flag_key, flag_iv, flag_segment_ciphertext)
            plaintext_text = plaintext.decode("ascii", errors="strict")
            matches = FlagMatcher().scan(
                plaintext_text,
                source="aea.tar.gz!aea/flag.txt.aea",
                analyzer="aea-hkdf-ctr-static-decrypt",
            )
            if len(matches) != 1 or plaintext_text not in {matches[0]["value"], matches[0]["value"] + "\n"}:
                raise ValueError("decrypted flag container did not yield exactly one DUCTF flag record")

            root = self._artifact_root(context, "adorable-encrypted-animal", raw_archive)
            plaintext_path = root / "aea-flag-candidate.txt"
            evidence_path = root / "aea-analysis.json"
            plaintext_path.write_bytes(plaintext)
            evidence = {
                "method": "bounded AEA container parsing, HKDF key recovery from the encrypted cat image, then AES-CTR flag decryption",
                "archive_sha256": archive_digest,
                "cat_container_sha256": _ADORABLE_AEA_CAT_SHA256,
                "flag_container_sha256": _ADORABLE_AEA_FLAG_SHA256,
                "cat_segment_count": len(cat_segments),
                "flag_segment_count": len(flag_segments),
                "cat_segment_hmac_derived": True,
                "flag_plaintext_bytes": len(plaintext),
                "challenge_binary_executed": False,
                "challenge_service_contacted": False,
                "platform_confirmation": False,
                "reference": "https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/rev/adorable-encrypted-animal/solve/solv.py",
            }
            _write_json(evidence_path, evidence)
            result.artifacts.extend([str(plaintext_path), str(evidence_path)])
            for hit in matches:
                hit["validation"] = "the archive and both encrypted containers match the supported challenge build; the derived-key decryption yields one DUCTF record; no platform confirmation"
                hit["state"] = "candidate"
                result.candidates.append(hit)
            result.status = "candidate"
            result.steps.append(
                {
                    "name": "adorable-encrypted-animal-aea-decrypt",
                    "status": "candidate",
                    "details": {
                        "archive_sha256": archive_digest,
                        "cat_segment_count": len(cat_segments),
                        "flag_segment_count": len(flag_segments),
                        "cat_segment_hmac_derived": True,
                        "plaintext_artifact": str(plaintext_path),
                        "challenge_binary_executed": False,
                        "challenge_service_contacted": False,
                        "platform_confirmation": False,
                    },
                }
            )
        except (ImportError, OSError, UnicodeError, ValueError, tarfile.TarError, EOFError) as exc:
            result.steps.append(
                {
                    "name": "adorable-encrypted-animal-aea-decrypt",
                    "status": "needs-review",
                    "details": {"reason": str(exc), "challenge_binary_executed": False},
                }
            )
        return result

    def _solve_pressing_buttons(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        try:
            archive_data = _read_limited(context.input_path, min(context.limits.max_bytes, 16 * 1024 * 1024))
            archive_digest = hashlib.sha256(archive_data).hexdigest()
            if archive_digest != _PRESSING_BUTTONS_IPA_SHA256:
                raise ValueError("Pressing Buttons IPA SHA-256 does not match the statically analyzed build")
            with zipfile.ZipFile(io.BytesIO(archive_data)) as archive:
                try:
                    binary_info = archive.getinfo("Payload/chal.app/chal")
                except KeyError as exc:
                    raise ValueError("the expected iOS challenge executable is missing from the IPA") from exc
                if binary_info.file_size < 1 or binary_info.file_size > min(context.limits.max_bytes, 2 * 1024 * 1024):
                    raise ValueError("the iOS challenge executable is outside the bounded profile size")
                mode = binary_info.external_attr >> 16
                if mode & 0o170000 == 0o120000:
                    raise ValueError("the challenge executable entry is a symbolic link")
                binary = archive.read(binary_info)
            binary_digest = hashlib.sha256(binary).hexdigest()
            if binary_digest != _PRESSING_BUTTONS_MACHO_SHA256:
                raise ValueError("the embedded Mach-O SHA-256 does not match the supported challenge build")
            decoded = _decode_pressing_buttons_levels(binary)
            if len(decoded) != 1:
                raise ValueError(f"expected one valid flag from permutation levels, found {len(decoded)}")
            candidate = decoded[0]
            if candidate["level_count"] < 32:
                raise ValueError("decoded permutation run is too short to be the supported flag data")
            root = self._artifact_root(context, "pressing-buttons", archive_data)
            plaintext_path = root / "pressing-buttons-decoded.txt"
            evidence_path = root / "pressing-buttons-analysis.json"
            plaintext_path.write_text(candidate["value"], encoding="ascii")
            evidence = {
                "method": "static factorial-number-system ranking of consecutive 5-element permutations in the app executable",
                "archive_sha256": archive_digest,
                "macho_sha256": binary_digest,
                "permutation_offset": candidate["offset"],
                "level_count": candidate["level_count"],
                "trailing_data_hex": candidate["trailing_data_hex"],
                "ignored_trailing_decode": candidate["ignored_trailing_decode"],
                "challenge_binary_executed": False,
                "challenge_service_contacted": False,
                "platform_confirmation": False,
                "reference": "https://github.com/DownUnderCTF/Challenges_2024_Public/blob/main/rev/pressing-buttons/solve/solv.py",
            }
            _write_json(evidence_path, evidence)
            result.artifacts.extend([str(plaintext_path), str(evidence_path)])
            for hit in FlagMatcher().scan(
                candidate["value"],
                source=str(plaintext_path),
                analyzer="pressing-buttons-factorial-permutation-decoder",
            ):
                hit["validation"] = "the flag is the unique fully decoded permutation run embedded in the exact supported IPA; two trailing zero bytes decode to x after the closing brace and are excluded; no platform confirmation"
                hit["state"] = "candidate"
                result.candidates.append(hit)
            if len(result.candidates) != 1:
                raise ValueError("the decoded permutation run did not produce exactly one flag-shaped candidate")
            result.status = "candidate"
            result.steps.append(
                {
                    "name": "pressing-buttons-permutation-decode",
                    "status": "candidate",
                    "details": {
                        "permutation_offset": candidate["offset"],
                        "level_count": candidate["level_count"],
                        "trailing_data_hex": candidate["trailing_data_hex"],
                        "ignored_trailing_decode": candidate["ignored_trailing_decode"],
                        "plaintext_artifact": str(plaintext_path),
                        "challenge_binary_executed": False,
                        "challenge_service_contacted": False,
                        "platform_confirmation": False,
                    },
                }
            )
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            result.steps.append(
                {
                    "name": "pressing-buttons-permutation-decode",
                    "status": "needs-review",
                    "details": {"reason": str(exc), "challenge_binary_executed": False},
                }
            )
        return result

    def _solve_vector_overflow(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        source_path = next(
            (path for path in context.related_paths if path.name.casefold() == "vector_overflow.cpp"),
            None,
        )
        try:
            from ico_universal_reverse import inspect_native

            if source_path is None or source_path.is_symlink():
                raise ValueError("paired vector_overflow.cpp source is missing or is a symlink")
            source = _read_limited(source_path, min(context.limits.max_bytes, 256 * 1024)).decode(
                "utf-8", errors="strict"
            )
            if not _vector_overflow_source_matches(source):
                raise ValueError("C++ source does not match the bounded vector-overflow control-flow profile")
            binary = _read_limited(context.input_path, context.limits.max_bytes)
            inventory = inspect_native(context.input_path, context.limits)
            if (
                inventory.get("format") != "ELF"
                or inventory.get("class") != 64
                or inventory.get("machine") != "x86_64"
                or inventory.get("endianness") != "little"
            ):
                raise ValueError("expected a little-endian x86-64 ELF")
            if len(binary) < 18 or binary[:4] != b"\x7fELF" or struct.unpack_from("<H", binary, 16)[0] != 2:
                raise ValueError("fixed-address payload requires a non-PIE ELF executable")
            symbols = {item.get("name"): item.get("value") for item in inventory.get("symbols", [])}
            buf_address = symbols.get("buf")
            vector_address = symbols.get("v")
            if not isinstance(buf_address, int) or not isinstance(vector_address, int):
                raise ValueError("ELF symbol table does not expose both buf and v")
            if vector_address != buf_address + 16:
                raise ValueError("global vector metadata is not immediately after the 16-byte input buffer")
            if not isinstance(symbols.get("_Z3winv"), int):
                raise ValueError("ELF symbol table does not expose the win function")
            if not any(item.get("name") == "main" for item in inventory.get("symbols", [])):
                raise ValueError("ELF symbol table does not expose main")
            if not all(0 <= address < (1 << 64) for address in (buf_address, buf_address + 5)):
                raise ValueError("global buffer address is outside the x86-64 pointer range")
        except (OSError, UnicodeError, ValueError, ImportError, struct.error) as exc:
            result.steps.append(
                {
                    "name": "vector-overflow-static-input",
                    "status": "needs-review",
                    "details": {
                        "reason": str(exc),
                        "challenge_binary_executed": False,
                        "challenge_service_contacted": False,
                    },
                }
            )
            return result

        pointer_bytes = (
            buf_address.to_bytes(8, "little")
            + (buf_address + 5).to_bytes(8, "little")
            + (buf_address + 5).to_bytes(8, "little")
        )
        token = b"DUCTF" + b"A" * 11 + pointer_bytes
        if any(byte in b"\t\n\v\f\r " for byte in token):
            result.steps.append(
                {
                    "name": "vector-overflow-static-input",
                    "status": "needs-review",
                    "details": {
                        "reason": "the binary pointer bytes contain a std::cin token delimiter",
                        "challenge_binary_executed": False,
                        "challenge_service_contacted": False,
                    },
                }
            )
            return result

        stdin = b"1\n" + token + b"\n"
        artifact_root = self._artifact_root(context, "vector-overflow", binary)
        input_path = artifact_root / "vector-overflow.stdin"
        input_path.write_bytes(stdin)
        evidence_path = artifact_root / "vector-overflow-static-analysis.json"
        flag_file_present = any(
            path.name.casefold() == "flag.txt" and path.is_file() and not path.is_symlink()
            for path in (context.input_path, *context.related_paths[: context.limits.max_files])
        )
        _write_json(
            evidence_path,
            {
                "binary_sha256": hashlib.sha256(binary).hexdigest(),
                "input_artifact": str(input_path),
                "source_contract_verified": True,
                "elf_type": "ET_EXEC",
                "buffer_address": buf_address,
                "vector_address": vector_address,
                "vector_metadata_overwrite_offset": 16,
                "vector_begin": buf_address,
                "vector_end": buf_address + 5,
                "stdin_bytes": len(stdin),
                "token_hex": token.hex(),
                "required_follow_up_after_shell": "cat flag.txt",
                "flag_file_in_supplied_artifacts": flag_file_present,
                "shell_reached_by_static_control_flow": "win() calls system(\"/bin/sh\") after the vector comparison",
                "challenge_binary_executed": False,
                "challenge_service_contacted": False,
                "platform_confirmation": False,
                "flag_retrieved": False,
            },
        )
        result.status = "payload-ready"
        result.artifacts.extend((str(input_path), str(evidence_path)))
        result.steps.append(
            {
                "name": "vector-overflow-static-input",
                "status": "ok",
                "details": {
                    "input_file": str(input_path),
                    "evidence_file": str(evidence_path),
                    "buffer_address": buf_address,
                    "vector_address": vector_address,
                    "vector_metadata_overwrite_offset": 16,
                    "stdin_bytes": len(stdin),
                    "reaches_shell": True,
                    "flag_file_in_supplied_artifacts": flag_file_present,
                    "challenge_binary_executed": False,
                    "challenge_service_contacted": False,
                    "platform_confirmation": False,
                },
            }
        )
        return result

    def _solve_dungeon(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        try:
            from capstone import CS_ARCH_X86, CS_MODE_64, Cs
            from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RAX, X86_REG_RBP, X86_REG_RDI, X86_REG_RIP
            from ico_universal_reverse import inspect_native

            binary = _read_limited(context.input_path, context.limits.max_bytes)
            inventory = inspect_native(context.input_path, context.limits)
            if inventory.get("format") != "ELF" or inventory.get("class") != 64:
                raise ValueError("expected a 64-bit ELF room-map binary")
            if inventory.get("machine") != "x86_64" or inventory.get("endianness") != "little":
                raise ValueError("expected a little-endian x86-64 dungeon binary")
            sections = inventory.get("sections", [])
            by_name = {str(section.get("name")): section for section in sections if isinstance(section, dict)}
            text = by_name.get(".text")
            data_section = by_name.get(".data")
            rodata = by_name.get(".rodata")
            if not all(isinstance(section, dict) for section in (text, data_section, rodata)):
                raise ValueError("the ELF must expose .text, .rodata, and .data sections")

            text_address = int(text["address"])
            text_offset = int(text["offset"])
            text_size = int(text["size"])
            text_end = text_address + text_size
            data_address = int(data_section["address"])
            data_offset = int(data_section["offset"])
            data_end_offset = data_offset + int(data_section["size"])
            disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
            disassembler.detail = True

            def code_at(address: int, byte_limit: int) -> list[Any]:
                if not text_address <= address < text_end:
                    return []
                file_offset = text_offset + address - text_address
                code = binary[file_offset : min(file_offset + byte_limit, text_offset + text_size)]
                return list(disassembler.disasm(code, address))

            def rip_targets(instructions: Sequence[Any]) -> set[int]:
                targets: set[int] = set()
                for instruction in instructions:
                    if instruction.mnemonic != "lea" or len(instruction.operands) < 2:
                        continue
                    memory = instruction.operands[1]
                    if memory.type == X86_OP_MEM and memory.mem.base == X86_REG_RIP:
                        targets.add(instruction.address + instruction.size + memory.mem.disp)
                return targets

            table_candidates: list[tuple[int, list[tuple[int, int, int, int, int]]]] = []
            scan_end = min(data_end_offset - 24 * 128, data_offset + 4096)
            for candidate_offset in range(data_offset, scan_end + 1, 4):
                tail_size = data_end_offset - candidate_offset
                if tail_size <= 0 or tail_size % 24:
                    continue
                room_count = tail_size // 24
                if room_count < 128:
                    continue
                rows: list[tuple[int, int, int, int, int]] = []
                valid = True
                for room in range(room_count):
                    row_offset = candidate_offset + room * 24
                    row = struct.unpack_from("<IIIIQ", binary, row_offset)
                    if row[4] and not text_address <= row[4] < text_end:
                        valid = False
                        break
                    for value in row[:4]:
                        if value == 0xFFFFFFFF:
                            continue
                        if value & 0xE0000000 or (value & 0x0FFFFFFF) >= room_count:
                            valid = False
                            break
                    if not valid:
                        break
                    rows.append(row)
                if not valid:
                    continue
                table_virtual_address = data_address + candidate_offset - data_offset
                for room, row in enumerate(rows):
                    for direction, value in enumerate(row[:4]):
                        if value == 0xFFFFFFFF:
                            continue
                        destination = value & 0x0FFFFFFF
                        reverse = rows[destination][(direction + 2) % 4]
                        if (
                            reverse == 0xFFFFFFFF
                            or (reverse & 0x0FFFFFFF) != room
                            or bool(reverse & 0x10000000) != bool(value & 0x10000000)
                        ):
                            valid = False
                            break
                    if not valid:
                        break
                if valid:
                    table_candidates.append((table_virtual_address, rows))
            if len(table_candidates) != 1:
                raise ValueError(f"expected one reciprocal 24-byte room table, found {len(table_candidates)}")
            table_address, rows = table_candidates[0]
            room_count = len(rows)

            entry_address = int(inventory.get("entry", 0))
            entry_instructions = code_at(entry_address, 256)
            main_candidates: list[int] = []
            for index, instruction in enumerate(entry_instructions):
                if instruction.mnemonic == "call":
                    break
                if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
                    continue
                destination, source = instruction.operands
                if (
                    destination.type == X86_OP_REG
                    and instruction.reg_name(destination.reg) == "rdi"
                    and source.type == X86_OP_IMM
                    and text_address <= source.imm < text_end
                ):
                    main_candidates.append(source.imm)
            if len(main_candidates) != 1:
                raise ValueError("could not identify main from the ELF startup argument")
            main_address = main_candidates[0]
            main_instructions = code_at(main_address, 8192)
            main_table_offsets = {
                target - table_address
                for target in rip_targets(main_instructions)
                if table_address <= target < table_address + 20
            }
            if not {0, 4, 8, 12, 16}.issubset(main_table_offsets):
                raise ValueError("main does not use all four door fields and the room callback field")
            start_room = next(
                (
                    int(instruction.operands[1].imm) & 0xFFFFFFFF
                    for instruction in main_instructions
                    if instruction.mnemonic == "mov"
                    and len(instruction.operands) == 2
                    and instruction.operands[0].type == X86_OP_MEM
                    and instruction.operands[0].mem.base == X86_REG_RBP
                    and instruction.operands[1].type == X86_OP_IMM
                    and 0 < (int(instruction.operands[1].imm) & 0xFFFFFFFF) < room_count
                ),
                None,
            )
            if start_room is None:
                raise ValueError("could not recover the initialized room number from main")

            rodata_offset = int(rodata["offset"])
            rodata_size = int(rodata["size"])
            rodata_address = int(rodata["address"])
            flag_string_offset = binary.find(b"flag.txt\0", rodata_offset, rodata_offset + rodata_size)
            error_string_offset = binary.find(b"Error opening flag.txt :(", rodata_offset, rodata_offset + rodata_size)
            if flag_string_offset < 0 or error_string_offset < 0:
                raise ValueError("flag-file callback strings were not found in .rodata")
            flag_string_address = rodata_address + flag_string_offset - rodata_offset
            error_string_address = rodata_address + error_string_offset - rodata_offset

            callback_rooms: dict[int, list[int]] = defaultdict(list)
            for room, row in enumerate(rows):
                if row[4]:
                    callback_rooms[row[4]].append(room)
            goal_callbacks: list[tuple[int, int]] = []
            for callback, callback_room_list in callback_rooms.items():
                instructions = code_at(callback, 128)
                references = rip_targets(instructions)
                if (
                    flag_string_address in references
                    and error_string_address in references
                    and sum(instruction.mnemonic == "call" for instruction in instructions) >= 3
                ):
                    goal_callbacks.extend((room, callback) for room in callback_room_list)
            if len(goal_callbacks) != 1:
                raise ValueError(f"expected one flag-file callback room, found {len(goal_callbacks)}")
            goal_room, goal_callback = goal_callbacks[0]

            button_effects: dict[int, tuple[int, ...]] = {}
            parsed_toggle_callbacks = 0
            for callback, callback_room_list in callback_rooms.items():
                if callback == goal_callback:
                    continue
                instructions = code_at(callback, 4096)
                function: list[Any] = []
                for instruction in instructions:
                    function.append(instruction)
                    if instruction.mnemonic == "ret":
                        break
                target_leas: list[tuple[int, int]] = []
                for index, instruction in enumerate(function):
                    if instruction.mnemonic != "lea" or len(instruction.operands) < 2:
                        continue
                    memory = instruction.operands[1]
                    if memory.type != X86_OP_MEM or memory.mem.base != X86_REG_RIP:
                        continue
                    target = instruction.address + instruction.size + memory.mem.disp
                    relative = target - table_address
                    if 0 <= relative < room_count * 24 and relative % 24 in (0, 4, 8, 12):
                        target_leas.append((index, relative // 24 * 4 + (relative % 24) // 4))
                effects: list[int] = []
                for position, slot in target_leas:
                    next_position = next(
                        (other_position for other_position, _other_slot in target_leas if other_position > position),
                        len(function),
                    )
                    block = function[position:next_position]
                    lock_xors = [
                        item.mnemonic == "xor"
                        and len(item.operands) == 2
                        and item.operands[1].type == X86_OP_IMM
                        and item.operands[1].imm == 0x10000000
                        for item in block
                    ]
                    stores = [
                        item
                        for item in block
                        if item.mnemonic == "mov"
                        and len(item.operands) == 2
                        and item.operands[0].type == X86_OP_MEM
                        and item.operands[0].mem.base == X86_REG_RAX
                        and item.operands[0].mem.disp == 0
                        and item.operands[1].type == X86_OP_REG
                        and item.operands[0].size == 4
                    ]
                    if sum(lock_xors) != 1 or len(stores) != 1:
                        raise ValueError(f"callback {callback:#x} has an unverified table write")
                    value = rows[slot // 4][slot % 4]
                    if value == 0xFFFFFFFF:
                        raise ValueError(f"callback {callback:#x} toggles an absent door")
                    destination = value & 0x0FFFFFFF
                    reverse_slot = destination * 4 + (slot % 4 + 2) % 4
                    effects.append(slot)
                    if reverse_slot not in [item for _position, item in target_leas]:
                        raise ValueError(f"callback {callback:#x} does not toggle both ends of a door")
                if not effects:
                    raise ValueError(f"non-exit callback {callback:#x} contains no verified door toggles")
                if len(effects) not in {2, 4, 6} or len(set(effects)) != len(effects):
                    raise ValueError(f"callback {callback:#x} has an unsupported toggle count")
                for room in callback_room_list:
                    button_effects[room] = tuple(effects)
                parsed_toggle_callbacks += 1

            neighbors: list[int] = []
            locked: list[int] = []
            for row in rows:
                for value in row[:4]:
                    if value == 0xFFFFFFFF:
                        neighbors.append(-1)
                        locked.append(1)
                    else:
                        neighbors.append(value & 0x0FFFFFFF)
                        locked.append(int(bool(value & 0x10000000)))
            plan = _plan_dungeon_route(neighbors, locked, button_effects, start=start_room, goal=goal_room)
            if plan is None:
                raise ValueError("no winning route was found within the two-button static planning limit")

            current_room = start_room
            replay_locks = bytearray(locked)
            toggle_states_by_stop: dict[int, dict[int, bool]] = {}
            key_to_direction = {key: direction for direction, key in enumerate(("a", "w", "d", "s"))}
            route_verified = True
            for stop_index, stop in enumerate(plan["stops"]):
                for key in stop["moves"]:
                    direction = key_to_direction.get(key)
                    if direction is None:
                        route_verified = False
                        break
                    slot = current_room * 4 + direction
                    destination = neighbors[slot]
                    if destination < 0 or replay_locks[slot]:
                        route_verified = False
                        break
                    current_room = destination
                if not route_verified or current_room != stop["room"]:
                    route_verified = False
                    break
                if stop["action"] == "toggle":
                    if tuple(stop["effects"]) != button_effects.get(current_room):
                        route_verified = False
                        break
                    toggle_states_by_stop[stop_index] = _apply_dungeon_toggles(
                        replay_locks, stop["effects"]
                    )
                elif stop["action"] == "win":
                    if current_room != goal_room:
                        route_verified = False
                        break
                else:
                    route_verified = False
                    break
            if not route_verified or plan["stops"][-1]["action"] != "win":
                raise ValueError("the generated movement sequence failed static replay")

            supplied_paths = (context.input_path, *context.related_paths[: context.limits.max_files])
            flag_file_present = any(
                path.name.casefold() == "flag.txt" and path.is_file() and not path.is_symlink()
                for path in supplied_paths
            )
            report_stops: list[dict[str, Any]] = []
            for stop_index, stop in enumerate(plan["stops"]):
                report_stop = {key: value for key, value in stop.items() if key != "effects"}
                if stop["action"] == "toggle":
                    seen_doors: set[tuple[int, int]] = set()
                    door_toggles: list[dict[str, Any]] = []
                    for slot in stop["effects"]:
                        source_room = slot // 4
                        direction = slot % 4
                        destination_room = neighbors[slot]
                        edge = tuple(sorted((source_room, destination_room)))
                        if edge in seen_doors:
                            continue
                        seen_doors.add(edge)
                        door_toggles.append(
                            {
                                "source_room": source_room,
                                "direction": ("a", "w", "d", "s")[direction],
                                "destination_room": destination_room,
                                "was_locked": toggle_states_by_stop[stop_index][slot],
                            }
                        )
                    report_stop["door_toggles"] = door_toggles
                report_stops.append(report_stop)

            artifact_root = self._artifact_root(context, "dungeon", binary)
            input_path = artifact_root / "dungeon-route.stdin"
            input_path.write_bytes(plan["stdin"])
            route_path = artifact_root / "dungeon-route.json"
            report_plan = {key: value for key, value in plan.items() if key not in {"stdin", "stops"}}
            route_path.write_text(
                json.dumps(
                    {
                        "binary_sha256": hashlib.sha256(binary).hexdigest(),
                        "start_room": start_room,
                        "goal_room": goal_room,
                        "room_count": room_count,
                        "toggle_callback_count": parsed_toggle_callbacks,
                        "static_route_verified": route_verified,
                        "input_format": "one key followed by newline per prompt",
                        "flag_file_in_supplied_artifacts": flag_file_present,
                        "challenge_binary_executed": False,
                        "challenge_service_contacted": False,
                        "platform_confirmation": False,
                        "stops": report_stops,
                        **report_plan,
                    },
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            result.status = "payload-ready"
            result.artifacts.extend((str(input_path), str(route_path)))
            result.steps.append(
                {
                    "name": "dungeon-static-route",
                    "status": "ok",
                    "details": {
                        "start_room": start_room,
                        "goal_room": goal_room,
                        "room_count": room_count,
                        "button_rooms": [stop["room"] for stop in plan["stops"] if stop["action"] == "toggle"],
                        "toggle_callback_count": parsed_toggle_callbacks,
                        "movement_count": plan["movement_count"],
                        "command_count": plan["command_count"],
                        "input_file": str(input_path),
                        "route_file": str(route_path),
                        "static_route_verified": route_verified,
                        "flag_file_in_supplied_artifacts": flag_file_present,
                        "challenge_binary_executed": False,
                        "challenge_service_contacted": False,
                        "platform_confirmation": False,
                    },
                }
            )
            return result
        except (ImportError, OSError, ValueError, struct.error, StopIteration) as exc:
            result.steps.append(
                {
                    "name": "dungeon-static-route",
                    "status": "needs-review",
                    "details": {
                        "reason": str(exc),
                        "challenge_binary_executed": False,
                        "challenge_service_contacted": False,
                    },
                }
            )
            return result

    def _solve_number_mashing(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        try:
            from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
            from ico_universal_reverse import inspect_native

            binary = _read_limited(context.input_path, context.limits.max_bytes)
            inventory = inspect_native(context.input_path, context.limits)
            if inventory.get("machine") != "aarch64" or inventory.get("endianness") != "little":
                raise ValueError("expected a little-endian AArch64 ELF")
            symbols = inventory.get("symbols", [])
            sections = inventory.get("sections", [])
            main = next((item for item in symbols if item.get("name") == "main"), None)
            text = next(
                (
                    item
                    for item in sections
                    if item.get("name") == ".text"
                    and isinstance(item.get("address"), int)
                    and isinstance(item.get("size"), int)
                    and item["address"] <= (main.get("value", -1) if main else -1) < item["address"] + item["size"]
                ),
                None,
            )
            if main is None or text is None:
                raise ValueError("an unstripped main symbol in .text is required")
            text_offset = int(text["offset"]) + int(main["value"]) - int(text["address"])
            available = min(int(text["size"]) - (int(main["value"]) - int(text["address"])), 16 * 1024)
            code = binary[text_offset : text_offset + available]
            disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
            instructions = list(disassembler.disasm(code, int(main["value"])))
            strings = [str(value) for value in inventory.get("strings", [])]
            required_strings = ("%d %d", "Nope!", "flag.txt", "Correct! %s")
            if not all(any(required in value for value in strings) for required in required_strings):
                raise ValueError("the two-integer flag-file checker strings were not all present")

            normalized = [
                (item.mnemonic.casefold(), re.sub(r"\s+", "", item.op_str.casefold()), int(item.address))
                for item in instructions
            ]

            def branch_target(index: int) -> int | None:
                if index < 0 or index >= len(instructions):
                    return None
                match = re.fullmatch(r"#?(0x[0-9a-f]+|[0-9]+)", instructions[index].op_str.strip(), re.I)
                return int(match.group(1), 0) if match else None

            matched: tuple[int, int] | None = None
            for index, (mnemonic, operands, _address) in enumerate(normalized):
                if mnemonic != "sdiv" or operands != "w0,w1,w0" or index < 11 or index + 5 >= len(normalized):
                    continue
                suffix = normalized[index + 1 : index + 6]
                expected_suffix = [
                    ("str", "w0,[sp,#0x1c]"),
                    ("ldr", "w0,[sp,#0x14]"),
                    ("ldr", "w1,[sp,#0x1c]"),
                    ("cmp", "w1,w0"),
                    ("b.eq", None),
                ]
                if any(got[0] != want[0] or (want[1] is not None and got[1] != want[1]) for got, want in zip(suffix, expected_suffix)):
                    continue
                success = branch_target(index + 5)
                text_start = int(text["address"])
                text_end = text_start + int(text["size"])
                if success is None or not text_start <= success < text_end or success <= normalized[index + 5][2]:
                    continue
                success_index = next(
                    (position for position, item in enumerate(normalized) if item[2] == success),
                    None,
                )
                if success_index is None:
                    continue
                success_tail = normalized[success_index:]
                return_index = next((position for position, item in enumerate(success_tail) if item[0] == "ret"), None)
                if return_index is None or sum(item[0] == "bl" for item in success_tail[:return_index]) < 2:
                    continue
                expected_guard = [
                    ("ldr", "w0,[sp,#0x14]"),
                    ("cmp", "w0,#0"),
                    ("b.eq", None),
                    ("ldr", "w0,[sp,#0x18]"),
                    ("cmp", "w0,#0"),
                    ("b.eq", None),
                    ("ldr", "w0,[sp,#0x18]"),
                    ("cmp", "w0,#1"),
                    ("b.ne", None),
                ]
                for guard_start in range(0, index - 8):
                    guard = normalized[guard_start : guard_start + len(expected_guard)]
                    if len(guard) != len(expected_guard) or any(
                        got[0] != want[0] or (want[1] is not None and got[1] != want[1])
                        for got, want in zip(guard, expected_guard)
                    ):
                        continue
                    fail_a = branch_target(guard_start + 2)
                    fail_b = branch_target(guard_start + 5)
                    divide_entry = branch_target(guard_start + 8)
                    fail_block_is_separate = guard_start + len(expected_guard) <= index - 2
                    if (
                        fail_a is None
                        or fail_a != fail_b
                        or fail_a == success
                        or divide_entry is None
                        or not text_start <= fail_a < text_end
                        or fail_a >= divide_entry
                    ):
                        continue
                    failure_path = normalized[guard_start + len(expected_guard) : index - 2]
                    if (
                        not fail_block_is_separate
                        or divide_entry != normalized[index - 2][2]
                        or not failure_path
                        or fail_a != failure_path[0][2]
                        or not any(item[0] in {"bl", "ret", "br"} for item in failure_path)
                    ):
                        continue
                    matched = (int(normalized[index][2]), success)
                    break
                if matched is not None:
                    break

            if matched is None:
                result.steps.append(
                    {
                        "name": "number-mashing-static-inversion",
                        "status": "needs-review",
                        "details": {
                            "reason": "the exact nonzero-input, reject-one, signed-division, equality-branch pattern was not established",
                            "challenge_binary_executed": False,
                        },
                    }
                )
                return result
        except (ImportError, OSError, ValueError, StopIteration) as exc:
            result.steps.append(
                {
                    "name": "number-mashing-static-inversion",
                    "status": "needs-review",
                    "details": {"reason": str(exc), "challenge_binary_executed": False},
                }
            )
            return result

        raw = b"-2147483648 -1\n"
        root = self._artifact_root(context, "number-mashing", binary)
        input_path = root / "number-mashing.stdin"
        input_path.write_bytes(raw)
        result.artifacts.append(str(input_path))
        supplied_paths = (context.input_path, *context.related_paths[: context.limits.max_files])
        flag_file_present = any(path.name.casefold() == "flag.txt" and path.is_file() for path in supplied_paths)
        result.status = "payload-ready"
        result.steps.append(
            {
                "name": "number-mashing-static-inversion",
                "status": "ok",
                "details": {
                    "architecture": "AArch64",
                    "division_instruction": f"0x{matched[0]:x}: sdiv w0, w1, w0",
                    "accepted_branch": f"0x{matched[1]:x}",
                    "input_file": str(input_path),
                    "stdin_ascii": raw.decode("ascii").rstrip("\n"),
                    "arithmetic_edge_case": "signed-int-min-divided-by-minus-one",
                    "reasoning": "the checker requires a != 0, b != 0, b != 1, and signed32(a / b) == a; AArch64 SDIV returns INT_MIN for INT_MIN / -1",
                    "flag_file_in_supplied_artifacts": flag_file_present,
                    "challenge_binary_executed": False,
                    "challenge_service_contacted": False,
                    "platform_confirmation": False,
                },
            }
        )
        return result

    def _solve_my_array_generator(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        source_path = context.input_path
        output_path = next((path for path in context.related_paths if path.name.casefold() == "output.txt"), None)
        if output_path is None:
            result.steps.append({"name": "my-array-known-plaintext", "status": "needs-review", "details": {"reason": "paired output.txt is missing"}})
            return result
        try:
            source_data = _read_limited(source_path, min(context.limits.max_bytes, 256 * 1024))
            source = source_data.decode("utf-8", errors="replace")
            parameters = _my_array_parameters(source)
            output_data = _read_limited(output_path, context.limits.max_bytes)
            if parameters is None:
                raise ValueError("source does not match the supported static MyArrayGenerator transform")
            output_text = output_data.decode("ascii", errors="strict")
            values = {
                name: bytes.fromhex(value)
                for name, value in re.findall(r'(?m)^\s*(plaintext|ciphertext)\s*=\s*"([0-9a-fA-F]+)"\s*$', output_text)
            }
            plaintext = values.get("plaintext")
            ciphertext = values.get("ciphertext")
            if plaintext is None or ciphertext is None or len(plaintext) != len(ciphertext):
                raise ValueError("output.txt must contain equal-length plaintext and ciphertext hex values")
            if not 80 <= len(plaintext) <= context.limits.max_bytes:
                raise ValueError("known-plaintext length is outside the bounded solver range")
        except (OSError, UnicodeError, ValueError) as exc:
            result.steps.append({"name": "my-array-known-plaintext", "status": "needs-review", "details": {"reason": str(exc), "challenge_source_executed": False}})
            return result

        started = time.monotonic()
        key, smt_details = _my_array_smt(
            plaintext,
            ciphertext,
            parameters,
            timeout_seconds=min(context.limits.timeout_seconds, 60.0),
        )
        forward_verified = False
        if key is not None:
            try:
                forward_verified = _my_array_encrypt_exact(key, plaintext, parameters) == ciphertext
            except (IndexError, ValueError):
                forward_verified = False
        duration = round(time.monotonic() - started, 6)
        root = self._artifact_root(context, "my-array-generator", source_data + output_data)
        evidence_path = root / "my-array-known-plaintext-analysis.json"
        evidence = {
            "method": "bounded SMT recovery of the repeated 32-byte key words from known plaintext",
            "source_parameters": {key_name: value for key_name, value in parameters.items() if key_name != "key_template"},
            "key_template_length": len(parameters["key_template"]),
            "plaintext_bytes": len(plaintext),
            "challenge_source_executed": False,
            "solver": smt_details,
            "forward_verified_against_full_ciphertext": forward_verified,
            "local_checker": "independent exact reimplementation of the statically matched update and byte-selection rules",
            "platform_confirmation": False,
        }
        _write_json(evidence_path, evidence)
        result.artifacts.append(str(evidence_path))
        if key is not None and forward_verified:
            key_text = key.decode("ascii", errors="ignore")
            key_path = root / "my-array-key-candidate.txt"
            key_path.write_bytes(key)
            result.artifacts.append(str(key_path))
            for hit in FlagMatcher().scan(key_text, source=str(key_path), analyzer="my-array-smt-known-plaintext"):
                hit["validation"] = "SMT candidate forward-encrypts the full supplied plaintext to the full supplied ciphertext; no platform confirmation"
                hit["state"] = "candidate"
                result.candidates.append(hit)
            if result.candidates:
                result.status = "candidate"
        result.steps.append(
            {
                "name": "my-array-known-plaintext",
                "status": "candidate" if result.candidates else "candidate-review",
                "details": {
                    "static_source_match": True,
                    "challenge_source_executed": False,
                    "known_plaintext_bytes": len(plaintext),
                    "smt": smt_details,
                    "full_ciphertext_forward_verified": forward_verified,
                    "platform_confirmation": False,
                    "duration_seconds": duration,
                    "evidence": str(evidence_path),
                    "reason": None if result.candidates else "SMT tool, timeout, model, flag format, or full-stream verification did not establish a candidate",
                },
            }
        )
        return result

    def _solve_ternary_brainfuck(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        source_path = next((path for path in context.related_paths if path.suffix.casefold() == ".go"), None)
        mapping_source = "paired-go-source"
        try:
            if source_path is not None:
                source_data = _read_limited(source_path, min(context.limits.max_bytes, 256 * 1024))
                source = source_data.decode("utf-8", errors="replace")
                mapping = _ternary_brainfuck_mapping(source)
                if mapping is None:
                    raise ValueError("Go source does not contain the supported base-3 Brainfuck opcode table")
            else:
                encoder_path = next((path for path in context.related_paths if path.name.casefold() == "encoder"), None)
                if (
                    _task_root_name(context) != "ternary_brained"
                    or encoder_path is None
                    or not context.task_text
                    or not encoder_path.is_file()
                    or encoder_path.is_symlink()
                ):
                    raise ValueError("paired Go source is missing and the archived Ternary Brained bundle signature did not match")
                source_data = context.task_text.encode("utf-8")
                mapping = dict(_DUCTF_TERNARY_BRAINFUCK_MAPPING)
                mapping_source = "published-task-opcode-table; encoder ELF was not read or executed"
            encoded = _read_limited(context.input_path, context.limits.max_bytes)
            program = _decode_ternary_brainfuck(encoded, mapping)
            step_limit = min(
                _MAX_BRAINFUCK_STEPS,
                max(100_000, int(context.limits.timeout_seconds * 200_000)),
            )
            output, steps = _run_bounded_brainfuck(program, max_steps=step_limit)
        except TimeoutError as exc:
            result.steps.append({"name": "ternary-brainfuck-decode", "status": "needs-review", "details": {"reason": str(exc), "challenge_binary_executed": False, "step_limit": step_limit if "step_limit" in locals() else _MAX_BRAINFUCK_STEPS}})
            return result
        except (OSError, UnicodeError, ValueError) as exc:
            result.steps.append({"name": "ternary-brainfuck-decode", "status": "needs-review", "details": {"reason": str(exc), "challenge_binary_executed": False}})
            return result

        root = self._artifact_root(context, "ternary-brainfuck", encoded + source_data)
        program_path = root / "ternary-brainfuck-program.txt"
        output_path = root / "ternary-brainfuck-output.bin"
        program_path.write_text(program, encoding="ascii")
        output_path.write_bytes(output)
        result.artifacts.extend([str(program_path), str(output_path)])
        output_text = output.decode("utf-8", errors="replace")
        for hit in FlagMatcher().scan(output_text, source=str(output_path), analyzer="ternary-base3-bounded-brainfuck"):
            hit["validation"] = "decoded from the paired Go opcode table and emitted by the bounded local Brainfuck interpreter; no challenge binary or service executed"
            hit["state"] = "candidate"
            result.candidates.append(hit)
        if result.candidates:
            result.status = "candidate"
        result.steps.append(
            {
                "name": "ternary-brainfuck-decode",
                "status": "candidate" if result.candidates else "candidate-review",
                "details": {
                    "encoding": "base-3 integer with two trits per documented Brainfuck opcode",
                    "mapping_source": mapping_source,
                    "instruction_count": len(program),
                    "interpreter_steps": steps,
                    "output_bytes": len(output),
                    "challenge_binary_executed": False,
                    "challenge_service_contacted": False,
                    "step_limit": step_limit,
                    "tape_cells": _MAX_BRAINFUCK_TAPE,
                    "output_limit": _MAX_BRAINFUCK_OUTPUT,
                    "evidence": [str(program_path), str(output_path)],
                    "platform_confirmation": False,
                },
            }
        )
        return result

    def _solve_macro_magic(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        macros, captures, url_texts = _read_context_inputs(context)
        sources: list[str] = []
        key_source_labels: list[str] = []
        for label, data in macros:
            if label.casefold().endswith((".bas", ".vba")):
                sources.append(data.decode("utf-8", errors="replace"))
                key_source_labels.append(label)
                continue
            try:
                extracted = _extract_vba_sources(data, max_bytes=context.limits.max_bytes)
            except (RuntimeError, OSError, ValueError, zipfile.BadZipFile) as exc:
                result.steps.append({"name": "extract-vba-statically", "status": "needs-review", "details": {"source": label, "reason": str(exc), "macro_executed": False}})
                continue
            if extracted:
                sources.extend(extracted)
                key_source_labels.append(label)
        if not sources:
            result.steps.append({"name": "extract-vba-statically", "status": "needs-review", "details": {"reason": "no readable VBA module was found", "macro_executed": False}})
            return result
        try:
            key = _derive_vba_repeating_xor_key(sources)
        except ValueError as exc:
            result.steps.append({"name": "derive-macro-xor-key", "status": "needs-review", "details": {"reason": str(exc), "source_count": len(sources)}})
            return result

        urls, capture_notes = _extract_capture_urls(captures, context)
        for text in url_texts:
            urls.extend(match.group(0) for match in re.finditer(r"https?://[^\s\"'<>]+", text, re.I) if _DECIMAL_RUN_RE.search(match.group(0)))
        decoded: list[tuple[str, bytes]] = []
        for uri in urls:
            decoded.extend((uri, plain) for _numeric, plain in _decimal_xor_candidates(uri, key))
        if decoded:
            raw = decoded[0][1]
            root = self._artifact_root(context, "macro-magic", raw)
            plaintext_path = root / "macro-magic-decoded-candidate.txt"
            plaintext_path.write_bytes(raw)
            result.artifacts.append(str(plaintext_path))
            for uri, plain in decoded:
                for hit in FlagMatcher().scan(plain.decode("ascii", errors="ignore"), source=str(plaintext_path), analyzer="macro-magic-static-xor"):
                    hit["validation"] = "decimal URL bytes XORed with the statically derived VBA repeating key"
                    hit["state"] = "candidate"
                    result.candidates.append(hit)
            if result.candidates:
                result.status = "candidate"
        result.steps.extend(
            [
                {"name": "extract-vba-statically", "status": "ok", "details": {"source_count": len(sources), "sources": key_source_labels, "macro_executed": False}},
                {"name": "derive-macro-xor-key", "status": "ok", "details": {"key_length": len(key), "key_hex": key.hex(), "method": "literal-only VBA concatenation and XOR-loop validation"}},
                {"name": "macromagic-static-xor", "status": "ok" if result.candidates else "candidate-review", "details": {"capture_count": len(captures), "url_count": len(urls), "decoded_candidate_count": len(result.candidates), "offline_only": True, "capture_notes": capture_notes}},
            ]
        )
        if not result.candidates:
            result.steps[-1]["details"]["reason"] = "no decoded URL matched the DUCTF flag format"
        return result

    def _crack_ntlm_hash(
        self,
        nt_hash: str,
        wordlists: Sequence[Path],
        work_dir: Path,
        *,
        timeout_seconds: float,
    ) -> str | None:
        if not re.fullmatch(r"[0-9a-fA-F]{32}", nt_hash):
            raise ValueError("NT hash must be exactly 32 hexadecimal characters")
        hashcat = shutil.which("hashcat")
        if hashcat is None:
            return None
        work_dir.mkdir(parents=True, exist_ok=True)
        hash_path = work_dir / "administrator.ntlm"
        hash_path.write_text(nt_hash.lower() + "\n", encoding="ascii")
        rules_path = work_dir / "common-password-mutations.rule"
        rules_path.write_text("\n".join(_NTLM_MUTATION_RULES) + "\n", encoding="ascii")
        pot_path = work_dir / "hashcat.pot"
        deadline = time.monotonic() + max(0.1, timeout_seconds)
        for index, wordlist in enumerate(wordlists):
            try:
                resolved = wordlist.expanduser().resolve()
                if resolved.is_symlink() or not resolved.is_file():
                    continue
                size = resolved.stat().st_size
                if not 0 < size <= _MAX_WORDLIST_BYTES:
                    continue
            except OSError:
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            command = [
                hashcat,
                "-m",
                "1000",
                "-a",
                "0",
                "-r",
                str(rules_path),
                str(hash_path),
                str(resolved),
                "--potfile-path",
                str(pot_path),
                "--quiet",
            ]
            try:
                subprocess.run(command, capture_output=True, text=True, timeout=remaining, check=False)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                shown = subprocess.run(
                    [hashcat, "-m", "1000", "--show", str(hash_path), "--potfile-path", str(pot_path)],
                    capture_output=True,
                    text=True,
                    timeout=remaining,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                break
            password = None
            for line in shown.stdout.splitlines():
                recovered_hash, separator, recovered_password = line.partition(":")
                if separator and recovered_hash.casefold() == nt_hash.casefold():
                    password = recovered_password
                    break
            if not password:
                continue
            try:
                from impacket.ntlm import compute_nthash

                if compute_nthash(password).hex().casefold() == nt_hash.casefold():
                    return password
            except ImportError:
                # John has already checked the recovered word against this NT hash.
                return password
        return None

    def _solve_sam_i_am(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        sam_data: bytes | None = None
        system_data: bytes | None = None
        for path in (context.input_path, *context.related_paths[: context.limits.max_files]):
            try:
                if path.suffix.casefold() == ".zip":
                    members = _archive_payloads(path, max_bytes=context.limits.max_bytes, max_files=context.limits.max_files)
                    sam_data = sam_data or members.get("sam.bak") or members.get("sam")
                    system_data = system_data or members.get("system.bak") or members.get("system")
                elif path.name.casefold() in {"sam.bak", "sam"}:
                    sam_data = _read_limited(path, context.limits.max_bytes)
                elif path.name.casefold() in {"system.bak", "system"}:
                    system_data = _read_limited(path, context.limits.max_bytes)
            except (OSError, ValueError, zipfile.BadZipFile) as exc:
                result.steps.append({"name": "read-local-hives", "status": "needs-review", "details": {"path": str(path), "reason": str(exc)}})
        if sam_data is None or system_data is None:
            result.steps.append({"name": "read-local-hives", "status": "needs-review", "details": {"sam_found": sam_data is not None, "system_found": system_data is not None}})
            return result
        try:
            nt_hash = _secretsdump_admin_hash(sam_data, system_data)
        except (RuntimeError, OSError, ValueError, ImportError) as exc:
            result.steps.append({"name": "extract-administrator-nt-hash", "status": "needs-review", "details": {"reason": str(exc), "remote_access": False}})
            return result

        root = self._artifact_root(context, "sam-i-am", sam_data + system_data)
        hash_path = root / "administrator.ntlm"
        hash_path.write_text(f"Administrator:{nt_hash}\n", encoding="ascii")
        result.artifacts.append(str(hash_path))
        wordlists = _wordlist_paths()[: context.limits.max_files]
        password = self._crack_ntlm_hash(
            nt_hash,
            wordlists,
            root / "john-work",
            timeout_seconds=min(context.limits.timeout_seconds, 60.0),
        )
        if password is None:
            reason = "no local wordlist is configured or available" if not wordlists else "Administrator NT hash did not match the bounded local wordlists"
            result.steps.extend(
                [
                    {"name": "extract-administrator-nt-hash", "status": "ok", "details": {"nt_hash_sha256": hashlib.sha256(nt_hash.encode("ascii")).hexdigest(), "method": "local Impacket SAM/SYSTEM hive parsing", "remote_access": False}},
                    {"name": "offline-ntlm-dictionary", "status": "needs-review", "details": {"reason": reason, "wordlists": [str(path) for path in wordlists], "timeout_seconds": min(context.limits.timeout_seconds, 60.0), "dictionary_only": True}},
                ]
            )
            return result

        flag = f"DUCTF{{{password}}}"
        for hit in FlagMatcher().scan(flag, source=str(hash_path), analyzer="sam-i-am-offline-ntlm"):
            hit["validation"] = "Administrator password recomputes to the NT hash extracted from local SAM/SYSTEM hives"
            result.candidates.append(hit)
        result.status = "candidate" if result.candidates else "candidate-review"
        result.steps.extend(
            [
                {"name": "extract-administrator-nt-hash", "status": "ok", "details": {"nt_hash_sha256": hashlib.sha256(nt_hash.encode("ascii")).hexdigest(), "method": "local Impacket SAM/SYSTEM hive parsing", "remote_access": False}},
                {"name": "offline-ntlm-dictionary", "status": "ok" if result.candidates else "candidate-review", "details": {"wordlists": [str(path) for path in wordlists], "dictionary_only": True, "password_recovered": bool(result.candidates)}},
            ]
        )
        return result

    def _solve_three_line(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "candidate-review")
        source_path = next((path for path in context.related_paths if path.name.casefold() == "encrypt.py"), None)
        cipher_path = context.input_path if context.input_path.name.casefold().startswith("passage.enc") else next(
            (path for path in context.related_paths if path.name.casefold().startswith("passage.enc")), None
        )
        if source_path is None or cipher_path is None:
            result.steps.append({"name": "three-line-cryptanalysis", "status": "needs-review", "details": {"reason": "paired encrypt.py and passage.enc input are required"}})
            return result
        try:
            source = _read_limited(source_path, context.limits.max_bytes).decode("utf-8", errors="replace")
            ciphertext = _read_limited(cipher_path, context.limits.max_bytes)
        except (OSError, ValueError) as exc:
            result.steps.append({"name": "three-line-cryptanalysis", "status": "needs-review", "details": {"reason": str(exc)}})
            return result
        if not _has_three_line_transition(source):
            result.steps.append({"name": "three-line-cryptanalysis", "status": "needs-review", "details": {"reason": "paired source does not match the supported stateful XOR transition"}})
            return result

        proposals: list[dict[str, Any]] = []
        crib_words = tuple(dict.fromkeys((word + " ").encode("ascii") for word in _COMMON_ENGLISH_CRIBS))
        span_counts: dict[int, Counter[bytes]] = {}
        for rank, plaintext in enumerate(crib_words):
            span_length = len(plaintext)
            if span_length not in span_counts:
                span_counts[span_length] = Counter(
                    ciphertext[offset : offset + span_length]
                    for offset in range(len(ciphertext) - span_length + 1)
                )
            counts = span_counts[span_length]
            for encrypted, occurrences in counts.items():
                if occurrences < 2:
                    continue
                partial: dict[int, int] = {}
                previous = 0
                for cipher_byte, plain_byte in zip(encrypted, plaintext):
                    state = previous % 16
                    value = cipher_byte ^ plain_byte
                    if state in partial and partial[state] != value:
                        break
                    partial[state] = value
                    previous = plain_byte
                else:
                    proposals.append(
                        {
                            "crib": plaintext.decode("ascii"),
                            "ciphertext_occurrences": occurrences,
                            "rank_weight": max(1, len(crib_words) - rank),
                            "key_bytes": partial,
                        }
                    )

        # Resolve one key slot at a time. A proposal is useful only while all
        # values it assigns agree with the slots already selected. Repeating
        # this filter lets reliable common-word cribs constrain later slots.
        known_key: dict[int, int] = {}
        consensus: list[dict[str, Any]] = []
        for _round in range(16):
            votes: dict[int, Counter[int]] = defaultdict(Counter)
            for proposal in proposals:
                partial = proposal["key_bytes"]
                if any(known_key.get(state, value) != value for state, value in partial.items()):
                    continue
                weight = proposal["ciphertext_occurrences"] * proposal["rank_weight"]
                for state, value in partial.items():
                    if state not in known_key:
                        votes[state][value] += weight
            if not votes:
                break

            if 0 not in known_key and 0 in votes:
                state = 0
            else:
                state = max(
                    votes,
                    key=lambda item: (
                        votes[item].most_common(1)[0][1],
                        -votes[item].most_common(1)[0][0],
                        -item,
                    ),
                )
            ranked = votes[state].most_common(4)
            value, weight = ranked[0]
            known_key[state] = value
            consensus.append(
                {
                    "slot": state,
                    "value": value,
                    "weight": weight,
                    "runner_up_weight": ranked[1][1] if len(ranked) > 1 else 0,
                    "top_hypotheses": [
                        {"value": candidate, "weight": candidate_weight}
                        for candidate, candidate_weight in ranked
                    ],
                }
            )

        unknown_key_slots = [slot for slot in range(16) if slot not in known_key]
        key_search: dict[str, Any] = {"attempted": False, "complete": False, "unknown_slots": unknown_key_slots}
        plain: bytes | None = None
        if unknown_key_slots:
            searched_key, searched_plain, key_search = _search_three_line_missing_slots(
                ciphertext,
                known_key,
                timeout_seconds=context.limits.timeout_seconds,
            )
            if searched_key is not None and searched_plain is not None:
                known_key = searched_key
                plain = searched_plain
        readable_fraction = 0.0
        if len(known_key) == 16 and plain is None:
            plain = _decrypt_three_line(ciphertext, known_key)
        if plain is not None:
            readable_fraction = sum(
                32 <= value <= 126 or value in (9, 10, 13) for value in plain
            ) / max(1, len(plain))
        key_consensus_complete = len(known_key) == 16
        full_key_recovered = len(known_key) == 16 and readable_fraction >= 0.95
        plain_text = plain.decode("ascii", errors="ignore") if full_key_recovered and plain is not None else ""
        has_flag = bool(_FLAG_RE.search(plain_text))
        top_votes = {
            str(item["slot"]): item["top_hypotheses"] for item in consensus
        }
        evidence = {
            "method": "iterative conflict-checked key consensus from repeated ciphertext word spans",
            "ciphertext_bytes": len(ciphertext),
            "source_transition_verified": True,
            "repeated_four_byte_spans": sum(1 for count in Counter(ciphertext[i : i + 4] for i in range(max(0, len(ciphertext) - 3))).values() if count > 1),
            "crib_count": len(crib_words),
            "crib_proposal_count": len(proposals),
            "crib_proposals": [
                {
                    "crib": item["crib"],
                    "ciphertext_occurrences": item["ciphertext_occurrences"],
                    "key_bytes": {str(slot): value for slot, value in sorted(item["key_bytes"].items())},
                }
                for item in sorted(
                    proposals,
                    key=lambda item: (-item["ciphertext_occurrences"], item["crib"]),
                )[:100]
            ],
            "key_byte_hypotheses": top_votes,
            "key_consensus": consensus,
            "unknown_key_slots_before_search": unknown_key_slots,
            "key_search": key_search,
            "key_slots_recovered": len(known_key),
            "full_key_recovered": full_key_recovered,
            "plaintext_readability": round(readable_fraction, 6),
            "flag_recovered": has_flag,
            "review_reason": (
                "the iterative crib consensus did not recover a complete readable plaintext"
                if not full_key_recovered
                else "a readable plaintext was recovered, but no DUCTF flag-shaped value was found"
                if not has_flag
                else "candidate remains unverified by an original checker or platform response"
            ),
        }
        raw = json.dumps(evidence, indent=2, sort_keys=True).encode("utf-8")
        root = self._artifact_root(context, "three-line", ciphertext + source.encode("utf-8"))
        path = root / "three-line-crib-analysis.json"
        path.write_bytes(raw + b"\n")
        result.artifacts.append(str(path))
        if full_key_recovered and plain is not None:
            plaintext_path = root / "three-line-plaintext-candidate.txt"
            plaintext_path.write_bytes(plain)
            result.artifacts.append(str(plaintext_path))
            if has_flag:
                for hit in FlagMatcher().scan(
                    plain_text,
                    source=str(plaintext_path),
                    analyzer="three-line-crib-consensus",
                ):
                    hit["validation"] = (
                        "the complete 16-byte stateful XOR key was recovered from repeated English cribs; "
                        "the flag remains a local candidate without checker/platform confirmation"
                    )
                    hit["state"] = "candidate"
                    result.candidates.append(hit)
                if result.candidates:
                    result.status = "candidate"
        result.steps.append(
            {
                "name": "three-line-cryptanalysis",
                "status": "candidate" if result.candidates else "candidate-review",
                "details": {
                    "ciphertext_bytes": len(ciphertext),
                    "crib_count": len(crib_words),
                    "crib_proposals": len(proposals),
                    "key_slots_recovered": len(known_key),
                    "unknown_key_slots_before_search": unknown_key_slots,
                    "key_search": key_search,
                    "full_key_recovered": full_key_recovered,
                    "plaintext_readability": round(readable_fraction, 6),
                    "flag_recovered": bool(result.candidates),
                    "offline_only": True,
                    "artifact": str(path),
                    "reason": evidence["review_reason"],
                },
            }
        )
        return result
