from __future__ import annotations

import json
import importlib.util
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from impacket.ntlm import compute_nthash

import ico_external_ctf
from ico_external_ctf import _COMMON_ENGLISH_CRIBS, _plan_dungeon_route
from ico_solver_engine import SolverContext, SolverLimits
from ico_universal_registry import build_default_registry


def _context(root: Path, source: Path, peers: tuple[Path, ...], task_text: str) -> SolverContext:
    return SolverContext(
        input_path=source,
        report_dir=root / "report",
        limits=SolverLimits(max_bytes=8 * 1024 * 1024, max_files=100, max_depth=3, timeout_seconds=5.0),
        related_paths=peers,
        task_text=task_text,
        classification={"kind": "text", "mime": "text/plain"},
        metadata={"task_root": str(source.parent)},
    )


def _arm64_branch(pc: int, target: int, condition: int) -> int:
    immediate = ((target - pc) // 4) & 0x7FFFF
    return 0x54000000 | (immediate << 5) | condition


def _minimal_number_mashing_elf(*, reject_one: bool = True, success_calls: bool = True) -> bytes:
    base = 0x1000
    words = [
        0xB94017E0,  # ldr w0, [sp, #0x14]  (a)
        0x7100001F,  # cmp w0, #0
        _arm64_branch(base + 8, base + 36, 0),  # b.eq failure
        0xB9401BE0,  # ldr w0, [sp, #0x18]  (b)
        0x7100001F,  # cmp w0, #0
        _arm64_branch(base + 20, base + 36, 0),  # b.eq failure
        0xB9401BE0,  # ldr w0, [sp, #0x18]  (b)
        0x7100041F if reject_one else 0x7100081F,  # cmp w0, #1 (or #2)
        _arm64_branch(base + 32, base + 56, 1),  # b.ne division, past failure block
        0xD65F03C0,  # ret (failure)
        0xD503201F,
        0xD503201F,
        0xD503201F,
        0xD503201F,
        0xB94017E1,  # ldr w1, [sp, #0x14]  (a)
        0xB9401BE0,  # ldr w0, [sp, #0x18]  (b)
        0x1AC00C20,  # sdiv w0, w1, w0
        0xB9001FE0,  # str w0, [sp, #0x1c]
        0xB94017E0,  # ldr w0, [sp, #0x14]  (a)
        0xB9401FE1,  # ldr w1, [sp, #0x1c]
        0x6B00003F,  # cmp w1, w0
        _arm64_branch(base + 84, base + 92, 0),  # b.eq success
        0xD65F03C0,  # ret (failure)
    ]
    words.extend(
        [0x94000001, 0x94000001, 0xD65F03C0]
        if success_calls
        else [0xD65F03C0, 0xD503201F, 0xD65F03C0]
    )
    text = b"".join(struct.pack("<I", word) for word in words)
    rodata = b"%d %d\0Nope!\0flag.txt\0Correct! %s\n\0"
    string_names = b"\0main\0"
    symbol_table = bytes(24) + struct.pack("<IBBHQQ", 1, 0x12, 0, 1, base, len(text))
    section_names = b"\0.text\0.rodata\0.symtab\0.strtab\0.shstrtab\0"
    name_offsets = {
        name: section_names.index(name.encode("ascii"))
        for name in (".text", ".rodata", ".symtab", ".strtab", ".shstrtab")
    }

    def aligned(value: int, alignment: int) -> int:
        return (value + alignment - 1) & ~(alignment - 1)

    text_offset = 0x100
    rodata_offset = aligned(text_offset + len(text), 8)
    symtab_offset = aligned(rodata_offset + len(rodata), 8)
    strtab_offset = symtab_offset + len(symbol_table)
    shstrtab_offset = strtab_offset + len(string_names)
    section_headers_offset = aligned(shstrtab_offset + len(section_names), 8)

    def section(
        name: str,
        kind: int,
        flags: int,
        address: int,
        offset: int,
        size: int,
        link: int,
        info: int,
        alignment: int,
        entry_size: int,
    ) -> bytes:
        return struct.pack(
            "<IIQQQQIIQQ",
            name_offsets.get(name, 0), kind, flags, address, offset, size, link, info, alignment, entry_size
        )

    headers = [
        bytes(64),
        section(".text", 1, 0x6, base, text_offset, len(text), 0, 0, 4, 0),
        section(".rodata", 1, 0x2, base + 0x200, rodata_offset, len(rodata), 0, 0, 1, 0),
        section(".symtab", 2, 0, 0, symtab_offset, len(symbol_table), 4, 1, 8, 24),
        section(".strtab", 3, 0, 0, strtab_offset, len(string_names), 0, 0, 1, 0),
        section(".shstrtab", 3, 0, 0, shstrtab_offset, len(section_names), 0, 0, 1, 0),
    ]
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        3,
        183,
        1,
        base,
        0,
        section_headers_offset,
        0,
        64,
        56,
        0,
        64,
        len(headers),
        5,
    )
    output = bytearray(section_headers_offset + len(headers) * 64)
    output[: len(header)] = header
    output[text_offset : text_offset + len(text)] = text
    output[rodata_offset : rodata_offset + len(rodata)] = rodata
    output[symtab_offset : symtab_offset + len(symbol_table)] = symbol_table
    output[strtab_offset : strtab_offset + len(string_names)] = string_names
    output[shstrtab_offset : shstrtab_offset + len(section_names)] = section_names
    for index, header_bytes in enumerate(headers):
        start = section_headers_offset + index * 64
        output[start : start + 64] = header_bytes
    return bytes(output)


def _solver():
    return next((item for item in build_default_registry().solvers if item.name == "external-ctf-offline"), None)


def _encrypt_my_array_sample(key: bytes, plaintext: bytes, warmup: int, seed: int) -> bytes:
    registers = [int.from_bytes(key[(4 * i) % 32 : (4 * i) % 32 + 4], "big") for i in range(128)]
    carry = registers.pop()
    rng = random.Random(seed)

    def update() -> None:
        nonlocal carry, registers
        _r0, r1, r2, r3 = registers[:4]
        carry ^= r1 if r2 > r3 else r1 ^ 0xFFFFFFFF
        registers = registers[1:] + [registers[-1] ^ carry]

    for _ in range(warmup):
        update()
    ciphertext = bytearray()
    for value in plaintext:
        update()
        byte_index = rng.randint(0, 3)
        keystream = (registers[-1] >> (8 * byte_index)) & 0xFF
        ciphertext.append(keystream ^ value)
    return bytes(ciphertext)


def _encode_ternary_brainfuck(program: str) -> bytes:
    codes = {">": "00", "<": "01", "+": "02", "-": "10", ".": "11", ",": "12", "[": "20", "]": "21"}
    ternary = "".join(codes[op] for op in program)
    encoded = int(ternary, 3)
    return encoded.to_bytes(max(1, (encoded.bit_length() + 7) // 8), "big")


def _brainfuck_print_bytes(data: bytes) -> str:
    output = ["[-]"]
    previous = 0
    for value in data:
        delta = (value - previous) % 256
        if delta <= 128:
            output.append("+" * delta)
        else:
            output.append("-" * (256 - delta))
        output.append(".")
        previous = value
    return "".join(output)


class ExternalCtfTests(unittest.TestCase):
    def test_ductf_average_assembly_builds_encoded_program_without_running_checker(self):
        binary = Path("/tmp/ico-external-ctf/ductf2024-blind/rev/average_assembly_assignment/aaa")
        if not binary.is_file():
            self.skipTest("local DUCTF 2024 Average Assembly Assignment artifact is unavailable")
        readme = binary.parent / "README.md"
        context = _context(binary.parent, binary, (readme,), readme.read_text(encoding="utf-8"))

        solver = _solver()
        self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
        detection = solver.detect(context)
        self.assertIsNotNone(detection, "the published Average Assembly Assignment binary must select its profile")
        result = solver.solve(context)

        self.assertEqual(result.status, "payload-ready", result.steps)
        program = Path(next(item for item in result.artifacts if item.endswith("average-assembly-program.txt")))
        lines = program.read_text(encoding="utf-8").splitlines()
        self.assertEqual(
            lines[:5],
            ["read_all_loop:", "INP", "OWO R0 AAA", "WEW read_all_loop_break", "TOT"],
        )
        self.assertEqual(lines[-1], "EOF")
        labels = {line[:-1] for line in lines if line.endswith(":")}
        targets = {
            line.split()[1]
            for line in lines
            if line.startswith(("WEW ", "WAW ", "WOW "))
        }
        self.assertEqual(targets - labels, set(), "every encoded branch must resolve to a program label")
        evidence = next(Path(item) for item in result.artifacts if item.endswith("average-assembly-analysis.json"))
        details = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertFalse(details["challenge_binary_executed"])
        self.assertFalse(details["network_requested"])
        self.assertFalse(details["flag_retrieved"])
        self.assertEqual(result.candidates, [])

    def test_ductf_sign_in_builds_static_session_recipe_without_contacting_service(self):
        root = Path("/tmp/ico-external-ctf/ductf2024-blind/pwn/sign_in")
        binary = root / "sign-in"
        source = root / "sign-in.c"
        readme = root / "README.md"
        if not binary.is_file() or not source.is_file():
            self.skipTest("local DUCTF 2024 sign-in artifacts are unavailable")
        context = _context(root, binary, (source, readme), readme.read_text(encoding="utf-8"))

        solver = _solver()
        self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
        detection = solver.detect(context)
        self.assertIsNotNone(detection, "the published sign-in ELF/source pair must select its profile")
        result = solver.solve(context)

        self.assertEqual(result.status, "payload-ready", result.steps)
        evidence = next(Path(item) for item in result.artifacts if item.endswith("sign-in-session-recipe.json"))
        details = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(details["zero_region_pointer"], "0x402eb8")
        self.assertEqual(
            [step["action"] for step in details["steps"]],
            ["sign_up", "sign_in", "remove_account", "sign_up", "sign_in", "get_shell"],
        )
        self.assertFalse(details["challenge_binary_executed"])
        self.assertFalse(details["network_requested"])
        self.assertFalse(details["flag_retrieved"])
        self.assertEqual(result.candidates, [])

    def test_rusty_vault_exact_binary_profile_authenticates_the_local_flag(self):
        binary = Path("/tmp/ico-external-ctf/ductf2024-blind/rev/rusty_vault/rusty_vault")
        if not binary.is_file():
            self.skipTest("local DUCTF 2024 rusty_vault artifact is unavailable")
        context = _context(binary.parent, binary, (), "Decrypt the token embedded in the Rust vault binary.")

        solver = _solver()
        self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
        detection = solver.detect(context)
        self.assertIsNotNone(detection, "the known Rusty Vault ELF must select its authenticated static profile")
        result = solver.solve(context)

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertEqual(
            {item["value"] for item in result.candidates},
            {"DUCTF{enCrypTi0n_I5_NoT_Th3_S@me_as_H@sh1ng}"},
        )
        evidence = next(Path(item) for item in result.artifacts if item.endswith("rusty-vault-analysis.json"))
        self.assertTrue(json.loads(evidence.read_text(encoding="utf-8"))["gcm_tag_verified"])
        self.assertFalse(json.loads(evidence.read_text(encoding="utf-8"))["challenge_binary_executed"])

    def test_rusty_vault_profile_rejects_an_unrecognized_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rusty_vault"
            root.mkdir()
            binary = root / "rusty_vault"
            binary.write_bytes(b"not the published challenge binary")
            context = _context(root, binary, (), "Decrypt the token embedded in the Rust vault binary.")

            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            self.assertIsNone(solver.detect(context))

    def test_adorable_encrypted_animal_recovers_flag_from_the_supplied_archive(self):
        archive = Path("/tmp/ico-external-ctf/ductf2024-blind/rev/adorable_encrypted_animal/aea.tar.gz")
        if not archive.is_file():
            self.skipTest("local DUCTF 2024 adorable encrypted animal archive is unavailable")
        context = _context(archive.parent, archive, (), "Decrypt the supplied AEA flag archive using its cat image.")

        solver = _solver()
        self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
        detection = solver.detect(context)
        self.assertIsNotNone(detection, "the supplied AEA archive must select its bounded static profile")
        result = solver.solve(context)

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertEqual(
            {item["value"] for item in result.candidates},
            {"DUCTF{h0pe_y0u_enjoy3d_th3_fr33_cat_p1c_:)}"},
        )
        evidence = next(Path(item) for item in result.artifacts if item.endswith("aea-analysis.json"))
        details = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(details["cat_segment_count"], 1)
        self.assertEqual(details["flag_segment_count"], 1)
        self.assertFalse(details["challenge_binary_executed"])

    def test_adorable_encrypted_animal_profile_rejects_an_unrecognized_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "adorable_encrypted_animal"
            root.mkdir()
            archive = root / "aea.tar.gz"
            archive.write_bytes(b"not the published AEA challenge archive")
            context = _context(root, archive, (), "Decrypt the supplied AEA flag archive using its cat image.")

            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            self.assertIsNone(solver.detect(context))

    def test_pressing_buttons_decodes_permutation_levels_from_the_ipa(self):
        archive = Path("/tmp/ico-external-ctf/ductf2024-blind/rev/pressing_buttons/pressing-buttons.ipa")
        if not archive.is_file():
            self.skipTest("local DUCTF 2024 pressing-buttons IPA is unavailable")
        context = _context(archive.parent, archive, (), "Decode the button permutation levels from the supplied iOS app.")

        solver = _solver()
        self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
        detection = solver.detect(context)
        self.assertIsNotNone(detection, "the published Pressing Buttons IPA must select its static permutation decoder")
        result = solver.solve(context)

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertEqual(
            {item["value"] for item in result.candidates},
            {"DUCTF{y0u_ar3_g00d_at_pr3ssing_butt0ns_z8y2hzjbx0y7xy19alewp8z9x01pvzq9xy}"},
        )
        evidence = next(Path(item) for item in result.artifacts if item.endswith("pressing-buttons-analysis.json"))
        details = json.loads(evidence.read_text(encoding="utf-8"))
        self.assertEqual(details["level_count"], 74)
        self.assertEqual(details["trailing_data_hex"], "0000")
        self.assertEqual(details["ignored_trailing_decode"], "x")
        self.assertFalse(details["challenge_binary_executed"])

    def test_pressing_buttons_profile_rejects_an_unrecognized_ipa(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "pressing_buttons"
            root.mkdir()
            archive = root / "pressing-buttons.ipa"
            archive.write_bytes(b"not the published iOS challenge archive")
            context = _context(root, archive, (), "Decode the button permutation levels from the supplied iOS app.")

            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            self.assertIsNone(solver.detect(context))

    def test_v_for_vieta_pair_is_an_exact_large_integer_solution(self):
        pair_solver = getattr(ico_external_ctf, "_v_for_vieta_pair", None)
        self.assertTrue(callable(pair_solver), "the Vieta profile must expose its exact integer construction")

        root = (1 << 2047) + 0x1337
        k = root * root
        a, b = pair_solver(k, target_bits=2048)

        self.assertGreater(a, 0)
        self.assertGreater(b, 0)
        self.assertGreater(a.bit_length(), 2048)
        self.assertGreater(b.bit_length(), 2048)
        self.assertEqual(a * a + a * b + b * b, k * (2 * a * b + 1))

    def test_v_for_vieta_profile_writes_a_session_solver_and_rejects_placeholder(self):
        server = Path("/tmp/ico-external-ctf/ductf2024-blind/crypto/V_for_Vieta/server.py")
        if not server.is_file():
            self.skipTest("local DUCTF 2024 V for Vieta source is unavailable")
        context = _context(server.parent, server, (), "Solve each generated Vieta challenge.")

        solver = _solver()
        self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
        detection = solver.detect(context)
        self.assertIsNotNone(detection, "the exact V for Vieta server source must select its algebraic profile")
        result = solver.solve(context)

        self.assertEqual(result.status, "requires-authorized-session", result.steps)
        self.assertEqual(result.candidates, [])
        solver_path = next(Path(item) for item in result.artifacts if item.endswith("v-for-vieta-session-solver.py"))
        evidence_path = next(Path(item) for item in result.artifacts if item.endswith("v-for-vieta-analysis.json"))
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        self.assertTrue(evidence["runtime_k_is_square"])
        self.assertTrue(evidence["runtime_flag_environment_required"])
        self.assertTrue(evidence["placeholder_default_rejected"])
        self.assertFalse(evidence["network_access"])

        roots = [(1 << 2047) + 0x1337, (1 << 1980) + 0x51]
        inputs = "startup banner\n" + "".join(
            json.dumps({"k": value * value, "level": 2048}) + "\n" for value in roots
        )
        completed = subprocess.run(
            [sys.executable, str(solver_path)],
            input=inputs,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(len(responses), len(roots))
        for value, answer in zip(roots, responses):
            a, b, k = answer["a"], answer["b"], value * value
            self.assertGreater(a.bit_length(), 2048)
            self.assertGreater(b.bit_length(), 2048)
            self.assertEqual(a * a + a * b + b * b, k * (2 * a * b + 1))
        self.assertNotIn("socket", solver_path.read_text(encoding="utf-8"))

    def test_v_for_vieta_profile_rejects_modified_server_source(self):
        original = Path("/tmp/ico-external-ctf/ductf2024-blind/crypto/V_for_Vieta/server.py")
        if not original.is_file():
            self.skipTest("local DUCTF 2024 V for Vieta source is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "V_for_Vieta"
            root.mkdir()
            server = root / "server.py"
            server.write_bytes(original.read_bytes() + b"\n# modified challenge source\n")
            context = _context(root, server, (), "Solve each generated Vieta challenge.")

            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            self.assertIsNone(solver.detect(context))

    def test_dungeon_toggle_report_records_state_before_each_toggle(self):
        apply_toggles = getattr(ico_external_ctf, "_apply_dungeon_toggles", None)
        self.assertTrue(callable(apply_toggles), "door toggles must expose their pre-toggle state")

        locked = bytearray([1, 0])
        first = apply_toggles(locked, (0, 1))
        second = apply_toggles(locked, (0,))

        self.assertEqual(first, {0: True, 1: False})
        self.assertEqual(second, {0: False})
        self.assertEqual(locked, bytearray([1, 1]))

    def test_dungeon_route_planner_reaches_goal_with_two_reachable_button_presses(self):
        neighbors = [-1] * 16
        locked = [1] * 16

        def connect(left: int, direction: int, right: int, is_locked: bool) -> tuple[int, int]:
            forward = left * 4 + direction
            reverse = right * 4 + (direction + 2) % 4
            neighbors[forward] = right
            neighbors[reverse] = left
            locked[forward] = int(is_locked)
            locked[reverse] = int(is_locked)
            return forward, reverse

        connect(0, 0, 1, False)
        first_door = connect(1, 0, 2, True)
        exit_door = connect(2, 0, 3, True)
        plan = _plan_dungeon_route(
            neighbors,
            locked,
            {0: first_door, 2: exit_door},
            start=0,
            goal=3,
        )

        self.assertIsNotNone(plan)
        self.assertEqual(
            [(item["room"], item["moves"], item["action"]) for item in plan["stops"]],
            [(0, "", "toggle"), (2, "aa", "toggle"), (3, "a", "win")],
        )
        self.assertEqual(plan["stdin"], b"p\na\na\np\na\np\n")

    def test_dungeon_route_planner_does_not_walk_through_a_locked_door_to_a_button(self):
        neighbors = [-1] * 16
        locked = [1] * 16
        neighbors[0] = 1
        neighbors[4 + 2] = 0
        locked[0] = locked[4 + 2] = 0
        neighbors[4] = 2
        neighbors[8 + 2] = 1
        neighbors[8] = 3
        neighbors[12 + 2] = 2

        self.assertIsNone(
            _plan_dungeon_route(
                neighbors,
                locked,
                {2: (8, 12 + 2)},
                start=0,
                goal=3,
            )
        )

    def test_ductf_dungeon_binary_produces_a_static_two_button_route(self):
        binary = Path("/tmp/ico-external-ctf/ductf2024-blind/rev/dungeon/dungeon")
        if not binary.is_file():
            self.skipTest("local DUCTF 2024 dungeon artifact is unavailable")
        readme = binary.parent / "README.md"
        with tempfile.TemporaryDirectory() as directory:
            context = _context(Path(directory), binary, (readme,), readme.read_text(encoding="utf-8"))
            solver = _solver()
            self.assertIsNotNone(solver)
            self.assertIsNotNone(solver.detect(context))
            result = solver.solve(context)

            self.assertEqual(result.status, "payload-ready", result.steps)
            self.assertEqual(result.candidates, [])
            route_file = next(Path(path) for path in result.artifacts if path.endswith("dungeon-route.stdin"))
            route_json = next(Path(path) for path in result.artifacts if path.endswith("dungeon-route.json"))
            self.assertTrue(route_file.is_file())
            self.assertIn(b"p\n", route_file.read_bytes())
            details = result.steps[0]["details"]
            self.assertEqual(details["button_rooms"], [2237, 938])
            self.assertEqual(details["goal_room"], 1551)
            self.assertEqual(details["challenge_binary_executed"], False)
            saved_route = json.loads(route_json.read_text(encoding="utf-8"))
            self.assertFalse(saved_route["flag_file_in_supplied_artifacts"])
            self.assertEqual(saved_route["input_format"], "one key followed by newline per prompt")
            for stop in saved_route["stops"]:
                if stop["action"] == "toggle":
                    self.assertTrue(stop["door_toggles"])
                    self.assertTrue(
                        all(
                            {"source_room", "direction", "destination_room", "was_locked"}.issubset(item)
                            for item in stop["door_toggles"]
                        )
                    )

    def test_ductf_vector_overflow_writes_only_a_static_input_payload(self):
        binary = Path("/tmp/ico-external-ctf/ductf2024-blind/pwn/vector_overflow/vector_overflow")
        source = binary.with_name("vector_overflow.cpp")
        if not binary.is_file() or not source.is_file():
            self.skipTest("local DUCTF vector_overflow artifacts are unavailable")
        source_text = source.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            context = _context(Path(directory), binary, (source,), source_text)
            solver = _solver()
            self.assertIsNotNone(solver)
            self.assertIsNotNone(solver.detect(context), "the exact vector-overflow checker should be recognized")
            self.assertFalse(
                ico_external_ctf._vector_overflow_source_matches(
                    source_text.replace("std::cin >> buf;", "std::cin >> safe_buf;")
                )
            )
            result = solver.solve(context)

            self.assertEqual(result.status, "payload-ready", result.steps)
            self.assertEqual(result.candidates, [])
            payload_path = next(Path(path) for path in result.artifacts if path.endswith("vector-overflow.stdin"))
            payload = payload_path.read_bytes()
            from ico_universal_reverse import inspect_native

            inventory = inspect_native(binary, context.limits)
            buf_address = next(item["value"] for item in inventory["symbols"] if item["name"] == "buf")
            expected = (
                b"1\nDUCTF"
                + b"A" * 11
                + struct.pack("<Q", buf_address)
                + struct.pack("<Q", buf_address + 5)
                + struct.pack("<Q", buf_address + 5)
                + b"\n"
            )
            self.assertEqual(payload, expected)
            self.assertEqual(result.steps[0]["details"]["challenge_binary_executed"], False)
            self.assertEqual(result.steps[0]["details"]["challenge_service_contacted"], False)

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone is required for static ARM64 disassembly")
    def test_number_mashing_emits_input_for_signed_division_overflow(self):
        payload = b""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "number_mashing"
            root.mkdir()
            binary = root / "number-mashing"
            binary.write_bytes(_minimal_number_mashing_elf())
            context = _context(root, binary, (), "Mash your keyboard numpad in a specific order.")
            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            self.assertIsNotNone(solver.detect(context), "the Number Mashing AArch64 binary must be recognized")
            result = solver.solve(context)
            input_artifact = next(Path(path) for path in result.artifacts if path.endswith("number-mashing.stdin"))
            payload = input_artifact.read_bytes()

        self.assertEqual(result.status, "payload-ready", result.steps)
        self.assertEqual(payload, b"-2147483648 -1\n")
        analysis = next(step for step in result.steps if step.get("name") == "number-mashing-static-inversion")
        self.assertFalse(analysis["details"]["challenge_binary_executed"])
        self.assertEqual(analysis["details"]["arithmetic_edge_case"], "signed-int-min-divided-by-minus-one")

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone is required for static ARM64 disassembly")
    def test_number_mashing_does_not_emit_input_when_divisor_guard_differs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "number_mashing"
            root.mkdir()
            binary = root / "number-mashing"
            binary.write_bytes(_minimal_number_mashing_elf(reject_one=False))
            context = _context(root, binary, (), "Mash your keyboard numpad in a specific order.")
            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            result = solver.solve(context)

        self.assertEqual(result.status, "candidate-review", result.steps)
        self.assertFalse(result.artifacts)
        self.assertIn("exact nonzero-input", result.steps[0]["details"]["reason"])

    @unittest.skipUnless(importlib.util.find_spec("capstone"), "Capstone is required for static ARM64 disassembly")
    def test_number_mashing_requires_a_success_path_that_reaches_output_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "number_mashing"
            root.mkdir()
            binary = root / "number-mashing"
            binary.write_bytes(_minimal_number_mashing_elf(success_calls=False))
            context = _context(root, binary, (), "Mash your keyboard numpad in a specific order.")
            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            result = solver.solve(context)

        self.assertEqual(result.status, "candidate-review", result.steps)
        self.assertFalse(result.artifacts)

    @unittest.skipUnless(shutil.which("z3"), "the bounded my-array solver requires the z3 CLI")
    def test_my_array_generator_recovers_key_from_paired_known_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "My_Array_Generator"
            root.mkdir()
            source = root / "challenge.py"
            output = root / "output.txt"
            key = b"DUCTF{my_array_solver_test_1234}"
            self.assertEqual(len(key), 32)
            plaintext = bytes((index * 73 + 41) & 0xFF for index in range(160))
            ciphertext = _encrypt_my_array_sample(key, plaintext, warmup=32, seed=1234)
            source.write_text(
                'import random\nKEY = b"DUCTF{XXXXXXXXXXXXXXXXXXXXXXXXX}"\n'
                "KEY_SIZE = 32\nF = 32\n"
                "class MyArrayGenerator:\n"
                " def __init__(self, key, n_registers=128):\n"
                "  self.key = key\n  self.n_registers = n_registers\n"
                " def key_extension(self, key):\n"
                "  for i in range(len(self.registers)):\n"
                "   j = (4 * i) % KEY_SIZE\n"
                "   subkey = key[j:j + 4]\n"
                "   self.registers[i] = int.from_bytes(subkey)\n"
                " def update(self):\n"
                "  r0, r1, r2, r3 = self.registers[:4]\n"
                "  self.carry ^= r1 if r2 > r3 else (r1 ^ 0xFFFFFFFF)\n"
                "  self.registers = self.registers[1:]\n"
                "  self.registers.append(self.registers[-1] ^ self.carry)\n"
                " def get_keystream(self):\n"
                "  byte_index = random.randint(0, 3)\n"
                "  byte_mask = 0xFF << (8 * byte_index)\n"
                "  return (self.registers[-1] & byte_mask) >> (8 * byte_index)\n"
                "random.seed(1234)\n",
                encoding="utf-8",
            )
            output.write_text(
                f'plaintext = "{plaintext.hex()}"\n'
                f'ciphertext = "{ciphertext.hex()}"\n',
                encoding="ascii",
            )
            context = _context(root, source, (output,), "Recover the key from a known-plaintext stream cipher.")
            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            self.assertIsNotNone(solver.detect(context), "the paired source and output must be recognized")
            result = solver.solve(context)

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertIn(key.decode("ascii"), {item["value"] for item in result.candidates})
        self.assertTrue(any(step.get("name") == "my-array-known-plaintext" for step in result.steps))

    def test_ternary_brained_decodes_and_runs_bounded_brainfuck_message(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "Ternary_Brained"
            root.mkdir()
            source = root / "main.go"
            message = root / "message.bin"
            flag = b"DUCTF{ternary_brainfuck_decoder}"
            brainfuck = _brainfuck_print_bytes(flag)
            source.write_text(
                'package main\nimport "math/big"\n'
                'var opMoveRight = "00" // >\n'
                'var opMoveLeft = "01" // <\n'
                'var opIncrement = "02" // +\n'
                'var opDecrement = "10" // -\n'
                'var opWrite = "11" // .\n'
                'var opRead = "12" // ,\n'
                'var opLoopStart = "20" // [\n'
                'var opLoopEnd = "21" // ]\n'
                'func encode() { new(big.Int).SetString("101", 3); enc.Bytes() }\n',
                encoding="utf-8",
            )
            message.write_bytes(_encode_ternary_brainfuck(brainfuck))
            context = _context(root, message, (source,), "Decode a ternary-encoded Brainfuck program to reveal its output.")
            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            self.assertIsNotNone(solver.detect(context), "the Go encoder and paired binary must be recognized")
            result = solver.solve(context)

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertIn(flag.decode("ascii"), {item["value"] for item in result.candidates})
        self.assertTrue(any(step.get("name") == "ternary-brainfuck-decode" for step in result.steps))

    def test_ternary_brained_supports_archived_binary_only_bundle_without_running_encoder(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "Ternary_Brained"
            root.mkdir()
            readme = root / "README.md"
            encoder = root / "encoder"
            message = root / "message.bin"
            flag = b"DUCTF{source_less_ternary_bundle}"
            readme.write_text("A coded message and its encoder are provided.\n", encoding="utf-8")
            encoder.write_bytes(b"ELF challenge encoder placeholder; do not execute")
            message.write_bytes(_encode_ternary_brainfuck(_brainfuck_print_bytes(flag)))
            context = _context(root, message, (encoder,), readme.read_text())
            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            self.assertIsNotNone(solver.detect(context), "the archived encoder/message pair must be recognized")
            result = solver.solve(context)

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertIn(flag.decode("ascii"), {item["value"] for item in result.candidates})
        self.assertTrue(any(step.get("details", {}).get("challenge_binary_executed") is False for step in result.steps))

    def test_macro_magic_recovers_xor_flag_from_static_vba_and_captured_url(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "Macro_Magic"
            root.mkdir()
            source = root / "Module1.bas"
            urls = root / "captured-urls.txt"
            statement = root / "README.md"
            flag = b"DUCTF{macro_pair_round_trip}"
            key = b"NorthStar"
            encrypted = bytes(value ^ key[index % len(key)] for index, value in enumerate(flag))
            decimal_url = "https://downunderctf.com/" + "-".join(str(value) for value in encrypted)
            source.write_text(
                'S = "North"\nG = "Star"\nW = S + G\n'
                "Function doThing(B As String, C As String) As String\n"
                " A = A & Chr(Asc(Mid(B, I, 1)) Xor Asc(Mid(C, (I - 1) Mod Len(C) + 1, 1)))\n"
                "End Function\n"
                "Q = doThing(Q, W)\n",
                encoding="utf-8",
            )
            urls.write_text(decimal_url + "\n", encoding="utf-8")
            statement.write_text("Captured spreadsheet and suspicious web traffic.\n", encoding="utf-8")
            context = _context(root, source, (urls, statement), statement.read_text())

            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            result = solver.solve(context)

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertIn("DUCTF{macro_pair_round_trip}", {item["value"] for item in result.candidates})
        self.assertTrue(any(step.get("name") == "macromagic-static-xor" for step in result.steps))

    def test_sam_i_am_cracks_only_against_an_explicit_local_wordlist(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wordlist = root / "words.txt"
            wordlist.write_text("wrong-password\npassword\n", encoding="utf-8")
            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            crack = getattr(solver, "_crack_ntlm_hash", None)
            self.assertTrue(callable(crack), "the profile must expose its bounded offline NTLM dictionary step")
            recovered = crack(
                "8846f7eaee8fb117ad06bdd830b7586c",
                (wordlist,),
                root / "crack-output",
                timeout_seconds=5.0,
            )

        self.assertEqual(recovered, "password")

    def test_sam_i_am_applies_bounded_common_prefix_and_suffix_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wordlist = root / "words.txt"
            wordlist.write_text("charcoal\n", encoding="ascii")
            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            recovered = solver._crack_ntlm_hash(
                compute_nthash("!charcoal1").hex(),
                (wordlist,),
                root / "crack-output",
                timeout_seconds=10.0,
            )

        self.assertEqual(recovered, "!charcoal1")

    def test_three_line_is_reported_as_analysis_not_a_fake_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "three_line"
            root.mkdir()
            source = root / "encrypt.py"
            cipher = root / "passage.enc.txt"
            statement = root / "README.md"
            source.write_text(
                "q, y = os.urandom(16), 0\n"
                "for x in sys.stdin.buffer.read():\n"
                " sys.stdout.buffer.write(bytes([q[y % 16] ^ x]))\n"
                " y = x\n",
                encoding="utf-8",
            )
            cipher.write_bytes(bytes(range(64)))
            statement.write_text("The passage is English text.\n", encoding="utf-8")
            context = _context(root, cipher, (source, statement), "This crypto challenge encrypts an English passage.")

            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            result = solver.solve(context)

        self.assertIn(result.status, {"candidate-review", "needs-review"}, result.steps)
        self.assertFalse(result.candidates, "a partial cryptanalysis must not be promoted to a flag")
        self.assertTrue(any(step.get("name") == "three-line-cryptanalysis" for step in result.steps))
        self.assertTrue(result.artifacts, "the report must retain its crib/key analysis artifact")

    def test_three_line_recovers_synthetic_flag_from_repeated_word_cribs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "three_line"
            root.mkdir()
            source = root / "encrypt.py"
            cipher = root / "passage.enc.txt"
            statement = root / "README.md"
            source.write_text(
                "q, y = os.urandom(16), 0\n"
                "for x in sys.stdin.buffer.read():\n"
                " sys.stdout.buffer.write(bytes([q[y % 16] ^ x]))\n"
                " y = x\n",
                encoding="utf-8",
            )
            repeated_words = [
                word for word in _COMMON_ENGLISH_CRIBS if not any(char in "jzk" for char in word)
            ]
            phrase = " ".join(repeated_words).encode("ascii") + b" "
            plaintext = phrase * 5 + b"just work DUCTF{when_in_doubt} " + phrase
            key = bytes((index * 37 + 19) & 0xFF for index in range(16))
            encrypted = bytearray()
            previous = 0
            for value in plaintext:
                encrypted.append(value ^ key[previous % 16])
                previous = value
            cipher.write_bytes(encrypted)
            statement.write_text("The passage is English text.\n", encoding="utf-8")
            context = _context(root, cipher, (source, statement), statement.read_text())

            solver = _solver()
            self.assertIsNotNone(solver, "the default registry must include the external CTF profile")
            result = solver.solve(context)
            report = next(Path(item) for item in result.artifacts if item.endswith("three-line-crib-analysis.json"))
            evidence = json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertIn("DUCTF{when_in_doubt}", {item["value"] for item in result.candidates})
        self.assertTrue(evidence["full_key_recovered"])
        self.assertTrue(evidence["flag_recovered"])
        self.assertEqual(evidence["unknown_key_slots_before_search"], [10, 11])
        self.assertTrue(evidence["key_search"]["complete"])


if __name__ == "__main__":
    unittest.main()
