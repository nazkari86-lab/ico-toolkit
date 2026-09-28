from __future__ import annotations

import base64
import gzip
import tempfile
import unittest
import zipfile
import struct
from pathlib import Path

from ico_prompt_solvers import solve_prompt_task


def _values(result):
    return [str(item["value"]) for item in result.candidates]


def _vigenere_encrypt_base64(token: str, key: str) -> str:
    output: list[str] = []
    index = 0
    for char in token:
        if char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(key[index % len(key)].upper()) - ord("A")
            output.append(chr((ord(char) - base + shift) % 26 + base))
            index += 1
        else:
            output.append(char)
    return "".join(output)


class PromptSolverTests(unittest.TestCase):
    def test_multiple_choice_and_plain_answer_are_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = solve_prompt_task(
                "External ICO 2025 final task 1. ECB question. Choose: 1, 2, 3, 4.",
                root,
                (),
                root / "report",
            )
        self.assertEqual(_values(result), ["3"])
        self.assertEqual(result.candidates[0]["state"], "candidate")

    def test_caesar_key_uses_modulo_26(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            text = (
                "External ICO 2025 final task 7. Shift cipher. "
                "input string abc and key value 999."
            )
            result = solve_prompt_task(text, root, (), root / "report")
        self.assertEqual(_values(result), ["lmn"])

    def test_ecb_and_ctr_options_are_derived_from_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ecb = solve_prompt_task(
                """External ICO 2025 final task 1.
                ciphertext was ```10101010 00001010 01011011```
                - **P1:** `11111111 00000000 11111111`
                - **P2:** `00000000 00000000 00000000`
                - **P3:** `11111111 00000000 10101010`
                1. ○ Must be P1
                2. ○ Must be P2
                3. ○ Must be P3
                4. ○ Could be P1 or P3, but not P2
                """,
                root,
                (),
                root / "report",
            )
            ctr = solve_prompt_task(
                """External ICO 2025 final task 2.
                C1 = 00000000 11111111 00000000
                C2 = 00000000 00001111 00001111
                - **P1:** `11111010 00001111`
                - **P2:** `00001010 00000000`
                - **P3:** `11111111 00001010`
                1. ○ Both were P1.
                2. ○ Both were P2.
                3. ○ One of them was P1, and the other was P2.
                4. ○ One of them was P2, and the other was P3.
                """,
                root,
                (),
                root / "report",
            )
        self.assertEqual(_values(ecb), ["3"])
        self.assertEqual(ecb.steps[0]["details"]["matching_plaintext"], "P3")
        self.assertEqual(_values(ctr), ["3"])
        self.assertEqual(ctr.steps[0]["details"]["matching_pair"], (1, 2))

    def test_buffer_and_cidr_answers_are_derived_from_capacity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            buffer_result = solve_prompt_task(
                """External ICO 2025 final task 8.
                char buffer[10]; gets(buffer);
                - ○ `1234`
                - ○ `"teststring"`
                - ○ `@$%^&*()`
                - ○ None of the above answer can cause the error.
                """,
                root,
                (),
                root / "report",
            )
            cidr_result = solve_prompt_task(
                """External ICO 2025 final task 13.
                The operations department utilizes 10 workstations. There are plans to double the number.
                """,
                root,
                (),
                root / "report",
            )
        self.assertEqual(_values(buffer_result), ["2"])
        self.assertEqual(_values(cidr_result), ["{27}"])

    def test_network_answers_keep_the_submission_braces_required_by_each_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nat = solve_prompt_task(
                "External ICO 2025 final task 9. Use 192.168.x.x private address space. "
                "Submit your flag in the format of: {XXX}. Enter the acronym in all CAPS.",
                root,
                (),
                root / "report",
            )
            osi = solve_prompt_task(
                "External ICO 2025 final task 11. At which OSI layer does the router operate? "
                "Submit your flag in the format of {xxx}, where xxx is a number.",
                root,
                (),
                root / "report",
            )

        self.assertEqual(_values(nat), ["{NAT}"])
        self.assertEqual(_values(osi), ["{3}"])

    def test_vigenere_then_base64_decodes_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plaintext = b"Hide and seek: CTF{vigenere_fixture}"
            encoded = base64.b64encode(plaintext).decode("ascii")
            encrypted = _vigenere_encrypt_base64(encoded, "INTERNATIONAL")
            text = (
                "External ICO 2025 final task 3. Use keyword INTERNATIONAL; "
                "binary and 64.\n" + encrypted
            )
            result = solve_prompt_task(text, root, (), root / "report")
        self.assertEqual(_values(result), ["CTF{vigenere_fixture}"])

    def test_q17_swaps_decoded_half_blocks_without_inventing_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = b"{left_half_flag}{right_half____}"
            swapped = original[16:] + original[:16]
            compressed = gzip.compress(base64.b64encode(swapped) + b"randomnoise")
            archive = root / "q17.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("output.txt", compressed)
            result = solve_prompt_task(
                "External ICO 2025 final task 17. Decode This two files.",
                root,
                (archive,),
                root / "report",
            )
        self.assertEqual(_values(result), [original.decode("ascii")])
        self.assertTrue(result.candidates[0]["evidence"])

    def test_q10_extracts_zip_appended_after_png_iend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            png = root / "task.png"
            # Minimal structurally valid PNG: signature, IHDR, IEND.  The
            # solver only needs the chunk boundary and never decodes pixels.
            signature = b"\x89PNG\r\n\x1a\n"
            ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
            ihdr = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + struct.pack(">I", 0)
            iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", 0)
            with tempfile.TemporaryDirectory() as archive_dir:
                archive_path = Path(archive_dir) / "payload.zip"
                with zipfile.ZipFile(archive_path, "w") as handle:
                    handle.writestr("flag.txt", "ico{png_tail_fixture}\n")
                png.write_bytes(signature + ihdr + iend + archive_path.read_bytes())
            result = solve_prompt_task(
                "External ICO 2025 final task 10. Steganography Challenge.",
                root,
                (png,),
                root / "report",
            )
        self.assertEqual(_values(result), ["ico{png_tail_fixture}"])
        self.assertEqual(result.candidates[0]["method"], "png-iend-appended-zip")


if __name__ == "__main__":
    unittest.main()
