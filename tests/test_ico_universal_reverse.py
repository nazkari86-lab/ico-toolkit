from __future__ import annotations

import os
import tempfile
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from ico_solver_engine import SolverContext, SolverLimits
from ico_universal_reverse import ReverseSolver, build_static_pwn_report, inspect_native, recover_power_equality_checker, recover_static_checker


LIMITS = SolverLimits(max_bytes=4 * 1024 * 1024, max_files=100, max_depth=2, timeout_seconds=1.0)


def _minimal_elf(body: bytes) -> bytes:
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        ident,
        2,
        62,
        1,
        0x401000,
        0,
        0,
        0,
        64,
        56,
        0,
        64,
        0,
        0,
    )
    return header + body


def _minimal_macho64(*, cpu_type: int, flags: int) -> bytes:
    return struct.pack(
        "<IiiIIIII",
        0xFEEDFACF,
        cpu_type,
        0,
        2,
        0,
        0,
        flags,
        0,
    )


class UniversalReverseTests(unittest.TestCase):
    def test_power_equality_checker_recovers_contiguous_bytes_and_rejects_bad_power(self):
        flag = b"ico{power_checks}"
        clauses = " and ".join(
            f"inp.__getitem__({index ^ 739}^739).__pow__(3).__eq__({value**3})"
            for index, value in enumerate(flag)
        )
        recovered = recover_power_equality_checker(f"if {clauses}: pass")
        self.assertEqual(recovered["status"], "verified")
        self.assertEqual(recovered["plaintext"], flag)
        self.assertEqual(recover_power_equality_checker(clauses.replace(str(flag[0] ** 3), str(flag[0] ** 3 + 1), 1))["status"], "inconsistent")

    def test_reverse_solver_does_not_route_c_or_shell_sources_to_native_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_contexts = []
            for name in ("challenge.c", "run.sh"):
                source = root / name
                source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
                source_contexts.append(
                    SolverContext(
                        input_path=source,
                        report_dir=root / "report",
                        limits=LIMITS,
                        task_text="Pwn challenge",
                        classification={"kind": "binary" if name.endswith(".sh") else "text"},
                    )
                )

            detections = [ReverseSolver().detect(context) for context in source_contexts]

        self.assertEqual(detections, [None, None])

    def test_macho_inventory_reports_cpu_type_and_pie_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "arm64-pie"
            source.write_bytes(_minimal_macho64(cpu_type=0x0100000C, flags=0x00200000))

            inventory = inspect_native(source, LIMITS)

        self.assertEqual(inventory["machine"], "aarch64")
        self.assertEqual(inventory["machine_id"], 0x0100000C)
        self.assertTrue(inventory["protections"]["pie"])

    def test_reverse_solver_extracts_a_flag_from_reversed_python_literal_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "desrever.py"
            code = 'print("ICO{reverse_literal_fixture}")'
            source.write_text(f"exec({code[::-1]!r}[::-1])\n", encoding="utf-8")
            context = SolverContext(
                input_path=source,
                report_dir=root / "report",
                limits=LIMITS,
                task_text="Reversing challenge",
                classification={"kind": "binary"},
            )
            result = ReverseSolver().solve(context)

        self.assertIn("ICO{reverse_literal_fixture}", {item["value"] for item in result.candidates})
        transform = next(step for step in result.steps if step["name"] == "static-source-transforms")
        self.assertFalse(transform["details"]["executed"])

    def test_reverse_solver_surfaces_embedded_flag_strings_as_unverified_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "hidden.elf"
            embedded = "jctf{n0t_the_real_flag?_or_is_it?}"
            source.write_bytes(_minimal_elf(embedded.encode() + b"\x00"))
            context = SolverContext(
                input_path=source,
                report_dir=root / "report",
                limits=LIMITS,
                task_text="Reverse engineering",
                classification={"kind": "binary"},
            )

            result = ReverseSolver().solve(context)

        self.assertIn(embedded, {item["value"] for item in result.candidates})
        raw_strings = next(step for step in result.steps if step["name"] == "embedded-flag-strings")
        self.assertEqual(raw_strings["status"], "candidate-review")
        self.assertFalse(raw_strings["details"]["executed"])

    def test_hidden_decoy_literal_is_downgraded_when_plt_shellcode_preempts_main(self):
        source = Path("/tmp/ico-external-ctf/imaginary-blind/Reversing_hidden/hidden")
        if not source.is_file():
            self.skipTest("external static ELF fixture is unavailable")
        expected = "jctf{n0t_the_real_flag?_or_is_it?}"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = SolverContext(
                input_path=source,
                report_dir=root / "report",
                limits=LIMITS,
                task_text="How well did I hide my code?",
                classification={"kind": "binary"},
            )

            result = ReverseSolver().solve(context)

        candidate = next(item for item in result.candidates if item["value"] == expected)
        self.assertEqual(candidate["triage"], "likely-placeholder")
        self.assertEqual(candidate["verification"], "static-branch-preempted-by-plt-shellcode")
        self.assertFalse(candidate["executed"])

    def test_hidden_shellcode_input_is_inverted_without_running_the_elf(self):
        source = Path("/tmp/ico-external-ctf/imaginary-blind/Reversing_hidden/hidden")
        if not source.is_file():
            self.skipTest("external static ELF fixture is unavailable")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = SolverContext(
                input_path=source,
                report_dir=root / "report",
                limits=LIMITS,
                task_text="How well did I hide my code?",
                classification={"kind": "binary"},
            )
            result = ReverseSolver().solve(context)

            expected = "ictf{h1ddenc0de_1a29d3}"
            candidate = next(item for item in result.candidates if item["value"] == expected)
            self.assertEqual(candidate["verification"], "static-shellcode-inversion")
            self.assertFalse(candidate["executed"])
            inversion = next(step for step in result.steps if step["name"] == "hidden-shellcode-inversion")
            self.assertEqual(inversion["status"], "candidate")
            self.assertFalse(inversion["details"]["executed"])
            accepted_input = Path(inversion["details"]["input_artifact"])
            self.assertEqual(accepted_input.read_bytes(), expected.encode() + b"\n")

    def test_hidden_flag_literal_is_not_upgraded_when_equality_routes_to_the_failure_branch(self):
        source = Path("/tmp/ico-external-ctf/imaginary-blind/Reversing_hidden/hidden")
        if not source.is_file():
            self.skipTest("external static ELF fixture is unavailable")
        expected = "jctf{n0t_the_real_flag?_or_is_it?}"
        original = source.read_bytes()
        original_branch = b"\x85\xc0\x75\x16"
        self.assertEqual(original.count(original_branch), 1, "fixture branch encoding changed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inverted = root / "inverted-branch.elf"
            inverted.write_bytes(original.replace(original_branch, b"\x85\xc0\x74\x16", 1))
            context = SolverContext(
                input_path=inverted,
                report_dir=root / "report",
                limits=LIMITS,
                task_text="How well did I hide my code?",
                classification={"kind": "binary"},
            )

            result = ReverseSolver().solve(context)

        candidate = next(item for item in result.candidates if item["value"] == expected)
        self.assertEqual(candidate["triage"], "likely-placeholder")
        self.assertEqual(candidate.get("verification"), "embedded-string-only")
        acceptance = next(step for step in result.steps if step["name"] == "static-input-acceptance")
        self.assertEqual(acceptance["details"]["accepted_literals"], [])

    def test_static_checker_recovers_declared_xor_crib_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = b"CTF{static_checker_fixture}"
            source = root / "checker.bin"
            source.write_bytes(b"prefix" + bytes(value ^ 0x55 for value in flag))
            result = recover_static_checker(source, LIMITS)
        self.assertEqual(result.status, "candidate")
        self.assertEqual(result.candidates[0]["value"], flag.decode())
        self.assertTrue(all(step.get("details", {}).get("executed") is False for step in result.steps))

    def test_static_checker_keeps_ductf_prefix_instead_of_matching_inner_ctf(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "config.py"
            source.write_text('FLAG = "DUCTF{test_flag_real_flag_on_instance}"\n', encoding="utf-8")
            result = recover_static_checker(source, LIMITS)

        values = {item["value"] for item in result.candidates}
        self.assertEqual(values, {"DUCTF{test_flag_real_flag_on_instance}"})
        self.assertEqual(result.candidates[0]["triage"], "likely-placeholder")

    def test_native_inventory_is_static(self):
        source = Path(os.environ.get("ICO_CTF_REAL_ROOT", str(Path.home() / "Downloads" / "ico_ctf_real"))) / "06_reverse_elf" / "chall"
        if not source.is_file():
            self.skipTest("local ELF fixture is unavailable")
        inventory = inspect_native(source, LIMITS)
        self.assertEqual(inventory["format"], "ELF")
        self.assertFalse(inventory["executed"])
        self.assertIn("protections", inventory)

    def test_fgets_symbol_does_not_create_a_false_gets_overflow_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "bounded.elf"
            source.write_bytes(_minimal_elf(b"fgets\x00"))
            inventory = inspect_native(source, LIMITS)
            report = build_static_pwn_report(source, LIMITS)

        self.assertIn("fgets", inventory["imports"])
        self.assertNotIn("gets", inventory["imports"])
        self.assertEqual(report.status, "unsupported")

    def test_benign_elf_without_pwn_markers_stays_unsupported(self):
        source = Path(os.environ.get("ICO_CTF_REAL_ROOT", str(Path.home() / "Downloads" / "ico_ctf_real"))) / "06_reverse_elf" / "chall"
        if not source.is_file():
            self.skipTest("local ELF fixture is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            result = build_static_pwn_report(source, LIMITS, report_dir=Path(directory))
        self.assertEqual(result.status, "unsupported")
        self.assertFalse(result.artifacts)
        self.assertTrue(all(step.get("details", {}).get("executed") is False for step in result.steps))

    def test_vulnerability_hints_without_exploit_parameters_require_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "hint-only.elf"
            source.write_bytes(_minimal_elf(b"printf(%n)\x00gets\x00"))
            result = build_static_pwn_report(source, LIMITS, report_dir=root / "report")
            report_file = next(Path(item) for item in result.artifacts if item.endswith(".report.txt"))
            report_text = report_file.read_text(encoding="utf-8")

        self.assertEqual(result.status, "candidate-review")
        construction = next(step for step in result.steps if step["name"] == "payload-construction")
        self.assertIsNone(construction["details"].get("payload"))
        self.assertIn("format_probe", construction["details"])
        self.assertIn("review_reasons=", report_text)
        self.assertIn("format-string output is only a diagnostic probe", report_text)
        self.assertTrue(all(step.get("details", {}).get("executed") is False for step in result.steps))

    def test_known_format_string_challenge_writes_loader_offset(self):
        challenge_dir = Path("/tmp/ico-external-ctf/imaginary-blind/Pwn_fmt_fun/challenge")
        source = challenge_dir / "fmt_fun"
        libc = challenge_dir / "libc.so.6"
        if not source.is_file() or not libc.is_file():
            self.skipTest("exact ImaginaryCTF 2022 format-string artifacts are unavailable")

        with tempfile.TemporaryDirectory() as directory:
            result = build_static_pwn_report(
                source,
                LIMITS,
                report_dir=Path(directory) / "report",
                task_text="Title: Format String Fun\nCategory: Pwn\n",
                related_paths=(libc,),
            )
            self.assertEqual(result.status, "payload-ready")
            construction = next(step for step in result.steps if step["name"] == "payload-construction")
            payload = Path(construction["details"]["payload"]).read_bytes()

        self.assertEqual(payload[:10], b"%680c%26$n")
        self.assertEqual(payload[10:32], b"a" * 22)
        self.assertEqual(payload[32:], struct.pack("<Q", 0x401251))
        self.assertEqual(len(payload), 40)
        self.assertEqual(result.candidates, [])
        self.assertFalse(construction["details"]["executed"])
        self.assertFalse(construction["details"]["flag_retrieved"])

    def test_shared_library_imports_do_not_create_executable_pwn_review(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "libc.so.6"
            source.write_bytes(_minimal_elf(b"printf(%n)\x00gets\x00system\x00"))

            result = build_static_pwn_report(source, LIMITS, report_dir=Path(directory) / "report")

        self.assertEqual(result.status, "unsupported")
        self.assertFalse(result.artifacts)
        self.assertEqual(result.steps[0]["name"], "shared-library-no-pwn-entrypoint")

    def test_window_string_does_not_create_a_ret2win_review(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "frontend.elf"
            source.write_bytes(_minimal_elf(b"window title\x00"))

            result = build_static_pwn_report(source, LIMITS, report_dir=Path(directory) / "report")

        self.assertEqual(result.status, "unsupported")
        self.assertFalse(result.artifacts)

    def test_reverse_solver_propagates_review_when_no_payload_was_constructed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "hint-only.elf"
            source.write_bytes(_minimal_elf(b"printf(%n)\x00gets\x00"))
            context = SolverContext(
                input_path=source,
                report_dir=root / "report",
                limits=LIMITS,
                classification={"kind": "binary"},
            )
            result = ReverseSolver().solve(context)

        self.assertEqual(result.status, "candidate-review")
        self.assertTrue(any(step["name"] == "vulnerability-hints" for step in result.steps))

    def test_reverse_solver_uses_explicit_task_text_to_construct_ret2win_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "task.elf"
            source.write_bytes(_minimal_elf(b"gets\x00"))
            context = SolverContext(
                input_path=source,
                report_dir=root / "report",
                limits=LIMITS,
                task_text="Ret2win challenge; offset=72 target=0x401136.",
                classification={"kind": "binary"},
            )
            result = ReverseSolver().solve(context)
            construction = next(step for step in result.steps if step["name"] == "payload-construction")
            payload = Path(construction["details"]["payload"]).read_bytes()

        self.assertEqual(result.status, "payload-ready")
        self.assertEqual(payload, b"A" * 72 + struct.pack("<Q", 0x401136))

    def test_reverse_solver_derives_ret2win_payload_from_adjacent_source_and_static_symbol(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "vuln"
            source = root / "vuln.c"
            binary.write_bytes(_minimal_elf(b"gets\x00"))
            source.write_text(
                "char **return_address;\n"
                "int win(void) { return 0; }\n"
                "int main(void) { char buf[16]; return_address = buf + 24; gets(buf); }\n",
                encoding="utf-8",
            )
            inventory = {
                "format": "ELF",
                "bits": 64,
                "machine": "x86_64",
                "protections": {"pie": False, "canary": False},
                "imports": ["gets"],
                "symbols": [{"name": "win", "value": 0x401136}],
                "strings": ["gets", "win"],
            }
            context = SolverContext(
                input_path=binary,
                report_dir=root / "report",
                limits=LIMITS,
                related_paths=(source,),
                task_text="Can you overwrite the return address?",
                classification={"kind": "binary"},
            )
            with patch("ico_universal_reverse.inspect_native", return_value=inventory):
                result = ReverseSolver().solve(context)
            self.assertEqual(result.status, "payload-ready")
            construction = next(step for step in result.steps if step["name"] == "payload-construction")
            payload = Path(construction["details"]["payload"]).read_bytes()

        self.assertEqual(payload, b"A" * 24 + struct.pack("<Q", 0x401136))
        self.assertEqual(construction["details"]["offset_source"], "adjacent-source")
        self.assertEqual(construction["details"]["target_source"], "static-symbol")

    def test_static_pwn_derives_bounded_sprintf_overflow_from_adjacent_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "bof"
            source = root / "bof.c"
            binary.write_bytes(_minimal_elf(b"fgets\x00sprintf\x00system\x00"))
            source.write_text(
                "struct string { char buf[64]; int check; };\n"
                "char temp[1337];\n"
                "int main(void) { struct string str; str.check=0xdeadbeef; "
                "fgets(temp,5,stdin); sprintf(str.buf,temp); "
                "if (str.check != 0xdeadbeef) system(\"cat flag.txt\"); }\n",
                encoding="utf-8",
            )
            inventory = {
                "format": "ELF",
                "bits": 64,
                "machine": "x86_64",
                "protections": {"pie": True, "canary": True},
                "imports": ["fgets", "sprintf", "system"],
                "symbols": [],
                "strings": ["fgets", "sprintf", "system", "cat flag.txt"],
            }
            context = SolverContext(
                input_path=binary,
                report_dir=root / "report",
                limits=LIMITS,
                related_paths=(source,),
                task_text="Can you bof me?",
                classification={"kind": "binary"},
            )
            with patch("ico_universal_reverse.inspect_native", return_value=inventory):
                result = ReverseSolver().solve(context)
            self.assertEqual(result.status, "payload-ready")
            construction = next(step for step in result.steps if step["name"] == "payload-construction")
            payload = Path(construction["details"]["payload"]).read_bytes()

        self.assertEqual(payload, b"%70c")
        self.assertEqual(construction["details"]["strategy"], "bounded-format-string-overflow")
        self.assertEqual(construction["details"]["output_width"], 70)


if __name__ == "__main__":
    unittest.main()
