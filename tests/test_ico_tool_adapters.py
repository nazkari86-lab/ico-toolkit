from __future__ import annotations

import base64
import gzip
import io
import tempfile
import unittest
import shutil
import os
import sys
import time
import subprocess
import urllib.parse
import zipfile
from unittest.mock import patch
from pathlib import Path

from ico_scan_core import Classification, CommandRunner, classify
from ico_tool_adapters import (
    AdapterProfile,
    TOOL_SPECS,
    available_tool_specs,
    cyberchef_asset,
    profiles_for_classification,
    run_adapter_profiles,
    run_cyberchef_adapter,
    tool_inventory,
)
from ico_platform_tools import platform_tool_status


def _base58_encode_for_test(data: bytes) -> bytes:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value = int.from_bytes(data, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = alphabet[remainder] + encoded
    padding = len(data) - len(data.lstrip(b"\0"))
    return ("1" * padding + encoded).encode("ascii")


class ToolAdapterTests(unittest.TestCase):
    def test_inventory_contains_the_extended_toolchain(self):
        names = {spec.name for spec in TOOL_SPECS}
        self.assertGreaterEqual(len(names), 55)
        for expected in {"cyberchef", "binwalk", "zsteg", "tshark", "radare2", "pwntools", "RsaCtfTool", "volatility"}:
            self.assertIn(expected, names)
        for expected in {"checksec", "ROPgadget", "ropper", "olevba", "apktool", "jadx", "angr", "fls", "semgrep", "xortool", "jwt_tool", "peepdf", "hashpumpy", "seccomp-tools", "AFL++", "arjun", "nuclei", "SageMath"}:
            self.assertIn(expected, names)

    def test_high_value_file_tools_from_the_plan_are_registered(self):
        names = {spec.name for spec in TOOL_SPECS}
        self.assertTrue({"unblob", "binary-refinery", "floss", "capa"}.issubset(names))

    def test_rsa_coppersmith_profile_requires_explicit_small_root_parameters(self):
        classification = Classification("text/plain", "ASCII text", "text", ".txt")
        profile = next(
            item for item in profiles_for_classification(classification)
            if item.name == "rsa-coppersmith-known-prefix"
        )
        self.assertTrue(profile.offline)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "parameters.txt"
            source.write_text(
                "n=3233\ne=3\nc=42\nknown_prefix=ico{\nunknown_suffix_bytes=4\n",
                encoding="ascii",
            )
            self.assertTrue(profile.predicate(source))
            source.write_text("n=3233\ne=3\nc=42\n", encoding="ascii")
            self.assertFalse(profile.predicate(source))

    def test_available_tool_specs_are_deterministic(self):
        first = [spec.name for spec in available_tool_specs()]
        second = [spec.name for spec in available_tool_specs()]
        self.assertEqual(first, second)

    def test_file_profiles_are_type_matched_and_offline(self):
        classification = Classification("image/png", "PNG image", "png", ".png")
        profiles = profiles_for_classification(classification)
        names = {profile.name for profile in profiles}
        self.assertIn("zsteg", names)
        self.assertIn("pngcheck", names)
        self.assertIn("stegoveritas", names)
        self.assertNotIn("nmap", names)
        self.assertNotIn("hydra", names)
        self.assertNotIn("arjun", names)
        self.assertNotIn("nuclei", names)
        self.assertNotIn("AFL++", names)
        self.assertTrue(all(profile.offline for profile in profiles))

    def test_signature_and_carving_profiles_skip_unproductive_file_types(self):
        text = Classification("text/plain", "ASCII text", "text", ".txt")
        text_names = {profile.name for profile in profiles_for_classification(text)}
        self.assertNotIn("binwalk-signatures", text_names)
        self.assertNotIn("scalpel-carve", text_names)

        archive = Classification("application/zip", "Zip archive", "archive", ".zip")
        archive_names = {profile.name for profile in profiles_for_classification(archive)}
        self.assertIn("binwalk-signatures", archive_names)
        self.assertIn("unblob-extract", archive_names)
        self.assertNotIn("scalpel-carve", archive_names)

        png = Classification("image/png", "PNG image", "png", ".png")
        png_names = {profile.name for profile in profiles_for_classification(png)}
        self.assertIn("binwalk-signatures", png_names)
        self.assertIn("unblob-extract", png_names)
        self.assertNotIn("scalpel-carve", png_names)

        opaque = Classification("application/octet-stream", "data", "data", ".bin")
        opaque_names = {profile.name for profile in profiles_for_classification(opaque)}
        self.assertTrue({"binwalk-signatures", "unblob-extract", "scalpel-carve"}.issubset(opaque_names))

    def test_heavy_source_scanners_skip_ordinary_text_but_keep_code_and_config(self):
        classification = Classification("text/plain", "ASCII text", "text", ".txt")
        profiles = {
            item.name: item
            for item in profiles_for_classification(classification)
            if item.name in {"semgrep-local-rules", "trufflehog-local"}
        }
        self.assertEqual(set(profiles), {"semgrep-local-rules", "trufflehog-local"})
        self.assertTrue(all(item.predicate is not None for item in profiles.values()))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prose = root / "task.txt"
            prose.write_text("The analyst found a clue near the old station.", encoding="utf-8")
            source = root / "main.py"
            source.write_text("import os\nprint(os.getenv('TOKEN'))\n", encoding="utf-8")
            config = root / "compose.yml"
            config.write_text("services:\n  app:\n    environment:\n      TOKEN: example\n", encoding="utf-8")
            code_in_text = root / "attachment.txt"
            code_in_text.write_text("#include <stdio.h>\nint main(void) { return 0; }\n", encoding="utf-8")

            for item in profiles.values():
                self.assertFalse(item.predicate(prose))
                self.assertTrue(item.predicate(source))
                self.assertTrue(item.predicate(config))
                self.assertTrue(item.predicate(code_in_text))

    def test_stegseek_seed_profile_is_offline_jpeg_only_and_has_no_wordlist(self):
        jpeg = Classification("image/jpeg", "JPEG image", "jpeg", ".jpg")
        profile = next(
            item for item in profiles_for_classification(jpeg)
            if item.name == "stegseek-seed"
        )
        self.assertTrue(profile.offline)
        self.assertEqual(profile.stage, "deep")
        self.assertIsNotNone(profile.collect_dir)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "clue.jpg"
            source.write_bytes(b"jpeg fixture")
            args = profile.args_for(source, root / "output")
            output_dir = profile.collect_dir(source, root / "output")

        self.assertEqual(args[:2], ["stegseek", "--seed"])
        self.assertEqual(Path(args[-1]).parent, output_dir)
        self.assertNotIn("--crack", args)
        self.assertNotIn("--wordlist", args)
        png = Classification("image/png", "PNG image", "png", ".png")
        self.assertNotIn(
            "stegseek-seed",
            {item.name for item in profiles_for_classification(png)},
        )

    def test_stegseek_seed_profile_refuses_a_symlinked_extraction_target(self):
        classification = Classification("image/jpeg", "JPEG image", "jpeg", ".jpg")
        profile = next(item for item in profiles_for_classification(classification) if item.name == "stegseek-seed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "clue.jpg"
            source.write_bytes(b"jpeg fixture")
            output = root / "output"
            extraction_dir = profile.collect_dir(source, output)
            outside = root / "outside.txt"
            outside.write_text("preserve me", encoding="utf-8")
            (extraction_dir / "extracted.txt").symlink_to(outside)

            with self.assertRaises(OSError):
                profile.args_for(source, output)

    @unittest.skipUnless(shutil.which("stegseek") and shutil.which("steghide") and shutil.which("ffmpeg"), "StegSeek fixture tools are optional")
    def test_stegseek_seed_profile_recovers_unencrypted_embedded_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cover = root / "cover.jpg"
            stego = root / "stego.jpg"
            secret = root / "secret.txt"
            secret.write_text("ico{stegseek_seed_fixture}", encoding="ascii")
            subprocess.run(
                ["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", "color=c=blue:s=1280x720", "-frames:v", "1", str(cover)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["steghide", "embed", "-cf", str(cover), "-ef", str(secret), "-p", "", "-e", "none", "-Z", "-N", "-sf", str(stego)],
                check=True,
                capture_output=True,
            )
            classification = Classification("image/jpeg", "JPEG image", "jpeg", ".jpg")
            profile = next(item for item in profiles_for_classification(classification) if item.name == "stegseek-seed")
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                evidence = run_adapter_profiles(
                    [stego],
                    classifications={stego.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    mode="full",
                    workers=1,
                )

        adapter = next(item for item in evidence if item.tool == "stegseek-seed")
        self.assertEqual(adapter.status, "ok", adapter.output)
        self.assertTrue(any(item["value"] == "ico{stegseek_seed_fixture}" for item in adapter.candidates))

    def test_pdf_and_disk_profiles_include_remaining_forensics(self):
        pdf = Classification("application/pdf", "PDF document", "pdf", ".pdf")
        pdf_names = {profile.name for profile in profiles_for_classification(pdf)}
        self.assertTrue({"pdfid", "pdf-parser", "peepdf-static"}.issubset(pdf_names))
        disk = Classification("application/octet-stream", "disk image", "disk", ".dd")
        disk_names = {profile.name for profile in profiles_for_classification(disk)}
        self.assertTrue({"dissect-qfind-flags", "fls-recursive", "mmls", "tsk-recover"}.issubset(disk_names))

    def test_binary_profiles_include_static_pwn_and_reverse_inventory(self):
        classification = Classification("application/octet-stream", "ELF 64-bit executable", "binary", ".elf")
        names = {profile.name for profile in profiles_for_classification(classification)}
        for expected in {"checksec", "ROPgadget", "ropper-info", "objdump", "nm", "lldb-modules", "upx-list", "angr-disassemble", "angr-symbolic-stdin"}:
            self.assertIn(expected, names)

    def test_aggressive_profiles_are_opt_in_and_expand_local_strategies(self):
        text = Classification("text/plain", "ASCII text", "text", ".txt")
        default_names = {profile.name for profile in profiles_for_classification(text)}
        aggressive_names = {profile.name for profile in profiles_for_classification(text, aggressive=True)}
        self.assertNotIn("ciphey-full", default_names)
        self.assertNotIn("binary-refinery-bitrev", default_names)
        self.assertTrue({"ciphey-full", "binary-refinery-bitrev", "binary-refinery-decompress"}.issubset(aggressive_names))
        self.assertNotIn("featherduster", aggressive_names)

    def test_aggressive_rsa_and_angr_profiles_have_expanded_budgets(self):
        text = Classification("text/plain", "RSA public key", "text", ".pem")
        binary = Classification("application/octet-stream", "ELF checker", "binary", ".elf")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "public.pem"
            key.write_text("-----BEGIN RSA PUBLIC KEY-----\nRSA\n-----END RSA PUBLIC KEY-----\n", encoding="ascii")
            (root / "cipher.ct").write_text("42", encoding="ascii")
            rsa = next(item for item in profiles_for_classification(text, aggressive=True) if item.name == "RsaCtfTool-all-attacks")
            args = rsa.args_for(key, root / "out")
            self.assertEqual(args[args.index("--attack") + 1], "all")
            self.assertEqual(args[args.index("--timeout") + 1], "20")
            checker = root / "checker"
            checker.write_bytes(b"\x7fELF" + b"no textual success marker")
            angr = next(item for item in profiles_for_classification(binary, aggressive=True) if item.name == "angr-symbolic-stdin-aggressive")
            self.assertTrue(angr.predicate(checker))
            angr_args = angr.args_for(checker, root / "out")
            self.assertIn("256", angr_args)
            self.assertIn("768", angr_args)

    def test_angr_symbolic_profile_requires_success_and_failure_markers(self):
        classification = Classification("application/octet-stream", "ELF checker", "binary", ".elf")
        profile = next(item for item in profiles_for_classification(classification) if item.name == "angr-symbolic-stdin")
        self.assertEqual(profile.stage, "deep")
        self.assertTrue(profile.offline)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "checker"
            binary.write_bytes(b"Correct! Try again")
            self.assertTrue(profile.predicate(binary))
            binary.write_bytes(b"Correct! only")
            self.assertFalse(profile.predicate(binary))
            args = profile.args_for(binary, root / "out")
        self.assertIn("--max-seconds", args)
        self.assertIn("48", args)
        self.assertIn("--max-states", args)

    @unittest.skipUnless(shutil.which("ico-angr-symbolic") and shutil.which("clang") and shutil.which("ld.lld"), "angr runtime and cross-linker are optional")
    def test_angr_symbolic_profile_recovers_checker_input_without_native_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "checker.s"
            obj = root / "checker.o"
            binary = root / "checker"
            source.write_text(
                '.section .rodata\n'
                'expected: .ascii "ico{angr_symbolic_fixture}"\n'
                '.equ expected_len, .-expected\n'
                'correct_msg: .ascii "Correct!\\n"\n'
                'wrong_msg: .ascii "Wrong\\n"\n'
                '.section .bss\n.lcomm input, 64\n'
                '.section .text\n.globl _start\n_start:\n'
                'mov $0, %eax\nmov $0, %edi\nlea input(%rip), %rsi\nmov $64, %edx\nsyscall\n'
                'cmp $expected_len+1, %rax\njne wrong\n'
                'lea input(%rip), %rsi\nlea expected(%rip), %rdi\nmov $expected_len, %rcx\ncld\nrepe cmpsb\njne wrong\n'
                'lea input(%rip), %rsi\nadd $expected_len, %rsi\ncmpb $10, (%rsi)\njne wrong\n'
                'mov $1, %eax\nmov $1, %edi\nlea correct_msg(%rip), %rsi\nmov $8, %edx\nsyscall\njmp done\n'
                'wrong:\nmov $1, %eax\nmov $1, %edi\nlea wrong_msg(%rip), %rsi\nmov $6, %edx\nsyscall\n'
                'done:\nmov $60, %eax\nxor %edi, %edi\nsyscall\n',
                encoding="utf-8",
            )
            subprocess.run(["clang", "-target", "x86_64-unknown-linux-gnu", "-c", str(source), "-o", str(obj)], check=True, capture_output=True)
            subprocess.run(["ld.lld", "-m", "elf_x86_64", "-e", "_start", "-o", str(binary), str(obj)], check=True, capture_output=True)
            classification = Classification("application/octet-stream", "compiled local ELF checker", "binary", ".elf")
            profile = next(item for item in profiles_for_classification(classification) if item.name == "angr-symbolic-stdin")
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                evidence = run_adapter_profiles(
                    [binary],
                    classifications={binary.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    mode="full",
                    workers=1,
                    deadline_seconds=55,
                )
            adapter = next(item for item in evidence if item.tool == "angr-symbolic-stdin")
            self.assertEqual(adapter.status, "ok", adapter.output)
            self.assertTrue(any(item["value"] == "ico{angr_symbolic_fixture}" for item in adapter.candidates), adapter.candidates)

    @unittest.skipUnless(shutil.which("ico-angr-symbolic") and shutil.which("clang"), "angr runtime and clang are optional")
    def test_angr_fails_closed_for_unsupported_macho_variadic_checker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "checker.c"
            binary = root / "checker"
            source.write_text(
                '#include <stdio.h>\n#include <string.h>\n'
                'int main(void) { char input[64]; if (scanf("%63s", input) != 1) return 1; '
                'if (strcmp(input, "ico{fixture}") == 0) puts("Correct!"); else puts("Wrong"); return 0; }\n',
                encoding="utf-8",
            )
            subprocess.run(["clang", "-O0", str(source), "-o", str(binary)], check=True, capture_output=True)
            result = subprocess.run(
                ["ico-angr-symbolic", "--binary", str(binary), "--max-seconds", "8", "--max-input", "16"],
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
            record = __import__("json").loads(result.stdout)
            self.assertEqual(record["status"], "unsupported", record)
            self.assertIn("Darwin arm64", record["reason"])

    def test_binary_profiles_include_bounded_ghidra_headless_summary(self):
        classification = Classification("application/octet-stream", "ELF 64-bit executable", "binary", ".elf")
        profiles = {profile.name: profile for profile in profiles_for_classification(classification)}
        self.assertIn("ghidra-headless-summary", profiles)
        profile = profiles["ghidra-headless-summary"]
        self.assertTrue(profile.offline)
        self.assertEqual(profile.stage, "deep")
        self.assertIsNotNone(profile.collect_dir)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.elf"
            source.write_bytes(b"local test input")
            args = profile.args_for(source, root / "adapters")
        self.assertIn("-import", args)
        self.assertIn("-analysisTimeoutPerFile", args)
        self.assertIn("IcoTriage.java", args)
        self.assertIn("-deleteProject", args)

    @unittest.skipUnless(shutil.which("ghidraRun") and shutil.which("clang"), "Ghidra and clang are optional")
    def test_ghidra_headless_profile_writes_static_string_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "fixture.c"
            binary = root / "fixture.bin"
            source.write_text(
                '#include <stdio.h>\nint main(void) { puts("ico{ghidra_static_fixture}"); return 0; }\n',
                encoding="utf-8",
            )
            subprocess.run(["clang", str(source), "-o", str(binary)], check=True, capture_output=True)
            classification = Classification("application/octet-stream", "compiled local fixture", "binary", ".bin")
            profile = next(
                item for item in profiles_for_classification(classification)
                if item.name == "ghidra-headless-summary"
            )
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                evidence = run_adapter_profiles(
                    [binary],
                    classifications={binary.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    mode="full",
                    workers=1,
                    deadline_seconds=240,
                )
            adapter = next(item for item in evidence if item.tool == "ghidra-headless-summary")
            self.assertEqual(adapter.status, "ok", adapter.output)
            summary = profile.collect_dir(binary, root / "adapters") / "ghidra-summary.txt"
            self.assertIn("ico{ghidra_static_fixture}", summary.read_text(encoding="utf-8"))
            self.assertTrue(any(item["value"] == "ico{ghidra_static_fixture}" for item in adapter.candidates))

    def test_ghidra_headless_profile_rejects_symlinked_output_directories(self):
        classification = Classification("application/octet-stream", "ELF 64-bit executable", "binary", ".elf")
        profile = next(
            item for item in profiles_for_classification(classification)
            if item.name == "ghidra-headless-summary"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.elf"
            source.write_bytes(b"static test bytes")
            output = root / "adapters"
            output.mkdir()
            outside = root / "outside"
            outside.mkdir()
            (output / "ghidra-projects").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(OSError):
                profile.args_for(source, output)

    def test_binary_profiles_schedule_floss_and_capa_as_bounded_static_analysis(self):
        classification = Classification("application/octet-stream", "ELF 64-bit executable", "binary", ".elf")
        profiles = {profile.name: profile for profile in profiles_for_classification(classification)}
        self.assertIn("floss-strings", profiles)
        self.assertIn("capa-capabilities", profiles)
        self.assertTrue(profiles["floss-strings"].offline)
        self.assertTrue(profiles["capa-capabilities"].offline)
        self.assertLessEqual(profiles["floss-strings"].timeout, 120)
        self.assertLessEqual(profiles["capa-capabilities"].timeout, 60)

    def test_unblob_is_selected_for_container_and_opaque_binary_inputs(self):
        classification = Classification("application/octet-stream", "data", "data", ".bin")
        profiles = {profile.name: profile for profile in profiles_for_classification(classification)}
        self.assertIn("unblob-extract", profiles)
        profile = profiles["unblob-extract"]
        self.assertTrue(profile.offline)
        self.assertIsNotNone(profile.collect_dir)
        self.assertLessEqual(profile.timeout, 120)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "evidence.bin"
            artifact.write_bytes(b"opaque")
            args = profile.args_for(artifact, root / "adapters")
        self.assertIn("run_unblob_bounded.py", " ".join(args))
        self.assertIn("--max-bytes", args)
        self.assertIn("268435456", args)
        self.assertIn("--max-entries", args)
        self.assertNotIn("--no-sandbox", args)

    def test_unblob_adapter_extracts_a_nested_local_flag_fixture(self):
        if shutil.which("unblob") is None:
            self.skipTest("unblob optional runtime is not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inner = root / "nested.zip"
            source = root / "evidence.bin"
            with zipfile.ZipFile(inner, "w") as archive:
                archive.writestr("payload.txt", "ico{unblob_nested_fixture}")
            with zipfile.ZipFile(source, "w") as archive:
                archive.write(inner, "nested.zip")
            classification = Classification("application/octet-stream", "data", "data", ".bin")
            profile = next(
                item for item in profiles_for_classification(classification)
                if item.name == "unblob-extract"
            )
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                evidence = run_adapter_profiles(
                    [source],
                    classifications={source.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    mode="full",
                    workers=1,
                )
        adapter = next(item for item in evidence if item.tool == "unblob-extract")
        self.assertEqual(adapter.status, "ok", adapter.output)
        self.assertTrue(any(item["value"] == "ico{unblob_nested_fixture}" for item in adapter.candidates))
        self.assertGreaterEqual(adapter.metadata.get("derived_text_files", 0), 1)

    def test_binary_refinery_base64_profile_decodes_a_local_fixture(self):
        if not next(item for item in tool_inventory() if item["name"] == "binary-refinery")["available"]:
            self.skipTest("Binary Refinery optional runtime is not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "encoded.txt"
            source.write_bytes(base64.b64encode(b"ico{refinery_adapter_fixture}"))
            classification = Classification("text/plain", "text", "text", ".txt")
            profile = next(
                item for item in profiles_for_classification(classification)
                if item.name == "binary-refinery-base64"
            )
            self.assertTrue(profile.predicate(source))
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                evidence = run_adapter_profiles(
                    [source],
                    classifications={source.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    mode="full",
                    workers=1,
                )
        adapter = next(item for item in evidence if item.tool == "binary-refinery-base64")
        self.assertEqual(adapter.status, "ok", adapter.output)
        self.assertTrue(any(item["value"] == "ico{refinery_adapter_fixture}" for item in adapter.candidates))

    def test_binary_refinery_hex_profile_decodes_a_local_fixture(self):
        if not next(item for item in tool_inventory() if item["name"] == "binary-refinery")["available"]:
            self.skipTest("Binary Refinery optional runtime is not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "encoded.hex"
            source.write_text("69636f7b726566696e6572795f6865787d", encoding="ascii")
            classification = Classification("text/plain", "text", "text", ".hex")
            profile = next(
                item for item in profiles_for_classification(classification)
                if item.name == "binary-refinery-hex"
            )
            self.assertTrue(profile.predicate(source))
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                evidence = run_adapter_profiles(
                    [source],
                    classifications={source.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    mode="full",
                    workers=1,
                )
        adapter = next(item for item in evidence if item.tool == "binary-refinery-hex")
        self.assertEqual(adapter.status, "ok", adapter.output)
        self.assertTrue(any(item["value"] == "ico{refinery_hex}" for item in adapter.candidates))

    def test_binary_refinery_additional_units_decode_local_fixtures(self):
        if not next(item for item in tool_inventory() if item["name"] == "binary-refinery")["available"]:
            self.skipTest("Binary Refinery optional runtime is not installed")
        plaintext = b"ico{refinery_extra_unit_fixture}"
        encoded_cases = (
            ("base32", "binary-refinery-base32", base64.b32encode(plaintext)),
            ("base58", "binary-refinery-base58", _base58_encode_for_test(plaintext)),
            ("base85", "binary-refinery-base85", base64.b85encode(plaintext)),
            ("url", "binary-refinery-url", urllib.parse.quote_from_bytes(plaintext).encode("ascii")),
        )
        classification = Classification("text/plain", "text", "text", ".txt")
        for label, profile_name, encoded in encoded_cases:
            with self.subTest(unit=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / f"encoded-{label}.txt"
                source.write_bytes(encoded)
                profile = next(
                    item for item in profiles_for_classification(classification)
                    if item.name == profile_name
                )
                self.assertIsNotNone(profile.predicate)
                self.assertTrue(profile.predicate(source), f"{label} signal was not recognized")
                with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                    evidence = run_adapter_profiles(
                        [source],
                        classifications={source.resolve(): classification},
                        output_dir=root / "adapters",
                        runner=CommandRunner(root / "commands"),
                        mode="full",
                        workers=1,
                    )
                adapter = next(item for item in evidence if item.tool == profile_name)
                self.assertEqual(adapter.status, "ok", adapter.output)
                self.assertTrue(any(item["value"] == plaintext.decode("ascii") for item in adapter.candidates))

    def test_rsactftool_runs_bounded_offline_attacks_for_adjacent_ciphertext(self):
        if shutil.which("RsaCtfTool") is None or shutil.which("openssl") is None:
            self.skipTest("RsaCtfTool and OpenSSL are optional")
        plaintext = b"ico{rsactftool_adapter_fixture}"
        message = int.from_bytes(plaintext, "big")
        classification = Classification("application/x-pem-file", "RSA public key", "data", ".pem")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_key = root / "private.pem"
            public_key = root / "public.pem"
            ciphertext = root / "ciphertext.bin"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:1024", "-pkeyopt", "rsa_keygen_pubexp:3", "-out", str(private_key)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
                check=True,
                capture_output=True,
            )
            modulus_output = subprocess.run(
                ["openssl", "rsa", "-pubin", "-in", str(public_key), "-modulus", "-noout"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            modulus = int(modulus_output.strip().split("=", 1)[1], 16)
            self.assertLess(message**3, modulus)
            ciphertext.write_bytes((message**3).to_bytes((modulus.bit_length() + 7) // 8, "big"))

            profile = next(
                item for item in profiles_for_classification(classification)
                if item.name == "RsaCtfTool-offline-decrypt"
            )
            args = profile.args_for(public_key, root / "adapters")
            self.assertTrue({"cube_root", "wiener", "fermat", "smallq", "pollard_p_1"}.issubset(set(args)))
            self.assertNotIn("factordb", args)
            self.assertNotIn("wolframalpha", args)
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                evidence = run_adapter_profiles(
                    [public_key],
                    classifications={public_key.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    mode="full",
                    workers=1,
                )
        adapter = next(item for item in evidence if item.tool == "RsaCtfTool-offline-decrypt")
        self.assertEqual(adapter.status, "ok", adapter.output)
        self.assertTrue(any(item["value"] == plaintext.decode("ascii") for item in adapter.candidates))

    def test_dissect_qfind_extracts_a_flag_from_json_byte_context(self):
        if shutil.which("target-qfind") is None:
            self.skipTest("Dissect optional runtime is not installed")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "image.dd"
            source.write_bytes("sector data ico{dissect_qfind_fixture}".encode("utf-16-le"))
            classification = Classification("application/octet-stream", "disk image", "disk", ".dd")
            profile = next(
                item for item in profiles_for_classification(classification)
                if item.name == "dissect-qfind-flags"
            )
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                evidence = run_adapter_profiles(
                    [source],
                    classifications={source.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    mode="full",
                    workers=1,
                    deadline_seconds=20,
                )
        adapter = next(item for item in evidence if item.tool == "dissect-qfind-flags")
        self.assertEqual(adapter.status, "ok", adapter.output)
        self.assertTrue(any(item["value"] == "ico{dissect_qfind_fixture}" for item in adapter.candidates))

    def test_signal_gated_specialists_are_registered_for_text_and_rsa_material(self):
        text = Classification("text/plain", "text", "text", ".txt")
        text_names = {profile.name for profile in profiles_for_classification(text)}
        self.assertTrue({"hashid", "ciphey", "xortool", "seccomp-tools-disasm"}.issubset(text_names))
        rsa = Classification("application/octet-stream", "data", "data", ".pem")
        rsa_names = {profile.name for profile in profiles_for_classification(rsa)}
        self.assertIn("RsaCtfTool-dump", rsa_names)
        self.assertIn("RsaCtfTool-offline-decrypt", rsa_names)

    def test_office_and_mobile_profiles_are_local_and_collect_outputs(self):
        office = Classification("application/vnd.ms-office", "Microsoft Office", "archive", ".docm")
        office_names = {profile.name for profile in profiles_for_classification(office)}
        self.assertTrue({"oleid", "olevba", "mraptor"}.issubset(office_names))
        mobile = Classification("application/vnd.android.package-archive", "Android package", "archive", ".apk")
        mobile_profiles = profiles_for_classification(mobile)
        mobile_names = {profile.name for profile in mobile_profiles}
        self.assertTrue({"apktool-decode", "jadx-decompile"}.issubset(mobile_names))
        for profile in mobile_profiles:
            self.assertTrue(profile.offline)

    def test_network_specialists_are_inventory_only(self):
        network_names = {"jwt_tool", "arjun", "kiterunner", "graphql-cop", "graphw00f", "nuclei", "factordb"}
        specs = {spec.name: spec for spec in TOOL_SPECS}
        for name in network_names:
            self.assertFalse(specs[name].offline_default)

    def test_cyberchef_asset_is_local_only(self):
        with tempfile.TemporaryDirectory() as directory:
            asset = cyberchef_asset(Path(directory))
        self.assertIsNone(asset)

    def test_cyberchef_writes_decoded_container_for_shared_solver_queue(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("payload.txt", "ico{cyberchef_handoff_fixture}")
            token = base64.b64encode(archive.getvalue())
            table = bytes.maketrans(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            )
            source = root / "rot13-layer.txt"
            source.write_bytes(token.translate(table))

            evidence = run_cyberchef_adapter(source, output_dir=root / "adapters")
            derived_payloads = [Path(path).read_bytes() for path in evidence.metadata.get("derived_artifact_paths", [])]
            transform_chains = evidence.metadata.get("derived_transformations", [])

        self.assertEqual(len(derived_payloads), 1, evidence.output)
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(derived_payloads[0])))
        self.assertIn("ROT13", str(transform_chains[0]["chain"]))

    def test_cyberchef_discards_decompression_overflow(self):
        from ico_tool_adapters import _cyberchef_decode_chain

        bomb = gzip.compress(b"A" * (5 * 1024 * 1024), mtime=0)
        encoded = base64.b64encode(bomb)
        views = _cyberchef_decode_chain(encoded)

        self.assertTrue(views)
        self.assertTrue(all(len(payload) <= 4 * 1024 * 1024 for payload, _chain in views))

    def test_remaining_platform_tools_expose_explicit_status(self):
        statuses = {name: platform_tool_status(name) for name in ("qiling", "scalpel", "strace", "ltrace")}
        self.assertEqual(set(statuses), {"qiling", "scalpel", "strace", "ltrace"})
        for name, status in statuses.items():
            self.assertEqual(status["name"], name)
            self.assertIn(status["state"], {"available", "compat", "missing"})
            self.assertTrue(status["backend"])

    def test_remaining_tools_are_visible_in_inventory_with_backend(self):
        inventory = {item["name"]: item for item in tool_inventory()}
        for name in ("qiling", "scalpel", "strace", "ltrace"):
            self.assertIn(name, inventory)
            self.assertIn("backend", inventory[name])

    def test_scalpel_is_selected_for_file_carving(self):
        classification = Classification("application/octet-stream", "data", "data", ".bin")
        names = {profile.name for profile in profiles_for_classification(classification)}
        self.assertIn("scalpel-carve", names)

    def test_scalpel_carve_collects_flag_shaped_payload(self):
        if shutil.which("scalpel") is None:
            self.skipTest("scalpel wrapper is not on PATH")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "evidence.bin"
            artifact.write_bytes(
                b"prefix\x89PNG\r\n\x1a\n"
                b"ico{scalpel_adapter_test}"
                b"\x00\x00\x00\x00IEND\xaeB`\x82suffix"
            )
            command_dir = root / "commands"
            classification = classify(artifact, CommandRunner(command_dir))
            evidence = run_adapter_profiles(
                [artifact],
                classifications={artifact.resolve(): classification},
                output_dir=root / "adapters",
                runner=CommandRunner(command_dir),
                mode="full",
            )
        scalpel = [item for item in evidence if item.tool == "scalpel-carve"]
        self.assertEqual(len(scalpel), 1)
        self.assertTrue(any(item["value"] == "ico{scalpel_adapter_test}" for item in scalpel[0].candidates))

    def test_profiles_run_in_parallel_and_keep_stable_order(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "evidence.bin"
            artifact.write_bytes(b"parallel")
            profiles = (
                AdapterProfile(
                    "slow-a",
                    sys.executable,
                    lambda _path, _out: [sys.executable, "-c", "import time; time.sleep(.25); print('ico{parallel_a}')"],
                    timeout=3,
                    stage="specialized",
                ),
                AdapterProfile(
                    "slow-b",
                    sys.executable,
                    lambda _path, _out: [sys.executable, "-c", "import time; time.sleep(.25); print('ico{parallel_b}')"],
                    timeout=3,
                    stage="specialized",
                ),
            )
            classification = Classification("application/octet-stream", "data", "data", ".bin")
            started = time.monotonic()
            with patch("ico_tool_adapters.profiles_for_classification", return_value=profiles):
                evidence = run_adapter_profiles(
                    [artifact],
                    classifications={artifact.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    workers=2,
                )
            elapsed = time.monotonic() - started
        tools = [item.tool for item in evidence if item.tool != "cyberchef"]
        self.assertEqual(tools, ["slow-a", "slow-b"])
        self.assertLess(elapsed, 0.48, f"profiles were not overlapped: {elapsed:.3f}s")
        self.assertEqual({candidate["value"] for item in evidence for candidate in item.candidates}, {"ico{parallel_a}", "ico{parallel_b}"})

    def test_adapter_cache_reuses_command_result_and_invalidates_on_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "evidence.txt"
            artifact.write_text("first", encoding="utf-8")
            profiles = (AdapterProfile("cached", sys.executable, lambda _path, _out: [sys.executable, "-c", "print('ico{cached}')"], timeout=3, stage="fast"),)
            classification = Classification("text/plain", "text", "text", ".txt")
            kwargs = {
                "classifications": {artifact.resolve(): classification},
                "output_dir": root / "adapters",
                "runner": CommandRunner(root / "commands"),
                "mode": "full",
                "cache_dir": root / "cache",
            }
            with patch("ico_tool_adapters.profiles_for_classification", return_value=profiles):
                first = run_adapter_profiles([artifact], **kwargs)
                second = run_adapter_profiles([artifact], **kwargs)
            first_cached = next(item for item in first if item.tool == "cached")
            second_cached = next(item for item in second if item.tool == "cached")
            self.assertFalse(first_cached.cache_hit)
            self.assertTrue(second_cached.cache_hit)
            artifact.write_text("changed", encoding="utf-8")
            with patch("ico_tool_adapters.profiles_for_classification", return_value=profiles):
                third = run_adapter_profiles([artifact], **kwargs)
            self.assertFalse(next(item for item in third if item.tool == "cached").cache_hit)

    def test_adapter_cache_invalidates_when_toolkit_revision_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "evidence.txt"
            artifact.write_text("same", encoding="utf-8")
            profiles = (AdapterProfile("revisioned", sys.executable, lambda _path, _out: [sys.executable, "-c", "print('ico{revisioned}')"], timeout=3, stage="fast"),)
            classification = Classification("text/plain", "text", "text", ".txt")
            kwargs = {
                "classifications": {artifact.resolve(): classification},
                "output_dir": root / "adapters",
                "runner": CommandRunner(root / "commands"),
                "mode": "full",
                "cache_dir": root / "cache",
            }
            with patch.dict(os.environ, {"ICO_TOOLKIT_REVISION": "revision-a"}):
                with patch("ico_tool_adapters.profiles_for_classification", return_value=profiles):
                    first = run_adapter_profiles([artifact], **kwargs)
            with patch.dict(os.environ, {"ICO_TOOLKIT_REVISION": "revision-b"}):
                with patch("ico_tool_adapters.profiles_for_classification", return_value=profiles):
                    second = run_adapter_profiles([artifact], **kwargs)
            self.assertFalse(next(item for item in first if item.tool == "revisioned").cache_hit)
            self.assertFalse(next(item for item in second if item.tool == "revisioned").cache_hit)

    def test_verified_paths_can_skip_generic_adapters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "verified.bin"
            artifact.write_bytes(b"verified")
            classification = Classification("application/octet-stream", "data", "data", ".bin")
            profile = AdapterProfile("should-not-run", sys.executable, lambda _path, _out: [sys.executable, "-c", "raise SystemExit(9)"])
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                evidence = run_adapter_profiles(
                    [artifact],
                    classifications={artifact.resolve(): classification},
                    output_dir=root / "adapters",
                    runner=CommandRunner(root / "commands"),
                    skip_paths={artifact.resolve()},
                )
            self.assertEqual(evidence, ())


if __name__ == "__main__":
    unittest.main()
