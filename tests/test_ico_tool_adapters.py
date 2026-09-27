from __future__ import annotations

import tempfile
import unittest
import shutil
import sys
import time
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
    tool_inventory,
)
from ico_platform_tools import platform_tool_status


class ToolAdapterTests(unittest.TestCase):
    def test_inventory_contains_the_extended_toolchain(self):
        names = {spec.name for spec in TOOL_SPECS}
        self.assertGreaterEqual(len(names), 55)
        for expected in {"cyberchef", "binwalk", "zsteg", "tshark", "radare2", "pwntools", "RsaCtfTool", "volatility"}:
            self.assertIn(expected, names)
        for expected in {"checksec", "ROPgadget", "ropper", "olevba", "apktool", "jadx", "angr", "fls", "semgrep", "xortool", "jwt_tool", "peepdf", "hashpumpy", "seccomp-tools"}:
            self.assertIn(expected, names)

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
        self.assertTrue(all(profile.offline for profile in profiles))

    def test_pdf_and_disk_profiles_include_remaining_forensics(self):
        pdf = Classification("application/pdf", "PDF document", "pdf", ".pdf")
        pdf_names = {profile.name for profile in profiles_for_classification(pdf)}
        self.assertTrue({"pdfid", "pdf-parser", "peepdf-static"}.issubset(pdf_names))
        disk = Classification("application/octet-stream", "disk image", "disk", ".dd")
        disk_names = {profile.name for profile in profiles_for_classification(disk)}
        self.assertTrue({"fls-recursive", "mmls", "tsk-recover"}.issubset(disk_names))

    def test_binary_profiles_include_static_pwn_and_reverse_inventory(self):
        classification = Classification("application/octet-stream", "ELF 64-bit executable", "binary", ".elf")
        names = {profile.name for profile in profiles_for_classification(classification)}
        for expected in {"checksec", "ROPgadget", "ropper-info", "objdump", "nm", "lldb-modules", "upx-list", "angr-disassemble"}:
            self.assertIn(expected, names)

    def test_signal_gated_specialists_are_registered_for_text_and_rsa_material(self):
        text = Classification("text/plain", "text", "text", ".txt")
        text_names = {profile.name for profile in profiles_for_classification(text)}
        self.assertTrue({"hashid", "ciphey", "xortool", "seccomp-tools-disasm"}.issubset(text_names))
        rsa = Classification("application/octet-stream", "data", "data", ".pem")
        rsa_names = {profile.name for profile in profiles_for_classification(rsa)}
        self.assertIn("RsaCtfTool-dump", rsa_names)

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
