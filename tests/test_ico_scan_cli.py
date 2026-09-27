from __future__ import annotations

import json
import ipaddress
import lzma
import os
import shutil
import subprocess
import struct
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from ico_scan import main, run_scan
from ico_scan_core import CommandResult, CommandRunner, Classification
from ico_scan_profiles import ToolProfile
from ico_solver_engine import Detection, SolverContext, SolverRegistry, SolverResult
from ico_universal_registry import build_default_registry


def strings_only(_classification: Classification) -> list[ToolProfile]:
    return [
        ToolProfile(
            "strings-ascii",
            "strings",
            lambda path: ["strings", "-a", "-n", "4", str(path)],
            timeout=10.0,
        )
    ]


def duplicate_strings(_classification: Classification) -> list[ToolProfile]:
    profile = strings_only(_classification)[0]
    return [profile, profile]


def _pcap_with_http_user_agent(user_agent: str) -> bytes:
    payload = (
        b"GET / HTTP/1.1\r\nHost: target.local\r\nUser-Agent: "
        + user_agent.encode("ascii")
        + b"\r\n\r\n"
    )
    tcp = struct.pack(">HHII", 40000, 80, 100, 0) + bytes([0x50, 0x18]) + struct.pack(">HHH", 65535, 0, 0)
    source = ipaddress.IPv4Address("10.0.0.1").packed
    target = ipaddress.IPv4Address("10.0.0.2").packed
    total_length = 20 + len(tcp) + len(payload)
    ip = bytes([0x45, 0]) + struct.pack(">H", total_length) + b"\x00\x00\x40\x00\x40\x06\x00\x00" + source + target
    frame = b"\x00" * 12 + struct.pack(">H", 0x0800) + ip + tcp + payload
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    record = struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    return header + record


class CliTests(unittest.TestCase):
    def test_launcher_uses_toolkit_python_instead_of_a_shadowed_python(self):
        toolkit = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            fake_bin = Path(directory)
            fake_python = fake_bin / "python3"
            fake_python.write_text("#!/bin/sh\nprintf 'shadow-python\\n'\n", encoding="utf-8")
            fake_python.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
            completed = subprocess.run(
                [str(toolkit / "ico-scan"), "--help"],
                cwd=toolkit,
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("usage: ico-scan", completed.stdout.lower())
        self.assertNotIn("shadow-python", completed.stdout)

    def test_scan_accepts_file_and_directory_and_follows_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            direct = root / "direct.bin"
            direct.write_bytes(b"noise\nico{fixture_direct}\n")
            nested = root / "nested.txt"
            nested.write_text("CTF{fixture_nested}\n", encoding="utf-8")
            archive = root / "fixture.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.write(nested, "nested.txt")
            negative = root / "negative.txt"
            negative.write_text("the word flag appears without a value", encoding="utf-8")
            out_dir = root / "report"
            runner = CommandRunner()
            report = run_scan(
                [str(direct), str(root)],
                out_dir=out_dir,
                patterns=None,
                max_depth=2,
                max_files=20,
                max_bytes=1024 * 1024,
                tool_timeout=10,
                runner=runner,
                profile_selector=strings_only,
            )
            values = {candidate["value"] for candidate in report["candidates"]}
            report_json = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
            artifact_paths = [candidate["artifact"] for candidate in report["candidates"]]
            self.assertTrue((out_dir / "report.txt").exists())
        self.assertEqual(values, {"ico{fixture_direct}", "CTF{fixture_nested}"})
        self.assertTrue(any("nested.txt" in path for path in artifact_paths))
        self.assertEqual(report_json["summary"]["candidate_count"], 2)

    def test_scan_routes_xz_derived_pcap_to_task_aware_forensics_solver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task_root = root / "Forensics" / "Babys_First_Forensics"
            task_root.mkdir(parents=True)
            (task_root / "README.md").write_text(
                "What tool were they using and its version? Wrap your answer in DUCTF{}, "
                "e.g. DUCTF{nmap_7.25}.",
                encoding="utf-8",
            )
            source = task_root / "capture.pcap.xz"
            source.write_bytes(
                lzma.compress(_pcap_with_http_user_agent("Mozilla/5.00 (Nikto/2.1.6) (Test:001)"))
            )
            report = run_scan(
                [str(task_root)],
                out_dir=root / "report",
                max_depth=3,
                max_files=10,
                max_bytes=1024 * 1024,
                tool_timeout=10,
                verbose=False,
                solver_registry=build_default_registry(),
                runner=CommandRunner(),
                profile_selector=lambda _classification: [],
                mode="fast",
            )

        values = {item["value"] for item in report["candidates"]}
        self.assertIn("DUCTF{nikto_2.1.6}", values)

    def test_fast_mode_stops_macro_magic_expansion_after_task_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "Macro_Magic"
            root.mkdir()
            key = b"NorthStar"
            flag = b"DUCTF{fast_task_candidate}"
            encrypted = bytes(value ^ key[index % len(key)] for index, value in enumerate(flag))
            url = "https://example.test/" + "-".join(str(value) for value in encrypted)
            macro = (
                'S = "North"\nG = "Star"\nW = S + G\n'
                "Function doThing(B As String, C As String) As String\n"
                " A = A & Chr(Asc(Mid(B, I, 1)) Xor Asc(Mid(C, (I - 1) Mod Len(C) + 1, 1)))\n"
                "End Function\nQ = doThing(Q, W)\n"
            )
            archive = root / "macromagic.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("Module1.bas", macro)
                handle.writestr("captured-urls.txt", url)
                for index in range(60):
                    handle.writestr(f"workbook/media/member-{index:02d}.txt", "ordinary workbook data")
            (root / "README.md").write_text("Captured workbook and web traffic.", encoding="utf-8")

            report = run_scan(
                [str(root)],
                out_dir=root / "report",
                max_depth=3,
                max_files=200,
                max_bytes=1024 * 1024,
                tool_timeout=10,
                verbose=False,
                solver_registry=build_default_registry(),
                runner=CommandRunner(),
                profile_selector=lambda _classification: [],
                mode="fast",
            )

        values = {item["value"] for item in report["candidates"]}
        self.assertIn("DUCTF{fast_task_candidate}", values)
        self.assertLessEqual(report["summary"]["processed_files"], 4)
        self.assertTrue(
            any(
                event.get("type") == "derived-input-skip"
                and "task-aware candidate" in event.get("reason", "")
                for event in report["events"]
            )
        )

    def test_default_file_budget_reaches_archives_after_large_input_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(200):
                (root / f"{index:03d}.bin").write_bytes(b"duplicate input")
            with zipfile.ZipFile(root / "zzz-answer.zip", "w") as archive:
                archive.writestr("answer.txt", "ico{processed_after_input_budget}")
            report = run_scan(
                [str(root)],
                out_dir=root / "report",
                max_depth=1,
                max_bytes=1024 * 1024,
                tool_timeout=10,
                verbose=False,
                solver_registry=SolverRegistry(),
                runner=CommandRunner(),
                profile_selector=lambda _classification: [],
                mode="fast",
            )

        values = {item["value"] for item in report["candidates"]}
        self.assertIn("ico{processed_after_input_budget}", values)

    def test_large_binary_without_xor_task_hint_skips_generic_xor_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "large.bin"
            with source.open("wb") as handle:
                handle.truncate(2 * 1024 * 1024 + 1)
            with patch("ico_scan.select_solver", return_value=None), patch(
                "ico_scan._run_single_byte_xor",
                return_value=(CommandResult(args=["builtin:xor-single-byte"], returncode=0), []),
            ) as xor_pass:
                report = run_scan(
                    [str(source)],
                    out_dir=root / "report",
                    max_files=10,
                    max_bytes=4 * 1024 * 1024,
                    tool_timeout=10,
                    verbose=False,
                    solver_registry=SolverRegistry(),
                    runner=CommandRunner(),
                    profile_selector=lambda _classification: [],
                    mode="fast",
                )

        xor_pass.assert_not_called()
        self.assertTrue(
            any(
                event.get("type") == "tool-skip"
                and event.get("analyzer") == "xor-single-byte"
                and "large binary" in event.get("reason", "")
                for event in report["events"]
            )
        )

    def test_explicit_xor_task_hint_keeps_large_binary_xor_pass_enabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task_root = root / "task"
            task_root.mkdir()
            (task_root / "task.txt").write_text("Recover the value using single-byte XOR.", encoding="utf-8")
            source = task_root / "large.bin"
            with source.open("wb") as handle:
                handle.truncate(2 * 1024 * 1024 + 1)
            with patch("ico_scan.select_solver", return_value=None), patch(
                "ico_scan._run_single_byte_xor",
                return_value=(CommandResult(args=["builtin:xor-single-byte"], returncode=0), []),
            ) as xor_pass:
                run_scan(
                    [str(task_root)],
                    out_dir=root / "report",
                    max_files=10,
                    max_bytes=4 * 1024 * 1024,
                    tool_timeout=10,
                    verbose=False,
                    solver_registry=SolverRegistry(),
                    runner=CommandRunner(),
                    profile_selector=lambda _classification: [],
                    mode="fast",
                )

        xor_pass.assert_called_once()

    def test_scan_keeps_candidates_unconfirmed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("ico{candidate_only}", encoding="utf-8")
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=strings_only,
                runner=CommandRunner(),
            )
        self.assertEqual(report["candidates"][0]["state"], "candidate")
        self.assertNotIn("submitted", report["candidates"][0])
        self.assertEqual(report["summary"]["universal_solved_count"], 0)

    def test_universal_candidate_is_not_counted_as_solved(self):
        class CandidateOnlySolver:
            name = "fixture-candidate"
            category = "crypto"

            def detect(self, context: SolverContext) -> Detection:
                return Detection(self.name, self.category, 100, "test fixture")

            def solve(self, context: SolverContext) -> SolverResult:
                return SolverResult(
                    self.name,
                    self.category,
                    "candidate",
                    candidates=[{"value": "ico{fixture_candidate}", "state": "candidate"}],
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence.bin"
            source.write_bytes(b"fixture")
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
                solver_registry=SolverRegistry([CandidateOnlySolver()]),
                verbose=False,
            )

        self.assertEqual(report["summary"]["universal_solved_count"], 0)
        self.assertEqual(report["summary"]["universal_candidate_result_count"], 1)

    def test_scan_retains_triage_labels_in_candidate_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("ICO{example_flag1}\nICO{network_flag}\nFLAG{N}\n", encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                report = run_scan(
                    [str(source)],
                    out_dir=root / "report",
                    profile_selector=strings_only,
                    runner=CommandRunner(),
                )
            report_text = (root / "report" / "report.txt").read_text(encoding="utf-8")
        by_value = {candidate["value"]: candidate for candidate in report["candidates"]}
        self.assertEqual(set(by_value), {"ICO{example_flag1}", "ICO{network_flag}", "FLAG{N}"})
        self.assertEqual(by_value["ICO{example_flag1}"]["triage"], "likely-placeholder")
        self.assertEqual(by_value["ICO{network_flag}"]["triage"], "candidate")
        self.assertEqual(by_value["FLAG{N}"]["triage"], "likely-noise")
        self.assertEqual(by_value["FLAG{N}"]["state"], "candidate")
        self.assertEqual(report["summary"]["likely_placeholder_count"], 1)
        self.assertEqual(report["summary"]["likely_noise_count"], 1)
        self.assertIn("Low-priority flag-shaped values (retained as candidates)", report_text)
        self.assertIn("ICO{example_flag1}", report_text)
        self.assertIn("FLAG{N}", report_text)
        self.assertIn("triage=likely-placeholder", stdout.getvalue())
        self.assertIn("LOW-PRIORITY FLAG-LIKE VALUE: ICO{example_flag1}", stdout.getvalue())
        self.assertNotIn("FOUND CANDIDATE: ICO{example_flag1}", stdout.getvalue())

    def test_jctf_self_labeled_decoy_is_visible_as_low_priority_not_promoted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "hidden.txt"
            source.write_text("jctf{n0t_the_real_flag?_or_is_it?}\n", encoding="utf-8")
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
            )

        candidate = next(item for item in report["candidates"] if item["value"].startswith("jctf{"))
        self.assertEqual(candidate["triage"], "likely-placeholder")
        self.assertIn("n0t_the_real_flag", candidate["triage_reason"])

    def test_cli_separates_actionable_and_low_priority_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("input", encoding="utf-8")
            report = {
                "report_dir": str(root / "report"),
                "candidates": [
                    {
                        "value": "ICO{example_flag1}",
                        "triage": "likely-placeholder",
                        "triage_reason": "contains placeholder marker: example",
                        "artifact": str(source),
                    },
                    {"value": "ICO{network_flag}", "triage": "candidate", "artifact": str(source)},
                ],
                "task_results": [],
                "universal_results": [
                    {
                        "solver": "universal-reverse",
                        "status": "payload-ready",
                        "evidence_context": {"input_path": "/tmp/chall.elf"},
                        "steps": [
                            {
                                "name": "payload-construction",
                                "details": {"payload": "/tmp/chall.elf.ret2win.payload"},
                            }
                        ],
                    },
                    {
                        "solver": "universal-data",
                        "status": "unsupported",
                        "evidence_context": {"input_path": "/tmp/task.txt"},
                        "steps": [],
                    },
                    {
                        "solver": "universal-web",
                        "status": "payload-ready",
                        "evidence_context": {"input_path": "/tmp/index.js"},
                        "steps": [
                            {
                                "name": "source-to-template-flow",
                                "details": {"evidence": "/tmp/mojo-process-env-request.txt"},
                            }
                        ],
                    },
                ],
                "summary": {
                    "candidate_count": 2,
                    "quals_task_count": 0,
                    "reference_candidate_count": 0,
                },
            }
            stdout = StringIO()
            with patch("ico_scan.run_scan", return_value=report), redirect_stdout(stdout):
                self.assertEqual(main(["--out", str(root / "report"), str(source)]), 0)
        output = stdout.getvalue()
        self.assertIn(
            "CANDIDATE RECORDS: 2 (local-run evidence; includes 1 low-priority record(s))",
            output,
        )
        self.assertIn("CANDIDATE VALUES: 1 (actionable local evidence; not platform-confirmed)", output)
        self.assertNotIn("FLAGS:", output)
        self.assertNotIn("\nICO{example_flag1}\n", output)
        self.assertIn("\nICO{network_flag}\n", output)
        self.assertIn("LOW-PRIORITY FLAG-LIKE CANDIDATE VALUES", output)
        self.assertIn("likely-placeholder: ICO{example_flag1}", output)
        self.assertIn("ACTIONABLE RESULTS:", output)
        self.assertIn("PAYLOAD-READY: universal-reverse (chall.elf)", output)
        self.assertIn("artifact: /tmp/chall.elf.ret2win.payload", output)
        self.assertIn("artifact: /tmp/mojo-process-env-request.txt", output)
        self.assertNotIn("UNSUPPORTED:", output)

    def test_cli_does_not_print_likely_noise_as_an_actionable_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence.bin"
            source.write_bytes(b"fixture")
            noisy_value = "DUCTF{\\x16}"
            noisy_candidate = {
                "value": noisy_value,
                "triage": "likely-noise",
                "triage_reason": "contains non-printable characters",
                "artifact": str(source),
            }
            report = {
                "report_dir": str(root / "report"),
                "candidates": [noisy_candidate],
                "task_results": [],
                "universal_results": [],
                "task_coverage": [
                    {
                        "title": "vector_overflow",
                        "category": "Pwn",
                        "status": "payload-ready",
                        "artifact_count": 2,
                        "solver_count": 3,
                        "candidates": [noisy_candidate],
                    }
                ],
                "summary": {"candidate_count": 1, "quals_task_count": 0},
            }
            stdout = StringIO()
            with patch("ico_scan.run_scan", return_value=report), redirect_stdout(stdout):
                self.assertEqual(main(["--out", str(root / "report"), str(source)]), 0)

        output = stdout.getvalue()
        self.assertIn("CANDIDATE VALUES: 0 (actionable local evidence; not platform-confirmed)", output)
        self.assertIn(f"likely-noise: {noisy_value}", output)
        self.assertIn("low-priority values=1", output)
        self.assertNotIn(f"candidates={noisy_value}", output)
        self.assertNotIn(f"\n{noisy_value}\n", output)

    def test_scan_decodes_single_byte_xor_for_data_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plaintext = b"noise CTF{xor_cli_fixture} tail"
            ciphertext = bytes(value ^ 0x5A for value in plaintext)
            source = root / "evidence.bin"
            source.write_bytes(ciphertext)
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
            )
        self.assertEqual({item["value"] for item in report["candidates"]}, {"CTF{xor_cli_fixture}"})
        candidate = report["candidates"][0]
        self.assertEqual(candidate["analyzer"], "xor-single-byte")
        self.assertEqual(candidate["key"], 0x5A)
        self.assertEqual(candidate["offset"], plaintext.index(b"CTF{"))

    def test_scan_decodes_ductf_without_promoting_its_inner_ctf_substring(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plaintext = b"noise DUCTF{external_corpus_fixture} tail"
            ciphertext = bytes(value ^ 0x5A for value in plaintext)
            source = root / "evidence.bin"
            source.write_bytes(ciphertext)
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
            )

        self.assertEqual({item["value"] for item in report["candidates"]}, {"DUCTF{external_corpus_fixture}"})
        self.assertEqual(report["candidates"][0]["crib"], "CTF{")

    def test_scan_decodes_nested_base64_without_a_task_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            import base64

            root = Path(directory)
            flag = b"CTF{generic_nested_encoding}"
            source = root / "evidence.txt"
            source.write_bytes(b"payload=" + base64.b64encode(flag))
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
            )
        self.assertEqual({item["value"] for item in report["candidates"]}, {flag.decode()})
        self.assertTrue(any(item["analyzer"] == "decode-base64" for item in report["candidates"]))

    def test_scan_records_portable_utf16le_builtin_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "wide.bin"
            source.write_bytes("hidden wide text".encode("utf-16-le"))
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
            )
        tools = [entry for artifact in report["artifacts"] for entry in artifact["tools"]]
        wide = [entry for entry in tools if entry["analyzer"] == "strings-utf16le"]
        self.assertEqual(len(wide), 1)
        self.assertEqual(wide[0]["type"], "builtin")
        self.assertIn("hidden wide text", wide[0]["result"]["stdout"])

    def test_progress_is_bounded_and_goes_to_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence.txt"
            source.write_text("ico{progress_fixture}", encoding="utf-8")
            stderr = StringIO()
            with redirect_stderr(stderr):
                report = run_scan(
                    [str(source)],
                    out_dir=root / "report",
                    profile_selector=lambda _classification: [],
                    runner=CommandRunner(),
                    progress=True,
                    verbose=False,
                )
        self.assertIn("stage=start", stderr.getvalue())
        self.assertIn("stage=file-complete", stderr.getvalue())
        self.assertEqual({item["value"] for item in report["candidates"]}, {"ico{progress_fixture}"})

    def test_duplicate_profile_uses_run_local_cache_and_records_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence.txt"
            source.write_text("ico{cache_fixture}", encoding="utf-8")
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                profile_selector=duplicate_strings,
                runner=CommandRunner(),
                verbose=False,
            )
        hits = [event for event in report["events"] if event.get("type") == "cache-hit"]
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["original_artifact"], str(source.resolve()))
        tool_events = [entry for artifact in report["artifacts"] for entry in artifact["tools"]]
        self.assertEqual([entry["cache"]["hit"] for entry in tool_events if entry["analyzer"] == "strings-ascii"], [False, True])

    def test_cache_key_changes_when_input_bytes_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence.txt"
            report_dir = root / "report"
            source.write_text("ico{cache_before}", encoding="utf-8")
            first = run_scan(
                [str(source)],
                out_dir=report_dir,
                profile_selector=strings_only,
                runner=CommandRunner(),
                verbose=False,
            )
            source.write_text("ico{cache_after}", encoding="utf-8")
            second = run_scan(
                [str(source)],
                out_dir=report_dir,
                profile_selector=strings_only,
                runner=CommandRunner(),
                verbose=False,
            )
        self.assertFalse(any(event.get("type") == "cache-hit" for event in first["events"]))
        self.assertFalse(any(event.get("type") == "cache-hit" for event in second["events"]))
        self.assertEqual({item["value"] for item in second["candidates"]}, {"ico{cache_after}"})

    def test_scan_solves_all_local_ico_ctf_real_tasks(self):
        source_root = Path(os.environ.get("ICO_CTF_REAL_ROOT", str(Path.home() / "Downloads" / "ico_ctf_real")))
        if not (source_root / "flag_hashes.json").is_file():
            self.skipTest("local ico_ctf_real pack is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ico_ctf_real"
            shutil.copytree(
                source_root,
                root,
                ignore=shutil.ignore_patterns("ico-scan-runs", ".DS_Store"),
            )
            report = run_scan(
                [str(root)],
                out_dir=Path(directory) / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
            )
            report_text = (Path(directory) / "report" / "report.txt").read_text(encoding="utf-8")
            self.assertIn("Generic artifacts: 0", report_text)
            self.assertIn("Task artifacts: 10", report_text)
            self.assertIn("Derived artifacts: 18", report_text)
        self.assertEqual(report["summary"]["solved_tasks"], 10)
        self.assertEqual(report["summary"]["task_failure_count"], 0)
        self.assertEqual(report["summary"]["task_artifact_count"], 10)
        self.assertEqual(report["summary"]["derived_artifact_count"], 18)
        self.assertEqual(len(report["task_results"]), 10)
        self.assertEqual(sum(item["state"] == "hash-verified" for item in report["candidates"]), 10)

    def test_scan_solves_a_task_pack_when_given_only_the_zip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = "CTF{zip_pack_task}"
            task_root = root / "pack" / "01_xor_binary"
            task_root.mkdir(parents=True)
            (task_root / "task.txt").write_text("Single-byte XOR. Ключ 0..255.", encoding="utf-8")
            plaintext = b"prefix " + flag.encode() + b" suffix"
            (task_root / "evidence.bin").write_bytes(bytes(value ^ 0x5A for value in plaintext))
            (root / "pack" / "flag_hashes.json").write_text(
                json.dumps({"1": __import__("hashlib").sha256(flag.encode()).hexdigest()}),
                encoding="utf-8",
            )
            archive = root / "pack.zip"
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                for path in sorted((root / "pack").rglob("*")):
                    if path.is_file():
                        handle.write(path, path.relative_to(root).as_posix())

            report = run_scan(
                [str(archive)],
                out_dir=root / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
            )

        self.assertEqual(len(report["task_results"]), 1)
        self.assertEqual(report["task_results"][0]["status"], "hash-verified")
        self.assertEqual({item["value"] for item in report["candidates"]}, {flag})
        self.assertEqual(report["summary"]["candidate_count"], 1)

    def test_scan_discovers_ico_quals_pack_nested_in_7z_archive(self):
        if shutil.which("7zz") is None:
            self.skipTest("7zz is unavailable")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pack = root / "ico2027_qualifying_files"
            pack.mkdir()
            flag = "ico{seven_zip_qualifying_pack}"
            encoded = __import__("base64").b64encode(flag[::-1].encode()).decode()

            with zipfile.ZipFile(pack / "rev_zero.zip", "w") as archive:
                archive.writestr(
                    "rev_zero.html",
                    f"btoa(input.split('').reverse().join('')) === '{encoded}'",
                )
            with zipfile.ZipFile(pack / "Wolf_Protocol.zip", "w") as archive:
                archive.writestr("wolf_protocol.bin", b"\x7fELF" + b"\x00" * 128)
            with zipfile.ZipFile(pack / "Five_Shards.zip", "w"):
                pass
            with zipfile.ZipFile(pack / "Can_You_Hear_the_Flag.zip", "w") as archive:
                archive.writestr("challenge.png", b"\x89PNG\r\n\x1a\n")
            (pack / "chall").write_bytes(b"\x7fELF" + b"\x00" * 128)
            (pack / "chall(1)").write_bytes(b"\x7fELF" + b"\x00" * 128)
            (pack / "sha256_ext.py").write_text("# helper\n", encoding="utf-8")

            archive_path = root / "ico2027_qualifying_files.7z"
            built = subprocess.run(
                ["7zz", "a", "-t7z", str(archive_path), pack.name],
                cwd=root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=20,
            )
            self.assertEqual(built.returncode, 0, built.stdout)

            def profile_selector(classification):
                if classification.extension == ".png":
                    return [
                        ToolProfile(
                            "zsteg",
                            "ico-test-zsteg-must-be-skipped",
                            lambda path: ["ico-test-zsteg-must-be-skipped", str(path)],
                        )
                    ]
                return []

            report = run_scan(
                [str(archive_path)],
                out_dir=root / "report",
                profile_selector=profile_selector,
                runner=CommandRunner(),
            )

            challenge_artifact = next(
                item
                for item in report["artifacts"]
                if Path(item["path"]).name == "challenge.png"
            )

        self.assertEqual(report["summary"]["quals_task_count"], 10)
        self.assertEqual(report["summary"]["quals_candidate_task_count"], 1)
        self.assertEqual({item["value"] for item in report["candidates"]}, {flag})
        self.assertTrue(
            any(
                event.get("type") == "tool-skip"
                and event.get("analyzer") == "zsteg"
                and event.get("artifact") == challenge_artifact["path"]
                and "bounded OCR solver" in event.get("reason", "")
                for event in report["events"]
            )
        )

    def test_scan_discovers_real_ico_quals_pack_and_keeps_service_statuses(self):
        source_root = Path(os.environ.get("ICO_QUALS_ROOT", str(Path.home() / "Downloads" / "ico_quals")))
        if not (source_root / "rev_zero.zip").is_file() or not (source_root / "five_shards.zip").is_file():
            self.skipTest("local ico_quals pack is unavailable")
        index_files_exist = False
        answer_text = ""
        bundle_text = ""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ico_quals"
            shutil.copytree(
                source_root,
                root,
                ignore=shutil.ignore_patterns("ico-scan-runs", ".DS_Store", "__pycache__"),
            )
            report = run_scan(
                [str(root)],
                out_dir=Path(directory) / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
            )
            report_text = (Path(directory) / "report" / "report.txt").read_text(encoding="utf-8")
            self.assertIn("Task solvers:", report_text)
            answer_index = report["quals_answer_indexes"][0]
            index_files_exist = (
                Path(answer_index["json"]).is_file()
                and Path(answer_index["markdown"]).is_file()
                and Path(answer_index["text"]).is_file()
                and Path(answer_index["bundle"]).is_file()
            )
            answer_text = Path(answer_index["text"]).read_text(encoding="utf-8")
            bundle_text = Path(answer_index["bundle"]).read_text(encoding="utf-8")
        self.assertEqual(report["summary"]["quals_task_count"], 10)
        self.assertEqual(report["summary"]["quals_candidate_task_count"], 3)
        self.assertEqual(report["summary"]["quals_payload_ready_count"], 2)
        self.assertEqual(report["summary"]["quals_requires_session_count"], 4)
        self.assertEqual(report["summary"]["quals_review_count"], 1)
        self.assertEqual(report["summary"]["quals_historical_task_count"], 10)
        self.assertEqual(report["summary"]["quals_historical_answer_count"], 12)
        self.assertEqual(report["summary"]["quals_solution_task_count"], 10)
        self.assertEqual(report["summary"]["quals_solution_answer_count"], 12)
        self.assertEqual(report["summary"]["quals_historical_artifact_count"], 10)
        self.assertEqual(report["summary"]["reference_candidate_count"], 12)
        self.assertFalse(any(event.get("type") == "tool-error" for event in report["events"]))
        self.assertEqual(len(report["quals_answer_indexes"]), 1)
        answer_index = report["quals_answer_indexes"][0]
        self.assertEqual(answer_index["task_count"], 10)
        self.assertTrue(index_files_exist)
        self.assertIn("ico{R3v3R$3_fR0m_Z3r0}", answer_text)
        self.assertIn("ico{7519ee9f05a6a11ca96cc044c971b6ae}", answer_text)
        self.assertIn("backdoor", bundle_text)
        self.assertIn("journal-operator", bundle_text)
        self.assertTrue(all(item["state"] == "reference-only" for item in report["reference_candidates"]))
        self.assertEqual(
            {item["value"] for item in report["candidates"]},
            {
                "ico{R3v3R$3_fR0m_Z3r0}",
                "ico{5h4rd5_4r3_b3tt3r_t0g3th3r!}",
                "ico{w0lves_see_th3_h1dd3n_truth_42}",
            },
        )
        statuses = {item["task_id"]: item["status"] for item in report["quals_task_results"]}
        self.assertEqual(statuses["aezakmi"], "payload-ready")
        self.assertEqual(statuses["journal-operator"], "payload-ready")
        self.assertEqual(statuses["backdoor"], "requires-authorized-session")

    def test_fast_quals_scan_is_task_first_and_skips_generic_derivative_fanout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ico_quals"
            root.mkdir()
            (root / "rev_zero.zip").write_bytes(b"placeholder archive")
            (root / "wolf_protocol.zip").write_bytes(b"placeholder archive")
            report = run_scan(
                [str(root)],
                out_dir=Path(directory) / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
                mode="fast",
            )

        self.assertEqual(report["summary"]["processed_files"], 0)
        self.assertTrue(any(event.get("type") == "quals-generic-skip" for event in report["events"]))

    def test_scan_imports_ico_2027_writeup_as_reference_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ico_qualifying_round"
            root.mkdir()
            (root / "ico_ctf_writeup.md").write_text(
                "## 2. Wolf Protocol\n\nHistorical answer: `ico{wolf_static_reference}`\n",
                encoding="utf-8",
            )
            (root / "RULES.md").write_text(
                "The flag format is `ICO{...}`.\n",
                encoding="utf-8",
            )
            report = run_scan(
                [str(root)],
                out_dir=Path(directory) / "report",
                profile_selector=lambda _classification: [],
                runner=CommandRunner(),
            )
            self.assertEqual(report["candidates"], [])
            self.assertEqual(
                [(item["value"], item["state"]) for item in report["reference_candidates"]],
                [("ico{wolf_static_reference}", "reference-only")],
            )
            answer_rows = json.loads(
                Path(report["quals_answer_indexes"][0]["json"]).read_text(encoding="utf-8")
            )
            wolf_index = next(item for item in answer_rows if item["task_id"] == "wolf-protocol")
            wolf = next(item for item in report["quals_task_results"] if item["task_id"] == "wolf-protocol")
            self.assertEqual(wolf["candidates"], [])
            self.assertEqual(wolf_index["answer_state"], "historical-reference")
            statuses = {item["task_id"]: item["status"] for item in report["quals_task_results"]}
            self.assertEqual(statuses["aezakmi"], "missing-artifact")
            self.assertEqual(statuses["journal-operator"], "missing-artifact")
            self.assertEqual(report["summary"]["task_failure_count"], 0)

    def test_real_quals_cli_prints_one_flat_flag_list(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ico_quals"
            root.mkdir()
            (root / "rev_zero.zip").write_bytes(b"PK")
            (root / "wolf_protocol.zip").write_bytes(b"PK")
            report_dir = root / "report"
            answer_file = report_dir / "answers.txt"
            answer_file.parent.mkdir()
            answer_file.write_text("ico{first}\nICO{second}\n", encoding="utf-8")
            fake_report = {
                "report_dir": str(report_dir),
                "summary": {
                    "candidate_count": 1,
                    "quals_task_count": 10,
                },
                "quals_answer_indexes": [{"text": str(answer_file)}],
                "candidates": [{"value": "ico{first}"}],
                "quals_task_results": [],
            }
            output = StringIO()
            with patch("ico_scan.run_scan", return_value=fake_report), redirect_stdout(output):
                exit_code = main([str(root), "--out", str(report_dir)])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                f"REPORT: {report_dir}",
                "CANDIDATE VALUES: 1 (local evidence; not platform-confirmed)",
                "ico{first}",
            ],
        )

    def test_real_quals_cli_uses_flat_output_when_archive_discovery_is_deferred(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "ico2027_qualifying_files.7z"
            archive.write_bytes(b"7z placeholder")
            report_dir = root / "report"
            answer_file = report_dir / "answers.txt"
            answer_file.parent.mkdir()
            answer_file.write_text("ico{archive_candidate}\n", encoding="utf-8")
            fake_report = {
                "report_dir": str(report_dir),
                "summary": {
                    "candidate_count": 1,
                    "quals_task_count": 10,
                    "quals_solution_task_count": 10,
                    "quals_solution_answer_count": 12,
                    "quals_candidate_task_count": 1,
                    "quals_historical_answer_count": 12,
                    "reference_candidate_count": 12,
                },
                "quals_answer_indexes": [
                    {
                        "text": str(answer_file),
                        "markdown": str(answer_file),
                        "json": str(answer_file),
                        "bundle": str(answer_file),
                        "task_count": 10,
                        "historical_answer_count": 12,
                    }
                ],
                "candidates": [{"value": "ico{archive_candidate}"}],
                "quals_task_results": [],
            }
            output = StringIO()
            with patch("ico_scan.run_scan", return_value=fake_report), redirect_stdout(output):
                exit_code = main([str(archive), "--out", str(report_dir)])

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                f"REPORT: {report_dir}",
                "CANDIDATE VALUES: 1 (local evidence; not platform-confirmed)",
                "ico{archive_candidate}",
            ],
        )


if __name__ == "__main__":
    unittest.main()
