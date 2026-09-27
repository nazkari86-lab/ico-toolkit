from __future__ import annotations

import tempfile
import unittest
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ico_scan_core import (
    Classification,
    CommandRunner,
    FlagMatcher,
    RunnerPolicy,
    classify,
    encoded_views,
    sha256_file,
    single_byte_xor_views,
)


class FakeRunner:
    def __init__(self, outputs: dict[tuple[str, ...], str]) -> None:
        self.outputs = outputs

    def run(self, args, *, cwd, timeout, log_name):
        from ico_scan_core import CommandResult

        key = tuple(str(item) for item in args)
        return CommandResult(args=list(key), returncode=0, stdout=self.outputs.get(key, ""))


class CoreTests(unittest.TestCase):
    def test_runner_policy_requires_positive_limits(self):
        with self.assertRaises(ValueError):
            RunnerPolicy(max_cpu_seconds=0)
        with self.assertRaises(ValueError):
            RunnerPolicy(max_memory_bytes=-1)
        with self.assertRaises(ValueError):
            RunnerPolicy(max_output_bytes=0)

    def test_runner_policy_bounds_captured_output(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = CommandRunner(
                Path(directory),
                policy=RunnerPolicy(max_output_bytes=32),
            )
            result = runner.run(
                [sys.executable, "-c", "print('ico{' + 'x' * 200 + '}')"],
                cwd=Path(directory),
                timeout=5,
                log_name="bounded-output",
            )
        self.assertLessEqual(len(result.stdout.encode("utf-8")), 32 + 64)
        self.assertIn("output truncated", result.stdout)

    def test_command_runner_log_paths_are_unique_when_called_concurrently(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = CommandRunner(Path(directory) / "commands")
            with ThreadPoolExecutor(max_workers=6) as executor:
                results = list(
                    executor.map(
                        lambda index: runner.run(
                            [sys.executable, "-c", f"print('run-{index}')"],
                            cwd=Path(directory),
                            timeout=5,
                            log_name="parallel",
                        ),
                        range(12),
                    )
                )
            paths = [result.log_path for result in results]
            self.assertEqual(len(paths), len(set(paths)))
            self.assertTrue(all(result.returncode == 0 for result in results))
            self.assertEqual(len(list((Path(directory) / "commands").glob("*.json"))), 12)

    def test_flag_matcher_requires_brace_form(self):
        matcher = FlagMatcher()
        hits = matcher.scan("noise flag word\nico{demo_123}", source="x", analyzer="strings")
        self.assertEqual(hits[0]["value"], "ico{demo_123}")
        self.assertEqual(matcher.scan("flag without braces", source="x", analyzer="strings"), [])

    def test_flag_matcher_recognizes_common_external_ctf_prefixes(self):
        values = {
            "DUCTF{down_under_fixture}",
            "picoCTF{pico_fixture}",
            "HTB{hack_the_box_fixture}",
            "SECCON{seccon_fixture}",
        }
        text = "\n".join(sorted(values) + ["txtCTF{archive_suffix_fixture}"])
        hits = FlagMatcher().scan(text, source="x", analyzer="test")
        self.assertEqual({hit["value"] for hit in hits}, values)

    def test_custom_pattern_is_added_to_default_pattern(self):
        matcher = FlagMatcher([r"KEY\[[A-Z0-9]+\]"])
        values = {hit["value"] for hit in matcher.scan("ico{default} KEY[ABC123]", source="x", analyzer="test")}
        self.assertEqual(values, {"ico{default}", "KEY[ABC123]"})

    def test_flag_matcher_marks_obvious_templates_without_dropping_candidates(self):
        values = [
            "ICO{...}",
            "ICO{REDACTED_4}",
            "ICO{example_flag1}",
            "ICO{fake_flag}",
            "ICO{client_side_flag_here}",
            "ICO{network_flag}",
            "ICO{just_a_sanity_check_flag_for_you}",
            "ictf{[a-z_]*}",
            "FLAG{\x10X\x11}",
            "FLAG{N}",
        ]
        hits = FlagMatcher().scan("\n".join(values), source="x", analyzer="test")
        by_value = {hit["value"]: hit for hit in hits}

        self.assertEqual(set(by_value), set(values))
        for value in values[:5]:
            self.assertEqual(by_value[value]["triage"], "likely-placeholder")
            self.assertTrue(by_value[value]["triage_reason"])
        for value in values[5:7]:
            self.assertEqual(by_value[value]["triage"], "candidate")
            self.assertNotIn("triage_reason", by_value[value])
        self.assertEqual(by_value[values[7]]["triage"], "likely-placeholder")
        self.assertEqual(by_value[values[7]]["triage_reason"], "flag body contains regular-expression syntax")
        for value in values[8:]:
            self.assertEqual(by_value[value]["triage"], "likely-noise")
            self.assertTrue(by_value[value]["triage_reason"])
        self.assertEqual(by_value[values[8]]["triage_reason"], "contains non-printable characters")
        self.assertEqual(by_value[values[9]]["triage_reason"], "flag body is unusually short (1 character)")

    def test_flag_matcher_triages_dummy_flag_but_keeps_the_evidence(self):
        hits = FlagMatcher().scan("CTF{dummy_flag}", source="server.py", analyzer="strings")

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["value"], "CTF{dummy_flag}")
        self.assertEqual(hits[0]["state"], "candidate")
        self.assertEqual(hits[0]["triage"], "likely-placeholder")
        self.assertIn("dummy", hits[0]["triage_reason"].lower())

    def test_flag_matcher_triages_test_templates_and_repeated_x_but_keeps_real_values(self):
        placeholders = [
            "DUCTF{testflag}",
            "DUCTF{test_flag_real_flag_on_instance}",
            "DUCTF{XXXXXXXXXXXXXXXXXXXXXXXXX}",
        ]
        real = "CTF{test_of_the_array_generator}"
        hits = FlagMatcher().scan("\n".join(placeholders + [real]), source="server.py", analyzer="strings")
        by_value = {hit["value"]: hit for hit in hits}
        self.assertEqual(set(by_value), set(placeholders + [real]))
        for value in placeholders:
            self.assertEqual(by_value[value]["triage"], "likely-placeholder")
        self.assertEqual(by_value[real]["triage"], "candidate")

    def test_classifier_uses_file_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "note.txt"
            path.write_text("hello", encoding="utf-8")
            runner = FakeRunner(
                {
                    ("file", "--brief", "--mime-type", str(path)): "text/plain\n",
                    ("file", "--brief", str(path)): "ASCII text\n",
                }
            )
            result = classify(path, runner)
        self.assertEqual(result.kind, "text")
        self.assertEqual(result.mime, "text/plain")

    def test_magic_classification_does_not_depend_on_file_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.bin"
            path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 12)
            result = classify(path, FakeRunner({}))
        self.assertEqual(result.kind, "png")

    def test_memory_dump_extension_selects_memory_kind(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.dmp"
            path.write_bytes(b"memory bytes")
            runner = FakeRunner(
                {
                    ("file", "--brief", "--mime-type", str(path)): "application/octet-stream\n",
                    ("file", "--brief", str(path)): "data\n",
                }
            )
            result = classify(path, runner)
        self.assertEqual(result.kind, "memory")

    def test_runner_records_missing_command(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = CommandRunner(Path(directory))
            result = runner.run(["definitely-not-a-real-command"], cwd=Path(directory), log_name="missing")
        self.assertTrue(result.missing)
        self.assertFalse(result.ok)
        self.assertTrue(result.log_path)

    def test_runner_uses_no_shell_and_returns_output(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = CommandRunner(Path(directory))
            result = runner.run(["printf", "ico{runner_test}"], cwd=Path(directory), log_name="printf")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "ico{runner_test}")

    def test_runner_records_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = CommandRunner(Path(directory))
            result = runner.run(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                cwd=Path(directory),
                timeout=0.1,
                log_name="timeout",
            )
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)

    def test_sha256_is_stable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.bin"
            path.write_bytes(b"abc")
            self.assertEqual(
                sha256_file(path),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_single_byte_xor_views_find_known_prefix_at_any_offset(self):
        plaintext = b"noise CTF{xor_fixture} tail"
        key = 0x5A
        ciphertext = bytes(value ^ key for value in plaintext)
        views = single_byte_xor_views(ciphertext, prefix=b"CTF{")
        self.assertEqual(len(views), 1)
        self.assertEqual(views[0]["key"], key)
        self.assertEqual(views[0]["offset"], plaintext.index(b"CTF{"))
        self.assertEqual(views[0]["plaintext"], plaintext)

    def test_encoded_views_decode_common_nested_representations(self):
        import base64

        flag = b"CTF{nested_encoding}"
        source = b"b64=" + base64.b64encode(flag) + b" hex=" + flag.hex().encode() + b" url=%43%54%46%7Burl%7D"
        views = encoded_views(source)
        self.assertIn(("base64", flag), {(item["encoding"], item["decoded"]) for item in views})
        self.assertIn(("hex", flag), {(item["encoding"], item["decoded"]) for item in views})
        self.assertIn(("url", b"CTF{url}"), {(item["encoding"], item["decoded"]) for item in views})


if __name__ == "__main__":
    unittest.main()
