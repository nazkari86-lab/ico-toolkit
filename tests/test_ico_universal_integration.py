from __future__ import annotations

import base64
import gzip
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from ico_scan import main, run_scan
from ico_solver_engine import Detection, SolverRegistry, SolverResult
from ico_universal_registry import build_default_registry


class UniversalIntegrationTests(unittest.TestCase):
    def test_default_registry_has_stable_family_order(self):
        self.assertEqual(
            [solver.name for solver in build_default_registry().solvers],
            [
                "universal-data",
                "universal-media",
                "universal-forensics",
                "universal-crypto",
                "universal-reverse",
                "universal-web",
                "external-ctf-offline",
            ],
        )

    def test_unknown_task_words_do_not_create_a_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "evidence.txt"
            source.write_text("the task mentions flag and crypto but gives no encoded value", encoding="utf-8")
            report = run_scan(
                [str(source)],
                out_dir=root / "report",
                verbose=False,
                solver_registry=build_default_registry(),
                profile_selector=lambda _classification: [],
            )
        self.assertEqual(report["candidates"], [])
        self.assertTrue(report["summary"]["universal_solver_count"] >= 1)

    def test_base85_decoded_gzip_is_fed_back_to_the_solver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "crypto_base85"
            task.mkdir()
            (task / "task.txt").write_text(
                "Title: layered message\nCategory: Crypto\nRecover the original file hidden in this text.\n",
                encoding="utf-8",
            )
            expected = "ico{base85_gzip_pipeline_fixture}"
            (task / "payload.txt").write_bytes(base64.b85encode(gzip.compress(expected.encode(), mtime=0)))
            report = run_scan(
                [str(task)],
                out_dir=root / "report",
                verbose=False,
                max_depth=3,
                max_files=24,
                solver_registry=build_default_registry(),
                profile_selector=lambda _classification: [],
                mode="fast",
            )

        self.assertIn(expected, {candidate["value"] for candidate in report["candidates"]})
        self.assertTrue(any(event.get("type") == "derived-input-queued" for event in report["events"]))

    def test_generic_task_coverage_groups_candidates_by_task_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus = root / "corpus"
            alpha = corpus / "Crypto_alpha"
            beta = corpus / "Web_beta"
            alpha.mkdir(parents=True)
            beta.mkdir(parents=True)
            (alpha / "task.txt").write_text(
                "Title: alpha\nCategory: Crypto\nDifficulty: Easy\nDescription:\nRecover the message.\n",
                encoding="utf-8",
            )
            (alpha / "evidence.txt").write_text("cipher output: ico{alpha_candidate}\n", encoding="utf-8")
            (beta / "task.txt").write_text(
                "Title: beta\nCategory: Web\nDifficulty: Medium\nDescription:\nInspect the app.\n",
                encoding="utf-8",
            )
            (beta / "evidence.txt").write_text("no flag-shaped value here\n", encoding="utf-8")

            report = run_scan(
                [str(corpus)],
                out_dir=root / "report",
                verbose=False,
                solver_registry=build_default_registry(),
                profile_selector=lambda _classification: [],
            )

        coverage = {Path(item["task_root"]).name: item for item in report.get("task_coverage", [])}
        self.assertEqual(set(coverage), {"Crypto_alpha", "Web_beta"})
        self.assertEqual(coverage["Crypto_alpha"]["title"], "alpha")
        self.assertEqual(coverage["Crypto_alpha"]["status"], "candidate")
        self.assertEqual(coverage["Crypto_alpha"]["candidate_count"], 1)
        self.assertEqual(coverage["Web_beta"]["candidate_count"], 0)
        self.assertEqual(report["summary"]["challenge_task_count"], 2)

    def test_readme_ctf_task_is_grouped_and_dummy_flag_is_low_priority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            event = root / "ctfs" / "DownUnderCTF" / "2024"
            task = event / "crypto" / "v_for_vieta"
            task.mkdir(parents=True)
            (event / "README.md").write_text("Archive overview", encoding="utf-8")
            (task / "README.md").write_text(
                "Have this on loop while you solve.\nAuthor: wednesday\nExample format: CTF{example_flag}\n",
                encoding="utf-8",
            )
            (task / "server.py").write_text(
                'FLAG = os.getenv("FLAG", "CTF{dummy_flag}")\n',
                encoding="utf-8",
            )
            report = run_scan(
                [str(root)],
                out_dir=root / "report",
                verbose=False,
                solver_registry=build_default_registry(),
                profile_selector=lambda _classification: [],
            )

        coverage = report["task_coverage"]
        self.assertEqual(len(coverage), 1)
        self.assertEqual(coverage[0]["title"], "v_for_vieta")
        self.assertEqual(coverage[0]["category"], "Crypto")
        self.assertEqual(coverage[0]["task_file"], str((task / "README.md").resolve()))
        self.assertIn("Have this on loop", coverage[0]["description"])
        self.assertEqual(coverage[0]["status"], "candidate-review")
        values = {candidate["value"]: candidate for candidate in report["candidates"]}
        self.assertEqual(set(values), {"CTF{dummy_flag}"})
        self.assertEqual(values["CTF{dummy_flag}"]["triage"], "likely-placeholder")
        self.assertEqual(report["summary"]["likely_placeholder_count"], 1)
        contexts = [item["evidence_context"] for item in report["universal_results"] if "evidence_context" in item]
        self.assertTrue(any("Have this on loop" in context.get("task_text", "") for context in contexts))

    def test_task_coverage_preserves_authorized_session_requirement(self):
        class SessionSolver:
            name = "fixture-session-solver"
            category = "crypto"

            def detect(self, context):
                if context.input_path.name == "server.py":
                    return Detection(self.name, self.category, 100, "runtime values are supplied by the task service")
                return None

            def solve(self, context):
                return SolverResult(
                    self.name,
                    self.category,
                    "requires-authorized-session",
                    steps=[{"name": "session-bound-input", "status": "blocked", "details": {"reason": "runtime challenge value is absent"}}],
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "Crypto_session_task"
            task.mkdir()
            (task / "task.txt").write_text(
                "Title: session_task\nCategory: Crypto\nDescription:\nThe challenge is generated at runtime.\n",
                encoding="utf-8",
            )
            (task / "server.py").write_text("print('runtime challenge')\n", encoding="utf-8")
            report = run_scan(
                [str(root)],
                out_dir=root / "report",
                verbose=False,
                solver_registry=SolverRegistry([SessionSolver()]),
                profile_selector=lambda _classification: [],
            )

        self.assertEqual(report["task_coverage"][0]["status"], "requires-authorized-session")
        self.assertEqual(report["summary"]["challenge_requires_authorized_session_task_count"], 1)
        self.assertEqual(report["summary"]["challenge_review_task_count"], 0)

    def test_task_coverage_explains_when_web_source_needs_missing_service_assets(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "corpus"
            task = corpus / "Web_minigolf"
            task.mkdir(parents=True)
            (task / "task.txt").write_text(
                "Title: minigolf\nCategory: Web\nDifficulty: Easy-Medium\nDescription:\nFlask template challenge.\n",
                encoding="utf-8",
            )
            (task / "app.py").write_text(
                'from flask import Flask, render_template_string, request\n'
                'import html\n'
                'app = Flask(__name__)\n'
                'blacklist = ["{{", "}}", "[", "]", "_"]\n'
                'txt = html.escape(request.args["txt"])\n'
                'return render_template_string(txt)\n',
                encoding="utf-8",
            )
            report = run_scan(
                [str(corpus)],
                out_dir=Path(directory) / "report",
                verbose=False,
                solver_registry=build_default_registry(),
                profile_selector=lambda _classification: [],
            )

        coverage = report["task_coverage"][0]
        self.assertEqual(coverage["status"], "candidate-review")
        self.assertTrue(any("include target" in note for note in coverage["analysis_notes"]))

    def test_task_manifest_flag_format_is_not_reported_as_a_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "Forensics_example"
            task.mkdir()
            (task / "task.txt").write_text(
                "Title: example\nCategory: Forensics\nDescription:\nFlag format: ictf{[a-z_]*}\n",
                encoding="utf-8",
            )
            (task / "evidence.txt").write_text("plain evidence without a flag\n", encoding="utf-8")
            report = run_scan(
                [str(root)],
                out_dir=root / "report",
                verbose=False,
                solver_registry=build_default_registry(),
                profile_selector=lambda _classification: [],
            )

        self.assertNotIn("ictf{[a-z_]*}", {candidate["value"] for candidate in report["candidates"]})

    def test_real_pack_answers_remain_hash_verified_without_source_mutation(self):
        source = Path(os.environ.get("ICO_CTF_REAL_ROOT", str(Path.home() / "Downloads" / "ico_ctf_real")))
        if not source.is_dir():
            self.skipTest("local real corpus is unavailable")
        before = {path: path.read_bytes() for path in source.rglob("*") if path.is_file() and "ico-scan-runs" not in path.parts}
        with tempfile.TemporaryDirectory() as directory:
            report = run_scan([str(source)], out_dir=Path(directory) / "report", verbose=False, solver_registry=build_default_registry(), profile_selector=lambda _classification: [])
        self.assertEqual(report["summary"]["solved_tasks"], 10)
        self.assertEqual(sum(item.get("state") == "hash-verified" for item in report["candidates"]), 10)
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_synthetic_unresolved_regressions_are_now_covered(self):
        source = Path(__file__).resolve().parents[1] / "benchmarks" / "ico_synthetic_unresolved"
        if not source.is_dir():
            self.skipTest("synthetic regression fixtures are unavailable")
        before = {path: path.read_bytes() for path in source.rglob("*") if path.is_file()}
        with tempfile.TemporaryDirectory() as directory:
            report = run_scan(
                [str(source)],
                out_dir=Path(directory) / "report",
                verbose=False,
                solver_registry=build_default_registry(),
                profile_selector=lambda _classification: [],
            )
        values = {item["value"] for item in report["candidates"]}
        self.assertEqual(
            values,
            {"ico{bench_crypto_easy_caesar}", "ico{bench_forensics_hard_dns}"},
        )
        self.assertTrue(
            any(
                item.get("solver") == "universal-reverse" and item.get("status") == "payload-ready"
                for item in report["universal_results"]
            )
        )
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_cli_surfaces_synthetic_payload_ready_artifact_without_unsupported_noise(self):
        source = Path(__file__).resolve().parents[1] / "benchmarks" / "ico_synthetic_unresolved"
        if not source.is_dir():
            self.skipTest("synthetic regression fixtures are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            output = StringIO()
            report_dir = Path(directory) / "report"
            with redirect_stdout(output):
                exit_code = main(
                    [
                        "--mode",
                        "fast",
                        "--max-depth",
                        "2",
                        "--max-files",
                        "100",
                        "--timeout",
                        "10",
                        "--out",
                        str(report_dir),
                        str(source),
                    ]
                )
        text = output.getvalue()
        self.assertEqual(exit_code, 0)
        self.assertIn("ico{bench_crypto_easy_caesar}", text)
        self.assertIn("ico{bench_forensics_hard_dns}", text)
        self.assertIn("PAYLOAD-READY: universal-reverse (chall.elf)", text)
        self.assertIn("static-pwn/chall.elf.ret2win.payload", text)
        self.assertNotIn("UNSUPPORTED:", text)



if __name__ == "__main__":
    unittest.main()
