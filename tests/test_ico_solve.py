from __future__ import annotations

import base64
import hashlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from ico_solve import (
    SolveCandidate,
    SolveReport,
    SolveSlot,
    _run_adapter_derived_pipeline,
    _write_gpt_handoffs,
    _scan_budget_for_deadline,
    _slot_for_artifact,
    discover_solve_slots,
    format_stdout,
    rank_candidates,
    select_flags,
    solve_inputs,
)
from ico_scan_core import Classification, CommandRunner
from ico_solver_engine import SolverLimits
from ico_solver_engine import SolverResult
from ico_tool_adapters import AdapterEvidence, AdapterProfile
from ico_evidence_store import EvidenceStore


class IcoSolveModelTests(unittest.TestCase):
    def test_global_deadline_reserves_time_for_adapter_workers(self):
        self.assertEqual(_scan_budget_for_deadline(180, "fast"), 120)
        self.assertEqual(_scan_budget_for_deadline(180, "full"), 117)
        self.assertEqual(_scan_budget_for_deadline(20, "fast"), 13)

    def test_discovery_excludes_walkthrough_and_generated_control_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ico_quals"
            root.mkdir()
            (root / "ICO_full_walkthrough.md").write_text("ico{historical_only}", encoding="utf-8")
            (root / "ICO_self_solve_manual.md").write_text("ico{manual_only}", encoding="utf-8")
            evidence = root / "evidence.bin"
            evidence.write_bytes(b"opaque")

            slots = discover_solve_slots([root], Path(directory) / "workspace", SolverLimits())

        self.assertEqual(len(slots), 1)
        self.assertEqual([path.name for path in slots[0].paths], ["evidence.bin"])

    def test_artifact_slot_prefers_sibling_task_directory_over_story_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "quals"
            task_root = root / "rev_zero"
            task_root.mkdir(parents=True)
            archive = root / "rev_zero.zip"
            archive.write_bytes(b"archive fixture")
            broad = SolveSlot("story_01/misc", "story_01", "misc", "unknown", (archive,), root=root)
            task = SolveSlot("story_02/reverse", "story_02", "reverse", "unknown", (task_root / "rev_zero.html",), root=task_root)

            selected = _slot_for_artifact(archive, (broad, task))

        self.assertIsNotNone(selected)
        self.assertEqual(selected.task_id, "story_02/reverse")

    def test_discovery_reads_story_family_and_difficulty(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "story_01" / "crypto_medium"
            root.mkdir(parents=True)
            (root / "task.txt").write_text(
                "Family: Crypto\nDifficulty: Medium\nDecode the supplied value.\n",
                encoding="utf-8",
            )
            (root / "cipher.txt").write_text("ico{fixture}", encoding="utf-8")
            slots = discover_solve_slots([root], Path(directory) / "workspace", SolverLimits())

        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0].story_id, "story_01")
        self.assertEqual(slots[0].family, "crypto")
        self.assertEqual(slots[0].difficulty, "medium")
        self.assertIn((root / "cipher.txt").resolve(), slots[0].paths)

    def test_nested_archive_is_discovered_as_one_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "story_02_web.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("web/task.txt", "Web\nEasy\n")
                handle.writestr("web/response.txt", "ico{nested_fixture}")
            slots = discover_solve_slots([archive], root / "workspace", SolverLimits())

        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0].family, "web")
        self.assertEqual(slots[0].story_id, "story_02")
        self.assertTrue(any(path.name == "response.txt" for path in slots[0].paths))

    def test_rank_prefers_verified_and_corroborated_values(self):
        slot = SolveSlot("story_01/crypto", "story_01", "crypto", "easy", ())
        result = type(
            "Result",
            (),
            {
                "candidates": [
                    {"value": "ico{same}", "state": "candidate", "triage": "candidate", "analyzer": "a"},
                    {"value": "ico{same}", "state": "candidate", "triage": "candidate", "analyzer": "b"},
                    {"value": "ico{verified}", "state": "hash-verified", "triage": "candidate", "analyzer": "c"},
                    {"value": "ico{dummy_flag}", "state": "hash-verified", "triage": "likely-placeholder", "analyzer": "d"},
                ],
                "solver": "fixture",
                "category": "crypto",
            },
        )()
        ranked = rank_candidates([result], [slot])
        self.assertEqual(ranked[0].value, "ico{verified}")
        self.assertNotIn("ico{dummy_flag}", {item.value for item in ranked})

    def test_format_stdout_is_copy_ready(self):
        candidates = (
            SolveCandidate("ico{a}", "story_01/crypto", "story_01", "crypto", "candidate", 100, ("a",), "candidate"),
            SolveCandidate("ico{b}", "story_01/web", "story_01", "web", "candidate", 100, ("b",), "candidate"),
        )
        report = SolveReport((), candidates, ())
        self.assertEqual(format_stdout(report), "story_01/web\tico{b}\nstory_01/crypto\tico{a}\n")


class IcoSolvePipelineTests(unittest.TestCase):
    def test_prompt_solver_is_wired_into_solve_inputs_and_keeps_task_root_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "task_01" / "crypto_medium"
            root.mkdir(parents=True)
            (root / "task.txt").write_text(
                "External ICO 2025 final task 1\nFamily: crypto\n"
                "ECB repeated blocks; choose 1, 2, 3, or 4.\n",
                encoding="utf-8",
            )
            report = solve_inputs([root], debug_dir=Path(directory) / "debug", mode="fast")

        self.assertEqual(report.slots[0].story_id, "task_01")
        selected = select_flags(report)
        self.assertEqual([(item.task_id, item.value) for item in selected], [("task_01/crypto", "3")])
        audit = report.metadata["prompt_solver_audits"]["task_01/crypto"]
        self.assertEqual(audit["status"], "candidate")
        self.assertEqual(audit["candidates"][0]["method"], "ecb-repeated-block-inference")
        self.assertEqual(audit["artifacts"], [])

    def test_solve_inputs_recovers_nested_base64_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "crypto"
            root.mkdir()
            (root / "task.txt").write_text("Crypto\nDecode base64\n", encoding="utf-8")
            value = base64.b64encode(b"ico{base64_fixture}").decode()
            (root / "cipher.txt").write_text(value, encoding="ascii")
            debug = Path(directory) / "debug"
            report = solve_inputs([root], debug_dir=debug, mode="fast")
            self.assertIn("ico{base64_fixture}", {candidate.value for candidate in select_flags(report)})
            self.assertTrue((debug / "report.json").is_file())
            self.assertEqual(json.loads((debug / "report.json").read_text(encoding="utf-8"))["schema_version"], 1)
            self.assertEqual(report.metadata["runner_policy"]["max_output_bytes"], 1_048_576)

    def test_explicit_crypto_chain_flows_from_classical_decode_to_data_solver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "story_04" / "crypto_medium"
            root.mkdir(parents=True)
            (root / "task.txt").write_text(
                "Family: Crypto\nDifficulty: Medium\n"
                "Decode the ciphertext with ROT13, then decode the result with Base64.\n",
                encoding="utf-8",
            )
            encoded = base64.b64encode(b"ico{cross_solver_chain}")
            rot13_table = bytes.maketrans(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            )
            (root / "cipher.txt").write_bytes(b"cipher=" + encoded.translate(rot13_table))

            report = solve_inputs([root], debug_dir=Path(directory) / "debug", mode="fast", workers=1)
            scan_report = json.loads((Path(directory) / "debug" / "scan" / "report.json").read_text())

        self.assertEqual(
            [(candidate.task_id, candidate.value) for candidate in select_flags(report)],
            [("story_04/crypto", "ico{cross_solver_chain}")],
        )
        audit = report.metadata["prompt_solver_audits"]["story_04/crypto"]
        self.assertNotEqual(audit["status"], "failed")
        self.assertTrue(
            any(event.get("type") == "derived-input-queued" and event.get("solver") == "universal-crypto" for event in scan_report.get("events", [])),
            scan_report.get("events", []),
        )

    def test_prompt_solver_artifacts_enter_registry_and_gpt_handoff(self):
        class PromptArtifactRegistry:
            def __init__(self):
                self.visited = []

            def solve(self, context):
                self.visited.append(context.input_path.name)
                if context.input_path.name == "vigenere-base64-decoded.bin":
                    return [SolverResult(
                        "prompt-derived-check",
                        "crypto",
                        "candidate",
                        steps=[{"name": "fixture-forward-check", "status": "ok"}],
                        candidates=[{"value": "ico{prompt_derived_chain}", "state": "candidate"}],
                    )]
                return []

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task_root = root / "story_03" / "crypto_medium"
            task_root.mkdir(parents=True)
            token = base64.b64encode(b"ico{prompt_derived_chain}").decode("ascii")
            task = task_root / "task.txt"
            task.write_text(
                "External ICO 2025 final task 3. Family: crypto. "
                f"Use Vigenere with keyword A. Ciphertext: {token}\n",
                encoding="utf-8",
            )
            debug = root / "debug"
            registry = PromptArtifactRegistry()
            with (
                patch("ico_solve.run_scan", return_value={"summary": {}, "candidates": [], "artifacts": []}),
                patch("ico_solve.build_default_registry", return_value=registry),
                patch("ico_solve.run_adapter_profiles", return_value=[]),
                patch("ico_solve.classify", return_value=Classification("application/octet-stream", "data", "data", ".bin")),
            ):
                report = solve_inputs([task_root], debug_dir=debug, mode="fast", workers=1, deadline_seconds=10)

            handoff = report.metadata["gpt_handoffs"][0]
            prompt = Path(handoff["prompt"]).read_text(encoding="utf-8")
            with zipfile.ZipFile(handoff["evidence_bundle"]) as bundle:
                bundle_names = bundle.namelist()

        self.assertIn("vigenere-base64-decoded.bin", registry.visited)
        self.assertIn("ico{prompt_derived_chain}", {item.value for item in report.candidates})
        self.assertIn("no hash/checker/service-confirmed answer", prompt)
        self.assertTrue(any("vigenere-base64-decoded.bin" in name for name in bundle_names))
        self.assertGreaterEqual(report.metadata["recursive_adapter_artifact_count"], 1)

    def test_collected_adapter_file_is_reprocessed_by_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "story_01" / "forensics"
            root.mkdir(parents=True)
            (root / "task.txt").write_text("Family: Forensics\nDifficulty: Easy\n", encoding="utf-8")
            source = root / "evidence.bin"
            source.write_bytes(b"opaque")
            code = (
                "import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.mkdir(parents=True,exist_ok=True); "
                "(p/'derived.txt').write_text('ico{derived_registry}', encoding='utf-8')"
            )
            profile = AdapterProfile(
                "fixture-collector",
                sys.executable,
                lambda _path, out: [sys.executable, "-c", code, str(out / "derived-tree")],
                timeout=5,
                stage="specialized",
                collect_dir=lambda _path, out: out / "derived-tree",
            )
            debug = Path(directory) / "debug"
            with patch("ico_tool_adapters.profiles_for_classification", return_value=(profile,)):
                report = solve_inputs([root], debug_dir=debug, mode="full")
            self.assertEqual({candidate.value for candidate in select_flags(report)}, {"ico{derived_registry}"})
            self.assertGreaterEqual(report.metadata["derived_solver_result_count"], 1)

    def test_adapter_artifacts_are_reprocessed_recursively_with_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "story_01" / "forensics"
            root.mkdir(parents=True)
            (root / "task.txt").write_text("Family: Forensics\nDifficulty: Easy\n", encoding="utf-8")
            source = root / "evidence.bin"
            source.write_bytes(b"\x00opaque-root")
            code = (
                "import base64,pathlib,sys; "
                "source=pathlib.Path(sys.argv[1]); dest=pathlib.Path(sys.argv[2]); "
                "dest.mkdir(parents=True,exist_ok=True); "
                "name='nested.bin' if source.read_bytes()==b'\\x00opaque-root' else 'payload.txt'; "
                "data=b'\\x00opaque-child' if name=='nested.bin' else base64.b64encode(b'ico{recursive_adapter}') ; "
                "(dest/name).write_bytes(data)"
            )

            def collect_dir(path, output):
                digest = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
                return output / f"recursive-{digest}"

            profile = AdapterProfile(
                "recursive-fixture",
                sys.executable,
                lambda path, out: [sys.executable, "-c", code, str(path), str(collect_dir(path, out))],
                timeout=5,
                stage="specialized",
                collect_dir=collect_dir,
            )
            debug = Path(directory) / "debug"

            def profiles_for_fixture(classification):
                return (profile,) if classification.kind == "data" else ()

            def fake_scan(*_args, **_kwargs):
                return {"summary": {}, "candidates": []}

            with (
                patch("ico_tool_adapters.profiles_for_classification", side_effect=profiles_for_fixture),
                patch("ico_solve.run_scan", side_effect=fake_scan),
            ):
                report = solve_inputs([root], debug_dir=debug, mode="full", workers=1)

        selected = select_flags(report)
        self.assertEqual([(candidate.task_id, candidate.value) for candidate in selected], [
            ("story_01/forensics", "ico{recursive_adapter}")
        ])
        self.assertGreaterEqual(report.metadata["adapter_count"], 2)
        self.assertEqual(report.metadata["recursive_adapter_artifact_count"], 2)
        self.assertEqual(report.metadata["recursive_adapter_round_count"], 2)

    def test_registry_derived_outputs_are_processed_in_the_next_bounded_round(self):
        class ChainedRegistry:
            def __init__(self):
                self.visited = []

            def solve(self, context):
                self.visited.append(context.input_path.name)
                if context.input_path.name == "stage-one.bin":
                    child = context.report_dir / "stage-two.txt"
                    child.parent.mkdir(parents=True, exist_ok=True)
                    child.write_text("second-stage evidence", encoding="utf-8")
                    return [SolverResult("stage-one", "misc", "derived", derived_inputs=[str(child)])]
                if context.input_path.name == "stage-two.txt":
                    return [SolverResult(
                        "stage-two", "misc", "candidate",
                        candidates=[{"value": "ico{registry_next_round}", "state": "candidate"}],
                    )]
                return []

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task_root = root / "story_01" / "misc"
            task_root.mkdir(parents=True)
            task = task_root / "task.txt"
            task.write_text("Family: Misc\n", encoding="utf-8")
            original = task_root / "seed.dat"
            original.write_bytes(b"seed")
            derived_root = root / "derived-solvers"
            adapter_root = root / "adapter-artifacts"
            seed = adapter_root / "prompt-seed" / "stage-one.bin"
            seed.parent.mkdir(parents=True)
            seed.write_bytes(b"first-stage evidence")
            slot = SolveSlot("story_01/misc", "story_01", "misc", "unknown", (original,), task, task_root)
            registry = ChainedRegistry()
            with (
                patch("ico_solve.build_default_registry", return_value=registry),
                patch("ico_solve.classify", return_value=Classification("application/octet-stream", "data", "data", ".bin")),
                patch("ico_solve.run_adapter_profiles", return_value=[]),
            ):
                evidence, results, stats = _run_adapter_derived_pipeline(
                    [],
                    seed_derived_inputs=[(task, (str(seed),))],
                    slots=[slot],
                    report_dir=derived_root,
                    adapter_output_dir=adapter_root,
                    limits=SolverLimits(max_bytes=1024 * 1024, max_files=10, max_depth=3, timeout_seconds=1),
                    runner=CommandRunner(root / "commands"),
                    mode="fast",
                    workers=1,
                    deadline_seconds=10,
                    cache_dir=None,
                    context_hashes={},
                )

        self.assertEqual(registry.visited, ["stage-one.bin", "stage-two.txt"])
        self.assertEqual(stats["recursive_artifact_count"], 2)
        self.assertEqual(stats["recursive_round_count"], 2)
        self.assertEqual(results[-1].candidates[0]["task_id"], "story_01/misc")
        self.assertEqual(evidence, [])

    def test_unresolved_task_gets_copy_ready_gpt_handoff_and_bounded_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task_root = root / "story_03" / "forensics"
            task_root.mkdir(parents=True)
            task = task_root / "task.txt"
            task.write_text("Family: Forensics\nInspect the supplied image and recover the hidden message.\n", encoding="utf-8")
            image = task_root / "evidence.bin"
            image.write_bytes(b"synthetic image bytes")
            expected_hashes = {hashlib.sha256(task.read_bytes()).hexdigest(), hashlib.sha256(image.read_bytes()).hexdigest()}
            slot = SolveSlot("story_03/forensics", "story_03", "forensics", "hard", (image,), task, task_root)
            workspace = root / "workspace"
            workspace.mkdir()
            out_dir = root / "handoffs"
            handoffs = _write_gpt_handoffs(
                out_dir,
                slots=[slot],
                candidates=[],
                limits=SolverLimits(max_bytes=1024 * 1024, max_files=10, max_depth=3, timeout_seconds=1),
                workspace=workspace,
                scan_report={"summary": {"candidate_count": 0}, "task_results": [], "quals_task_results": [], "universal_results": []},
                prompt_audits={},
                adapter_evidence=[],
                derived_solver_results=[],
                errors=["one optional adapter was unavailable"],
            )

            prompt_path = Path(handoffs[0]["prompt"])
            prompt = prompt_path.read_text(encoding="utf-8")
            with zipfile.ZipFile(handoffs[0]["evidence_bundle"]) as bundle:
                names = bundle.namelist()
                manifest = json.loads(bundle.read("evidence-manifest.json"))

        self.assertEqual(len(handoffs), 1)
        self.assertIn("No flag-shaped candidate was produced", prompt)
        self.assertIn("Best next step", prompt)
        self.assertIn("optional adapter was unavailable", prompt)
        self.assertEqual(len(manifest["files"]), 2)
        self.assertEqual(
            {item["sha256"] for item in manifest["files"]},
            expected_hashes,
        )
        self.assertIn("gpt-4.1-handoff.md", names)
        self.assertEqual(sum(name.startswith("files/") for name in names), 2)

    def test_solve_inputs_reuses_scanner_classifications_by_content(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "story_03" / "forensics"
            root.mkdir(parents=True)
            task = root / "task.txt"
            evidence = root / "evidence.txt"
            task.write_text("Family: Forensics\nInspect the supplied evidence.\n", encoding="utf-8")
            evidence.write_text("no flag here\n", encoding="utf-8")
            scanner_copy = Path(directory) / "scanner-copy" / "evidence.txt"
            scanner_copy.parent.mkdir()
            scanner_copy.write_text(evidence.read_text(encoding="utf-8"), encoding="utf-8")
            stat = scanner_copy.stat()
            scanner_artifacts = [{
                "path": str(scanner_copy.resolve()),
                "sha256": hashlib.sha256(scanner_copy.read_bytes()).hexdigest(),
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "classification": {
                    "mime": "text/plain",
                    "description": "ASCII text",
                    "kind": "text",
                    "extension": scanner_copy.suffix,
                },
            }]

            with (
                patch("ico_solve.run_scan", return_value={"summary": {}, "candidates": [], "artifacts": scanner_artifacts}),
                patch("ico_solve.classify", side_effect=AssertionError("scanner classification should be reused")) as classify_again,
                patch("ico_tool_adapters.profiles_for_classification", return_value=()),
            ):
                report = solve_inputs(
                    [root],
                    debug_dir=Path(directory) / "debug",
                    mode="fast",
                    workers=1,
                    deadline_seconds=10,
                )

        classify_again.assert_not_called()
        self.assertEqual(report.metadata["classification_cache_reused"], 1)
        self.assertEqual(report.metadata["classification_cache_reused_by_content"], 1)
        self.assertEqual(report.metadata["classification_cache_misses"], 0)

    def test_cyberchef_transformed_archive_reaches_universal_solvers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "story_02" / "forensics"
            root.mkdir(parents=True)
            (root / "task.txt").write_text("Family: Forensics\nRecover the hidden file.\n", encoding="utf-8")
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as handle:
                handle.writestr("payload.txt", "ico{cyberchef_solver_handoff}")
            token = base64.b64encode(archive.getvalue())
            rot13 = bytes.maketrans(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            )
            (root / "evidence.txt").write_bytes(token.translate(rot13))

            def fake_scan(*_args, **_kwargs):
                return {"summary": {}, "candidates": []}

            with (
                patch("ico_tool_adapters.profiles_for_classification", return_value=()),
                patch("ico_solve.run_scan", side_effect=fake_scan),
            ):
                report = solve_inputs(
                    [root],
                    debug_dir=Path(directory) / "debug",
                    mode="full",
                    workers=1,
                    deadline_seconds=20,
                )

        self.assertIn("ico{cyberchef_solver_handoff}", {candidate.value for candidate in select_flags(report)})
        self.assertGreaterEqual(report.metadata["recursive_adapter_artifact_count"], 1)

    def test_solve_inputs_persists_optional_evidence_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "crypto"
            root.mkdir()
            (root / "task.txt").write_text("Crypto\nDecode base64\n", encoding="utf-8")
            (root / "cipher.txt").write_text(base64.b64encode(b"ico{stored_fixture}").decode(), encoding="ascii")
            database = Path(directory) / "evidence.sqlite3"
            report = solve_inputs([root], debug_dir=Path(directory) / "debug", mode="fast", evidence_db=database)
            self.assertIn("ico{stored_fixture}", {candidate.value for candidate in select_flags(report)})
            with EvidenceStore(database) as store:
                snapshot = store.snapshot()
            self.assertGreaterEqual(snapshot["counts"]["artifacts"], 1)
            self.assertGreaterEqual(snapshot["counts"]["executions"], 1)
            self.assertGreaterEqual(snapshot["counts"]["candidates"], 1)


if __name__ == "__main__":
    unittest.main()
