from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
import tempfile
import unittest
import wave
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

import ico_quals_solvers
from ico_scan_core import CommandResult
from ico_quals_solvers import (
    build_aezakmi_payload,
    build_journal_payload,
    discover_ico_quals_roots,
    extract_walkthrough_references,
    recover_lcg_predictions,
    sha256_length_extend,
    solve_can_you_hear,
    plan_ocr_inputs,
    solve_five_shards,
    solve_aezakmi,
    solve_journal,
    solve_rev_zero,
    solve_service_task,
    solve_wolf_protocol,
    solve_ico_quals_root,
    build_qual_answer_matrix,
    write_qual_answer_index,
    _find_transcript,
)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _png_with_trailer(trailer: bytes) -> bytes:
    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    rows = zlib.compress(b"\x00\x00\x00\x00")
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", header)
        + _png_chunk(b"IDAT", rows)
        + _png_chunk(b"IEND", b"")
        + trailer
    )


def _wav_bytes() -> bytes:
    stream = io.BytesIO()
    with wave.open(stream, "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(8000)
        audio.writeframes(struct.pack("<hh", 0, 0))
    return stream.getvalue()


def _dns_pcap(labels: list[str]) -> bytes:
    packets = []
    for index, label in enumerate(labels):
        qname = b"".join(bytes([len(part)]) + part.encode() for part in [label, "shard4", "ctf"]) + b"\x00"
        dns = struct.pack(">HHHHHH", index + 1, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)
        udp = struct.pack(">HHHH", 53000, 53, 8 + len(dns), 0) + dns
        ip = bytes.fromhex("45000000") + struct.pack(">H", index) + b"\x00\x00\x40\x11\x00\x00" + bytes([192, 168, 1, 42, 8, 8, 8, 8])
        ip = ip[:2] + struct.pack(">H", 20 + len(udp)) + ip[4:]
        ethernet = b"\x00" * 12 + b"\x08\x00"
        packet = ethernet + ip + udp
        packets.append(struct.pack("<IIII", index + 1, 0, len(packet), len(packet)) + packet)
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"".join(packets)


def _dns_pcapng(labels: list[str]) -> bytes:
    classic = _dns_pcap(labels)
    frames: list[bytes] = []
    offset = 24
    while offset + 16 <= len(classic):
        _sec, _usec, captured, _original = struct.unpack_from("<IIII", classic, offset)
        offset += 16
        frames.append(classic[offset : offset + captured])
        offset += captured

    def block(block_type: int, body: bytes) -> bytes:
        total = (12 + len(body) + 3) & ~3
        return struct.pack("<II", block_type, total) + body + b"\x00" * (total - 12 - len(body)) + struct.pack("<I", total)

    section = struct.pack("<I H H q", 0x1A2B3C4D, 1, 0, -1)
    interface = struct.pack("<H H I", 1, 0, 65535)
    packets = [
        struct.pack("<I I I I I", 0, 0, index, len(frame), len(frame)) + frame
        for index, frame in enumerate(frames, 1)
    ]
    return block(0x0A0D0D0A, section) + block(1, interface) + b"".join(block(6, packet) for packet in packets)


class _FakeRunner:
    def __init__(self, outputs: dict[str, str] | None = None) -> None:
        self.outputs = outputs or {}
        self.calls: list[list[str]] = []

    def run(self, args, *, cwd, timeout, log_name):
        argv = [str(item) for item in args]
        self.calls.append(argv)
        stdout = self.outputs.get(argv[0], "")
        return CommandResult(args=argv, returncode=0, stdout=stdout)


class RealQualsSolverTests(unittest.TestCase):
    def test_ocr_planner_deduplicates_named_views_and_ignores_unrelated_images(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spectrum = root / "spectrum.png"
            spectrum.write_bytes(b"same-pixels")
            (root / "spectrum_crop.png").write_bytes(b"same-pixels")
            (root / "text_mask.png").write_bytes(b"mask-view")
            (root / "unrelated.png").write_bytes(b"unrelated")
            planned = plan_ocr_inputs(spectrum, root)
        paths = {Path(item["path"]).name for item in planned}
        hashes = [item["sha256"] for item in planned if item["sha256"]]
        self.assertIn("spectrum.png", paths)
        self.assertIn("text_mask.png", paths)
        self.assertNotIn("spectrum_crop.png", paths)
        self.assertNotIn("unrelated.png", paths)
        self.assertEqual(len(hashes), len(set(hashes)))

    def test_lcg_recovery_is_offline_and_predicts_states(self):
        m, a, c = 10007, 37, 91
        x0 = 1234
        x1 = (a * x0 + c) % m
        x2 = (a * x1 + c) % m
        x3 = (a * x2 + c) % m
        text = f"m = {m}\nx0 = {x0}\nx1 = {x1}\nx2_top = {x2 >> 2}\nx3 = {x3}\nhidden_bits = 2\nrounds = 3\n"
        result = recover_lcg_predictions(text)
        self.assertEqual(result["parameters"], {"a": a, "c": c, "x2": x2})
        self.assertEqual(result["predictions"], [(a * x3 + c) % m, (a * ((a * x3 + c) % m) + c) % m, (a * ((a * ((a * x3 + c) % m) + c) % m) + c) % m])

    def test_sha256_length_extension_matches_secret_prefix_mac(self):
        secret = b"S" * 18
        old = b"user=guest&level=basic"
        suffix = b"&level=admin"
        old_token = hashlib.sha256(secret + old).hexdigest()
        new_token, glue = sha256_length_extend(old_token, len(secret) + len(old), suffix)
        self.assertEqual(hashlib.sha256(secret + old + glue + suffix).hexdigest(), new_token)

    def test_walkthrough_references_are_separate_from_solver_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "ICO_full_walkthrough.md"
            source.write_text(
                "# 1. NorthStar\nfirst ico{northstar_one} second ico{northstar_two}\n\n"
                "# 6. Rev Zero\n`ico{rev_zero}`\n",
                encoding="utf-8",
            )
            references = extract_walkthrough_references(source)
        self.assertEqual(
            {(item["task_id"], item["value"]) for item in references},
            {
                ("northstar", "ico{northstar_one}"),
                ("northstar", "ico{northstar_two}"),
                ("rev-zero", "ico{rev_zero}"),
            },
        )
        self.assertTrue(all(item["state"] == "reference-only" for item in references))

    def test_historical_solution_bundle_writes_one_note_per_task(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            walkthrough = root / "ICO_full_walkthrough.md"
            walkthrough.write_text(
                "# 1. NorthStar\n`ico{northstar_one}`\n\n"
                "# 6. Rev Zero\n`ico{rev_zero}`\n",
                encoding="utf-8",
            )
            northstar = solve_service_task("northstar", root / "report")
            northstar.references = extract_walkthrough_references(walkthrough)[:1]
            results = [northstar]
            index = write_qual_answer_index(results, root / "report")
            bundle = Path(index["bundle"])
            historical = Path(northstar.artifacts[-1])
            self.assertTrue(bundle.is_file())
            self.assertTrue(historical.is_file())
            self.assertIn("ico{northstar_one}", bundle.read_text(encoding="utf-8"))
            self.assertIn("reference-only", historical.read_text(encoding="utf-8"))
            self.assertEqual(
                Path(index["text"]).read_text(encoding="utf-8").splitlines(),
                ["ico{northstar_one}"],
            )

    def test_rev_zero_decodes_base64_then_reverses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flag = "ico{rev_fixture}"
            encoded = base64.b64encode(flag[::-1].encode()).decode()
            html = f"<script>if (btoa(input.split('').reverse().join('')) === '{encoded}') {{}}</script>"
            source = root / "rev_zero.html"
            source.write_text(html, encoding="utf-8")
            result = solve_rev_zero(source, root / "report")
        self.assertEqual(result.candidates[0]["value"], flag)
        self.assertEqual(result.status, "candidate")

    def test_can_you_hear_extracts_trailer_and_uses_ocr_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.png"
            source.write_bytes(_png_with_trailer(_wav_bytes()))
            runner = _FakeRunner({"tesseract": "ico{audio_fixture}"})
            result = solve_can_you_hear(source, root / "report", runner=runner)
            self.assertTrue((root / "report" / "artifacts" / "ico-quals" / "can-you-hear" / "hidden.wav").is_file())
        self.assertEqual(result.candidates[0]["value"], "ico{audio_fixture}")
        self.assertTrue(any(call[0] == "tesseract" for call in runner.calls))

    def test_can_you_hear_ocr_has_hard_budget_and_records_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.png"
            source.write_bytes(_png_with_trailer(_wav_bytes()))
            for name in ("spectrum_crop.png", "spectrum_zoom.png", "text_mask.png", "text_bw.png", "text_g.png", "unrelated.png"):
                (root / name).write_bytes(name.encode("ascii"))
            runner = _FakeRunner()
            result = solve_can_you_hear(source, root / "report", runner=runner)
        tesseract_calls = [call for call in runner.calls if call[0] == "tesseract"]
        plan = next(step for step in result.steps if step["name"] == "ocr-plan")
        self.assertLessEqual(len(tesseract_calls), 8)
        self.assertLessEqual(len(plan["details"]["inputs"]), 4)
        self.assertNotIn("unrelated.png", {Path(item["path"]).name for item in plan["details"]["inputs"]})
        self.assertEqual(result.status, "candidate-review")

    def test_ocr_planner_includes_generated_frequency_focused_spectrum(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_view = root / "spectrum.png"
            focused_view = root / "spectrum-2k-5k.png"
            compact_view = root / "spectrum-2k-5k-ocr-compact.png"
            source_view.write_bytes(b"source spectrum")
            focused_view.write_bytes(b"frequency-focused spectrum")
            compact_view.write_bytes(b"vertically compressed OCR view")

            planned = plan_ocr_inputs(
                source_view,
                root / "challenge",
                focused_spectrum_path=focused_view,
                compact_spectrum_path=compact_view,
            )

        self.assertEqual(
            [Path(item["path"]).name for item in planned],
            ["spectrum.png", "spectrum-2k-5k.png", "spectrum-2k-5k-ocr-compact.png"],
        )
        self.assertEqual(planned[1]["reason"], "generated 2-5 kHz spectrogram")
        self.assertEqual(planned[2]["reason"], "generated compact vertical-crop OCR view")

    def test_can_you_hear_saves_frequency_focused_spectrum(self):
        class ArtifactRunner(_FakeRunner):
            def run(self, args, *, cwd, timeout, log_name):
                result = super().run(args, cwd=cwd, timeout=timeout, log_name=log_name)
                if result.args[0] == "ffmpeg":
                    output = Path(result.args[-1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(b"test spectrum")
                return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.png"
            source.write_bytes(_png_with_trailer(_wav_bytes()))
            runner = ArtifactRunner()

            result = solve_can_you_hear(source, root / "report", runner=runner)

            focused = root / "report" / "artifacts" / "ico-quals" / "can-you-hear" / "spectrum-2k-5k.png"
            focused_exists = focused.is_file()
            ffmpeg_calls = [call for call in runner.calls if call[0] == "ffmpeg"]

        self.assertTrue(focused_exists)
        self.assertEqual(len(ffmpeg_calls), 3)
        self.assertIn("start=2000:stop=5000", " ".join(ffmpeg_calls[1]))
        self.assertIn("crop=4096:480:0:300,scale=4096:230:flags=lanczos", " ".join(ffmpeg_calls[2]))
        self.assertIn(str(focused.resolve()), result.artifacts)

    def test_can_you_hear_builds_and_records_compact_ocr_view(self):
        class ArtifactRunner(_FakeRunner):
            def run(self, args, *, cwd, timeout, log_name):
                result = super().run(args, cwd=cwd, timeout=timeout, log_name=log_name)
                if result.args[0] == "ffmpeg":
                    output = Path(result.args[-1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(("image fixture: " + output.name).encode("ascii"))
                return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.png"
            source.write_bytes(_png_with_trailer(_wav_bytes()))
            runner = ArtifactRunner()

            result = solve_can_you_hear(source, root / "report", runner=runner)

            compact = root / "report" / "artifacts" / "ico-quals" / "can-you-hear" / "spectrum-2k-5k-ocr-compact.png"
            compact_exists = compact.is_file()
            compact_sha256 = hashlib.sha256(compact.read_bytes()).hexdigest() if compact_exists else None
            ffmpeg_calls = [call for call in runner.calls if call[0] == "ffmpeg"]
            plan = next(step for step in result.steps if step["name"] == "ocr-plan")
            render = next(step for step in result.steps if step["name"] == "render-compact-ocr-view")

        self.assertTrue(compact_exists)
        self.assertEqual(len(ffmpeg_calls), 3)
        self.assertIn("crop=4096:480:0:300,scale=4096:230:flags=lanczos", " ".join(ffmpeg_calls[2]))
        planned = next(item for item in plan["details"]["inputs"] if Path(item["path"]).name == compact.name)
        self.assertEqual(planned["reason"], "generated compact vertical-crop OCR view")
        self.assertEqual(planned["sha256"], compact_sha256)
        self.assertEqual(render["details"]["crop_xywh"], [0, 300, 4096, 480])
        self.assertEqual(render["details"]["output_size"], [4096, 230])
        self.assertIn(str(compact.resolve()), result.artifacts)

    def test_can_you_hear_records_ocr_near_miss_for_manual_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.png"
            source.write_bytes(_png_with_trailer(_wav_bytes()))
            raw = "icofaf3ac3e2b6d4afcOaiedae7ab4afe1}"
            runner = _FakeRunner({"tesseract": raw})
            result = solve_can_you_hear(source, root / "report", runner=runner)

        review = next(step for step in result.steps if step["name"] == "ocr-review")
        self.assertEqual(review["status"], "needs-review")
        self.assertEqual(
            review["details"]["values"][0]["normalized"],
            "ico{faf3ac3e2b6d4afcOaiedae7ab4afe1}",
        )
        self.assertFalse(result.candidates)
        self.assertEqual(result.status, "candidate-review")

    def test_can_you_hear_records_unprefixed_hex_like_ocr_only_for_review(self):
        class ArtifactRunner(_FakeRunner):
            def run(self, args, *, cwd, timeout, log_name):
                result = super().run(args, cwd=cwd, timeout=timeout, log_name=log_name)
                if result.args[0] == "ffmpeg":
                    output = Path(result.args[-1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(("image fixture: " + output.name).encode("ascii"))
                return result

        raw = "4eofa7f3c91e2b6d4ef5caod83e72b4f61}"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.png"
            source.write_bytes(_png_with_trailer(_wav_bytes()))
            runner = ArtifactRunner({"tesseract": raw})
            result = solve_can_you_hear(source, root / "report", runner=runner)

        review = next(step for step in result.steps if step["name"] == "ocr-review")
        hint = review["details"]["values"][0]
        self.assertEqual(hint["raw"], raw)
        self.assertEqual(hint["normalized"], raw)
        self.assertIn("not inferred", hint["reason"])
        self.assertFalse(result.candidates)
        self.assertEqual(result.status, "candidate-review")

    def test_can_you_hear_uses_two_bounded_segmentation_fallbacks_on_compact_view(self):
        class ArtifactRunner(_FakeRunner):
            def run(self, args, *, cwd, timeout, log_name):
                result = super().run(args, cwd=cwd, timeout=timeout, log_name=log_name)
                if result.args[0] == "ffmpeg":
                    output = Path(result.args[-1])
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(("image fixture: " + output.name).encode("ascii"))
                return result

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "challenge.png"
            source.write_bytes(_png_with_trailer(_wav_bytes()))
            runner = ArtifactRunner()
            result = solve_can_you_hear(source, root / "report", runner=runner)
            ocr_calls = [call for call in runner.calls if call[0] == "tesseract"]

        compact_calls = [call for call in ocr_calls if Path(call[1]).name == "spectrum-2k-5k-ocr-compact.png"]
        compact_psms = {call[call.index("--psm") + 1] for call in compact_calls}
        self.assertLessEqual(len(ocr_calls), 8)
        self.assertTrue({"8", "11"}.issubset(compact_psms))
        self.assertEqual(result.status, "candidate-review")

    def test_five_shards_reassembles_dns_fragments_with_wav_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "five_shards"
            task.mkdir()
            key = bytes.fromhex("CA FE BA BE DE AD C0 DE")
            pieces = [b"ico{5", b"h4rd5", b"_4r3_", b"b3tt3", b"r_t0g", b"3th3r", b"!}"]
            joined = b"".join(pieces)
            encrypted = bytes(value ^ key[pos % len(key)] for pos, value in enumerate(joined))
            labels = []
            cursor = 0
            for index, piece in enumerate(pieces):
                encoded = encrypted[cursor : cursor + len(piece)]
                cursor += len(piece)
                labels.append(f"{index:03d}-" + base64.b32encode(encoded).decode().rstrip("="))
            (task / "corrupted.wav").write_bytes(key + _wav_bytes()[8:])
            (task / "traffic.pcap").write_bytes(_dns_pcap(labels))
            result = solve_five_shards(task, root / "report")
        self.assertEqual(result.candidates[0]["value"], "ico{5h4rd5_4r3_b3tt3r_t0g3th3r!}")
        self.assertEqual(result.status, "candidate")

    def test_five_shards_reassembles_dns_fragments_from_pcapng(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "five_shards"
            task.mkdir()
            key = bytes.fromhex("CA FE BA BE DE AD C0 DE")
            flag = b"ico{pcapng_five_shards}"
            encrypted = bytes(value ^ key[pos % len(key)] for pos, value in enumerate(flag))
            label = "000-" + base64.b32encode(encrypted).decode().rstrip("=")
            (task / "corrupted.wav").write_bytes(key + _wav_bytes()[8:])
            (task / "traffic.pcap").write_bytes(_dns_pcapng([label]))
            result = solve_five_shards(task, root / "report")

        self.assertEqual(result.candidates[0]["value"], flag.decode())
        self.assertEqual(result.status, "candidate")

    def test_pwn_solvers_emit_static_payloads_without_execution(self):
        aez = build_aezakmi_payload()
        journal = build_journal_payload()
        self.assertEqual(aez[:72], b"A" * 72)
        self.assertEqual(struct.unpack("<Q", aez[72:80])[0], 0x401140)
        self.assertEqual(struct.unpack("<Q", aez[88:96])[0], 0x1337C0DE)
        self.assertEqual(journal[:20], b"%c" * 9 + b"%n")
        self.assertEqual(struct.unpack("<Q", journal[32:40])[0], 0x40407C)

    def test_aezakmi_solver_requires_a_validated_binary_before_emitting_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "chall"
            source.write_bytes(b"\x7fELF" + b"\x00" * 64)
            result = solve_aezakmi(source, root / "report")

        self.assertEqual(result.status, "candidate-review")
        self.assertFalse(result.artifacts)
        validation = next(step for step in result.steps if step["name"] == "static-payload-validation")
        self.assertEqual(validation["status"], "needs-review")
        self.assertFalse(validation["details"]["executed"])

    def test_journal_solver_requires_a_validated_binary_before_emitting_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "journal"
            source.write_bytes(b"\x7fELF" + b"\x00" * 64)
            result = solve_journal(source, root / "report")

        self.assertEqual(result.status, "candidate-review")
        self.assertFalse(result.artifacts)
        self.assertFalse(result.candidates)
        validation = next(step for step in result.steps if step["name"] == "static-payload-validation")
        self.assertEqual(validation["status"], "needs-review")
        self.assertFalse(validation["details"]["executed"])

    def test_wolf_solver_inverts_ciphertext_and_forward_checks_exact_target(self):
        data = b"\x7fELF" + b"wolf-static-fixture" * 8
        expected_target = "204fce1173dd734e50722b8dc91af48262a87e49b8cace426f64aed9aa5a45a0b842c0"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "wolf_protocol.bin"
            source.write_bytes(data)
            with patch.object(
                ico_quals_solvers,
                "WOLF_ARTIFACT_SHA256",
                hashlib.sha256(data).hexdigest(),
                create=True,
            ):
                result = solve_wolf_protocol(source, root / "report")

            self.assertEqual(result.status, "candidate")
            self.assertEqual(result.candidates[0]["value"], "ico{w0lves_see_th3_h1dd3n_truth_42}")
            evidence_path = next(Path(path) for path in result.artifacts if path.endswith("wolf-protocol-static.json"))
            evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

        self.assertEqual(evidence["target_hex"], expected_target)
        self.assertEqual(evidence["forward_encoded_hex"], expected_target)
        self.assertFalse(evidence["executed"])

    def test_wolf_solver_rejects_unrecognized_binary_without_transcript(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "wolf_protocol.bin"
            source.write_bytes(b"\x7fELF" + b"unrelated" * 16)
            result = solve_wolf_protocol(source, root / "report")

        self.assertEqual(result.status, "no-candidate")
        self.assertFalse(result.candidates)

    def test_service_task_requires_authorized_session_and_writes_playbook(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = solve_service_task("backdoor", root / "report")
            playbook = Path(result.artifacts[0])
            self.assertTrue(playbook.is_file())
        self.assertEqual(result.status, "requires-authorized-session")
        self.assertFalse(result.candidates)
        self.assertIn("transcript", result.to_dict()["next_action"].lower())

    def test_service_transcript_candidates_are_labelled_transcript_derived(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "backdoor.transcript"
            transcript.write_text(
                "response flag=ico{from_authorized_transcript}\n",
                encoding="utf-8",
            )
            result = solve_service_task("backdoor", root / "report", transcript=transcript)
            matrix = build_qual_answer_matrix([result])

        self.assertEqual(result.candidates[0]["state"], "transcript-derived")
        self.assertEqual(matrix[1]["answer_state"], "transcript-derived")

    def test_local_and_transcript_values_keep_both_evidence_channels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "backdoor.transcript"
            transcript.write_text("ico{from_authorized_transcript}\n", encoding="utf-8")
            result = solve_service_task("backdoor", root / "report", transcript=transcript)
            result.candidates.append({"value": "ico{from_local_artifact}", "state": "candidate"})
            matrix = build_qual_answer_matrix([result])

        self.assertEqual(matrix[1]["answer_state"], "local-and-transcript")
        self.assertEqual(
            {item["value"] for item in matrix[1]["local_candidates"]},
            {"ico{from_authorized_transcript}", "ico{from_local_artifact}"},
        )

    def test_service_transcript_builds_pixelmart_predictions_and_vip_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pixel = root / "pixelmart.log"
            pixel.write_text("m = 10007 x0 = 1234 x1 = 5721 x2_top = 405 x3 = 26 hidden_bits = 2 rounds = 2", encoding="utf-8")
            vip = root / "vip-club.log"
            old = b"user=guest&level=basic"
            token = hashlib.sha256(b"S" * 18 + old).hexdigest()
            vip.write_text(f"data0={old.hex()} token0={token}", encoding="utf-8")
            pixel_result = solve_service_task("pixelmart", root / "report", transcript=pixel)
            vip_result = solve_service_task("vip-club", root / "report", transcript=vip)
        self.assertEqual(pixel_result.status, "payload-ready")
        self.assertEqual(vip_result.status, "payload-ready")
        self.assertTrue(any("lcg" in path for path in pixel_result.artifacts))
        self.assertTrue(any("extension" in path for path in vip_result.artifacts))

    def test_root_discovery_uses_real_pack_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "rev_zero.zip").write_bytes(b"PK")
            (root / "aezakmi").write_bytes(b"ELF")
            self.assertEqual(discover_ico_quals_roots([str(root)]), [root.resolve()])

    def test_root_discovery_accepts_flat_ico_2027_download_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ico2027_qualifying_files"
            root.mkdir()
            for name in (
                "Wolf_Protocol.zip",
                "rev_zero.zip",
                "Five_Shards.zip",
                "Can_You_Hear_the_Flag.zip",
            ):
                (root / name).write_bytes(b"PK")

            self.assertEqual(discover_ico_quals_roots([str(root)]), [root.resolve()])

    def test_flat_ico_2027_pack_routes_known_files_to_existing_solvers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "ico2027_qualifying_files"
            root.mkdir()
            flag = "ico{flat_pack_rev}"
            encoded = base64.b64encode(flag[::-1].encode()).decode()
            with zipfile.ZipFile(root / "Wolf_Protocol.zip", "w") as archive:
                archive.writestr("wolf_protocol.bin", b"\x7fELF" + b"\x00" * 32)
            with zipfile.ZipFile(root / "rev_zero.zip", "w") as archive:
                archive.writestr(
                    "rev_zero.html",
                    f"btoa(input.split('').reverse().join('')) === '{encoded}'",
                )
            key = bytes.fromhex("CA FE BA BE DE AD C0 DE")
            shard = b"ico{flat_pack_shards}"
            encrypted = bytes(value ^ key[index % len(key)] for index, value in enumerate(shard))
            label = "000-" + base64.b32encode(encrypted).decode().rstrip("=")
            with zipfile.ZipFile(root / "Five_Shards.zip", "w") as archive:
                archive.writestr("corrupted.wav", key + _wav_bytes()[8:])
                archive.writestr("traffic.pcap", _dns_pcap([label]))
                archive.writestr("readme.txt", "five files, five shards")
                archive.writestr("noise.png", b"noise")
                archive.writestr("photo.jpg", b"photo")
            with zipfile.ZipFile(root / "Can_You_Hear_the_Flag.zip", "w") as archive:
                archive.writestr("challenge.png", b"not a PNG")
            (root / "chall").write_bytes(b"\x7fELF" + b"\x00" * 32)
            (root / "chall(1)").write_bytes(b"\x7fELF" + b"\x00" * 32)

            results = solve_ico_quals_root(root, root / "report")
            five_result = next(result for result in results if result.task_id == "five-shards")
            inventory = next(
                Path(path)
                for path in five_result.artifacts
                if Path(path).name == "forensic-inventory.json"
            )
            inventory_text = inventory.read_text(encoding="utf-8")

        by_task = {result.task_id: result for result in results}
        self.assertEqual(by_task["rev-zero"].candidates[0]["value"], flag)
        self.assertEqual(by_task["five-shards"].candidates[0]["value"], "ico{flat_pack_shards}")
        self.assertIn("readme.txt", inventory_text)
        self.assertIn("noise.png", inventory_text)
        self.assertIn("photo.jpg", inventory_text)
        self.assertEqual(by_task["wolf-protocol"].status, "no-candidate")
        self.assertEqual(by_task["can-you-hear"].status, "failed")
        self.assertIn("expected PNG input", by_task["can-you-hear"].error or "")
        self.assertEqual(by_task["aezakmi"].status, "candidate-review")
        self.assertEqual(by_task["aezakmi"].artifacts, [])
        self.assertEqual(by_task["journal-operator"].status, "candidate-review")
        self.assertEqual(by_task["journal-operator"].artifacts, [])

    def test_answer_matrix_keeps_local_and_historical_states_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = solve_service_task("backdoor", root / "report")
            result.references = [
                {
                    "task_id": "backdoor",
                    "value": "ico{historical_fixture}",
                    "state": "reference-only",
                }
            ]
            matrix = build_qual_answer_matrix([result])
            index = write_qual_answer_index([result], root / "report")
            self.assertEqual(matrix[1]["task_id"], "backdoor")
            self.assertEqual(matrix[1]["answer_state"], "historical-reference")
            self.assertEqual(index["task_count"], 10)
            self.assertTrue(Path(index["json"]).is_file())
            self.assertTrue(Path(index["markdown"]).is_file())

    def test_answer_bundle_deduplicates_values_and_writes_all_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "backdoor.transcript"
            transcript.write_text("ico{from_authorized_transcript}\n", encoding="utf-8")
            result = solve_service_task("backdoor", root / "report", transcript=transcript)
            result.candidates.append({"value": "ico{from_local_artifact}", "state": "candidate"})
            result.references = [
                {
                    "task_id": "backdoor",
                    "value": "ico{historical_fixture}",
                    "state": "reference-only",
                },
                {
                    "task_id": "backdoor",
                    "value": "ico{historical_fixture}",
                    "state": "reference-only",
                },
            ]
            index = write_qual_answer_index([result], root / "report")
            paths = {key: Path(index[key]) for key in ("json", "markdown", "text", "bundle")}
            self.assertTrue(all(path.is_file() for path in paths.values()))
            self.assertEqual(
                paths["text"].read_text(encoding="utf-8").splitlines(),
                [
                    "ico{from_authorized_transcript}",
                    "ico{from_local_artifact}",
                    "ico{historical_fixture}",
                ],
            )
            self.assertIn("ico{historical_fixture}", paths["bundle"].read_text(encoding="utf-8"))
            self.assertIn("historical-reference", paths["markdown"].read_text(encoding="utf-8"))

    def test_transcript_discovery_is_recursive_and_accepts_response_formats(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "captures" / "round-1"
            nested.mkdir(parents=True)
            response = nested / "backdoor_response.json"
            response.write_text('{"flag":"ico{nested_transcript}"}', encoding="utf-8")
            self.assertEqual(_find_transcript(root, "backdoor"), response.resolve())


if __name__ == "__main__":
    unittest.main()
