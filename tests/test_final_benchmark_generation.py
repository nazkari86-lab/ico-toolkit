from __future__ import annotations

import hashlib
import json
from pathlib import Path

from scripts.generate_final_benchmark import generate


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


def test_first_round_has_fifty_unique_records(tmp_path: Path) -> None:
    manifest = generate(round_id=1, root=tmp_path / "corpus", manifest_path=tmp_path / "expected.json")
    assert len(manifest.records) == 50
    assert len({record.task_id for record in manifest.records}) == 50
    assert {record.family for record in manifest.records} == {"web", "pwn", "forensics", "reverse", "crypto"}
    assert len({record.story for record in manifest.records}) == 10
    assert not (tmp_path / "corpus" / "expected.json").exists()


def test_generation_is_byte_deterministic(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_manifest = generate(round_id=1, root=first_root, manifest_path=tmp_path / "first.json")
    second_manifest = generate(round_id=1, root=second_root, manifest_path=tmp_path / "second.json")
    assert _tree_hash(first_root) == _tree_hash(second_root)
    assert first_manifest.to_dict() == second_manifest.to_dict()
    assert json.loads((tmp_path / "first.json").read_text()) == json.loads((tmp_path / "second.json").read_text())


def test_task_statements_identify_family_and_difficulty(tmp_path: Path) -> None:
    generate(round_id=1, root=tmp_path / "corpus", manifest_path=tmp_path / "expected.json")
    statements = list((tmp_path / "corpus").glob("story_*/*/task.txt"))
    assert len(statements) == 50
    for statement in statements:
        text = statement.read_text(encoding="utf-8")
        assert "Task ID:" in text
        assert "Family:" in text
        assert "Difficulty:" in text
        assert "Answer:" not in text


def test_long_rounds_use_bounded_gif_comment_subblocks(tmp_path: Path) -> None:
    # Round 7 has enough base64 layers to cross the one-byte GIF sub-block
    # length boundary; generation must remain valid instead of raising.
    manifest = generate(round_id=7, root=tmp_path / "corpus", manifest_path=tmp_path / "expected.json")
    path = tmp_path / "corpus" / "story_07" / "forensics_medium" / "evidence.gif"
    data = path.read_bytes()
    assert data.startswith(b"GIF89a\x21\xFE")
    assert len(data) > 256
    assert manifest.round_id == 7


def test_hardest_profile_is_all_hard_and_keeps_flags_out_of_evidence(tmp_path: Path) -> None:
    manifest = generate(
        round_id=1,
        profile="hardest",
        root=tmp_path / "corpus",
        manifest_path=tmp_path / "expected.json",
    )
    assert manifest.profile == "hardest"
    assert len(manifest.records) == 50
    assert {record.difficulty for record in manifest.records} == {"hard"}
    for record in manifest.records:
        task_root = tmp_path / "corpus" / record.story / f"{record.family}_{record.difficulty}"
        evidence = b"".join(path.read_bytes() for path in task_root.rglob("*") if path.is_file())
        expected = record.answer_sha256.encode()
        assert expected not in evidence
        assert b"ICO FINAL BENCHMARK" in (task_root / "task.txt").read_bytes()
        assert len([path for path in task_root.iterdir() if path.name != "task.txt"]) >= 3


def test_hardest_profile_records_family_specific_inverse_stage(tmp_path: Path) -> None:
    manifest = generate(round_id=1, profile="hardest", root=tmp_path / "corpus", manifest_path=tmp_path / "expected.json")
    stages = set()
    for record in manifest.records:
        chain = json.loads(
            (tmp_path / "corpus" / record.story / f"{record.family}_{record.difficulty}" / "chain.json").read_text()
        )
        stages.add(chain["family_stage"])
        assert chain["family"] == record.family
    assert stages == {"web-block-xor", "pwn-endian-delta", "forensics-nibble-mask", "reverse-vm", "crypto-affine"}


def test_hardest_successors_strictly_increase_chain_complexity(tmp_path: Path) -> None:
    generate(round_id=2, profile="hardest", root=tmp_path / "round2", manifest_path=tmp_path / "round2.json")
    generate(round_id=3, profile="hardest", root=tmp_path / "round3", manifest_path=tmp_path / "round3.json")
    chain2 = json.loads((tmp_path / "round2" / "story_01" / "web_hard" / "chain.json").read_text())
    chain3 = json.loads((tmp_path / "round3" / "story_01" / "web_hard" / "chain.json").read_text())
    assert chain3["complexity"] > chain2["complexity"]
    assert chain3["fragment_count"] > chain2["fragment_count"]
    assert chain3["decoys"] > chain2["decoys"]
    assert chain3["cycle_count"] > chain2["cycle_count"]
