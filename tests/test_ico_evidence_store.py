from __future__ import annotations

from pathlib import Path

from ico_evidence_store import EvidenceStore


def test_evidence_store_round_trip_and_resume(tmp_path: Path) -> None:
    source = tmp_path / "evidence.bin"
    child = tmp_path / "decoded.txt"
    source.write_bytes(b"source")
    child.write_text("ico{derived}", encoding="utf-8")
    database = tmp_path / "evidence.sqlite3"

    with EvidenceStore(database) as store:
        parent_id = store.record_artifact(source, kind="binary")
        child_id = store.record_artifact(child, kind="text")
        execution_id = store.start_execution(
            artifact_id=parent_id,
            solver_id="decode-test",
            solver_revision="rev-1",
            context_hash="ctx-1",
            metadata={"mode": "fast"},
        )
        finding_id = store.record_finding(
            execution_id=execution_id,
            artifact_id=child_id,
            value="ico{derived}",
            source="decoded.txt",
        )
        store.record_candidate(
            execution_id=execution_id,
            finding_id=finding_id,
            task_id="story_01/forensics_easy",
            value="ico{derived}",
            score=600,
        )
        store.record_relationship(
            parent_artifact_id=parent_id,
            child_artifact_id=child_id,
            transform="base64",
            execution_id=execution_id,
        )
        store.finish_execution(execution_id, status="completed", duration_seconds=0.25)
        assert store.has_execution(
            artifact_sha256=parent_id,
            solver_id="decode-test",
            solver_revision="rev-1",
            context_hash="ctx-1",
        )
        snapshot = store.snapshot()
        assert snapshot["counts"] == {
            "artifacts": 2,
            "executions": 1,
            "findings": 1,
            "candidates": 1,
            "relationships": 1,
        }

    with EvidenceStore(database) as reopened:
        assert reopened.has_execution(
            artifact_sha256=parent_id,
            solver_id="decode-test",
            solver_revision="rev-1",
            context_hash="ctx-1",
        )
        assert reopened.snapshot()["counts"]["candidates"] == 1


def test_evidence_store_rejects_missing_artifact(tmp_path: Path) -> None:
    with EvidenceStore(tmp_path / "evidence.sqlite3") as store:
        try:
            store.record_artifact(tmp_path / "missing.bin")
        except FileNotFoundError:
            pass
        else:
            raise AssertionError("missing artifact should be rejected")
