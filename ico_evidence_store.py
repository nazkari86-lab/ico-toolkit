#!/usr/bin/env python3
"""Durable, bounded provenance for ICO/CTF solver runs.

The store keeps metadata and hashes rather than copying artifact bytes.  It is
deliberately independent from ``SolveReport`` so the existing solver facade
can opt into persistence without creating an import cycle.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


SCHEMA_VERSION = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _json(value: Mapping[str, object] | None) -> str:
    return json.dumps(dict(value or {}), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


class EvidenceStore:
    """SQLite-backed artifact/execution/finding/candidate relationship store."""

    _COUNT_TABLES = ("artifacts", "executions", "findings", "candidates", "relationships")

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(str(self.path), timeout=30.0, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    sha256 TEXT NOT NULL UNIQUE,
                    path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    kind TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                    solver_id TEXT NOT NULL,
                    solver_revision TEXT NOT NULL,
                    context_hash TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'running',
                    started_at TEXT NOT NULL,
                    finished_at TEXT,
                    duration_seconds REAL,
                    error TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}',
                    UNIQUE(artifact_id, solver_id, solver_revision, context_hash)
                );
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id INTEGER NOT NULL REFERENCES executions(execution_id),
                    artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                    value TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'candidate',
                    triage TEXT NOT NULL DEFAULT 'candidate',
                    source TEXT NOT NULL DEFAULT '',
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS candidates (
                    candidate_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id INTEGER REFERENCES executions(execution_id),
                    finding_id INTEGER REFERENCES findings(finding_id),
                    task_id TEXT NOT NULL,
                    value TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'candidate',
                    score INTEGER NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS relationships (
                    parent_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                    child_artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id),
                    transform TEXT NOT NULL,
                    execution_id INTEGER REFERENCES executions(execution_id),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(parent_artifact_id, child_artifact_id, transform)
                );
                CREATE INDEX IF NOT EXISTS idx_executions_resume
                    ON executions(artifact_id, solver_id, solver_revision, context_hash, status);
                CREATE INDEX IF NOT EXISTS idx_findings_execution ON findings(execution_id);
                CREATE INDEX IF NOT EXISTS idx_candidates_task ON candidates(task_id);
                INSERT OR IGNORE INTO metadata(key, value) VALUES ('schema_version', '1');
                """
            )

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()

    def record_artifact(
        self,
        path: Path | str,
        *,
        kind: str = "",
        metadata: Mapping[str, object] | None = None,
    ) -> str:
        source = Path(path).expanduser().resolve()
        if source.is_symlink() or not source.is_file():
            raise FileNotFoundError(source)
        digest, size = _sha256(source)
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR IGNORE INTO artifacts
                    (artifact_id, sha256, path, size, kind, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (digest, digest, str(source), size, str(kind), _json(metadata), _now()),
            )
        return digest

    def start_execution(
        self,
        *,
        artifact_id: str,
        solver_id: str,
        solver_revision: str,
        context_hash: str = "",
        metadata: Mapping[str, object] | None = None,
    ) -> int:
        with self._lock, self._connection:
            if self._connection.execute(
                "SELECT 1 FROM artifacts WHERE artifact_id = ?", (artifact_id,)
            ).fetchone() is None:
                raise KeyError(f"unknown artifact: {artifact_id}")
            self._connection.execute(
                """
                INSERT OR IGNORE INTO executions
                    (artifact_id, solver_id, solver_revision, context_hash, status, started_at, metadata_json)
                VALUES (?, ?, ?, ?, 'running', ?, ?)
                """,
                (artifact_id, str(solver_id), str(solver_revision), str(context_hash), _now(), _json(metadata)),
            )
            row = self._connection.execute(
                """
                SELECT execution_id FROM executions
                WHERE artifact_id = ? AND solver_id = ? AND solver_revision = ? AND context_hash = ?
                """,
                (artifact_id, str(solver_id), str(solver_revision), str(context_hash)),
            ).fetchone()
        if row is None:
            raise RuntimeError("execution row was not created")
        return int(row["execution_id"])

    def finish_execution(
        self,
        execution_id: int,
        *,
        status: str,
        duration_seconds: float | None = None,
        error: str | None = None,
    ) -> None:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE executions
                SET status = ?, finished_at = ?, duration_seconds = ?, error = ?
                WHERE execution_id = ?
                """,
                (str(status), _now(), duration_seconds, error, int(execution_id)),
            )
            if cursor.rowcount != 1:
                raise KeyError(f"unknown execution: {execution_id}")

    def record_finding(
        self,
        *,
        execution_id: int,
        artifact_id: str,
        value: str,
        state: str = "candidate",
        triage: str = "candidate",
        source: str = "",
        metadata: Mapping[str, object] | None = None,
    ) -> int:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO findings
                    (execution_id, artifact_id, value, state, triage, source, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (int(execution_id), str(artifact_id), str(value), str(state), str(triage), str(source), _json(metadata)),
            )
            return int(cursor.lastrowid)

    def record_candidate(
        self,
        *,
        task_id: str,
        value: str,
        execution_id: int | None = None,
        finding_id: int | None = None,
        state: str = "candidate",
        score: int = 0,
        metadata: Mapping[str, object] | None = None,
    ) -> int:
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                INSERT INTO candidates
                    (execution_id, finding_id, task_id, value, state, score, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (execution_id, finding_id, str(task_id), str(value), str(state), int(score), _json(metadata)),
            )
            return int(cursor.lastrowid)

    def record_relationship(
        self,
        *,
        parent_artifact_id: str,
        child_artifact_id: str,
        transform: str,
        execution_id: int | None = None,
    ) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT OR IGNORE INTO relationships
                    (parent_artifact_id, child_artifact_id, transform, execution_id, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (str(parent_artifact_id), str(child_artifact_id), str(transform), execution_id, _now()),
            )

    def has_execution(
        self,
        *,
        artifact_sha256: str,
        solver_id: str,
        solver_revision: str,
        context_hash: str = "",
    ) -> bool:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT 1 FROM executions
                WHERE artifact_id = ? AND solver_id = ? AND solver_revision = ? AND context_hash = ?
                  AND status = 'completed'
                LIMIT 1
                """,
                (str(artifact_sha256), str(solver_id), str(solver_revision), str(context_hash)),
            ).fetchone()
        return row is not None

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            counts = {
                table: int(self._connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in self._COUNT_TABLES
            }
            return {"schema_version": SCHEMA_VERSION, "path": str(self.path), "counts": counts}


def persist_solve_report(
    store: EvidenceStore,
    report: Any,
    *,
    solver_id: str = "ico-solve",
    solver_revision: str = "1",
) -> dict[str, object]:
    """Persist a duck-typed ``SolveReport`` and return a compact snapshot."""

    slots = getattr(report, "slots", ()) or ()
    candidates = getattr(report, "candidates", ()) or ()
    by_task: dict[str, list[Any]] = {}
    for candidate in candidates:
        by_task.setdefault(str(getattr(candidate, "task_id", "")), []).append(candidate)
    report_metadata = getattr(report, "metadata", {})
    if not isinstance(report_metadata, Mapping):
        report_metadata = {}
    for slot in slots:
        task_id = str(getattr(slot, "task_id", ""))
        paths = tuple(getattr(slot, "paths", ()) or ())
        source = next((Path(item) for item in paths if Path(item).is_file() and not Path(item).is_symlink()), None)
        if source is None:
            continue
        artifact_id = store.record_artifact(source, kind=str(getattr(slot, "family", "")))
        context_hash = hashlib.sha256(
            json.dumps(
                {"task_id": task_id, "family": str(getattr(slot, "family", "")), "difficulty": str(getattr(slot, "difficulty", ""))},
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if store.has_execution(
            artifact_sha256=artifact_id,
            solver_id=solver_id,
            solver_revision=solver_revision,
            context_hash=context_hash,
        ):
            continue
        execution_id = store.start_execution(
            artifact_id=artifact_id,
            solver_id=solver_id,
            solver_revision=solver_revision,
            context_hash=context_hash,
            metadata={"task_id": task_id, "report": report_metadata},
        )
        for candidate in by_task.get(task_id, []):
            value = str(getattr(candidate, "value", ""))
            if not value:
                continue
            state = str(getattr(candidate, "state", "candidate"))
            finding_id = store.record_finding(
                execution_id=execution_id,
                artifact_id=artifact_id,
                value=value,
                state=state,
                triage=str(getattr(candidate, "triage", "candidate")),
                source=", ".join(str(item) for item in getattr(candidate, "sources", ()) or ()),
            )
            store.record_candidate(
                execution_id=execution_id,
                finding_id=finding_id,
                task_id=task_id,
                value=value,
                state=state,
                score=int(getattr(candidate, "score", 0)),
            )
        store.finish_execution(execution_id, status="completed", duration_seconds=float(report_metadata.get("wall_clock_seconds", 0.0) or 0.0))
    return store.snapshot()


__all__ = ["EvidenceStore", "SCHEMA_VERSION", "persist_solve_report"]
