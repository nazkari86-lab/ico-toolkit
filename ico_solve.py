#!/usr/bin/env python3
"""Final-facing, file-only ICO solver facade.

``ico-scan`` remains the evidence-heavy command.  This module adds a small
copy-ready facade: it groups task files into story/category slots, reuses the
existing registry and task solvers, invokes the extended offline adapters, and
selects only the highest-confidence flag-shaped value per slot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import sqlite3
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterable, Sequence

from ico_scan import run_scan
from ico_scan_core import MAX_CAPTURE_BYTES, CommandRunner, Classification, RunnerPolicy, classify, flag_triage
from ico_scan_profiles import profiles_for
from ico_solver_engine import SolverContext, SolverLimits
from ico_tool_adapters import AdapterEvidence, available_tool_specs, run_adapter_profiles, tool_inventory
from ico_universal_registry import build_default_registry
from ico_final_benchmark_solver import solve_final_task
from ico_evidence_store import EvidenceStore, persist_solve_report


FAMILIES = ("web", "pwn", "forensics", "reverse", "crypto")
FAMILY_ALIASES = {
    "web": "web",
    "website": "web",
    "http": "web",
    "pwn": "pwn",
    "pwnable": "pwn",
    "exploit": "pwn",
    "binary-exploitation": "pwn",
    "forensic": "forensics",
    "forensics": "forensics",
    "stego": "forensics",
    "network": "forensics",
    "pcap": "forensics",
    "reverse": "reverse",
    "reversing": "reverse",
    "rev": "reverse",
    "crypto": "crypto",
    "cryptography": "crypto",
    "crypt": "crypto",
}
DIFFICULTIES = {"easy", "medium", "hard"}
STATE_SCORES = {
    "hash-verified": 1000,
    "checker-verified": 1000,
    "local-replica": 900,
    "transcript-derived": 800,
    "candidate": 600,
    "payload-ready": 350,
    "candidate-review": 200,
    "needs-review": 180,
    "reference-only": 0,
}
IGNORED_PARTS = {"ico-scan-runs", "commands", "artifacts", "cache", "__pycache__", ".git"}
CONTROL_FILES = {
    "readme.md",
    "cheatsheet.md",
    "rules.md",
    "flag_hashes.json",
    ".ds_store",
    ".gitignore",
    # Walkthroughs and manuals are evidence about old runs, never current
    # task input.  Keep them out of both slot discovery and generic adapters.
    "ico_full_walkthrough.md",
    "ico_ctf_writeup.md",
    "ico_self_solve_manual.md",
    "ico_final_selection_prep.md",
    "ico_learning_course.md",
    "historical-solution.md",
    "playbook.md",
    "solution.md",
    "solutions.md",
    "writeup.md",
}


def _is_control_file(path: Path) -> bool:
    return path.name.casefold() in CONTROL_FILES
MANIFEST_NAMES = ("task.txt", "task.md", "challenge.md", "README.md")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (SolveCandidate, SolveSlot, SolveReport)):
        return value.to_dict()
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    return value


@dataclass(frozen=True)
class SolveCandidate:
    value: str
    task_id: str
    story_id: str
    family: str
    state: str
    score: int
    sources: tuple[str, ...] = ()
    triage: str = "candidate"

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class SolveSlot:
    task_id: str
    story_id: str
    family: str
    difficulty: str
    paths: tuple[Path, ...]
    task_path: Path | None = None
    root: Path | None = None

    def to_dict(self) -> dict[str, object]:
        return _jsonable(asdict(self))


@dataclass(frozen=True)
class SolveReport:
    slots: tuple[SolveSlot, ...]
    candidates: tuple[SolveCandidate, ...]
    errors: tuple[str, ...] = ()
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "slots": [slot.to_dict() for slot in self.slots],
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "errors": list(self.errors),
            "metadata": _jsonable(self.metadata),
        }


def _safe_name(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")
    return clean or "input"


def _read_text(path: Path, limit: int) -> str:
    try:
        return path.read_bytes()[:limit].decode("utf-8", errors="replace")
    except OSError:
        return ""


def _manifest_for(root: Path) -> Path | None:
    for name in MANIFEST_NAMES:
        candidate = root / name
        if not candidate.is_file() or candidate.is_symlink():
            continue
        # README is only authoritative when it lives inside a named task
        # directory; a story-level README must not swallow all five slots.
        if name == "README.md" and not any(part.casefold() in FAMILY_ALIASES for part in root.parts):
            continue
        return candidate.resolve()
    return None


def _iter_files(root: Path, *, max_files: int, max_bytes: int) -> list[Path]:
    if root.is_file():
        return [root.resolve()]
    output: list[Path] = []
    for current, directories, names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = [
            name
            for name in directories
            if not name.startswith(".")
            and name not in IGNORED_PARTS
            and not (current_path / name).is_symlink()
        ]
        for name in sorted(names):
            if name.startswith("."):
                continue
            candidate = current_path / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                if candidate.stat().st_size > max_bytes:
                    continue
            except OSError:
                continue
            output.append(candidate.resolve())
            if len(output) >= max_files:
                return output
    return output


def _safe_member(name: str) -> bool:
    path = Path(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name and not name.startswith(("-", "@"))


def _extract_archive(
    path: Path,
    destination: Path,
    limits: SolverLimits,
    *,
    runner_policy: RunnerPolicy | None = None,
) -> Path:
    """Extract common containers with path, file-count, and byte bounds."""

    destination.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0

    def write_member(name: str, payload: bytes) -> None:
        nonlocal total, count
        if not _safe_member(name):
            return
        if count >= limits.max_files or total + len(payload) > limits.max_bytes:
            return
        target = (destination / name).resolve()
        try:
            target.relative_to(destination.resolve())
        except ValueError:
            return
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        total += len(payload)
        count += 1

    suffix = path.suffix.lower()
    if suffix in {".zip", ".pk3", ".jar", ".apk", ".docx", ".xlsx", ".pptx"} or zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if info.is_dir() or not _safe_member(info.filename) or info.file_size > limits.max_bytes:
                    continue
                with archive.open(info) as stream:
                    payload = stream.read(min(info.file_size, limits.max_bytes - total + 1))
                if len(payload) <= limits.max_bytes - total:
                    write_member(info.filename, payload)
        return destination
    if suffix in {".tar", ".tgz", ".tbz", ".tbz2", ".txz"} or tarfile.is_tarfile(path):
        with tarfile.open(path, "r:*") as archive:
            for info in archive.getmembers():
                if not info.isfile() or not _safe_member(info.name) or info.size > limits.max_bytes:
                    continue
                stream = archive.extractfile(info)
                if stream is None:
                    continue
                write_member(info.name, stream.read(min(info.size, limits.max_bytes - total + 1)))
        return destination
    # Single-stream compression is kept flat and named after the source.
    if suffix in {".gz", ".xz", ".bz2", ".lzma"}:
        from ico_universal_data import extract_container

        extracted = extract_container(path, destination, limits)
        for item in extracted:
            relative = item.relative_to(destination / "artifacts" / "universal-data") if (destination / "artifacts" / "universal-data").exists() else item.name
            _ = relative
        return destination
    # 7z/rar/iso are handled by the already bounded 7zz extractor when it is
    # present.  If it is absent, retain the source as a single artifact.
    executable = shutil.which("7zz")
    if executable and suffix in {".7z", ".rar", ".iso"}:
        runner = CommandRunner(destination / "commands", policy=runner_policy)
        runner.run([executable, "x", "-y", f"-o{destination}", str(path)], cwd=path.parent, timeout=120.0, log_name="solve-archive-extract")
    return destination


def _prepare_inputs(
    inputs: Sequence[Path],
    workspace: Path,
    limits: SolverLimits,
    *,
    runner_policy: RunnerPolicy | None = None,
) -> tuple[Path, ...]:
    prepared: list[Path] = []
    source_root = workspace / "sources"
    source_root.mkdir(parents=True, exist_ok=True)
    for raw in inputs:
        path = raw.expanduser().resolve()
        if not path.exists() or path.is_symlink():
            continue
        if path.is_dir():
            prepared.append(path)
            continue
        if path.suffix.lower() in {".zip", ".pk3", ".jar", ".apk", ".7z", ".rar", ".iso", ".tar", ".tgz", ".gz", ".bz2", ".xz", ".lzma"}:
            digest = hashlib.sha256(path.read_bytes()[: limits.max_bytes]).hexdigest()[:12]
            destination = source_root / f"{_safe_name(path.stem)}-{digest}"
            try:
                prepared.append(_extract_archive(path, destination, limits, runner_policy=runner_policy))
            except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile):
                prepared.append(path)
            continue
        prepared.append(path)
    return tuple(prepared)


def _nearest_manifest(path: Path) -> Path | None:
    current = path if path.is_dir() else path.parent
    for candidate in (current, *current.parents):
        manifest = _manifest_for(candidate)
        if manifest is not None:
            return manifest
        if candidate.name in IGNORED_PARTS:
            break
    return None


def _normalise_family(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_-]+", " ", value.casefold())
    for token in re.split(r"[\s/_-]+", cleaned):
        if token in FAMILY_ALIASES:
            return FAMILY_ALIASES[token]
    for alias, family in FAMILY_ALIASES.items():
        if alias in cleaned:
            return family
    return "misc"


def _family_from_text(text: str, root: Path) -> str:
    for pattern in (r"(?im)^\s*(?:family|category|type)\s*[:=]\s*([A-Za-z _-]+)", r"(?im)^\s*#?\s*(web|pwn|forensics?|reverse|crypto)\b"):
        match = re.search(pattern, text)
        if match:
            family = _normalise_family(match.group(1))
            if family != "misc":
                return family
    family = _normalise_family(" ".join(root.parts[-4:]))
    if family != "misc":
        return family
    hint_text = f"{root.name} {text}".casefold()
    def has_hint(*tokens: str) -> bool:
        return any(re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", hint_text) for token in tokens)

    # Common pack naming conventions are useful only as a fallback after an
    # explicit task field.  They never override a stated family.
    if has_hint("pwn", "rop", "ret2", "format_string", "overflow", "heap"):
        return "pwn"
    if has_hint("reverse", "reversing", "rev", "elf", "disasm", "decompile"):
        return "reverse"
    if has_hint("crypto", "rsa", "aes", "cipher", "xor", "hash", "lcg", "mt19937"):
        return "crypto"
    if has_hint("web", "wordpress", "jwt", "oauth", "sqli", "ssti", "graphql"):
        return "web"
    if has_hint("forensic", "stego", "png", "wav", "pcap", "sqlite", "archive", "magic", "metadata", "dns"):
        return "forensics"
    return "misc"


def _difficulty_from_text(text: str, root: Path) -> str:
    match = re.search(r"(?im)^\s*(?:difficulty|level)\s*[:=]\s*(easy|medium|hard)\b", text)
    if match:
        return match.group(1).lower()
    for part in reversed(root.parts):
        if part.casefold() in DIFFICULTIES:
            return part.casefold()
    return "unknown"


def _story_id(root: Path, fallback_index: int) -> str:
    for part in reversed(root.parts):
        match = re.search(r"(?i)story[_ -]?(\d+)", part)
        if match:
            return f"story_{int(match.group(1)):02d}"
    return f"story_{fallback_index:02d}"


def _task_id(text: str, story: str, family: str) -> str:
    match = re.search(r"(?im)^\s*(?:task\s*id|id|slug)\s*[:=]\s*([A-Za-z0-9_.:/-]+)", text)
    return match.group(1).strip() if match else f"{story}/{family}"


def discover_solve_slots(
    inputs: Sequence[Path],
    workspace: Path,
    limits: SolverLimits,
    *,
    runner_policy: RunnerPolicy | None = None,
) -> tuple[SolveSlot, ...]:
    """Expand supplied containers and group related files into deterministic slots."""

    workspace = workspace.expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    prepared = _prepare_inputs(inputs, workspace, limits, runner_policy=runner_policy)
    manifests: dict[Path, Path] = {}
    loose: list[Path] = []
    for prepared_root in prepared:
        files = _iter_files(prepared_root, max_files=limits.max_files, max_bytes=limits.max_bytes)
        if prepared_root.is_file():
            manifest = _nearest_manifest(prepared_root)
            if manifest is not None:
                manifests[manifest.parent.resolve()] = manifest
            else:
                loose.append(prepared_root)
            continue
        for path in files:
            if _is_control_file(path):
                continue
            manifest = _nearest_manifest(path)
            if manifest is None:
                loose.append(path)
            else:
                manifests[manifest.parent.resolve()] = manifest

    grouped: list[tuple[Path, Path | None, list[Path]]] = []
    for root, manifest in sorted(manifests.items(), key=lambda item: str(item[0])):
        files = [
            path
            for path in _iter_files(root, max_files=limits.max_files, max_bytes=limits.max_bytes)
            if path != manifest and not _is_control_file(path) and path.name.casefold() not in IGNORED_PARTS
        ]
        grouped.append((root, manifest, files or [manifest]))
    if loose:
        by_parent: dict[Path, list[Path]] = {}
        for path in sorted(set(loose), key=str):
            by_parent.setdefault(path.parent.resolve(), []).append(path)
        for root, files in sorted(by_parent.items(), key=lambda item: str(item[0])):
            files = [path for path in files if not _is_control_file(path)]
            if not files:
                continue
            grouped.append((root, None, files))

    slots: list[SolveSlot] = []
    for index, (root, manifest, files) in enumerate(grouped, start=1):
        text = _read_text(manifest, limits.max_bytes) if manifest is not None else ""
        story = _story_id(root, index)
        family = _family_from_text(text, root)
        difficulty = _difficulty_from_text(text, root)
        task_id = _task_id(text, story, family)
        slots.append(SolveSlot(task_id, story, family, difficulty, tuple(sorted(set(files), key=str)), manifest, root))
    family_order = {name: index for index, name in enumerate(FAMILIES)}
    slots.sort(key=lambda slot: (slot.story_id, family_order.get(slot.family, 99), slot.task_id, tuple(map(str, slot.paths))))
    return tuple(slots)


def _slot_for_path(path: str | Path, slots: Sequence[SolveSlot]) -> SolveSlot | None:
    try:
        resolved = Path(path).expanduser().resolve()
    except OSError:
        return None
    matches: list[SolveSlot] = []
    for slot in slots:
        root = slot.root or (slot.task_path.parent if slot.task_path else (slot.paths[0].parent if slot.paths else None))
        if root is None:
            continue
        try:
            resolved.relative_to(root.resolve())
        except (OSError, ValueError):
            continue
        matches.append(slot)
    return max(matches, key=lambda slot: len((slot.root or Path()).parts)) if matches else None


def _candidate_hit(value: dict[str, object], slot: SolveSlot | None, *, fallback_source: str = "") -> dict[str, object]:
    hit = dict(value)
    hit["value"] = str(hit.get("value", "")).strip()
    if slot is not None:
        hit.setdefault("task_id", slot.task_id)
        hit.setdefault("story_id", slot.story_id)
        hit.setdefault("family", slot.family)
    hit.setdefault("state", "candidate")
    hit.setdefault("triage", flag_triage(hit["value"])[0])
    hit.setdefault("source", fallback_source)
    hit.setdefault("analyzer", "unknown")
    return hit


def _iter_result_candidates(result: Any) -> Iterable[dict[str, object]]:
    if isinstance(result, dict):
        raw = result.get("candidates", [])
    else:
        raw = getattr(result, "candidates", [])
    if not isinstance(raw, (list, tuple)):
        return ()
    for item in raw:
        if isinstance(item, dict):
            yield item


def rank_candidates(results: Iterable[Any], slots: Iterable[SolveSlot]) -> tuple[SolveCandidate, ...]:
    slots_tuple = tuple(slots)
    aggregates: dict[tuple[str, str], dict[str, object]] = {}
    for result in results:
        solver = str(result.get("solver", "unknown") if isinstance(result, dict) else getattr(result, "solver", "unknown"))
        category = str(result.get("category", "misc") if isinstance(result, dict) else getattr(result, "category", "misc"))
        for raw in _iter_result_candidates(result):
            value = str(raw.get("value", "")).strip()
            if not value:
                continue
            triage = str(raw.get("triage") or flag_triage(value)[0])
            if triage in {"likely-placeholder", "likely-noise"}:
                continue
            artifact = raw.get("artifact") or raw.get("path") or raw.get("source") or ""
            slot = None
            task_id = str(raw.get("task_id", ""))
            if task_id:
                slot = next((item for item in slots_tuple if item.task_id == task_id), None)
            if slot is None and artifact:
                slot = _slot_for_path(str(artifact), slots_tuple)
            if slot is None and len(slots_tuple) == 1:
                slot = slots_tuple[0]
            if slot is None and category in FAMILIES:
                matching = [item for item in slots_tuple if item.family == category]
                if len(matching) == 1:
                    slot = matching[0]
            if slot is None:
                continue
            key = (slot.task_id, value)
            state = str(raw.get("state", "candidate"))
            source = str(raw.get("source") or artifact or solver)
            analyzer = str(raw.get("analyzer") or solver)
            aggregate = aggregates.setdefault(
                key,
                {
                    "task_id": slot.task_id,
                    "story_id": slot.story_id,
                    "family": slot.family,
                    "value": value,
                    "state": state,
                    "sources": set(),
                    "analyzers": set(),
                    "triage": triage,
                },
            )
            if STATE_SCORES.get(state, 0) > STATE_SCORES.get(str(aggregate["state"]), 0):
                aggregate["state"] = state
            aggregate["sources"].add(source)  # type: ignore[union-attr]
            aggregate["analyzers"].add(analyzer)  # type: ignore[union-attr]
            # Some scanner candidates already carry independent analyzer names.
            for independent in raw.get("analyzers", ()) if isinstance(raw.get("analyzers"), (list, tuple, set)) else ():
                aggregate["analyzers"].add(str(independent))  # type: ignore[union-attr]
    ranked: list[SolveCandidate] = []
    for aggregate in aggregates.values():
        state = str(aggregate["state"])
        analyzers = aggregate["analyzers"]
        sources = aggregate["sources"]
        score = STATE_SCORES.get(state, 100)
        score += min(120, max(0, len(analyzers) - 1) * 20)
        score += min(60, max(0, len(sources) - 1) * 10)
        ranked.append(
            SolveCandidate(
                value=str(aggregate["value"]),
                task_id=str(aggregate["task_id"]),
                story_id=str(aggregate["story_id"]),
                family=str(aggregate["family"]),
                state=state,
                score=score,
                sources=tuple(sorted(str(item) for item in sources)),
                triage=str(aggregate["triage"]),
            )
        )
    family_order = {name: index for index, name in enumerate(FAMILIES)}
    ranked.sort(key=lambda item: (item.story_id, family_order.get(item.family, 99), item.task_id, -item.score, item.value))
    return tuple(ranked)


def select_flags(report: SolveReport) -> tuple[SolveCandidate, ...]:
    selected: dict[str, SolveCandidate] = {}
    for candidate in report.candidates:
        existing = selected.get(candidate.task_id)
        if existing is None or (candidate.score, candidate.value) > (existing.score, existing.value):
            selected[candidate.task_id] = candidate
    family_order = {name: index for index, name in enumerate(FAMILIES)}
    return tuple(sorted(selected.values(), key=lambda item: (item.story_id, family_order.get(item.family, 99), item.task_id)))


def format_stdout(report: SolveReport, *, quiet: bool = True) -> str:
    selected = select_flags(report)
    if not selected:
        return ""
    if len(selected) == 1 and len(report.slots) <= 1:
        return selected[0].value + "\n"
    return "".join(f"{item.task_id}\t{item.value}\n" for item in selected)


def _make_context(slot: SolveSlot, report_dir: Path, limits: SolverLimits, runner: CommandRunner) -> SolverContext:
    input_path = slot.paths[0] if slot.paths else (slot.task_path or slot.root or report_dir)
    classification: Classification = classify(input_path, runner) if input_path.is_file() else Classification("", "", "data", input_path.suffix.lower())
    task_text = _read_text(slot.task_path, limits.max_bytes) if slot.task_path else None
    return SolverContext(
        input_path=input_path,
        report_dir=report_dir,
        limits=limits,
        related_paths=tuple(path for path in slot.paths if path != input_path),
        task_text=task_text,
        classification=classification.to_dict(),
        metadata={"task_root": str(slot.root or input_path.parent), "task_id": slot.task_id, "story_id": slot.story_id, "family": slot.family},
    )


def _slot_for_artifact(path: Path, slots: Sequence[SolveSlot]) -> SolveSlot | None:
    resolved = path.resolve()
    scored: list[tuple[tuple[int, int, int], SolveSlot]] = []
    for slot in slots:
        for member in slot.paths:
            try:
                member_path = member.resolve()
                member_parent = member_path.parent
                root = (slot.root or member_parent).resolve()
            except (OSError, ValueError):
                continue
            score = 0
            # Prefer an exact artifact or the deepest containing task root.
            if resolved == member_path:
                score = max(score, 500)
            if resolved == root:
                score = max(score, 450)
            try:
                if resolved.is_relative_to(root):
                    score = max(score, 300 + len(root.parts))
                if resolved.is_relative_to(member_parent):
                    score = max(score, 200 + len(member_parent.parts))
            except (OSError, ValueError):
                pass
            # A story directory often contains both ``task.zip`` and an
            # already extracted ``task/`` directory.  Attribute the archive
            # to the sibling task directory so its derived evidence cannot
            # create a duplicate story-level slot.
            if (
                resolved.parent == root.parent
                and resolved.stem.casefold() == root.name.casefold()
                and root != resolved.parent
            ):
                score = max(score, 650 + len(root.parts))
            if score:
                scored.append(((score, len(root.parts), len(slot.paths)), slot))
    if not scored:
        return None
    return max(scored, key=lambda item: item[0])[1]


def _run_adapter_derived_solvers(
    adapter_evidence: Sequence[AdapterEvidence],
    *,
    slots: Sequence[SolveSlot],
    report_dir: Path,
    limits: SolverLimits,
    runner: CommandRunner,
) -> list[Any]:
    """Feed bounded adapter outputs through the static registry once."""

    registry = build_default_registry()
    seen: set[str] = set()
    results: list[Any] = []
    processed = 0
    for evidence in adapter_evidence:
        raw_paths = evidence.metadata.get("derived_paths", []) if isinstance(evidence.metadata, dict) else []
        if not isinstance(raw_paths, list):
            continue
        slot = _slot_for_artifact(Path(evidence.path), slots)
        if slot is None:
            continue
        for raw in raw_paths:
            if processed >= limits.max_files:
                return results
            path = Path(str(raw)).expanduser()
            if not path.is_file() or path.is_symlink():
                continue
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                continue
            if digest in seen:
                continue
            seen.add(digest)
            processed += 1
            context = _make_context(
                SolveSlot(
                    slot.task_id,
                    slot.story_id,
                    slot.family,
                    slot.difficulty,
                    (path,),
                    slot.task_path,
                    slot.root,
                ),
                report_dir,
                limits,
                runner,
            )
            try:
                solved = registry.solve(context)
            except Exception:
                continue
            for solved_result in solved:
                for candidate in getattr(solved_result, "candidates", []) or []:
                    if isinstance(candidate, dict):
                        candidate.setdefault("task_id", slot.task_id)
                        candidate.setdefault("story_id", slot.story_id)
                        candidate.setdefault("family", slot.family)
            results.extend(solved)
    return results


def solve_inputs(
    inputs: Sequence[Path],
    *,
    debug_dir: Path | None = None,
    mode: str = "full",
    limits: SolverLimits = SolverLimits(),
    workers: int = 4,
    deadline_seconds: float | None = None,
    cache_dir: Path | None = None,
    evidence_db: Path | None = None,
) -> SolveReport:
    """Run task-aware, universal, and extended offline adapters."""

    if mode not in {"fast", "full"}:
        raise ValueError(f"unsupported solve mode: {mode}")
    source_paths = tuple(Path(item).expanduser() for item in inputs)
    errors: list[str] = []
    if not source_paths:
        return SolveReport((), (), ("no input paths supplied",))
    missing = [str(path) for path in source_paths if not path.exists()]
    if missing:
        errors.extend(f"input does not exist: {path}" for path in missing)
    if debug_dir is not None:
        workspace = debug_dir.expanduser().resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        temporary: tempfile.TemporaryDirectory[str] | None = None
    else:
        temporary = tempfile.TemporaryDirectory(prefix="ico-solve-")
        workspace = Path(temporary.name).resolve()
    started = time.monotonic()
    deadline_at = None if deadline_seconds is None else started + max(0.0, deadline_seconds)
    try:
        # Apply one bounded policy to every external process launched by the
        # solve path.  ``run_scan`` receives this runner below, so its
        # classifiers, task solvers, and adapter profiles share the same
        # process-group cleanup and resource limits.
        runner_policy = RunnerPolicy(
            max_cpu_seconds=max(1, math.ceil(limits.timeout_seconds)),
            max_memory_bytes=2 * 1024 * 1024 * 1024,
            max_output_bytes=MAX_CAPTURE_BYTES,
        )
        prepared_inputs = _prepare_inputs(source_paths, workspace / "prepared", limits, runner_policy=runner_policy)
        slots = discover_solve_slots(prepared_inputs, workspace / "discovery", limits, runner_policy=runner_policy)
        if not slots:
            errors.append("no readable task files or artifacts found")
            return SolveReport((), (), tuple(errors))
        benchmark_results: list[dict[str, Any]] = []
        benchmark_slots = True
        for slot in slots:
            task_text = _read_text(slot.task_path, limits.max_bytes) if slot.task_path else ""
            if "ICO FINAL BENCHMARK" not in task_text or slot.root is None:
                benchmark_slots = False
                continue
            mechanism_match = re.search(r"(?im)^\s*Mechanism\s*:\s*(\S+)\s*$", task_text)
            mechanism = mechanism_match.group(1) if mechanism_match else ""
            solved = solve_final_task(slot.root, slot.task_id, slot.family, mechanism, task_text)
            if solved is not None:
                benchmark_results.append(solved)
        # The generated benchmark has a dedicated, deterministic task solver.
        # Avoid generic fan-out on its synthetic evidence: generic adapters can
        # surface encoded decoys and would make a local benchmark score depend
        # on which optional binaries happen to be installed.
        benchmark_fast_path = bool(slots) and benchmark_slots
        runner = CommandRunner(workspace / "adapter-commands", policy=runner_policy)
        scan_report: dict[str, object] = {}
        if benchmark_fast_path:
            scan_report = {"summary": {"benchmark_fast_path": True}}
        else:
            try:
                scan_budget = None if deadline_at is None else max(0.0, deadline_at - time.monotonic())
                scan_report = run_scan(
                    [str(path) for path in prepared_inputs if path.exists()],
                    out_dir=workspace / "scan",
                    max_depth=limits.max_depth,
                    max_files=limits.max_files,
                    max_bytes=limits.max_bytes,
                    tool_timeout=limits.timeout_seconds,
                    archive_timeout=max(60.0, limits.timeout_seconds * 4),
                    verbose=False,
                    progress=False,
                    solver_registry=build_default_registry(),
                    mode=mode,
                    profile_workers=max(1, min(int(workers), 32)),
                    deadline_seconds=scan_budget,
                )
            except Exception as exc:  # preserve adapter results if one scanner stage fails
                errors.append(f"ico-scan: {type(exc).__name__}: {exc}")
        classifications: dict[Path, Classification] = {}
        all_paths = sorted({path for slot in slots for path in slot.paths if path.is_file()}, key=str)
        for path in all_paths:
            try:
                classifications[path.resolve()] = classify(path, runner)
            except Exception as exc:
                errors.append(f"classification {path}: {type(exc).__name__}: {exc}")
        context_hashes: dict[Path, str] = {}
        for slot in slots:
            task_text = _read_text(slot.task_path, limits.max_bytes) if slot.task_path else ""
            related = []
            for related_path in slot.paths:
                try:
                    related.append((str(related_path), hashlib.sha256(related_path.read_bytes()).hexdigest()))
                except OSError:
                    continue
            context_payload = json.dumps(
                {"task_id": slot.task_id, "task_text": task_text, "related": related},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            context_hash = hashlib.sha256(context_payload).hexdigest()
            for slot_path in slot.paths:
                context_hashes[slot_path.resolve()] = context_hash
        selected_cache = cache_dir.expanduser().resolve() if cache_dir is not None else workspace / "adapter-cache"
        adapter_deadline = None if deadline_at is None else max(0.0, deadline_at - time.monotonic())
        verified_paths: set[Path] = set()
        if isinstance(scan_report, dict):
            for candidate in scan_report.get("candidates", []) if isinstance(scan_report.get("candidates", []), list) else []:
                if not isinstance(candidate, dict) or str(candidate.get("state", "")) not in {"hash-verified", "checker-verified"}:
                    continue
                raw_artifact = candidate.get("artifact")
                if isinstance(raw_artifact, str) and raw_artifact:
                    try:
                        verified_paths.add(Path(raw_artifact).expanduser().resolve())
                    except OSError:
                        pass
        if benchmark_fast_path:
            adapter_evidence = []
            derived_solver_results = []
        else:
            adapter_evidence = run_adapter_profiles(
                all_paths,
                classifications=classifications,
                output_dir=workspace / "adapter-artifacts",
                runner=runner,
                mode=mode,
                workers=workers,
                deadline_seconds=adapter_deadline,
                cache_dir=selected_cache,
                context_hashes=context_hashes,
                skip_paths=verified_paths,
            )
            derived_solver_results = _run_adapter_derived_solvers(
                adapter_evidence,
                slots=slots,
                report_dir=workspace / "derived-solvers",
                limits=limits,
                runner=runner,
            )
        result_objects: list[Any] = []
        result_objects.extend(benchmark_results)
        scan_candidates = scan_report.get("candidates", []) if isinstance(scan_report, dict) else []
        if isinstance(scan_candidates, list):
            result_objects.append(SimpleNamespace(solver="ico-scan", category="misc", candidates=scan_candidates))
        for evidence in adapter_evidence:
            result_objects.append(
                SimpleNamespace(
                    solver=f"adapter:{evidence.tool}",
                    category="forensics" if evidence.tool in {"zsteg", "binwalk-signatures", "tshark-summary", "metadata", "cyberchef"} else "misc",
                    candidates=[dict(candidate, artifact=evidence.path, source=candidate.get("source", evidence.log_path or evidence.path), analyzer=evidence.tool) for candidate in evidence.candidates],
                )
            )
        for derived_result in derived_solver_results:
            result_objects.append(derived_result)
        candidates = rank_candidates(result_objects, slots)
        metadata = {
            "mode": mode,
            "wall_clock_seconds": round(time.monotonic() - started, 6),
            "benchmark_fast_path": benchmark_fast_path,
            "benchmark_result_count": len(benchmark_results),
            "tool_inventory": tool_inventory(),
            "available_tool_count": len(available_tool_specs()),
            "scan_summary": scan_report.get("summary", {}) if isinstance(scan_report, dict) else {},
            "adapter_count": len(adapter_evidence),
            "adapter_statuses": {evidence.tool: evidence.status for evidence in adapter_evidence},
            "adapter_cache_hits": sum(1 for evidence in adapter_evidence if evidence.cache_hit),
            "adapter_duration_seconds": round(sum(evidence.duration_seconds for evidence in adapter_evidence), 6),
            "derived_solver_result_count": len(derived_solver_results),
            "workers": max(1, min(int(workers), 32)),
            "deadline_seconds": deadline_seconds,
            "cache_dir": str(selected_cache),
            "verified_paths_skipped": len(verified_paths),
            "runner_policy": {
                "max_cpu_seconds": runner_policy.max_cpu_seconds,
                "max_memory_bytes": runner_policy.max_memory_bytes,
                "max_output_bytes": runner_policy.max_output_bytes,
            },
        }
        report = SolveReport(slots, candidates, tuple(errors), metadata)
        if evidence_db is not None:
            try:
                with EvidenceStore(evidence_db) as store:
                    metadata["evidence_store"] = persist_solve_report(
                        store,
                        report,
                        solver_revision="ico-solve-1",
                    )
                metadata["evidence_db"] = str(Path(evidence_db).expanduser().resolve())
            except (OSError, ValueError, sqlite3.Error) as exc:
                errors.append(f"evidence-store: {type(exc).__name__}: {exc}")
                report = SolveReport(slots, candidates, tuple(errors), metadata)
        if debug_dir is not None:
            (workspace / "report.json").write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
            (workspace / "adapter-evidence.json").write_text(json.dumps(_jsonable([asdict(item) for item in adapter_evidence]), ensure_ascii=False, indent=2), encoding="utf-8")
        return report
    finally:
        if temporary is not None:
            temporary.cleanup()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ico-solve", description="Offline ICO final solver for supplied task files and local replicas.")
    parser.add_argument("paths", nargs="*", type=Path, help="task file, directory, archive, or story bundle")
    parser.add_argument("--mode", choices=("fast", "full"), default="full")
    parser.add_argument("--debug", type=Path, help="write report.json and adapter evidence to this directory")
    parser.add_argument("--family", choices=FAMILIES, help="print only one family after solving")
    parser.add_argument("--story", help="print only one story after solving")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-tool timeout in seconds")
    parser.add_argument("--workers", type=int, default=4, help="parallel adapter workers (1-32)")
    parser.add_argument("--deadline", type=float, help="global adapter deadline in seconds")
    parser.add_argument("--cache", type=Path, help="persistent adapter cache directory")
    parser.add_argument("--evidence-db", type=Path, help="persist artifact provenance and candidates in SQLite")
    parser.add_argument("--tools", action="store_true", help="show all integrated tools and availability")
    parser.add_argument("--version", action="version", version="ico-solve 0.1.0")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.tools:
        for item in tool_inventory():
            state = str(item.get("state") or ("available" if item["available"] else "missing"))
            mode = "offline" if item["offline_default"] else "local-only"
            backend = str(item.get("backend") or "native-or-python")
            print(f"{item['name']}\t{state}\t{mode}\t{backend}\t{item['description']}")
        return 0
    if not args.paths:
        _build_parser().error("at least one input path is required unless --tools is used")
    if args.timeout <= 0:
        _build_parser().error("--timeout must be positive")
    if args.workers < 1 or args.workers > 32:
        _build_parser().error("--workers must be between 1 and 32")
    if args.deadline is not None and args.deadline <= 0:
        _build_parser().error("--deadline must be positive")
    try:
        report = solve_inputs(
            args.paths,
            debug_dir=args.debug,
            mode=args.mode,
            limits=SolverLimits(timeout_seconds=args.timeout),
            workers=args.workers,
            deadline_seconds=args.deadline,
            cache_dir=args.cache,
            evidence_db=args.evidence_db,
        )
    except (OSError, ValueError) as exc:
        print(f"ico-solve: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    if args.family or args.story:
        selected_slots = tuple(slot for slot in report.slots if (not args.family or slot.family == args.family) and (not args.story or slot.story_id == args.story))
        selected_ids = {slot.task_id for slot in selected_slots}
        report = SolveReport(selected_slots, tuple(candidate for candidate in report.candidates if candidate.task_id in selected_ids), report.errors, report.metadata)
    output = format_stdout(report)
    if output:
        sys.stdout.write(output)
    if not report.slots:
        return 1
    return 0 if len(select_flags(report)) == len(report.slots) else 2


if __name__ == "__main__":
    raise SystemExit(main())
