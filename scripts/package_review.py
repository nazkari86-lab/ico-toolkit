#!/usr/bin/env python3
"""Export a committed, first-party source snapshot for an offline AI review."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile


PRIORITY = (
    "ico_solver_engine.py", "ico_solve.py", "ico_universal_registry.py",
    "ico_task_solvers.py", "ico_prompt_solvers.py", "TOOL_CATALOG.md",
)
ROOT_FILES = {
    "README.md", "TOOL_CATALOG.md", "AI_REVIEW.md", "env.sh", "verify.sh",
    "ico-scan", "ico-solve", "ico", "ico-quals-active", ".gitignore", ".gitattributes",
    "androguard", "hashpump", "lief", "pdf-parser", "pdfid",
}
TEXT_SUFFIXES = {".py", ".sh", ".java", ".md", ".txt", ".json", ".toml", ".yaml", ".yml", ".c", ".cpp", ".h"}


def selected(name: str) -> bool:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        return False
    if len(path.parts) == 1:
        return (name in ROOT_FILES or re.fullmatch(r"ico_[\w]+\.py", name) is not None
                or re.fullmatch(r"requirements[\w-]*\.txt", name) is not None)
    if path.parts[0] in {"scripts", "tests", "docs"}:
        return path.suffix in TEXT_SUFFIXES
    if path.parts[0] == "bin":
        return True  # Only UTF-8 text blobs are accepted below.
    return name.startswith(".github/workflows/") and path.suffix in {".yml", ".yaml"}


def git(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def read_tree(repo: Path, revision: str) -> list[dict]:
    entries = []
    for record in git(repo, "ls-tree", "-rlz", revision).split(b"\0"):
        if not record:
            continue
        header, name = record.split(b"\t", 1)
        mode, kind, object_id, size = header.split()
        entries.append({"path": name.decode("utf-8"), "mode": mode.decode(),
                        "kind": kind.decode(), "object_id": object_id.decode(),
                        "bytes": int(size) if size != b"-" else 0})
    return sorted(entries, key=lambda item: item["path"])


def inventory(entries: list[dict], revision: str) -> str:
    lines = [f"Committed directory inventory: {revision}", "Sizes are uncompressed Git blob bytes.", ""]
    for directory in ("scripts", "tests", "docs", "benchmarks"):
        children: dict[str, list[int]] = {}
        for entry in entries:
            parts = PurePosixPath(entry["path"]).parts
            if len(parts) < 2 or parts[0] != directory:
                continue
            label = parts[1] + ("/" if len(parts) > 2 else "")
            count, size = children.setdefault(label, [0, 0])
            children[label] = [count + 1, size + entry["bytes"]]
        lines.append(f"{directory}/")
        for label, (count, size) in sorted(children.items()):
            lines.append(f"  {label} | {count} files | {size} bytes")
        lines.append("")
    return "\n".join(lines)


def write_zip(path: Path, contents: dict[str, bytes], modes: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(contents.items()):
            member = zipfile.ZipInfo("ico-toolkit/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = int(modes.get(name, "100644"), 8) << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, data)


def package(repo: Path, out: Path, ref: str) -> dict:
    revision = git(repo, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}").decode().strip()
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError("output directory must be empty; existing files were preserved")
    entries = read_tree(repo, revision)
    contents: dict[str, bytes] = {}
    modes: dict[str, str] = {}
    excluded = Counter()
    for entry in entries:
        name = entry["path"]
        if not selected(name) or entry["mode"] not in {"100644", "100755"} or entry["bytes"] > 1024 * 1024:
            excluded[PurePosixPath(name).parts[0]] += 1
            continue
        data = git(repo, "cat-file", "blob", entry["object_id"])
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            excluded[PurePosixPath(name).parts[0]] += 1
            continue
        if b"\x00" in data:
            excluded[PurePosixPath(name).parts[0]] += 1
            continue
        contents[name] = data
        modes[name] = entry["mode"]
    if not contents:
        raise ValueError("no first-party text files found in the selected commit")
    manifest = {
        "schema_version": 1, "revision": revision,
        "scope": "Committed first-party source, tests, scripts, launchers, and documentation; not a full runtime distribution.",
        "priority": [name for name in PRIORITY if name in contents],
        "excluded_by_top_level": dict(sorted(excluded.items())),
        "files": [{"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in sorted(contents.items())],
    }
    source_links = "\n".join(
        f"- https://raw.githubusercontent.com/nazkari86-lab/ico-toolkit/{revision}/{name}"
        for name in manifest["priority"]
    )
    first = f"""# ICO Toolkit: offline code review

Snapshot: `{revision}`. All source bytes come from this Git commit.
Uncommitted files, local reports, virtual environments, third-party sources,
models, native binaries, and benchmark challenge data are excluded.
The archives are source-review packages, not standalone installations.

## Start here

Read the six priority files, then follow imports using the rest of ico-src.zip.
manifest.json lists every exported file, its size, and its SHA-256.
DIRECTORY_INVENTORY.txt lists scripts/, tests/, docs/, and benchmarks/ from
the same commit. Benchmark contents themselves are not supplied.

## Revision-specific links for the public ICO Toolkit repository

If this commit is published there, these URLs refer to the same source revision
as the attachments. A local-only commit or a different repository may not exist
at these URLs; the attached source remains available without network access.
Paste the URLs directly into the reviewing AI chat if it requires explicit URLs.

{source_links}

## Architecture map

- ico_solve.py: orchestration, candidate selection, derived artifact flow, CLI.
- ico_solve.py::_write_gpt_handoffs: GPT-4.1 handoff prompts and evidence ZIPs.
- ico_prompt_solvers.py: solvers that derive answers from task statements;
  this module does not own the GPT handoff packager.
- ico_solver_engine.py and ico_universal_registry.py: solver contracts and registration.
- ico_task_solvers.py and ico_quals_solvers.py: task-aware offline solvers.
- ico_universal_*.py: category-specific offline analysis.
- ico_tool_adapters.py: tool selection, execution, and output interpretation.
- TOOL_CATALOG.md: tool capabilities and prerequisites.

## Suggested review request

Review this snapshot as a CTF solver. Prioritize concrete failures on new tasks,
broken links between analysis stages, false candidates, and wasted time.
Inspect the GPT-4.1 handoff for context-budget handling, missing evidence,
category-specific prompts, and useful next actions. Propose fixes with file
and function references and reproducible regression cases. Distinguish observed
behavior, static hypotheses, and tests actually executed. A candidate or a
prepared payload alone is not a confirmed solve.

The full local check is ./verify.sh and needs optional tools and datasets.
Do not claim it passed in a review environment where those are unavailable.
"""
    metadata = {
        "REVIEW_FIRST.md": first.encode(),
        "manifest.json": (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode(),
        "DIRECTORY_INVENTORY.txt": inventory(entries, revision).encode(),
    }
    priority = {name: contents[name] for name in PRIORITY if name in contents}
    text = [first]
    for name, data in priority.items():
        text.extend([f"\n===== BEGIN FILE: {name} =====\n", data.decode("utf-8"),
                     f"\n===== END FILE: {name} =====\n"])
    out.mkdir(parents=True, exist_ok=True)
    for name, data in metadata.items():
        (out / name).write_bytes(data)
    (out / "ico-priority.txt").write_text("".join(text), encoding="utf-8")
    write_zip(out / "ico-src.zip", {**contents, **metadata}, modes)
    priority_metadata = {**metadata, "manifest.json": (
        json.dumps({**manifest, "files": [item for item in manifest["files"] if item["path"] in priority]},
                   ensure_ascii=False, indent=2) + "\n").encode()}
    write_zip(out / "ico-priority.zip", {**priority, **priority_metadata}, modes)
    return {"revision": revision, "source_files": len(contents),
            "source_bytes": sum(map(len, contents.values())),
            "outputs": {p.name: {"path": str(p.resolve()), "bytes": p.stat().st_size}
                        for p in sorted(out.iterdir()) if p.is_file()}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--revision", default="HEAD", help="committed Git revision; working-tree changes are excluded")
    parser.add_argument("--out", type=Path, required=True, help="new or empty export directory")
    args = parser.parse_args()
    try:
        result = package(args.repo.resolve(), args.out.expanduser().absolute(), args.revision)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"review export failed: {exc}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
