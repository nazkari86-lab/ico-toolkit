#!/usr/bin/env python3
"""Read-only tool profiles and bounded archive extraction for ico-scan."""

from __future__ import annotations

import os
import re
import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, Optional

from ico_scan_core import Classification, CommandResult, CommandRunner


ArgsBuilder = Callable[[Path], list[str]]


@dataclass(frozen=True)
class ToolProfile:
    name: str
    executable: str
    build_args: ArgsBuilder
    timeout: float = 30.0
    stage: str = "specialized"

    def args_for(self, path: Path) -> list[str]:
        return self.build_args(path)


@dataclass
class ArchiveMember:
    path: str
    size: Optional[int]
    is_directory: bool = False
    is_symlink: bool = False


@dataclass
class ExtractionResult:
    discovered: list[Path] = field(default_factory=list)
    listing: str = ""
    extracted: bool = False
    partial: bool = False
    refused_reason: Optional[str] = None
    total_declared_bytes: int = 0
    declared_files: int = 0
    selected_entries: list[ArchiveMember] = field(default_factory=list)
    skipped_entries: list[dict[str, object]] = field(default_factory=list)
    command: Optional[CommandResult] = None

    def archive_report(self) -> dict[str, object]:
        return {
            "extracted": self.extracted,
            "partial": self.partial,
            "refused_reason": self.refused_reason,
            "total_declared_bytes": self.total_declared_bytes,
            "declared_files": self.declared_files,
            "selected_entries": [
                {
                    "path": member.path,
                    "size": member.size,
                    "is_directory": member.is_directory,
                }
                for member in self.selected_entries
            ],
            "skipped_entries": self.skipped_entries,
        }


def _args(executable: str, *prefix: str) -> ArgsBuilder:
    return lambda path: [executable, *prefix, str(path)]


def _universal_profiles(classification: Classification) -> list[ToolProfile]:
    profiles = [
        ToolProfile("strings-ascii", "strings", _args("strings", "-a", "-n", "4"), timeout=20.0, stage="fast"),
        ToolProfile("binwalk-signatures", "binwalk", _args("binwalk"), timeout=45.0, stage="deep"),
    ]
    metadata_kinds = {"png", "jpeg", "bmp", "image", "audio", "wav", "video", "media", "pdf", "archive"}
    if classification.kind in metadata_kinds:
        profiles.insert(1, ToolProfile("metadata", "exiftool", _args("exiftool"), timeout=20.0, stage="fast"))
    return profiles


def profiles_for(classification: Classification) -> list[ToolProfile]:
    profiles = _universal_profiles(classification)
    kind = classification.kind
    if kind in {"png", "bmp"}:
        profiles.extend(
            [
                ToolProfile("zsteg", "zsteg", _args("zsteg", "-a"), timeout=60.0, stage="deep"),
                ToolProfile("pngcheck", "pngcheck", _args("pngcheck", "-vt"), timeout=20.0, stage="specialized"),
            ]
        )
    if kind in {"jpeg", "wav"} or classification.extension in {".au", ".aiff", ".aif"}:
        profiles.append(ToolProfile("steghide-info", "steghide", _args("steghide", "info", "-p", ""), timeout=20.0, stage="specialized"))
    if is_archive(classification):
        profiles.append(ToolProfile("archive-list", "7zz", _args("7zz", "l", "-slt"), timeout=30.0, stage="specialized"))
    if kind == "pdf":
        profiles.extend(
            [
                ToolProfile("qpdf-check", "qpdf", _args("qpdf", "--check"), timeout=20.0, stage="specialized"),
                ToolProfile(
                    "pdf-text",
                    "pdftotext",
                    lambda path: ["pdftotext", "-layout", str(path), "-"],
                    timeout=30.0,
                    stage="specialized",
                ),
            ]
        )
    if kind == "pcap":
        profiles.append(
            ToolProfile(
                "tshark-summary",
                "tshark",
                lambda path: ["tshark", "-r", str(path), "-q", "-z", "io,phs"],
                timeout=45.0,
                stage="deep",
            )
        )
    if kind == "memory":
        profiles.extend(
            [
                ToolProfile(
                    "volatility-windows-info",
                    "vol",
                    lambda path: ["vol", "--offline", "-q", "-f", str(path), "windows.info"],
                    timeout=60.0,
                    stage="deep",
                ),
                ToolProfile(
                    "volatility-linux-banners",
                    "vol",
                    lambda path: ["vol", "--offline", "-q", "-f", str(path), "linux.banners"],
                    timeout=60.0,
                    stage="deep",
                ),
            ]
        )
    if kind == "binary":
        profiles.append(
            ToolProfile(
                "radare2-strings",
                "r2",
                lambda path: ["r2", "-q", "-c", "izz~(ico|ctf|flag)", "-c", "q", str(path)],
                timeout=45.0,
                stage="deep",
            )
        )
    if kind in {"audio", "video", "media", "wav"}:
        profiles.append(
            ToolProfile(
                "ffprobe",
                "ffprobe",
                lambda path: ["ffprobe", "-v", "error", "-show_format", "-show_streams", "-of", "json", str(path)],
                timeout=30.0,
                stage="fast",
            )
        )
    return profiles


def filter_profiles_for_mode(profiles: list[ToolProfile], mode: str) -> list[ToolProfile]:
    """Select the bounded profile stages for a scan mode."""

    if mode == "full":
        return list(profiles)
    if mode == "fast":
        return [profile for profile in profiles if profile.stage == "fast"]
    raise ValueError(f"unsupported scan mode: {mode}")


def is_archive(classification: Classification) -> bool:
    if classification.kind == "archive":
        return True
    mime = classification.mime.lower()
    description = classification.description.lower()
    extension = classification.extension.lower()
    return (
        any(token in mime or token in description for token in ("zip", "rar", "7-zip", "gzip", "bzip", "compressed", "tar", "iso 9660", "openxml"))
        or extension in {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".iso", ".jar", ".apk", ".docx", ".xlsx", ".pptx"}
    )


class ArchiveExtractor:
    def __init__(self, runner: CommandRunner, *, max_bytes: int = 100 * 1024 * 1024, max_files: int = 200) -> None:
        self.runner = runner
        self.max_bytes = max_bytes
        self.max_files = max_files

    @staticmethod
    def _parse_members(listing: str) -> list[ArchiveMember]:
        records: list[dict[str, str]] = []
        fields: dict[str, str] = {}
        in_entries = False

        def flush() -> None:
            nonlocal fields
            if fields:
                records.append(fields)
                fields = {}

        for line in listing.splitlines():
            if line.strip() == "----------":
                flush()
                in_entries = True
                continue
            if not in_entries:
                continue
            if not line.strip():
                flush()
                continue
            if " = " in line:
                key, value = line.split(" = ", 1)
                fields[key.strip()] = value.strip()
        flush()

        members: list[ArchiveMember] = []
        for record in records:
            raw_path = record.get("Path", "")
            size_text = record.get("Size", "")
            if not raw_path:
                continue
            size = int(size_text) if size_text.isdecimal() else None
            attributes = record.get("Attributes", "")
            members.append(
                ArchiveMember(
                    path=raw_path,
                    size=size,
                    is_directory=record.get("Folder") == "+" or "D" in attributes.split(),
                    is_symlink=bool(record.get("Symbolic Link") or record.get("Hard Link"))
                    or any(token.startswith("l") for token in attributes.split()),
                )
            )
        return members

    @staticmethod
    def _unsafe_member_reason(member: ArchiveMember) -> Optional[str]:
        raw_path = member.path
        if any(ord(character) < 32 or ord(character) == 127 for character in raw_path):
            return "control character in member path"
        if "\\" in raw_path:
            return "backslash in member path"
        if any(character in raw_path for character in "*?[]"):
            return "wildcard in member path"
        if raw_path.startswith(("-", "@")):
            return "reserved leading character in member path"
        if raw_path.startswith("/") or re.match(r"^[A-Za-z]:", raw_path):
            return "absolute member path"
        parts = PurePosixPath(raw_path).parts
        if not parts or ".." in parts:
            return "parent traversal in member path"
        if member.is_symlink:
            return "link entry"
        return None

    def extract(
        self,
        path: Path,
        classification: Classification,
        destination: Path,
        *,
        timeout: float = 300.0,
    ) -> ExtractionResult:
        result = ExtractionResult()
        if not is_archive(classification):
            result.refused_reason = "not classified as an archive"
            return result
        listing_result = self.runner.run(
            ["7zz", "l", "-slt", str(path)],
            cwd=path.parent,
            timeout=min(30.0, timeout),
            log_name=f"archive-list-{path.name}",
        )
        result.command = listing_result
        result.listing = listing_result.combined_output()
        if listing_result.missing:
            result.refused_reason = "7zz is unavailable"
            return result
        if listing_result.timed_out:
            result.refused_reason = "archive listing timed out"
            return result
        if listing_result.returncode not in (0, None):
            result.refused_reason = f"archive listing failed with exit {listing_result.returncode}"
            return result
        members = self._parse_members(result.listing)
        files = [member for member in members if not member.is_directory]
        result.total_declared_bytes = sum(member.size or 0 for member in files)
        result.declared_files = len(files)

        selected_bytes = 0
        selected_names: set[str] = set()
        for member in files:
            reason = self._unsafe_member_reason(member)
            if reason is None and member.size is None:
                reason = "invalid or missing declared size"
            if reason is None and member.path in selected_names:
                reason = "duplicate member path"
            if reason is None and member.size > self.max_bytes:
                reason = "member exceeds byte limit"
            if reason is None and len(result.selected_entries) >= self.max_files:
                reason = "file-count limit reached"
            if reason is None and selected_bytes + member.size > self.max_bytes:
                reason = "cumulative byte limit reached"
            if reason:
                result.skipped_entries.append({"path": member.path, "size": member.size, "reason": reason})
                continue
            result.selected_entries.append(member)
            selected_names.add(member.path)
            selected_bytes += member.size

        result.partial = bool(result.skipped_entries)
        if not result.selected_entries:
            result.refused_reason = "no safe archive members fit the extraction limits"
            return result

        destination = destination.resolve()
        destination.mkdir(parents=True, exist_ok=True)
        selected_paths = [member.path for member in result.selected_entries]
        extraction = self.runner.run(
            ["7zz", "x", "-y", "-aoa", f"-o{destination}", str(path), *selected_paths],
            cwd=path.parent,
            timeout=timeout,
            log_name=f"archive-extract-{path.name}",
        )
        result.command = extraction
        if extraction.missing:
            result.refused_reason = "7zz is unavailable"
            return result
        if extraction.timed_out:
            result.refused_reason = "archive extraction timed out"
            return result
        if extraction.returncode not in (0, None):
            result.refused_reason = f"archive extraction failed with exit {extraction.returncode}"
            return result
        root = destination.resolve()
        selected_set = {PurePosixPath(name).as_posix() for name in selected_paths}
        actual_bytes = 0
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = [name for name in directories if not (current_path / name).is_symlink()]
            for filename in files:
                candidate = current_path / filename
                if candidate.is_symlink():
                    continue
                try:
                    resolved = candidate.resolve()
                    resolved.relative_to(root)
                except (OSError, ValueError):
                    continue
                relative = resolved.relative_to(root).as_posix()
                if resolved.is_file() and relative in selected_set:
                    result.discovered.append(resolved)
                    actual_bytes += resolved.stat().st_size
        if actual_bytes > self.max_bytes:
            result.discovered.clear()
            result.refused_reason = "actual extracted size exceeds byte limit"
            return result
        result.extracted = True
        return result
