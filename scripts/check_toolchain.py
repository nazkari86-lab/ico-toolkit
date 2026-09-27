#!/usr/bin/env python3
"""Report optional analyzer availability without making a scan fail."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Iterable


DEFAULT_TOOLS = (
    "strings",
    "exiftool",
    "binwalk",
    "zsteg",
    "pngcheck",
    "steghide",
    "7zz",
    "qpdf",
    "pdftotext",
    "tshark",
    "vol",
    "r2",
    "ffprobe",
    "ffmpeg",
    "checksec",
    "ROPgadget",
    "ropper",
    "objdump",
    "nm",
    "otool",
    "lldb",
    "upx",
    "angr",
    "fls",
    "mmls",
    "icat",
    "tsk_recover",
    "olevba",
    "oleid",
    "mraptor",
    "giftext",
    "sox",
    "apktool",
    "jadx",
    "semgrep",
    "trufflehog",
    "gitleaks",
    "stegoveritas",
    "xortool",
    "hashid",
    "hashpumpy",
    "pdfid",
    "pdf-parser",
    "bulk_extractor",
    "qiling",
    "scalpel",
    "strace",
    "ltrace",
)


def inspect_tool(name: str, *, timeout: float = 2.0) -> dict[str, object]:
    """Return a JSON-safe capability record for one optional executable."""

    path = shutil.which(name)
    if path is None:
        return {"name": name, "status": "unavailable", "path": None, "version": None}
    record: dict[str, object] = {"name": name, "status": "available", "path": path, "version": None}
    try:
        probe = subprocess.run(
            [path, "--version"],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
        text = (probe.stdout or probe.stderr).strip()
        if text:
            record["version"] = text.splitlines()[0][:300]
        if probe.returncode not in (0, 1, 2):
            record["probe_status"] = "nonzero"
    except (OSError, subprocess.TimeoutExpired) as exc:
        record["probe_status"] = type(exc).__name__
    return record


def report_tools(names: Iterable[str] = DEFAULT_TOOLS) -> list[dict[str, object]]:
    return [inspect_tool(name) for name in names]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report ico-scan optional analyzer capabilities")
    parser.add_argument("tools", nargs="*", default=list(DEFAULT_TOOLS))
    args = parser.parse_args(argv)
    print(json.dumps({"schema_version": 1, "tools": report_tools(args.tools)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
