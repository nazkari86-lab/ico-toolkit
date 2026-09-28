#!/usr/bin/env python3
"""Report optional analyzer availability without making a scan fail."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ico_tool_adapters import TOOL_SPECS, tool_inventory


DEFAULT_TOOLS = tuple(spec.name for spec in TOOL_SPECS)


def inspect_tool(name: str) -> dict[str, object]:
    """Check an unregistered executable by path without running it."""

    path = shutil.which(name)
    if path is None:
        return {
            "name": name,
            "status": "unavailable",
            "state": "missing",
            "available": False,
            "path": None,
            "version": None,
            "availability_reason": "not found on PATH",
        }
    return {
        "name": name,
        "status": "available",
        "state": "available",
        "available": True,
        "path": path,
        "version": None,
        "availability_reason": "executable found on PATH; not executed",
    }


def report_tools(names: Iterable[str] | None = None) -> list[dict[str, object]]:
    """Report all registered capabilities, or selected names, without execution."""

    registry = {str(item["name"]): item for item in tool_inventory()}
    selected = DEFAULT_TOOLS if names is None else tuple(names)
    return [registry[name] if name in registry else inspect_tool(name) for name in selected]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Report ico-scan optional analyzer capabilities")
    parser.add_argument("tools", nargs="*", default=None)
    args = parser.parse_args(argv)
    print(json.dumps({"schema_version": 1, "tools": report_tools(args.tools or None)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
