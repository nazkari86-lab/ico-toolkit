#!/usr/bin/env python3
from __future__ import annotations

import argparse
import zipfile
from pathlib import Path


def make_fixtures(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "direct.bin").write_bytes(b"header\nico{fixture_direct}\ntrailer\n")
    (destination / "nested.txt").write_text("nested evidence: CTF{fixture_nested}\n", encoding="utf-8")
    (destination / "negative.txt").write_text("the word flag appears without a brace-form value\n", encoding="utf-8")
    with zipfile.ZipFile(destination / "fixture.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        info = zipfile.ZipInfo("nested.txt", date_time=(2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        archive.writestr(info, "nested evidence: CTF{fixture_nested}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    make_fixtures(args.out.expanduser().resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
