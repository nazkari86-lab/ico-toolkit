#!/usr/bin/env python3
"""Small offline CLI for the installed hashpumpy length-extension library."""

from __future__ import annotations

import argparse
import base64
import sys

import hashpumpy


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a hash length-extension message for a known digest."
    )
    parser.add_argument("hexdigest")
    parser.add_argument("original")
    parser.add_argument("append")
    parser.add_argument("key_length", type=int)
    parser.add_argument("--base64", action="store_true", help="print the forged message as base64")
    args = parser.parse_args(argv)
    digest, forged = hashpumpy.hashpump(
        args.hexdigest, args.original, args.append, args.key_length
    )
    if isinstance(forged, str):
        forged_bytes = forged.encode("latin1")
    else:
        forged_bytes = bytes(forged)
    print(digest)
    print(
        base64.b64encode(forged_bytes).decode("ascii")
        if args.base64
        else forged_bytes.decode("latin1")
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
