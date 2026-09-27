#!/usr/bin/env python3
"""Offline response generator for the DUCTF 2024 V for Vieta protocol.

Read one JSON challenge object per line on stdin and print the corresponding
JSON answer. This helper never opens a network connection or submits a flag.
"""

from __future__ import annotations

import json
import math
import sys


TARGET_BITS = 2048


def solve_pair(k: int, *, target_bits: int = TARGET_BITS) -> tuple[int, int]:
    """Return positive integers satisfying the challenge equation exactly."""

    if isinstance(k, bool) or not isinstance(k, int) or k <= 0:
        raise ValueError("k must be a positive integer")
    if target_bits < 1:
        raise ValueError("target_bits must be positive")

    root = math.isqrt(k)
    if root * root != k:
        raise ValueError("k is not a perfect square")
    if root < 2:
        raise ValueError("the square root of k is too small for a positive Vieta-jump pair")

    # (root, 2*root^3-root) is one root pair. Replacing the first root
    # by the other root of the quadratic gives a pair above the bit-length gate.
    b = 2 * root**3 - root
    a = (2 * k - 1) * b - root
    if a <= 0 or b <= 0:
        raise ValueError("the Vieta-jump pair is not positive")
    if a.bit_length() <= target_bits or b.bit_length() <= target_bits:
        raise ValueError("the Vieta-jump pair does not meet the challenge bit-length gate")

    numerator = a * a + a * b + b * b
    denominator = 2 * a * b + 1
    if numerator != k * denominator:
        raise ValueError("the derived pair failed exact equation verification")
    return a, b


def main() -> int:
    for line_number, line in enumerate(sys.stdin, start=1):
        try:
            challenge = json.loads(line)
        except json.JSONDecodeError:
            # The service prints a human-readable banner before its first JSON.
            continue
        if not isinstance(challenge, dict) or "k" not in challenge:
            continue
        try:
            k = int(challenge["k"])
            a, b = solve_pair(k)
        except (TypeError, ValueError) as exc:
            print(f"line {line_number}: {exc}", file=sys.stderr)
            continue
        print(json.dumps({"a": a, "b": b}, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
