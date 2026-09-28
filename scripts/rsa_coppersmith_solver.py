#!/usr/bin/env python3
"""Recover low-exponent RSA messages with an explicitly supplied known prefix.

This is a bounded univariate Coppersmith profile.  It only runs when the task
provides n, e, c, a known plaintext prefix, and the byte length of the unknown
tail.  A recovered plaintext is emitted only after exact RSA re-encryption.
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from typing import Any


MAX_INPUT_BYTES = 1_048_576
MAX_MODULUS_BITS = 4096
MAX_UNKNOWN_BYTES = 64
MAX_LATTICE_DIMENSION = 35


def _integer_field(text: str, labels: tuple[str, ...]) -> int | None:
    label = "|".join(labels)
    pattern = re.compile(
        rf"(?im)^\s*(?:{label})\s*[:=]\s*(0x[0-9a-f]+|[0-9]+)\b"
    )
    matches = pattern.findall(text)
    if len(matches) != 1:
        return None
    token = matches[0]
    try:
        return int(token, 0) if token.lower().startswith("0x") else int(token, 10)
    except ValueError:
        return None


def parse_parameters(text: str) -> dict[str, Any] | None:
    """Parse one deliberately explicit RSA known-prefix instance."""

    n = _integer_field(text, ("n", "modulus"))
    e = _integer_field(text, ("e", "public[_ ]?exponent"))
    c = _integer_field(text, ("c", "ciphertext", "cipher"))
    if n is None or e is None or c is None:
        return None

    prefix_hex = re.findall(
        r"(?im)^\s*known_prefix_hex\s*[:=]\s*([0-9a-f]+)\s*$", text
    )
    prefix_text = re.findall(
        r"(?im)^\s*(?:known[_ -]*(?:plaintext[_ -]*)?prefix|"
        r"(?:the[_ -]+)?plaintext[_ -]*(?:starts|begins)[_ -]*with|starts[_ -]*with)"
        r"\s*[:=]?\s*[\"'`]?([A-Za-z0-9{}_.\-/]{2,64})",
        text,
    )
    if len(prefix_hex) == 1 and not prefix_text:
        try:
            prefix = bytes.fromhex(prefix_hex[0])
        except ValueError:
            return None
    elif len(prefix_text) == 1 and not prefix_hex:
        prefix = prefix_text[0].encode("ascii")
    else:
        return None

    length_fields = re.findall(
        r"(?im)^\s*(?:unknown_suffix_bytes|unknown_bytes|suffix_bytes|"
        r"unknown_suffix_length)\s*[:=]\s*([0-9]+)\s*$",
        text,
    )
    prose_lengths = re.findall(r"(?i)\bunknown\s+(?:suffix\s+)?([0-9]+)\s+bytes\b", text)
    lengths = length_fields or prose_lengths
    if len(lengths) != 1:
        return None
    unknown_bytes = int(lengths[0])

    suffix_matches = re.findall(
        r"(?im)^\s*known_suffix\s*[:=]\s*[\"'`]?([A-Za-z0-9{}_.\-/]{1,64})",
        text,
    )
    if len(suffix_matches) > 1:
        return None
    suffix = suffix_matches[0].encode("ascii") if suffix_matches else b""

    if not prefix or unknown_bytes < 1 or unknown_bytes > MAX_UNKNOWN_BYTES:
        return None
    if n.bit_length() < 256 or n.bit_length() > MAX_MODULUS_BITS:
        return None
    if n <= 0 or n % 2 == 0 or c < 0 or c >= n or e not in {3, 5, 7}:
        return None
    return {
        "n": n,
        "e": e,
        "c": c,
        "prefix": prefix,
        "unknown_bytes": unknown_bytes,
        "suffix": suffix,
    }


def recover(parameters: dict[str, Any], *, max_seconds: float = 30.0) -> dict[str, Any]:
    """Run bounded LLL small-root recovery and validate every returned value."""

    try:
        from fpylll import IntegerMatrix, LLL
        from sympy import Poly, symbols
        from sympy.polys.polytools import ground_roots
    except ImportError as exc:
        return {"schema_version": 1, "status": "unavailable", "reason": str(exc)}

    n = int(parameters["n"])
    exponent = int(parameters["e"])
    ciphertext = int(parameters["c"])
    prefix = bytes(parameters["prefix"])
    unknown_bytes = int(parameters["unknown_bytes"])
    suffix = bytes(parameters.get("suffix", b""))

    x_bound = 1 << (8 * unknown_bytes)
    if x_bound**exponent * 2 >= n:
        return {
            "schema_version": 1,
            "status": "unsupported",
            "reason": "unknown-tail bound is too large for the univariate Coppersmith bound",
        }

    # Construct ((prefix * 256^(unknown+suffix) + x * 256^suffix + suffix)^e - c) mod n.
    # The direct binomial expansion below avoids polynomial-ring dependencies.
    prefix_value = int.from_bytes(prefix, "big")
    suffix_value = int.from_bytes(suffix, "big") if suffix else 0
    suffix_scale = 1 << (8 * len(suffix))
    constant = (prefix_value * x_bound * suffix_scale + suffix_value) % n
    coefficients = [0] * (exponent + 1)
    # The exponent is capped at seven, so the binomial coefficients stay tiny.
    from math import comb

    for power in range(exponent + 1):
        coefficients[power] = (
            comb(exponent, power)
            * pow(constant, exponent - power, n)
            * pow(suffix_scale, power, n)
        ) % n
    coefficients[0] = (coefficients[0] - ciphertext) % n
    if coefficients[-1] != 1:
        try:
            inverse = pow(coefficients[-1], -1, n)
        except ValueError:
            return {"schema_version": 1, "status": "unsupported", "reason": "polynomial is not invertible modulo n"}
        coefficients = [(coefficient * inverse) % n for coefficient in coefficients]

    deadline = time.monotonic() + max(0.1, min(float(max_seconds), 35.0))
    x = symbols("x")
    roots_seen: set[int] = set()
    max_m = min(6, max(2, MAX_LATTICE_DIMENSION // exponent))
    for m in range(2, max_m + 1):
        if time.monotonic() >= deadline:
            break
        dimension = exponent * m
        matrix = IntegerMatrix(dimension, dimension)
        rows: list[list[int]] = []
        f_poly = Poly.from_list(list(reversed(coefficients)), x, domain="ZZ")
        powers = [Poly(1, x, domain="ZZ")]
        for _ in range(m):
            powers.append(powers[-1] * f_poly)
        for i in range(m):
            for j in range(exponent):
                shifted = powers[i] * (n ** (m - i)) * (x**j)
                row = [0] * dimension
                for (degree,), coefficient in shifted.terms():
                    row[degree] = int(coefficient) * (x_bound**degree)
                rows.append(row)
        if len(rows) != dimension:
            return {"schema_version": 1, "status": "error", "reason": "lattice dimension mismatch"}
        for row_index, row in enumerate(rows):
            for column, value in enumerate(row):
                matrix[row_index, column] = value
        LLL.reduction(matrix)

        for row_index in range(min(dimension, 8)):
            coefficients_g: list[int] = []
            exact_division = True
            for degree in range(dimension):
                divisor = x_bound**degree
                value = int(matrix[row_index, degree])
                if value % divisor:
                    exact_division = False
                    break
                coefficients_g.append(value // divisor)
            if not exact_division:
                continue
            g = Poly.from_list(list(reversed(coefficients_g)), x, domain="ZZ")
            if g.is_zero or g.degree() <= 0:
                continue
            try:
                integer_roots = ground_roots(g)
            except (ArithmeticError, ValueError, TypeError):
                continue
            for root in integer_roots:
                if not getattr(root, "is_Integer", False):
                    continue
                candidate_x = int(root)
                if candidate_x < 0 or candidate_x >= x_bound or candidate_x in roots_seen:
                    continue
                roots_seen.add(candidate_x)
                message = prefix_value * x_bound * suffix_scale + candidate_x * suffix_scale + suffix_value
                if message >= n or pow(message, exponent, n) != ciphertext:
                    continue
                plaintext = message.to_bytes((message.bit_length() + 7) // 8, "big")
                if not plaintext.startswith(prefix) or (suffix and not plaintext.endswith(suffix)):
                    continue
                return {
                    "schema_version": 1,
                    "status": "candidate",
                    "method": "rsa-coppersmith-known-prefix",
                    "plaintext_hex": plaintext.hex(),
                    "plaintext": plaintext.decode("utf-8", errors="replace"),
                    "unknown_bytes": unknown_bytes,
                    "exponent": exponent,
                    "lattice_dimension": dimension,
                    "verification": "exact-rsa-reencryption",
                }

    status = "timeout" if time.monotonic() >= deadline else "no-root"
    return {"schema_version": 1, "status": status, "roots_checked": len(roots_seen)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--max-seconds", type=float, default=30.0)
    args = parser.parse_args(argv)
    try:
        if args.input.is_symlink() or not args.input.is_file():
            raise ValueError("input must be a regular, non-symlink file")
        if args.input.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError("input exceeds 1 MiB limit")
        text = args.input.read_text(encoding="utf-8", errors="replace")
        parameters = parse_parameters(text)
        if parameters is None:
            result = {"schema_version": 1, "status": "not-applicable", "reason": "explicit RSA prefix parameters not found"}
        else:
            result = recover(parameters, max_seconds=args.max_seconds)
    except (OSError, ValueError) as exc:
        result = {"schema_version": 1, "status": "error", "reason": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
