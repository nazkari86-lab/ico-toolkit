#!/usr/bin/env python3
"""Bounded cryptographic recovery profiles for local task evidence."""

from __future__ import annotations

import base64
import ast
import hashlib
import math
import random
import re
import shutil
import subprocess
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

from ico_quals_solvers import recover_lcg_predictions, sha256_length_extend
from ico_scan_core import FlagMatcher
from ico_solver_engine import Detection, SolverContext, SolverLimits, SolverResult


_CHAIN_TRANSFORM_HINTS = (
    ("base16", re.compile(r"\b(?:base\s*16|hex(?:adecimal)?)\b", re.IGNORECASE)),
    ("base32", re.compile(r"\bbase\s*32\b", re.IGNORECASE)),
    ("base58", re.compile(r"\bbase\s*58\b", re.IGNORECASE)),
    ("base64", re.compile(r"\bbase\s*64\b", re.IGNORECASE)),
    ("base85", re.compile(r"\b(?:base\s*85|ascii\s*85)\b", re.IGNORECASE)),
    ("rotation", re.compile(r"\b(?:rot(?!\s*47)\s*\d+|caesar)\b", re.IGNORECASE)),
    ("rot47", re.compile(r"\brot\s*47\b", re.IGNORECASE)),
    ("atbash", re.compile(r"\batbash\b", re.IGNORECASE)),
    ("morse", re.compile(r"\bmorse\b", re.IGNORECASE)),
    ("nato", re.compile(r"\b(?:nato|phonetic alphabet)\b", re.IGNORECASE)),
    ("t9", re.compile(r"\b(?:t9|multi[- ]tap)\b", re.IGNORECASE)),
    ("rail-fence", re.compile(r"\brail\s*[- ]?fence\b", re.IGNORECASE)),
    ("vigenere", re.compile(r"\bvigen[eè]re\b", re.IGNORECASE)),
    ("affine", re.compile(r"\baffine cipher\b", re.IGNORECASE)),
    ("xor", re.compile(r"\b(?:xor|exclusive or)\b", re.IGNORECASE)),
    ("url", re.compile(r"\burl[- ]?(?:encoding|decoding|encoded|decoded)\b", re.IGNORECASE)),
    ("gzip", re.compile(r"\bgzip\b", re.IGNORECASE)),
    ("zip", re.compile(r"\bzip(?:ped)?\b", re.IGNORECASE)),
    ("aes", re.compile(r"\baes(?:[- ]?(?:ecb|cbc|ctr|gcm))?\b", re.IGNORECASE)),
)


def _explicit_transform_families(task_text: str) -> tuple[str, ...]:
    """Return distinct, explicitly named transform families from a condition."""

    return tuple(name for name, pattern in _CHAIN_TRANSFORM_HINTS if pattern.search(task_text))


def _read_limited(path: Path, limit: int) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise ValueError(f"input exceeds byte limit: {size} > {limit}")
    return path.read_bytes()


def _undo_right(value: int, shift: int) -> int:
    result = value & 0xFFFFFFFF
    for _ in range(6):
        result = (value ^ (result >> shift)) & 0xFFFFFFFF
    return result


def _undo_left(value: int, shift: int, mask: int) -> int:
    result = value & 0xFFFFFFFF
    for _ in range(6):
        result = (value ^ ((result << shift) & mask)) & 0xFFFFFFFF
    return result


def _untemper(value: int) -> int:
    value = _undo_right(value, 18)
    value = _undo_left(value, 15, 0xEFC60000)
    value = _undo_left(value, 7, 0x9D2C5680)
    value = _undo_right(value, 11)
    return value & 0xFFFFFFFF


def recover_mt19937(outputs: list[int], limits: SolverLimits) -> dict[str, object]:
    if len(outputs) < 624:
        raise ValueError(f"MT19937 recovery needs 624 outputs, found {len(outputs)}")
    if len(outputs) > limits.max_files * 4:
        raise ValueError("MT19937 output count exceeds offline bound")
    if any(value < 0 or value > 0xFFFFFFFF for value in outputs[:624]):
        raise ValueError("MT19937 output is outside uint32 range")
    state = [_untemper(value) for value in outputs[:624]]
    clone = random.Random()
    clone.setstate((3, tuple(state + [624]), None))
    return {"state": state, "next_output": clone.getrandbits(32), "outputs_used": 624}


def recover_lcg(text: str, limits: SolverLimits) -> dict[str, object]:
    if len(text.encode("utf-8")) > limits.max_bytes:
        raise ValueError("LCG transcript exceeds byte limit")
    return recover_lcg_predictions(text)


def _integer_nth_root(value: int, exponent: int) -> tuple[int, bool]:
    if value < 0 or exponent < 2:
        raise ValueError("invalid integer-root input")
    low, high = 0, max(1, value)
    while low + 1 < high:
        middle = (low + high) // 2
        if middle**exponent <= value:
            low = middle
        else:
            high = middle
    return low, low**exponent == value


def recover_rsa_broadcast(
    samples: list[tuple[int, int]],
    exponent: int,
    *,
    max_samples: int = 64,
    max_bits: int = 8192,
) -> dict[str, object] | None:
    """Recover an unpadded low-exponent RSA message from Håstad samples.

    Every accepted sample must be a ciphertext of the same message and
    exponent under a pairwise-coprime modulus. Recovery is returned only when
    CRT yields an exact integer power and the message re-encrypts to every
    supplied ciphertext.
    """

    if exponent < 2 or exponent > 7 or len(samples) < exponent or len(samples) > max_samples:
        return None
    selected: list[tuple[int, int]] = []
    for modulus, ciphertext in samples:
        if (
            modulus <= 1
            or modulus.bit_length() > max_bits
            or ciphertext < 0
            or ciphertext >= modulus
        ):
            return None
        if any(math.gcd(modulus, previous_modulus) != 1 for previous_modulus, _ in selected):
            continue
        selected.append((modulus, ciphertext))
        if len(selected) == exponent:
            break
    if len(selected) < exponent:
        return None

    product = math.prod(modulus for modulus, _ in selected)
    combined = 0
    try:
        for modulus, ciphertext in selected:
            partial = product // modulus
            combined += ciphertext * partial * pow(partial, -1, modulus)
    except ValueError:
        return None
    combined %= product
    message, exact = _integer_nth_root(combined, exponent)
    if not exact or any(pow(message, exponent, modulus) != ciphertext for modulus, ciphertext in selected):
        return None
    return {
        "method": "rsa-broadcast-hastad",
        "plaintext": _int_to_bytes(message),
        "exponent": exponent,
        "samples_used": len(selected),
        "modulus_product_bits": product.bit_length(),
    }


def recover_rsa_shared_primes(
    samples: list[tuple[int, int, int]],
    *,
    max_samples: int = 64,
    max_bits: int = 8192,
) -> list[dict[str, object]]:
    """Decrypt RSA samples whose moduli share a non-trivial prime factor.

    This is the batch-GCD failure mode covered by classic CTF crypto toolkits:
    weak key generation can reuse one prime across otherwise distinct public
    keys. Each recovered plaintext is accepted only after exact RSA
    re-encryption matches its original ciphertext.
    """

    if len(samples) < 2 or len(samples) > max_samples:
        return []
    bounded: list[tuple[int, int, int]] = []
    for modulus, exponent, ciphertext in samples:
        if (
            modulus <= 3
            or modulus.bit_length() > max_bits
            or exponent <= 1
            or exponent >= modulus
            or ciphertext < 0
            or ciphertext >= modulus
        ):
            return []
        bounded.append((modulus, exponent, ciphertext))

    recovered: dict[str, dict[str, object]] = {}
    for index, (modulus, exponent, ciphertext) in enumerate(bounded):
        for other_index, (other_modulus, _other_exponent, _other_ciphertext) in enumerate(bounded):
            if index == other_index:
                continue
            shared = math.gcd(modulus, other_modulus)
            if shared <= 1 or shared >= modulus:
                continue
            other_factor, remainder = divmod(modulus, shared)
            if remainder:
                continue
            phi = (shared - 1) * (other_factor - 1)
            if phi <= 0:
                continue
            try:
                private_exponent = pow(exponent, -1, phi)
                message = pow(ciphertext, private_exponent, modulus)
            except ValueError:
                continue
            if pow(message, exponent, modulus) != ciphertext:
                continue
            plaintext = _int_to_bytes(message)
            key = hashlib.sha256(plaintext).hexdigest()
            recovered.setdefault(
                key,
                {
                    "method": "rsa-shared-prime-batch-gcd",
                    "plaintext": plaintext,
                    "key_index": index,
                    "peer_index": other_index,
                    "shared_factor_bits": shared.bit_length(),
                    "modulus_bits": modulus.bit_length(),
                    "roundtrip_verified": True,
                },
            )
            break
    return list(recovered.values())


def _int_to_bytes(value: int) -> bytes:
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def _parse_indexed_rsa_samples(text: str, *, max_samples: int) -> list[tuple[int, int]]:
    """Pair explicitly numbered modulus/ciphertext assignments in task text."""

    integer = r"(0x[0-9a-fA-F]+|\d+)"
    index = r"(?:_\s*(\d+)|\[\s*(\d+)\s*\]|(\d+))"
    assignments: dict[str, dict[str, int]] = {}
    patterns = (
        ("n", re.compile(rf"(?<![A-Za-z0-9])(?:n|modulus){index}\s*[:=]\s*{integer}", re.I)),
        ("c", re.compile(rf"(?<![A-Za-z0-9])(?:ciphertext|cipher|encrypted|ct|c){index}\s*[:=]\s*{integer}", re.I)),
    )
    for field, pattern in patterns:
        for match in pattern.finditer(text):
            sample_index = next(value for value in match.groups()[:3] if value is not None)
            raw_value = match.groups()[3]
            value = int(raw_value, 0) if raw_value.lower().startswith("0x") else int(raw_value, 10)
            slot = assignments.setdefault(sample_index, {})
            if field not in slot:
                slot[field] = value
            if len(assignments) >= max_samples:
                break
    return [
        (assignments[key]["n"], assignments[key]["c"])
        for key in sorted(assignments, key=lambda value: (len(value), value))
        if {"n", "c"}.issubset(assignments[key])
    ][:max_samples]


def _parse_indexed_rsa_key_samples(
    text: str, *, max_samples: int
) -> list[tuple[int, int, int]]:
    """Pair explicitly indexed n/e/c values without guessing field alignment."""

    integer = r"(0x[0-9a-fA-F]+|\d+)"
    index = r"(?:_\s*(\d+)|\[\s*(\d+)\s*\]|(\d+))"
    aliases = (
        ("n", r"(?:n|modulus)"),
        ("e", r"(?:e|exponent)"),
        ("c", r"(?:ciphertext|encrypted|ct|c)"),
    )
    assignments: dict[str, dict[str, int]] = {}
    for field, name_pattern in aliases:
        pattern = re.compile(
            rf"(?<![A-Za-z0-9]){name_pattern}{index}\s*[:=]\s*{integer}",
            re.IGNORECASE,
        )
        for match in pattern.finditer(text):
            sample_index = next(value for value in match.groups()[:3] if value is not None)
            raw_value = match.groups()[3]
            value = int(raw_value, 0) if raw_value.lower().startswith("0x") else int(raw_value, 10)
            assignments.setdefault(sample_index, {}).setdefault(field, value)
            if len(assignments) >= max_samples:
                break
    ordered = sorted(assignments, key=lambda value: (int(value), value))
    return [
        (assignments[key]["n"], assignments[key]["e"], assignments[key]["c"])
        for key in ordered
        if {"n", "e", "c"}.issubset(assignments[key])
    ][:max_samples]


def _aethmap_sealer_parameters(source: bytes) -> dict[str, int]:
    """Parse and validate the public AETHMAP sealing recipe without executing it."""

    text = source.decode("utf-8", errors="strict")
    tree = ast.parse(text)
    constants: dict[str, int] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names = [node.target.id]
        else:
            continue
        for name in names:
            try:
                value = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                continue
            if isinstance(value, int) and not isinstance(value, bool):
                constants[name] = value

    p, g = constants.get("P"), constants.get("G")
    if p is None or g is None or p <= 2 or g <= 1 or g >= p or p.bit_length() > 2048:
        raise ValueError("sealer must define bounded integer constants P and G")
    functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    derive = functions.get("derive_keystream")
    seal = functions.get("seal_map")
    if derive is None or seal is None:
        raise ValueError("sealer must define derive_keystream() and seal_map()")
    derive_text = "".join((ast.get_source_segment(text, derive) or "").split())
    seal_text = "".join((ast.get_source_segment(text, seal) or "").split())
    required = (
        "s=bytes_to_long(secret_bytes)",
        "bind_base=pow(G,coil_factor,P)",
        "bind=pow(bind_base,s,P)",
        "weave=pow(vault_seal,coil_factor,P)",
        "breath=pow(G,(s+coil_factor)%(P-1),P)",
        "coil=(bind*weave*breath)%P",
    )
    if not all(fragment in derive_text for fragment in required):
        raise ValueError("sealer keystream does not match the supported AETHMAP identity")
    if "vault_seal=pow(G,bytes_to_long(secret),P)" not in seal_text:
        raise ValueError("sealer does not bind vault_seal to the secret exponent")
    seal_required = (
        "ks=derive_keystream(secret,vault_seal,len(payload))",
        "ciphertext=bytes(p^kforp,kinzip(payload,ks))",
    )
    payload_offset_match = re.search(r"payload=plaintext_aethmap\[(0x[0-9a-fA-F]+|\d+):\]", seal_text)
    if not all(fragment in seal_text for fragment in seal_required) or not payload_offset_match:
        raise ValueError("sealer does not match the supported AETHMAP payload layout")

    factor_match = re.search(
        r"coil_factor=\(i\*(0x[0-9a-fA-F]+|\d+)\+(0x[0-9a-fA-F]+|\d+)\)%\(P-1\)",
        derive_text,
    )
    output_match = re.search(
        r"out\.append\(\(coil>>\(\(i\*(\d+)\)%(\d+)\)\)&(0x[0-9a-fA-F]+|\d+)\)",
        derive_text,
    )
    header_match = re.search(r"header=plaintext_aethmap\[:(0x[0-9a-fA-F]+|\d+)\]", seal_text)
    seal_width_match = re.search(r"long_to_bytes\(vault_seal,(\d+)\)", seal_text)
    if not factor_match or not output_match or not header_match or not seal_width_match:
        raise ValueError("sealer is missing supported AETHMAP offsets or byte schedule")
    if int(payload_offset_match.group(1), 0) != int(header_match.group(1), 0):
        raise ValueError("AETHMAP payload offset does not match the declared header size")

    values = {
        "p": p,
        "g": g,
        "factor_multiplier": int(factor_match.group(1), 0),
        "factor_offset": int(factor_match.group(2), 0),
        "shift_multiplier": int(output_match.group(1)),
        "shift_modulus": int(output_match.group(2)),
        "byte_mask": int(output_match.group(3), 0),
        "header_size": int(header_match.group(1), 0),
        "seal_width": int(seal_width_match.group(1)),
    }
    if (
        values["factor_multiplier"] < 0
        or values["factor_offset"] < 0
        or values["shift_modulus"] < 1
        or values["byte_mask"] < 0
        or values["byte_mask"] > 0xFF
        or values["header_size"] < 4
        or values["seal_width"] < 1
        or values["seal_width"] > 512
    ):
        raise ValueError("sealer has out-of-range AETHMAP parameters")
    return values


def _decrypt_aethmap(data: bytes, params: dict[str, int]) -> bytes:
    header_size = params["header_size"]
    seal_width = params["seal_width"]
    if not data.startswith(b"AETH") or len(data) < header_size + seal_width:
        raise ValueError("input is not a complete AETHMAP sealed map")
    p, g = params["p"], params["g"]
    seal_start = header_size
    vault_seal = int.from_bytes(data[seal_start : seal_start + seal_width], "big")
    if not 0 < vault_seal < p or math.gcd(vault_seal, p) != 1 or math.gcd(g, p) != 1:
        raise ValueError("AETHMAP seal or generator is outside the supported multiplicative group")

    # bind = vault_seal**k and weave = vault_seal**k; breath is
    # vault_seal * G**k. Thus the secret exponent cancels from the byte stream.
    base = (pow(vault_seal, 2, p) * g) % p
    order = p - 1
    if (
        math.gcd(base, p) != 1
        or pow(g, order, p) != 1
        or pow(vault_seal, order, p) != 1
        or pow(base, order, p) != 1
    ):
        raise ValueError("AETHMAP recurrence is not valid for the supplied group")
    multiplier = params["factor_multiplier"]
    factor = params["factor_offset"] % order
    coil = (vault_seal * pow(base, factor, p)) % p
    coil_step = pow(base, multiplier, p)
    shift_modulus = params["shift_modulus"]
    shift_multiplier = params["shift_multiplier"]
    mask = params["byte_mask"]
    ciphertext = data[seal_start + seal_width :]
    plaintext = bytearray(len(ciphertext))
    for index, value in enumerate(ciphertext):
        if index:
            coil = (coil * coil_step) % p
        shift = (index * shift_multiplier) % shift_modulus
        plaintext[index] = value ^ ((coil >> shift) & mask)
    return data[:seal_start] + plaintext


def _aethmap_sealer_path(context: SolverContext) -> Path | None:
    candidates = [context.input_path.parent / "aethmap_sealer.py", *context.related_paths]
    for candidate in candidates[: context.limits.max_files]:
        if candidate.name.casefold() != "aethmap_sealer.py" or candidate.is_symlink():
            continue
        try:
            if candidate.is_file() and candidate.stat().st_size <= context.limits.max_bytes:
                return candidate
        except OSError:
            continue
    return None


def _extended_gcd(left: int, right: int) -> tuple[int, int, int]:
    if right == 0:
        return left, 1, 0
    gcd_value, x1, y1 = _extended_gcd(right, left % right)
    return gcd_value, y1, x1 - (left // right) * y1


def check_rsa_patterns(values: dict[str, int], limits: SolverLimits) -> list[dict[str, object]]:
    if len(values) > limits.max_files * 8:
        raise ValueError("RSA parameter set is too large")
    results: list[dict[str, object]] = []
    n, e, c = values.get("n"), values.get("e"), values.get("c")
    if n and e and c and 2 <= e <= 7:
        root, exact = _integer_nth_root(c, e)
        if exact and root < n:
            results.append({"method": "low-exponent", "plaintext": _int_to_bytes(root), "e": e, "n": n})
    n = values.get("n")
    e1, e2 = values.get("e1"), values.get("e2")
    c1, c2 = values.get("c1"), values.get("c2")
    if n and e1 and e2 and c1 is not None and c2 is not None:
        gcd_value, s1, s2 = _extended_gcd(e1, e2)
        if gcd_value == 1:
            try:
                left = pow(c1, s1, n) if s1 >= 0 else pow(pow(c1, -1, n), -s1, n)
                right = pow(c2, s2, n) if s2 >= 0 else pow(pow(c2, -1, n), -s2, n)
                results.append({"method": "common-modulus", "plaintext": _int_to_bytes((left * right) % n), "n": n})
            except ValueError:
                pass
    # Wiener recovery is a continued-fraction attack on a deliberately small
    # private exponent.  It is bounded by the supplied integer set and never
    # factors arbitrary moduli or searches candidate messages.
    if n and e and n > 0 and e > 0:
        fraction = _continued_fraction(e, n)
        for numerator, denominator in fraction[: limits.max_files * 2]:
            k, d = numerator, denominator
            if k == 0 or (e * d - 1) % k:
                continue
            phi = (e * d - 1) // k
            s = n - phi + 1
            discriminant = s * s - 4 * n
            if discriminant < 0:
                continue
            root = math.isqrt(discriminant)
            if root * root != discriminant or (s + root) % 2:
                continue
            results.append({"method": "wiener", "d": d, "phi": phi, "n": n})
            break
    return results


def _continued_fraction(numerator: int, denominator: int) -> list[tuple[int, int]]:
    terms: list[int] = []
    while denominator and len(terms) < 128:
        quotient, remainder = divmod(numerator, denominator)
        terms.append(quotient)
        numerator, denominator = denominator, remainder
    convergents: list[tuple[int, int]] = []
    p_minus2, p_minus1 = 0, 1
    q_minus2, q_minus1 = 1, 0
    for term in terms:
        p = term * p_minus1 + p_minus2
        q = term * q_minus1 + q_minus2
        convergents.append((p, q))
        p_minus2, p_minus1 = p_minus1, p
        q_minus2, q_minus1 = q_minus1, q
    return convergents


def _parse_ints(text: str, names: tuple[str, ...]) -> dict[str, int]:
    result: dict[str, int] = {}
    for name in names:
        aliases = {"c": ("c", "ct", "ciphertext", "encrypted")}.get(name, (name,))
        alternatives = "|".join(re.escape(alias) for alias in aliases)
        match = re.search(rf"\b(?:{alternatives})\s*=\s*(0x[0-9a-fA-F]+|\d+)", text, re.IGNORECASE)
        if match:
            raw = match.group(1)
            result[name] = int(raw, 0) if raw.lower().startswith("0x") else int(raw, 16) if re.search(r"[a-fA-F]", raw) else int(raw, 10)
    return result


@lru_cache(maxsize=4)
def _prime_powers_through(bound: int) -> tuple[tuple[int, int], ...]:
    if bound < 2 or bound > 1 << 20:
        raise ValueError("Pollard p-1 smooth bound must be between 2 and 2^20")
    sieve = bytearray(b"\x01") * (bound + 1)
    sieve[0:2] = b"\x00\x00"
    for candidate in range(2, math.isqrt(bound) + 1):
        if sieve[candidate]:
            start = candidate * candidate
            count = (bound - start) // candidate + 1
            sieve[start : bound + 1 : candidate] = b"\x00" * count
    powers: list[tuple[int, int]] = []
    for prime, is_prime in enumerate(sieve):
        if not is_prime:
            continue
        power = prime
        while power <= bound // prime:
            power *= prime
        powers.append((prime, power))
    return tuple(powers)


def pollard_pm1_factor(
    modulus: int,
    *,
    smooth_bound: int = 1 << 20,
    timeout_seconds: float = 5.0,
) -> int | None:
    """Try Pollard p-1 with shuffled smooth factors and repeated prime powers.

    The source hint used by several CTFs bounds the *prime factors* of ``p-1``;
    their multiplicities are not bounded by the usual largest-prime-power
    stage-1 exponent. Raising by each factor repeatedly covers those
    multiplicities. Shuffling avoids applying a shared final factor to both
    RSA primes at the same time, which would make the GCD equal ``n``.
    """

    if modulus <= 3 or modulus.bit_length() > 8192 or timeout_seconds <= 0:
        return None
    prime_powers = _prime_powers_through(smooth_bound)
    deadline = time.monotonic() + timeout_seconds
    try:
        import gmpy2

        modulus_value = gmpy2.mpz(modulus)
        modular_power = gmpy2.powmod
        greatest_common_divisor = gmpy2.gcd
    except ImportError:
        modulus_value = modulus
        modular_power = pow
        greatest_common_divisor = math.gcd

    for base in range(3, 13):
        ordered = list(prime_powers)
        seed = (modulus ^ (base * 0x9E3779B1)) & ((1 << 64) - 1)
        random.Random(seed).shuffle(ordered)
        value = base % modulus
        operations = 0
        for prime, _max_power in ordered:
            for _ in range(10):
                value = modular_power(value, prime, modulus_value)
                divisor = int(greatest_common_divisor(value - 1, modulus_value))
                if 1 < divisor < modulus:
                    return divisor
                if divisor == modulus:
                    break
                operations += 1
                if operations % 256 == 0 and time.monotonic() >= deadline:
                    return None
            if divisor == modulus:
                break
        if time.monotonic() >= deadline:
            return None
    return None


def _factor_small_prime_product(modulus: int, bound: int) -> tuple[dict[int, int], int] | None:
    """Factor a modulus made entirely from primes at or below a small bound."""

    if modulus <= 1 or modulus.bit_length() > 8192 or bound < 2 or bound > 1 << 16:
        return None
    remaining = modulus
    factors: dict[int, int] = {}
    for prime, _power in _prime_powers_through(bound):
        if prime * prime > remaining:
            if remaining > 1:
                factors[remaining] = factors.get(remaining, 0) + 1
                remaining = 1
            break
        while remaining % prime == 0:
            factors[prime] = factors.get(prime, 0) + 1
            remaining //= prime
    if remaining > 1:
        return None
    phi = modulus
    for prime in factors:
        phi = (phi // prime) * (prime - 1)
    return factors, phi


def _task_text_evidence(context: SolverContext, initial: bytes) -> tuple[str, int]:
    """Read bounded textual siblings so split source/output challenges can be joined."""

    paths = (context.input_path, *context.related_paths[: context.limits.max_files - 1])
    remaining = context.limits.max_bytes
    chunks: list[str] = [context.task_text or ""]
    used = 0
    visited: set[Path] = set()
    text_suffixes = {".txt", ".out", ".log", ".py", ".sage", ".json", ".yaml", ".yml", ".csv", ".hex", ".pem"}
    for index, path in enumerate(paths):
        try:
            resolved = path.resolve()
            if resolved in visited or path.is_symlink() or not path.is_file():
                continue
            visited.add(resolved)
            if index and path.suffix.lower() not in text_suffixes:
                continue
            size = path.stat().st_size
            if size > remaining:
                continue
            payload = initial if path == context.input_path else path.read_bytes()
        except OSError:
            continue
        if len(payload) > remaining or (b"\x00" in payload[:4096] and path.suffix.lower() not in {".pem"}):
            continue
        remaining -= len(payload)
        used += 1
        chunks.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(chunks), used


def _is_task_evidence_anchor(context: SolverContext) -> bool:
    """Let one stable textual input own expensive sibling-aware task solving."""

    text_suffixes = {".txt", ".out", ".log", ".py", ".sage", ".json", ".yaml", ".yml", ".csv", ".hex", ".pem"}
    paths = [context.input_path, *context.related_paths[: context.limits.max_files - 1]]
    eligible: set[Path] = set()
    for path in paths:
        if path != context.input_path and path.suffix.lower() not in text_suffixes:
            continue
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > context.limits.max_bytes:
                continue
            eligible.add(path.resolve())
        except OSError:
            continue
    return bool(eligible) and context.input_path.resolve() == min(eligible, key=str)


def _decrypt_rsa_small_prime_product(
    values: dict[str, int], *, factor_bound: int
) -> tuple[bytes, int] | None:
    n, e, c = values.get("n"), values.get("e"), values.get("c")
    if not n or not e or c is None:
        return None
    factored = _factor_small_prime_product(n, factor_bound)
    if factored is None:
        return None
    factors, phi = factored
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return None
    plaintext = _int_to_bytes(pow(c, d, n))
    if pow(int.from_bytes(plaintext, "big"), e, n) != c:
        return None
    return plaintext, len(factors)


def _decrypt_rsa_pm1(
    values: dict[str, int], *, smooth_bound: int, timeout_seconds: float
) -> bytes | None:
    n, e, c = values.get("n"), values.get("e"), values.get("c")
    if not n or not e or c is None:
        return None
    factor = pollard_pm1_factor(n, smooth_bound=smooth_bound, timeout_seconds=timeout_seconds)
    if factor is None:
        return None
    cofactor, remainder = divmod(n, factor)
    if remainder:
        return None
    try:
        from Crypto.Util.number import isPrime
    except ImportError:
        try:
            from sympy import isprime as isPrime
        except ImportError:
            return None
    try:
        if not isPrime(factor) or not isPrime(cofactor):
            return None
    except (ValueError, OverflowError):
        return None
    phi = (factor - 1) * (cofactor - 1)
    try:
        d = pow(e, -1, phi)
    except ValueError:
        return None
    plaintext = _int_to_bytes(pow(c, d, n))
    if pow(int.from_bytes(plaintext, "big"), e, n) != c:
        return None
    return plaintext


def _has_squared_qword_xor_source(text: str) -> bool:
    square = re.search(r"\b([A-Za-z_]\w*)\s*\*=\s*\1\b", text)
    if square is None:
        square = re.search(r"\b([A-Za-z_]\w*)\s*=\s*\1\s*\*\s*\1\b", text)
    if square is None:
        return False
    key = re.escape(square.group(1))
    xor = re.search(rf"\[[^\]]+\]\s*(?:\^=|=[^;\n]*\^)\s*{key}\b", text)
    return xor is not None and re.search(r"/\s*8\b", text) is not None


def _has_squared_qword_xor_assembly(text: str) -> bool:
    xor = re.search(r"\bxorq\s+%([a-z0-9]+),\s*\([^\n]*,\s*8\)", text, re.IGNORECASE)
    if xor is None:
        return False
    register = re.escape(xor.group(1))
    square = re.search(rf"\bimulq?\s+%{register},\s*%{register}\b", text, re.IGNORECASE)
    return square is not None


def _squared_xor_stream_evidence(context: SolverContext) -> dict[str, str] | None:
    executable = shutil.which("objdump")
    for path in context.related_paths[: context.limits.max_files]:
        if path == context.input_path or path.is_symlink() or not path.is_file():
            continue
        try:
            if path.stat().st_size > context.limits.max_bytes:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if path.suffix.lower() in {".c", ".h", ".cc", ".cpp"}:
            source = data.decode("utf-8", errors="replace")
            if _has_squared_qword_xor_source(source):
                return {"path": str(path), "method": "paired-source"}
            continue
        if not data.startswith(b"\x7fELF") or executable is None:
            continue
        try:
            completed = subprocess.run(
                [executable, "-d", str(path)],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=min(context.limits.timeout_seconds, 10.0),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0 and _has_squared_qword_xor_assembly(completed.stdout):
            return {"path": str(path), "method": "static-objdump"}
    return None


def recover_xor_square_stream(
    ciphertext: bytes,
    *,
    flag_length: int,
    known_prefix: bytes,
    timeout_seconds: float,
) -> tuple[bytes | None, dict[str, object]]:
    """Recover a qword XOR stream whose key is squared after each block.

    The search covers only the unknown bytes in the first keystream word. A
    three-byte zero-padded suffix gives a 24-bit known-plaintext filter before
    the complete plaintext is checked.
    """

    details: dict[str, object] = {
        "flag_length_bytes": flag_length,
        "known_prefix": known_prefix.decode("ascii", errors="replace"),
        "ciphertext_bytes": len(ciphertext),
        "key_search_attempts": 0,
        "key_search_bits": max(0, (8 - len(known_prefix)) * 8),
        "ciphertext_roundtrip": False,
    }
    if (
        len(ciphertext) < 16
        or len(ciphertext) % 8
        or not 5 <= len(known_prefix) <= 8
        or flag_length < len(known_prefix) + 1
        or flag_length > len(ciphertext) - 3
        or timeout_seconds <= 0
    ):
        details["reason"] = "ciphertext, flag length, prefix, or timeout is outside the supported bounds"
        return None, details

    block_count = len(ciphertext) // 8
    unknown_bits = (8 - len(known_prefix)) * 8
    search_count = 1 << unknown_bits
    details["key_search_bits"] = unknown_bits
    details["key_search_space"] = search_count
    first_cipher_word = int.from_bytes(ciphertext[:8], "little")
    known_word = int.from_bytes(known_prefix.ljust(8, b"\x00"), "little")
    tail_filter = int.from_bytes(ciphertext[-3:], "little")
    modulus = 1 << 64
    mask = modulus - 1
    deadline = time.monotonic() + timeout_seconds
    try:
        import gmpy2

        modular_power = gmpy2.powmod
    except ImportError:
        modular_power = pow

    for guess in range(search_count):
        if guess % 16384 == 0 and time.monotonic() >= deadline:
            details["timed_out"] = True
            return None, details
        first_plain_word = known_word | (guess << (8 * len(known_prefix)))
        key = first_cipher_word ^ first_plain_word
        final_key = int(modular_power(key, 1 << (block_count - 1), modulus))
        details["key_search_attempts"] = guess + 1
        if final_key >> 40 != tail_filter:
            continue

        plaintext = bytearray()
        state = key
        for offset in range(0, len(ciphertext), 8):
            word = int.from_bytes(ciphertext[offset : offset + 8], "little") ^ state
            plaintext.extend(word.to_bytes(8, "little"))
            state = (state * state) & mask

        padded = bytes(plaintext[flag_length:])
        body = bytes(plaintext[:flag_length]).rstrip(b"\r\n")
        if (
            any(padded)
            or not body.startswith(known_prefix)
            or not body.endswith(b"}")
            or not body.isascii()
            or any(value < 32 or value > 126 for value in body)
        ):
            continue

        encrypted = bytearray()
        state = key
        for offset in range(0, len(plaintext), 8):
            word = int.from_bytes(plaintext[offset : offset + 8], "little") ^ state
            encrypted.extend(word.to_bytes(8, "little"))
            state = (state * state) & mask
        details["ciphertext_roundtrip"] = bytes(encrypted) == ciphertext
        if details["ciphertext_roundtrip"]:
            details["key_search_attempts"] = guess + 1
            details["padding_zero_verified"] = True
            return body, details

    details["timed_out"] = time.monotonic() >= deadline
    return None, details


def analyze_symmetric_transcript(text: str, limits: SolverLimits) -> list[dict[str, object]]:
    if len(text.encode("utf-8")) > limits.max_bytes:
        raise ValueError("symmetric transcript exceeds byte limit")
    records: list[dict[str, object]] = []
    data_match = re.search(r"\b(?:data0|old_data|data)\s*=\s*([0-9a-fA-F]+)", text, re.IGNORECASE)
    token_match = re.search(r"\b(?:token0|old_token|token)\s*=\s*([0-9a-fA-F]{64})", text, re.IGNORECASE)
    suffix_match = re.search(r"\b(?:suffix|append)\s*=\s*([^\s]+)", text, re.IGNORECASE)
    if data_match and token_match and suffix_match:
        old_data = bytes.fromhex(data_match.group(1))
        suffix = suffix_match.group(1).encode("utf-8")
        length_match = re.search(r"\b(?:secret_length|key_length)\s*=\s*(\d+)", text, re.IGNORECASE)
        secret_length = int(length_match.group(1)) if length_match else 18
        token, glue = sha256_length_extend(token_match.group(1), secret_length + len(old_data), suffix)
        records.append({"method": "sha256-length-extension", "token": token, "glue": glue, "data": old_data + glue + suffix, "secret_length": secret_length})
    return records


def _classical_transforms(text: str, task: str) -> list[dict[str, object]]:
    """Decode explicitly labelled classical-cipher fields only."""

    records: list[dict[str, object]] = []
    match = re.search(r"\b(?:cipher|ciphertext|encoded|message|text)\s*[:=]\s*([^\s]{4,})", text, re.I)
    if not match:
        return records
    ciphertext = match.group(1)
    if "rot47" in task:
        decoded = "".join(
            chr((ord(char) - 33 + 47) % 94 + 33)
            if 33 <= ord(char) <= 126
            else char
            for char in ciphertext
        )
        records.append({"method": "rot47", "plaintext": decoded.encode(), "parameters": {"rotation": 47}})
    elif "rot" in task or "caesar" in task:
        # Accept both compact challenge syntax (``Caesar 7``/``ROT7``) and
        # ordinary prose (``Caesar-shifted by 7``/``rotation of 7``).  The
        # number remains condition-backed by the task statement; we never try
        # every possible shift when it is absent.
        shift_patterns = (
            r"\b(?:rot|caesar)\s*[- ]?(?:shift(?:ed)?\s*)?(?:by\s*|[:=]?\s*)(\d{1,2})\b",
            r"\b(?:rotation|shift)\s*(?:of\s*|by\s*|[:=]?\s*)(\d{1,2})\b",
        )
        shift = 13
        for pattern in shift_patterns:
            shift_match = re.search(pattern, task, re.I)
            if shift_match:
                shift = int(shift_match.group(1)) % 26
                break
        decoded = "".join(
            chr((ord(char) - 65 - shift) % 26 + 65) if char.isupper() else chr((ord(char) - 97 - shift) % 26 + 97) if char.islower() else char
            for char in ciphertext
        )
        records.append({"method": f"caesar-{shift}", "plaintext": decoded.encode(), "parameters": {"shift": shift}})
    if "atbash" in task:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        reversed_alphabet = "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba"
        decoded = ciphertext.translate(str.maketrans(alphabet, reversed_alphabet))
        records.append({"method": "atbash", "plaintext": decoded.encode(), "parameters": {"alphabet": "Latin"}})
    if "affine" in task:
        a_match = re.search(r"\ba\s*[:=]\s*(\d+)", task, re.I)
        b_match = re.search(r"\bb\s*[:=]\s*(\d+)", task, re.I)
        if a_match and b_match:
            a, b = int(a_match.group(1)) % 26, int(b_match.group(1)) % 26
            if math.gcd(a, 26) == 1:
                inverse = pow(a, -1, 26)
                decoded = "".join(
                    chr((inverse * (ord(char.upper()) - 65 - b)) % 26 + 65).lower() if char.islower() else chr((inverse * (ord(char.upper()) - 65 - b)) % 26 + 65) if char.isalpha() else char
                    for char in ciphertext
                )
                records.append({"method": "affine", "plaintext": decoded.encode(), "parameters": {"a": a, "b": b}})
    if "vigen" in task:
        key_match = re.search(r"\bkey\s*[:=]\s*([A-Za-z]+)", task, re.I)
        if key_match:
            key = key_match.group(1).lower()
            offset = 0
            out: list[str] = []
            for char in ciphertext:
                if char.isalpha():
                    base = 65 if char.isupper() else 97
                    out.append(chr((ord(char) - base - (ord(key[offset % len(key)]) - 97)) % 26 + base))
                    offset += 1
                else:
                    out.append(char)
            records.append({"method": "vigenere", "plaintext": "".join(out).encode(), "parameters": {"key": key}})
    return records


_MORSE_TO_TEXT = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9", "-.-.--": "!",
    "..--..": "?", ".-.-.-": ".", "--..--": ",", "-.-.-.": ";",
    "---...": ":", "-....-": "-", "..--.-": "_", ".-..-.": '"',
    ".----.": "'", "-..-.": "/", "-.--.": "(", "-.--.-": ")",
}
_NATO_TO_TEXT = {
    name: chr(ord("A") + index)
    for index, name in enumerate(
        (
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
            "hotel", "india", "juliett", "kilo", "lima", "mike", "november",
            "oscar", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
            "victor", "whiskey", "xray", "yankee", "zulu",
        )
    )
}
_NATO_TO_TEXT.update({"alfa": "A", "juliet": "J", "x-ray": "X"})
_T9_MULTI_TAP = {
    "2": "ABC", "3": "DEF", "4": "GHI", "5": "JKL", "6": "MNO",
    "7": "PQRS", "8": "TUV", "9": "WXYZ",
}


def _labelled_ciphertext_line(text: str) -> str | None:
    match = re.search(
        r"(?im)^\s*(?:cipher(?:text)?|encoded|message|text)\s*[:=]\s*([^\r\n]+)",
        text,
    )
    return match.group(1).strip() if match else None


def _decode_morse_field(value: str) -> bytes | None:
    decoded_words: list[str] = []
    for word in re.split(r"\s*/\s*", value.strip()):
        characters: list[str] = []
        for token in word.split():
            if token in "{}[]()_":
                characters.append(token)
            elif token in _MORSE_TO_TEXT:
                characters.append(_MORSE_TO_TEXT[token])
            else:
                return None
        if characters:
            decoded_words.append("".join(characters))
    if not decoded_words:
        return None
    return " ".join(decoded_words).encode("ascii")


def _decode_nato_field(value: str) -> bytes | None:
    output: list[str] = []
    word_count = 0
    for token in value.split():
        normalized = token.strip(",.;:").casefold()
        if normalized in _NATO_TO_TEXT:
            output.append(_NATO_TO_TEXT[normalized])
            word_count += 1
        elif token in "{}[]()_-.!":
            output.append(token)
        else:
            return None
    if word_count < 3:
        return None
    return "".join(output).encode("ascii")


def _decode_t9_field(value: str) -> bytes | None:
    output: list[str] = []
    groups = value.split()
    if not groups:
        return None
    for group in groups:
        if group in "{}[]()_-.!":
            output.append(group)
        elif group in {"0", "*"}:
            output.append(" ")
        elif len(group) <= 4 and group[0] in _T9_MULTI_TAP and set(group) == {group[0]}:
            letters = _T9_MULTI_TAP[group[0]]
            if len(group) > len(letters):
                return None
            output.append(letters[len(group) - 1])
        else:
            return None
    return "".join(output).encode("ascii")


def _rail_fence_decrypt(ciphertext: str, rails: int) -> str | None:
    if len(ciphertext) > 1_000_000 or not 2 <= rails <= min(len(ciphertext), 256):
        return None
    rows: list[int] = []
    row, direction = 0, 1
    for _ in ciphertext:
        rows.append(row)
        if row == 0:
            direction = 1
        elif row == rails - 1:
            direction = -1
        row += direction
    counts = [0] * rails
    for row_index in rows:
        counts[row_index] += 1
    rails_data: list[str] = []
    offset = 0
    for count in counts:
        rails_data.append(ciphertext[offset : offset + count])
        offset += count
    positions = [0] * rails
    plaintext: list[str] = []
    for row_index in rows:
        plaintext.append(rails_data[row_index][positions[row_index]])
        positions[row_index] += 1
    return "".join(plaintext)


def _katana_inspired_text_transforms(text: str, task: str) -> list[dict[str, object]]:
    """Small, offline-only transforms selected by explicit task wording."""
    value = _labelled_ciphertext_line(text)
    if value is None:
        return []
    records: list[dict[str, object]] = []
    if "morse" in task:
        plaintext = _decode_morse_field(value)
        if plaintext is not None:
            records.append({"method": "morse", "plaintext": plaintext, "parameters": {"word_separator": "/"}})
    if "nato" in task or "phonetic" in task:
        plaintext = _decode_nato_field(value)
        if plaintext is not None:
            records.append({"method": "nato-phonetic", "plaintext": plaintext, "parameters": {"alphabet": "NATO"}})
    if "t9" in task or "multi-tap" in task:
        plaintext = _decode_t9_field(value)
        if plaintext is not None:
            records.append({"method": "t9-multi-tap", "plaintext": plaintext, "parameters": {"separator": "whitespace"}})
    if "rail fence" in task or "railfence" in task:
        rail_match = re.search(r"\b(\d{1,3})\s+rails?\b|\brails?\s*[:=]\s*(\d{1,3})\b", task)
        if rail_match:
            rails = int(rail_match.group(1) or rail_match.group(2))
            plaintext = _rail_fence_decrypt(value, rails)
            if plaintext is not None:
                records.append({"method": "rail-fence", "plaintext": plaintext.encode(), "parameters": {"rails": rails}})
    return records


def _known_plaintext_permutation(text: str, task_description: str) -> list[dict[str, object]]:
    """Invert a fixed character permutation from known and censored pairs."""

    task = task_description.casefold()
    if not any(word in task for word in ("shuffle", "permutation", "transposition")):
        return []

    flag_prefix = re.search(r"\b([A-Za-z][A-Za-z0-9]{1,15})\s*\{\s*\}", task_description)
    if flag_prefix is None:
        return []

    known: list[tuple[str, str]] = []
    censored: list[tuple[str, str]] = []
    for line in text.splitlines():
        if line.count("->") != 1:
            continue
        left, right = (part.strip() for part in line.split("->", 1))
        if not left or len(left) != len(right) or not left.isascii() or not right.isascii():
            continue
        if re.fullmatch(r"\?{2,256}", left) and "?" not in right:
            censored.append((left, right))
        elif "?" not in left and "?" not in right:
            known.append((left, right))

    if len(known) < 2 or not censored:
        return []
    size = len(known[0][0])
    if not 2 <= size <= 256 or any(len(left) != size for left, _ in known + censored):
        return []

    permutation: list[int] = []
    for output_index in range(size):
        output_signature = tuple(right[output_index] for _, right in known)
        matches = [
            input_index
            for input_index in range(size)
            if tuple(left[input_index] for left, _ in known) == output_signature
        ]
        if len(matches) != 1:
            return []
        permutation.append(matches[0])
    if sorted(permutation) != list(range(size)):
        return []

    ciphertext = censored[0][1]
    plaintext = [""] * size
    for output_index, input_index in enumerate(permutation):
        plaintext[input_index] = ciphertext[output_index]
    body = "".join(plaintext)
    if not re.fullmatch(r"[A-Za-z0-9_.!@$&+\-]{4,256}", body):
        return []

    roundtrip_verified = all(
        "".join(left[permutation[index]] for index in range(size)) == right
        for left, right in known
    ) and "".join(body[permutation[index]] for index in range(size)) == ciphertext
    if not roundtrip_verified:
        return []

    prefix = flag_prefix.group(1).upper()
    return [
        {
            "method": "known-plaintext-permutation",
            "candidate": f"{prefix}{{{body}}}".encode("ascii"),
            "parameters": {
                "permutation": permutation,
                "known_pairs": len(known),
                "roundtrip_verified": roundtrip_verified,
            },
        }
    ]


def _explicit_xor(text: str, task: str) -> list[dict[str, object]]:
    if "xor" not in task:
        return []
    key_match = re.search(r"\b(?:key|xor_key)\s*[:=]\s*(0x[0-9a-fA-F]+|[0-9]+|[A-Za-z]{1,64})", text, re.I)
    cipher_match = re.search(r"\b(?:cipher|ciphertext|data)\s*[:=]\s*([0-9a-fA-F]{8,}|[A-Za-z0-9+/=_-]{8,})", text, re.I)
    if not key_match or not cipher_match:
        return []
    key_raw = key_match.group(1)
    if key_raw.lower().startswith("0x") or key_raw.isdigit():
        key = bytes([int(key_raw, 0) & 0xFF])
    else:
        key = key_raw.encode()
    token = cipher_match.group(1)
    try:
        ciphertext = bytes.fromhex(token) if re.fullmatch(r"[0-9a-fA-F]+", token) and len(token) % 2 == 0 else base64.b64decode(token, validate=True)
    except (ValueError, TypeError):
        # A malformed explicitly labelled field is unsupported, not a reason
        # to try every interpretation of the surrounding file.
        return []
    plaintext = bytes(value ^ key[index % len(key)] for index, value in enumerate(ciphertext))
    return [{"method": "known-key-xor", "plaintext": plaintext, "parameters": {"key_length": len(key)}}]


def _block_and_nonce_views(text: str, task: str) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    if "ecb" in task:
        match = re.search(r"\b(?:cipher|ciphertext)\s*[:=]\s*([0-9a-fA-F]{32,})", text, re.I)
        if match and len(match.group(1)) % 32 == 0:
            raw = bytes.fromhex(match.group(1))
            blocks = [raw[index : index + 16] for index in range(0, len(raw), 16)]
            duplicates = len(blocks) - len(set(blocks))
            if duplicates:
                records.append({"method": "ecb-repeated-blocks", "duplicates": duplicates, "blocks": len(blocks)})
    if "ctr" in task or "nonce" in task:
        first = re.search(r"\b(?:cipher1|c1)\s*[:=]\s*([0-9a-fA-F]{8,})", text, re.I)
        second = re.search(r"\b(?:cipher2|c2)\s*[:=]\s*([0-9a-fA-F]{8,})", text, re.I)
        if first and second:
            left, right = bytes.fromhex(first.group(1)), bytes.fromhex(second.group(1))
            length = min(len(left), len(right))
            records.append({"method": "ctr-nonce-reuse", "xor": bytes(a ^ b for a, b in zip(left[:length], right[:length]))})
    return records


class CryptoSolver:
    name = "universal-crypto"
    category = "crypto"

    def detect(self, context: SolverContext) -> Detection | None:
        kind = str(context.classification.get("kind", ""))
        suffix = context.input_path.suffix.lower()
        task = (context.task_text or "").lower()
        try:
            with context.input_path.open("rb") as handle:
                magic = handle.read(4)
        except OSError:
            magic = b""
        if magic == b"AETH" or suffix == ".aethmap":
            return Detection(self.name, self.category, 100, "AETHMAP sealed-map signature", {"suffix": suffix})
        hints = (
            "crypto",
            "cipher",
            "rsa",
            "aes",
            "lcg",
            "mt19937",
            "sha-256",
            "length extension",
            "vigenere",
            "rot",
            "rot47",
            "atbash",
            "morse",
            "nato",
            "phonetic",
            "t9",
            "multi-tap",
            "rail fence",
            "railfence",
            "shuffle",
            "permutation",
            "transposition",
        )
        if any(word in task for word in hints) or suffix in {".enc", ".cipher", ".key", ".pem", ".log"}:
            return Detection(self.name, self.category, 80, "cryptographic task hint", {"suffix": suffix})
        if kind == "text" and any(word in suffix for word in ("key", "enc")):
            return Detection(self.name, self.category, 40, "cryptographic extension", {"suffix": suffix})
        return None

    def solve(self, context: SolverContext) -> SolverResult:
        result = SolverResult(self.name, self.category, "unsupported")
        try:
            data = _read_limited(context.input_path, context.limits.max_bytes)
            text = data.decode("utf-8", errors="replace")
            task = (context.task_text or "").lower()
            evidence_text, evidence_files = _task_text_evidence(context, data)
            root = context.report_dir / "artifacts" / "universal-crypto" / hashlib.sha256(data).hexdigest()[:12]
            matcher = FlagMatcher()
            wrote = False
            needs_review = False

            def scan(payload: bytes, source: str, analyzer: str, *, validated: bool = False) -> None:
                hits = matcher.scan(payload.decode("utf-8", errors="replace"), source=source, analyzer=analyzer)
                if validated:
                    for hit in hits:
                        hit["validation"] = "cryptographic round-trip verified"
                        if hit.get("triage") == "likely-placeholder":
                            hit["triage"] = "candidate"
                            hit.pop("triage_reason", None)
                result.candidates.extend(hits)

            def handoff_intermediate(payload: bytes, method: str) -> None:
                """Queue an intermediate only when the condition names a chain."""

                nonlocal wrote
                families = _explicit_transform_families(context.task_text or "")
                if len(families) < 2 or not payload or len(payload) > context.limits.max_bytes:
                    return
                text_view = payload.decode("utf-8", errors="replace")
                if FlagMatcher().scan(text_view, source=str(context.input_path), analyzer=method):
                    return
                digest = hashlib.sha256(payload).hexdigest()
                path = root / f"chain-stage-{digest[:16]}.bin"
                path.parent.mkdir(parents=True, exist_ok=True)
                if not path.exists():
                    path.write_bytes(payload)
                if str(path) not in result.derived_inputs and len(result.derived_inputs) < 16:
                    result.derived_inputs.append(str(path))
                if str(path) not in result.artifacts:
                    result.artifacts.append(str(path))
                result.steps.append(
                    {
                        "name": "handoff-explicit-transform-chain",
                        "status": "derived",
                        "details": {
                            "method": method,
                            "next_stage_hints": list(families),
                            "output": str(path),
                            "bytes": len(payload),
                        },
                    }
                )
                wrote = True

            if data.startswith(b"AETH"):
                sealer_path = _aethmap_sealer_path(context)
                if sealer_path is None:
                    result.steps.append(
                        {
                            "name": "aethmap-sealer-source",
                            "status": "unsupported",
                            "details": {"reason": "adjacent aethmap_sealer.py was not supplied"},
                        }
                    )
                else:
                    try:
                        sealer_source = _read_limited(sealer_path, context.limits.max_bytes)
                        params = _aethmap_sealer_parameters(sealer_source)
                        plaintext = _decrypt_aethmap(data, params)
                    except (OSError, UnicodeDecodeError, SyntaxError, ValueError, OverflowError) as exc:
                        result.steps.append(
                            {
                                "name": "aethmap-public-seal-decrypt",
                                "status": "unsupported",
                                "details": {"error": f"{type(exc).__name__}: {exc}", "sealer": str(sealer_path)},
                            }
                        )
                    else:
                        path = root / "aethmap-decrypted.bin"
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(plaintext)
                        result.artifacts.append(str(path))
                        result.steps.append(
                            {
                                "name": "aethmap-public-seal-decrypt",
                                "status": "ok",
                                "details": {
                                    "sealer": str(sealer_path),
                                    "header_size": params["header_size"],
                                    "seal_width": params["seal_width"],
                                    "ciphertext_bytes": len(data) - params["header_size"] - params["seal_width"],
                                    "secret_recovered": False,
                                    "identity": "bind * weave * breath = vault_seal^(2*k+1) * G^k mod P",
                                },
                            }
                        )
                        scan(plaintext, str(path), "aethmap-public-seal-decrypt")
                        wrote = True

            for record in _classical_transforms(text, task):
                plaintext = bytes(record["plaintext"])
                scan(plaintext, str(context.input_path), str(record["method"]))
                handoff_intermediate(plaintext, str(record["method"]))
                result.steps.append({"name": str(record["method"]), "status": "ok", "details": record.get("parameters", {})})
                wrote = True

            for record in _katana_inspired_text_transforms(text, task):
                plaintext = bytes(record["plaintext"])
                scan(plaintext, str(context.input_path), str(record["method"]))
                handoff_intermediate(plaintext, str(record["method"]))
                result.steps.append({"name": str(record["method"]), "status": "ok", "details": record.get("parameters", {})})
                wrote = True

            for record in _known_plaintext_permutation(text, context.task_text or ""):
                candidate = bytes(record["candidate"])
                before = len(result.candidates)
                scan(candidate, str(context.input_path), str(record["method"]))
                for hit in result.candidates[before:]:
                    hit["validation"] = "known pairs and recovered ciphertext round-trip verified"
                result.steps.append(
                    {"name": str(record["method"]), "status": "ok", "details": record["parameters"]}
                )
                wrote = True

            for record in _explicit_xor(text, task):
                plaintext = bytes(record["plaintext"])
                scan(plaintext, str(context.input_path), str(record["method"]))
                result.steps.append({"name": str(record["method"]), "status": "ok", "details": record.get("parameters", {})})
                wrote = True

            for index, record in enumerate(_block_and_nonce_views(text, task)):
                method = str(record["method"])
                if "xor" in record:
                    payload = bytes(record["xor"])
                    path = root / f"{method}-{index:02d}.bin"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(payload)
                    result.artifacts.append(str(path))
                    result.steps.append({"name": method, "status": "ok", "details": {"artifact": str(path)}})
                    wrote = True
                else:
                    result.steps.append({"name": method, "status": "ok", "details": {"duplicates": record.get("duplicates"), "blocks": record.get("blocks")}})
                    wrote = True

            if "lcg" in task or all(name in text for name in ("m", "x0", "x1", "x2_top", "x3")):
                try:
                    recovered = recover_lcg(text, context.limits)
                except (ValueError, OverflowError) as exc:
                    result.steps.append({"name": "recover-lcg", "status": "unsupported", "details": {"error": str(exc)}})
                else:
                    output = (
                        f"parameters={recovered['parameters']}\n"
                        + "\n".join(f"round_{index}={value}" for index, value in enumerate(recovered["predictions"], 1))
                        + "\n"
                    ).encode()
                    path = root / "lcg-predictions.txt"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(output)
                    result.artifacts.append(str(path))
                    result.steps.append({"name": "recover-lcg", "status": "ok", "details": recovered["parameters"]})
                    wrote = True
                    scan(output, str(path), "lcg-predictions")

            outputs = [int(match.group(1), 0) for match in re.finditer(r"\b(?:output|value)\s*=\s*(0x[0-9a-fA-F]+|\d+)", text, re.IGNORECASE)]
            if "mt19937" in task and len(outputs) >= 624:
                recovered = recover_mt19937(outputs, context.limits)
                output = f"next_output={recovered['next_output']}\n".encode()
                path = root / "mt19937-recovery.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(output)
                result.artifacts.append(str(path))
                result.steps.append({"name": "recover-mt19937", "status": "ok", "details": {"outputs": 624}})
                wrote = True

            normalized_evidence = re.sub(r"\s+", "", evidence_text.casefold())
            rsa_hint = "rsa" in evidence_text.casefold() or any(
                recipe in normalized_evidence
                for recipe in ("pow(m,e,n)", "pow(flag,e,n)", "pow(message,e,n)")
            )
            rsa_values = _parse_ints(evidence_text, ("n", "e", "c", "e1", "e2", "c1", "c2"))
            if rsa_hint and {"n", "e", "c"}.issubset(rsa_values) and _is_task_evidence_anchor(context):
                try:
                    rsa_records = check_rsa_patterns(rsa_values, context.limits)
                except (ValueError, OverflowError) as exc:
                    rsa_records = []
                    result.steps.append({"name": "rsa-pattern", "status": "unsupported", "details": {"error": str(exc)}})
                for record in rsa_records:
                    if "plaintext" in record:
                        plaintext = bytes(record["plaintext"])
                        is_verified = pow(
                            int.from_bytes(plaintext, "big"), rsa_values["e"], rsa_values["n"]
                        ) == rsa_values["c"]
                        scan(
                            plaintext,
                            str(context.input_path),
                            f"rsa-{record['method']}",
                            validated=is_verified,
                        )
                    result.steps.append({"name": "rsa-pattern", "status": "ok", "details": {"method": record["method"]}})
                    wrote = True

                if not result.candidates:
                    small_factor_hint = re.search(r"getPrime\s*\(\s*10\s*\)", evidence_text, re.IGNORECASE)
                    if small_factor_hint:
                        recovered = _decrypt_rsa_small_prime_product(rsa_values, factor_bound=1023)
                        if recovered is not None:
                            plaintext, distinct_factors = recovered
                            scan(plaintext, str(context.input_path), "rsa-small-prime-product", validated=True)
                            result.steps.append(
                                {
                                    "name": "rsa-small-prime-product",
                                    "status": "ok",
                                    "details": {"factor_bound": 1023, "distinct_factors": distinct_factors},
                                }
                            )
                            wrote = True
                    smooth_pminus1_hint = bool(
                        re.search(r"factor\s*\(\s*[A-Za-z_]\w*\s*-\s*1\s*\)", evidence_text, re.IGNORECASE)
                        and re.search(r"bit_length\s*\(\s*\)\s*<=\s*20", evidence_text, re.IGNORECASE)
                    )
                    if not result.candidates and smooth_pminus1_hint:
                        plaintext = _decrypt_rsa_pm1(
                            rsa_values,
                            smooth_bound=1 << 20,
                            timeout_seconds=context.limits.timeout_seconds,
                        )
                        if plaintext is not None:
                            scan(plaintext, str(context.input_path), "rsa-pollard-pminus1", validated=True)
                            result.steps.append(
                                {
                                    "name": "rsa-pollard-pminus1",
                                    "status": "ok",
                                    "details": {
                                        "smooth_bound": 1 << 20,
                                        "timeout_seconds": context.limits.timeout_seconds,
                                        "task_evidence_files": evidence_files,
                                    },
                                }
                            )
                            wrote = True

            if rsa_hint and _is_task_evidence_anchor(context):
                broadcast_exponent = _parse_ints(evidence_text, ("e",)).get("e")
                broadcast_samples = _parse_indexed_rsa_samples(
                    evidence_text, max_samples=min(context.limits.max_files, 64)
                )
                if broadcast_exponent is not None:
                    broadcast = recover_rsa_broadcast(
                        broadcast_samples,
                        broadcast_exponent,
                        max_samples=min(context.limits.max_files, 64),
                    )
                    if broadcast is not None:
                        plaintext = bytes(broadcast["plaintext"])
                        scan(plaintext, str(context.input_path), "rsa-broadcast-hastad", validated=True)
                        result.steps.append(
                            {
                                "name": "rsa-broadcast-hastad",
                                "status": "candidate",
                                "details": {
                                    "exponent": broadcast["exponent"],
                                    "samples_used": broadcast["samples_used"],
                                    "modulus_product_bits": broadcast["modulus_product_bits"],
                                    "validation": "exact CRT root and ciphertext round-trip verified",
                                },
                            }
                        )
                        wrote = True

                shared_prime_samples = _parse_indexed_rsa_key_samples(
                    evidence_text, max_samples=min(context.limits.max_files, 64)
                )
                for shared_prime in recover_rsa_shared_primes(
                    shared_prime_samples,
                    max_samples=min(context.limits.max_files, 64),
                ):
                    plaintext = bytes(shared_prime["plaintext"])
                    known_values = {str(item.get("value", "")) for item in result.candidates}
                    start = len(result.candidates)
                    scan(
                        plaintext,
                        str(context.input_path),
                        "rsa-shared-prime-batch-gcd",
                        validated=bool(shared_prime["roundtrip_verified"]),
                    )
                    result.candidates[start:] = [
                        item
                        for item in result.candidates[start:]
                        if str(item.get("value", "")) not in known_values
                    ]
                    new_candidate_count = len(result.candidates) - start
                    result.steps.append(
                        {
                            "name": "rsa-shared-prime-batch-gcd",
                            "status": "candidate" if new_candidate_count else "ok",
                            "details": {
                                "key_index": shared_prime["key_index"],
                                "peer_index": shared_prime["peer_index"],
                                "shared_factor_bits": shared_prime["shared_factor_bits"],
                                "modulus_bits": shared_prime["modulus_bits"],
                                "roundtrip_verified": shared_prime["roundtrip_verified"],
                            },
                        }
                    )
                    wrote = True

            stream_evidence = _squared_xor_stream_evidence(context)
            flag_length_match = re.search(
                r"\b(\d+)\s*[- ]?\s*byte[- ]+flag\b", evidence_text, re.IGNORECASE
            )
            if stream_evidence and flag_length_match and not result.candidates:
                flag_length = int(flag_length_match.group(1))
                explicit_prefix = re.search(
                    r"known\s+(?:plaintext\s+)?prefix\s*[:=]\s*([A-Za-z0-9_{}!$?-]{5,8})",
                    evidence_text,
                    re.IGNORECASE,
                )
                if explicit_prefix:
                    prefixes = [explicit_prefix.group(1).encode("ascii")]
                else:
                    format_prefix = re.search(r"\b(ictf|ico|ctf|flag)\s*\{", evidence_text, re.IGNORECASE)
                    preferred = format_prefix.group(1).encode("ascii") + b"{" if format_prefix else b"ictf{"
                    prefixes = list(dict.fromkeys((preferred, b"ictf{", b"ico{", b"CTF{", b"flag{")))

                deadline = time.monotonic() + context.limits.timeout_seconds
                recovered: bytes | None = None
                recovery_details: dict[str, object] = {}
                for prefix in prefixes:
                    recovered, recovery_details = recover_xor_square_stream(
                        data,
                        flag_length=flag_length,
                        known_prefix=prefix,
                        timeout_seconds=max(0.0, deadline - time.monotonic()),
                    )
                    if recovered is not None or recovery_details.get("timed_out"):
                        break

                if recovered is not None:
                    plaintext_path = root / "squared-xor-plaintext.txt"
                    plaintext_path.parent.mkdir(parents=True, exist_ok=True)
                    plaintext_path.write_bytes(recovered + b"\n")
                    result.artifacts.append(str(plaintext_path))
                    result.steps.append(
                        {
                            "name": "recover-xor-square-stream",
                            "status": "candidate",
                            "details": {
                                **recovery_details,
                                "static_evidence": stream_evidence,
                                "encrypted_flag_bytes": flag_length,
                                "known_zero_padding": len(data) - flag_length,
                            },
                        }
                    )
                    scan(
                        recovered,
                        str(plaintext_path),
                        "xor-squared-key-stream-known-plaintext",
                        validated=bool(recovery_details.get("ciphertext_roundtrip")),
                    )
                    wrote = True
                else:
                    result.steps.append(
                        {
                            "name": "recover-xor-square-stream",
                            "status": "needs-review",
                            "details": {
                                **recovery_details,
                                "static_evidence": stream_evidence,
                                "reason": recovery_details.get(
                                    "reason", "no printable flag passed the known-prefix and zero-padding checks"
                                ),
                            },
                        }
                    )
                    needs_review = True

            symmetric = analyze_symmetric_transcript(text, context.limits)
            for index, record in enumerate(symmetric):
                path = root / f"length-extension-{index:02d}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                payload = f"token={record['token']}\ndata={bytes(record['data']).hex()}\n".encode()
                path.write_bytes(payload)
                result.artifacts.append(str(path))
                result.steps.append({"name": record["method"], "status": "ok", "details": {"secret_length": record["secret_length"]}})
                wrote = True
                scan(payload, str(path), str(record["method"]))

            if result.candidates:
                result.status = "candidate"
            elif symmetric or any(step.get("name") == "ctr-nonce-reuse" for step in result.steps):
                result.status = "payload-ready"
            elif needs_review:
                result.status = "candidate-review"
            elif wrote:
                result.status = "derived"
            else:
                result.status = "unsupported"
        except Exception as exc:
            result.status = "failed"
            result.error = f"{type(exc).__name__}: {exc}"
            result.steps.append({"name": "solve", "status": "error", "details": {"error": result.error}})
        return result
