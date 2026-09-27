#!/usr/bin/env python3
"""Bounded, static solver for the published DUCTF 2024 Algebraic Eraser task."""

from __future__ import annotations

import ast
import hashlib
import io
import itertools
import math
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DUCTF_AES_OUTPUT_SHA256 = "13e6cc712683a210a23a012dfc792d4f7bb1f2e0001c3faaef65c5a190bb40f9"
_FIELD = 743
_ORDER = 16
_MATRIX_SIZE = 15
_MAX_SOURCE_BYTES = 1_000_000
_MAX_AST_NODES = 400_000
_MAX_POWER = 64
_SALT = b"DownUnderCTF 2024"


@dataclass(frozen=True)
class DuctfAesOutput:
    tau: tuple[int, ...]
    kappa: tuple[tuple[int, ...], ...]
    braid_matrices: tuple[tuple[tuple[int, ...], ...], ...]
    braid_matrix_nodes: tuple[ast.AST, ...]
    braid_permutations: tuple[tuple[int, ...], ...]
    alice_matrix: tuple[tuple[int, ...], ...]
    alice_permutation: tuple[int, ...]
    bob_matrix: tuple[tuple[int, ...], ...]
    bob_permutation: tuple[int, ...]
    ciphertext: bytes
    nonce: bytes


def _integer_literal(node: ast.AST) -> int:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _integer_literal(node.operand)
        return value if isinstance(node.op, ast.UAdd) else -value
    raise ValueError("finite-field exponent must be an integer literal")


def _eval_gf_node(node: ast.AST, tau: tuple[int, ...], p: int = _FIELD) -> Any:
    """Evaluate only literals, tau variables, containers, and finite-field arithmetic."""

    if isinstance(node, ast.Constant):
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value % p
        if isinstance(node.value, str):
            return node.value
        raise ValueError("unsupported literal in Sage data")
    if isinstance(node, ast.Name):
        if len(node.id) > 1 and node.id[0] == "t" and node.id[1:].isdigit():
            index = int(node.id[1:])
            if index < len(tau):
                return tau[index] % p
        raise ValueError(f"unsupported identifier in Sage data: {node.id}")
    if isinstance(node, (ast.List, ast.Tuple)):
        return tuple(_eval_gf_node(item, tau, p) for item in node.elts)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = _eval_gf_node(node.operand, tau, p)
        if not isinstance(value, int):
            raise ValueError("unary arithmetic on non-integer Sage data")
        return value if isinstance(node.op, ast.UAdd) else (-value) % p
    if isinstance(node, ast.BinOp):
        left = _eval_gf_node(node.left, tau, p)
        if isinstance(node.op, (ast.Pow, ast.BitXor)):
            exponent = _integer_literal(node.right)
            if abs(exponent) > _MAX_POWER:
                raise ValueError("Sage exponent exceeds the bounded parser limit")
            if not isinstance(left, int):
                raise ValueError("power base is not a finite-field scalar")
            try:
                return pow(left, exponent, p)
            except ValueError as exc:
                raise ValueError("negative power of zero in Sage data") from exc
        right = _eval_gf_node(node.right, tau, p)
        if not isinstance(left, int) or not isinstance(right, int):
            raise ValueError("only scalar finite-field arithmetic is allowed")
        if isinstance(node.op, ast.Add):
            return (left + right) % p
        if isinstance(node.op, ast.Sub):
            return (left - right) % p
        if isinstance(node.op, ast.Mult):
            return (left * right) % p
    raise ValueError(f"unsupported Sage syntax: {type(node).__name__}")


def _matrix(value: Any, n: int = _MATRIX_SIZE) -> tuple[tuple[int, ...], ...]:
    if not isinstance(value, tuple) or len(value) != n:
        raise ValueError(f"expected a {n} by {n} matrix")
    rows: list[tuple[int, ...]] = []
    for row in value:
        if not isinstance(row, tuple) or len(row) != n or any(not isinstance(x, int) for x in row):
            raise ValueError(f"expected a {n} by {n} integer matrix")
        rows.append(tuple(x % _FIELD for x in row))
    return tuple(rows)


def _parse_permutation(source: str, n: int = _ORDER) -> tuple[int, ...]:
    if not isinstance(source, str):
        raise ValueError("permutation must be a Sage cycle string")
    permutation = list(range(n))
    cursor = 0
    while cursor < len(source):
        if source[cursor].isspace():
            cursor += 1
            continue
        if source[cursor] != "(":
            raise ValueError("malformed Sage permutation cycle string")
        end = source.find(")", cursor + 1)
        if end < 0:
            raise ValueError("unterminated Sage permutation cycle")
        body = source[cursor + 1 : end].strip()
        if body:
            try:
                cycle = [int(item.strip()) for item in body.split(",")]
            except ValueError as exc:
                raise ValueError("non-integer Sage permutation cycle") from exc
            if any(item < 1 or item > n for item in cycle) or len(set(cycle)) != len(cycle):
                raise ValueError("Sage permutation cycle is outside S_n")
            for index, item in enumerate(cycle):
                permutation[item - 1] = cycle[(index + 1) % len(cycle)] - 1
        cursor = end + 1
    if sorted(permutation) != list(range(n)):
        raise ValueError("Sage permutation cycles do not form a bijection")
    return tuple(permutation)


def parse_output(path: Path) -> DuctfAesOutput:
    """Parse the challenge's data-only Sage output without evaluating Python code."""

    if path.is_symlink():
        raise ValueError("refusing to parse a symlinked AES output file")
    raw = path.read_bytes()
    if len(raw) > _MAX_SOURCE_BYTES:
        raise ValueError("Sage output exceeds the bounded parser size")
    if hashlib.sha256(raw).hexdigest() != DUCTF_AES_OUTPUT_SHA256:
        raise ValueError("Sage output SHA-256 does not match the analyzed DUCTF AES artifact")
    try:
        source = raw.decode("ascii")
        tokens = tokenize.generate_tokens(io.StringIO(source).readline)
        python_source = tokenize.untokenize(
            (token.type, "**" if token.type == tokenize.OP and token.string == "^" else token.string)
            for token in tokens
        )
        module = ast.parse(python_source, filename=str(path), mode="exec")
    except (UnicodeDecodeError, SyntaxError, tokenize.TokenError) as exc:
        raise ValueError("Sage output is not parseable ASCII assignment data") from exc

    count = 0
    stack = [module]
    while stack:
        node = stack.pop()
        count += 1
        if count > _MAX_AST_NODES:
            raise ValueError("Sage output AST exceeds the bounded node limit")
        stack.extend(ast.iter_child_nodes(node))

    assignments: dict[str, ast.AST] = {}
    for statement in module.body:
        if (
            not isinstance(statement, ast.Assign)
            or len(statement.targets) != 1
            or not isinstance(statement.targets[0], ast.Name)
        ):
            raise ValueError("Sage output contains a non-assignment statement")
        name = statement.targets[0].id
        if name in assignments:
            raise ValueError(f"duplicate Sage output assignment: {name}")
        assignments[name] = statement.value
    required = {
        "tau_i", "kappa", "A", "alice_public_matrix", "alice_public_perm",
        "bob_public_matrix", "bob_public_perm", "ct", "nonce",
    }
    if set(assignments) != required:
        raise ValueError("Sage output assignment set differs from the analyzed challenge format")

    tau_value = _eval_gf_node(assignments["tau_i"], ())
    if not isinstance(tau_value, tuple) or len(tau_value) != _ORDER:
        raise ValueError("tau_i must contain exactly sixteen field values")
    tau = tuple(int(value) % _FIELD for value in tau_value)
    if any(value == 0 for value in tau):
        raise ValueError("tau_i contains zero, which is invalid for Laurent terms")

    kappa = _matrix(_eval_gf_node(assignments["kappa"], tau))
    alice_matrix = _matrix(_eval_gf_node(assignments["alice_public_matrix"], tau))
    bob_matrix = _matrix(_eval_gf_node(assignments["bob_public_matrix"], tau))
    alice_permutation = _parse_permutation(_eval_gf_node(assignments["alice_public_perm"], tau))
    bob_permutation = _parse_permutation(_eval_gf_node(assignments["bob_public_perm"], tau))

    braid_node = assignments["A"]
    if not isinstance(braid_node, (ast.List, ast.Tuple)) or not 1 <= len(braid_node.elts) <= 128:
        raise ValueError("A must contain a bounded list of public braid generators")
    braid_matrices: list[tuple[tuple[int, ...], ...]] = []
    braid_matrix_nodes: list[ast.AST] = []
    braid_permutations: list[tuple[int, ...]] = []
    for item in braid_node.elts:
        if not isinstance(item, (ast.List, ast.Tuple)) or len(item.elts) != 2:
            raise ValueError("malformed public braid generator")
        matrix_node, permutation_node = item.elts
        braid_matrix_nodes.append(matrix_node)
        braid_matrices.append(_matrix(_eval_gf_node(matrix_node, tau)))
        braid_permutations.append(_parse_permutation(_eval_gf_node(permutation_node, tau)))

    ciphertext_hex = _eval_gf_node(assignments["ct"], tau)
    nonce_hex = _eval_gf_node(assignments["nonce"], tau)
    if not isinstance(ciphertext_hex, str) or not isinstance(nonce_hex, str):
        raise ValueError("ciphertext and nonce must be hexadecimal strings")
    try:
        ciphertext = bytes.fromhex(ciphertext_hex)
        nonce = bytes.fromhex(nonce_hex)
    except ValueError as exc:
        raise ValueError("ciphertext or nonce is not valid hexadecimal") from exc
    if not ciphertext or len(nonce) != 12:
        raise ValueError("ciphertext is empty or the ChaCha20 nonce has the wrong size")

    return DuctfAesOutput(
        tau=tau,
        kappa=kappa,
        braid_matrices=tuple(braid_matrices),
        braid_matrix_nodes=tuple(braid_matrix_nodes),
        braid_permutations=tuple(braid_permutations),
        alice_matrix=alice_matrix,
        alice_permutation=alice_permutation,
        bob_matrix=bob_matrix,
        bob_permutation=bob_permutation,
        ciphertext=ciphertext,
        nonce=nonce,
    )


def _identity_matrix(n: int) -> list[list[int]]:
    return [[int(row == col) for col in range(n)] for row in range(n)]


def _matrix_multiply(left: tuple[tuple[int, ...], ...] | list[list[int]], right: tuple[tuple[int, ...], ...] | list[list[int]]) -> list[list[int]]:
    n = len(left)
    return [
        [sum(left[row][k] * right[k][col] for k in range(n)) % _FIELD for col in range(n)]
        for row in range(n)
    ]


def _matrix_inverse(matrix: tuple[tuple[int, ...], ...] | list[list[int]]) -> list[list[int]]:
    n = len(matrix)
    work = [[int(value) % _FIELD for value in row] + identity for row, identity in zip(matrix, _identity_matrix(n))]
    for col in range(n):
        pivot = next((row for row in range(col, n) if work[row][col] % _FIELD), None)
        if pivot is None:
            raise ValueError("matrix is singular over GF(743)")
        work[col], work[pivot] = work[pivot], work[col]
        scale = pow(work[col][col], _FIELD - 2, _FIELD)
        work[col] = [(value * scale) % _FIELD for value in work[col]]
        for row in range(n):
            if row == col:
                continue
            factor = work[row][col]
            if factor:
                work[row] = [(a - factor * b) % _FIELD for a, b in zip(work[row], work[col])]
    return [row[n:] for row in work]


def _identity_permutation(n: int) -> tuple[int, ...]:
    return tuple(range(n))


def _compose_permutations(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    """Sage's left-action product: (left * right)(i) = right(left(i))."""

    return tuple(right[left[index]] for index in range(len(left)))


def _inverse_permutation(permutation: tuple[int, ...]) -> tuple[int, ...]:
    inverse = [0] * len(permutation)
    for index, image in enumerate(permutation):
        inverse[image] = index
    return tuple(inverse)


def _permutation_order(permutation: tuple[int, ...]) -> int:
    seen: set[int] = set()
    order = 1
    for start in range(len(permutation)):
        if start in seen:
            continue
        current = start
        length = 0
        while current not in seen:
            seen.add(current)
            current = permutation[current]
            length += 1
        order = math.lcm(order, length)
    return order


def _apply_permutation_to_tau(permutation: tuple[int, ...], tau: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(tau[index] for index in permutation)


def _word_permutation(word: tuple[tuple[int, ...], ...] | list[tuple[int, ...]], n: int) -> tuple[int, ...]:
    result = _identity_permutation(n)
    for permutation in word:
        result = _compose_permutations(result, permutation)
    return result


def _minkwitz_factorization(
    generators: tuple[tuple[int, ...], ...], target: tuple[int, ...]
) -> list[tuple[int, int]]:
    """Port of the challenge author's bounded length-1/2 Minkwitz factorizer."""

    degree = max(
        (
            index + 1
            for permutation in (*generators, target)
            for index, image in enumerate(permutation)
            if index != image
        ),
        default=0,
    )
    if degree == 0:
        return []
    generators = tuple(permutation[:degree] for permutation in generators)
    target = target[:degree]
    n = degree
    levels: dict[int, dict[int, tuple[tuple[int, ...], ...]]] = {i: {} for i in range(1, n + 1)}
    syllables = list(generators) + [_inverse_permutation(item) for item in generators]
    identity = _identity_permutation(n)
    product_cache: dict[tuple[tuple[int, ...], ...], tuple[int, ...]] = {(): identity}
    inverse_word_cache: dict[tuple[tuple[int, ...], ...], tuple[tuple[int, ...], ...]] = {}

    def word_product(word: tuple[tuple[int, ...], ...]) -> tuple[int, ...]:
        if word not in product_cache:
            result = identity
            for item in word:
                result = _compose_permutations(result, item)
            product_cache[word] = result
        return product_cache[word]

    def reverse_inverse_word(word: tuple[tuple[int, ...], ...]) -> tuple[tuple[int, ...], ...]:
        if word not in inverse_word_cache:
            inverse_word_cache[word] = tuple(_inverse_permutation(item) for item in reversed(word))
        return inverse_word_cache[word]

    for length in (1, 2):
        for initial_word in itertools.product(syllables, repeat=length):
            word = tuple(initial_word)
            group_element = word_product(word)
            for level in range(1, n + 1):
                image = group_element[level - 1] + 1
                for upper in range(1, level):
                    if image not in levels[upper] or len(word) < len(levels[upper][image]):
                        levels[upper][image] = word
                if image not in levels[level] or len(word) < len(levels[level][image]):
                    levels[level][image] = word
                    break
                previous_word = levels[level][image]
                word = word + reverse_inverse_word(previous_word)
                if len(word) > 8192:
                    raise ValueError("Minkwitz word exceeded the bounded factorization limit")
                group_element = _compose_permutations(
                    group_element,
                    _inverse_permutation(word_product(previous_word)),
                )

    inverse_syllables: tuple[tuple[int, ...], ...] = ()
    current = target
    for level in range(1, n + 1):
        image = current[level - 1] + 1
        if image > level:
            correction = levels[level].get(image)
            if correction is None:
                raise ValueError("Minkwitz factorization table is incomplete")
            inverse_syllables = correction + inverse_syllables
            current = _compose_permutations(
                current,
                _inverse_permutation(word_product(correction)),
            )

    if word_product(inverse_syllables) != target:
        raise ValueError("Minkwitz factorization does not reproduce Alice's public permutation")
    index_by_permutation = {permutation: index for index, permutation in enumerate(generators)}
    factors: list[tuple[int, int]] = []
    for syllable in inverse_syllables:
        if syllable in index_by_permutation:
            factors.append((index_by_permutation[syllable], 1))
        else:
            inverse = _inverse_permutation(syllable)
            if inverse not in index_by_permutation:
                raise ValueError("Minkwitz word uses an unknown braid generator")
            factors.append((index_by_permutation[inverse], -1))
    return factors


def _right_kernel_vector(rows: list[list[int]], columns: int) -> list[int]:
    if any(len(row) != columns for row in rows):
        raise ValueError("linear system has inconsistent row widths")
    try:
        import numpy as np
    except ImportError as exc:
        raise RuntimeError("NumPy is required for the bounded finite-field matrix solve") from exc

    # Values stay below 743^2, so signed 64-bit vector operations are exact.
    work = np.asarray(rows, dtype=np.int64) % _FIELD
    pivot_columns: list[int] = []
    pivot_row = 0
    for column in range(columns):
        candidates = np.flatnonzero(work[pivot_row:, column])
        if not len(candidates):
            continue
        pivot = pivot_row + int(candidates[0])
        work[pivot_row], work[pivot] = work[pivot], work[pivot_row]
        scale = pow(int(work[pivot_row, column]), _FIELD - 2, _FIELD)
        work[pivot_row] = (work[pivot_row] * scale) % _FIELD
        factors = work[:, column].copy()
        factors[pivot_row] = 0
        affected = np.flatnonzero(factors)
        if len(affected):
            work[affected] = (
                work[affected] - factors[affected, None] * work[pivot_row][None, :]
            ) % _FIELD
        pivot_columns.append(column)
        pivot_row += 1
        if pivot_row == work.shape[0]:
            break

    pivot_set = set(pivot_columns)
    free_columns = [column for column in range(columns) if column not in pivot_set]
    if len(free_columns) != 1:
        raise ValueError(f"secret-matrix linear system has nullity {len(free_columns)}, expected one")
    free = free_columns[0]
    vector = [0] * columns
    vector[free] = 1
    for row, column in enumerate(pivot_columns):
        vector[column] = (-int(work[row, free])) % _FIELD
    return vector


def _equation_rows(left: list[list[int]], right: list[list[int]]) -> list[list[int]]:
    n = len(left)
    rows: list[list[int]] = []
    for row in range(n):
        for col in range(n):
            coefficients = [0] * (n * n)
            for index in range(n):
                coefficients[row * n + index] += left[index][col]
                coefficients[index * n + col] -= right[row][index]
            rows.append([value % _FIELD for value in coefficients])
    return rows


def _product_word(
    factors: list[tuple[int, int]],
    data: DuctfAesOutput,
    tau: tuple[int, ...],
    matrix_cache: dict[tuple[int, tuple[int, ...]], list[list[int]]],
) -> tuple[list[list[int]], tuple[int, ...]]:
    n = len(data.tau)
    current_matrix = _identity_matrix(_MATRIX_SIZE)
    current_permutation = _identity_permutation(n)

    def matrix_at(index: int, values: tuple[int, ...]) -> list[list[int]]:
        key = (index, values)
        if key not in matrix_cache:
            value = _eval_gf_node(data.braid_matrix_nodes[index], values)
            matrix_cache[key] = [list(row) for row in _matrix(value)]
        return matrix_cache[key]

    for index, exponent in factors:
        generator_permutation = data.braid_permutations[index]
        if exponent == 1:
            factor_matrix = matrix_at(index, _apply_permutation_to_tau(current_permutation, tau))
            factor_permutation = generator_permutation
        elif exponent == -1:
            inverse_permutation = _inverse_permutation(generator_permutation)
            shifted_tau = _apply_permutation_to_tau(
                inverse_permutation,
                _apply_permutation_to_tau(current_permutation, tau),
            )
            factor_matrix = _matrix_inverse(matrix_at(index, shifted_tau))
            factor_permutation = inverse_permutation
        else:
            raise ValueError("Minkwitz factor exponent is not ±1")
        current_matrix = _matrix_multiply(current_matrix, factor_matrix)
        current_permutation = _compose_permutations(current_permutation, factor_permutation)
    return current_matrix, current_permutation


def solve_output(path: Path) -> dict[str, Any]:
    """Recover the local plaintext and return evidence; this does not contact a checker."""

    data = parse_output(path)
    cache = {
        (index, data.tau): [list(row) for row in matrix]
        for index, matrix in enumerate(data.braid_matrices)
    }

    orders = [_permutation_order(permutation) for permutation in data.braid_permutations]
    alpha_index = min(range(len(orders)), key=orders.__getitem__)
    alpha_order = orders[alpha_index]
    alpha_factors = [(alpha_index, 1)] * alpha_order
    alpha_matrix, alpha_permutation = _product_word(alpha_factors, data, data.tau, cache)
    if alpha_permutation != _identity_permutation(_ORDER):
        raise ValueError("selected alpha power did not reduce its permutation to identity")
    if alpha_matrix == _identity_matrix(_MATRIX_SIZE):
        raise ValueError("selected alpha power has an identity evaluated matrix")

    def evaluate_alpha(values: tuple[int, ...]) -> list[list[int]]:
        result, permutation = _product_word(alpha_factors, data, values, cache)
        if permutation != _identity_permutation(_ORDER):
            raise ValueError("alpha evaluator produced a non-identity permutation")
        return result

    q = [list(row) for row in data.bob_matrix]
    q_inverse = _matrix_inverse(q)
    bob_alpha = _matrix_multiply(
        q,
        evaluate_alpha(_apply_permutation_to_tau(data.bob_permutation, data.tau)),
    )
    right_factor = _matrix_multiply(bob_alpha, q_inverse)
    equation_rows = _equation_rows(alpha_matrix, right_factor)
    equation_rows.extend(_equation_rows([list(row) for row in data.kappa], [list(row) for row in data.kappa]))
    flat_secret = _right_kernel_vector(equation_rows, _MATRIX_SIZE * _MATRIX_SIZE)
    secret_matrix = [flat_secret[i : i + _MATRIX_SIZE] for i in range(0, len(flat_secret), _MATRIX_SIZE)]
    if _matrix_multiply(secret_matrix, alpha_matrix) != _matrix_multiply(right_factor, secret_matrix):
        raise ValueError("recovered matrix does not satisfy the public intertwining equation")
    if _matrix_multiply(secret_matrix, data.kappa) != _matrix_multiply(data.kappa, secret_matrix):
        raise ValueError("recovered matrix does not commute with kappa")
    secret_inverse = _matrix_inverse(secret_matrix)

    factors = _minkwitz_factorization(data.braid_permutations, data.alice_permutation)
    delta_matrix, delta_permutation = _product_word(factors, data, data.tau, cache)
    if delta_permutation != data.alice_permutation:
        raise ValueError("recovered braid word does not match Alice's public permutation")
    shared_secret = _matrix_multiply(secret_matrix, data.alice_matrix)
    shared_secret = _matrix_multiply(shared_secret, _matrix_inverse(delta_matrix))
    shared_secret = _matrix_multiply(shared_secret, secret_inverse)
    shared_secret = _matrix_multiply(shared_secret, q)
    shared_secret = _matrix_multiply(shared_secret, delta_matrix)

    try:
        from Crypto.Cipher import ChaCha20
        from Crypto.Protocol.KDF import PBKDF2
    except ImportError as exc:
        raise RuntimeError("PyCryptodome is required for the DUCTF AES profile") from exc
    password = b"".join(f"{value % _FIELD:03x}".encode("ascii") for row in shared_secret for value in row)
    key = PBKDF2(password, _SALT, 32, count=1_000_000)
    plaintext = ChaCha20.new(key=key, nonce=data.nonce).decrypt(data.ciphertext)
    try:
        plaintext_text = plaintext.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("decrypted AES plaintext is not ASCII") from exc
    if not (plaintext_text.startswith("DUCTF{") and plaintext_text.endswith("}") and len(plaintext_text) <= 256):
        raise ValueError("decrypted plaintext does not have the expected DUCTF flag shape")
    return {
        "flag": plaintext_text,
        "plaintext_hex": plaintext.hex(),
        "output_sha256": DUCTF_AES_OUTPUT_SHA256,
        "alpha_generator_index": alpha_index,
        "alpha_permutation_order": alpha_order,
        "nullity": 1,
        "matrix_equation_verified": True,
        "kappa_commutation_verified": True,
        "alice_permutation_factor_count": len(factors),
        "alice_permutation_verified": True,
        "chacha20_plaintext_shape_verified": True,
        "challenge_code_executed": False,
        "network_requested": False,
        "platform_confirmation": False,
    }
