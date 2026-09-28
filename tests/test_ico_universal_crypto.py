from __future__ import annotations

import base64
import hashlib
import math
import random
import tempfile
import unittest
from pathlib import Path

from ico_quals_solvers import sha256_length_extend
from ico_solver_engine import SolverContext, SolverLimits
import ico_universal_crypto
from ico_universal_crypto import CryptoSolver, check_rsa_patterns, recover_lcg, recover_mt19937


def _context(
    root: Path,
    source: Path,
    task_text: str | None = None,
    related_paths: tuple[Path, ...] = (),
) -> SolverContext:
    return SolverContext(
        input_path=source,
        report_dir=root / "report",
        limits=SolverLimits(max_bytes=4 * 1024 * 1024, max_files=1000, max_depth=3, timeout_seconds=1.0),
        related_paths=related_paths,
        task_text=task_text,
        classification={"kind": "text", "mime": "text/plain"},
    )


def _encrypt_squared_xor_stream(data: bytes, key: int) -> bytes:
    size = (len(data) // 8 + 1) * 8
    padded = data.ljust(size, b"\x00")
    output = bytearray()
    for offset in range(0, size, 8):
        block = int.from_bytes(padded[offset : offset + 8], "little") ^ key
        output.extend(block.to_bytes(8, "little"))
        key = (key * key) & ((1 << 64) - 1)
    return bytes(output)


class UniversalCryptoTests(unittest.TestCase):
    def test_crypto_solver_recovers_a_squared_xor_stream_from_paired_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "stream.c"
            output = root / "out.txt"
            flag = b"ictf{abc}"
            source.write_text(
                "for (size_t i = 0; i < len / 8; ++i) {\n"
                "    data[i] = data[i] ^ key;\n"
                "    key *= key;\n"
                "}\n",
                encoding="utf-8",
            )
            output.write_bytes(_encrypt_squared_xor_stream(flag + b"\n", 0x1234567890ABCDEF))
            context = SolverContext(
                input_path=output,
                report_dir=root / "report",
                limits=SolverLimits(max_bytes=1024 * 1024, max_files=100, max_depth=2, timeout_seconds=2.0),
                related_paths=(source,),
                task_text="Crypto stream: 10-byte flag. Known prefix: ictf{ab",
                classification={"kind": "data", "mime": "application/octet-stream"},
            )
            result = CryptoSolver().solve(context)

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertIn("ictf{abc}", {candidate["value"] for candidate in result.candidates})
        self.assertTrue(any(step["name"] == "recover-xor-square-stream" for step in result.steps))

    def test_lcg_recovery_and_prediction(self):
        m, a, c, x0 = 10007, 37, 91, 1234
        x1 = (a * x0 + c) % m
        x2 = (a * x1 + c) % m
        x3 = (a * x2 + c) % m
        text = f"m={m} x0={x0} x1={x1} x2_top={x2 >> 2} x3={x3} hidden_bits=2 rounds=2"
        result = recover_lcg(text, SolverLimits(max_bytes=1024, max_files=10, max_depth=2, timeout_seconds=1.0))
        self.assertEqual(result["parameters"], {"a": a, "c": c, "x2": x2})
        self.assertEqual(result["predictions"][0], (a * x3 + c) % m)

    def test_mt19937_recovery_clones_next_output(self):
        source = random.Random(12345)
        outputs = [source.getrandbits(32) for _ in range(624)]
        expected = source.getrandbits(32)
        result = recover_mt19937(outputs, SolverLimits(max_bytes=100000, max_files=1000, max_depth=1, timeout_seconds=1.0))
        self.assertEqual(result["next_output"], expected)
        self.assertEqual(len(result["state"]), 624)

    def test_rsa_low_exponent_pattern_returns_plaintext(self):
        message = int.from_bytes(b"OK", "big")
        result = check_rsa_patterns(
            {"n": 1000000007 * 1000000009, "e": 3, "c": message**3},
            SolverLimits(max_bytes=1024, max_files=10, max_depth=1, timeout_seconds=1.0),
        )
        self.assertEqual(result[0]["plaintext"], b"OK")

    def test_rsa_broadcast_recovers_only_exact_crt_power(self):
        message = int.from_bytes(b"ICO{x}", "big")
        exponent = 3
        moduli = [(1 << 61) - 1, (1 << 61) - 3, (1 << 61) - 5]
        recover = getattr(ico_universal_crypto, "recover_rsa_broadcast", None)
        self.assertIsNotNone(recover, "Hastad broadcast solver is not implemented")

        result = recover([(modulus, pow(message, exponent, modulus)) for modulus in moduli], exponent)

        self.assertEqual(result["plaintext"], b"ICO{x}")
        self.assertEqual(result["method"], "rsa-broadcast-hastad")
        self.assertEqual(result["samples_used"], exponent)

    def test_rsa_broadcast_rejects_shared_modulus_factors_and_inexact_roots(self):
        recover = getattr(ico_universal_crypto, "recover_rsa_broadcast", None)
        self.assertIsNotNone(recover, "Hastad broadcast solver is not implemented")
        self.assertIsNone(recover([(15, 7), (21, 7), (33, 7)], 3))
        self.assertIsNone(recover([(101, 2), (103, 3), (107, 4)], 3))

    def test_rsa_shared_prime_batch_gcd_decrypts_only_with_verified_roundtrip(self):
        p, q1, q2, exponent = 1_000_000_007, 1_000_000_009, 1_000_000_033, 65_537
        message = int.from_bytes(b"ICO{x}", "big")
        samples = [
            (p * q1, exponent, pow(message, exponent, p * q1)),
            (p * q2, exponent, pow(message, exponent, p * q2)),
            (1_000_000_087 * 1_000_000_093, exponent, 12345),
        ]

        recovered = ico_universal_crypto.recover_rsa_shared_primes(samples)

        self.assertEqual(recovered[0]["plaintext"], b"ICO{x}")
        self.assertTrue(recovered[0]["roundtrip_verified"])
        self.assertEqual(recovered[0]["method"], "rsa-shared-prime-batch-gcd")
        self.assertEqual(ico_universal_crypto.recover_rsa_shared_primes(samples[1:]), [])

    def test_rsa_shared_prime_parser_pairs_only_explicitly_indexed_values(self):
        samples = ico_universal_crypto._parse_indexed_rsa_key_samples(
            "n_2=15 e_2=3 c_2=8\nn[1]=21 exponent[1]=5 ciphertext[1]=7\nn=33 e=7 c=2",
            max_samples=8,
        )

        self.assertEqual(samples, [(21, 5, 7), (15, 3, 8)])

    def test_crypto_solver_recovers_rsa_with_a_shared_prime_across_related_files(self):
        p, q1, q2, exponent = 1_000_000_007, 1_000_000_009, 1_000_000_033, 65_537
        message = int.from_bytes(b"ICO{x}", "big")
        n1, n2 = p * q1, p * q2
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "a_challenge.py"
            keys = root / "z_public_values.txt"
            source.write_text("# RSA key reuse challenge\n", encoding="utf-8")
            keys.write_text(
                f"n_1={n1}\ne_1={exponent}\nc_1={pow(message, exponent, n1)}\n"
                f"n_2={n2}\ne_2={exponent}\nc_2={pow(message, exponent, n2)}\n",
                encoding="utf-8",
            )

            result = CryptoSolver().solve(
                _context(root, source, "RSA shared-prime key reuse", related_paths=(keys,))
            )

        hit = next((item for item in result.candidates if item["value"] == "ICO{x}"), None)
        self.assertIsNotNone(hit, result.steps)
        self.assertEqual(hit["validation"], "cryptographic round-trip verified")
        self.assertTrue(any(step["name"] == "rsa-shared-prime-batch-gcd" for step in result.steps))

    def test_crypto_solver_recovers_numbered_rsa_broadcast_samples_from_task_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "a_challenge.py"
            samples_file = root / "z_samples.txt"
            message = int.from_bytes(b"ICO{x}", "big")
            exponent = 3
            moduli = [(1 << 61) - 1, (1 << 61) - 3, (1 << 61) - 5]
            lines = []
            for index, modulus in enumerate(moduli, 1):
                lines.extend((f"n_{index} = {modulus}", f"c_{index} = {pow(message, exponent, modulus)}"))
            source.write_text("# RSA broadcast, same unpadded message and exponent e=3.\n", encoding="utf-8")
            samples_file.write_text("\n".join(lines), encoding="utf-8")

            result = CryptoSolver().solve(
                _context(root, source, "RSA broadcast challenge", related_paths=(samples_file,))
            )

        hit = next((candidate for candidate in result.candidates if candidate["value"] == "ICO{x}"), None)
        self.assertIsNotNone(hit, result.steps)
        self.assertEqual(result.status, "candidate")
        self.assertEqual(hit["validation"], "cryptographic round-trip verified")
        self.assertTrue(any(step["name"] == "rsa-broadcast-hastad" for step in result.steps))

    def test_crypto_solver_joins_source_and_ciphertext_for_small_prime_rsa(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "chal.py"
            output = root / "out.txt"
            primes = [521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631]
            n = math.prod(primes)
            phi = math.prod(prime - 1 for prime in primes)
            e = 65537
            self.assertEqual(math.gcd(e, phi), 1)
            message = int.from_bytes(b"ICO{cross_file$?}", "big")
            self.assertLess(message, n)
            ciphertext = pow(message, e, n)
            source.write_text(
                "from Crypto.Util.number import getPrime\n"
                "primes = [getPrime(10) for _ in range(200)]\n"
                "n = p * q\ne = 65537\nct = pow(flag, e, n)\n",
                encoding="utf-8",
            )
            output.write_text(f"n = {n}\ne = {e}\nct = {ciphertext}\n", encoding="utf-8")
            result = CryptoSolver().solve(
                _context(root, source, "Crypto RSA challenge", related_paths=(output,))
            )

        recovered = next(item for item in result.candidates if item["value"].startswith("ICO{"))
        self.assertEqual(recovered["value"], "ICO{cross_file$?}")
        self.assertEqual(recovered["triage"], "candidate")
        self.assertEqual(recovered.get("validation"), "cryptographic round-trip verified")

    def test_pollard_pm1_splits_a_modulus_with_one_smooth_predecessor(self):
        factor = ico_universal_crypto.pollard_pm1_factor(101 * 173, smooth_bound=25)
        self.assertEqual(factor, 101)

    def test_pm1_rsa_decryption_works_without_pycryptodome(self):
        modulus = 97 * 193
        exponent = 17
        message = 42
        ciphertext = pow(message, exponent, modulus)
        plaintext = ico_universal_crypto._decrypt_rsa_pm1(
            {"n": modulus, "e": exponent, "c": ciphertext},
            smooth_bound=64,
            timeout_seconds=1.0,
        )

        self.assertEqual(plaintext, b"*")

    def test_pm1_batches_smooth_factors_and_recovers_factor_in_mid_batch(self):
        p = 13_385_572_201
        q = 20_078_358_301
        factor = ico_universal_crypto.pollard_pm1_factor(
            p * q,
            smooth_bound=1 << 20,
            timeout_seconds=10.0,
        )

        self.assertIn(factor, {p, q})

    def test_crypto_smoll_archive_instance_solves_with_default_task_budget(self):
        n = (
            13499674168194561466922316170242276798504319181439855249990301432638272860625833163910240845751072537454409673251895471438416265237739552031051231793428184850123919306354002012853393046964765903473183152496753902632017353507140401241943223024609065186313736615344552390240803401818454235028841174032276853980750514304794215328089
        )
        ciphertext = (
            12788784649128212003443801911238808677531529190358823987334139319133754409389076097878414688640165839022887582926546173865855012998136944892452542475239921395969959310532820340139252675765294080402729272319702232876148895288145134547288146650876233255475567026292174825779608187676620580631055656699361300542021447857973327523254
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "smoll.py"
            output = root / "output.txt"
            source.write_text(
                "from sage.all import factor\n"
                "for r in [p, q]:\n"
                "    for s, _ in factor(r - 1):\n"
                "        assert int(s).bit_length() <= 20\n"
                "n = p * q\ne = 65537\nct = pow(flag, e, n)\n",
                encoding="utf-8",
            )
            output.write_text(f"n = {n}\ne = 65537\nct = {ciphertext}\n", encoding="utf-8")
            context = SolverContext(
                input_path=output,
                report_dir=root / "report",
                limits=SolverLimits(
                    max_bytes=4 * 1024 * 1024,
                    max_files=1000,
                    max_depth=3,
                    timeout_seconds=30.0,
                ),
                related_paths=(source,),
                task_text="RSA with factor(r - 1) and prime factor bit_length() <= 20",
                classification={"kind": "text", "mime": "text/plain"},
            )
            result = CryptoSolver().solve(
                context
            )

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertEqual(len(result.candidates), 1)
        plaintext = result.candidates[0]["value"].encode()
        self.assertEqual(pow(int.from_bytes(plaintext, "big"), 65537, n), ciphertext)

    def test_crypto_solver_builds_length_extension_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = b"user=guest&level=basic"
            token = hashlib.sha256(b"S" * 18 + old).hexdigest()
            source = root / "vip.log"
            source.write_text(f"data0={old.hex()} token0={token} suffix=&level=admin", encoding="utf-8")
            result = CryptoSolver().solve(_context(root, source, "SHA-256 length extension"))
        self.assertEqual(result.status, "payload-ready")
        self.assertTrue(any("length" in path for path in result.artifacts))

    def test_crypto_solver_does_not_guess_plaintext_from_random_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "unknown.txt"
            source.write_text("random crypto words without parameters", encoding="utf-8")
            result = CryptoSolver().solve(_context(root, source, "cryptography"))
        self.assertEqual(result.candidates, [])
        self.assertIn(result.status, {"unsupported", "derived"})

    def test_explicit_rot_and_known_key_xor_are_condition_backed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "cipher.txt"
            source.write_text("cipher=PGS{ebg_svkgher} key=0x55", encoding="utf-8")
            result = CryptoSolver().solve(_context(root, source, "ROT13 crypto"))
        values = {item["value"] for item in result.candidates}
        self.assertIn("CTF{rot_fixture}", values)

    def test_caesar_prose_extracts_shift_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "cipher.txt"
            source.write_text("cipher: pjv{ilujo_jyfwav_lhzf_jhlzhy}", encoding="utf-8")
            task = "The field named cipher is Caesar-shifted by 7. Decode it."
            result = CryptoSolver().solve(_context(root, source, task))
        self.assertIn("ico{bench_crypto_easy_caesar}", {item["value"] for item in result.candidates})

    def test_crypto_solver_hands_off_explicit_multistage_transform_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "cipher.txt"
            encoded = base64.b64encode(b"ico{rot13_base64_chain}")
            rot13_table = bytes.maketrans(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            )
            source.write_bytes(b"cipher=" + encoded.translate(rot13_table))
            task = "Crypto task: decode the ciphertext with ROT13, then decode the result with Base64."
            result = CryptoSolver().solve(_context(root, source, task))
            self.assertEqual(len(result.derived_inputs), 1, result.steps)
            intermediate = Path(result.derived_inputs[0]).read_bytes()

        self.assertEqual(result.candidates, [])
        self.assertEqual(intermediate, encoded)
        self.assertTrue(any(step["name"] == "handoff-explicit-transform-chain" for step in result.steps))

    def test_crypto_solver_does_not_handoff_a_single_explicit_transform(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "cipher.txt"
            encoded = base64.b64encode(b"ico{single_transform}")
            rot13_table = bytes.maketrans(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                b"NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            )
            source.write_bytes(b"cipher=" + encoded.translate(rot13_table))
            result = CryptoSolver().solve(_context(root, source, "ROT13 crypto task"))

        self.assertEqual(result.derived_inputs, [])

    def test_katana_inspired_offline_text_decoders_are_condition_backed(self):
        cases = (
            ("cipher=.. -.-. --- { ..-. .-.. .- --. }", "Morse code challenge", "ICO{FLAG}"),
            ("cipher=India Charlie Oscar { Foxtrot Lima Alfa Golf }", "NATO phonetic alphabet", "ICO{FLAG}"),
            ("cipher=RXL{ZGYZHS}", "Atbash cipher", "ICO{ATBASH}"),
            ("cipher=:4@LC@EcfN", "ROT47 cipher", "ico{rot47}"),
            ("cipher=444 222 666 { 333 555 2 4 }", "T9 multi-tap cipher", "ICO{FLAG}"),
            ("cipher=ir_cc{alfneoie}", "Rail fence cipher with 3 rails", "ico{rail_fence}"),
        )
        for encoded, task, expected in cases:
            with self.subTest(task=task), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "cipher.txt"
                source.write_text(encoded, encoding="utf-8")
                context = _context(root, source, task)
                solver = CryptoSolver()
                self.assertIsNotNone(solver.detect(context), "explicit task hint should route to CryptoSolver")
                result = solver.solve(context)
            self.assertIn(expected, {item["value"] for item in result.candidates}, result.steps)

    def test_katana_inspired_rail_fence_requires_rails_from_condition(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "cipher.txt"
            source.write_text("cipher=WECRLTEERDSOEEFEAOCAIVDEN", encoding="utf-8")
            result = CryptoSolver().solve(_context(root, source, "Rail fence transposition cipher"))
        self.assertFalse(result.candidates)

    def test_katana_inspired_decoders_do_not_run_without_explicit_task_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "cipher.txt"
            source.write_text("cipher=RXL{ZGYZHS}", encoding="utf-8")
            result = CryptoSolver().solve(_context(root, source, "miscellaneous text"))
        self.assertFalse(result.candidates)

    def test_rail_fence_decoder_matches_standard_three_rail_vector(self):
        self.assertEqual(
            ico_universal_crypto._rail_fence_decrypt("WECRLTEERDSOEEFEAOCAIVDEN", 3),
            "WEAREDISCOVEREDFLEEATONCE",
        )

    def test_crypto_solver_recovers_known_plaintext_permutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "output_censored.txt"
            permutation = (3, 0, 6, 1, 7, 4, 2, 5)

            def apply_permutation(value: str) -> str:
                return "".join(value[index] for index in permutation)

            hidden = "hidden42"
            source.write_text(
                "aaaabbbb -> " + apply_permutation("aaaabbbb") + "\n"
                "abcdabcd -> " + apply_permutation("abcdabcd") + "\n"
                "???????? -> " + apply_permutation(hidden) + "\n",
                encoding="utf-8",
            )
            context = _context(
                root,
                source,
                "The text was shuffled using a fixed permutation. Recover the censored text and surround it with DUCTF{}.",
            )
            solver = CryptoSolver()
            detection = solver.detect(context)
            result = solver.solve(context)

        self.assertIsNotNone(detection)
        self.assertEqual(result.status, "candidate", result.steps)
        self.assertIn("DUCTF{hidden42}", {item["value"] for item in result.candidates})
        details = next(step["details"] for step in result.steps if step["name"] == "known-plaintext-permutation")
        self.assertTrue(details["roundtrip_verified"])
        self.assertEqual(details["known_pairs"], 2)

    def test_ecb_and_ctr_views_are_structural_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "modes.log"
            block = "00" * 16
            source.write_text(
                f"cipher={block}{block} nonce-reuse c1=0011223344556677 c2=1122334455667788",
                encoding="utf-8",
            )
            result = CryptoSolver().solve(_context(root, source, "AES ECB CTR nonce reuse"))
        self.assertIn(result.status, {"derived", "payload-ready"})
        self.assertTrue(any(step["name"] == "ecb-repeated-blocks" for step in result.steps))
        self.assertTrue(any(step["name"] == "ctr-nonce-reuse" for step in result.steps))

    def test_aethmap_public_seal_identity_decrypts_without_running_sealer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "gm_chamber.aethmap"
            sealer = root / "aethmap_sealer.py"
            sealer.write_text(
                """P = 257
G = 3

def derive_keystream(secret_bytes: bytes, vault_seal: int, length: int) -> bytes:
    s = bytes_to_long(secret_bytes)
    out = bytearray()
    for i in range(length):
        coil_factor = (i * 0x9E3779B9 + 0x12345678) % (P - 1)
        bind_base = pow(G, coil_factor, P)
        bind = pow(bind_base, s, P)
        weave = pow(vault_seal, coil_factor, P)
        breath = pow(G, (s + coil_factor) % (P - 1), P)
        coil = (bind * weave * breath) % P
        out.append((coil >> ((i * 7) % 24)) & 0xFF)
    return bytes(out)

def seal_map(plaintext_aethmap: bytes, secret: bytes | None = None) -> bytes:
    if secret is None:
        secret = os.urandom(32)
    vault_seal = pow(G, bytes_to_long(secret), P)
    header = plaintext_aethmap[:0xE0]
    payload = plaintext_aethmap[0xE0:]
    ks = derive_keystream(secret, vault_seal, len(payload))
    ciphertext = bytes(p ^ k for p, k in zip(payload, ks))
    return header + long_to_bytes(vault_seal, 32) + ciphertext
""",
                encoding="utf-8",
            )
            plaintext = b"ICO{aethmap_fixture}\n"
            header = bytearray(0xE0)
            header[:4] = b"AETH"
            secret = 47
            p, g = 257, 3
            seal = pow(g, secret, p)
            ciphertext = bytearray()
            for index, value in enumerate(plaintext):
                factor = (index * 0x9E3779B9 + 0x12345678) % (p - 1)
                bind_base = pow(g, factor, p)
                bind = pow(bind_base, secret, p)
                weave = pow(seal, factor, p)
                breath = pow(g, (secret + factor) % (p - 1), p)
                coil = (bind * weave * breath) % p
                ciphertext.append(value ^ ((coil >> ((index * 7) % 24)) & 0xFF))
            source.write_bytes(bytes(header) + seal.to_bytes(32, "big") + ciphertext)
            context = _context(root, source)

            result = CryptoSolver().solve(context)
            decrypted = Path(result.artifacts[0]).read_bytes()

        self.assertEqual(result.status, "candidate", result.steps)
        self.assertIn("ICO{aethmap_fixture}", {item["value"] for item in result.candidates})
        step = next(item for item in result.steps if item["name"] == "aethmap-public-seal-decrypt")
        self.assertEqual(step["status"], "ok")
        self.assertFalse(step["details"]["secret_recovered"])
        self.assertTrue(decrypted.startswith(b"AETH"))
        self.assertIn(plaintext, decrypted)


if __name__ == "__main__":
    unittest.main()
