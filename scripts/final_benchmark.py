#!/usr/bin/env python3
"""Shared constants and deterministic helpers for the ICO final benchmark.

The benchmark deliberately keeps expected values outside the input tree.  This
module is used by the generator and scorer; the task solver consumes the
evidence files and never imports the expected manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


FAMILIES = ("web", "pwn", "forensics", "reverse", "crypto")
STORIES = tuple(f"story_{index:02d}" for index in range(1, 11))
PROFILES = ("default", "hardest")

# (difficulty, stable mechanism key, human description)
MATRIX: dict[str, tuple[tuple[str, str, str], ...]] = {
    "web": (
        ("easy", "chunked_http", "chunked HTTP response reassembly"),
        ("medium", "har_nested_b64", "HAR nested base64 JSON"),
        ("hard", "jwt_payload", "JWT header/payload contradiction"),
        ("medium", "graphql_escaped", "GraphQL alias and escaped JSON"),
        ("hard", "websocket_masked", "masked WebSocket frame transcript"),
        ("easy", "multipart_qp", "multipart quoted-printable body"),
        ("medium", "chunk_extensions", "chunk extensions and encoded body"),
        ("hard", "http2_headers", "HTTP/2 pseudo-header transcript"),
        ("medium", "graphql_persisted", "persisted-query batch response"),
        ("hard", "http_batch", "batched HTTP response normalization"),
    ),
    "pwn": (
        ("medium", "ret2win_static", "ret2win symbol and offset inventory"),
        ("hard", "format_got", "format-string write plan with GOT target"),
        ("easy", "hardening_static", "static canary/PIE/RELRO triage"),
        ("medium", "integer_trunc", "integer truncation and signed comparison"),
        ("hard", "ret2csu_plan", "ret2csu register plan"),
        ("medium", "got_plt", "GOT/PLT relocation map"),
        ("easy", "stack_win", "stack layout and win candidate"),
        ("medium", "rop_constraints", "constrained ROP gadget inventory"),
        ("hard", "format_positional", "format-string positional map"),
        ("hard", "seccomp_read", "seccomp/read syscall constraint report"),
    ),
    "forensics": (
        ("hard", "dns_base32", "DNS PCAP with split base32 label"),
        ("medium", "sqlite_wal", "SQLite WAL fragments and row ordering"),
        ("easy", "png_itxt", "PNG ancillary chunk and palette recovery"),
        ("hard", "wav_spectro", "WAV spectrogram sidecar and metadata"),
        ("medium", "pdf_incremental", "PDF object stream and incremental update"),
        ("hard", "bmp_bitplane", "BMP bit-plane and palette alpha"),
        ("medium", "gif_comment", "GIF comments and frame order"),
        ("easy", "tar_pax", "TAR/PAX metadata and deleted-name carving"),
        ("hard", "pcap_gzip", "TCP stream reconstruction with gzip"),
        ("medium", "sqlite_trigger", "SQLite trigger history and hex fragments"),
    ),
    "reverse": (
        ("medium", "elf_xor_table", "XORed lookup table in ELF data"),
        ("hard", "bytecode_vm", "bounded bytecode VM trace"),
        ("medium", "utf16_rot", "rotated UTF-16 string table"),
        ("easy", "pe_checksum", "PE string and checksum transform"),
        ("hard", "opaque_control", "control-flow puzzle with opaque predicates"),
        ("medium", "macho_load", "Mach-O load-command string recovery"),
        ("hard", "vm_rotmix", "custom VM with rotate/add/xor opcodes"),
        ("easy", "arm64_constants", "ARM64 constant-folded checker"),
        ("medium", "dotnet_metadata", ".NET metadata/string decoding"),
        ("hard", "branch_tables", "multi-stage table/rotation/branch checker"),
    ),
    "crypto": (
        ("easy", "caesar_noise", "Caesar shift with alphabet-preserving noise"),
        ("medium", "repeating_xor", "repeating-key XOR with known crib"),
        ("hard", "rsa_cube", "RSA low exponent exact integer cube root"),
        ("medium", "affine_permutation", "affine cipher with permutation"),
        ("easy", "vigenere", "Vigenere with supplied partial key"),
        ("hard", "ecb_blocks", "AES-ECB cut-and-paste evidence transcript"),
        ("medium", "nonce_reuse", "nonce-reuse stream XOR pair"),
        ("hard", "rsa_common_modulus", "RSA common-modulus recovery"),
        ("easy", "rail_b64", "rail-fence plus URL-safe base64"),
        ("medium", "cbc_iv", "AES-CBC IV reuse with known prefix"),
    ),
}

# The hardest profile is intentionally a separate corpus.  Every record is a
# hard task and uses a family-specific artifact wrapper around the same
# multi-stage evidence chain.  Keeping it separate preserves the original
# regression corpus while giving the solver a demanding, reproducible target.
HARDEST_MATRIX: dict[str, tuple[tuple[str, str, str], ...]] = {
    "web": (
        ("hard", "hard_hpack_chain", "HPACK-like header table with keyed fragment reconstruction"),
        ("hard", "hard_jwt_jwe_split", "split token, compression, and nonce-derived integrity"),
        ("hard", "hard_graphql_apq", "persisted-query decoys with chained response transforms"),
        ("hard", "hard_ws_deflate", "masked compressed WebSocket records"),
        ("hard", "hard_multipart_polyglot", "nested multipart and polyglot body records"),
        ("hard", "hard_chunk_trailer", "chunk extensions, trailers, and reordered streams"),
        ("hard", "hard_redirect_cache", "redirect/cache transcript with split digest"),
        ("hard", "hard_service_worker", "service-worker cache entries with decoys"),
        ("hard", "hard_http3_qpack", "QPACK-like indexed response blocks"),
        ("hard", "hard_web_upload", "upload journal with independent integrity ledger"),
    ),
    "pwn": (
        ("hard", "hard_fmt_hhn", "format-string byte-write schedule and static evidence"),
        ("hard", "hard_ret2dlresolve", "ret2dlresolve relocation plan with keyed sections"),
        ("hard", "hard_heap_tcache", "tcache graph traversal and carved chunks"),
        ("hard", "hard_srop_frame", "sigreturn frame reconstruction from register traces"),
        ("hard", "hard_rop_constraints", "constraint-satisfying gadget chain inventory"),
        ("hard", "hard_got_partial", "partial GOT overwrite and endian reconstruction"),
        ("hard", "hard_canary_leak", "canary leak transcript with derived key"),
        ("hard", "hard_uaf_vtable", "UAF vtable delta and object carving"),
        ("hard", "hard_seccomp_oracle", "seccomp syscall trace with split payload"),
        ("hard", "hard_kernel_heap", "kernel heap metadata and static payload plan"),
    ),
    "forensics": (
        ("hard", "hard_dns_crypt", "out-of-order DNS labels with chained decoding"),
        ("hard", "hard_sqlite_wal", "WAL carving with journal order and integrity ledger"),
        ("hard", "hard_png_apng", "ancillary PNG chunks with compressed payload"),
        ("hard", "hard_wav_lsb", "interleaved PCM bit-plane evidence and decoys"),
        ("hard", "hard_pdf_objstm", "PDF object-stream reconstruction"),
        ("hard", "hard_memory_segments", "memory segment carving and pointer ordering"),
        ("hard", "hard_gif_extensions", "GIF application-extension stream"),
        ("hard", "hard_tar_journal", "tar journal with deleted records and timestamps"),
        ("hard", "hard_pcap_tcp", "TCP sequence reassembly with compressed blocks"),
        ("hard", "hard_fs_journal", "filesystem journal snapshots and hash-chain clues"),
    ),
    "reverse": (
        ("hard", "hard_vm_selfmod", "self-modifying bytecode and inverse state recovery"),
        ("hard", "hard_opaque_cfg", "opaque predicates and block permutation"),
        ("hard", "hard_elf_reloc", "relocation table with keyed data section"),
        ("hard", "hard_arm64_thumb", "mixed instruction literal extraction"),
        ("hard", "hard_dotnet_il", ".NET stack-machine trace"),
        ("hard", "hard_wasm_stack", "WASM-like stack bytecode"),
        ("hard", "hard_macho_fixups", "Mach-O chained-fixup table"),
        ("hard", "hard_vm_schedule", "stateful bytecode key schedule"),
        ("hard", "hard_llvm_phi", "basic-block and phi-node ordering"),
        ("hard", "hard_hash_gate", "self-hash gate with static inverse"),
    ),
    "crypto": (
        ("hard", "hard_rsa_crt_fault", "CRT fault transcript and exact recovery"),
        ("hard", "hard_ecdsa_reuse", "nonce-reuse signature transcript"),
        ("hard", "hard_lfsr_state", "known-plaintext LFSR state recovery"),
        ("hard", "hard_chacha_stream", "known-plaintext stream construction"),
        ("hard", "hard_cbc_oracle", "padding-oracle transcript reconstruction"),
        ("hard", "hard_rsa_wiener", "continued-fraction private exponent recovery"),
        ("hard", "hard_shamir_share", "threshold-share interpolation"),
        ("hard", "hard_dh_subgroup", "small-subgroup transcript"),
        ("hard", "hard_hash_length", "length-extension evidence transcript"),
        ("hard", "hard_merkle_proof", "Merkle proof and leaf reconstruction"),
    ),
}


@dataclass(frozen=True)
class ManifestRecord:
    task_id: str
    story: str
    family: str
    difficulty: str
    mechanism: str
    description: str
    answer_sha256: str
    checker: str = "sha256"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ManifestRecord":
        return cls(
            task_id=str(value["task_id"]),
            story=str(value["story"]),
            family=str(value["family"]),
            difficulty=str(value["difficulty"]),
            mechanism=str(value["mechanism"]),
            description=str(value.get("description", "")),
            answer_sha256=str(value["answer_sha256"]),
            checker=str(value.get("checker", "sha256")),
        )


@dataclass(frozen=True)
class BenchmarkManifest:
    schema_version: int
    round_id: int
    seed: str
    records: tuple[ManifestRecord, ...]
    profile: str = "default"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "round_id": self.round_id,
            "seed": self.seed,
            "profile": self.profile,
            "records": [record.to_dict() for record in self.records],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "BenchmarkManifest":
        records = tuple(ManifestRecord.from_dict(item) for item in value.get("records", []))
        return cls(
            int(value["schema_version"]),
            int(value["round_id"]),
            str(value["seed"]),
            records,
            str(value.get("profile", "default")),
        )


def seed_for(round_id: int) -> str:
    return hashlib.sha256(f"ico-final-50-round:{round_id}:2026".encode()).hexdigest()[:24]


def task_flag(round_id: int, story: str, family: str, difficulty: str, *, profile: str = "default") -> str:
    profile_prefix = "" if profile == "default" else f"{profile}:"
    token = hashlib.sha256(f"{profile_prefix}{seed_for(round_id)}:{story}:{family}:{difficulty}".encode()).hexdigest()[:20]
    return f"ico{{final_r{round_id:02d}_{story[-2:]}_{family[:3]}_{token}}}"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def records_for_round(round_id: int, *, profile: str = "default") -> tuple[ManifestRecord, ...]:
    if profile not in PROFILES:
        raise ValueError(f"unsupported benchmark profile: {profile}")
    matrix = HARDEST_MATRIX if profile == "hardest" else MATRIX
    records: list[ManifestRecord] = []
    for story_index, story in enumerate(STORIES):
        for family in FAMILIES:
            difficulty, mechanism, description = matrix[family][story_index]
            value = task_flag(round_id, story, family, difficulty, profile=profile)
            records.append(
                ManifestRecord(
                    task_id=f"{story}/{family}_{difficulty}",
                    story=story,
                    family=family,
                    difficulty=difficulty,
                    mechanism=mechanism,
                    description=description,
                    answer_sha256=sha256_text(value),
                )
            )
    return tuple(records)


def write_manifest(path: Path, manifest: BenchmarkManifest) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(manifest.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def load_manifest(path: Path) -> BenchmarkManifest:
    return BenchmarkManifest.from_dict(json.loads(path.read_text(encoding="utf-8")))


def default_root(root: Path, round_id: int, *, profile: str = "default") -> Path:
    if profile == "hardest":
        return root / "benchmarks" / f"ico_final_50_hardest_round_{round_id:02d}"
    if round_id == 1:
        return root / "benchmarks" / "ico_final_50"
    return root / "benchmarks" / f"ico_final_50_round_{round_id:02d}"


def default_manifest(root: Path, round_id: int, *, profile: str = "default") -> Path:
    if profile == "hardest":
        return root / "benchmarks" / f"ico_final_50_hardest_round_{round_id:02d}.expected.json"
    if round_id == 1:
        return root / "benchmarks" / "ico_final_50.expected.json"
    return root / "benchmarks" / f"ico_final_50_round_{round_id:02d}.expected.json"


def ensure_within(root: Path, paths: Iterable[Path]) -> None:
    resolved_root = root.resolve()
    for path in paths:
        path.resolve().relative_to(resolved_root)
