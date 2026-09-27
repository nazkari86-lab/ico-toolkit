#!/usr/bin/env python3
"""Bounded adapters for the local ICO/CTF toolchain.

The inventory is deliberately separate from the scanner's historical profile
list.  It lets ``ico-solve`` expose a larger toolchain while keeping active
network clients and password crackers behind an explicit local-only boundary.
All default profiles consume a local file and run without a shell.
"""

from __future__ import annotations

import base64
import binascii
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
import gzip
import hashlib
import importlib.util
import io
import json
import os
import shutil
import threading
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable, Sequence

from ico_scan_core import Classification, CommandResult, CommandRunner, FlagMatcher, encoded_views
from ico_platform_tools import platform_tool_inventory, platform_tool_status
from ico_evidence import structured_flag_hits


@dataclass(frozen=True)
class ToolSpec:
    name: str
    executables: tuple[str, ...] = ()
    python_modules: tuple[str, ...] = ()
    description: str = ""
    offline_default: bool = True
    category: str = "utility"
    local_only: bool = True


@dataclass(frozen=True)
class AdapterProfile:
    name: str
    executable: str
    build_args: Callable[[Path, Path], list[str]]
    timeout: float = 30.0
    stage: str = "specialized"
    offline: bool = True
    predicate: Callable[[Path], bool] | None = None
    # When set, the command writes a bounded derived tree here (for example
    # JADX Java or Apktool smali).  The runner scans text files in that tree
    # for flag-shaped evidence after the command exits.
    collect_dir: Callable[[Path, Path], Path] | None = None

    def args_for(self, path: Path, output_dir: Path) -> list[str]:
        return self.build_args(path, output_dir)


@dataclass(frozen=True)
class AdapterEvidence:
    tool: str
    path: str
    status: str
    output: str = ""
    candidates: tuple[dict[str, object], ...] = ()
    log_path: str | None = None
    stage: str = "specialized"
    cache_hit: bool = False
    duration_seconds: float = 0.0
    metadata: dict[str, object] = field(default_factory=dict)


def _spec(
    name: str,
    *executables: str,
    description: str,
    python_modules: tuple[str, ...] = (),
    offline_default: bool = True,
    category: str = "utility",
    local_only: bool = True,
) -> ToolSpec:
    return ToolSpec(
        name=name,
        executables=tuple(executables),
        python_modules=tuple(python_modules),
        description=description,
        offline_default=offline_default,
        category=category,
        local_only=local_only,
    )


# The names are intentionally stable: reports and final-run diagnostics use
# them as adapter identifiers.  Aliases in ``executables`` count as one tool.
TOOL_SPECS: tuple[ToolSpec, ...] = (
    _spec("binwalk", "binwalk", description="embedded signatures and container layers", category="forensics"),
    _spec("pngcheck", "pngcheck", description="PNG chunks and structural checks", category="forensics"),
    _spec("qpdf", "qpdf", description="PDF structure and repair checks", category="forensics"),
    _spec("7zz", "7zz", description="bounded archive listing and extraction", category="forensics"),
    _spec("zsteg", "zsteg", description="PNG/BMP bit-plane steganography", category="forensics"),
    _spec("stegseek", "stegseek", description="deterministic JPEG seed extraction only", category="forensics"),
    _spec("steghide", "steghide", description="embedded-data metadata inspection", category="forensics"),
    _spec("exiftool", "exiftool", description="metadata and embedded stream inspection", category="forensics"),
    _spec("foremost", "foremost", description="file carving to a bounded temporary directory", category="forensics"),
    _spec("ffuf", "ffuf", description="local web fuzzing when an explicit replica is supplied", offline_default=False, category="web", local_only=False),
    _spec("feroxbuster", "feroxbuster", description="local web content discovery when explicitly allowed", offline_default=False, category="web", local_only=False),
    _spec("gobuster", "gobuster", description="local web enumeration when explicitly allowed", offline_default=False, category="web", local_only=False),
    _spec("hashcat", "hashcat", description="bounded task-provided hash verification", offline_default=False, category="crypto"),
    _spec("hydra", "hydra", description="credential testing against a declared local service", offline_default=False, category="web", local_only=False),
    _spec("john", "john", description="task-provided wordlist verification", offline_default=False, category="crypto"),
    _spec("nmap", "nmap", description="local replica service inventory only", offline_default=False, category="web", local_only=False),
    _spec("radare2", "r2", "radare2", description="static reverse engineering and strings", category="reverse"),
    _spec("sqlmap", "sqlmap", description="saved/local SQLi recipe validation", offline_default=False, category="web", local_only=False),
    _spec("yara", "yara", description="local rule-based malware/CTF triage", category="forensics"),
    _spec("tshark", "tshark", description="PCAP summaries and stream fields", category="forensics"),
    _spec("volatility", "vol", "volatility", description="offline memory-dump profiles", category="forensics"),
    _spec("gdb", "gdb", description="non-executing batch binary inventory", category="pwn"),
    _spec("jq", "jq", description="JSON/HAR field normalization", category="web"),
    _spec("ffmpeg", "ffmpeg", description="media decoding and spectrogram preparation", category="forensics"),
    _spec("RsaCtfTool", "RsaCtfTool", "rsactftool", description="bounded RSA key/recovery checks", category="crypto"),
    _spec("tesseract", "tesseract", description="OCR for supplied images/audio renderings", category="forensics"),
    _spec("z3", "z3", description="constraint solving helper when exposed as a CLI", category="crypto"),
    _spec("pwntools", "pwn", description="local PWN payload construction library/CLI", category="pwn"),
    _spec("strings", "strings", description="portable printable and wide-string triage", category="reverse"),
    _spec("ffprobe", "ffprobe", description="media stream/container inventory", category="forensics"),
    _spec("pdftotext", "pdftotext", description="bounded PDF text extraction", category="forensics"),
    _spec("mitmproxy", "mitmproxy", description="saved/local HTTP transcript inspection", offline_default=False, category="web", local_only=False),
    _spec("ghidra", "ghidraRun", description="optional GUI/static reverse workbench", category="reverse"),
    _spec("cutter", "cutter", description="optional GUI/static reverse workbench", category="reverse"),
    _spec("cyberchef", description="local CyberChef recipe asset and bounded recipe adapter", category="transform"),
    # Static reverse/PWN inventory.  These are deliberately read-only profiles
    # in ico-solve; no challenge binary is executed.
    _spec("checksec", "checksec", description="ELF hardening profile (RELRO, canary, PIE, NX)", category="pwn"),
    _spec("ROPgadget", "ROPgadget", description="cross-architecture gadget inventory", category="pwn"),
    _spec("ropper", "ropper", description="gadget, symbol, and stack-pivot inventory", category="pwn"),
    _spec("objdump", "objdump", description="portable section, symbol, and disassembly dump", category="reverse"),
    _spec("nm", "nm", description="static symbol table inventory", category="reverse"),
    _spec("otool", "otool", description="Mach-O headers, loads, and linked libraries", category="reverse"),
    _spec("lldb", "lldb", description="non-running debugger module inspection", category="reverse"),
    _spec("upx", "upx", description="UPX packing detection and listing", category="reverse"),
    _spec("angr", "angr", description="symbolic execution and decompilation CLI", python_modules=("angr",), category="reverse"),
    _spec("unicorn", python_modules=("unicorn",), description="multi-architecture CPU emulation library", category="reverse"),
    # Qiling is installed in an isolated runtime.  Its capability probe is
    # cached and the command remains manual-only because emulation executes
    # supplied code; inventory presence is not an automatic run permission.
    _spec("qiling", python_modules=("qiling",), description="instrumentable cross-platform binary emulation (extra runtime)", offline_default=False, category="reverse"),
    _spec("lief", "lief", python_modules=("lief",), description="PE/ELF/Mach-O parser and instrumentation library", category="reverse"),
    _spec("fls", "fls", description="offline file-system listing from disk images", category="forensics"),
    _spec("mmls", "mmls", description="offline partition-table and volume-layout inspection", category="forensics"),
    _spec("icat", "icat", description="offline extraction of a file by inode from a disk image", category="forensics"),
    _spec("tsk_recover", "tsk_recover", description="offline recovery of allocated/deleted files from an image", category="forensics"),
    # Office, media, and mobile triage.
    _spec("olevba", "olevba", description="extract and deobfuscate VBA macros", category="forensics"),
    _spec("oleid", "oleid", description="OLE document feature and risk triage", category="forensics"),
    _spec("mraptor", "mraptor", description="static VBA macro execution-risk scan", category="forensics"),
    _spec("giftext", "giftext", description="GIF extensions, comments, and frame metadata", category="forensics"),
    _spec("sox", "sox", description="audio metadata and lossless signal statistics", category="forensics"),
    _spec("apktool", "apktool", description="offline APK manifest and smali decoding", category="reverse"),
    _spec("jadx", "jadx", description="offline DEX/APK Java decompilation", category="reverse"),
    _spec("androguard", "androguard", python_modules=("androguard",), description="offline Android manifest, DEX and call-graph analysis", category="reverse"),
    _spec("frida", "frida", description="instrument an explicitly attached local app session", offline_default=False, category="reverse"),
    _spec("objection", "objection", description="interactive local mobile runtime exploration", offline_default=False, category="reverse"),
    # Local source and secret triage.  No online rule/config update is used.
    _spec("semgrep", "semgrep", description="local source-pattern and secret triage with bundled rules", category="forensics"),
    _spec("trufflehog", "trufflehog", description="local high-entropy and credential discovery", category="forensics"),
    _spec("gitleaks", "gitleaks", description="local repository secret detection", category="forensics"),
    _spec("factordb", "factordb", description="FactorDB client; disabled by default because it is network-backed", offline_default=False, category="crypto", local_only=False),
    # Strong optional specialists found in the research pass.  Their presence
    # is shown in --tools when installed, but they are not assumed available.
    _spec("xortool", "xortool", description="crib-guided repeating-key XOR analysis", category="crypto"),
    _spec("hashid", "hashid", description="hash-family identification", category="crypto"),
    _spec("hashpump", "hashpump", description="hash length-extension payload builder", category="crypto"),
    _spec("hashpumpy", "hashpumpy", python_modules=("hashpumpy",), description="Python hash length-extension library", category="crypto"),
    _spec("Ciphey", "ciphey", python_modules=("ciphey",), description="automatic bounded encoding/classical-cipher decoder", category="crypto"),
    _spec("pdfid", "pdfid", description="PDF keyword and object triage", category="forensics"),
    _spec("pdf-parser", "pdf-parser", "pdf-parser.py", description="PDF object and stream inspection", category="forensics"),
    _spec("peepdf", "peepdf", description="PDF JavaScript and object analysis", category="forensics"),
    _spec("bulk_extractor", "bulk_extractor", description="bulk feature extraction from disk images", category="forensics"),
    _spec("scalpel", "scalpel", description="configurable file carving", category="forensics"),
    _spec("stegoveritas", "stegoveritas", description="multi-method image steganography triage", category="forensics"),
    _spec("one_gadget", "one_gadget", description="static libc one-gadget locator", category="pwn"),
    _spec("seccomp-tools", "seccomp-tools", description="static seccomp policy inspection", category="pwn"),
    _spec("strace", "strace", description="syscall trace for an explicitly authorized local replica", offline_default=False, category="pwn"),
    _spec("ltrace", "ltrace", description="library-call trace for an explicitly authorized local replica", offline_default=False, category="pwn"),
    # Web/API specialists are inventory-only and never auto-run against a host.
    _spec("jwt_tool", "jwt_tool", "jwt_tool.py", description="saved JWT/HAR analysis", offline_default=False, category="web", local_only=True),
    _spec("arjun", "arjun", description="local-replica HTTP parameter discovery", offline_default=False, category="web", local_only=False),
    _spec("kiterunner", "kr", description="OpenAPI wordlist discovery on a local replica", offline_default=False, category="web", local_only=False),
    _spec("graphql-cop", "graphql-cop", description="saved GraphQL transcript audit", offline_default=False, category="web", local_only=True),
    _spec("graphw00f", "graphw00f", description="GraphQL fingerprinting on a local replica", offline_default=False, category="web", local_only=False),
    _spec("clairvoyance", "clairvoyance", description="GraphQL schema inference on a local replica", offline_default=False, category="web", local_only=False),
    _spec("nuclei", "nuclei", description="local-replica template checks only", offline_default=False, category="web", local_only=False),
)


def _toolkit_root(root: Path | None = None) -> Path:
    if root is not None:
        return root.expanduser().resolve()
    configured = os.environ.get("ICO_TOOLKIT_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parent


def cyberchef_asset(root: Path | None = None) -> Path | None:
    """Return the local CyberChef HTML asset, never a remote URL."""

    base = _toolkit_root(root)
    candidates = (
        base / "CyberChef" / "app" / "CyberChef_v11.5.0.html",
        base / "CyberChef" / "CyberChef_v11.5.0.html",
    )
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    return None


def _available(spec: ToolSpec, root: Path | None = None) -> bool:
    if spec.name in {"qiling", "scalpel", "strace", "ltrace"}:
        return bool(platform_tool_status(spec.name, root)["available"])
    if spec.name == "cyberchef":
        return cyberchef_asset(root) is not None
    if any(shutil.which(executable) for executable in spec.executables):
        return True
    for module in spec.python_modules:
        try:
            if importlib.util.find_spec(module) is not None:
                return True
        except (ImportError, ModuleNotFoundError, ValueError):
            continue
    return False


def available_tool_specs(root: Path | None = None) -> tuple[ToolSpec, ...]:
    """Return the deterministic subset present on this machine."""

    return tuple(spec for spec in TOOL_SPECS if _available(spec, root))


def tool_inventory(root: Path | None = None) -> list[dict[str, object]]:
    """Serialize the full inventory without invoking any tool."""

    available = {spec.name for spec in available_tool_specs(root)}
    platform_statuses = platform_tool_inventory(root)
    return [
        {
            "name": spec.name,
            "available": spec.name in available,
            "executables": list(spec.executables),
            "python_modules": list(spec.python_modules),
            "offline_default": spec.offline_default,
            "local_only": spec.local_only,
            "category": spec.category,
            "description": spec.description,
            "backend": platform_statuses.get(spec.name, {}).get("backend", "native-or-python"),
            "state": platform_statuses.get(spec.name, {}).get(
                "state", "available" if spec.name in available else "missing"
            ),
            "exact": platform_statuses.get(spec.name, {}).get("exact", True),
            "availability_reason": platform_statuses.get(spec.name, {}).get(
                "reason", "present" if spec.name in available else "not found on PATH"
            ),
        }
        for spec in TOOL_SPECS
    ]


def _arg(executable: str, *prefix: str) -> Callable[[Path, Path], list[str]]:
    return lambda path, _out: [executable, *prefix, str(path)]


def _profile(
    name: str,
    executable: str,
    args: Callable[[Path, Path], list[str]],
    *,
    timeout: float = 30.0,
    stage: str = "specialized",
    collect_dir: Callable[[Path, Path], Path] | None = None,
    predicate: Callable[[Path], bool] | None = None,
) -> AdapterProfile:
    return AdapterProfile(
        name,
        executable,
        args,
        timeout=timeout,
        stage=stage,
        offline=True,
        collect_dir=collect_dir,
        predicate=predicate,
    )


def _derived_dir(label: str, path: Path, output_dir: Path) -> Path:
    """Return a deterministic, per-input output directory for decompilers."""

    try:
        # Content-addressing lets identical members extracted under different
        # archive paths share one derived tree and one cache entry.
        digest = _file_sha256(path)[:12]
    except (NameError, OSError):
        digest = hashlib.sha256(str(path).encode("utf-8")).hexdigest()[:12]
    return output_dir / f"{label}-{digest}"


def _collect_text_files(root: Path, *, max_files: int = 256, max_bytes: int = 8 * 1024 * 1024) -> list[Path]:
    """Collect small regular text-ish files without following symlinks."""

    if not root.is_dir() or root.is_symlink():
        return []
    collected: list[Path] = []
    total = 0
    for candidate in sorted(root.rglob("*"), key=str):
        if len(collected) >= max_files or not candidate.is_file() or candidate.is_symlink():
            continue
        try:
            size = candidate.stat().st_size
        except OSError:
            continue
        if size > 2 * 1024 * 1024 or total + size > max_bytes:
            continue
        suffix = candidate.suffix.lower()
        if suffix not in {".java", ".kt", ".smali", ".xml", ".json", ".txt", ".js", ".py", ".vba", ".bas", ".cls", ".properties", ".yml", ".yaml"}:
            continue
        collected.append(candidate)
        total += size
    return collected


def _bounded_text(path: Path, limit: int = 2 * 1024 * 1024) -> str:
    try:
        return path.read_bytes()[:limit].decode("utf-8", errors="replace")
    except OSError:
        return ""


def _looks_like_hash_input(path: Path) -> bool:
    text = _bounded_text(path, 512 * 1024)
    if not text:
        return False
    import re

    return any(re.search(rf"(?m)^[0-9a-fA-F]{{{length}}}$", line.strip()) for line in text.splitlines() for length in (32, 40, 56, 64, 96, 128))


def _looks_like_ciphertext(path: Path) -> bool:
    text = _bounded_text(path, 128 * 1024).casefold()
    name = path.name.casefold()
    return any(token in f"{name}\n{text}" for token in ("xor", "cipher", "encrypted", "crypt", "decode", "encoded"))


def _looks_like_ciphey_text(path: Path) -> bool:
    text = _bounded_text(path, 2 * 1024 * 1024)
    if len(text.strip()) < 8:
        return False
    import re

    return bool(re.search(r"(?:[A-Za-z0-9+/]{16,}={0,2}|[0-9a-fA-F]{16,}|[A-Z2-7]{16,}=*)", text))


def _looks_like_rsa_material(path: Path) -> bool:
    text = _bounded_text(path, 256 * 1024).casefold()
    name = path.name.casefold()
    return path.suffix.casefold() in {".pem", ".pub", ".der", ".key"} or "begin rsa" in text or "modulus" in text or "public exponent" in text or "rsa" in name


def _looks_like_libc(path: Path) -> bool:
    name = path.name.casefold()
    return path.suffix.casefold() in {".so", ".dylib"} and "libc" in name


def _looks_like_seccomp_dump(path: Path) -> bool:
    text = _bounded_text(path, 256 * 1024).casefold()
    return "seccomp" in path.name.casefold() or "seccomp" in text or "bpf" in text and "allow" in text


def profiles_for_classification(classification: Classification) -> tuple[AdapterProfile, ...]:
    """Select only file-consuming, offline-safe adapters for a file kind."""

    kind = classification.kind.lower()
    extension = classification.extension.lower()
    profiles: list[AdapterProfile] = [
        _profile("strings-ascii", "strings", lambda path, _out: ["strings", "-a", "-n", "4", str(path)], timeout=20.0, stage="fast"),
        _profile("binwalk-signatures", "binwalk", _arg("binwalk"), timeout=45.0, stage="deep"),
        _profile("yara-flag-pattern", "yara", lambda path, out: ["yara", str(out / "flag-shape.yar"), str(path)], timeout=20.0, stage="fast"),
    ]
    if kind in {"data", "binary", "archive", "image", "png", "jpeg", "bmp", "audio", "wav", "video", "media", "pdf"}:
        profiles.append(
            _profile(
                "foremost-carve",
                "foremost",
                lambda path, out: ["foremost", "-Q", "-T", "-i", str(path), "-o", str(_derived_dir("foremost", path, out))],
                timeout=60.0,
                stage="deep",
            )
        )
        profiles.append(
            _profile(
                "scalpel-carve",
                "scalpel",
                lambda path, out: [
                    "scalpel",
                    "-o",
                    str(_derived_dir("scalpel", path, out)),
                    str(path),
                ],
                timeout=90.0,
                stage="deep",
                collect_dir=lambda path, out: _derived_dir("scalpel", path, out),
            )
        )
    if kind in {"png", "bmp"}:
        profiles.extend(
            [
                _profile("zsteg", "zsteg", lambda path, _out: ["zsteg", "-a", str(path)], timeout=60.0, stage="deep"),
                _profile("pngcheck", "pngcheck", lambda path, _out: ["pngcheck", "-vt", str(path)], timeout=20.0),
                _profile(
                    "stegoveritas",
                    "stegoveritas",
                    lambda path, out: [
                        "stegoveritas",
                        "-out",
                        str(_derived_dir("stegoveritas", path, out)),
                        "-meta",
                        "-imageTransform",
                        "-extractLSB",
                        "-trailing",
                        "-exif",
                        "-xmp",
                        "-carve",
                        str(path),
                    ],
                    timeout=120.0,
                    stage="deep",
                    collect_dir=lambda path, out: _derived_dir("stegoveritas", path, out),
                ),
            ]
        )
    if kind in {"png", "bmp", "jpeg", "image", "audio", "wav", "video", "media", "pdf", "archive"}:
        profiles.append(_profile("metadata", "exiftool", _arg("exiftool"), timeout=20.0, stage="fast"))
    if kind in {"jpeg", "wav", "audio", "image"} or extension in {".aif", ".aiff", ".au"}:
        profiles.append(
            _profile(
                "steghide-info",
                "steghide",
                lambda path, _out: ["steghide", "info", "-p", "", str(path)],
                timeout=20.0,
            )
        )
    if kind == "archive" or extension in {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz", ".jar", ".apk"}:
        profiles.append(_profile("archive-list", "7zz", lambda path, _out: ["7zz", "l", "-slt", str(path)], timeout=30.0))
    if kind == "pdf":
        profiles.extend(
            [
                _profile("qpdf-check", "qpdf", _arg("qpdf", "--check"), timeout=20.0),
                _profile("pdf-text", "pdftotext", lambda path, _out: ["pdftotext", "-layout", str(path), "-"], timeout=30.0),
                _profile("pdfid", "pdfid", _arg("pdfid"), timeout=30.0, stage="fast"),
                _profile("pdf-parser", "pdf-parser", _arg("pdf-parser"), timeout=45.0, stage="deep"),
                _profile(
                    "peepdf-static",
                    "peepdf",
                    lambda path, _out: ["peepdf", "-g", "-m", "-j", str(path)],
                    timeout=60.0,
                    stage="deep",
                ),
            ]
        )
    if kind == "pcap" or extension in {".pcap", ".pcapng", ".cap"}:
        profiles.append(
            _profile(
                "tshark-summary",
                "tshark",
                lambda path, _out: ["tshark", "-r", str(path), "-q", "-z", "io,phs"],
                timeout=45.0,
                stage="deep",
            )
        )
    if kind == "memory" or extension in {".dmp", ".vmem", ".memdump", ".lime"}:
        profiles.extend(
            [
                _profile("volatility-windows-info", "vol", lambda path, _out: ["vol", "--offline", "-q", "-f", str(path), "windows.info"], timeout=60.0, stage="deep"),
                _profile("volatility-linux-banners", "vol", lambda path, _out: ["vol", "--offline", "-q", "-f", str(path), "linux.banners"], timeout=60.0, stage="deep"),
            ]
        )
    if kind == "binary" or extension in {".elf", ".exe", ".dll", ".so", ".dylib", ".wasm"}:
        profiles.extend(
            [
                _profile("radare2-strings", "r2", lambda path, _out: ["r2", "-q", "-c", "izz~(ico|ctf|flag)", "-c", "q", str(path)], timeout=45.0, stage="deep"),
                _profile("gdb-inventory", "gdb", lambda path, _out: ["gdb", "-q", "-batch", str(path), "-ex", "info files"], timeout=30.0, stage="deep"),
                _profile("checksec", "checksec", lambda path, _out: ["checksec", "--file", str(path)], timeout=20.0, stage="fast"),
                _profile("ROPgadget", "ROPgadget", lambda path, _out: ["ROPgadget", "--binary", str(path), "--silent"], timeout=75.0, stage="deep"),
                _profile("ropper-info", "ropper", lambda path, _out: ["ropper", "--file", str(path), "--info", "--nocolor"], timeout=75.0, stage="deep"),
                _profile("objdump", "objdump", lambda path, _out: ["objdump", "-x", "-s", str(path)], timeout=45.0, stage="deep"),
                _profile("nm", "nm", lambda path, _out: ["nm", "-an", str(path)], timeout=30.0, stage="fast"),
                _profile("otool", "otool", lambda path, _out: ["otool", "-hv", "-l", "-L", str(path)], timeout=30.0, stage="fast"),
                _profile("lldb-modules", "lldb", lambda path, _out: ["lldb", "--batch", "--no-lldbinit", "-o", "target modules list", "-o", "image lookup -rn flag", "--", str(path)], timeout=45.0, stage="deep"),
                _profile("upx-list", "upx", lambda path, _out: ["upx", "-l", str(path)], timeout=30.0, stage="fast"),
                _profile("angr-disassemble", "angr", lambda path, _out: ["angr", "-n", "dis", "--catch-exceptions", str(path)], timeout=90.0, stage="deep"),
            ]
        )
    if extension in {".img", ".dd", ".raw", ".dmg", ".e01", ".ewf", ".aff", ".qcow", ".vhd", ".vmdk"} or kind == "disk":
        profiles.extend(
            [
                _profile("fls-recursive", "fls", lambda path, _out: ["fls", "-r", "-p", str(path)], timeout=75.0, stage="deep"),
                _profile("mmls", "mmls", _arg("mmls"), timeout=45.0, stage="fast"),
                _profile(
                    "tsk-recover",
                    "tsk_recover",
                    lambda path, out: ["tsk_recover", "-a", str(path), str(_derived_dir("tsk-recover", path, out))],
                    timeout=120.0,
                    stage="deep",
                    collect_dir=lambda path, out: _derived_dir("tsk-recover", path, out),
                ),
                _profile(
                    "bulk-extractor",
                    "bulk_extractor",
                    lambda path, out: [
                        "bulk_extractor",
                        "-q",
                        "-o",
                        str(_derived_dir("bulk-extractor", path, out)),
                        "-R",
                        str(path),
                    ],
                    timeout=120.0,
                    stage="deep",
                    collect_dir=lambda path, out: _derived_dir("bulk-extractor", path, out),
                ),
            ]
        )
    if extension in {".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlt", ".ppt", ".pptm", ".pot", ".msg", ".rtf", ".ole"}:
        profiles.extend(
            [
                _profile("oleid", "oleid", _arg("oleid"), timeout=30.0, stage="fast"),
                _profile("olevba", "olevba", lambda path, _out: ["olevba", "--decode", "--reveal", str(path)], timeout=60.0, stage="deep"),
                _profile("mraptor", "mraptor", _arg("mraptor"), timeout=45.0, stage="deep"),
            ]
        )
    if extension == ".gif":
        profiles.append(_profile("giftext", "giftext", _arg("giftext"), timeout=30.0, stage="fast"))
    if kind in {"audio", "wav", "video", "media"} or extension in {".mp3", ".mp4", ".mkv", ".avi", ".flac", ".ogg", ".aif", ".aiff"}:
        profiles.extend(
            [
                _profile("ffprobe", "ffprobe", lambda path, _out: ["ffprobe", "-v", "error", "-show_format", "-show_streams", "-of", "json", str(path)], timeout=30.0, stage="fast"),
                _profile("ffmpeg-decode-check", "ffmpeg", lambda path, _out: ["ffmpeg", "-hide_banner", "-nostdin", "-i", str(path), "-f", "null", "-"], timeout=60.0, stage="deep"),
                _profile("sox-stat", "sox", lambda path, _out: ["sox", str(path), "-n", "stat"], timeout=45.0, stage="deep"),
            ]
        )
    if extension == ".apk":
        profiles.extend(
            [
                _profile(
                    "apktool-decode",
                    "apktool",
                    lambda path, out: ["apktool", "d", "-q", "-f", "--no-res", "--no-assets", "--no-debug-info", "-o", str(_derived_dir("apktool", path, out)), str(path)],
                    timeout=120.0,
                    stage="deep",
                    collect_dir=lambda path, out: _derived_dir("apktool", path, out),
                ),
                _profile(
                    "jadx-decompile",
                    "jadx",
                    lambda path, out: ["jadx", "-q", "-r", "--show-bad-code", "--no-debug-info", "-d", str(_derived_dir("jadx", path, out)), str(path)],
                    timeout=120.0,
                    stage="deep",
                    collect_dir=lambda path, out: _derived_dir("jadx", path, out),
                ),
                _profile("androguard-apkid", "androguard", lambda path, _out: ["androguard", "apkid", str(path)], timeout=60.0, stage="fast"),
                _profile("androguard-axml", "androguard", lambda path, _out: ["androguard", "axml", str(path)], timeout=75.0, stage="deep"),
            ]
        )
    if kind == "text" or extension in {".py", ".js", ".ts", ".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".go", ".java", ".php", ".sh", ".yaml", ".yml", ".json", ".xml", ".html", ".md", ".txt"}:
        profiles.extend(
            [
                _profile(
                    "semgrep-local-rules",
                    "semgrep",
                    lambda path, out: ["semgrep", "scan", "--metrics=off", "--config", str(out / "semgrep-local.yml"), "--json", "--no-git-ignore", str(path)],
                    timeout=75.0,
                    stage="deep",
                ),
                _profile(
                    "trufflehog-local",
                    "trufflehog",
                    lambda path, _out: ["trufflehog", "filesystem", "--no-update", "--no-verification", "--results=unverified", "--json", "--no-color", "--force-skip-archives", "--force-skip-binaries", str(path)],
                    timeout=75.0,
                    stage="deep",
                ),
                _profile(
                    "gitleaks-local",
                    "gitleaks",
                    lambda path, _out: ["gitleaks", "detect", "--no-banner", "--no-color", "--no-git", "--redact=0", "--report-format", "json", "--report-path", "-", "--source", str(path)],
                    timeout=75.0,
                    stage="deep",
                ),
            ]
        )
    if kind in {"png", "jpeg", "bmp", "image"}:
        profiles.append(_profile("tesseract", "tesseract", lambda path, _out: ["tesseract", str(path), "stdout"], timeout=45.0, stage="deep"))
    if kind in {"text", "data", "binary"} or extension in {".txt", ".log", ".json", ".csv", ".bin", ".dat"}:
        profiles.extend(
            [
                _profile(
                    "hashid",
                    "hashid",
                    lambda path, _out: ["hashid", "-m", _bounded_text(path, 1024).strip().splitlines()[0]],
                    timeout=15.0,
                    stage="fast",
                    predicate=_looks_like_hash_input,
                ),
                _profile(
                    "ciphey",
                    "ciphey",
                    lambda path, _out: ["ciphey", "-f", str(path), "-q", "-g"],
                    timeout=45.0,
                    stage="specialized",
                    predicate=_looks_like_ciphey_text,
                ),
                _profile(
                    "xortool",
                    "xortool",
                    lambda path, _out: ["xortool", "-m", "32", "-p", "ico{", "-f", str(path)],
                    timeout=60.0,
                    stage="specialized",
                    predicate=_looks_like_ciphertext,
                ),
                _profile(
                    "seccomp-tools-disasm",
                    "seccomp-tools",
                    lambda path, _out: ["seccomp-tools", "disasm", str(path)],
                    timeout=30.0,
                    stage="specialized",
                    predicate=_looks_like_seccomp_dump,
                ),
            ]
        )
    if kind in {"binary", "data", "text"} or extension in {".pem", ".pub", ".der", ".key"}:
        profiles.append(
            _profile(
                "RsaCtfTool-dump",
                "rsactftool",
                lambda path, _out: ["rsactftool", "--publickey", str(path), "--dumpkey", "--timeout", "30"],
                timeout=45.0,
                stage="specialized",
                predicate=_looks_like_rsa_material,
            )
        )
    if kind == "binary" or extension in {".so", ".dylib"}:
        profiles.append(
            _profile(
                "one-gadget",
                "one_gadget",
                lambda path, _out: ["one_gadget", "--output-format", "json", str(path)],
                timeout=60.0,
                stage="deep",
                predicate=_looks_like_libc,
            )
        )
    if extension in {".json", ".har"} or "json" in classification.mime.lower() or "json" in classification.description.lower():
        profiles.append(_profile("jq", "jq", lambda path, _out: ["jq", "-c", ".", str(path)], timeout=20.0, stage="fast"))
    # Keep ordering stable and remove duplicate executable/analyzer pairs.
    seen: set[str] = set()
    unique: list[AdapterProfile] = []
    for profile in profiles:
        if profile.name in seen:
            continue
        seen.add(profile.name)
        unique.append(profile)
    return tuple(unique)


def _candidate_hits(output: str, *, tool: str, source: str) -> tuple[dict[str, object], ...]:
    if not output:
        return ()
    hits = list(FlagMatcher().scan(output, source=source, analyzer=tool))
    existing = {(str(hit.get("value", "")), str(hit.get("source", ""))) for hit in hits}
    for hit in structured_flag_hits(output, analyzer=tool, source=source):
        key = (str(hit.get("value", "")), str(hit.get("source", "")))
        if key not in existing:
            hits.append(hit)
            existing.add(key)
    return tuple(hits)


def _cyberchef_decode_chain(data: bytes, *, max_depth: int = 2, max_views: int = 96) -> list[tuple[bytes, str]]:
    """Run a bounded subset of common CyberChef recipes in-process.

    The adapter only consumes syntactically valid encodings and standard
    compression.  It does not enumerate keys, passwords, or flag values.
    """

    queue: list[tuple[bytes, int, str]] = [(data[:4 * 1024 * 1024], 0, "input")]
    seen: set[bytes] = {queue[0][0]}
    output: list[tuple[bytes, str]] = []

    def add(payload: bytes, chain: str, depth: int) -> None:
        if not payload or len(payload) > 4 * 1024 * 1024 or payload in seen or len(output) >= max_views:
            return
        seen.add(payload)
        output.append((payload, chain))
        if depth < max_depth:
            queue.append((payload, depth, chain))

    while queue and len(output) < max_views:
        current, depth, chain = queue.pop(0)
        for view in encoded_views(current, max_bytes=4 * 1024 * 1024, max_tokens=32):
            add(bytes(view["decoded"]), f"{chain}|{view['encoding']}", depth + 1)
        if depth >= max_depth:
            continue
        if current.startswith(b"\x1f\x8b"):
            try:
                add(gzip.decompress(current), f"{chain}|gunzip", depth + 1)
            except (OSError, EOFError, zlib.error):
                pass
        if current.startswith((b"x\x9c", b"x\xda", b"x\x01")):
            try:
                add(zlib.decompress(current), f"{chain}|zlib", depth + 1)
            except zlib.error:
                pass
        try:
            text = current.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text:
            rot13 = text.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")).encode()
            if rot13 != current:
                add(rot13, f"{chain}|ROT13", depth + 1)
            if text[::-1].encode() != current:
                add(text[::-1].encode(), f"{chain}|Reverse", depth + 1)
    return output


def run_cyberchef_adapter(path: Path, *, source: str | None = None) -> AdapterEvidence:
    try:
        data = path.read_bytes()[:4 * 1024 * 1024]
    except OSError as exc:
        return AdapterEvidence("cyberchef", str(path), "failed", str(exc), stage="fast")
    views = _cyberchef_decode_chain(data)
    candidates: list[dict[str, object]] = []
    for payload, chain in views:
        for candidate in _candidate_hits(payload.decode("utf-8", errors="replace"), tool="cyberchef", source=source or str(path)):
            candidate["recipe_chain"] = chain
            candidates.append(candidate)
    return AdapterEvidence("cyberchef", str(path), "ok", f"views={len(views)}", tuple(candidates), stage="fast")


def run_lief_adapter(path: Path, *, max_output_bytes: int = 1_048_576) -> AdapterEvidence:
    """Read PE/ELF/Mach-O structure through LIEF without executing it."""

    started = time.monotonic()
    try:
        import lief  # type: ignore
    except (ImportError, ModuleNotFoundError) as exc:
        return AdapterEvidence("lief", str(path), "missing", str(exc), stage="specialized")
    try:
        binary = lief.parse(str(path))
    except Exception as exc:
        return AdapterEvidence("lief", str(path), "unsupported", f"{type(exc).__name__}: {exc}", stage="specialized")
    if binary is None:
        return AdapterEvidence("lief", str(path), "unsupported", "LIEF did not recognize the file", stage="specialized")
    summary: dict[str, object] = {"format": type(binary).__name__}
    for attribute in ("name", "header", "entrypoint", "imagebase"):
        try:
            value = getattr(binary, attribute)
        except Exception:
            continue
        if isinstance(value, (str, int, float, bool)):
            summary[attribute] = value
    hits: list[dict[str, object]] = []
    sections = getattr(binary, "sections", [])
    section_count = 0
    for section in sections:
        if section_count >= 128:
            break
        section_count += 1
        try:
            name = str(getattr(section, "name", "section"))
            content = bytes(getattr(section, "content", []))[:max_output_bytes]
        except Exception:
            continue
        if content:
            hits.extend(_candidate_hits(content.decode("utf-8", errors="replace"), tool="lief", source=f"{path}#{name}"))
    summary["sections"] = section_count
    output = json.dumps(summary, ensure_ascii=False, sort_keys=True)
    return AdapterEvidence("lief", str(path), "ok", output, tuple(hits), stage="specialized", duration_seconds=time.monotonic() - started)


@lru_cache(maxsize=512)
def _file_sha256_cached(raw_path: str, size: int, mtime_ns: int) -> str:
    digest = hashlib.sha256()
    with Path(raw_path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_sha256(path: Path) -> str:
    stat = path.stat()
    return _file_sha256_cached(str(path.resolve()), stat.st_size, stat.st_mtime_ns)


def _executable_identity(executable: str) -> dict[str, object]:
    resolved = shutil.which(executable)
    if not resolved:
        return {"path": None, "size": None, "mtime_ns": None}
    try:
        path = Path(resolved).resolve()
        stat = path.stat()
        return {"path": str(path), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}
    except OSError:
        return {"path": str(resolved), "size": None, "mtime_ns": None}


def _normalise_cache_args(args: Sequence[str], path: Path, output_dir: Path) -> list[str]:
    raw = str(path)
    resolved = str(path.resolve())
    output = str(output_dir.resolve())
    normalised: list[str] = []
    for value in args:
        text = str(value)
        if text in {raw, resolved}:
            normalised.append("<input>")
        elif text == output or text.startswith(output + os.sep):
            normalised.append("<output>" + text[len(output):])
        else:
            normalised.append(text)
    return normalised


def _adapter_cache_key(
    *,
    path: Path,
    profile: AdapterProfile,
    args: Sequence[str],
    output_dir: Path,
    input_sha256: str,
    task_context: str,
) -> tuple[str, dict[str, object]]:
    # Cache entries must be invalidated when the adapter implementation or
    # its parsing contract changes.  Keep the revision explicit and
    # overridable so a release can bump it without rewriting every artifact.
    toolkit_revision = os.environ.get(
        "ICO_TOOLKIT_REVISION",
        "ico-toolkit-cache-v3",
    )
    invocation: dict[str, object] = {
        "schema_version": 3,
        "toolkit_revision": toolkit_revision,
        "input_sha256": input_sha256,
        "task_context": task_context,
        "adapter": profile.name,
        "stage": profile.stage,
        "executable": _executable_identity(profile.executable),
        "args": _normalise_cache_args(args, path, output_dir),
        "parser": "flag-matcher-v1",
    }
    payload = json.dumps(invocation, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest(), invocation


def _result_from_cache(value: dict[str, object]) -> CommandResult:
    return CommandResult(
        args=[str(item) for item in value.get("args", [])],
        returncode=value.get("returncode"),
        stdout=str(value.get("stdout", "")),
        stderr=str(value.get("stderr", "")),
        timed_out=bool(value.get("timed_out", False)),
        missing=bool(value.get("missing", False)),
        duration_seconds=float(value.get("duration_seconds", 0.0) or 0.0),
        log_path=value.get("log_path"),
    )


def _run_cached_adapter_command(
    runner: CommandRunner,
    args: Sequence[str],
    *,
    path: Path,
    profile: AdapterProfile,
    output_dir: Path,
    timeout: float,
    cache_dir: Path | None,
    input_sha256: str,
    task_context: str,
) -> tuple[CommandResult, bool, str | None]:
    """Run one adapter command and reuse only content-addressed safe output.

    Commands that write derived trees are intentionally not cached here: a
    cached stdout without recreating the tree would silently lose evidence.
    Their inputs are still deduplicated by the surrounding scheduler.
    """

    command_cwd = output_dir if profile.name in {"xortool"} else path.parent
    if cache_dir is None or profile.collect_dir is not None:
        return (
            runner.run(
                args,
                cwd=command_cwd,
                timeout=timeout,
                log_name=f"adapter-{profile.name}-{path.name}",
            ),
            False,
            None,
        )
    cache_dir.mkdir(parents=True, exist_ok=True)
    key, invocation = _adapter_cache_key(
        path=path,
        profile=profile,
        args=args,
        output_dir=output_dir,
        input_sha256=input_sha256,
        task_context=task_context,
    )
    cache_path = cache_dir / f"{key}.json"
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if cached.get("invocation") == invocation and isinstance(cached.get("result"), dict):
            return _result_from_cache(cached["result"]), True, str(cache_path)
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        pass
    result = runner.run(
        args,
        cwd=command_cwd,
        timeout=timeout,
        log_name=f"adapter-{profile.name}-{path.name}",
    )
    record = {
        "schema_version": 2,
        "invocation": invocation,
        "result": result.to_dict(),
        "original": {"artifact": str(path), "log_path": result.log_path},
    }
    try:
        temporary = cache_path.with_name(
            f"{cache_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(temporary, cache_path)
    except OSError:
        try:
            temporary.unlink()
        except (UnboundLocalError, OSError):
            pass
        pass
    return result, False, str(cache_path)


def _profile_stage_rank(stage: str) -> int:
    return {"fast": 0, "specialized": 1, "deep": 2}.get(stage, 1)


def _run_profile_job(
    path: Path,
    profile: AdapterProfile,
    *,
    output_dir: Path,
    runner: CommandRunner,
    max_output_bytes: int,
    deadline: float | None,
    cache_dir: Path | None,
    task_context: str,
    input_sha256: str,
) -> AdapterEvidence:
    started = time.monotonic()
    remaining = profile.timeout if deadline is None else min(profile.timeout, deadline - started)
    if remaining <= 0:
        return AdapterEvidence(
            profile.name,
            str(path),
            "deadline",
            "global adapter deadline reached",
            stage=profile.stage,
            duration_seconds=0.0,
            metadata={"reason": "global deadline reached"},
        )
    args = profile.args_for(path, output_dir)
    result, cache_hit, cache_path = _run_cached_adapter_command(
        runner,
        args,
        path=path,
        profile=profile,
        output_dir=output_dir,
        timeout=max(0.1, remaining),
        cache_dir=cache_dir,
        input_sha256=input_sha256,
        task_context=task_context,
    )
    output = result.combined_output()[:max_output_bytes]
    status = "missing" if result.missing else "timeout" if result.timed_out else "ok" if result.returncode == 0 else "nonzero"
    hits_list = list(_candidate_hits(output, tool=profile.name, source=result.log_path or str(path)))
    if profile.name == "yara-flag-pattern" and output and result.returncode == 0:
        try:
            payload = path.read_bytes()[:max_output_bytes]
        except OSError:
            payload = b""
        hits_list.extend(_candidate_hits(payload.decode("utf-8", errors="replace"), tool=profile.name, source=str(path)))
    if profile.name in {"foremost-carve", "scalpel-carve"}:
        label = profile.name.removesuffix("-carve")
        if profile.name == "scalpel-carve" and profile.collect_dir is not None:
            carve_roots = [profile.collect_dir(path, output_dir)]
        else:
            prefix = _derived_dir(label, path, output_dir).name
            carve_roots = sorted((candidate for candidate in output_dir.glob(f"{prefix}*") if candidate.is_dir()), key=str)
        for carve_root in carve_roots:
            if not carve_root.is_dir():
                continue
            for carved in sorted(carve_root.rglob("*"), key=str):
                if not carved.is_file() or carved.is_symlink():
                    continue
                try:
                    payload = carved.read_bytes()[:max_output_bytes]
                except OSError:
                    continue
                hits_list.extend(_candidate_hits(payload.decode("utf-8", errors="replace"), tool=profile.name, source=str(carved)))
    derived_count = 0
    derived_paths: list[str] = []
    if result.returncode == 0 and profile.collect_dir is not None:
        collected_root = profile.collect_dir(path, output_dir)
        for derived in _collect_text_files(collected_root):
            try:
                text = derived.read_bytes().decode("utf-8", errors="replace")
            except OSError:
                continue
            hits_list.extend(_candidate_hits(text, tool=profile.name, source=str(derived)))
            derived_count += 1
            derived_paths.append(str(derived))
        output = f"{output}\nderived_text_files={derived_count}" if output else f"derived_text_files={derived_count}"
    metadata: dict[str, object] = {"input_sha256": input_sha256}
    if cache_path is not None:
        metadata["cache_path"] = cache_path
    if derived_count:
        metadata["derived_text_files"] = derived_count
        metadata["derived_paths"] = derived_paths
    return AdapterEvidence(
        profile.name,
        str(path),
        status,
        output,
        tuple(hits_list),
        result.log_path,
        profile.stage,
        cache_hit,
        time.monotonic() - started,
        metadata,
    )


def run_adapter_profiles(
    paths: Iterable[Path],
    *,
    classifications: dict[Path, Classification],
    output_dir: Path,
    runner: CommandRunner,
    mode: str = "full",
    max_output_bytes: int = 1_048_576,
    workers: int = 4,
    deadline_seconds: float | None = None,
    cache_dir: Path | None = None,
    context_hashes: dict[Path, str] | None = None,
    skip_paths: set[Path] | None = None,
) -> tuple[AdapterEvidence, ...]:
    """Run all available type-matched offline adapters and CyberChef.

    Jobs are staged so cheap evidence is available quickly while expensive
    carving/decompilation cannot starve the fast pass.  Results are emitted in
    stable path/profile order even though subprocesses run concurrently.
    """

    if mode not in {"fast", "full"}:
        raise ValueError(f"unsupported adapter mode: {mode}")
    workers = max(1, min(int(workers), 32))

    output_dir.mkdir(parents=True, exist_ok=True)
    yara_rule = output_dir / "flag-shape.yar"
    if not yara_rule.exists():
        yara_rule.write_text(
            "rule IcoFlagShape { strings: $flag = /(ico|ctf|flag|picoctf|htb|seccon)\\{[^{}\\r\\n]{1,256}\\}/ nocase condition: $flag }\n",
            encoding="utf-8",
        )
    semgrep_rule = output_dir / "semgrep-local.yml"
    if not semgrep_rule.exists():
        # A local rule avoids Semgrep's registry and telemetry paths.  It is a
        # detector for evidence, not a claim that every matching string is a
        # real flag; the normal triage gate still applies below.
        semgrep_rule.write_text(
            "rules:\n"
            "  - id: ico-flag-shape\n"
            "    message: possible CTF flag-shaped value\n"
            "    severity: INFO\n"
            "    languages: [generic]\n"
            "    patterns:\n"
            "      - pattern-regex: '(?i)(?:ico|ctf|flag|picoctf|htb|seccon)\\{[^{}\\r\\n]{1,256}\\}'\n",
            encoding="utf-8",
        )
    skipped = {Path(path).resolve() for path in (skip_paths or set())}
    raw_paths = sorted({Path(path).resolve() for path in paths if Path(path).resolve() not in skipped}, key=str)
    deadline = None if deadline_seconds is None else time.monotonic() + max(0.0, deadline_seconds)
    evidence: list[AdapterEvidence] = []
    # CyberChef is an in-process fast pass.  Run it concurrently too, but keep
    # the stable path order when collecting the results.
    cyberchef_paths = [path for path in raw_paths if path.is_file() and not path.is_symlink()]
    if cyberchef_paths:
        with ThreadPoolExecutor(max_workers=min(workers, len(cyberchef_paths)), thread_name_prefix="ico-cyberchef") as executor:
            futures = [executor.submit(run_cyberchef_adapter, path) for path in cyberchef_paths]
            for future in futures:
                try:
                    evidence.append(future.result())
                except Exception as exc:
                    path = cyberchef_paths[len(evidence)] if len(evidence) < len(cyberchef_paths) else cyberchef_paths[-1]
                    evidence.append(AdapterEvidence("cyberchef", str(path), "failed", f"{type(exc).__name__}: {exc}", stage="fast"))

    # LIEF is a read-only parser and is cheap enough to run before external
    # reverse-engineering profiles.  It is intentionally absent for text and
    # media inputs; Qiling/Unicorn remain manual because they execute code.
    if mode == "full":
        for raw_path in raw_paths:
            classification = classifications.get(raw_path)
            if not raw_path.is_file() or raw_path.is_symlink() or classification is None:
                continue
            if classification.kind == "binary" or classification.extension.lower() in {".elf", ".exe", ".dll", ".so", ".dylib"}:
                evidence.append(run_lief_adapter(raw_path, max_output_bytes=max_output_bytes))

    jobs: list[tuple[Path, AdapterProfile, str, str]] = []
    for raw_path in raw_paths:
        if not raw_path.is_file() or raw_path.is_symlink():
            continue
        classification = classifications.get(raw_path)
        if classification is None:
            continue
        try:
            input_sha256 = _file_sha256(raw_path)
        except OSError:
            continue
        task_context = (context_hashes or {}).get(raw_path, "")
        profiles = profiles_for_classification(classification)
        applicable_profiles: list[AdapterProfile] = []
        for profile in profiles:
            if profile.predicate is None:
                applicable_profiles.append(profile)
                continue
            try:
                if profile.predicate(raw_path):
                    applicable_profiles.append(profile)
            except Exception:
                # A hint detector is advisory.  A broken hint must not hide
                # the normal type-matched profiles or fail the scan.
                continue
        profiles = tuple(applicable_profiles)
        if mode == "fast":
            profiles = tuple(profile for profile in profiles if profile.stage == "fast")
        for profile in profiles:
            jobs.append((raw_path, profile, input_sha256, task_context))

    by_stage: dict[int, list[tuple[Path, AdapterProfile, str, str]]] = {0: [], 1: [], 2: []}
    for job in jobs:
        by_stage.setdefault(_profile_stage_rank(job[1].stage), []).append(job)
    ordered_results: list[AdapterEvidence] = []
    for stage_rank in sorted(by_stage):
        stage_jobs = by_stage[stage_rank]
        if not stage_jobs:
            continue
        stage_jobs.sort(key=lambda item: (str(item[0]), item[1].name))
        if deadline is not None and time.monotonic() >= deadline:
            ordered_results.extend(
                AdapterEvidence(
                    profile.name,
                    str(path),
                    "deadline",
                    "global adapter deadline reached",
                    stage=profile.stage,
                    metadata={"reason": "global deadline reached"},
                )
                for path, profile, _digest, _context in stage_jobs
            )
            continue
        executor = ThreadPoolExecutor(max_workers=min(workers, len(stage_jobs)), thread_name_prefix=f"ico-adapter-{stage_rank}")
        futures: dict[Future[AdapterEvidence], tuple[Path, AdapterProfile]] = {}
        try:
            for path, profile, digest, task_context in stage_jobs:
                futures[executor.submit(
                    _run_profile_job,
                    path,
                    profile,
                    output_dir=output_dir,
                    runner=runner,
                    max_output_bytes=max_output_bytes,
                    deadline=deadline,
                    cache_dir=cache_dir,
                    task_context=task_context,
                    input_sha256=digest,
                )] = (path, profile)
            stage_results: dict[tuple[str, str], AdapterEvidence] = {}
            wait_timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
            try:
                for future in as_completed(futures, timeout=wait_timeout):
                    path, profile = futures[future]
                    try:
                        stage_results[(str(path), profile.name)] = future.result()
                    except Exception as exc:
                        stage_results[(str(path), profile.name)] = AdapterEvidence(
                            profile.name,
                            str(path),
                            "failed",
                            f"{type(exc).__name__}: {exc}",
                            stage=profile.stage,
                        )
            except TimeoutError:
                pass
            for future, (path, profile) in futures.items():
                key = (str(path), profile.name)
                if key in stage_results:
                    ordered_results.append(stage_results[key])
                else:
                    future.cancel()
                    ordered_results.append(
                        AdapterEvidence(
                            profile.name,
                            str(path),
                            "deadline",
                            "global adapter deadline reached",
                            stage=profile.stage,
                            metadata={"reason": "global deadline reached"},
                        )
                    )
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
    # CyberChef was collected first; stable final ordering is by path, stage,
    # and analyzer so debug reports do not depend on thread completion order.
    combined = evidence + ordered_results
    combined.sort(key=lambda item: (item.path, _profile_stage_rank(item.stage), item.tool))
    return tuple(combined)


__all__ = [
    "AdapterEvidence",
    "AdapterProfile",
    "ToolSpec",
    "TOOL_SPECS",
    "available_tool_specs",
    "cyberchef_asset",
    "profiles_for_classification",
    "run_lief_adapter",
    "run_adapter_profiles",
    "run_cyberchef_adapter",
    "tool_inventory",
]
