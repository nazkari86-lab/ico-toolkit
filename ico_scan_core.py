#!/usr/bin/env python3
"""Core primitives for the local, offline ICO/CTF file scanner."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import signal
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence


MAX_CAPTURE_BYTES = 1_048_576
MAX_SINGLE_BYTE_XOR_BYTES = 8 * 1024 * 1024
MAX_GENERIC_XOR_BYTES = 2 * 1024 * 1024
MAX_ENCODED_VIEW_BYTES = 4 * 1024 * 1024
MAX_ENCODED_TOKENS = 256
FLAG_XOR_CRIBS = (
    b"SECCON{",
    b"HTB{",
    b"CTF{",
    b"ICO{",
    b"ico{",
    b"FLAG{",
    b"flag{",
)

_BASE64_TOKEN_RE = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/])")
_BASE32_TOKEN_RE = re.compile(rb"(?<![A-Za-z2-7])[A-Z2-7]{8,}={0,6}(?![A-Z2-7])")
_HEX_TOKEN_RE = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){4,}(?![0-9A-Fa-f])")
_URL_TOKEN_RE = re.compile(
    rb"(?<![A-Za-z0-9])(?:%[0-9A-Fa-f]{2}|[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=\-]){4,}(?![A-Za-z0-9])"
)
_FLAG_PLACEHOLDER_RE = re.compile(
    r"(?i)(?<![a-z0-9])(?:example|sample|fake|dummy|test[_-]?flag|redacted|placeholder|your_flag|insert_flag|flag_here|n[o0]t[_-]?the[_-]?real[_-]?flag)(?![a-z0-9])"
)
_FLAG_PREFIX_PATTERN = r"(?i:ico|seccon|htb|flag|pwn|ctf|ductf|picoctf|tjctf|corctf|uiuctf|umdctf|utctf|lactf|bctf|ictf|jctf|csawctf|kctf|imaginaryctf)"
_FLAG_SHAPED_VALUE_RE = re.compile(r"^" + _FLAG_PREFIX_PATTERN + r"\{([^{}]*)\}$")


def flag_triage(value: str) -> tuple[str, Optional[str]]:
    """Label unmistakable placeholder/noise patterns without rejecting a hit."""

    if any(not character.isprintable() for character in value):
        return "likely-noise", "contains non-printable characters"
    if "..." in value or "…" in value:
        return "likely-placeholder", "contains an ellipsis placeholder"
    match = _FLAG_PLACEHOLDER_RE.search(value)
    if match:
        return "likely-placeholder", f"contains placeholder marker: {match.group(0)}"
    flag_match = _FLAG_SHAPED_VALUE_RE.fullmatch(value)
    if flag_match and re.search(r"[\[\]*^?]", flag_match.group(1)):
        return "likely-placeholder", "flag body contains regular-expression syntax"
    if flag_match and len(flag_match.group(1).strip()) <= 1:
        return "likely-noise", "flag body is unusually short (1 character)"
    if flag_match and re.fullmatch(r"[xX]{8,}", flag_match.group(1)):
        return "likely-placeholder", "flag body is a repeated X template"
    return "candidate", None


@dataclass(frozen=True)
class Artifact:
    path: Path
    depth: int = 0
    parent: Optional[str] = None
    task_root: Optional[Path] = None


@dataclass(frozen=True)
class Classification:
    mime: str
    description: str
    kind: str
    extension: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class CommandResult:
    args: list[str]
    returncode: Optional[int]
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    missing: bool = False
    duration_seconds: float = 0.0
    log_path: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.missing

    def combined_output(self) -> str:
        if self.stdout and self.stderr:
            return f"{self.stdout}\n{self.stderr}"
        return self.stdout or self.stderr

    def to_dict(self) -> dict[str, Any]:
        return asdict(self) | {"ok": self.ok}


@dataclass(frozen=True)
class RunnerPolicy:
    """Optional child-process limits; ``None`` preserves legacy behavior."""

    max_cpu_seconds: int | None = None
    max_memory_bytes: int | None = None
    max_output_bytes: int | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("max_cpu_seconds", self.max_cpu_seconds),
            ("max_memory_bytes", self.max_memory_bytes),
            ("max_output_bytes", self.max_output_bytes),
        ):
            if value is not None and int(value) <= 0:
                raise ValueError(f"{name} must be positive when provided")


def _apply_child_limits(policy: RunnerPolicy) -> None:
    """Apply POSIX limits in the child immediately before exec."""

    if os.name != "posix":
        return
    try:
        import resource

        if policy.max_cpu_seconds is not None:
            limit = int(policy.max_cpu_seconds)
            resource.setrlimit(resource.RLIMIT_CPU, (limit, limit))
        if policy.max_memory_bytes is not None and hasattr(resource, "RLIMIT_AS"):
            limit = int(policy.max_memory_bytes)
            current_soft, current_hard = resource.getrlimit(resource.RLIMIT_AS)
            hard = limit if current_hard in (-1, resource.RLIM_INFINITY) else min(current_hard, limit)
            resource.setrlimit(resource.RLIMIT_AS, (min(limit, hard), hard))
    except (ImportError, OSError, ValueError):
        # Limits are an additional hardening layer.  Timeout/process-group
        # cleanup remains authoritative when a platform rejects a limit.
        return


@dataclass
class CommandRunner:
    """Run external tools without a shell and preserve bounded evidence."""

    log_dir: Optional[Path] = None
    capture_limit: int = MAX_CAPTURE_BYTES
    policy: RunnerPolicy | None = None
    _sequence: int = field(default=0, init=False, repr=False)
    _log_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.log_dir is not None:
            self.log_dir.mkdir(parents=True, exist_ok=True)

    def run(
        self,
        args: Sequence[str],
        *,
        cwd: Path,
        timeout: float = 30.0,
        log_name: str = "command",
    ) -> CommandResult:
        argv = [str(value) for value in args]
        started = time.monotonic()
        result = CommandResult(args=argv, returncode=None)
        capture_limit = self.capture_limit
        if self.policy is not None and self.policy.max_output_bytes is not None:
            capture_limit = min(capture_limit, int(self.policy.max_output_bytes))
        executable = shutil.which(argv[0]) if argv else None
        if not argv or executable is None:
            result.missing = True
            result.stderr = f"executable not found: {argv[0] if argv else '<empty command>'}"
            result.duration_seconds = time.monotonic() - started
            self._write_log(log_name, result)
            return result

        try:
            with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
                process = subprocess.Popen(
                    argv,
                    cwd=str(cwd),
                    stdin=subprocess.DEVNULL,
                    stdout=stdout_file,
                    stderr=stderr_file,
                    shell=False,
                    start_new_session=True,
                    preexec_fn=(lambda: _apply_child_limits(self.policy)) if self.policy is not None and os.name == "posix" else None,
                )
                try:
                    process.communicate(timeout=max(0.1, timeout))
                except subprocess.TimeoutExpired:
                    result.timed_out = True
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (OSError, ProcessLookupError):
                        process.kill()
                    process.communicate()
                result.returncode = process.returncode
                stdout_file.flush()
                stderr_file.flush()
                stdout_file.seek(0)
                stderr_file.seek(0)
                result.stdout = self._decode(stdout_file.read(capture_limit + 1), capture_limit)
                result.stderr = self._decode(stderr_file.read(capture_limit + 1), capture_limit)
        except OSError as exc:
            result.returncode = None
            result.stderr = f"{type(exc).__name__}: {exc}"
        result.duration_seconds = time.monotonic() - started
        self._write_log(log_name, result)
        return result

    def _decode(self, data: bytes, capture_limit: int | None = None) -> str:
        if not data:
            return ""
        limit = self.capture_limit if capture_limit is None else capture_limit
        truncated = len(data) > limit
        view = data[:limit]
        text = view.decode("utf-8", errors="replace")
        if truncated:
            text += f"\n[output truncated at {limit} bytes]"
        return text

    def _write_log(self, log_name: str, result: CommandResult) -> None:
        if self.log_dir is None:
            return
        # Adapter profiles may run concurrently.  Keep only sequence
        # allocation and the tiny log write in the lock; subprocess work and
        # output capture remain fully parallel.
        with self._log_lock:
            self._sequence += 1
            safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", log_name).strip("_") or "command"
            log_path = self.log_dir / f"{self._sequence:04d}-{safe_name}.json"
            result.log_path = str(log_path)
            log_path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def sha256_file(path: Path, limit: Optional[int] = None) -> str:
    digest = hashlib.sha256()
    remaining = limit
    with path.open("rb") as handle:
        while True:
            read_size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
            if read_size <= 0:
                break
            chunk = handle.read(read_size)
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return digest.hexdigest()


def encoded_views(
    data: bytes | str,
    *,
    max_bytes: int = MAX_ENCODED_VIEW_BYTES,
    max_tokens: int = MAX_ENCODED_TOKENS,
) -> list[dict[str, Any]]:
    """Decode bounded, explicit textual encodings embedded in an artifact.

    This is a deterministic nested-view pass for unknown CTF files. It only
    accepts syntactically valid Base64, Base32, hexadecimal, or percent-URL
    tokens; it does not guess keys, passwords, or flag contents. Returned
    bytes are capped and deduplicated so random binary data cannot create an
    unbounded decode workload.
    """

    if max_bytes <= 0 or max_tokens <= 0:
        return []
    source = data if isinstance(data, bytes) else data.encode("utf-8", errors="replace")
    source = source[:max_bytes]
    views: list[dict[str, Any]] = []
    seen: set[tuple[str, bytes]] = set()

    def add(encoding: str, token: bytes, decoded: bytes, offset: int) -> None:
        if not decoded or len(decoded) > max_bytes:
            return
        key = (encoding, decoded)
        if key in seen:
            return
        seen.add(key)
        views.append(
            {
                "encoding": encoding,
                "token": token.decode("ascii", errors="replace"),
                "offset": offset,
                "decoded": decoded,
            }
        )

    for match in _BASE64_TOKEN_RE.finditer(source):
        if len(views) >= max_tokens:
            break
        token = match.group(0)
        try:
            decoded = base64.b64decode(token, validate=True)
        except (ValueError, binascii.Error):
            continue
        add("base64", token, decoded, match.start())

    if len(views) < max_tokens:
        for match in _BASE32_TOKEN_RE.finditer(source):
            if len(views) >= max_tokens:
                break
            token = match.group(0)
            try:
                decoded = base64.b32decode(token + b"=" * (-len(token) % 8), casefold=False)
            except (ValueError, binascii.Error):
                continue
            add("base32", token, decoded, match.start())

    if len(views) < max_tokens:
        for match in _HEX_TOKEN_RE.finditer(source):
            if len(views) >= max_tokens:
                break
            token = match.group(0)
            try:
                decoded = bytes.fromhex(token.decode("ascii"))
            except (ValueError, UnicodeDecodeError):
                continue
            add("hex", token, decoded, match.start())

    if len(views) < max_tokens:
        for match in _URL_TOKEN_RE.finditer(source):
            if len(views) >= max_tokens:
                break
            token = match.group(0)
            offset = match.start()
            if b"=" in token:
                prefix, token = token.rsplit(b"=", 1)
                offset += len(prefix) + 1
            if b"%" not in token:
                continue
            decoded = urllib.parse.unquote_to_bytes(token)
            add("url", token, decoded, offset)

    return views


def single_byte_xor_views(
    data: bytes,
    *,
    prefix: bytes | None = None,
    prefixes: Iterable[bytes] | None = None,
    max_bytes: int = MAX_SINGLE_BYTE_XOR_BYTES,
) -> list[dict[str, Any]]:
    """Return deterministic single-byte-XOR plaintext views matching known cribs.

    This is intentionally a crib search, not flag guessing: the caller supplies
    the expected plaintext prefix (or prefixes), and a view is returned only when
    one of the 256 keys produces that exact byte sequence somewhere in the input.
    The scan is bounded so an accidentally supplied large artifact cannot turn
    this cheap CTF transform into an unbounded workload.
    """

    selected: list[bytes] = []
    if prefix is not None:
        selected.append(prefix)
    if prefixes is not None:
        selected.extend(prefixes)
    selected = list(dict.fromkeys(item for item in selected if item))
    selected.sort(key=len, reverse=True)
    if not selected or max_bytes <= 0:
        return []
    sample = data[:max_bytes]
    found: dict[int, dict[str, Any]] = {}
    for expected in selected:
        if len(expected) > len(sample):
            continue
        for key in range(256):
            if key in found:
                continue
            encoded_crib = bytes(value ^ key for value in expected)
            offset = sample.find(encoded_crib)
            if offset < 0:
                continue
            plaintext = bytes(value ^ key for value in sample)
            found[key] = {
                "key": key,
                "offset": offset,
                "prefix": expected,
                "plaintext": plaintext,
            }
    return [found[key] for key in sorted(found)]


def _magic_kind(path: Path) -> tuple[str, str]:
    try:
        header = path.read_bytes()[:32]
    except OSError:
        return "unknown", ""
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "PNG image"
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg", "JPEG image"
    if header.startswith(b"BM"):
        return "bmp", "BMP image"
    if header.startswith(b"%PDF-"):
        return "pdf", "PDF document"
    if header.startswith(b"PK\x03\x04"):
        return "archive", "ZIP archive"
    if header.startswith(b"\x7fELF"):
        return "binary", "ELF executable"
    if header[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
        return "binary", "Mach-O executable"
    if header.startswith(b"MZ"):
        return "binary", "DOS/PE executable"
    if header.startswith(b"RIFF"):
        if b"WAVE" in header[:16]:
            return "wav", "WAV audio"
        return "media", "RIFF media container"
    return "unknown", ""


def _kind_from_text(mime: str, description: str, extension: str, magic_kind: str) -> str:
    lower_mime = mime.lower()
    lower_desc = description.lower()
    lower_ext = extension.lower()
    if magic_kind != "unknown":
        return magic_kind
    if lower_mime == "image/png" or "png image" in lower_desc:
        return "png"
    if lower_mime in {"image/jpeg", "image/jpg"} or "jpeg image" in lower_desc:
        return "jpeg"
    if lower_mime == "image/bmp" or "bmp image" in lower_desc:
        return "bmp"
    if lower_mime == "application/pdf" or "pdf document" in lower_desc:
        return "pdf"
    if lower_mime in {"audio/wav", "audio/x-wav"} or "wave audio" in lower_desc:
        return "wav"
    if any(marker in lower_desc for marker in ("memory dump", "crash dump", "hibernation file", "lime memory")) or lower_ext in {".dmp", ".vmem", ".memdump", ".lime"}:
        return "memory"
    if "pcap" in lower_mime or "pcap" in lower_desc or lower_ext in {".pcap", ".pcapng", ".cap"}:
        return "pcap"
    archive_markers = (
        "zip",
        "7-zip",
        "rar",
        "gzip",
        "bzip",
        "xz compressed",
        "tar archive",
        "iso 9660",
        "microsoft word 2007+",
        "microsoft excel 2007+",
        "openxml",
        "java archive",
    )
    if any(marker in lower_mime or marker in lower_desc for marker in archive_markers):
        return "archive"
    if "executable" in lower_desc or "shared object" in lower_desc or "mach-o" in lower_desc:
        return "binary"
    if lower_mime.startswith("text/") or any(marker in lower_desc for marker in ("ascii text", "utf-8 unicode text", "json data", "xml document")):
        return "text"
    if lower_mime.startswith("audio/"):
        return "audio"
    if lower_mime.startswith("video/"):
        return "video"
    if lower_mime.startswith("image/"):
        return "image"
    if lower_mime in {"application/wasm", "application/x-sharedlib", "application/octet-stream"}:
        return "binary" if lower_ext in {".elf", ".exe", ".dll", ".dylib", ".so", ".wasm"} else "data"
    if lower_ext in {".py", ".js", ".ts", ".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".go", ".java", ".php", ".sh"}:
        return "text"
    return "data"


def classify(path: Path, runner: CommandRunner) -> Classification:
    extension = path.suffix.lower()
    mime_result = runner.run(["file", "--brief", "--mime-type", str(path)], cwd=path.parent, timeout=5, log_name="classify-mime")
    desc_result = runner.run(["file", "--brief", str(path)], cwd=path.parent, timeout=5, log_name="classify-description")
    mime = mime_result.stdout.strip().splitlines()[0] if mime_result.stdout.strip() else "application/octet-stream"
    description = desc_result.stdout.strip().splitlines()[0] if desc_result.stdout.strip() else "unknown data"
    magic_kind, magic_description = _magic_kind(path)
    kind = _kind_from_text(mime, description, extension, magic_kind)
    if magic_kind != "unknown" and description == "unknown data":
        description = magic_description
    return Classification(mime=mime, description=description, kind=kind, extension=extension)


class FlagMatcher:
    DEFAULT_PATTERN = r"(?<![A-Za-z0-9_])" + _FLAG_PREFIX_PATTERN + r"\{[^{}\r\n]{1,256}\}"

    def __init__(self, patterns: Iterable[str] | None = None) -> None:
        selected = [self.DEFAULT_PATTERN]
        for pattern in patterns or []:
            if pattern not in selected:
                selected.append(pattern)
        self.patterns = [re.compile(pattern) for pattern in selected]

    def scan(self, text: str, *, source: str, analyzer: str) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for line_number, line in enumerate(text.splitlines(), start=1):
            for pattern in self.patterns:
                for match in pattern.finditer(line):
                    key = (match.group(0), line_number)
                    if key in seen:
                        continue
                    seen.add(key)
                    triage, triage_reason = flag_triage(match.group(0))
                    hit = {
                        "value": match.group(0),
                        "state": "candidate",
                        "triage": triage,
                        "source": source,
                        "analyzer": analyzer,
                        "line": line_number,
                        "evidence": line[:1000],
                    }
                    if triage_reason:
                        hit["triage_reason"] = triage_reason
                    hits.append(
                        hit
                    )
        return hits


def read_text_views(path: Path, limit: int = 8 * 1024 * 1024) -> str:
    try:
        data = path.read_bytes()[:limit]
    except OSError as exc:
        return f"[read error: {type(exc).__name__}: {exc}]"
    views = [data.decode("utf-8", errors="ignore")]
    if len(data) >= 2:
        views.append(data.decode("utf-16-le", errors="ignore"))
    return "\n".join(view for view in views if view)


def as_jsonable(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (Artifact, Classification, CommandResult)):
        return as_jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): as_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [as_jsonable(item) for item in value]
    return value
