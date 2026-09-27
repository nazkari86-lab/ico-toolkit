#!/usr/bin/env python3
"""Capability probes and safe entry points for platform-sensitive tools.

The normal solver is intentionally static.  This module makes the remaining
tools discoverable and usable by an operator without making emulation or
process tracing part of the automatic file pipeline.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
from functools import lru_cache
from pathlib import Path


REMAINING_TOOLS = ("qiling", "scalpel", "strace", "ltrace")


def toolkit_root(root: Path | None = None) -> Path:
    if root is not None:
        return root.expanduser().resolve()
    configured = os.environ.get("ICO_TOOLKIT_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parent


def _extra_python(root: Path) -> Path | None:
    configured = os.environ.get("ICO_EXTRA_VENV")
    candidates = []
    if configured:
        candidates.append(Path(configured) / "bin" / "python")
    candidates.extend(
        (
            root.parent / "ico-extra-venv314" / "bin" / "python",
            root.parent / "ico-extra-venv313" / "bin" / "python",
        )
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def _keystone_environment() -> dict[str, str]:
    env = os.environ.copy()
    if platform.system() != "Darwin":
        return env
    paths = ["/opt/homebrew/opt/keystone/lib", "/opt/homebrew/lib"]
    existing = env.get("DYLD_LIBRARY_PATH")
    if existing:
        paths.append(existing)
    env["DYLD_LIBRARY_PATH"] = os.pathsep.join(paths)
    return env


@lru_cache(maxsize=16)
def _qiling_status(root: Path) -> dict[str, object]:
    python = _extra_python(root)
    base = {"name": "qiling", "path": str(python) if python else None, "backend": "python-extra"}
    if python is None:
        return {**base, "state": "missing", "available": False, "exact": True, "reason": "extra Python runtime is missing"}
    try:
        probe = subprocess.run(
            [
                str(python),
                "-c",
                "import qiling, keystone, unicorn, capstone; from keystone import Ks, KS_ARCH_X86, KS_MODE_64; Ks(KS_ARCH_X86, KS_MODE_64).asm('nop'); from qiling import Qiling; print(qiling.__version__)",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
            env=_keystone_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            **base,
            "state": "missing",
            "available": False,
            "exact": True,
            "reason": f"Qiling runtime probe failed: {type(exc).__name__}",
        }
    version = (probe.stdout or "").strip().splitlines()
    if probe.returncode == 0:
        return {
            **base,
            "state": "available",
            "available": True,
            "exact": True,
            "version": version[0] if version else None,
            "reason": "Qiling, Keystone, Unicorn, and Capstone import successfully",
        }
    detail = (probe.stderr or probe.stdout or "import failed").strip().splitlines()
    return {
        **base,
        "state": "missing",
        "available": False,
        "exact": True,
        "reason": detail[-1][:300] if detail else "Qiling runtime probe failed",
    }


def scalpel_binary(root: Path | None = None) -> Path | None:
    base = toolkit_root(root)
    configured = os.environ.get("ICO_SCALPEL_BINARY")
    candidates = []
    if configured:
        candidates.append(Path(configured).expanduser())
    candidates.extend(
        (
            base / "vendor" / "scalpel" / "build" / "scalpel",
            base / "vendor" / "scalpel" / "scalpel",
            base / "bin" / "scalpel.real",
        )
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    return None


@lru_cache(maxsize=16)
def _scalpel_status(root: Path) -> dict[str, object]:
    binary = scalpel_binary(root)
    if binary is None:
        return {
            "name": "scalpel",
            "path": None,
            "backend": "bundled-arm64-build",
            "state": "missing",
            "available": False,
            "exact": True,
            "reason": "run scripts/build_scalpel.sh to build against Homebrew TRE",
        }
    return {
        "name": "scalpel",
        "path": str(binary),
        "backend": "bundled-arm64-build",
        "state": "available",
        "available": True,
        "exact": True,
        "reason": "bundled Scalpel executable is present",
    }


def _path_without_wrappers(root: Path) -> str:
    wrapper_dir = (root / "bin").resolve()
    entries: list[str] = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        try:
            if Path(entry).expanduser().resolve() == wrapper_dir:
                continue
        except OSError:
            pass
        entries.append(entry)
    return os.pathsep.join(entries)


def _native_trace(name: str, root: Path) -> Path | None:
    path = shutil.which(name, path=_path_without_wrappers(root))
    return Path(path).resolve() if path else None


@lru_cache(maxsize=32)
def _trace_status(name: str, root: Path) -> dict[str, object]:
    native = _native_trace(name, root)
    if native is not None:
        return {
            "name": name,
            "path": str(native),
            "backend": "native",
            "state": "available",
            "available": True,
            "exact": True,
            "reason": "native tracer is available outside the toolkit wrappers",
        }
    dtruss = shutil.which("dtruss")
    if platform.system() == "Darwin" and dtruss:
        return {
            "name": name,
            "path": str(Path(dtruss).resolve()),
            "backend": "dtruss-compat",
            "state": "compat",
            "available": True,
            "exact": False,
            "reason": "macOS dtruss fallback is syscall-level; it is not an exact library-call tracer",
        }
    return {
        "name": name,
        "path": None,
        "backend": "none",
        "state": "missing",
        "available": False,
        "exact": True,
        "reason": "no native tracer or macOS dtruss fallback is available",
    }


def platform_tool_status(name: str, root: Path | None = None) -> dict[str, object]:
    if name not in REMAINING_TOOLS:
        raise ValueError(f"unknown platform tool: {name}")
    base = toolkit_root(root)
    if name == "qiling":
        return _qiling_status(base)
    if name == "scalpel":
        return _scalpel_status(base)
    return _trace_status(name, base)


def platform_tool_inventory(root: Path | None = None) -> dict[str, dict[str, object]]:
    return {name: platform_tool_status(name, root) for name in REMAINING_TOOLS}


def _qiling_cli(root: Path, argv: list[str]) -> int:
    status = platform_tool_status("qiling", root)
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print("Usage: qiling --probe | --version | --run <python-script> [args...]")
        print("Qiling is a Python emulation framework; ico-solve keeps it manual and never executes challenge binaries automatically.")
        print("--probe  verify Qiling, Keystone, Unicorn, and Capstone in the extra runtime")
        print("--run    execute an operator-provided Qiling script in the isolated extra runtime")
        return 0
    if argv[0] in {"--version", "version"}:
        print(f"qiling {status.get('version', 'unavailable')} ({status['backend']})")
        return 0 if status["available"] else 127
    if argv[0] in {"--probe", "probe", "status"}:
        print(json.dumps(status, ensure_ascii=False, sort_keys=True))
        return 0 if status["available"] else 127
    if argv[0] == "--run":
        python = _extra_python(root)
        if python is None or not status["available"]:
            print(f"qiling: unavailable: {status['reason']}", file=sys.stderr)
            return 127
        if len(argv) < 2:
            print("qiling: --run requires a Python script", file=sys.stderr)
            return 2
        completed = subprocess.run([str(python), *argv[1:]], env=_keystone_environment(), check=False)
        return completed.returncode
    print("qiling: unknown option; use --help", file=sys.stderr)
    return 2


def _trace_cli(name: str, root: Path, argv: list[str]) -> int:
    status = platform_tool_status(name, root)
    if not argv or argv[0] in {"-h", "--help", "help"}:
        print(f"Usage: {name} [options] command [args...]")
        print(f"Backend: {status['backend']} ({status['state']})")
        if name == "ltrace" and status["state"] == "compat":
            print("macOS compatibility mode uses dtruss syscall events; it cannot reproduce Linux ltrace library symbols.")
        print("The wrapper is manual-only; ico-solve never executes supplied processes.")
        return 0
    if argv[0] in {"--version", "version"}:
        print(f"{name} wrapper 0.1 ({status['backend']})")
        return 0 if status["available"] else 127
    if not status["available"]:
        print(f"{name}: unavailable: {status['reason']}", file=sys.stderr)
        return 127
    if status["state"] == "compat" and os.environ.get("ICO_ALLOW_COMPAT_TRACE") != "1":
        print(
            f"{name}: compatibility backend is disabled by default; set ICO_ALLOW_COMPAT_TRACE=1 for an explicitly authorized local process",
            file=sys.stderr,
        )
        return 126
    executable = str(status["path"])
    if status["backend"] == "dtruss-compat":
        return subprocess.run([executable, *argv], check=False).returncode
    os.execv(executable, [executable, *argv])
    return 127


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print("usage: ico_platform_tools.py {qiling|strace|ltrace} ...", file=sys.stderr)
        return 2
    name, rest = args[0], args[1:]
    root = toolkit_root()
    if name == "qiling":
        return _qiling_cli(root, rest)
    if name in {"strace", "ltrace"}:
        return _trace_cli(name, root, rest)
    print(f"unknown platform tool: {name}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
