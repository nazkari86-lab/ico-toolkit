#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ANALYSIS_VENV=${ICO_ANALYSIS_VENV:-"$ROOT/../ico-analysis-venv312"}
ANGR_VENV=${ICO_ANGR_VENV:-"$ROOT/../ico-angr-venv312"}

if [ ! -x "$ANALYSIS_VENV/bin/python" ]; then
  if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.12 "$ANALYSIS_VENV"
  elif command -v python3.12 >/dev/null 2>&1; then
    python3.12 -m venv "$ANALYSIS_VENV"
  else
    echo "Python 3.12 or uv is required for the isolated analysis runtime" >&2
    exit 1
  fi
fi

if command -v uv >/dev/null 2>&1; then
  uv pip install --python "$ANALYSIS_VENV/bin/python" -r "$ROOT/requirements-optional-analysis.txt"
else
  "$ANALYSIS_VENV/bin/python" -m pip install -r "$ROOT/requirements-optional-analysis.txt"
fi

# Keep angr and Claripy separate from the main Python 3.14 runtime and from
# the analysis stack's fpylll/LIEF dependency set.
if [ ! -x "$ANGR_VENV/bin/python" ]; then
  if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.12 "$ANGR_VENV"
  elif command -v python3.12 >/dev/null 2>&1; then
    python3.12 -m venv "$ANGR_VENV"
  else
    echo "Python 3.12 or uv is required for the isolated angr runtime" >&2
    exit 1
  fi
fi
if command -v uv >/dev/null 2>&1; then
  uv pip install --python "$ANGR_VENV/bin/python" -r "$ROOT/requirements-optional-angr.txt"
else
  "$ANGR_VENV/bin/python" -m pip install -r "$ROOT/requirements-optional-angr.txt"
fi

ICO_TOOLKIT_ROOT=$ROOT
export ICO_TOOLKIT_ROOT
. "$ROOT/env.sh"
if command -v uv >/dev/null 2>&1; then
  uv pip install --python "$ICO_EXTRA_VENV/bin/python" -r "$ROOT/requirements-optional-unblob.txt"
else
  "$ICO_EXTRA_VENV/bin/python" -m pip install -r "$ROOT/requirements-optional-unblob.txt"
fi

echo "Optional solver tools installed. Run: . $ROOT/env.sh"
