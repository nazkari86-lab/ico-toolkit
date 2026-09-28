#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if ! command -v brew >/dev/null 2>&1; then
  echo "Homebrew is required to install AFL++ and Nuclei" >&2
  exit 1
fi

brew install afl++ nuclei

ICO_TOOLKIT_ROOT=$ROOT
export ICO_TOOLKIT_ROOT
. "$ROOT/env.sh"

if [ ! -x "$ICO_ANALYSIS_VENV/bin/python" ]; then
  if command -v uv >/dev/null 2>&1; then
    uv venv --python 3.12 "$ICO_ANALYSIS_VENV"
  elif command -v python3.12 >/dev/null 2>&1; then
    python3.12 -m venv "$ICO_ANALYSIS_VENV"
  else
    echo "Python 3.12 or uv is required for the isolated Arjun runtime" >&2
    exit 1
  fi
fi

if command -v uv >/dev/null 2>&1; then
  uv pip install --python "$ICO_ANALYSIS_VENV/bin/python" -r "$ROOT/requirements-optional-network.txt"
else
  "$ICO_ANALYSIS_VENV/bin/python" -m pip install -r "$ROOT/requirements-optional-network.txt"
fi

nuclei -update-templates -silent
echo "Optional active tools installed. They remain disabled in file-only scans."
