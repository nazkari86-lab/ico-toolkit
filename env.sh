#!/bin/sh

# Activate the toolkit from any checkout location:
#   source ./env.sh
# Optional runtimes can be supplied explicitly with ICO_TOOLKIT_VENV and
# ICO_EXTRA_VENV.  A sibling runtime is used when it exists (the layout used
# by the original local installation); a fresh checkout otherwise defaults to
# repository-local .venv directories.

if [ -n "${ZSH_VERSION:-}" ]; then
  ICO_ENV_FILE="${(%):-%x}"
elif [ -n "${BASH_SOURCE:-}" ]; then
  ICO_ENV_FILE="${BASH_SOURCE}"
else
  ICO_ENV_FILE="$0"
fi
ICO_ENV_DIR=$(CDPATH= cd -- "$(dirname -- "$ICO_ENV_FILE")" && pwd)
ICO_TOOLKIT_ROOT=${ICO_TOOLKIT_ROOT:-$ICO_ENV_DIR}
if [ ! -d "$ICO_TOOLKIT_ROOT" ]; then
  echo "ico-toolkit: root does not exist: $ICO_TOOLKIT_ROOT" >&2
  return 1 2>/dev/null || exit 1
fi

if [ -z "${ICO_TOOLKIT_VENV:-}" ]; then
  if [ -d "$ICO_TOOLKIT_ROOT/../ico-toolkit-venv314" ]; then
    ICO_TOOLKIT_VENV="$ICO_TOOLKIT_ROOT/../ico-toolkit-venv314"
  else
    ICO_TOOLKIT_VENV="$ICO_TOOLKIT_ROOT/.venv"
  fi
fi
if [ -z "${ICO_EXTRA_VENV:-}" ]; then
  if [ -d "$ICO_TOOLKIT_ROOT/../ico-extra-venv314" ]; then
    ICO_EXTRA_VENV="$ICO_TOOLKIT_ROOT/../ico-extra-venv314"
  else
    ICO_EXTRA_VENV="$ICO_TOOLKIT_ROOT/.venv-extra"
  fi
fi
ICO_TOOL_BIN=${ICO_TOOL_BIN:-$ICO_TOOLKIT_ROOT/bin}
export ICO_TOOLKIT_ROOT ICO_TOOLKIT_VENV ICO_EXTRA_VENV ICO_TOOL_BIN

# Small compatibility wrappers must win over same-named legacy entry points in
# the shared extra runtime.  Re-prepending is intentional when this file is
# sourced again: the wrapper directory remains first.
PATH="${ICO_TOOL_BIN}:${PATH}"

case ":${PATH}:" in
  *":${ICO_EXTRA_VENV}/bin:"*) ;;
  *) PATH="${ICO_EXTRA_VENV}/bin:${PATH}" ;;
esac

case ":${PATH}:" in
  *":${ICO_TOOLKIT_VENV}/bin:"*) ;;
  *) PATH="${ICO_TOOLKIT_VENV}/bin:${PATH}" ;;
esac
case ":${PATH}:" in
  *":${ICO_TOOLKIT_ROOT}:"*) ;;
  *) PATH="${ICO_TOOLKIT_ROOT}:${PATH}" ;;
esac
case ":${PATH}:" in
  *":${ICO_TOOLKIT_ROOT}/steghide/bin:"*) ;;
  *) PATH="${ICO_TOOLKIT_ROOT}/steghide/bin:${PATH}" ;;
esac
case ":${PATH}:" in
  *":/opt/homebrew/lib/ruby/gems/4.0.0/bin:"*) ;;
  *) PATH="/opt/homebrew/lib/ruby/gems/4.0.0/bin:${PATH}" ;;
esac
case ":${PATH}:" in
  *":/Library/Frameworks/Python.framework/Versions/3.14/bin:"*) ;;
  *) PATH="/Library/Frameworks/Python.framework/Versions/3.14/bin:${PATH}" ;;
esac
# Reassert the intended precedence after the legacy runtime paths above
# prepend themselves as well: wrappers, main toolkit Python, extra CLIs, then
# the rest of the user's PATH.
PATH="${ICO_TOOL_BIN}:${ICO_TOOLKIT_VENV}/bin:${ICO_EXTRA_VENV}/bin:${ICO_TOOLKIT_ROOT}:${PATH}"
export PATH
