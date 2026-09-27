#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE="$ROOT/vendor/scalpel"
OUTPUT="$SOURCE/build/scalpel"

if [ -x "$OUTPUT" ] && [ "${ICO_SCALPEL_REBUILD:-0}" != "1" ]; then
  echo "Scalpel already built: $OUTPUT"
  exit 0
fi

tre_prefix=${TRE_PREFIX:-/opt/homebrew/opt/tre}
if [ ! -d "$tre_prefix/include" ] || [ ! -d "$tre_prefix/lib" ]; then
  echo "Scalpel build requires Homebrew TRE at $tre_prefix" >&2
  exit 2
fi

workdir=$(mktemp -d "${TMPDIR:-/tmp}/ico-scalpel-build.XXXXXX")
trap 'rm -rf "$workdir"' EXIT HUP INT TERM
cp -a "$SOURCE/." "$workdir/source"
cd "$workdir/source"

./configure \
  CPPFLAGS="-I$tre_prefix/include" \
  LDFLAGS="-L$tre_prefix/lib" \
  LIBS="-ltre -lpthread" \
  CXXFLAGS="${CXXFLAGS:--std=gnu++98}" \
  >/dev/null
make -j"${ICO_BUILD_JOBS:-2}" >/dev/null

mkdir -p "$(dirname -- "$OUTPUT")"
cp "$workdir/source/scalpel" "$OUTPUT"
chmod +x "$OUTPUT"
echo "Built Scalpel: $OUTPUT"
