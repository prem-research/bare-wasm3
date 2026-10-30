#!/bin/sh
# Apply WebAssembly Reference Types patches to wasm3 sources using quilt.
# Idempotent — safe to run multiple times.
# Run after bare-make generate (cmake-fetch re-extracts the source).
#
# Usage: sh patch-wasm3.sh [build/<target> ...]   (default: every build/*/)
#
set -e

BASE="$(cd "$(dirname "$0")" && pwd)"

# Relative to the wasm3 source, so quilt's saved path works on any machine.
REL_PATCHES="../../../../../patches"

[ "$#" -gt 0 ] || set -- build/*/

for build_dir in "$@"; do
  build_dir="${build_dir%/}"
  src="$BASE/$build_dir/_deps/github+wasm3+wasm3-src/source"
  if [ ! -d "$src" ]; then
    echo "  [patch] skipping $build_dir (not yet generated)"
    continue
  fi

  echo "  [patch] applying patches to $build_dir ..."
  # Fix absolute paths saved by older runs.
  if [ -f "$src/.pc/.quilt_patches" ]; then
    echo "$REL_PATCHES" > "$src/.pc/.quilt_patches"
  fi
  rc=0
  (cd "$src" && QUILT_PATCHES="$REL_PATCHES" quilt --quiltrc - push -a) || rc=$?
  # ignore re-applying patches
  [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ] || exit "$rc"

  # Force a full rebuild of the wasm3 sub-project by removing its build output.
  # cmake-fetch uses stamp files that survive source edits, so ninja would
  # silently skip recompilation without this.
  wasm3_build="$BASE/$build_dir/_deps/github+wasm3+wasm3-build"
  if [ -d "$wasm3_build" ]; then
    echo "  [patch] removing wasm3 build dir to force recompile"
    rm -rf "$wasm3_build"
  fi
done
