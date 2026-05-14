#!/bin/sh
# Apply WebAssembly Reference Types patches to wasm3 sources using quilt.
# Idempotent — safe to run multiple times.
# Run after bare-make generate (cmake-fetch re-extracts the source).
#
set -e

BASE="$(cd "$(dirname "$0")" && pwd)"

for build_dir in "build/ios-arm64" "build/ios-arm64-simulator" "build/android-arm64"; do
  src="$BASE/$build_dir/_deps/github+wasm3+wasm3-src/source"
  if [ ! -d "$src" ]; then
    echo "  [patch] skipping $build_dir (not yet generated)"
    continue
  fi

  echo "  [patch] applying patches to $build_dir ..."
  rc=0
  (cd "$src" && QUILT_PATCHES="$BASE/patches" quilt --quiltrc - push -a) || rc=$?
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
