#!/bin/sh
# Apply WebAssembly Reference Types patches to wasm3 sources.
# Idempotent — safe to run multiple times.
# Run after bare-make generate (cmake-fetch re-extracts the source).
set -e

BASE="$(cd "$(dirname "$0")" && pwd)"

python3 "$BASE/patch-wasm3.py"

# Force a full rebuild of the wasm3 sub-project by removing its build output.
# cmake-fetch uses stamp files that survive source edits, so ninja would silently
# skip recompilation. Removing the build dir guarantees a clean rebuild.
for dir in "$BASE/build/ios-arm64" "$BASE/build/ios-arm64-simulator"; do
  build="$dir/_deps/github+wasm3+wasm3-build"
  if [ -d "$build" ]; then
    echo "  [patch] removing $build to force wasm3 rebuild"
    rm -rf "$build"
  fi
done
