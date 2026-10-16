#!/usr/bin/env bash
# Download the wheel for every entry of a hashed lock, for CPython 3.12 on x86_64 Linux (manylinux, glibc
# up to 2.28), verifying each against the lock's hashes. Binary wheels only: an entry without a suitable
# wheel fails the build rather than silently building an sdist with unpinned build dependencies.
#
#   fetch_wheels.sh [REQUIREMENTS] [OUT_DIR]      defaults: requirements/runtime.txt build/wheelhouse
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
req=${1:-$root/requirements/runtime.txt}
out=${2:-$root/build/wheelhouse}
py=$("$here/buildenv.sh")

plats=()
for v in $(seq 28 -1 5); do plats+=(--platform "manylinux_2_${v}_x86_64"); done
plats+=(--platform manylinux2014_x86_64 --platform manylinux2010_x86_64 --platform manylinux1_x86_64)

mkdir -p "$out"
"$py" -m pip download --quiet --disable-pip-version-check --no-deps --only-binary=:all: --require-hashes \
    --python-version 3.12 --implementation cp --abi cp312 "${plats[@]}" -r "$req" -d "$out"
echo "wheels: $(find "$out" -maxdepth 1 -name '*.whl' | wc -l) in $out" >&2
