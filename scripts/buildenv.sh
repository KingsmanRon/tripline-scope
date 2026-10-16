#!/usr/bin/env bash
# Create (or reuse) the build-machine virtualenv with pip/setuptools/wheel from requirements/build.txt,
# installed with --require-hashes. Prints the path of its python on stdout.
#
#   BUILD_DIR   where to keep it (default: build/)
#   UV          uv executable (optional; falls back to python3.12 -m venv + pip)
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
build_dir=${BUILD_DIR:-$root/build}
venv=$build_dir/buildenv
lock=$root/requirements/build.txt
stamp=$venv/.lock-sha256
want=$(sha256sum "$lock" | cut -d' ' -f1)

if [[ -x $venv/bin/python && -f $stamp && $(cat "$stamp") == "$want" ]]; then
    echo "$venv/bin/python"
    exit 0
fi
rm -rf "$venv"
mkdir -p "$build_dir"
UV=${UV:-$(command -v uv || true)}
if [[ -n $UV ]]; then
    "$UV" venv --quiet --python 3.12 "$venv" >&2
    "$UV" pip install --quiet --python "$venv/bin/python" --require-hashes -r "$lock" >&2
else
    py=$(command -v python3.12 || command -v python3)
    "$py" -m venv "$venv" >&2
    "$venv/bin/python" -m pip install --quiet --disable-pip-version-check --require-hashes -r "$lock" >&2
fi
echo "$want" > "$stamp"
echo "$venv/bin/python"
