#!/usr/bin/env bash
# Regenerate the hashed lock files under requirements/ (build machine; needs network and uv).
#
#   requirements/runtime.txt  runtime closure of tripline-scope + tripline-scope-verify (PyPI packages only)
#   requirements/dev.txt      runtime + dev tools (pytest, ruff, cyclonedx-bom, httpx), constrained to runtime pins
#   requirements/build.txt    pip/setuptools/wheel used on the build machine to build and fetch wheels
#
# Target: CPython 3.12 on x86_64 Linux (manylinux). Every entry is pinned with == and carries the SHA-256 of
# every published artefact of that version. Existing pins are kept as preferences, so re-running without
# changes to pyproject.toml is a no-op; pass --upgrade (or --upgrade-package NAME) to move pins.
#
# The local verifier (verify/) satisfies pyproject's "tripline-scope-verify==0.1.0" during resolution via
# requirements/local.in and is excluded from the output: it is built from source, never fetched from PyPI.
set -euo pipefail
cd "$(dirname "$0")/.."
UV=${UV:-uv}
common=(--generate-hashes --python-version 3.12 --python-platform x86_64-manylinux_2_28 --quiet
        --custom-compile-command "make lock")

"$UV" pip compile pyproject.toml requirements/local.in "${common[@]}" "$@" \
    --no-emit-package tripline-scope-verify -o requirements/runtime.txt

"$UV" pip compile pyproject.toml requirements/local.in --extra dev -c requirements/runtime.txt \
    "${common[@]}" "$@" --no-emit-package tripline-scope-verify -o requirements/dev.txt

"$UV" pip compile requirements/build.in "${common[@]}" "$@" -o requirements/build.txt

echo "locked: $(grep -c '^[A-Za-z]' requirements/runtime.txt) runtime, $(grep -c '^[A-Za-z]' requirements/dev.txt) dev," \
     "$(grep -c '^[A-Za-z]' requirements/build.txt) build packages"
