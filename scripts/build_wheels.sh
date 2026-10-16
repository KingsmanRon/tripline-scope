#!/usr/bin/env bash
# Build the two first-party wheels (tripline-scope, tripline-scope-verify) from the files tracked by git,
# offline, with the hash-pinned build tools (requirements/build.txt) and no build isolation. Timestamps come
# from SOURCE_DATE_EPOCH (default: the last commit time) so the same tree gives byte-identical wheels.
#
#   build_wheels.sh [OUT_DIR]        default: build/dist
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
out=$(mkdir -p "${1:-$root/build/dist}" && cd "${1:-$root/build/dist}" && pwd)
py=$("$here/buildenv.sh")
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}

src=$(mktemp -d "${TMPDIR:-/tmp}/tscope-src.XXXXXX")
trap 'rm -rf "$src"' EXIT
# Only tracked files (working-tree content): untracked files, build output and caches never reach a wheel.
git -C "$root" ls-files -z | (cd "$root" && tar --null -T - -cf -) | tar -xf - -C "$src"

rm -f "$out"/tripline_scope-*.whl "$out"/tripline_scope_verify-*.whl
for pkg in "$src/verify" "$src"; do
    "$py" -m pip wheel --quiet --disable-pip-version-check --no-deps --no-build-isolation --no-index \
        --wheel-dir "$out" "$pkg" >&2
done
ls "$out"/tripline_scope-*.whl "$out"/tripline_scope_verify-*.whl
