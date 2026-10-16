#!/usr/bin/env bash
# make bundle: build the offline installer bundle/out/tripline-scope-<version>/ (build machine).
#
#   wheels/            every runtime wheel pinned by hash (fetched, hash-verified) + our two wheels (built here)
#   requirements.txt   the hashed runtime lock plus the two first-party wheels pinned by their SHA-256
#   images/*.tar       docker save of the app image (built with --network none) and PostgreSQL 16;
#                      SQL Server Developer only when WITH_MSSQL_DEMO=1 (synthetic demos/tests only)
#   sbom.cdx.json      CycloneDX SBOM of the runtime closure (with wheel hashes, linked Rust crates)
#   licences.json      licence gate report
#   install.sh, smoke-test.sh, prune.list, prune.sh, docker-compose.yml, compose.env.example, Dockerfile, docs/
#   BUILDINFO.json, release.pub, SHA256SUMS, SHA256SUMS.sig
#
# Environment: PYTHON (interpreter with the dev requirements: cyclonedx-bom, cryptography, rfc8785),
# UV (uv executable), RELEASE_KEY / RELEASE_KEY_PASSPHRASE (else an ephemeral key, see sign_release.py),
# WITH_IMAGES=0 (wheels-only bundle), WITH_MSSQL_DEMO=1, TSCOPE_POSTGRES_IMAGE, TSCOPE_MSSQL_IMAGE.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
PYTHON=${PYTHON:-python3}
UV=${UV:-$(command -v uv || true)}
WITH_IMAGES=${WITH_IMAGES:-1}
WITH_MSSQL_DEMO=${WITH_MSSQL_DEMO:-0}
PG_IMAGE=${TSCOPE_POSTGRES_IMAGE:-mirror.gcr.io/library/postgres:16}
MSSQL_IMAGE=${TSCOPE_MSSQL_IMAGE:-mcr.microsoft.com/mssql/server:2022-latest}
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}

version=$("$PYTHON" -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb"))["project"]["version"])' \
          "$root/pyproject.toml")
out=$root/bundle/out/tripline-scope-$version
step() { printf '\n==> %s\n' "$*"; }

step "bundle tripline-scope $version -> $out"
rm -rf "$out"
mkdir -p "$out/wheels" "$out/images" "$out/docs"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tscope-bundle.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

step "runtime wheels (binary only, verified against requirements/runtime.txt)"
"$here/fetch_wheels.sh" "$root/requirements/runtime.txt" "$out/wheels"

step "first-party wheels (built from tracked files, reproducible)"
"$here/build_wheels.sh" "$tmp/dist" >/dev/null
cp "$tmp"/dist/*.whl "$out/wheels/"

step "requirements.txt (runtime lock + first-party wheels pinned by hash)"
{
    cat "$root/requirements/runtime.txt"
    echo
    echo "# First-party wheels built from this repository (bundle only; never fetched from an index)."
    for w in "$tmp"/dist/*.whl; do
        name=$(basename "$w" | cut -d- -f1 | tr _ -)
        ver=$(basename "$w" | cut -d- -f2)
        echo "$name==$ver \\"
        echo "    --hash=sha256:$(sha256sum "$w" | cut -d' ' -f1)"
    done
} > "$out/requirements.txt"

step "clean staging venv installed offline from the bundle (for the SBOM)"
if [[ -n $UV ]]; then
    "$UV" venv --quiet --python 3.12 "$tmp/venv"
    "$UV" pip install --quiet --python "$tmp/venv/bin/python" --offline --no-index --find-links "$out/wheels" \
        --require-hashes -r "$out/requirements.txt"
else
    python3.12 -m venv "$tmp/venv"
    "$tmp/venv/bin/python" -m pip install --quiet --no-index --find-links "$out/wheels" --require-hashes \
        -r "$out/requirements.txt"
    "$tmp/venv/bin/python" -m pip uninstall --yes --quiet pip
fi
sh "$root/bundle/prune.sh" "$tmp/venv/bin/python" "$root/bundle/prune.list"

step "licence gate (the wheels exactly as shipped)"
"$PYTHON" "$here/check_licences.py" --requirements "$root/requirements/runtime.txt" --wheels "$out/wheels" \
    --native-audit "$root/requirements/native-audit.json" --json-out "$out/licences.json" --quiet

step "CycloneDX SBOM"
"$PYTHON" "$here/sbom.py" generate --python "$tmp/venv/bin/python" --wheels "$out/wheels" \
    --lock "$out/requirements.txt" --pyproject "$root/pyproject.toml" \
    --native-audit "$root/requirements/native-audit.json" --out "$out/sbom.cdx.json"
"$PYTHON" "$here/sbom.py" check --sbom "$out/sbom.cdx.json" --lock "$root/requirements/runtime.txt"

step "installer, compose and docs"
cp "$root/bundle/install.sh" "$root/bundle/smoke-test.sh" "$root/bundle/prune.list" "$root/bundle/prune.sh" \
   "$root/bundle/compose.env.example" "$root/docker-compose.yml" "$root/Dockerfile" "$out/"
chmod 0755 "$out/install.sh" "$out/smoke-test.sh" "$out/prune.sh"
cp "$root/README.md" "$out/docs/README.md"
cp "$root"/docs/*.md "$out/docs/"
cp "$root/verify/README.md" "$out/docs/VERIFY.md"

images_json="[]"
if [[ $WITH_IMAGES != 0 ]]; then
    step "app image (docker build --network none: installs only from the bundled wheels)"
    ctx=$tmp/docker-context
    mkdir -p "$ctx"
    cp -R "$out/wheels" "$ctx/wheels"
    cp "$out/requirements.txt" "$root/bundle/prune.list" "$root/bundle/prune.sh" "$root/bundle/smoke-test.sh" "$ctx/"
    docker build --quiet --network none --build-arg "TSCOPE_VERSION=$version" -t "tripline-scope:$version" \
        -f "$root/Dockerfile" "$ctx"
    docker run --rm --network none "tripline-scope:$version" --version
    docker save -o "$out/images/tripline-scope-$version.tar" "tripline-scope:$version"

    step "PostgreSQL 16 image ($PG_IMAGE, must already be present locally)"
    docker image inspect "$PG_IMAGE" >/dev/null || { echo "missing image $PG_IMAGE (docker pull it first)" >&2; exit 1; }
    docker save -o "$out/images/postgres-16.tar" "$PG_IMAGE"
    saved=("tripline-scope:$version" "$PG_IMAGE")
    if [[ $WITH_MSSQL_DEMO == 1 ]]; then
        step "SQL Server Developer Edition image (synthetic demos and tests only)"
        docker image inspect "$MSSQL_IMAGE" >/dev/null
        docker save -o "$out/images/mssql-server-developer-demo-only.tar" "$MSSQL_IMAGE"
        cat > "$out/images/MSSQL-DEVELOPER-EDITION.txt" <<'EOF'
SQL Server Developer Edition (mssql-server-developer-demo-only.tar)

Licensed by Microsoft for development, test and demonstration only, under the Microsoft EULA, which must
be accepted explicitly (TSCOPE_MSSQL_ACCEPT_EULA=Y). Tripline Scope uses it ONLY for the synthetic demo
and tests. For real cases, .bak restores go to a SQL Server instance the hospital provides and licenses,
typically its existing restore or test server. Do not restore real backups into this container.
EOF
        saved+=("$MSSQL_IMAGE")
    fi
    {
        echo "# Container images in this bundle: reference, image id, repo digest. Load with: docker load -i FILE"
        for ref in "${saved[@]}"; do
            docker image inspect "$ref" --format "$ref  {{.Id}}  {{range \$i, \$d := .RepoDigests}}{{if \$i}},{{end}}{{\$d}}{{end}}  {{.Os}}/{{.Architecture}}"
        done
        echo "# Base image of the app image: $(sed -n 's/^ARG PYTHON_IMAGE=//p' "$root/Dockerfile")"
        echo "# OS packages inside base images are aggregated system components, not linked into the product."
    } > "$out/images/IMAGES.txt"
    images_json=$(printf '%s\n' "$(ls "$out/images")" | "$PYTHON" -c 'import json,sys; print(json.dumps(sys.stdin.read().split()))')
else
    rmdir "$out/images"
fi

step "BUILDINFO.json"
git_commit=$(git -C "$root" rev-parse HEAD)
git_dirty=$([[ -z $(git -C "$root" status --porcelain --untracked-files=no) ]] && echo false || echo true)
"$PYTHON" - "$out/BUILDINFO.json" <<EOF
import json, sys
json.dump({
    "product": "tripline-scope", "version": "$version", "git_commit": "$git_commit", "git_dirty": json.loads("$git_dirty"),
    "source_date_epoch": int("$SOURCE_DATE_EPOCH"),
    "target": "CPython 3.12, x86_64 Linux, glibc >= 2.28 (venv mode) or Docker (container mode)",
    "images": $images_json, "with_mssql_demo": "$WITH_MSSQL_DEMO" == "1",
}, open(sys.argv[1], "w"), indent=2, sort_keys=True)
EOF

step "SHA256SUMS and release signature"
"$PYTHON" "$here/sign_release.py" "$out"
(cd "$out" && PYTHONPATH="$root/verify/src" "$PYTHON" -m tscope_verify checksums SHA256SUMS --sig SHA256SUMS.sig \
    --key release.pub >/dev/null)

step "done: $(du -sh "$out" | cut -f1) in $out"
du -sh "$out"/* | sed 's|'"$out"'/||'
