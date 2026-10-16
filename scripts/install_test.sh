#!/usr/bin/env bash
# Offline install proof for a built bundle.
#
#   install_test.sh venv      [BUNDLE_DIR]   clean python:3.12-slim container started with --network none:
#                                            install.sh (venv mode), then smoke-test.sh --require-offline
#   install_test.sh container [BUNDLE_DIR]   install.sh --mode container on this host (docker load + compose
#                                            files), then the stack on an internal-only network: PostgreSQL 16
#                                            + the app container running smoke-test.sh, a probe proving the app
#                                            reaches PostgreSQL but nothing off the host; then everything is
#                                            removed again
#
# What this proves: a clean container with no network can install and run from the bundle. It is not a
# clean-VM install; see README "Offline install" for that procedure.
#
# Env: PY_IMAGE (default the digest-pinned base image from the Dockerfile), COMPOSE_PROJECT (tscope-pkg),
#      TSCOPE_TEST_PG_PORT (15445).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
mode=${1:?usage: install_test.sh venv|container [BUNDLE_DIR]}
bundle=${2:-$(ls -d "$root"/bundle/out/tripline-scope-* | sort | tail -1)}
bundle=$(cd "$bundle" && pwd)
PY_IMAGE=${PY_IMAGE:-$(sed -n 's/^ARG PYTHON_IMAGE=//p' "$root/Dockerfile")}
key_id=$(openssl pkey -pubin -in "$bundle/release.pub" -outform DER | tail -c 32 | sha256sum | cut -c1-32)
version=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$bundle/BUILDINFO.json" | head -1)
echo "bundle $bundle (version $version, release key id $key_id)"

if [[ $mode == venv ]]; then
    docker image inspect "$PY_IMAGE" >/dev/null 2>&1 || { echo "base image $PY_IMAGE not present" >&2; exit 2; }
    docker run --rm --network none -v "$bundle:/bundle:ro" -e KEY_ID="$key_id" "$PY_IMAGE" bash -euo pipefail -c '
        echo "--- interfaces: $(awk -F: "NR>2{print \$1}" /proc/net/dev | tr -d " " | tr "\n" " ")"
        python3 -c "import socket
try:
    socket.create_connection((\"1.1.1.1\", 443), timeout=3); print(\"NETWORK REACHABLE\"); raise SystemExit(1)
except OSError as e: print(\"--- no route off the container:\", type(e).__name__)"
        bash /bundle/install.sh --release-key-id "$KEY_ID" --mode venv --prefix /opt/tripline-scope \
            --bin-dir /usr/local/bin
        bash /opt/tripline-scope/share/smoke-test.sh /opt/tripline-scope --require-offline
        tscope --version && tscope-verify --help >/dev/null && echo "--- linked commands on PATH work"
    '
    echo "VENV-MODE OFFLINE INSTALL: PASS"
    exit 0
fi

[[ $mode == container ]] || { echo "unknown mode $mode" >&2; exit 2; }
project=${COMPOSE_PROJECT:-tscope-pkg}
work=$(mktemp -d "${TMPDIR:-/tmp}/tscope-container-test.XXXXXX")
cleanup() {
    (cd "$work/prefix/compose" 2>/dev/null && docker compose -p "$project" --profile cli down -v --remove-orphans \
        >/dev/null 2>&1) || true
    rm -rf "$work"
}
trap cleanup EXIT
bash "$bundle/install.sh" --release-key-id "$key_id" --mode container --prefix "$work/prefix"
cd "$work/prefix/compose"
mkdir -p cases sources kek restore-inbox
chown 10001:10001 cases kek 2>/dev/null || chmod 0777 cases kek
password=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
sed -i -e "s|^TSCOPE_PG_PASSWORD=.*|TSCOPE_PG_PASSWORD=$password|" \
       -e "s|^TSCOPE_PG_PORT=.*|TSCOPE_PG_PORT=${TSCOPE_TEST_PG_PORT:-15445}|" \
       -e "s|^TSCOPE_NETWORK_INTERNAL=.*|TSCOPE_NETWORK_INTERNAL=true|" .env
dc() { docker compose -p "$project" "$@"; }
[[ $(dc config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["networks"]["backend"]["internal"])') == True ]]
echo "--- backend network is internal (no route off the host)"
dc up -d --wait postgres
dc run --rm --entrypoint bash tscope /opt/tripline/share/smoke-test.sh
dc run --rm --entrypoint python tscope -c '
import os, socket, pg8000.native
c = pg8000.native.Connection(user=os.environ["TSCOPE_PG_USER"], password=os.environ["TSCOPE_PG_PASSWORD"],
                             host="postgres", database="restores")
print("--- app container reached PostgreSQL:", c.run("select version()")[0][0].split(",")[0])
c.close()
for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
    try:
        socket.create_connection((host, port), timeout=3)
        raise SystemExit(f"NETWORK REACHABLE: {host}:{port}")
    except OSError as e:
        print(f"--- {host}:{port} unreachable from the app container ({type(e).__name__})")
'
echo "CONTAINER-MODE INSTALL ON INTERNAL NETWORK: PASS"
