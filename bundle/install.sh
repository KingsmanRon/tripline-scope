#!/usr/bin/env bash
# Tripline Scope offline installer. Run it from the unpacked bundle directory. It never uses the network.
#
#   ./install.sh --release-key-id KEYID [--mode venv|container|both] [--prefix DIR] [--bin-dir DIR]
#
#   --release-key-id ID   the vendor's release key id, obtained OUT OF BAND (handover letter / phone). The
#                         bundle's release.pub is only trusted if its id matches. Alternatives:
#                         --release-key FILE (a trusted copy of release.pub) or, for test builds only,
#                         --trust-bundled-key.
#   --mode                venv (default): Python 3.12 virtualenv on this host
#                         container: docker load the images and install docker-compose.yml + .env template
#                         both: both of the above
#   --prefix DIR          install location (default /opt/tripline-scope)
#   --bin-dir DIR         also link tscope and tscope-verify into DIR (e.g. /usr/local/bin)
#   --verifier CMD        verify the signature with an already trusted tscope-verify when OpenSSL 3 is missing
#   --no-signature-check  skip the signature check (NOT for production; verify on another machine first)
#
# Order: (1) every file against SHA256SUMS, (2) the Ed25519 release signature over SHA256SUMS, before any
# bundled code runs, (3) install with pip --no-index --require-hashes (venv) and/or docker load (container),
# (4) delete unused font data listed in prune.list, (5) quick self-checks.
set -euo pipefail
cd "$(dirname "$0")"
BUNDLE=$(pwd)

mode=venv prefix=/opt/tripline-scope bin_dir="" key_id="" key_file="" trust_bundled=0 verifier="" nosig=0
while [[ $# -gt 0 ]]; do
    case $1 in
        --mode) mode=$2; shift 2 ;;
        --prefix) prefix=$2; shift 2 ;;
        --bin-dir) bin_dir=$2; shift 2 ;;
        --release-key-id) key_id=$2; shift 2 ;;
        --release-key) key_file=$2; shift 2 ;;
        --trust-bundled-key) trust_bundled=1; shift ;;
        --verifier) verifier=$2; shift 2 ;;
        --no-signature-check) nosig=1; shift ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done
case $mode in venv|container|both) ;; *) echo "--mode must be venv, container or both" >&2; exit 2 ;; esac

say() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ------------------------------------------------------------------------------------------- 1. integrity
say "checking every file against SHA256SUMS"
sha256sum --check --quiet --strict SHA256SUMS || die "bundle files do not match SHA256SUMS"
listed=$(cut -d' ' -f3- SHA256SUMS | sort)
present=$(find . -type f ! -name SHA256SUMS ! -name SHA256SUMS.sig | sed 's|^\./||' | sort)
[[ "$listed" == "$present" ]] || die "bundle contains files not listed in SHA256SUMS (or misses some)"

# ------------------------------------------------------------------------------------------- 2. signature
pub=release.pub
if [[ -n $key_file ]]; then
    cmp -s "$key_file" release.pub || die "bundled release.pub differs from the trusted key $key_file"
    pub=$key_file
fi
raw_key_id() {  # key id = first 32 hex chars of SHA-256 over the raw 32-byte Ed25519 public key
    openssl pkey -pubin -in "$1" -outform DER 2>/dev/null | tail -c 32 | sha256sum | cut -c1-32
}
have_openssl3() { command -v openssl >/dev/null && [[ $(openssl version | awk '{print $2}') =~ ^[3-9]\. ]]; }

if [[ $nosig == 1 ]]; then
    printf '\n!!! WARNING: release signature NOT checked (--no-signature-check). Verify SHA256SUMS.sig on a\n!!! trusted machine with: tscope-verify checksums SHA256SUMS --sig SHA256SUMS.sig --key release.pub\n\n' >&2
elif have_openssl3; then
    actual_id=$(raw_key_id "$pub")
    if [[ -n $key_id ]]; then
        [[ $actual_id == "$key_id" ]] || die "release key id $actual_id does not match the expected $key_id"
    elif [[ -z $key_file && $trust_bundled == 0 ]]; then
        die "release key id is $actual_id. Compare it with the id the vendor gave you out of band, then re-run with --release-key-id $actual_id"
    fi
    sigb64=$(sed -n 's/.*"signature":"\([A-Za-z0-9+/=]*\)".*/\1/p' SHA256SUMS.sig)
    grep -q '"role":"release"' SHA256SUMS.sig && grep -q '"signed_file":"SHA256SUMS"' SHA256SUMS.sig \
        || die "SHA256SUMS.sig is not a release signature over SHA256SUMS"
    tmpsig=$(mktemp)
    trap 'rm -f "$tmpsig"' EXIT
    printf '%s' "$sigb64" | base64 -d > "$tmpsig"
    openssl pkeyutl -verify -pubin -inkey "$pub" -rawin -in SHA256SUMS -sigfile "$tmpsig" >/dev/null \
        || die "release signature over SHA256SUMS is INVALID"
    say "release signature valid (Ed25519, key id $actual_id, checked with $(openssl version | cut -d' ' -f1-2))"
elif [[ -n $verifier ]]; then
    args=(checksums SHA256SUMS --sig SHA256SUMS.sig --key "$pub")
    "$verifier" "${args[@]}" || die "release signature check failed"
else
    die "OpenSSL 3 not found: verify with a trusted tscope-verify (--verifier PATH) or on another machine"
fi

# ------------------------------------------------------------------------------------------- 3. install
version=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' BUILDINFO.json | head -1)
install_venv() {
    local py
    py=$(command -v python3.12 || command -v python3 || true)
    [[ -n $py ]] || die "Python 3.12 is required for venv mode (or use --mode container)"
    "$py" -c 'import sys; sys.exit(0 if sys.version_info[:2] == (3, 12) else 1)' \
        || die "Python 3.12 is required for venv mode; found $("$py" -V 2>&1)"
    "$py" -c 'import ensurepip, venv' 2>/dev/null || die "the Python venv module is missing (Debian/Ubuntu: python3.12-venv)"
    say "creating virtualenv $prefix/venv"
    mkdir -p "$prefix"
    "$py" -m venv "$prefix/venv"
    say "installing $(ls wheels/*.whl | wc -l) wheels offline (--no-index --require-hashes)"
    PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_INPUT=1 "$prefix/venv/bin/python" -m pip install --quiet \
        --no-index --no-cache-dir --require-hashes --find-links "$BUNDLE/wheels" -r "$BUNDLE/requirements.txt"
    sh "$BUNDLE/prune.sh" "$prefix/venv/bin/python" "$BUNDLE/prune.list"
    # Environment for the service account (source it: set -a; . tripline.env; set +a). It also disables any
    # OpenTelemetry SDK that could ever be present (none is installed).
    cat > "$prefix/tripline.env" <<'EOF'
TSCOPE_HOME=/var/lib/tripline
OTEL_SDK_DISABLED=true
OTEL_TRACES_EXPORTER=none
OTEL_METRICS_EXPORTER=none
OTEL_LOGS_EXPORTER=none
EOF
    mkdir -p "$prefix/share"
    cp -R "$BUNDLE/docs" "$prefix/share/" 2>/dev/null || true
    cp "$BUNDLE/smoke-test.sh" "$BUNDLE/release.pub" "$BUNDLE/BUILDINFO.json" "$prefix/share/"
    if [[ -n $bin_dir ]]; then
        mkdir -p "$bin_dir"
        ln -sf "$prefix/venv/bin/tscope" "$bin_dir/tscope"
        ln -sf "$prefix/venv/bin/tscope-verify" "$bin_dir/tscope-verify"
    fi
    "$prefix/venv/bin/tscope" --version
    "$prefix/venv/bin/tscope-verify" checksums SHA256SUMS --sig SHA256SUMS.sig --key "$pub" >/dev/null \
        || die "installed tscope-verify disagrees with the bundle checksums"
    say "venv install complete: $prefix/venv/bin/tscope"
}

install_container() {
    command -v docker >/dev/null || die "docker is required for container mode"
    docker compose version >/dev/null 2>&1 || die "the docker compose plugin is required for container mode"
    for img in images/*.tar; do
        [[ $img == *mssql* ]] && say "loading $img (SQL Server Developer Edition: synthetic demos/tests only)"
        say "docker load -i $img"
        docker load -i "$img" | sed 's/^/    /'
    done
    mkdir -p "$prefix/compose"
    cp docker-compose.yml "$prefix/compose/"
    [[ -f $prefix/compose/.env ]] || { cp compose.env.example "$prefix/compose/.env"; chmod 600 "$prefix/compose/.env"; }
    sed -i "s|^TSCOPE_IMAGE=.*|TSCOPE_IMAGE=tripline-scope:${version}|" "$prefix/compose/.env"
    docker run --rm --network none "tripline-scope:${version}" --version
    say "container install complete: edit $prefix/compose/.env (set TSCOPE_PG_PASSWORD), then"
    say "  cd $prefix/compose && docker compose up -d postgres && docker compose run --rm tscope --help"
}

case $mode in
    venv) install_venv ;;
    container) install_container ;;
    both) install_venv; install_container ;;
esac
say "next: read docs/README.md (operator runbook), then run 'tscope init' (see 'Offline install')."
