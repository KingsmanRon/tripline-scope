#!/usr/bin/env bash
# Installation qualification for Tripline Scope. Synthetic and throw-away: everything happens in a fresh
# temporary directory (its own installation home, KEK, users and case) that is deleted afterwards. It does
# not touch the real installation or any patient data, and it needs no network.
#
#   smoke-test.sh [PREFIX] [--require-offline]
#
# PREFIX is the install prefix of a venv install (uses PREFIX/venv/bin); without it, tscope on PATH is used
# (container: docker compose run --rm --entrypoint bash tscope /opt/tripline/share/smoke-test.sh).
set -euo pipefail
bin="" require_offline=0
for a in "$@"; do
    case $a in
        --require-offline) require_offline=1 ;;
        *) bin="$a/venv/bin/" ;;
    esac
done
TSCOPE="${bin}tscope"
VERIFY="${bin}tscope-verify"
PY="${bin}python"
command -v "$PY" >/dev/null || PY=python3

ifaces=$(awk -F: 'NR > 2 {gsub(/ /, "", $1); print $1}' /proc/net/dev | tr '\n' ' ')
echo "network interfaces visible: ${ifaces:-none}"
if [[ $require_offline == 1 && -n ${ifaces// /} && ${ifaces// /} != "lo" ]]; then
    echo "ERROR: --require-offline but non-loopback interfaces are present: $ifaces" >&2
    exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/tscope-smoke.XXXXXX")
trap 'rm -rf "$work"' EXIT
export TSCOPE_HOME="$work/home" TSCOPE_SESSION_FILE="$work/session.token"
export TSCOPE_KEK_PASSPHRASE="smoke-kek-passphrase" TSCOPE_HOSPITAL_KEY_PASSPHRASE="smoke-signing-passphrase"
export TSCOPE_PASSWORD="Smoke-Test-Pass-2026!" TSCOPE_NEW_USER_PASSWORD="Smoke-Test-Pass-2026!"
export TSCOPE_APPROVER_PASSWORD="Smoke-Test-Pass-2026!"
export OTEL_SDK_DISABLED=true
case_dir="$work/case"

step() { printf '+ %s\n' "$*"; "$@"; }

step "$TSCOPE" --version
step "$VERIFY" --help >/dev/null
step "$TSCOPE" init --hospital-name "Installation Qualification" --admin admin --kek "$work/kek/kek.json"
step "$TSCOPE" login --user admin
for u in olivia rami ines; do step "$TSCOPE" user add "$u"; done
step "$TSCOPE" user list
step "$TSCOPE" case init "$case_dir" --case-id SMOKE-001 --mode incident --operator olivia --reviewer rami \
    --approver ines --incident-start 2026-01-01T00:00:00Z --incident-end 2026-01-02T00:00:00Z

mkdir -p "$work/source"
printf 'sample_ref,test_code,result\nS-0001,FBC,normal\nS-0002,HBA1C,raised\n' > "$work/source/sample.csv"
chmod a-w "$work/source/sample.csv"
before=$(sha256sum "$work/source/sample.csv")

step "$TSCOPE" login --user olivia
step "$TSCOPE" source add --case "$case_dir" --kind csv --path "$work/source/sample.csv" --label "smoke sample" \
    --evidence-role leak_sample --legal-basis "installation qualification (synthetic data)" \
    --supplied-by "hospital IT" --received-at 2026-01-01T08:00:00Z
step "$TSCOPE" source verify --case "$case_dir" --full
step "$TSCOPE" audit verify --case "$case_dir"
step "$TSCOPE" verify --case "$case_dir"
step "$VERIFY" audit "$case_dir/audit.log"

after=$(sha256sum "$work/source/sample.csv")
[[ $before == "$after" ]] || { echo "ERROR: source file changed" >&2; exit 1; }
echo "+ source unchanged: ${after%% *}"

# PDF rendering works with the pruned reportlab (standard fonts only), and the pruned files are gone.
step "$PY" - <<'EOF'
import sysconfig
from pathlib import Path
from tripline_scope.core.pdf import Section, pdf_text, render
pdf = render("Installation qualification", ["synthetic"], [Section("Check", ["PDF rendering works offline."])])
assert pdf.startswith(b"%PDF") and "PDF rendering works offline." in pdf_text(pdf)
fonts = Path(sysconfig.get_paths()["purelib"]) / "reportlab" / "fonts"
left = sorted(p.name for p in fonts.glob("DarkGarden*")) + sorted(p.name for p in fonts.glob("*.pfb"))
assert not left, f"pruned files still present: {left}"
print("+ PDF rendering ok; pruned font data absent")
EOF
echo "SMOKE TEST PASSED"
