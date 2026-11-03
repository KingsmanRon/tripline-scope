#!/usr/bin/env bash
# Tripline Scope — Synthetic Utility Financial-System Investigation (enterprise profile; fictional, synthetic data
# only; not a reconstruction of any real incident). One command, offline, no database container needed:
#
#   demo/enterprise-financial-incident/run.sh [--scenario a|b|c|all] [--workdir DIR] [--no-dashboard]
#
# TSCOPE_PYTHON selects the interpreter (default /opt/tscope-venv/bin/python).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PY="${TSCOPE_PYTHON:-/opt/tscope-venv/bin/python}"
exec "$PY" "$HERE/run_demo.py" "$@"
