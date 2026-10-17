"""``tscope`` command-line entry point.

Each module owns its sub-commands and exposes ``register(subparsers)``; this file only wires them together.
"""

from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import sys

from tripline_scope import __version__
from tripline_scope.core.errors import TriplineError
from tripline_scope.core.redact import install_log_scrubbing

COMMAND_MODULES = [
    "tripline_scope.cli.core_cmds",
    "tripline_scope.ingest.cli",
    "tripline_scope.exposure.cli",
    "tripline_scope.paths.cli",
    "tripline_scope.scope.cli",
    "tripline_scope.readiness.cli",
    "tripline_scope.readiness.report",
    "tripline_scope.investigator.cli",
]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tscope", description="Tripline Scope: breach scoping for SA hospitals and labs")
    p.add_argument("--version", action="version", version=f"tscope {__version__}")
    p.add_argument("--home", help="installation home (default $TSCOPE_HOME or ~/.tripline)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sub = p.add_subparsers(dest="command", required=True, metavar="COMMAND")
    for mod in COMMAND_MODULES:
        importlib.import_module(mod).register(sub)
    return p


def emit(args, payload: dict, text: str | None = None) -> None:
    """Print command output. Callers pass only counts, ids, hashes and masked values."""
    if getattr(args, "json", False):
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(text if text is not None else "\n".join(f"{k}: {v}" for k, v in payload.items()))


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=os.environ.get("TSCOPE_LOG_LEVEL", "WARNING"), format="%(levelname)s %(name)s: %(message)s")
    install_log_scrubbing()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        rc = args.func(args)
        return int(rc or 0)
    except TriplineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
