"""``tscope paths ...``: Module B access-path analysis (incident, offline).

Console output is limited to counts, ids and hashes. Every command runs inside ``core.context.command`` and is
audited; recommendations are advisory and nothing here acts on any system.
"""

from __future__ import annotations

from pathlib import Path

from tripline_scope.cli import emit
from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core.context import command


def cmd_ingest(args):
    from .ingest import run_ingest

    home, case = home_of(args), case_of(args)
    with command("paths ingest", home=home, case=case, role="operator",
                 params={"manifest": Path(args.manifest).name}) as ctx:
        summary = run_ingest(ctx, args.manifest)
    lines = [f"{s['source_id']}  {s['family']:13} events={s['events']} failures={s['parse_failures']}"
             + (f" indicators={s['indicators']}" if s.get("indicators") is not None else "")
             for s in summary["sources"]]
    lines.append(f"total events={summary['events']} parse_failures={summary['parse_failures']} "
                 f"indicators={summary['indicators']} rejected_indicators={summary['indicators_rejected']}")
    emit(args, summary, "\n".join(lines))


def register(sub) -> None:
    p = sub.add_parser("paths", help="Module B: access-path analysis from hospital-exported logs (offline)")
    ps = p.add_subparsers(dest="paths_cmd", required=True)

    q = ps.add_parser("ingest", help="register logs (custody) and normalise them into the common event schema")
    add_case_arg(q)
    q.add_argument("--manifest", required=True, help="logs.yaml (tripline.logs-manifest/v1)")
    q.set_defaults(func=cmd_ingest)
