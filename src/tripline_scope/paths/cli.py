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


def _window(args, case):
    from .timenorm import parse_window

    if args.window:
        return parse_window(args.window)
    iw = case.config.get("incident_window") or {}
    if not (iw.get("start") and iw.get("end")):
        from tripline_scope.core.errors import ConfigError

        raise ConfigError("give --window START/END (the case has no incident window)")
    return parse_window(f"{iw['start']}/{iw['end']}")


def cmd_analyse(args):
    from .analyse import run_analysis

    home, case = home_of(args), case_of(args)
    win = _window(args, case)
    with command("paths analyse", home=home, case=case, role="operator",
                 params={"window": f"{win[0].isoformat()}/{win[1].isoformat()}"}) as ctx:
        res = run_analysis(ctx, win)
    cls = {}
    for t in res["tables"]:
        k = t["consequence_class"] or "no_access_observed"
        cls[k] = cls.get(k, 0) + 1
    out = {"events": res["events_total"], "paths": len(res["paths"]), "edges": len(res["edges"]),
           "direct_edges": sum(1 for e in res["edges"] if e["label"] == "direct"),
           "correlated_edges": sum(1 for e in res["edges"] if e["label"] == "correlated"),
           "anomalies": len(res["anomalies"]), "gaps": len(res["gaps"]), "indicator_matches": res["indicator_match_total"],
           "sensitive_tables_by_class": dict(sorted(cls.items())), "analysis_sha256": res["_sha256"]}
    emit(args, out)


def register(sub) -> None:
    p = sub.add_parser("paths", help="Module B: access-path analysis from hospital-exported logs (offline)")
    ps = p.add_subparsers(dest="paths_cmd", required=True)

    q = ps.add_parser("ingest", help="register logs (custody) and normalise them into the common event schema")
    add_case_arg(q)
    q.add_argument("--manifest", required=True, help="logs.yaml (tripline.logs-manifest/v1)")
    q.set_defaults(func=cmd_ingest)

    q = ps.add_parser("analyse", aliases=["analyze"], help="reconstruct access paths, gaps and anomalies for a window")
    add_case_arg(q)
    q.add_argument("--window", help="START/END in ISO-8601 with zone (default: the case incident window)")
    q.set_defaults(func=cmd_analyse)
