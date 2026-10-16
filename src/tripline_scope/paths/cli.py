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


def cmd_report(args):
    from .report import build

    home, case = home_of(args), case_of(args)
    measures = None
    if args.measures:
        text = Path(args.measures).read_text(encoding="utf-8")
        measures = [ln.strip("-* \t") for ln in text.splitlines() if ln.strip()]
    with command("paths report", home=home, case=case, role="operator",
                 params={"exposure_report": bool(args.exposure_report), "measures": bool(args.measures),
                         "timeline_rows": args.timeline_rows}) as ctx:
        res = build(ctx, exposure_report=args.exposure_report, measures=measures, timeline_rows=args.timeline_rows)
    emit(args, {k: res[k] for k in ("draft_id", "version", "report_sha256", "paths", "recommendations",
                                     "timeline_rows", "timeline_truncated")})


def cmd_candidates(args):
    from tripline_scope.core.canonical import canonical_bytes, sha256_hex

    from .candidates import build_candidates

    home, case = home_of(args), case_of(args)
    with command("paths scope-candidates", home=home, case=case, role="operator",
                 params={"out": Path(args.out).name if args.out else None}) as ctx:
        doc = build_candidates(case, ctx.store)
        data = canonical_bytes(doc)
        ctx.output("scope_candidates", ctx.store.write_bytes("work/paths/scope_candidates.json", data))
        if args.out:
            Path(args.out).write_bytes(data)
    emit(args, {"coverage_status": doc["coverage_status"], "tables": len(doc["tables"]), **doc["counts"],
                "sha256": sha256_hex(data), "out": args.out})


def cmd_config(args):
    import yaml

    from tripline_scope.core.errors import ConfigError

    from .config import DEFAULTS, _merge, config_sha256, load_config, validate

    home, case = home_of(args), case_of(args)
    if args.file:
        doc = yaml.safe_load(Path(args.file).read_text()) or {}
        if not isinstance(doc, dict):
            raise ConfigError("paths settings file must be a mapping")
        doc = doc.get("paths", doc)
        validate(_merge(DEFAULTS, doc))
        with command("paths config", home=home, case=case, role="operator", params={"keys": sorted(doc)}) as ctx:
            case.config["paths"] = doc
            case.save()
            ctx.output("case.yaml", case.config_sha256())
    cfg = load_config(case)
    emit(args, {"config_sha256": config_sha256(cfg), "sensitive_table_patterns": len(cfg["sensitive_tables"]),
                "keys_set": sorted((case.config.get("paths") or {}).keys())})


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

    q = ps.add_parser("report", help="draft the signed-report body, PDF and bounded timeline (release with tscope release)")
    add_case_arg(q)
    q.add_argument("--exposure-report", help="Module A exposure report.json (or its version directory) to cross-reference")
    q.add_argument("--measures", help="text file: measures taken by the hospital, one per line (regulator summary)")
    q.add_argument("--timeline-rows", type=int, help="row cap for timeline.csv/jsonl (default case.yaml paths.timeline_max_rows)")
    q.set_defaults(func=cmd_report)

    q = ps.add_parser("scope-candidates", help="export candidate table/time constraints for Module C (JSON)")
    add_case_arg(q)
    q.add_argument("--out", help="also write the JSON here (it is always stored encrypted in the case)")
    q.set_defaults(func=cmd_candidates)

    q = ps.add_parser("config", help="show or set the case.yaml paths settings (sensitive tables, windows, hours...)")
    add_case_arg(q)
    q.add_argument("--file", help="YAML file with the paths settings to store in case.yaml")
    q.set_defaults(func=cmd_config)
