"""``tscope exposure ...``: Module A commands.

Console output carries only counts, ids, hashes, coverage reasons and redacted locations; never a secret value,
a patient identifier or a connection string.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core.context import command
from tripline_scope.core.errors import ConfigError


def _emit(args, payload: dict, text: str) -> None:
    from tripline_scope.cli import emit

    emit(args, payload, text)


def _sev_line(by: dict) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    return ", ".join(f"{k} {by[k]}" for k in order if by.get(k))


def cmd_scan(args):
    from .scan import run_scan

    home, case = home_of(args), case_of(args)
    with command("exposure scan", home=home, case=case, role="operator",
                 params={"inputs": os.path.basename(args.inputs)}) as ctx:
        res = run_scan(ctx, Path(args.inputs))
    scan, findings = res["scan"], res["findings"]
    by_sev: dict[str, int] = {}
    by_ctl: dict[str, int] = {}
    for f in findings:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        by_ctl[f["control_id"]] = by_ctl.get(f["control_id"], 0) + 1
    cov = scan["coverage"]
    mt = scan["metrics"]
    payload = {
        "case_id": case.case_id, "scan_id": scan["scan_id"], "as_of": scan["as_of"],
        "manifest_sha256": scan["manifest_sha256"], "config_sha256": scan["config_sha256"],
        "sources": {s["unit"]: s["source_id"] for s in scan["sources"]},
        "findings": len(findings), "by_severity": by_sev, "by_control": by_ctl,
        "assessed_units": sum(len(v) for v in cov["assessed"].values()),
        "not_assessed": len(cov["not_assessed"]), "unavailable": len(cov["unavailable"]),
        "parser_failures": mt["parser_failures"], "metrics": mt,
    }
    text = "\n".join([
        f"exposure scan {scan['scan_id']} for case {case.case_id} (as of {scan['as_of']})",
        "  sources: " + ", ".join(f"{s['unit']}={s['source_id']}" for s in scan["sources"]),
        f"  findings: {len(findings)} ({_sev_line(by_sev) or 'none'})",
        "  by control: " + ", ".join(f"{k} {v}" for k, v in sorted(by_ctl.items())),
        f"  coverage: {payload['assessed_units']} units assessed, {payload['not_assessed']} not assessed, "
        f"{payload['unavailable']} unavailable; {mt['parser_failures']} parser failures",
        f"  throughput: {mt['files_examined']} files, {mt['bytes_read']} bytes in {mt['wall_seconds']} s "
        f"({mt['files_per_second']} files/s, {mt['mb_per_second']} MB/s); peak RSS {mt['peak_rss_mb']} MB",
        "  results stored encrypted under work/exposure/; build the report with 'tscope exposure report'",
    ])
    _emit(args, payload, text)


def cmd_report(args):
    from .report import build_report

    home, case = home_of(args), case_of(args)
    with command("exposure report", home=home, case=case, role="operator", params={"pdf": not args.no_pdf}) as ctx:
        draft, body = build_report(ctx, pdf=not args.no_pdf)
        ctx.output("draft_report", draft.report_sha256)
    s = body["summary"]
    payload = {"draft_id": draft.draft_id, "version": draft.version, "report_sha256": draft.report_sha256,
               "findings": s["findings"], "by_severity": s["by_severity"], "by_state": s["by_state"],
               "previous_report_sha256": body["previous_report_sha256"]}
    text = "\n".join([
        f"exposure report draft {draft.draft_id} (version {draft.version}) for case {case.case_id}",
        f"  findings: {s['findings']} ({_sev_line(s['by_severity']) or 'none'})",
        "  states: " + ", ".join(f"{k} {v}" for k, v in sorted(s["by_state"].items())),
        f"  report sha256: {draft.report_sha256}",
        "  release requires the Information Officer: tscope release --kind exposure --approver <IO>",
    ])
    _emit(args, payload, text)


def cmd_diff(args):
    from .diff import diff_reports, load_report_ref, to_csv

    if args.case:
        home, case = home_of(args), case_of(args)
        with command("exposure diff", home=home, case=case, role=None,
                     params={"from": str(args.from_ref)[:80], "to": str(args.to_ref)[:80]}) as ctx:
            a, b = load_report_ref(args.from_ref, case), load_report_ref(args.to_ref, case)
            d = diff_reports(a, b)
            ctx.input("from_report", d["from"]["report_sha256"])
            ctx.input("to_report", d["to"]["report_sha256"])
    else:
        a, b = load_report_ref(args.from_ref, None), load_report_ref(args.to_ref, None)
        d = diff_reports(a, b)
    if args.out:
        from tripline_scope.core.canonical import canonical_bytes

        Path(args.out).write_bytes(canonical_bytes(d))
    if args.csv:
        Path(args.csv).write_bytes(to_csv(d))
    s = d["summary"]
    lines = [f"exposure diff v{d['from']['version']} -> v{d['to']['version']} (case {d['to']['case_id']})",
             "  " + ", ".join(f"{k} {v}" for k, v in s.items())]
    for key in ("new", "resolved", "not_reassessed", "severity_changed"):
        for f in d[key][:50]:
            lines.append(f"  {key:15} {f['severity']:8} {f['control_id']} {f['finding_id']} {f['title'][:70]}")
    _emit(args, d if args.json else {"summary": s}, "\n".join(lines))


def cmd_catalog_sql(args):
    from .catalog_sql import script

    text = script(args.engine)
    if args.out:
        Path(args.out).write_text(text)
        _emit(args, {"written": args.out, "engine": args.engine}, f"wrote {args.out}")
    else:
        print(text)


def _tls_args(args) -> dict:
    if args.engine != "mssql" or not args.tls_cafile:
        return {}
    return {"encryption": True, "tls_cafile": args.tls_cafile, "trust_server_certificate": args.trust_server_certificate}


def cmd_collect(args):
    from tripline_scope.core.home import get_secret

    from .collect import collect

    pw = get_secret(f"Password for metadata login {args.user}", args.password_env)
    doc = collect(args.engine, host=args.host, port=args.port, user=args.user, password=pw, database=args.database,
                  timeout_s=args.timeout, max_rows=args.max_rows, **_tls_args(args))
    out = Path(args.out)
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(doc, fh, indent=1, sort_keys=True, default=str)
    _emit(args, {"written": str(out), "queries": len(doc["queries"]), "errors": sorted(doc["errors"])},
          f"wrote {out}: {len(doc['queries'])} queries, {len(doc['errors'])} unavailable ({', '.join(sorted(doc['errors'])) or 'none'})")


def cmd_synth(args):
    from .synthetic import build, build_scale_tree

    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise ConfigError("output directory exists and is not empty")
    if args.scale_files:
        m = build_scale_tree(out, args.scale_files, seed=args.seed)
        _emit(args, {"manifest": str(m)}, f"scale tree with {args.scale_files} files; manifest {m}")
        return
    gt = build(out, args.variant, seed=args.seed)
    _emit(args, {"manifest": str(out / "manifest.yaml"), "variant": gt["variant"],
                 "expected_findings": len(gt["file_findings"]) + len(gt["db_findings"])},
          f"synthetic exposure inputs ({gt['variant']}) in {out}; manifest {out / 'manifest.yaml'}")


def cmd_purge(args):
    from .scan import WORK_DIR

    home, case = home_of(args), case_of(args)
    with command("exposure purge", home=home, case=case, role="operator") as ctx:
        store = ctx.store
        rels = store.list(WORK_DIR)
        for rel in rels:
            store.delete(rel)
        ctx.note(f"purged {len(rels)} exposure working files; released reports retain findings, counts, source "
                 "fingerprints and configuration")
    _emit(args, {"purged": len(rels)}, f"purged {len(rels)} exposure working files (released reports are kept)")


def register(sub) -> None:
    e = sub.add_parser("exposure", help="Module A: offline exposure scan (readiness)").add_subparsers(
        dest="exposure_cmd", required=True)
    p = e.add_parser("scan", help="scan the inputs declared in a manifest (writes encrypted results)")
    add_case_arg(p)
    p.add_argument("--inputs", required=True, help="tripline.exposure-manifest/v1 YAML")
    p.set_defaults(func=cmd_scan)
    p = e.add_parser("report", help="build a ranked JSON/PDF draft report from the latest scan")
    add_case_arg(p)
    p.add_argument("--no-pdf", action="store_true")
    p.set_defaults(func=cmd_report)
    p = e.add_parser("diff", help="compare two exposure reports (new / resolved / persisting)")
    add_case_arg(p)
    p.add_argument("--from", dest="from_ref", required=True, help="report.json, version dir, or vN/draft with --case")
    p.add_argument("--to", dest="to_ref", required=True)
    p.add_argument("--out", help="write the diff as canonical JSON")
    p.add_argument("--csv", help="write the diff as CSV")
    p.set_defaults(func=cmd_diff)
    p = e.add_parser("catalog-sql", help="print the read-only catalogue queries for the DBA")
    p.add_argument("--engine", choices=["mssql", "postgres"], required=True)
    p.add_argument("--out")
    p.set_defaults(func=cmd_catalog_sql)
    p = e.add_parser("collect-catalog", help="run the catalogue queries over a metadata-only read-only login")
    p.add_argument("--engine", choices=["mssql", "postgres"], required=True)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--user", required=True)
    p.add_argument("--database", required=True)
    p.add_argument("--password-env", default="TSCOPE_CATALOG_PASSWORD")
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--max-rows", type=int, default=200_000)
    p.add_argument("--tls-cafile", help="SQL Server: encrypt and verify the server against this CA/certificate")
    p.add_argument("--trust-server-certificate", action="store_true", help="SQL Server: skip the host-name check")
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_collect)
    p = e.add_parser("synth", help="write synthetic Module A inputs (tests, drills, demo)")
    p.add_argument("--out", required=True)
    p.add_argument("--variant", choices=["baseline", "fixed"], default="baseline")
    p.add_argument("--seed", type=int, default=20261001)
    p.add_argument("--scale-files", type=int, default=0)
    p.set_defaults(func=cmd_synth)
    p = e.add_parser("purge", help="delete exposure working files (released reports are kept)")
    add_case_arg(p)
    p.set_defaults(func=cmd_purge)
