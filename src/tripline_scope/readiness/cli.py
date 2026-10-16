"""``tscope map``: readiness data map (draft ``datamap`` report: JSON, PDF and CSV; no values)."""

from __future__ import annotations

from tripline_scope.cli import emit
from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core.context import command
from tripline_scope.core.errors import ConfigError
from tripline_scope.core.reports import ReportStore
from tripline_scope.ingest import restores  # noqa: F401 - registers the restored-database closure hook
from tripline_scope.ingest.config import limits
from tripline_scope.ingest.pipeline import (
    check_unchanged,
    discovery_rel,
    run_discovery,
    select_sources,
    verify_sources,
)

from .datamap import build_body, render_csv, render_pdf


def cmd_map(args):
    home, case = home_of(args), case_of(args)
    lim = limits(home)
    sample = args.sample_rows or lim.sample_rows
    params = {"sources": args.source or "all", "rediscover": args.rediscover, "sample_rows": sample}
    with command("map", home=home, case=case, role="operator", params=params) as ctx:
        sources = select_sources(case, args.source)
        if not sources:
            raise ConfigError("no ingestible sources registered on this case")
        before = verify_sources(ctx, "before")
        pairs = []
        for s in sources:
            rel = discovery_rel(s["source_id"])
            if ctx.store.exists(rel) and not args.rediscover:
                doc = ctx.store.read_json(rel)
                ctx.input(f"discovery/{s['source_id']}", ctx.store.file_sha256(rel))
            else:
                doc = run_discovery(ctx, s, lim, tables=None, sample_rows=sample, batch_rows=lim.batch_rows)
            pairs.append((s, doc))
        after = verify_sources(ctx, "after")
        check_unchanged(before, after)
        rs = ReportStore(case)
        body = build_body(rs, case, pairs)
        draft = rs.save_draft("datamap", body, pdf=render_pdf(body, home.config.get("hospital_name", "")),
                              attachments={"datamap.csv": render_csv(body)})
        ctx.output("datamap/report.json", draft.report_sha256)
        ctx.note(f"source sha256 identical before and after ({len(before)} files)")
    out = {"draft_id": draft.draft_id, "version": draft.version, "report_sha256": draft.report_sha256,
           **body["totals"], "groups": {g: v["tables"] for g, v in body["summary"].items()}}
    emit(args, out, "\n".join([f"datamap draft {draft.draft_id} (version {draft.version}): {out['sources']} source(s), "
                               f"{out['tables']} table(s), {out['rows']} row(s)"]
                              + [f"  {g}: {n} table(s)" for g, n in out["groups"].items()]
                              + ["release with: tscope release --kind datamap --approver <approver>"]))


def register(sub) -> None:
    p = sub.add_parser("map", help="readiness data map: where ID, contact, medical-aid, payment and clinical "
                                   "columns live (no values)")
    add_case_arg(p)
    p.add_argument("--source", action="append", help="source id (repeatable; default: every ingestible source)")
    p.add_argument("--rediscover", action="store_true", help="run discovery again even if it already exists")
    p.add_argument("--sample-rows", type=int)
    p.set_defaults(func=cmd_map)
