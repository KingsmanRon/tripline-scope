"""``tscope ingest`` / ``tscope discover``: restore, classify and extract case sources.

Console output is counts, ids and hashes only. Importing this module registers the closure hook that drops
restored databases (:mod:`tripline_scope.ingest.restores`).
"""

from __future__ import annotations

import argparse

from tripline_scope.cli import emit
from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core.auth import current_identity
from tripline_scope.core.context import command
from tripline_scope.core.errors import ConfigError, PermissionDenied
from tripline_scope.core.timeutil import now_iso

from . import restores  # noqa: F401 - registers the "restored_databases" closure hook
from .config import limits, live_connection, mssql_target, pg_target
from .pipeline import (
    category_counts,
    check_unchanged,
    discovery_rel,
    ingest_source,
    manifest_rel,
    run_discovery,
    select_sources,
    status_rel,
    verify_sources,
)


def _flat(lists) -> list[str] | None:
    if not lists:
        return None
    return [x for group in lists for x in group]


def _sizes(args, home):
    lim = limits(home)
    sample = args.sample_rows if getattr(args, "sample_rows", None) else lim.sample_rows
    batch = args.batch_rows if getattr(args, "batch_rows", None) else lim.batch_rows
    if sample < 1 or batch < 1:
        raise ConfigError("--sample-rows and --batch-rows must be positive")
    return lim, sample, batch


def _sources_for(args, case):
    sources = select_sources(case, args.source)
    if not sources:
        raise ConfigError("no ingestible sources registered on this case")
    tables = _flat(args.tables)
    if tables and len(sources) != 1:
        raise ConfigError("--tables needs exactly one --source")
    return sources, tables


def _line(st: dict) -> str:
    return (f"{st['source_id']} {st['kind']}: {st['tables']} tables ({st['tables_scanned']} scanned, "
            f"{st['tables_extracted']} extracted), {st['rows']} rows, {st['extracted_rows']} rows extracted, "
            f"{st['malformed_rows']} malformed")


def cmd_ingest(args):
    home, case = home_of(args), case_of(args)
    lim, sample, batch = _sizes(args, home)
    tables = _flat(args.tables)
    params = {"sources": args.source or "all", "tables": tables, "sample_rows": sample, "batch_rows": batch}
    results = []
    with command("ingest", home=home, case=case, role="operator", params=params) as ctx:
        sources, tables = _sources_for(args, case)
        before = verify_sources(ctx, "before")
        for s in sources:
            results.append(ingest_source(ctx, s, lim, tables=tables, sample_rows=sample, batch_rows=batch))
        after = verify_sources(ctx, "after")
        check_unchanged(before, after)
        ctx.note(f"source sha256 identical before and after ({len(before)} files)")
    payload = {"sources": [{k: v for k, v in r.items()} for r in results], "source_files_verified": len(before),
               "source_checksums_unchanged": True}
    emit(args, payload, "\n".join([_line(r) for r in results]
                                  + [f"source checksums identical before and after ({len(before)} files)"]))


def cmd_discover(args):
    home, case = home_of(args), case_of(args)
    lim, sample, batch = _sizes(args, home)
    tables = _flat(args.tables)
    params = {"sources": args.source or "all", "tables": tables, "sample_rows": sample, "batch_rows": batch}
    out = []
    with command("discover", home=home, case=case, role="operator", params=params) as ctx:
        sources, tables = _sources_for(args, case)
        before = verify_sources(ctx, "before")
        for s in sources:
            doc = run_discovery(ctx, s, lim, tables=tables, sample_rows=sample, batch_rows=batch)
            out.append({"source_id": s["source_id"], **doc["totals"], "categories": category_counts(doc)})
        after = verify_sources(ctx, "after")
        check_unchanged(before, after)
        ctx.note(f"source sha256 identical before and after ({len(before)} files)")
    emit(args, {"sources": out}, "\n".join(
        f"{o['source_id']}: {o['tables']} tables, {o['rows']} rows, {o['columns']} columns; "
        + " ".join(f"{k}={v}" for k, v in o["categories"].items()) for o in out))


def _any_case_role(home, case) -> str:
    ident = current_identity(home)
    roles = case.roles_of(ident.username)
    for r in ("operator", "reviewer", "approver"):
        if r in roles:
            return r
    raise PermissionDenied("user has no role on this case")


def cmd_status(args):
    home, case = home_of(args), case_of(args)
    role = _any_case_role(home, case)
    rows = []
    with command("ingest status", home=home, case=case, role=role, params={}) as ctx:
        store = ctx.store
        for s in case.sources():
            sid = s["source_id"]
            st = store.read_json(status_rel(sid)) if store.exists(status_rel(sid)) else None
            entry = {"source_id": sid, "kind": s["kind"],
                     "discovered": store.exists(discovery_rel(sid)), "extracted": store.exists(manifest_rel(sid)),
                     "restored": restores.active(store, sid) is not None}
            if st:
                entry.update({k: st[k] for k in ("tables", "tables_extracted", "rows", "extracted_rows",
                                                 "malformed_rows")})
            rows.append(entry)
    emit(args, {"sources": rows}, "\n".join(
        f"{r['source_id']} {r['kind']:10} discovered={'yes' if r['discovered'] else 'no'} "
        f"extracted={'yes' if r['extracted'] else 'no'} restored={'yes' if r['restored'] else 'no'}"
        + (f" tables={r['tables']} rows={r['rows']} extracted_rows={r['extracted_rows']}" if "rows" in r else "")
        for r in rows) or "no sources")


def cmd_restores(args):
    home, case = home_of(args), case_of(args)
    role = _any_case_role(home, case)
    with command("ingest restores", home=home, case=case, role=role, params={}) as ctx:
        doc = restores.load(ctx.store)
    rows = [{k: e.get(k) for k in ("source_id", "engine", "instance_ref", "database", "status", "restored_at",
                                   "dropped_at", "verified_absent")} for e in doc["restores"]]
    emit(args, {"restores": rows}, "\n".join(
        f"{r['source_id']} {r['engine']:8} {r['database']} {r['status']} instance={r['instance_ref']}"
        for r in rows) or "no restored databases")


def cmd_drop(args):
    home, case = home_of(args), case_of(args)
    with command("ingest drop", home=home, case=case, role="operator", params={"source": args.source}) as ctx:
        entry = restores.active(ctx.store, args.source)
        if entry is None:
            raise ConfigError("no restored database is recorded for this source")
        e = restores.drop_entry(home, ctx.store, entry)
        ctx.output("restores.json", ctx.store.file_sha256(restores.REL))
        if not e.get("verified_absent"):
            raise ConfigError("drop could not be verified")
    emit(args, {"source_id": args.source, "database": e["database"], "status": e["status"],
                "verified_absent": e["verified_absent"]})


def cmd_targets(args):
    home = home_of(args)
    out = {}
    for engine, fn in (("mssql", mssql_target), ("postgres", pg_target)):
        try:
            t = fn(home)
        except ConfigError as exc:
            if "no " in str(exc) and "configured" in str(exc):
                continue
            raise
        info = {"instance_ref": t.instance_ref, "valid": True}
        if engine == "mssql":
            info["backup_transfer"] = t.backup_transfer
        if args.check:
            with command("ingest targets --check", home=home, role="admin", params={"engine": engine}):
                info["reachable"] = _check_target(engine, t)
        out[engine] = info
    emit(args, {"restore_targets": out}, "\n".join(
        f"{k}: instance={v['instance_ref']} valid" + (f" reachable={v['reachable']}" if "reachable" in v else "")
        for k, v in out.items()) or "no restore targets configured")


def _check_target(engine: str, t) -> bool:
    if engine == "mssql":
        from .mssql import connect

        con = connect(t, timeout=30)
        try:
            cur = con.cursor()
            cur.execute("SELECT 1")
            return cur.fetchone()[0] == 1
        finally:
            con.close()
    from .postgres import connect as pg_connect

    con = pg_connect(t, t.maintenance_db)
    try:
        return con.run("SELECT 1")[0][0] == 1
    finally:
        con.close()


def cmd_live_enable(args):
    home, case = home_of(args), case_of(args)
    params = {"source": args.source, "connection": args.connection, "databases": args.database,
              "tables": args.table, "max_rows_per_table": args.max_rows}
    with command("ingest live-enable", home=home, case=case, role="approver", params=params) as ctx:
        src = case.source(args.source)
        if src["kind"] not in ("live_mssql", "live_pg"):
            raise ConfigError("only live_mssql / live_pg sources can be enabled for live access")
        conn = live_connection(home, args.connection)
        if (conn.engine == "mssql") != (src["kind"] == "live_mssql"):
            raise ConfigError("live connection engine does not match the source kind")
        if not args.database:
            raise ConfigError("name at least one approved --database")
        live = case.config.setdefault("live_access", {})
        live[args.source] = {
            "live": True,
            "connection": args.connection,
            "databases": sorted(set(args.database)),
            "tables": sorted(set(args.table or [])),
            "max_rows_per_table": args.max_rows,
            "approved_by": ctx.actor,
            "approved_at": now_iso(),
        }
        case.save()
        ctx.output("case.yaml", case.config_sha256())
        ctx.note("live read-only access approved for a production database")
    emit(args, {"source_id": args.source, "live": True, "approved_by": live[args.source]["approved_by"]})


def cmd_live_disable(args):
    home, case = home_of(args), case_of(args)
    with command("ingest live-disable", home=home, case=case, role="approver", params={"source": args.source}) as ctx:
        live = case.config.setdefault("live_access", {})
        if args.source in live:
            live[args.source]["live"] = False
            case.save()
        ctx.output("case.yaml", case.config_sha256())
    emit(args, {"source_id": args.source, "live": False})


def _common(p) -> None:
    p.add_argument("--source", action="append", help="source id (repeatable; default: every ingestible source)")
    p.add_argument("--tables", action="append", nargs="+", help="only these tables (needs one --source)")
    p.add_argument("--sample-rows", type=int, help="rows sampled per table before classification (default 10000)")
    p.add_argument("--batch-rows", type=int, help="rows per read batch (default 50000)")


def register(sub) -> None:
    p = sub.add_parser("ingest", help="restore if needed, discover (classify columns) and extract needed columns")
    add_case_arg(p)
    _common(p)
    p.set_defaults(func=cmd_ingest)
    isub = p.add_subparsers(dest="ingest_cmd", metavar="SUBCOMMAND")
    sup = argparse.SUPPRESS

    q = isub.add_parser("status", help="per-source ingest status (counts only)")
    q.add_argument("--case", default=sup)
    q.set_defaults(func=cmd_status)
    q = isub.add_parser("restores", help="restored databases recorded for the case")
    q.add_argument("--case", default=sup)
    q.set_defaults(func=cmd_restores)
    q = isub.add_parser("drop", help="drop a source's restored database now (closure drops the rest)")
    q.add_argument("--case", default=sup)
    q.add_argument("--source", required=True, default=sup)
    q.set_defaults(func=cmd_drop)
    q = isub.add_parser("targets", help="validate restore targets (admin with --check)")
    q.add_argument("--check", action="store_true", help="connect and run a trivial query")
    q.set_defaults(func=cmd_targets)
    q = isub.add_parser("live-enable", help="approver: allow read-only live access for a live_mssql/live_pg source")
    q.add_argument("--case", default=sup)
    q.add_argument("--source", required=True, default=sup)
    q.add_argument("--connection", required=True, help="name under installation config live_connections")
    q.add_argument("--database", action="append", help="approved database (repeatable)")
    q.add_argument("--table", action="append", help="approved schema.table (repeatable; default: all in database)")
    q.add_argument("--max-rows", type=int, default=None, help="row cap per table (default ingest.live_max_rows_per_table)")
    q.set_defaults(func=cmd_live_enable)
    q = isub.add_parser("live-disable", help="approver: withdraw live access for a source")
    q.add_argument("--case", default=sup)
    q.add_argument("--source", required=True, default=sup)
    q.set_defaults(func=cmd_live_disable)

    d = sub.add_parser("discover", help="classify every column (sample, then full scan) without extracting")
    add_case_arg(d)
    _common(d)
    d.set_defaults(func=cmd_discover)
