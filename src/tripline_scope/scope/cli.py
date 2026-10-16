"""CLI for Module C (``tscope estimate``, ``tscope scope ...``) plus ``tscope synth``, ``tscope profile`` and
``tscope drill`` (registered here so the readiness CLI stays untouched).

Command output is counts, hashes and ids only.
"""

from __future__ import annotations

import json
from pathlib import Path

from tripline_scope.cli import emit
from tripline_scope.cli.common import add_approver_args, add_case_arg, approver_sign_in, case_of, home_of
from tripline_scope.core.context import command
from tripline_scope.core.errors import ConfigError, PermissionDenied
from tripline_scope.core.reports import register_release_hook

from . import config as C

_HOOKED = False


def _hook() -> None:
    global _HOOKED
    if not _HOOKED:
        from .notify import on_release

        register_release_hook("scope", on_release)
        _HOOKED = True


_hook()


def _cfg(case, args):
    return C.load(case, getattr(args, "config", None))


def _provider(home, args):
    return home.provider_signer() if getattr(args, "provider_sign", False) else None


# ------------------------------------------------------------------------------------------------ estimate
def cmd_estimate(args):
    from . import report as REP
    from . import run as R

    home, case = home_of(args), case_of(args)
    with command("scope estimate", home=home, case=case, role="operator",
                 params={"config_file": bool(args.config), "threads": args.threads}) as ctx:
        cfg = _cfg(case, args)
        store = ctx.store
        out = R.run_estimate(case, store, cfg, threads=args.threads)
        for sid, h in out["extract_manifests_sha256"].items():
            ctx.input(f"extract/{sid}", h)
        ctx.output("estimate.json", store.file_sha256(R.ESTIMATE))
        body, pdf, att = REP.build_estimate_report(case, store)
        draft = REP.save(case, store, body, pdf, att, provider=_provider(home, args))
        ctx.output("scope_draft", draft.report_sha256)
    e = out["estimate"]
    emit(args, {"report_status": "preliminary", "draft": draft.draft_id, "version": draft.version,
                "people_estimate": e["point"], "lower": e["lower"], "upper": e["upper"],
                "unresolvable_rows": sum(out["unresolvable"].values())},
         f"PRELIMINARY estimate: about {e['point']} people (bounds {e['lower']}-{e['upper']}); "
         f"draft scope report v{draft.version} {draft.draft_id}")


# ------------------------------------------------------------------------------------------------ match
def cmd_match(args):
    from . import run as R

    home, case = home_of(args), case_of(args)
    with command("scope match", home=home, case=case, role="operator",
                 params={"config_file": bool(args.config), "threads": args.threads}) as ctx:
        cfg = _cfg(case, args)
        store = ctx.store
        summary, _ = R.run_match(case, store, cfg, threads=args.threads)
        for sid, h in summary["extract_manifests_sha256"].items():
            ctx.input(f"extract/{sid}", h)
        ctx.input("review_decisions", summary["review_decisions_sha256"])
        for rel in (R.MATCH, R.PEOPLE, R.PERSON_TABLES, R.PERSON_ROWS, "review/queue.json"):
            ctx.output(rel.split("/")[-1], store.file_sha256(rel))
    rq = summary["review_queue"]
    emit(args, {"people": summary["people"], "people_lower_bound": summary["people_lower_bound"],
                "review_items": rq["items"], "config_sha256": summary["config_sha256"],
                "review_decisions": summary["review_decisions"]["count"], "timings_s": summary["timings_s"]},
         f"people: {summary['people']} (lower bound {summary['people_lower_bound']}); review items pending: {rq['items']}")


# ------------------------------------------------------------------------------------------------ review & decide
def cmd_review(args):
    from .review_app import serve

    home, case = home_of(args), case_of(args)
    with command("scope review start", home=home, case=case, role=None, params={"port": args.port}) as ctx:
        roles = case.roles_of(ctx.actor)
        if not roles & {"reviewer", "operator"}:
            raise PermissionDenied("starting the review page needs the reviewer or operator role on this case")
        store = ctx.store
    serve(case, store, home, port=args.port)


def cmd_decide(args):
    from . import decisions as DEC

    home, case = home_of(args), case_of(args)
    if bool(args.file) == bool(args.simulate_reviewer):
        raise ConfigError("pass exactly one of --file or --simulate-reviewer")
    params = {"via": "file" if args.file else "simulated"}
    with command("scope decide", home=home, case=case, role="reviewer", params=params) as ctx:
        store = ctx.store
        queue = {q["pair_key"]: q for q in DEC.load_queue(store)}
        entries = []
        if args.file:
            for n, line in enumerate(Path(args.file).read_text().splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    raise ConfigError(f"line {n}: not JSON") from None
                item = queue.get(d.get("pair_key"))
                if item is None:
                    raise ConfigError(f"line {n}: pair is not in the current review queue")
                entries.append(DEC.entry(item, d.get("decision"), ctx.actor, "file"))
        else:
            from .simulate import simulate_decisions

            entries = simulate_decisions(case, store, _cfg(case, args), list(queue.values()),
                                         Path(args.simulate_reviewer), ctx.actor)
            ctx.note("decisions simulated from synthetic ground truth (drill/demo only)")
        n = DEC.append(store, entries)
        ctx.output("decisions.jsonl", store.file_sha256(DEC.DECISIONS) if n else "")
        ctx.params["decisions"] = n
    emit(args, {"recorded": n, "simulated": bool(args.simulate_reviewer),
                "same": sum(1 for e in entries if e["decision"] == "same"),
                "different": sum(1 for e in entries if e["decision"] == "different"),
                "skipped": sum(1 for e in entries if e["decision"] == "skip")},
         f"recorded {n} decision(s){' (simulated)' if args.simulate_reviewer else ''}; re-run 'tscope scope match'")


def cmd_queue(args):
    from . import decisions as DEC

    home, case = home_of(args), case_of(args)
    with command("scope queue", home=home, case=case, role=None, params={}) as ctx:
        if not case.roles_of(ctx.actor):
            raise PermissionDenied("not a member of this case")
        q = DEC.load_queue(ctx.store)
    emit(args, {"pending": len(q), "review_band": sum(1 for x in q if x["reason"] == "review_band"),
                "over_merge_guard": sum(1 for x in q if x["reason"] == "over_merge_guard")})


# ------------------------------------------------------------------------------------------------ constrain
def cmd_constrain(args):
    from . import constrain as K

    home, case = home_of(args), case_of(args)
    raw = Path(args.candidates).read_bytes() if args.candidates else None
    params = {"candidates": bool(raw), "widen": args.widen or [], "widen_all": args.widen_all,
              "ignore_time_windows": args.ignore_time_windows, "clear": args.clear, "reason": args.reason}
    with command("scope constrain", home=home, case=case, role="operator", params=params) as ctx:
        if raw is not None:
            from tripline_scope.core.canonical import sha256_hex

            ctx.input("scope_candidates", sha256_hex(raw))
        entry = K.record(ctx.store, candidates_raw=raw, reason=args.reason, actor=ctx.actor, widen=args.widen or [],
                         widen_all=args.widen_all, ignore_time_windows=args.ignore_time_windows, clear=args.clear)
        ctx.output("scoping_decisions.json", ctx.store.file_sha256(K.DECISIONS))
    emit(args, {"decision_id": entry["decision_id"], "kind": entry["kind"],
                "note": "recorded; the next 'tscope scope report' shows candidate and full-scope counts. Absent or "
                        "uncertain logs never narrow the notification proposal."})


# ------------------------------------------------------------------------------------------------ report
def cmd_report(args):
    from . import report as REP
    from . import run as R

    home, case = home_of(args), case_of(args)
    with command("scope report", home=home, case=case, role="operator", params={"provider": args.provider_sign}) as ctx:
        store = ctx.store
        if not store.exists(R.MATCH):
            raise ConfigError("no match results: run 'tscope scope match' first (or 'tscope estimate')")
        ctx.input("match.json", store.file_sha256(R.MATCH))
        body, pdf, att = REP.build_match_report(case, store, home=home)
        draft = REP.save(case, store, body, pdf, att, provider=_provider(home, args))
        ctx.output("scope_draft", draft.report_sha256)
    c = body["counts"]
    emit(args, {"draft": draft.draft_id, "version": draft.version, "report_sha256": draft.report_sha256,
                "unique_people": c["unique_people"], "minors": c["minors"]["total"],
                "without_contact_details": c["without_contact_details"]["total"],
                "simulated_review": body["review_decisions_simulated"]},
         f"draft scope report v{draft.version} {draft.draft_id}: {c['unique_people']} people")


# ------------------------------------------------------------------------------------------------ notify
def cmd_notify_build(args):
    from . import notify as NT

    home, case = home_of(args), case_of(args)
    with command("scope notify build", home=home, case=case, role="operator", params={}) as ctx:
        meta = NT.build(case, ctx.store, _cfg(case, args), threads=args.threads)
        ctx.input("scope_draft", meta["report_sha256"])
        ctx.output("pack.parquet", ctx.store.file_sha256(NT.PACK))
    emit(args, {"people": meta["people"], "segments": meta["segments"], "report_version": meta["report_version"],
                "locked": True})


def cmd_notify_export(args):
    from . import notify as NT

    home, case = home_of(args), case_of(args)
    approver = approver_sign_in(args, home, case)
    with command("scope notify export", home=home, case=case, role="approver", identity=approver, params={}) as ctx:
        if approver.username in set(case.team().get("operators", [])):
            raise PermissionDenied("separation of duties: an operator of this case cannot export notifications")
        manifest = NT.export(case, ctx.store, home, Path(args.out))
        ctx.input("pack", ctx.store.file_sha256(NT.PACK))
        for name, h in manifest["files"].items():
            if not name.startswith("notices/"):
                ctx.output(name, h)
        ctx.params["people"] = manifest["people"]
    emit(args, {"exported_people": manifest["people"], "segments": manifest["segments"],
                "report_version": manifest["report_version"], "out": str(args.out)})


# ------------------------------------------------------------------------------------------------ diff
def cmd_diff(args):
    from . import report as REP

    home, case = home_of(args), case_of(args)
    with command("scope diff", home=home, case=case, role=None, params={"from": args.from_v, "to": args.to_v}) as ctx:
        if not case.roles_of(ctx.actor):
            raise PermissionDenied("not a member of this case")
        store = ctx.store
        base = f"{REP.VERSIONS}/v{args.to_v:04d}"
        if not store.exists(f"{base}/people.parquet"):
            raise ConfigError(f"version {args.to_v} has no person-level result (preliminary or not released)")
        d = REP._diff(store, store.read_table(f"{base}/people.parquet"), store.read_table(f"{base}/person_rows.parquet"),
                      args.from_v)
    if args.out:
        from tripline_scope.core.canonical import canonical_bytes

        Path(args.out).write_bytes(canonical_bytes(d))
    emit(args, d)


# ------------------------------------------------------------------------------------------------ synth
def cmd_synth(args):
    import datetime as dt

    from tripline_scope.synth.generate import generate

    ref = dt.date.fromisoformat(args.reference_date) if args.reference_date else None
    kw = {"seed": args.seed, "databases": args.databases, "leak_rows": args.leak_rows}
    if ref:
        kw["reference_date"] = ref
    if args.threads:
        kw["threads"] = args.threads
    meta = generate(Path(args.out), args.rows, progress=(lambda m: None), **kw)
    emit(args, {"out": str(args.out), "totals": meta["totals"], "persons": meta["population"]["persons"],
                "seed": meta["seed"], "reference_date": meta["reference_date"]})


# ------------------------------------------------------------------------------------------------ registration
def _match_args(p):
    add_case_arg(p)
    p.add_argument("--config", help="matching configuration YAML (overrides case.yaml 'matching')")
    p.add_argument("--threads", type=int, help="DuckDB threads (default: all cores)")


def register(sub) -> None:
    p = sub.add_parser("estimate", help="preliminary people count with bounds (draft scope report, labelled preliminary)")
    _match_args(p)
    p.add_argument("--provider-sign", action="store_true", help="co-sign the draft with the provider key")
    p.set_defaults(func=cmd_estimate)

    s = sub.add_parser("scope", help="Module C: rows to people, scope report and notification pack").add_subparsers(
        dest="scope_cmd", required=True)
    p = s.add_parser("estimate", help="alias of 'tscope estimate'")
    _match_args(p)
    p.add_argument("--provider-sign", action="store_true")
    p.set_defaults(func=cmd_estimate)
    p = s.add_parser("match", help="link rows to people (deterministic + Splink), apply review decisions, cluster")
    _match_args(p)
    p.set_defaults(func=cmd_match)
    p = s.add_parser("review", help="serve the review page on 127.0.0.1 (reviewers sign in on the page)")
    add_case_arg(p)
    p.add_argument("--port", type=int, default=8765)
    p.set_defaults(func=cmd_review)
    p = s.add_parser("decide", help="record review decisions from a file (reviewer), or simulate them for drills")
    _match_args(p)
    p.add_argument("--file", help="JSON lines: {\"pair_key\": ..., \"decision\": \"same|different|skip\"}")
    p.add_argument("--simulate-reviewer", metavar="GROUND_TRUTH",
                   help="decide every pending item from synthetic ground truth (drills/demos only; marked simulated)")
    p.set_defaults(func=cmd_decide)
    p = s.add_parser("queue", help="count pending review items")
    add_case_arg(p)
    p.set_defaults(func=cmd_queue)
    p = s.add_parser("constrain", help="record a scoping decision from Module B scope candidates (never narrows the "
                                       "notification proposal on absent or uncertain logs)")
    add_case_arg(p)
    p.add_argument("--candidates", help="tripline.scope-candidates/v1 JSON from 'tscope paths scope-candidates'")
    p.add_argument("--widen", action="append", help="treat DATABASE.TABLE as accessed (repeatable)")
    p.add_argument("--widen-all", action="store_true", help="treat every table as accessed")
    p.add_argument("--ignore-time-windows", action="store_true", help="do not limit by record dates")
    p.add_argument("--clear", action="store_true", help="remove the candidate constraint")
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_constrain)
    p = s.add_parser("report", help="draft scope report (JSON + PDF + diff.json) from the latest match")
    add_case_arg(p)
    p.add_argument("--provider-sign", action="store_true", help="co-sign the draft with the provider key")
    p.set_defaults(func=cmd_report)
    n = s.add_parser("notify", help="notification pack").add_subparsers(dest="notify_cmd", required=True)
    p = n.add_parser("build", help="build the encrypted pack for the current draft (locked until release)")
    _match_args(p)
    p.set_defaults(func=cmd_notify_build)
    p = n.add_parser("export", help="approver exports people.csv, notices and the Regulator summary after release")
    add_case_arg(p)
    p.add_argument("--out", required=True)
    add_approver_args(p)
    p.set_defaults(func=cmd_notify_export)
    p = s.add_parser("diff", help="people added and removed per category between two released versions")
    add_case_arg(p)
    p.add_argument("--from", dest="from_v", type=int, required=True)
    p.add_argument("--to", dest="to_v", type=int, required=True)
    p.add_argument("--out")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("synth", help="generate synthetic lab-like databases with ground truth")
    p.add_argument("--rows", type=int, required=True, help="admission rows")
    p.add_argument("--out", required=True)
    p.add_argument("--seed", type=int, default=20260914)
    p.add_argument("--databases", type=int, default=10)
    p.add_argument("--leak-rows", type=int, default=300)
    p.add_argument("--reference-date", help="date ages are computed at (default 2026-09-14)")
    p.add_argument("--threads", type=int)
    p.set_defaults(func=cmd_synth)

    from tripline_scope.readiness import drill_cli, profile_cli

    profile_cli.register(sub)
    drill_cli.register(sub)
