"""``tscope investigator ...`` — the AI Investigator command family.

Every command runs inside ``core.context.command`` (authentication, case role, source integrity, audit). Output is
ids, statuses, counts and hashes; hypothesis text is shown only by ``show`` (validated text, never rejected text).
"""

from __future__ import annotations

from pathlib import Path

from tripline_scope.cli import emit
from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core.context import command
from tripline_scope.core.errors import PermissionDenied

from . import providers as PR
from . import report as REP
from . import run as RUN
from . import storage as S


def _any_role(ctx, case):
    if not case.roles_of(ctx.actor):
        raise PermissionDenied("requires a role on this case")


def _brief(res: dict) -> dict:
    prov = res.get("provenance") or {}
    return {"run_id": res["run_id"], "analysis_status": res["analysis_status"], "status_reason": res.get("status_reason"),
            "provider": prov.get("provider"), "provider_kind": prov.get("provider_kind"), "model_id": prov.get("model_id"),
            "is_model_inference": prov.get("is_model_inference"), "validation": (res.get("validation") or {}).get("counts"),
            "rejected_items": [r["item"] for r in (res.get("validation") or {}).get("rejections", [])],
            "hypotheses": [h["item_id"] for h in res.get("hypotheses", [])],
            "references": res.get("references"), "bundle_sha256": res.get("bundle_sha256"),
            "model_output_sha256": res.get("model_output_sha256")}


def _text(res: dict) -> str:
    b = _brief(res)
    kind = "deterministic fixture (NOT AI inference)" if b["provider_kind"] == "fixture" else b["provider_kind"]
    lines = [f"run {b['run_id']}: {b['analysis_status']}" + (f" — {b['status_reason']}" if b["status_reason"] else ""),
             f"provider: {b['provider']} [{kind}] model {b['model_id']}", f"validation: {b['validation']}"]
    if b["rejected_items"]:
        lines.append("rejected items (codes only, content dropped): " + ", ".join(b["rejected_items"]))
    return "\n".join(lines)


def cmd_analyse(args):
    home, case = home_of(args), case_of(args)
    with command("investigator analyse", home=home, case=case, role="operator", params={"provider": args.provider}) as ctx:
        res = RUN.analyse(case, home, ctx.store, provider_name=args.provider)
        ctx.output("result", ctx.store.file_sha256(f"{S.run_dir(res['run_id'])}/result.json"))
        ctx.note(f"run {res['run_id']} {res['analysis_status']}")
    emit(args, _brief(res), _text(res))
    if res["analysis_status"] == "unavailable":
        raise PR.ProviderUnavailable(f"provider {args.provider} unavailable: {res['status_reason']}")
    if res["analysis_status"] == "failed":
        raise PR.ProviderFailed(f"analysis failed ({res['status_reason']}); retry with 'tscope investigator analyse'")


def cmd_show(args):
    home, case = home_of(args), case_of(args)
    with command("investigator show", home=home, case=case, params={"run": args.run}) as ctx:
        _any_role(ctx, case)
        rid = args.run or S.latest_run_id(ctx.store) or S.latest_run_id(ctx.store, status=None)
        if rid is None:
            emit(args, {"status": "not_performed", "reason": "no investigator run for this case"},
                 "no investigator run for this case")
            return
        res = S.load_result(ctx.store, rid)
        res["human_review"]["decisions"] = S.load_reviews(ctx.store, rid)
        runs = S.list_runs(ctx.store)
    if args.json:
        emit(args, {"result": res, "runs": runs})
        return
    lines = [_text(res)]
    for h in res["hypotheses"]:
        d = res["human_review"]["decisions"].get(h["item_id"], {})
        lines.append(f"\n[{h['item_id']}] {h['rank']} · {h['basis']} · {h['consequence_class']} · confidence {h['confidence']} "
                     f"· {h['validation']['verdict']} · review: {d.get('decision', 'pending')}")
        lines.append(f"  {h['statement']}")
        lines.append(f"  supporting: {', '.join(h['supporting_evidence'])}")
        lines.append(f"  contradicting: {', '.join(h['contradicting_evidence']) or 'none cited'}")
        lines.append(f"  cannot conclude: {'; '.join(h['cannot_conclude'])}")
    for key, label in (("missing_evidence", "missing evidence"), ("investigation_steps", "next steps"),
                       ("remediation", "remediation (advisory, requires hospital authorisation)")):
        if res[key]:
            lines.append(f"\n{label}:")
            for it in res[key]:
                txt = it.get("description") or it.get("step") or it.get("action")
                lines.append(f"  [{it['item_id']}] {txt}")
    print("\n".join(lines))


def cmd_review(args):
    home, case = home_of(args), case_of(args)
    with command("investigator review", home=home, case=case, role="reviewer",
                 params={"run": args.run, "item": args.item, "decision": args.decision}) as ctx:
        row = RUN.review(ctx.store, args.run, args.item, args.decision, ctx.actor, args.note)
    emit(args, {"recorded": True, "item": row["item_id"], "decision": row["decision"]},
         f"recorded {row['decision']} for {row['item_id']}")


def cmd_report(args):
    home, case = home_of(args), case_of(args)
    with command("investigator report", home=home, case=case, role="operator", params={"run": args.run}) as ctx:
        rid = args.run or S.latest_run_id(ctx.store)
        if rid is None:
            from tripline_scope.core.errors import NotReady

            raise NotReady("no completed investigator run")
        draft, body = REP.draft(case, home, ctx.store, rid)
        ctx.input("frozen_result", body["frozen_result_sha256"])
        ctx.output("draft_report", draft.report_sha256)
    emit(args, {"draft_id": draft.draft_id, "version": draft.version, "report_sha256": draft.report_sha256, "run_id": rid,
                "hypotheses": len(body["ai_analysis"]["hypotheses"])},
         f"investigation draft v{draft.version} ({draft.draft_id}); release with: tscope release --kind investigation")


def cmd_verify(args):
    home, case = home_of(args), case_of(args)
    with command("investigator verify", home=home, case=case, params={}, allow_closed=True) as ctx:
        closed = case.is_closed
        if not closed:
            _any_role(ctx, case)
        store = None if closed else ctx.store
        out = REP.verify(case, home, store)
    emit(args, out, f"chain: {'OK' if out['chain_ok'] else 'FAILED'}; reproducible: {out['reproducible']}; {out['detail']}")
    return 0 if out["chain_ok"] and out["reproducible"] is not False else 4


def cmd_providers(args):
    home = home_of(args)
    out = PR.list_all(home)
    emit(args, {"providers": out}, "\n".join(f"{p['provider']:16} {'available' if p['available'] else 'UNAVAILABLE':12} "
                                             f"{p['detail']}" for p in out))


def cmd_bridge_export(args):
    home, case = home_of(args), case_of(args)
    with command("investigator bridge-export", home=home, case=case, role="operator", params={}) as ctx:
        out = RUN.bridge_export(case, home, ctx.store, Path(args.out))
        ctx.output("bundle", out["bundle_sha256"])
    emit(args, out, f"synthetic-only prompt written for run {out['run_id']}: {out['out']}")


def cmd_bridge_import(args):
    home, case = home_of(args), case_of(args)
    with command("investigator bridge-import", home=home, case=case, role="operator", params={"run": args.run}) as ctx:
        res = RUN.bridge_import(case, home, ctx.store, args.run, Path(args.response), args.model_label)
    emit(args, _brief(res), _text(res))
    if res["analysis_status"] != "completed":
        raise PR.ProviderFailed("imported response failed validation; export a new prompt to retry")


def register(sub) -> None:
    s = sub.add_parser("investigator", help="AI Investigator: advisory, evidence-grounded investigation analysis"
                       ).add_subparsers(dest="investigator_cmd", required=True)
    p = s.add_parser("analyse", help="analyse the released A/B/C reports with an explicitly chosen provider (operator)")
    add_case_arg(p, required=True)
    p.add_argument("--provider", required=True, help="fixture | local | openai-daybreak | anthropic (no fallback)")
    p.set_defaults(func=cmd_analyse)
    p = s.add_parser("show", help="show a run's validated result (any case role)")
    add_case_arg(p, required=True)
    p.add_argument("--run")
    p.set_defaults(func=cmd_show)
    p = s.add_parser("review", help="accept or reject one validated item (reviewer)")
    add_case_arg(p, required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--item", required=True, help="H1..H9, M1.., S1.., R1.., U1..")
    p.add_argument("--decision", required=True, choices=["accept", "reject"])
    p.add_argument("--note", default="", help="short reason (no identifiers)")
    p.set_defaults(func=cmd_review)
    p = s.add_parser("report", help="draft the investigation report from a reviewed run (operator)")
    add_case_arg(p, required=True)
    p.add_argument("--run")
    p.set_defaults(func=cmd_report)
    p = s.add_parser("verify", help="verify released investigation reports and re-render from the frozen input")
    add_case_arg(p, required=True)
    p.set_defaults(func=cmd_verify)
    p = s.add_parser("providers", help="list providers and whether each is available")
    p.set_defaults(func=cmd_providers)
    p = s.add_parser("bridge-export", help="SYNTHETIC CASES ONLY: write the prompt for a separately authorised session")
    add_case_arg(p, required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(func=cmd_bridge_export)
    p = s.add_parser("bridge-import", help="SYNTHETIC CASES ONLY: validate and store a pasted model reply")
    add_case_arg(p, required=True)
    p.add_argument("--run", required=True)
    p.add_argument("--response", required=True)
    p.add_argument("--model-label", required=True, help="the model name shown in the session (recorded as user-declared)")
    p.set_defaults(func=cmd_bridge_import)
