"""``tscope financial ...`` — enterprise-profile financial-system investigation.

Every command runs inside ``core.context.command`` (authentication, case role, source integrity, audit). Output is
ids, statuses, counts and hashes only. Release uses the shared ``tscope release --kind financial``.
"""

from __future__ import annotations

from tripline_scope.cli import emit
from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core.context import command
from tripline_scope.core.errors import ConfigError

from . import financial as FA
from . import report as REP


def _enterprise(case) -> None:
    if case.profile != "enterprise":
        raise ConfigError("financial investigation needs a case opened with --profile enterprise")


def cmd_analyse(args):
    home, case = home_of(args), case_of(args)
    _enterprise(case)
    cfg, cfg_sha = FA.load_config(args.config)
    with command("financial analyse", home=home, case=case, role="operator", params={"config_sha256": cfg_sha}) as ctx:
        ctx.input("financial_config", cfg_sha)
        res = FA.analyse(case, home, ctx.store, cfg, cfg_sha)
        ctx.output("analysis", ctx.store.file_sha256(f"{FA.WORK}/analysis.json"))
        ctx.note(f"impact {res['financial_impact']['status']}")
    c = res["counts"]
    emit(args, {"financial_impact": res["financial_impact"]["status"], "sessions": c["sessions"],
                "suspicious_sessions": c["suspicious_sessions"], "transactions": c["transactions"],
                "suspicious_transactions": c["suspicious_transactions"], "by_category": c["by_category"],
                "gaps": len(res["gaps"]), "references": res["references"]},
         f"financial analysis: impact {res['financial_impact']['status']}; {c['transactions']} transactions, "
         f"{c['suspicious_transactions']} suspicious; {c['suspicious_sessions']} suspicious session(s)")


def cmd_report(args):
    home, case = home_of(args), case_of(args)
    _enterprise(case)
    with command("financial report", home=home, case=case, role="operator") as ctx:
        res = REP.build(ctx)
    emit(args, {k: res[k] for k in ("draft_id", "version", "report_sha256", "financial_impact")},
         f"financial draft v{res['version']} ({res['draft_id']}); release with: tscope release --kind financial")


def register(sub) -> None:
    f = sub.add_parser("financial", help="enterprise profile: financial-system investigation").add_subparsers(
        dest="financial_cmd", required=True)
    p = f.add_parser("analyse", aliases=["analyze"], help="correlate privileged access and transaction evidence (operator)")
    add_case_arg(p)
    p.add_argument("--config", required=True, help="financial config (tripline.financial-config/v1)")
    p.set_defaults(func=cmd_analyse)
    p = f.add_parser("report", help="draft the financial report from the analysis (operator)")
    add_case_arg(p)
    p.set_defaults(func=cmd_report)
