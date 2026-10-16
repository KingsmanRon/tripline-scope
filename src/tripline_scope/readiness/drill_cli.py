"""``tscope drill`` (registered from ``scope/cli.py``)."""

from __future__ import annotations

from tripline_scope.cli import emit
from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core.context import command

from . import drill as DR


def cmd_drill(args):
    home, case = home_of(args), case_of(args)
    with command("drill", home=home, case=case, role="operator", params={"rows": args.rows}) as ctx:
        result = DR.run(args, home, case, ctx)
        draft = DR.save_report(case, result, DR.hardware())
        ctx.output("drill_draft", draft.report_sha256)
    failed = [s["step"] for s in result["steps"] if not s["ok"]]
    emit(args, {"drill_draft": draft.draft_id, "total_seconds": result["total_seconds"], "failed_steps": failed,
                "accuracy": result["accuracy"], "steps": {s["step"]: s["seconds"] for s in result["steps"]}})
    return 1 if failed else 0


def register(sub) -> None:
    p = sub.add_parser("drill", help="run a timed synthetic incident shaped like the hospital's mapped schema")
    add_case_arg(p)
    p.add_argument("--rows", type=int, default=100_000, help="synthetic admission rows (default 100000)")
    p.add_argument("--approver", help="also release and export, signing in as this approver")
    p.add_argument("--workdir", help="working directory for the throw-away case (default: a new temp dir)")
    p.add_argument("--keep", action="store_true", help="keep the synthetic data and throw-away case")
    p.set_defaults(func=cmd_drill)
