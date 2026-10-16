"""``tscope profile save|show|apply|list`` (registered from ``scope/cli.py``)."""

from __future__ import annotations

import yaml

from tripline_scope.cli import emit
from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core.auth import current_identity
from tripline_scope.core.context import command
from tripline_scope.core.errors import PermissionDenied

from . import profile as PR


def cmd_save(args):
    home, case = home_of(args), case_of(args)
    with command("profile save", home=home, case=case, role="operator", params={"name": args.name}) as ctx:
        p = PR.save(home, case, ctx.store, args.name)
        from tripline_scope.core.canonical import sha256_file

        ctx.output("profile", sha256_file(p))
    emit(args, {"profile": args.name, "path": str(p)})


def cmd_show(args):
    home = home_of(args)
    current_identity(home)
    prof = PR.load(home, args.name)
    if getattr(args, "json", False):
        emit(args, prof)
    else:
        print(yaml.safe_dump(prof, sort_keys=True))


def cmd_apply(args):
    home, case = home_of(args), case_of(args)
    with command("profile apply", home=home, case=case, role="operator", params={"name": args.name}) as ctx:
        prof = PR.apply(home, case, args.name)
        ctx.output("case.yaml", case.config_sha256())
    emit(args, {"applied": args.name, "config_sha256": case.config["profile"]["config_sha256"],
                "column_mapping_tables": sum(len(t) for t in (prof.get("column_mappings") or {}).values())})


def cmd_list(args):
    home = home_of(args)
    ident = current_identity(home)
    if ident is None:
        raise PermissionDenied("not signed in")
    emit(args, {"profiles": PR.list_profiles(home)})


def register(sub) -> None:
    pr = sub.add_parser("profile", help="save, show or apply the hospital's tuned configuration (no patient data)")
    ps = pr.add_subparsers(dest="profile_cmd", required=True)
    p = ps.add_parser("save")
    add_case_arg(p)
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_save)
    p = ps.add_parser("show")
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_show)
    p = ps.add_parser("apply")
    add_case_arg(p)
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_apply)
    p = ps.add_parser("list")
    p.set_defaults(func=cmd_list)
