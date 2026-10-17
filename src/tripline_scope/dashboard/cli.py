"""``tscope dashboard serve``: the read-only Investigation Workbench on a loopback address."""

from __future__ import annotations

from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core.context import command
from tripline_scope.core.errors import PermissionDenied

from .app import CASE_ROLES, DEFAULT_HOST, DEFAULT_PORT, check_host, check_port


def cmd_serve(args):
    from .app import serve

    home, case = home_of(args), case_of(args)
    with command("dashboard serve", home=home, case=case, role=None,
                 params={"port": args.port, "host": str(args.host)[:40]}) as ctx:
        host, port = check_host(args.host), check_port(args.port)
        roles = case.roles_of(ctx.actor) & set(CASE_ROLES)
        if not roles:
            raise PermissionDenied("starting the dashboard needs a role on this case (operator, reviewer or approver)")
        store = ctx.store
    serve(case, store, home, host=host, port=port)


def register(sub) -> None:
    d = sub.add_parser("dashboard", help="read-only Investigation Workbench on 127.0.0.1 (released reports only)")
    s = d.add_subparsers(dest="dashboard_cmd", required=True)
    p = s.add_parser("serve", help="serve the workbench on a loopback address; users sign in on the page")
    add_case_arg(p)
    p.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP port (default {DEFAULT_PORT})")
    p.add_argument("--host", default=DEFAULT_HOST,
                   help="loopback address to bind: 127.0.0.1 (default), localhost or ::1; anything else is refused")
    p.set_defaults(func=cmd_serve)
