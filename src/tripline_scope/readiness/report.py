"""Readiness report: a separately versioned, signed summary of the hospital's preparedness.

It cites the latest *released* data map, exposure report and drill report of a readiness case by version and
hash, and carries their summary counts. It is explicitly not a breach scope and never feeds one.
"""

from __future__ import annotations

from tripline_scope import METHOD_VERSION, __version__
from tripline_scope.cli import emit
from tripline_scope.cli.common import add_case_arg, case_of, home_of
from tripline_scope.core import pdf
from tripline_scope.core.context import command
from tripline_scope.core.errors import ConfigError
from tripline_scope.core.reports import ReportStore

COMPONENTS = ("datamap", "exposure", "drill")
STATEMENT = (
    "This readiness report describes preparedness before any incident: where personal data lives, conditions that "
    "could expose it, and how a rehearsed incident performed. It is not a breach scope, it does not count affected "
    "people, and it must not be used as a notification basis."
)


def _summary_of(body: dict) -> dict:
    """Pick a component's own summary block; fall back to scalar top-level counts. Never values."""
    s = body.get("summary")
    if isinstance(s, dict):
        return s
    return {k: v for k, v in body.items() if isinstance(v, int | float) and not isinstance(v, bool) and k != "version"}


def build_body(rs: ReportStore, case) -> dict:
    components = {}
    for kind in COMPONENTS:
        latest = rs.latest(kind)
        if latest is None:
            components[kind] = {"status": "not available", "version": None, "report_sha256": None}
            continue
        n, vdir, sha = latest
        body = rs.load(kind, n)
        components[kind] = {"status": "released", "version": n, "report_sha256": sha, "summary": _summary_of(body)}
    missing = [k for k, c in components.items() if c["status"] != "released"]
    return rs.new_body(
        "readiness",
        report_status="readiness",
        mode=case.mode,
        method_version=METHOD_VERSION,
        product_version=__version__,
        config_sha256=case.config_sha256(),
        statement=STATEMENT,
        components=components,
        missing_components=missing,
    )


def render(body: dict, hospital: str) -> bytes:
    rows = [["Component", "Status", "Version", "Report SHA-256"]]
    for kind, c in body["components"].items():
        rows.append([kind, c["status"], str(c["version"] or "-"), (c["report_sha256"] or "-")[:16] + "…"])
    sections = [
        pdf.Section("What this is", [body["statement"]]),
        pdf.Section("Components", table=rows),
    ]
    for kind, c in body["components"].items():
        if c.get("summary"):
            sections.append(pdf.Section(f"{kind} summary", table=[["Measure", "Value"]] +
                                        [[str(k), str(v)] for k, v in sorted(c["summary"].items())][:60]))
    if body["missing_components"]:
        sections.append(pdf.Section("Not yet available", [", ".join(body["missing_components"])]))
    return pdf.render(f"Readiness report — {body['case_id']} v{body['version']}",
                      [hospital, f"method {body['method_version']}"], sections,
                      footer="Readiness report — not a breach scope")


def cmd_readiness_report(args):
    home, case = home_of(args), case_of(args)
    if case.mode != "readiness":
        raise ConfigError("readiness reports are produced in readiness cases only")
    with command("readiness report", home=home, case=case, role="operator") as ctx:
        rs = ReportStore(case)
        body = build_body(rs, case)
        for kind, c in body["components"].items():
            if c["report_sha256"]:
                ctx.input(f"{kind}.v{c['version']}", c["report_sha256"])
        draft = rs.save_draft("readiness", body, pdf=render(body, home.config.get("hospital_name", "")),
                              provider=home.provider_signer())
        ctx.output("draft_report", draft.report_sha256)
    emit(args, {"draft": draft.draft_id, "version": draft.version, "missing": body["missing_components"]})


def register(sub) -> None:
    r = sub.add_parser("readiness", help="readiness summary report").add_subparsers(dest="readiness_cmd", required=True)
    p = r.add_parser("report", help="draft a signed-on-release readiness report from released map/exposure/drill reports")
    add_case_arg(p)
    p.set_defaults(func=cmd_readiness_report)
