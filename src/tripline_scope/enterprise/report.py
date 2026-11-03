"""``financial`` report: the enterprise financial-system investigation, signed and released like every report.

The body is built from ``work/financial/analysis.json`` and refuses to draft if the referenced Module B (or
Module A) report is no longer the latest released, verified version. It contains opaque references only: account
refs (``ACCT-``), sessions (``FSN-``), transactions (``TXN-``), privilege events (``PEV-``), gaps (``FGP-``),
counterparties (``CPTY-``) and Module B event ids. Raw transaction references, account names, bank details and
credentials never enter it. Containment items are advisory: none is executed by Tripline.
"""

from __future__ import annotations

from tripline_scope.core import pdf
from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import IntegrityError, NotReady
from tripline_scope.core.redact import find_identifier_like
from tripline_scope.core.reports import ReportStore

from . import financial as FA

REPORT_SCHEMA = "tripline.financial-report/v1"
STATEMENT = ("Investigation of privileged access to the financial environment and of financial-transaction evidence, "
             "built from the released, verified access-path report and its normalised, custody-recorded sources. "
             "It records what the evidence shows and what it does not; it makes no finding of fraud or of any "
             "person's responsibility, which are matters for the organisation's responsible officers, its auditors "
             "and the authorities.")
EVIDENCE_RULE = [
    "Credential or privilege exposure (Module A) is potential exposure; it does not show that an account was "
    "compromised.",
    "An account's activity does not show that the person who owns the account performed it.",
    "Suspicious activity does not show fraud; a payment request or approval does not show that money moved.",
    "A transaction is classified 'settled_corroborated' only when an independent settlement record (a source other "
    "than the financial application) carries the same reference, amount and currency with a settled outcome; the "
    "application's own 'settled' status is never sufficient.",
    "Missing, interrupted or unsupplied logs make outcomes undetermined; they never show that nothing happened.",
    "Correlated links are inferences from account and time and are never shown as direct.",
]
LIMITATIONS = [
    "Results are limited to the supplied, normalised exports and the declared correlation windows.",
    "Amounts are totalled per currency only; no currency conversion is performed.",
    "Account references are pseudonymous and case-keyed; mapping them to people requires the case key and an "
    "authorised investigator.",
    "Demonstrated on synthetic data only; customer production validation has not been performed.",
]


def containment(a: dict) -> list[dict]:
    """Advisory next steps derived from the analysis; never executed by Tripline."""
    out = []

    def add(key, action, priority, evidence):
        out.append({"rec_id": "FREC-" + sha256_hex(key.encode())[:12], "action": action, "priority": priority,
                    "evidence_ids": sorted(set(evidence))[:20], "requires_authorisation": True, "executed": False})
    for s in a["sessions"]:
        r = set(s["suspicious_reasons"])
        if "supplier_outside_window" in r:
            add(f"sup:{s['account_ref']}", f"Consider disabling supplier account {s['account_ref']} and reviewing its "
                "authorised access window with the contract owner.", "immediate", [s["session_id"]])
        if "privilege_granted_before_session" in r:
            pev = [p["pev_id"] for p in a["privilege_events"] if p.get("account_ref") == s["account_ref"]]
            add(f"priv:{s['account_ref']}", f"Review and, if unauthorised, remove the privileged access granted to "
                f"{s['account_ref']}; preserve the directory and application audit records first.", "immediate",
                [s["session_id"], *pev])
    held = [t["transaction_id"] for t in a["transactions"] if t["suspicious"] and t["category"] in
            ("released_not_posted", "posted", "approved_not_released", "pending_approval", "initiated")]
    if held:
        add("hold", "Ask Finance to hold or stop the listed transactions and to confirm their status directly with the "
            "bank; do not rely on the application's own status.", "immediate", held)
    settled = [t["transaction_id"] for t in a["transactions"] if t["suspicious"] and t["category"] == "settled_corroborated"]
    if settled:
        add("settled", "Engage the paying bank about recall or fraud-reporting procedures for the listed settled "
            "transactions; reporting and legal decisions rest with the responsible officers.", "immediate", settled)
    for g in a["gaps"]:
        if g["kind"] in ("declared_missing_period", "settlement_evidence_not_supplied", "source_family_missing"):
            add(f"gap:{g['gap_id']}", f"Obtain the missing evidence: {g['description']}", "next", [g["gap_id"]])
    add("preserve", "Preserve the financial application, identity-provider, VPN and server logs for the full window "
        "under chain of custody before any remediation changes them.", "immediate", [])
    return out


def build(ctx) -> dict:
    case, store, home = ctx.case, ctx.store, ctx.home
    if not store.exists(f"{FA.WORK}/analysis.json"):
        raise NotReady("no financial analysis: run 'tscope financial analyse --config FILE' first")
    a = store.read_json(f"{FA.WORK}/analysis.json")
    rs = ReportStore(case)
    for ref in a["references"]:
        latest = rs.latest(ref["kind"])
        if latest is None or (latest[0], latest[2]) != (ref["version"], ref["report_sha256"]):
            raise NotReady(f"stale analysis: the released {ref['kind']} report changed since the analysis; run "
                           "'tscope financial analyse' again")
        if not rs.verify(ref["kind"], home).ok:
            raise IntegrityError(f"released {ref['kind']} reports failed verification")
    a_sha = FA.analysis_sha(a)
    ctx.input("financial_analysis", a_sha)
    content = {
        "report_schema": REPORT_SCHEMA, "title": "Financial-system investigation (enterprise profile)",
        "report_status": "investigation", "profile": case.profile, "method_version": a["method_version"],
        "config_sha256": a["config_sha256"], "analysis_sha256": a_sha, "statement": STATEMENT,
        "evidence_rule": EVIDENCE_RULE, "references": a["references"], "inputs": a["inputs"],
        "financial_impact": a["financial_impact"], "counts": a["counts"], "sessions": a["sessions"],
        "privilege_events": a["privilege_events"], "transactions": a["transactions"], "gaps": a["gaps"],
        "credential_and_privilege_exposure": {
            "note": "Exposure findings from the released Module A report for accounts seen in this investigation. "
                    "Exposure is not evidence of compromise.", "findings": a["exposure"]},
        "containment": {"notice": "Advisory only: none of these steps has been or will be executed by Tripline; each "
                                  "needs the organisation's authorisation.", "recommendations": containment(a)},
        "limitations": LIMITATIONS,
    }
    body = rs.new_body("financial", **content)
    blob = canonical_bytes(body).decode("utf-8")
    kinds = find_identifier_like(blob.replace("\\\\", "\\"))
    if kinds:
        raise IntegrityError(f"refusing to draft: identifier-like values in the report ({sorted(set(kinds))})")
    pdf_bytes = render_pdf(body)
    draft = rs.save_draft("financial", body, pdf=pdf_bytes)
    ctx.output("draft_report", draft.report_sha256)
    return {"draft_id": draft.draft_id, "version": draft.version, "report_sha256": draft.report_sha256,
            "financial_impact": body["financial_impact"]["status"], "counts": body["counts"], "body": body}


def _amounts(totals: dict) -> str:
    parts = []
    for cat, cur in sorted(totals.items()):
        parts.append(cat + ": " + ", ".join(f"{c} {v / 100:,.2f}" if c not in ("JPY", "KRW", "BHD", "KWD")
                                            else f"{c} {v} (minor units)" for c, v in sorted(cur.items())))
    return "; ".join(parts) or "none"


def render_pdf(body: dict) -> bytes:
    c, imp = body["counts"], body["financial_impact"]
    secs = [pdf.Section("Summary", [body["statement"], f"Financial impact: {imp['status']} — {imp['statement']}"],
                        table=[["Measure", "Value (counted from the evidence)"],
                               ["Application sessions", str(c["sessions"])],
                               ["Suspicious sessions", str(c["suspicious_sessions"])],
                               ["Transactions", str(c["transactions"])],
                               ["Suspicious transactions", str(c["suspicious_transactions"])],
                               ["Linked to sessions with privilege evidence (account and time)",
                                str(c["linked_to_sessions_with_privilege_evidence"])],
                               ["Rejected or stopped", str(c["rejected_or_stopped"])],
                               ["Verified ledger postings", str(c["ledger_posting_verified"])],
                               ["Settlement corroborated (independent record)", str(c["settled_corroborated"])],
                               ["  of which no ledger posting recorded",
                                str(c["settled_corroborated_without_ledger_posting"])],
                               ["Unresolved", str(c["unresolved"])]]),
            pdf.Section("Evidence rule", list(body["evidence_rule"])),
            pdf.Section("Amounts by evidence category (per currency, never converted)",
                        [_amounts(c["amount_totals_minor_by_category"])])]
    rows = [["Session", "Account", "Identity", "Remote access", "Privilege", "Suspicion reasons"]]
    for s in body["sessions"]:
        if s["suspicious_reasons"] or s["transactions"] and len(rows) < 40:
            rows.append([s["session_id"], s["account_ref"], s["links"]["identity"]["label"],
                         s["links"]["remote_access"]["label"], s["links"]["privilege"]["label"],
                         ", ".join(s["suspicious_reasons"]) or "—"])
    secs.append(pdf.Section("Financial-application sessions", [], table=rows))
    trows = [["Transaction", "Category", "Amount", "Suspicious", "Indicators"]]
    for t in [t for t in body["transactions"] if t["suspicious"]][:60]:
        amt = f"{t['currency']} {t['amount_minor'] / 100:,.2f}" if t["amount_minor"] is not None and t["currency"] else "unknown"
        trows.append([t["transaction_id"], t["category"], amt, "yes", ", ".join(t["approval_indicators"]) or "—"])
    secs.append(pdf.Section("Suspicious transactions", [], table=trows))
    secs.append(pdf.Section("Evidence gaps", [f"{g['gap_id']} ({g['kind']}): {g['description']}" for g in body["gaps"]]
                            or ["None recorded."]))
    secs.append(pdf.Section("Containment considerations (advisory, not executed)",
                            [body["containment"]["notice"]] + [f"{r['rec_id']} [{r['priority']}]: {r['action']}"
                                                               for r in body["containment"]["recommendations"]]))
    secs.append(pdf.Section("Limitations", body["limitations"]))
    return pdf.render(f"Financial-system investigation — {body['case_id']} v{body['version']}",
                      ["Enterprise profile", f"Impact status: {imp['status']}"], secs,
                      footer="Tripline Scope — evidence, not a finding of fraud")
