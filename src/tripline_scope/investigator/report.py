"""The ``investigation`` report: deterministic findings, advisory AI analysis, human review, missing evidence.

The body is a pure function of a *frozen* input — the validated result, its review decisions and the evidence
bundle — so a released report can be re-rendered byte-for-byte from the frozen input (``verify``). Separate model
runs are not expected to produce identical output; reproducibility is of the report from a frozen, reviewed result.
The report never contains prompts, raw model output or rejected content, and never alters Module A/B/C reports.

Human acceptance: the AI analysis's hypotheses, investigation steps, remediation actions and missing-evidence
suggestions appear as part of the report's analysis only when a named reviewer explicitly accepted them. Proposals
that passed validation but that nobody reviewed are kept apart in ``ai_analysis.unreviewed_proposals``, labelled as
not reviewed and not approved; proposals a reviewer rejected are left out.
"""

from __future__ import annotations

from tripline_scope.core import pdf
from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import IntegrityError, NotReady
from tripline_scope.core.reports import ReportStore

from . import storage as S
from .bundle import MODULE_KINDS
from .schema import CONFIDENCE_MEANING

REPORT_SCHEMA = "tripline.investigation-report/v1"
FROZEN_SCHEMA = "tripline.investigation-frozen/v1"
STATEMENT = ("Investigation analysis built on the released, signed Module A, B and C reports of this case. The "
             "deterministic findings are computed by Tripline from those reports. The AI analysis section is advisory: "
             "hypotheses and recommendations proposed by the named provider, checked by Tripline's deterministic "
             "validator and explicitly accepted by a named reviewer; validated proposals that nobody reviewed are listed "
             "separately as unreviewed and form no part of this analysis. It does not change any evidence, classification, count, "
             "scope or notification decision, and no recommendation has been or will be executed by Tripline.")
UNREVIEWED_NOTICE = ("NOT REVIEWED: these AI-proposed steps, actions and missing-evidence suggestions passed validation "
                     "but no reviewer has accepted them. They are not approved, not part of this report's analysis and "
                     "must not be acted on without review and hospital authorisation.")
PROPOSAL_FIELDS = {"investigation_steps": ("item_id", "step", "priority", "evidence_ids"),
                   "remediation": ("item_id", "action", "priority", "evidence_ids", "asset_ids"),
                   "missing_evidence": ("item_id", "description", "source_family", "related_evidence")}
LIMITATIONS = [
    "Hypotheses are explanations consistent with the cited evidence, not established findings.",
    "Confidence labels are ordinal judgements with the documented meaning below, not probabilities.",
    "Missing, disabled or cleared logs make outcomes undetermined; they never show that nothing happened.",
    "Separate model runs can produce different text; this report reproduces exactly from its frozen, reviewed input.",
]


def current_refs(case) -> list[dict]:
    rs = ReportStore(case)
    out = []
    for kind in MODULE_KINDS:
        latest = rs.latest(kind)
        if latest:
            out.append({"kind": kind, "version": latest[0], "report_sha256": latest[2]})
    return out


def check_fresh(case, home, res: dict) -> None:
    """Refuse a run whose referenced reports are not the current, verified released versions."""
    want = current_refs(case)
    if want != res["references"]:
        raise IntegrityError("stale run: the released module reports changed since this analysis; run "
                             "'tscope investigator analyse' again")
    rs = ReportStore(case)
    for r in want:
        if not rs.verify(r["kind"], home).ok:
            raise IntegrityError(f"released {r['kind']} reports failed verification")


def _facts(bundle, prefix):
    return {k[len(prefix):]: v["value"] for k, v in sorted(bundle["facts"].items()) if k.startswith(prefix)}


def deterministic_findings(bundle: dict) -> dict:
    E = bundle["evidence"]
    refs = {r["kind"]: r for r in bundle["reports"]}
    out = {}
    if "exposure" in refs:
        top = [i for i in E.values() if i["type"] == "finding" and i["severity"] in ("critical", "high")][:12]
        out["exposure"] = {"report_version": refs["exposure"]["version"], "findings_by_severity": _facts(bundle, "FACT-A-severity-"),
                           "findings_by_control": _facts(bundle, "FACT-A-control-"),
                           "highest_severity_findings": [{"finding_id": i["id"], "severity": i["severity"], "title": i["statement"],
                                                          "assets": i["assets"]} for i in top]}
    else:
        out["exposure"] = {"status": "not assessed"}
    if "paths" in refs:
        out["paths"] = {
            "report_version": refs["paths"]["version"],
            "sensitive_tables_by_class": _facts(bundle, "FACT-B-sensitive_tables_by_class-"),
            "paths_by_class": _facts(bundle, "FACT-B-paths_by_class-"),
            "exfiltration_evidenced_tables": sorted({t for i in E.values() if i["type"] == "table_claim"
                                                     and i["consequence_class"] == "exfiltration_evidenced" for t in i["tables"]}),
            "corroborations": [{"id": i["id"], "kind": i["exfiltration_evidence_kind"], "tables": i["tables"]}
                               for i in E.values() if i["type"] == "corroboration"],
            "high_severity_anomalies": [{"anomaly_id": i["id"], "statement": i["statement"]} for i in E.values()
                                        if i["type"] == "anomaly" and i["severity"] == "high"][:15],
        }
    else:
        out["paths"] = {"status": "not assessed"}
    if "scope" in refs:
        tiers = _facts(bundle, "FACT-C-tier-")
        out["scope"] = {"report_version": refs["scope"]["version"], "report_status": bundle["facts"].get("FACT-C-report-status", {}).get("value"),
                        "scope_tiers": tiers, "preliminary_estimate": _facts(bundle, "FACT-C-preliminary-"),
                        "person_count_bounds": _facts(bundle, "FACT-C-people-"),
                        "unresolvable_rows": bundle["facts"].get("FACT-C-unresolvable-rows", {}).get("value")}
    else:
        out["scope"] = {"status": "not assessed"}
    return out


def _review_of(decisions: dict, item_id: str) -> dict:
    d = decisions.get(item_id)
    return {"status": "reviewed", **d} if d else {"status": "not reviewed"}


def content(frozen: dict) -> dict:
    """Pure function: frozen input → report content (everything except the chain fields)."""
    res, bundle = frozen["result"], frozen["bundle"]
    dec = res["human_review"]["decisions"]
    hyps = []
    for h in res["hypotheses"]:
        if h["validation"]["verdict"] != "accepted" or (dec.get(h["item_id"]) or {}).get("decision") != "accept":
            continue
        hyps.append({k: h[k] for k in ("item_id", "rank", "statement", "basis", "consequence_class", "supporting_evidence",
                                       "contradicting_evidence", "assets", "sources", "time_window", "confidence",
                                       "confidence_rationale", "alternative_explanations", "tests", "cannot_conclude",
                                       "quantities")} | {"advisory": True, "review": _review_of(dec, h["item_id"])})

    def decision(it):
        return (dec.get(it["item_id"]) or {}).get("decision")

    def items(key):
        """Validated proposals a reviewer explicitly accepted (the only ones in the report's analysis)."""
        out = [{k: it[k] for k in PROPOSAL_FIELDS[key]} | {"advisory": True, "review": _review_of(dec, it["item_id"])}
               for it in res[key] if it["validation"]["verdict"] == "accepted" and decision(it) == "accept"]
        if key == "remediation":
            out = [r | {"requires_hospital_authorisation": True, "executed": False} for r in out]
        return out

    unreviewed = []
    for key in PROPOSAL_FIELDS:
        for it in res[key]:
            if it["validation"]["verdict"] == "accepted" and decision(it) is None:
                row = {k: it[k] for k in PROPOSAL_FIELDS[key]} | {"proposal_type": key, "advisory": True,
                                                                    "review": {"status": "not reviewed"}}
                if key == "remediation":
                    row |= {"requires_hospital_authorisation": True, "executed": False}
                unreviewed.append(row)

    prov = dict(res["provenance"] or {})
    det_missing = [{"id": i["id"], "statement": i["statement"]} for i in bundle["evidence"].values()
                   if i["type"] in ("gap", "coverage_gap")][:40]
    return {
        "report_schema": REPORT_SCHEMA,
        "title": "Investigation report (AI-assisted, advisory)",
        "report_status": "advisory",
        "statement": STATEMENT,
        "run": {k: res[k] for k in ("run_id", "created_at", "bundle_sha256", "prompt_sha256", "method_version",
                                    "validator_version", "config_sha256")},
        "references": res["references"],
        "not_assessed_modules": res["not_assessed_modules"],
        "provenance": prov,
        "model_output_sha256": res["model_output_sha256"],
        "frozen_result_sha256": sha256_hex(canonical_bytes(frozen)),
        "deterministic_findings": deterministic_findings(bundle),
        "ai_analysis": {
            "advisory": True,
            "attribution": (f"Proposed by {prov.get('provider')} ({prov.get('provider_kind')}, model "
                            f"{prov.get('model_id')}); validated by {res['validator_version']}; reviewed by a human reviewer."),
            "is_model_inference": bool(prov.get("is_model_inference")),
            "summary": res["summary"],
            "hypotheses": hyps,
            "investigation_steps": items("investigation_steps"),
            "remediation": items("remediation"),
            "unproven_assertions": [{"item_id": u["item_id"], "text": u["text"]} for u in res["unproven_assertions"]
                                    if u["validation"]["verdict"] == "accepted"],
            "unreviewed_proposals": {"notice": UNREVIEWED_NOTICE, "approved": False, "items": unreviewed},
        },
        "human_reviewed_conclusions": [{"item_id": k, **v} for k, v in sorted(dec.items())],
        "missing_evidence": {
            "deterministic": det_missing,
            "source_families_not_supplied": bundle["missing_source_families"],
            "ai_proposed": items("missing_evidence"),
        },
        "validation": {"verdict": res["validation"]["verdict"], "counts": res["validation"]["counts"],
                       "rejections": res["validation"]["rejections"], "validator_version": res["validator_version"]},
        "confidence_labels": CONFIDENCE_MEANING,
        "limitations": LIMITATIONS,
    }


def freeze(store, run_id: str) -> dict:
    res = S.load_result(store, run_id)
    res["human_review"]["decisions"] = S.load_reviews(store, run_id)
    bundle = store.read_json(f"{S.run_dir(run_id)}/bundle.json")
    return {"schema": FROZEN_SCHEMA, "result": res, "bundle": bundle}


def render_pdf(body: dict) -> bytes:
    ai, det = body["ai_analysis"], body["deterministic_findings"]
    prov = body["provenance"]
    kind_note = ("Deterministic fixture output: NOT AI inference." if not ai["is_model_inference"]
                 else "AI-generated hypotheses: advisory, validated and human-reviewed; not findings.")
    exec_rows = [["Measure", "Value (from the released reports)"]]
    for k, v in (det.get("paths") or {}).get("sensitive_tables_by_class", {}).items():
        exec_rows.append([f"Sensitive tables: {k}", str(v)])
    for k, v in (det.get("scope") or {}).get("scope_tiers", {}).items():
        exec_rows.append([f"People: {k}", str(v)])
    sections = [pdf.Section("Executive summary", [body["statement"], kind_note,
                                                  f"Provider: {prov.get('provider')} / {prov.get('model_id')}"],
                            table=exec_rows if len(exec_rows) > 1 else None)]
    main = [h for h in ai["hypotheses"] if h["rank"] == "main"]
    if main:
        h = main[0]
        sections.append(pdf.Section("Main hypothesis (advisory)", [h["statement"], f"Confidence: {h['confidence']} — "
                                    f"{h['confidence_rationale']}", "Cannot conclude: " + "; ".join(h["cannot_conclude"])]))
    else:
        sections.append(pdf.Section("Main hypothesis (advisory)", ["No main hypothesis was accepted by validation and review."]))
    sections.append(pdf.Section("Deterministic findings", [], table=[["Module", "Report version", "Status"]] + [
        [m, str(v.get("report_version", "")), v.get("status", "released")] for m, v in det.items()]))
    for h in ai["hypotheses"]:
        sections.append(pdf.Section(f"Hypothesis {h['item_id']} ({h['rank']}, {h['basis']})", [
            h["statement"], f"Evidence class: {h['consequence_class']}",
            "Supporting evidence: " + ", ".join(h["supporting_evidence"]),
            "Contradicting evidence: " + (", ".join(h["contradicting_evidence"]) or "none cited"),
            f"Confidence: {h['confidence']} — {h['confidence_rationale']}",
            "Tests: " + "; ".join(f"{t['evidence_needed']} → {t['would_resolve']}" for t in h["tests"]),
            f"Review: {h['review'].get('decision', 'not reviewed')} by {h['review'].get('reviewer', '-')}"]))
    if ai["investigation_steps"]:
        sections.append(pdf.Section("Proposed investigation steps (advisory)", [], table=[["Item", "Priority", "Step", "Evidence"]] + [
            [s["item_id"], s["priority"], s["step"], ", ".join(s["evidence_ids"])] for s in ai["investigation_steps"]]))
    if ai["remediation"]:
        sections.append(pdf.Section("Proposed remediation (advisory; requires hospital authorisation; not executed)", [],
                                    table=[["Item", "Priority", "Action", "Evidence"]] + [
                                        [r["item_id"], r["priority"], r["action"], ", ".join(r["evidence_ids"])] for r in ai["remediation"]]))
    un = ai["unreviewed_proposals"]["items"]
    if un:
        sections.append(pdf.Section("Unreviewed AI proposals (NOT reviewed, NOT approved, not part of this analysis)",
                                    [ai["unreviewed_proposals"]["notice"]], table=[["Item", "Type", "Proposal"]] + [
                                        [u["item_id"], u["proposal_type"].replace("_", " "),
                                         u.get("step") or u.get("action") or u.get("description")] for u in un]))
    me = body["missing_evidence"]
    sections.append(pdf.Section("Missing evidence", ["Not supplied: " + ("; ".join(me["source_families_not_supplied"]) or "none recorded")]
                                + [f"{g['id']}: {g['statement']}" for g in me["deterministic"][:20]]
                                + [f"{m['item_id']}: {m['description']}" for m in me["ai_proposed"]]))
    v = body["validation"]
    sections.append(pdf.Section("Validation and provenance", [
        f"Validator {v['validator_version']}: {v['counts']}; rejected items: " +
        (", ".join(f"{r['item']} ({'/'.join(r['codes'])})" for r in v["rejections"]) or "none"),
        f"Model output SHA-256: {body['model_output_sha256']}", f"Frozen input SHA-256: {body['frozen_result_sha256']}",
        "References: " + "; ".join(f"{r['kind']} v{r['version']} {r['report_sha256']}" for r in body["references"])]
        + body["limitations"], page_break_before=True))
    return pdf.render(f"Investigation report — {body['case_id']} v{body['version']}",
                      ["Advisory investigation analysis", kind_note, f"Run {body['run']['run_id']}"], sections,
                      footer="Tripline Scope — advisory; the Information Officer decides")


def draft(case, home, store, run_id: str):
    res = S.load_result(store, run_id)
    if res.get("analysis_status") != "completed":
        raise NotReady("only a completed, validated run can be reported")
    check_fresh(case, home, res)
    decisions = S.load_reviews(store, run_id)
    pending = [h["item_id"] for h in res["hypotheses"] if h["validation"]["verdict"] == "accepted" and h["item_id"] not in decisions]
    if pending:
        raise NotReady("review every accepted hypothesis before reporting (pending: " + ", ".join(pending) + ")")
    frozen = freeze(store, run_id)
    rs = ReportStore(case)
    body = rs.new_body("investigation", **content(frozen))
    data = rs.save_draft("investigation", body, pdf=render_pdf(body))
    store.write_json(f"{S.run_dir(run_id)}/frozen.json", frozen)
    return data, body


def verify(case, home, store) -> dict:
    """Chain verification of released investigation reports + byte-identical re-render from the frozen input."""
    rs = ReportStore(case)
    versions = [n for n, _ in rs.versions("investigation")]
    if not versions:
        return {"chain_ok": True, "versions": [], "reproducible": None, "detail": "no released investigation report"}
    chain = rs.verify("investigation", home)
    out = {"chain_ok": bool(chain.ok), "versions": versions, "reproducible": None, "detail": None}
    if not chain.ok:
        out["detail"] = chain.render()
        return out
    body = rs.load("investigation")
    rel = f"{S.run_dir(body['run']['run_id'])}/frozen.json"
    if store is None or not store.exists(rel):
        out["detail"] = "frozen input not available (destroyed at case closure or never created): chain verified only"
        return out
    frozen = store.read_json(rel)
    rebuilt = dict({k: body[k] for k in ("schema", "case_id", "kind", "version", "previous_report_sha256")}, **content(frozen))
    out["reproducible"] = canonical_bytes(rebuilt) == canonical_bytes(body)
    out["detail"] = "re-rendered from the frozen input" + ("" if out["reproducible"] else ": MISMATCH")
    return out
