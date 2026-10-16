"""``tscope exposure report``: ranked, deterministic exposure report drafts (JSON + PDF) from the latest scan.

States are assigned against the previous **released** exposure report in the case's chain:

* ``new`` - not in the previous report (or previously mitigated and seen again);
* ``open`` - present before and now; ``first_seen`` is carried forward;
* ``accepted-risk`` - listed in the hospital's accepted-risk register (unexpired), recorded with who accepted it;
* ``mitigated`` - present before, absent now, **and** its coverage unit (root and path, database check or identity
  input) was assessed in this scan: a verified delta;
* ``not-assessed`` - present before, absent now, but its coverage unit was not assessed this time.

The report never carries wall-clock times (only the declared snapshot time), so identical inputs give a
byte-identical ``report.json``. Release is by the Information Officer (``tscope release --kind exposure``).
"""

from __future__ import annotations

import csv
import io

from tripline_scope.core import pdf as pdfmod
from tripline_scope.core.canonical import canonical_bytes
from tripline_scope.core.errors import NotReady
from tripline_scope.core.reports import ReportStore

from . import METHOD_VERSION, REPORT_SCHEMA_VARIANT
from .model import CONTROLS, SEVERITIES, Keys, rank_key
from .scan import FINDINGS_FILE, SCAN_FILE

STATEMENT = ("Configuration and data-exposure assessment of hospital-authorised, read-only snapshots and exports. "
             "It is not a vulnerability scan or penetration test: no network probing, exploitation, credential "
             "validation, deletion or revocation was performed. Findings describe exposure conditions; none of them "
             "implies that a compromise has occurred.")
GUARDRAILS = [
    "Only the roots, catalogue exports and identity exports declared in the manifest were read; symbolic links "
    "leaving a root were rejected and archives were expanded in memory within the declared budget.",
    "No network activity: an offline guard refused every connection attempt during the scan (live metadata "
    "logins, when declared, were checked to be read-only and queried with timeouts and row limits).",
    "Secret values and patient records were read transiently for classification only. This report holds redacted "
    "contexts, keyed case-local fingerprints, counts in bands and locations, never the values.",
    "Credentials were never used: their validity is unknown. Files were never deleted, moved or modified and no "
    "access was revoked; every remediation is a decision for the hospital.",
]
GOVERNANCE = [
    "Rotate exposed credentials and keys first, then move them into a vault or protected configuration store and "
    "remove the plaintext copies (including repository history and backups).",
    "Stray patient-data copies are removed or moved to controlled storage under the records-retention schedule; the "
    "owner confirms purpose before deletion. Never delete evidence while a legal hold or an investigation is open.",
    "Database role grants are reduced to the documented function of each principal; auditing is restored and its "
    "logs retained centrally.",
    "Supplier access is reviewed against the contract: MFA enforced and evidenced, rights limited to the contracted "
    "scope, expired or inactive accounts disabled.",
    "Accepted risks are recorded in the hospital's accepted-risk register with an owner, reason and expiry; the next "
    "report shows them as accepted-risk until they expire.",
]
LIMITATIONS = [
    "Exposure conditions only: the assessment does not determine whether data was accessed or exfiltrated.",
    "Findings labelled inference depend on naming conventions, partial exports or group membership evidence; "
    "uncertain findings carry lower confidence and caveats.",
    "Dormancy and inactivity are reported only for accounts covered by sign-in evidence that spans the declared "
    "observation window; otherwise they are unknown.",
    "Opaque formats (database backups, 7z/RAR archives, office documents, git packfiles) are recognised by format "
    "and metadata only, as listed under coverage.",
]
STABLE_FIELDS = ["finding_id", "control_id", "rule_id", "severity", "state", "asset.asset_id", "target_asset.asset_id",
                 "location.type", "location.root", "location.path", "location.member", "location.database",
                 "location.principal", "location.principal_domain", "location.object", "suggested_fix.action",
                 "secret_fingerprint", "coverage_unit"]
_STATE_ORDER = {"new": 0, "open": 0, "accepted-risk": 1, "not-assessed": 2, "mitigated": 3}


def _unit_assessed(scan: dict, keys: Keys, f: dict) -> bool:
    unit = f.get("coverage_unit") or ""
    cov = scan["coverage"]["assessed"].get(f["control_id"], [])
    if not any(u["unit"] == unit for u in cov):
        return False
    if unit.startswith("root:"):
        root_id = unit.split(":", 1)[1]
        if scan["coverage"].get("root_complete", {}).get(root_id):
            return True
        loc = f.get("location") or {}
        rel = loc.get("path") or ""
        scanned = set(scan.get("scanned_paths", {}).get(root_id, []))
        return keys.path(unit, rel) in scanned
    return True


def assign_states(findings: list[dict], prev: dict | None, scan: dict, keys: Keys) -> list[dict]:
    as_of = scan["as_of"]
    prev_f = {f["finding_id"]: f for f in (prev or {}).get("findings", [])}
    accepted = {}
    for a in scan.get("accepted_risks", []):
        if a.get("expires") and a["expires"] < as_of[:10]:
            continue
        accepted[a["finding_id"]] = a
    out = []
    current = set()
    for f in findings:
        f = dict(f)
        current.add(f["finding_id"])
        p = prev_f.get(f["finding_id"])
        if p is not None and p.get("state") != "mitigated":
            f["state"], f["first_seen"] = "open", p.get("first_seen") or as_of
        else:
            f["state"], f["first_seen"] = "new", as_of
            if p is not None:
                f["caveats"] = f["caveats"] + ["Previously reported as mitigated; observed again in this scan."]
        f["last_seen"] = as_of
        a = accepted.get(f["finding_id"])
        if a:
            f["state"] = "accepted-risk"
            f["accepted_risk"] = {k: a.get(k) for k in ("accepted_by", "reason", "expires", "reference")}
        out.append(f)
    for pid, p in sorted(prev_f.items()):
        if pid in current or p.get("state") == "mitigated":
            continue
        q = {k: v for k, v in p.items() if k not in ("rank", "accepted_risk", "verification")}
        if _unit_assessed(scan, keys, p):
            q["state"] = "mitigated"
            q["verification"] = (f"absent from this scan while coverage unit {p.get('coverage_unit')} was assessed: "
                                 "verified mitigated delta")
            q["mitigation_observed_at"] = as_of
        else:
            q["state"] = "not-assessed"
            q["verification"] = f"not re-assessed: coverage unit {p.get('coverage_unit')} was not assessed in this scan"
        out.append(q)
    out.sort(key=lambda f: (_STATE_ORDER[f["state"]], *rank_key(f)))
    for i, f in enumerate(out, 1):
        f["rank"] = i
    return out


def control_coverage(cov: dict) -> dict:
    out = {}
    for c, name in CONTROLS.items():
        assessed = cov["assessed"].get(c, [])
        na = [{k: x[k] for k in ("unit", "location", "reason")} for x in cov["not_assessed"] if c in x["controls"]]
        un = [{k: x[k] for k in ("unit", "location", "reason")} for x in cov["unavailable"] if c in x["controls"]]
        if assessed and not na and not un:
            status = "assessed"
        elif assessed:
            status = "partially assessed"
        elif un and not na:
            status = "unavailable"
        else:
            status = "not assessed"
        out[c] = {"control": name, "status": status, "assessed": assessed, "not_assessed": na, "unavailable": un,
                  "counts": cov.get("counts", {}).get(c, {}),
                  "suppressed_candidates": [s for s in cov.get("suppressed", []) if s["control"] == c]}
    return out


def _size(n: int) -> str:
    for unit, div in (("GiB", 1 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)):
        if n >= div and n % div == 0:
            return f"{n // div} {unit}"
    return f"{n} B"


def build_body(rs: ReportStore, scan: dict, findings: list[dict], prev: dict | None, prev_meta) -> dict:
    sm = scan["manifest"]
    active = [f for f in findings if f["state"] in ("new", "open", "accepted-risk")]
    by_sev = {s: sum(1 for f in active if f["severity"] == s) for s in SEVERITIES}
    by_state: dict[str, int] = {}
    for f in findings:
        by_state[f["state"]] = by_state.get(f["state"], 0) + 1
    cov = scan["coverage"]
    budget = {k: (_size(v) if k.endswith("bytes") else v) for k, v in sm["budget"].items()}
    return rs.new_body(
        "exposure",
        report_schema=REPORT_SCHEMA_VARIANT,
        method_version=METHOD_VERSION,
        detector_version=scan["detector_version"],
        title="Exposure assessment (readiness)",
        statement=STATEMENT,
        config_sha256=scan["config_sha256"],
        scan={
            "scan_id": scan["scan_id"], "as_of": scan["as_of"], "manifest_sha256": scan["manifest_sha256"],
            "config_sha256": scan["config_sha256"], "owner": sm["owner"], "legal_basis": sm["legal_basis"],
            "supplied_by": sm["supplied_by"], "received_at": sm["received_at"], "budget": budget,
            "observation_window": sm["observation_window"], "stale_after_days": sm["stale_after_days"],
            "roots": sm["roots"], "databases": sm["databases"], "identity_inputs": sm["identity_inputs"],
            "assets_sha256": sm["assets_sha256"], "accepted_risks_sha256": sm["accepted_risks_sha256"],
            "patient_data_assets": sm["patient_data_assets"], "suppress_test_fixtures": sm["suppress_test_fixtures"],
        },
        sources=scan["sources"],
        previous_report={"version": prev_meta[0], "report_sha256": prev_meta[2]} if prev_meta else None,
        summary={
            "findings": len(active), "by_severity": by_sev,
            "by_control": {c: sum(1 for f in active if f["control_id"] == c) for c in CONTROLS},
            "by_state": dict(sorted(by_state.items())),
            "coverage_status": {c: v["status"] for c, v in control_coverage(cov).items()},
        },
        findings=findings,
        coverage=control_coverage(cov),
        exclusions={
            "declared_patterns": sm["exclusions"] + [f"{r['id']}: {p}" for r in sm["roots"] for p in r.get("exclusions", [])],
            "applied": cov["exclusions"], "counts": cov["exclusion_counts"],
            "suppressed_secret_candidates": [s for s in cov["suppressed"] if s["control"] == "A1"],
            "overflow": cov["overflow"],
        },
        missing_evidence=cov["missing_evidence"],
        parser_failures={"counts": cov["parser_failure_counts"], "items": cov["parser_failures"]},
        accepted_risks=scan.get("accepted_risks", []),
        guardrails=GUARDRAILS,
        remediation_governance=GOVERNANCE,
        limitations=LIMITATIONS,
        stable_fields=STABLE_FIELDS,
    )


def findings_csv(body: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["rank", "finding_id", "state", "severity", "control_id", "rule_id", "title", "asset_id",
                "target_asset_id", "location", "principal", "likelihood", "impact", "basis", "confidence", "first_seen",
                "last_seen", "suggested_fix", "owner", "evidence_ids"])
    for f in body["findings"]:
        loc = f.get("location") or {}
        w.writerow([f["rank"], f["finding_id"], f["state"], f["severity"], f["control_id"], f["rule_id"], f["title"],
                    (f.get("asset") or {}).get("asset_id") or "", (f.get("target_asset") or {}).get("asset_id") or "",
                    loc.get("display", ""), loc.get("principal") or "", f["likelihood"], f["impact"], f["basis"],
                    f["confidence"], f.get("first_seen", ""), f.get("last_seen", ""), f["suggested_fix"]["action"],
                    (f.get("ownership") or {}).get("owner", ""), " ".join(f["evidence_ids"])])
    return buf.getvalue().encode("utf-8")


def render_pdf(body: dict) -> bytes:
    S = pdfmod.Section
    s = body["summary"]
    sc = body["scan"]
    secs = [S("Summary", [
        body["statement"],
        f"Active findings: {s['findings']} (" + ", ".join(f"{k} {v}" for k, v in s["by_severity"].items() if v) + ").",
        "By control: " + "; ".join(f"{c} {CONTROLS[c]} {n}" for c, n in s["by_control"].items()) + ".",
        "States: " + ", ".join(f"{k} {v}" for k, v in s["by_state"].items()) + ".",
        "Coverage: " + "; ".join(f"{c} {st}" for c, st in s["coverage_status"].items()) + ".",
    ])]
    rows = [["#", "Severity", "Ctl", "Finding", "Asset", "Location", "State", "Conf."]]
    for f in body["findings"]:
        rows.append([str(f["rank"]), f["severity"], f["control_id"], f["title"][:90],
                     (f.get("asset") or {}).get("asset_id") or (f.get("asset") or {}).get("name") or "",
                     (f.get("location") or {}).get("display", "")[:80], f["state"], f"{f['confidence']:.2f}"])
    mm = 2.835
    secs.append(S("Ranked findings", [], rows, [8 * mm, 15 * mm, 9 * mm, 48 * mm, 20 * mm, 45 * mm, 16 * mm, 13 * mm]))
    detail = []
    for f in body["findings"]:
        detail.append(f"#{f['rank']} {f['finding_id']} [{f['severity']}, {f['state']}] {f['title']} - "
                      f"{(f.get('location') or {}).get('display', '')}")
        detail.append(f"Impact ({f['impact']}): {f['severity_rationale'].get('impact', '')}. Likelihood ({f['likelihood']}): "
                      f"{f['severity_rationale'].get('likelihood', '')}. Basis: {f['basis']}; confidence "
                      f"{f['confidence']:.2f} ({f['confidence_reason']}). Owner: {(f.get('ownership') or {}).get('owner', '')}.")
        if f.get("redacted_context"):
            detail.append(f"Redacted context: {f['redacted_context']}")
        if f.get("verification"):
            detail.append(f"Verification: {f['verification']}")
        if f.get("caveats"):
            detail.append("Caveats: " + " ".join(f["caveats"]))
        detail.append(f"Suggested fix ({f['suggested_fix']['action']}): {f['suggested_fix']['text']}")
    secs.append(S("Finding details", detail, page_break_before=True))
    crow = [["Control", "Status", "Assessed", "Not assessed", "Unavailable"]]
    for c, v in body["coverage"].items():
        crow.append([f"{c} {v['control']}", v["status"], str(len(v["assessed"])), str(len(v["not_assessed"])),
                     str(len(v["unavailable"]))])
    gaps = []
    for c, v in body["coverage"].items():
        for x in v["not_assessed"][:40]:
            gaps.append(f"{c} not assessed - {x['unit']}{' ' + x['location'] if x.get('location') else ''}: {x['reason']}")
        for x in v["unavailable"][:40]:
            gaps.append(f"{c} unavailable - {x['unit']}{' ' + x['location'] if x.get('location') else ''}: {x['reason']}")
    secs.append(S("Coverage by control", gaps, crow, page_break_before=True))
    ex = body["exclusions"]
    secs.append(S("Exclusions and suppressed candidates",
                  [f"Declared exclusion patterns: {', '.join(ex['declared_patterns']) or 'none'}."]
                  + [f"{e['kind']} - {e['location'] or e['unit']}: {e['reason']}" for e in ex["applied"][:60]]
                  + [f"Suppressed secret candidates ({x['reason']}): {x['count']}" for x in ex["suppressed_secret_candidates"]]))
    secs.append(S("Missing evidence", [f"{m['control']} {m['item']}: {m['reason']}" + (f" ({m['count']})" if m.get("count") else "")
                                       for m in body["missing_evidence"]] or ["None recorded."]))
    pf = body["parser_failures"]["counts"]
    secs.append(S("Parser failures", [f"{p['format']}: {p['error_class']} x{p['count']}" for p in pf] or ["None."]))
    secs.append(S("Accepted risks", [f"{a['finding_id']}: accepted by {a['accepted_by']} - {a['reason']}"
                                     + (f" (expires {a['expires']})" if a.get("expires") else "")
                                     for a in body["accepted_risks"]] or ["None declared."]))
    src = [["Source", "Unit", "Kind", "Content SHA-256 (prefix)"]] + [
        [x["source_id"], x["unit"], x["kind"], (x.get("content_sha256") or "")[:16]] for x in body["sources"]]
    secs.append(S("Method, inputs and guardrails", [
        f"Method {body['method_version']} (detectors {body['detector_version']}). Snapshot as of {sc['as_of']}; owner "
        f"{sc['owner']}; legal basis: {sc['legal_basis']}.",
        f"Manifest SHA-256 {sc['manifest_sha256']}; configuration SHA-256 {sc['config_sha256']}; previous report "
        f"SHA-256 {body['previous_report_sha256'] or 'none (first version)'}.",
        *body["guardrails"]], src, page_break_before=True))
    secs.append(S("Remediation governance", body["remediation_governance"] + ["Limitations:"] + body["limitations"]))
    return pdfmod.render(f"Exposure assessment - {body['case_id']} v{body['version']}",
                         [f"Case {body['case_id']} - report version {body['version']} - snapshot as of {sc['as_of']}",
                          "DRAFT until released by the Information Officer (tscope release --kind exposure)."],
                         secs, footer=f"Tripline Scope exposure report {body['case_id']} v{body['version']} - "
                                      "no secret values or patient records")


def build_report(ctx, *, pdf: bool = True):
    case, store = ctx.case, ctx.store
    if not store.exists(SCAN_FILE) or not store.exists(FINDINGS_FILE):
        raise NotReady("no exposure scan results in this case: run 'tscope exposure scan' first")
    scan = store.read_json(SCAN_FILE)
    findings = store.read_json(FINDINGS_FILE)
    ctx.input("scan.json", store.file_sha256(SCAN_FILE))
    ctx.input("findings.json", store.file_sha256(FINDINGS_FILE))
    rs = ReportStore(case)
    prev_meta = rs.latest("exposure")
    prev = rs.load("exposure") if prev_meta else None
    states = assign_states(findings, prev, scan, Keys(store))
    body = build_body(rs, scan, states, prev, prev_meta)
    pdf_bytes = render_pdf(body) if pdf else None
    attachments = {"findings.csv": findings_csv(body), "coverage.json": canonical_bytes(body["coverage"])}
    provider = ctx.home.provider_signer()
    draft = rs.save_draft("exposure", body, pdf=pdf_bytes, attachments=attachments, provider=provider)
    return draft, body
