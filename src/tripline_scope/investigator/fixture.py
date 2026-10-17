"""Deterministic, rule-based fixture output for CI and synthetic demonstrations.

This is NOT AI inference and is never presented as such: its provenance says ``provider_kind: fixture`` and
``is_model_inference: false`` everywhere it appears (CLI, result, report, dashboard). It builds a candidate from the
bundle with fixed rules so the whole pipeline (validation, review, signed report, dashboard) can be exercised
reproducibly without a model. It goes through the same validator as any model output.
"""

from __future__ import annotations

import json

from .schema import CANDIDATE_SCHEMA

FIXTURE_MODEL_ID = "tripline-fixture-rules"
FIXTURE_VERSION = "1.0.0"
ORDER = ["access_observed", "export_or_staging_observed", "egress_suspected", "exfiltration_evidenced"]
HUMAN = {"access_observed": "access observed (reading, not proof of theft)",
         "export_or_staging_observed": "export or staging observed (a copy inside the hospital)",
         "egress_suspected": "egress suspected (outbound transfer of unknown content)",
         "exfiltration_evidenced": "exfiltration evidenced by independently corroborated evidence",
         "undetermined": "undetermined (gaps prevent a determination)"}
PRIO = {"critical": "immediate", "high": "immediate", "medium": "next", "low": "later"}


def _rank(c) -> int:
    return ORDER.index(c) if c in ORDER else -1


def _rel(item, prefix):
    return [r for r in item.get("related", []) if isinstance(r, str) and r.startswith(prefix)]


def candidate(bundle: dict) -> dict:
    E = bundle["evidence"]
    facts = bundle["facts"]
    by_type: dict[str, list[dict]] = {}
    for it in E.values():
        by_type.setdefault(it["type"], []).append(it)
    paths = sorted(by_type.get("path", []), key=lambda i: (-_rank(i["consequence_class"]), i["id"]))
    gaps = sorted(by_type.get("gap", []), key=lambda i: i["id"])[:4]
    findings = sorted(by_type.get("finding", []), key=lambda i: (["critical", "high", "medium", "low", "info"].index(
        i["severity"]) if i["severity"] in ("critical", "high", "medium", "low", "info") else 9, i["id"]))
    corr = [c for c in by_type.get("corroboration", []) if c.get("exfiltration_evidence_kind")]
    hyps, steps, rem, missing, unproven = [], [], [], [], []
    fact_pe = facts.get("FACT-C-tier-possible_exposure")
    pe_q = [{"fact_id": "FACT-C-tier-possible_exposure", "value": fact_pe["value"]}] if fact_pe and isinstance(
        fact_pe["value"], int) else []
    gap_ids = [g["id"] for g in gaps]

    if paths:
        top = paths[0]
        cls = top["consequence_class"] or "undetermined"
        anomalies = [r for r in top.get("related", []) if r in E and E[r]["type"] == "anomaly"][:6]
        tables = top.get("tables", [])[:3]
        tclaims = [c["id"] for c in by_type.get("table_claim", []) if set(c.get("tables", [])) & set(tables)][:4]
        asset_f = [f["id"] for f in findings if set(f["assets"]) & set(top["assets"])][:3]
        cover = [c for c in corr if set(c.get("tables", [])) & set(top.get("tables", []))]
        support = [top["id"]] + anomalies + tclaims + asset_f + [c["id"] for c in cover]
        asserted = "exfiltration_evidenced" if cover else cls
        acct = (top.get("accounts") or [{}])[0].get("account_ref")
        who = f"The account {acct}" if acct else "An account"
        where = f" on {top['assets'][0]}" if top["assets"] else ""
        if cover:
            # the exfiltration claim names only what the corroboration covers; other tables keep the path's class
            covered = sorted({t for c in cover for t in c.get("tables", [])} & set(top.get("tables", [])))
            others = [t for t in tables if t not in covered]
            stmt = (f"Exfiltration is evidenced for {', '.join(covered)} by {', '.join(c['id'] for c in cover)}; "
                    f"{'the account ' + acct if acct else 'an account'} read {'it' if len(covered) == 1 else 'them'}{where} through "
                    f"the route shown in {top['id']}.")
            if others:
                stmt += (f" For {', '.join(others)} exfiltration is not established: Tripline classifies the outcome "
                         f"there as {HUMAN[cls]}.")
        else:
            stmt = (f"{who} read sensitive tables ({', '.join(tables)}){where} through the route shown in {top['id']}; "
                    f"Tripline classifies the data outcome as {HUMAN[asserted]}.")
        if pe_q:
            stmt += f" Module C's possible-exposure population is {pe_q[0]['value']} people."
        hyps.append({
            "hypothesis_id": "H1", "rank": "main", "statement": stmt, "basis": "hypothesis", "consequence_class": asserted,
            "supporting_evidence": support + (["FACT-C-tier-possible_exposure"] if pe_q else []),
            "contradicting_evidence": gap_ids, "assets": top["assets"], "sources": top["sources"][:5],
            "time_window": top.get("time_window"), "confidence": "moderate" if gap_ids else "high",
            "confidence_rationale": "Database audit records of the access are observations; the links from sign-in and VPN "
                                    "to the database session are partly correlated by time and address, and the cited "
                                    "gaps leave parts of the window undetermined.",
            "alternative_explanations": ["An authorised administrator performed the activity for a business purpose and "
                                         "the outbound flows were unrelated transfers.",
                                         "Another person used the same account or a shared address."],
            "tests": [{"evidence_needed": "Disk and memory forensics of the database host for the staged export files",
                       "would_resolve": "whether exported files existed, their size and when they were removed"},
                      {"evidence_needed": "Packet capture or proxy content records for the outbound destinations",
                       "would_resolve": "what the outbound flows carried"},
                      {"evidence_needed": "Identity provider MFA and device records for the account's sign-ins",
                       "would_resolve": "who operated the account"}],
            "cannot_conclude": (["Which patient records, if any, left the hospital network: the content of the outbound "
                                 "flows is unknown"] if not cover else
                                ["Which route or session carried the corroborated copy out of the hospital"]) +
                               ["Who operated the account beyond the logged identity",
                                "What happened during the logging gaps"],
            "quantities": pe_q,
        })
        alt = next((p for p in paths if p["id"] != top["id"] and p["consequence_class"] == "export_or_staging_observed"),
                   None) or top
        hyps.append({
            "hypothesis_id": "H2", "rank": "alternative",
            "statement": "The exports were authorised administrative work and any later outbound transfers were "
                         "unrelated; the activity would then be legitimate but unusual for the account.",
            "basis": "hypothesis",
            "consequence_class": "export_or_staging_observed" if _rank(alt["consequence_class"]) >= 1 else "access_observed",
            "supporting_evidence": [alt["id"]], "contradicting_evidence": anomalies[:4] or gap_ids[:1],
            "assets": alt["assets"], "sources": alt["sources"][:5], "time_window": alt.get("time_window"),
            "confidence": "low", "confidence_rationale": "No change record or approval is in the evidence, and the cited "
                                                         "anomalies are unusual for authorised work.",
            "alternative_explanations": ["Unauthorised access as in the main hypothesis."],
            "tests": [{"evidence_needed": "Change and approval records for the database exports",
                       "would_resolve": "whether the exports were authorised"}],
            "cannot_conclude": ["Whether the exports had a business purpose"], "quantities": []})
        top_accts = {a.get("account_ref") for a in top.get("accounts", [])}
        vendor = next((p for p in paths if p["id"] not in (top["id"], alt["id"])
                       and {"web_identity:unresolved", "network:unresolved", "host_application:unresolved"} <= set(p.get("related", []))
                       and not ({a.get("account_ref") for a in p.get("accounts", [])} & top_accts)
                       and any("vendor" in (a.get("label") or "").lower() or "supplier" in (a.get("label") or "").lower()
                               for a in p.get("accounts", []))), None)
        if vendor:
            a5 = [f["id"] for f in findings if "control:A5" in f.get("related", [])][:2]
            hyps.append({
                "hypothesis_id": "H3", "rank": "alternative",
                "statement": f"Some database access came through a route with no upstream identity evidence ({vendor['id']}), "
                             "such as supplier or third-party access, and is unrelated to the main activity.",
                "basis": "hypothesis", "consequence_class": vendor["consequence_class"] or "undetermined",
                "supporting_evidence": [vendor["id"]] + a5, "contradicting_evidence": [],
                "assets": vendor["assets"], "sources": vendor["sources"][:5], "time_window": vendor.get("time_window"),
                "confidence": "low", "confidence_rationale": "The route stops at the database: who connected is unresolved.",
                "alternative_explanations": ["The same actor as in the main hypothesis used another route."],
                "tests": [{"evidence_needed": "Supplier access records and jump-host logs",
                           "would_resolve": "who opened the database session"}],
                "cannot_conclude": ["Who opened the database session"], "quantities": []})
        steps.append({"step": "Preserve and image the database hosts and web servers named in the cited evidence before "
                              "any remediation changes them.", "priority": "immediate", "evidence_ids": [top["id"]]})
        steps.append({"step": "Collect firewall, proxy and DNS records for the outbound destinations linked to the main "
                              "path.", "priority": "immediate", "evidence_ids": [top["id"]]})
        if acct:
            steps.append({"step": f"Validate every session of account {acct} with its owner against change records.",
                          "priority": "next", "evidence_ids": [top["id"]]})
        if not cover:
            unproven.append("That patient records were transmitted outside the hospital.")
        elif others:
            unproven.append(f"That {', '.join(others)} left the hospital: the corroboration covers other tables only.")
        unproven.append("That the outbound destination belongs to the actor: an indicator match is not attribution.")
    elif findings:
        top = findings[0]
        hyps.append({
            "hypothesis_id": "H1", "rank": "main",
            "statement": "The released exposure findings describe conditions that could allow access to patient data; "
                         "without access-path logs they do not show that access occurred.",
            "basis": "hypothesis", "consequence_class": "undetermined", "supporting_evidence": [f["id"] for f in findings[:3]],
            "contradicting_evidence": [], "assets": top["assets"], "sources": top["sources"][:5], "time_window": None,
            "confidence": "low", "confidence_rationale": "Exposure conditions are not evidence of access.",
            "alternative_explanations": ["The conditions were never used."],
            "tests": [{"evidence_needed": "Database audit, Windows security, VPN and firewall logs for the incident window",
                       "would_resolve": "whether the exposed conditions were used"}],
            "cannot_conclude": ["Whether any access or data movement happened"], "quantities": pe_q,
        })
    for g in gaps:
        kind = (_rel(g, "kind:") or ["kind:unknown"])[0][5:]
        missing.append({"description": f"Logs covered by {g['id']} are missing or unreliable; activity there is undetermined.",
                        "source_family": kind, "related_evidence": [g["id"]]})
        steps.append({"step": f"Recover or reconstruct the logs for the gap {g['id']} from backups or other systems.",
                      "priority": "next", "evidence_ids": [g["id"]]})
    for fam in bundle.get("missing_source_families", [])[:6]:
        missing.append({"description": f"Not supplied: {fam}.", "source_family": fam, "related_evidence": []})
    for r in sorted(by_type.get("recommendation", []), key=lambda r: (["critical", "high", "medium", "low"].index(
            r["severity"]) if r["severity"] in ("critical", "high", "medium", "low") else 9, r["id"]))[:8]:
        rem.append({"action": r["statement"], "priority": PRIO.get(r["severity"], "next"), "evidence_ids": [r["id"]],
                    "asset_ids": r["assets"]})
    for f in findings[:4]:
        fix = (_rel(f, "fix:") or [""])[0][4:]
        if fix and fix != "None":
            rem.append({"action": fix, "priority": PRIO.get(f["severity"], "next"), "evidence_ids": [f["id"]],
                        "asset_ids": f["assets"]})
    return {
        "schema": CANDIDATE_SCHEMA, "case_id": bundle["case_id"], "bundle_sha256": bundle["bundle_sha256"],
        "summary": "Deterministic fixture analysis (not AI inference) of the released module reports: a main hypothesis "
                   "and alternatives, each kept within Tripline's evidence classes, with missing evidence, next steps "
                   "and advisory remediation.",
        "hypotheses": hyps, "missing_evidence": missing, "investigation_steps": steps, "remediation": rem,
        "unproven_assertions": unproven,
    }


def output(bundle: dict) -> bytes:
    return json.dumps(candidate(bundle), sort_keys=True).encode("utf-8")
