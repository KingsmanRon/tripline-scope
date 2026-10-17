"""Evidence bundle: released, verified module reports → a bounded, allowlisted index of evidence and facts.

The bundle is the *only* thing a provider sees. It is built from released report versions of ``exposure`` (A),
``paths`` (B) and ``scope`` (C), each verified (signature and chain) first. Drafts, extracts, restores, logs, the
notification pack and case sources are never read. Items keep the ids already used in the reports (``AF-``,
``PATH-``, ``CLM-``, ``ANOM-``, ``GAP-``, ``COR-``, ``REC-``, ``IM-``); facts (``FACT-``) carry every number a
provider may quote. An item eligible to establish exfiltration also states exactly what it covers: ``tables``,
``categories`` (data categories) and ``fact:`` references in ``related`` (the only counts an exfiltration claim may
quote); the validator holds exfiltration claims to that scope. Only allowlisted fields are copied; strings are cleaned, re-scrubbed and truncated; Module B
and A text is untrusted data (it can contain attacker-controlled names) and is presented to providers as data.
"""

from __future__ import annotations

import re

from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import IntegrityError
from tripline_scope.core.evidence import EXFILTRATION_EVIDENCE_KINDS, Consequence
from tripline_scope.core.redact import scrub_text
from tripline_scope.core.reports import ReportStore

SCHEMA = "tripline.investigation-bundle/v1"
MODULE_KINDS = ("exposure", "paths", "scope")
MODULE = {"exposure": "A", "paths": "B", "scope": "C"}
MAX_ITEMS = 400
MAX_FACTS = 200
MAX_TEXT = 300
MAX_BYTES = 256 * 1024
CLASSES = [str(c) for c in Consequence]
# families an investigation of a database breach would want; Module B ingests the first group when supplied
KNOWN_FAMILIES = {
    "database audit": {"mssql_audit", "pgaudit"},
    "Windows security events": {"win_security"},
    "identity provider sign-ins": {"entra_signin"},
    "VPN sessions": {"vpn"},
    "firewall flows": {"firewall"},
    "web proxy": {"proxy"},
    "web server": {"iis", "apache", "nginx"},
}
# the only Module B counts an exfiltration claim backed by a Module B item may quote
_B_EXFIL_FACTS = ["fact:FACT-B-confirmed_exfiltration-tables", "fact:FACT-B-sensitive_tables_by_class-exfiltration_evidenced"]
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f​-‏ -‮⁦-⁩]")


def text(s, limit: int = MAX_TEXT) -> str | None:
    """Untrusted report text → single-line, control-free, re-scrubbed, bounded."""
    if s is None:
        return None
    s = _CTRL.sub(" ", str(s))
    s = " ".join(s.split())
    return scrub_text(s)[:limit]


def _ids(xs, limit: int = 20) -> list[str]:
    return [str(x)[:64] for x in (xs or [])][:limit]


def _acct(a) -> dict | None:
    if not isinstance(a, dict):
        return None
    return {"account_ref": str(a.get("account_ref") or "")[:20] or None, "label": text(a.get("label"), 80)}


class _Builder:
    def __init__(self):
        self.items: dict[str, dict] = {}
        self.facts: dict[str, dict] = {}
        self.assets: set[str] = set()
        self.sources: set[str] = set()
        self.dropped = {"items": 0, "facts": 0}

    def item(self, iid: str, kind: str, version: int, typ: str, **fields) -> None:
        if not iid or iid in self.items:
            return
        rec = {"id": str(iid)[:64], "module": MODULE[kind], "report": {"kind": kind, "version": version}, "type": typ,
               "basis": None, "consequence_class": None, "statement": None, "severity": None, "assets": [],
               "sources": [], "tables": [], "accounts": [], "time_window": None, "confidence": None,
               "limitations": [], "exfiltration_evidence_kind": None, "categories": [], "related": []}
        for k, v in fields.items():
            if k not in rec:
                raise KeyError(k)
            rec[k] = v
        if rec["consequence_class"] not in (None, *CLASSES):
            rec["consequence_class"] = None
        rec["assets"] = sorted({a for a in rec["assets"] if a})
        rec["sources"] = sorted({s for s in rec["sources"] if s})
        self.assets |= set(rec["assets"])
        self.sources |= set(rec["sources"])
        self.items[rec["id"]] = rec

    def fact(self, fid: str, value, unit: str, kind: str, version: int, pointer: str) -> None:
        if isinstance(value, bool) or value is None:
            return
        if isinstance(value, float):
            value = round(value, 4)
        if not isinstance(value, (int, float)):
            value = text(value, 120)
        self.facts[fid] = {"value": value, "unit": unit, "source": {"kind": kind, "version": version, "pointer": pointer}}


def _window(a, b) -> dict | None:
    return {"start": a, "end": b} if (a or b) else None


# ------------------------------------------------------------------------------------------------- module A
def _exposure(bd: _Builder, body: dict, v: int) -> None:
    findings = sorted([f for f in body.get("findings", []) if isinstance(f, dict)], key=lambda f: f.get("rank") or 10**9)
    for f in findings[:120]:
        loc = f.get("location") if isinstance(f.get("location"), dict) else {}
        assets = [((f.get("asset") or {}).get("asset_id")), ((f.get("target_asset") or {}).get("asset_id"))]
        bd.item(f.get("finding_id"), "exposure", v, "finding", basis=f.get("basis"), statement=text(f.get("title")),
                severity=f.get("severity"), assets=assets, sources=_ids(f.get("source_ids")),
                accounts=[{"account_ref": None, "label": text(loc.get("principal"), 80)}] if loc.get("principal") else [],
                time_window=_window(f.get("first_seen"), f.get("last_seen")), confidence=f.get("confidence"),
                limitations=[text(c, 160) for c in (f.get("caveats") or [])][:3],
                related=[f"control:{f.get('control_id')}", f"rule:{f.get('rule_id')}", f"state:{f.get('state')}",
                         f"fix:{text((f.get('suggested_fix') or {}).get('text'), 200)}"])
    summ = body.get("summary") or {}
    for group in ("by_severity", "by_control", "by_state"):
        for k, n in sorted((summ.get(group) or {}).items()):
            bd.fact(f"FACT-A-{group[3:]}-{k}", n, "findings", "exposure", v, f"summary.{group}.{k}")
    bd.fact("FACT-A-findings-total", len(body.get("findings", [])), "findings", "exposure", v, "findings")
    for ctl, cov in sorted((body.get("coverage") or {}).items()):
        if not isinstance(cov, dict):
            continue
        for i, u in enumerate((cov.get("not_assessed") or []) + (cov.get("unavailable") or [])):
            unit = u.get("unit") if isinstance(u, dict) else u
            iid = "XA-" + sha256_hex(f"{ctl}|{unit}".encode())[:12]
            bd.item(iid, "exposure", v, "coverage_gap", basis="unknown", consequence_class="undetermined",
                    statement=text(f"{ctl} not assessed for {unit}: {(u.get('reason') if isinstance(u, dict) else '')}"),
                    limitations=["a condition that was not assessed is not evidence that it is absent"])
            if i >= 10:
                break


# ------------------------------------------------------------------------------------------------- module B
def _paths(bd: _Builder, body: dict, v: int) -> list[str]:
    inputs = body.get("inputs") or {}
    host_asset, families = {}, set()
    for s in inputs.get("sources", []):
        families.add(s.get("family"))
    for a in (body.get("regulator") or {}).get("affected_systems", []):
        if isinstance(a, dict) and a.get("host") and a.get("asset_id"):
            host_asset[str(a["host"]).lower().split(".")[0]] = a["asset_id"]
    for c in inputs.get("corroborations", []):
        kind = c.get("kind")
        eligible = kind in EXFILTRATION_EVIDENCE_KINDS and bool(c.get("qualifies_as_exfiltration_evidence"))
        bd.item(c.get("corroboration_id"), "paths", v, "corroboration", basis="observation",
                consequence_class="exfiltration_evidenced" if eligible else None,
                statement=text(c.get("establishes")), tables=_ids(c.get("tables")), sources=_ids(c.get("evidence_ids")),
                exfiltration_evidence_kind=kind if eligible else None,
                limitations=[text(c.get("does_not_establish"))] if c.get("does_not_establish") else [],
                related=_B_EXFIL_FACTS if eligible else [])
    tables = [t for t in body.get("tables", []) if isinstance(t, dict)]
    order = {c: i for i, c in enumerate(["exfiltration_evidenced", "egress_suspected", "export_or_staging_observed",
                                         "access_observed", "undetermined"])}
    tables.sort(key=lambda t: (order.get(t.get("consequence_class"), 9), t.get("table") or ""))
    for t in tables:
        cl = t.get("claim") or {}
        if t.get("consequence_class") is None and t.get("window_class") in (None, "none_observed"):
            continue
        exfil = t.get("consequence_class") == "exfiltration_evidenced" and \
            cl.get("exfiltration_evidence_kind") in EXFILTRATION_EVIDENCE_KINDS
        bd.item(cl.get("claim_id"), "paths", v, "table_claim", basis=cl.get("basis"),
                consequence_class=t.get("consequence_class"), statement=text(cl.get("statement")),
                tables=[t.get("table")], sources=_ids(t.get("covering_sources")),
                time_window=_window(*(cl.get("source_time_window") or [None, None])[:2]), confidence=cl.get("confidence"),
                exfiltration_evidence_kind=cl.get("exfiltration_evidence_kind"),
                limitations=[text(x, 160) for x in cl.get("limitations", [])][:3],
                related=_ids(t.get("paths")) + [f"window:{t.get('window_class')}"] + _ids([c for c in t.get("corroborations", []) if isinstance(c, str)])
                + (_B_EXFIL_FACTS if exfil else []))
    for p in sorted(body.get("paths", []), key=lambda p: p.get("rank") or 10**9)[:60]:
        cl = p.get("claim") or {}
        route = p.get("route") or {}
        host = str(route.get("database_host") or "").lower().split(".")[0]
        stages = [f"{s.get('stage')}:{s.get('label')}" for s in p.get("stages", [])]
        bd.item(p.get("path_id"), "paths", v, "path", basis=cl.get("basis"), consequence_class=p.get("consequence_class"),
                statement=text(cl.get("statement")), assets=[host_asset.get(host)], sources=_ids(cl.get("source_ids")),
                tables=[t.get("table") for t in p.get("tables", []) if isinstance(t, dict)][:12],
                accounts=[a for a in [_acct(route.get("account"))] if a] + [a for a in (_acct(x) for x in p.get("upstream_accounts", [])) if a][:3],
                time_window=_window(p.get("first_activity"), p.get("last_activity")), confidence=p.get("chain_confidence"),
                limitations=[text(x, 160) for x in p.get("limitations", [])][:4],
                related=stages + _ids(p.get("anomalies"), 12) + [f"egress:{text(d, 80)}" for d in p.get("egress_destinations", [])][:4])
    for a in body.get("anomalies", [])[:60]:
        cl = a.get("claim") or {}
        bd.item(a.get("anomaly_id"), "paths", v, "anomaly", basis=cl.get("basis"),
                consequence_class=cl.get("consequence_class"), statement=text(cl.get("statement") or a.get("title")),
                severity=a.get("severity"), sources=_ids(cl.get("source_ids")),
                accounts=[x for x in (_acct(y) for y in a.get("accounts", [])) if x][:4],
                time_window=_window(a.get("first"), a.get("last")), confidence=cl.get("confidence"),
                limitations=[text(x, 160) for x in (cl.get("limitations") or [])][:3] +
                [text(x, 160) for x in (a.get("false_positive_caveats") or [])][:2],
                related=[f"detector:{a.get('detector')}"] + _ids(a.get("path_ids"), 8))
    for g in body.get("gaps", [])[:60]:
        bd.item(g.get("gap_id"), "paths", v, "gap", basis=g.get("basis") or "unknown", consequence_class="undetermined",
                statement=text(g.get("description")), sources=[g.get("source_id")],
                assets=[host_asset.get(str(g.get("host") or "").lower().split(".")[0])],
                time_window=_window(g.get("start"), g.get("end")),
                limitations=["missing or unreliable logs: activity in this gap is not determinable, not absent"],
                related=[f"kind:{g.get('kind')}", f"scope:{g.get('scope')}"] + ([f"database:{g.get('database')}"] if g.get("database") else []))
    for m in body.get("indicator_matches", [])[:15]:
        bd.item(m.get("match_id"), "paths", v, "indicator_match", basis="observation", statement=text(m.get("statement")),
                time_window=_window(m.get("ts_utc"), m.get("ts_utc")),
                related=[f"indicator:{m.get('indicator_type')}:{text(m.get('indicator_value'), 80)}", f"validity:{m.get('validity')}"])
    for r in (body.get("containment") or {}).get("recommendations", [])[:40]:
        tgt = r.get("target") or {}
        bd.item(r.get("rec_id"), "paths", v, "recommendation", basis=r.get("basis"), statement=text(r.get("action")),
                severity=r.get("urgency"), assets=[tgt.get("asset_id")],
                accounts=[_acct(tgt)] if tgt.get("kind") == "account" else [],
                confidence=r.get("confidence"), limitations=[text(x, 160) for x in r.get("caveats", [])][:3],
                related=[f"category:{r.get('category')}"] + _ids(r.get("path_ids"), 6) + _ids(r.get("anomaly_ids"), 6)
                + [x.get("finding_id") for x in r.get("module_a_refs", []) if isinstance(x, dict)][:6])
    cls = body.get("classification") or {}
    for group in ("paths_by_class", "sensitive_tables_by_class"):
        for k, n in sorted((cls.get(group) or {}).items()):
            bd.fact(f"FACT-B-{group}-{k}", n, "paths" if group == "paths_by_class" else "tables", "paths", v,
                    f"classification.{group}.{k}")
    counts = body.get("counts") or {}
    for tier in ("observed_access", "possible_exposure", "confirmed_exfiltration"):
        t = counts.get(tier) or {}
        bd.fact(f"FACT-B-{tier}-tables", t.get("tables"), "tables", "paths", v, f"counts.{tier}.tables")
    bd.fact("FACT-B-rows_returned_as_logged", (counts.get("observed_access") or {}).get("rows_returned_as_logged"), "rows",
            "paths", v, "counts.observed_access.rows_returned_as_logged")
    missing = [name for name, fams in KNOWN_FAMILIES.items() if not (fams & families)]
    missing += [text(x, 160) for x in (body.get("forensic_handoff") or {}).get("not_covered", [])]
    return missing


# ------------------------------------------------------------------------------------------------- module C
def _scope(bd: _Builder, body: dict, v: int) -> None:
    pe = body.get("preliminary_estimate") or {}
    for k in ("point", "lower", "upper"):
        bd.fact(f"FACT-C-preliminary-{k}", pe.get(k), "people", "scope", v, f"preliminary_estimate.{k}")
    counts = body.get("counts") or {}
    b = counts.get("bounds") or {}
    for k in ("lower", "upper"):
        bd.fact(f"FACT-C-people-{k}", b.get(k), "people", "scope", v, f"counts.bounds.{k}")
    for k, n in sorted((counts.get("people_per_category") or {}).items()):
        bd.fact(f"FACT-C-category-{k}", n, "people", "scope", v, f"counts.people_per_category.{k}")
    for k, n in sorted((counts.get("notification_routes") or {}).items()):
        bd.fact(f"FACT-C-route-{k}", n, "people", "scope", v, f"counts.notification_routes.{k}")
    tiers = body.get("scope_tiers") or {}
    for tier, t in sorted(tiers.items()):
        if not isinstance(t, dict):
            continue
        val = t.get("count", t.get("proposed_count"))
        bd.fact(f"FACT-C-tier-{tier}", val, "people", "scope", v, f"scope_tiers.{tier}")
        kind = t.get("exfiltration_evidence_kind")
        eligible = tier == "confirmed_exfiltration" and kind in EXFILTRATION_EVIDENCE_KINDS and isinstance(val, int)
        cats = []
        if eligible:
            # the data categories the evidence covers: only those with people counted in this tier
            for k, n in sorted((t.get("people_per_category") or {}).items()):
                if isinstance(n, int) and not isinstance(n, bool):
                    bd.fact(f"FACT-C-exfil-category-{k}", n, "people", "scope", v,
                            f"scope_tiers.confirmed_exfiltration.people_per_category.{k}")
                    if n > 0:
                        cats.append(str(k)[:40])
        bd.item(f"SCOPE-{tier}", "scope", v, "scope_tier", basis=t.get("basis"),
                consequence_class="exfiltration_evidenced" if eligible else None, statement=text(t.get("explanation")),
                exfiltration_evidence_kind=kind if eligible else None, categories=cats,
                related=[f"fact:FACT-C-tier-{tier}"] + [f"fact:FACT-C-exfil-category-{k}" for k in cats]
                + ([f"decided_by:{t.get('decided_by')}"] if tier == "notification_scope" else []))
    unres = 0
    for s in (body.get("rows_per_source") or {}).values():
        for t in s.get("tables", []) if isinstance(s, dict) else []:
            unres += int(t.get("unresolvable_identity_rows") or 0) + int(t.get("unresolvable_dependent_rows") or 0)
    bd.fact("FACT-C-unresolvable-rows", unres, "rows", "scope", v, "rows_per_source[*].tables[*].unresolvable_*")
    for k, n in sorted((body.get("measured_error_rates") or {}).items()):
        if k.endswith("_pct"):
            bd.fact(f"FACT-C-measured-{k}", n, "percent (synthetic benchmark)", "scope", v, f"measured_error_rates.{k}")
    bd.fact("FACT-C-report-status", body.get("report_status"), "status", "scope", v, "report_status")


def build(case, home) -> dict:
    """Build and return the bundle (``bundle_sha256`` included). Raises IntegrityError if a released chain fails."""
    rs = ReportStore(case)
    bd = _Builder()
    reports, not_assessed, missing_families = [], [], []
    # items are inserted in priority order (B, then C, then A) so size truncation drops Module A detail first
    for kind in ("paths", "scope", "exposure"):
        latest = rs.latest(kind)
        if latest is None:
            not_assessed.append(kind)
            continue
        res = rs.verify(kind, home)
        if not res.ok:
            raise IntegrityError(f"released {kind} reports failed verification; refusing to analyse them")
        n, _, sha = latest
        body = rs.load(kind, n)
        if body.get("case_id") != case.case_id:
            raise IntegrityError(f"released {kind} report belongs to another case")
        reports.append({"kind": kind, "version": n, "report_sha256": sha, "released": True, "verified": True})
        if kind == "exposure":
            _exposure(bd, body, n)
        elif kind == "paths":
            missing_families = _paths(bd, body, n)
        else:
            _scope(bd, body, n)
    if "paths" in not_assessed:
        missing_families = ["access-path logs (Module B not assessed)"]
    reports.sort(key=lambda r: MODULE_KINDS.index(r["kind"]))
    not_assessed.sort(key=MODULE_KINDS.index)
    items = list(bd.items.values())
    if len(items) > MAX_ITEMS:
        bd.dropped["items"] = len(items) - MAX_ITEMS
        items = items[:MAX_ITEMS]
    facts = dict(sorted(bd.facts.items())[:MAX_FACTS])
    bd.dropped["facts"] = max(0, len(bd.facts) - MAX_FACTS)
    win = (case.config.get("incident_window") or {})
    bundle = {
        "schema": SCHEMA,
        "case_id": case.case_id,
        "case_mode": case.mode,
        "incident_window": {"start": win.get("start"), "end": win.get("end")},
        "reports": reports,
        "not_assessed": not_assessed,
        "evidence": {i["id"]: i for i in items},
        "facts": facts,
        "assets": sorted(bd.assets),
        "sources": sorted(bd.sources),
        "missing_source_families": missing_families,
        "consequence_order": ["access_observed", "export_or_staging_observed", "egress_suspected", "exfiltration_evidenced"],
        "truncated": bd.dropped,
    }
    data = canonical_bytes(bundle)
    while len(data) > MAX_BYTES and bundle["evidence"]:
        # drop lowest-priority items (the end of the ordered list) until the bundle fits
        last = list(bundle["evidence"])[-1]
        del bundle["evidence"][last]
        bundle["truncated"]["items"] += 1
        data = canonical_bytes(bundle)
    bundle["bundle_sha256"] = sha256_hex(data)
    return bundle


def bundle_hash(bundle: dict) -> str:
    return sha256_hex(canonical_bytes({k: v for k, v in bundle.items() if k != "bundle_sha256"}))
