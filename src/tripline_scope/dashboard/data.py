"""Read models for the Investigation Workbench: pure functions over a case's *released* reports.

Nothing here writes. Inputs are released report versions (``ReportStore``) and, for the AI Investigator section,
the latest validated investigator run read through the case store. Drafts, ``notify/``, extracts, sources and
attachments other than the released Module B timeline are never read.

Missing data is returned as ``{"status": "not_assessed" | "not_determinable" | "awaiting_analysis" | ...}`` and
never as 0. Person-level rows are never returned: the scope report itself carries counts only.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from tripline_scope.core.case import Case
from tripline_scope.core.redact import scrub_text
from tripline_scope.core.reports import ReportStore
from tripline_scope.core.timeutil import parse_utc
from tscope_verify import formats as F

# Report kinds the workbench shows and serves; files that may be downloaded from a released version.
REPORT_KINDS = ("exposure", "paths", "scope", "investigation", "readiness")
SERVABLE_FILES = {F.REPORT_FILE: "application/json", "report.pdf": "application/pdf",
                  F.RELEASE_FILE: "application/json", F.SIGNATURES_FILE: "application/json"}

CONSEQUENCE_CLASSES = ("access_observed", "export_or_staging_observed", "egress_suspected",
                       "exfiltration_evidenced", "undetermined")
# Event-level classes in the Module B timeline add ``not_applicable`` (context events) and ``no_access_observed``.
TIMELINE_CLASSES = CONSEQUENCE_CLASSES + ("not_applicable", "no_access_observed")
FAMILIES = ("mssql_audit", "pg_log", "pgaudit", "iis", "apache", "nginx", "win_security", "entra_signin",
            "vpn", "firewall", "proxy", "indicators", "generic")
# Log-source families Module B can use, grouped by the part of an access path they can establish.
FAMILY_GROUPS = (
    ("identity provider sign-ins", ("entra_signin",)),
    ("VPN", ("vpn",)),
    ("host security (Windows)", ("win_security",)),
    ("web server", ("iis", "apache", "nginx")),
    ("database audit", ("mssql_audit", "pg_log", "pgaudit")),
    ("network flow (firewall / proxy)", ("firewall", "proxy")),
)
EDGE_LABELS = ("direct", "correlated", "unresolved", "observed")

TIMELINE_LIMIT_DEFAULT = 100
TIMELINE_LIMIT_MAX = 500
TIMELINE_OFFSET_MAX = 10_000_000
TIMELINE_PARAMS = {"start", "end", "source", "family", "account", "asset", "class", "offset", "limit"}
_SOURCE = re.compile(r"^SRC-\d{1,6}$")
_ACCOUNT = re.compile(r"^ACCT-[0-9a-f]{4,40}$")
_ASSET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_INT = re.compile(r"^\d{1,9}$")

# Investigator evidence id prefixes -> (module, type).
EVIDENCE_PREFIXES = {
    "AF-": ("exposure", "finding"),
    "PATH-": ("paths", "path"),
    "CLM-": ("paths", "table_claim"),
    "ANOM-": ("paths", "anomaly"),
    "GAP-": ("paths", "gap"),
    "COR-": ("paths", "corroboration"),
    "REC-": ("paths", "recommendation"),
    "FACT-": (None, "quantity"),
}
_EVIDENCE_ID = re.compile(r"^[A-Z]{2,5}-[A-Za-z0-9_.:-]{1,64}$")


class BadRequest(ValueError):
    """An invalid query parameter (the app answers 400)."""


# ------------------------------------------------------------------------------------------------ helpers
def awaiting(reason: str) -> dict:
    return {"status": "awaiting_analysis", "reason": reason}


def not_assessed(reason: str) -> dict:
    return {"status": "not_assessed", "reason": reason}


def not_determinable(reason: str) -> dict:
    return {"status": "not_determinable", "reason": reason}


def quantity(value, reason: str = "not recorded in the released report"):
    """A number from a report, or an explicit not-determinable status. Never turns a missing value into 0."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value
    if value is None:
        return not_determinable(reason)
    if isinstance(value, str):
        return not_determinable(value[:300])
    return not_determinable(reason)


# Investigator ids are opaque references too (``RUN-`` + 12 hex can read as a phone number, e.g. RUN-0123456789ab).
_SAFE_ID = re.compile(r"(?<![0-9A-Za-z])(?:RUN-[0-9a-f]{12}|FACT-[0-9A-Za-z_]{1,64})(?![0-9A-Za-z])")


def _scrub_str(s: str) -> str:
    out, pos = [], 0
    for m in _SAFE_ID.finditer(s):
        out.append(scrub_text(s[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(scrub_text(s[pos:]))
    return "".join(out)


def scrub(obj):
    """Defence in depth on every response: identifier-like text in string values is redacted (hashes and Tripline's
    own opaque references are left intact by :func:`scrub_text`; investigator run and fact ids likewise)."""
    if isinstance(obj, str):
        return _scrub_str(obj)
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    return obj


@lru_cache(maxsize=64)
def _load_json_cached(path: str, mtime_ns: int, size: int):
    return json.loads(Path(path).read_bytes())


def _read_json(path: Path):
    st = path.stat()
    return _load_json_cached(str(path), st.st_mtime_ns, st.st_size)


def released(case: Case, kind: str, version: int | None = None) -> tuple[int, Path, dict] | None:
    """(version, directory, report body) of a released version (latest by default), or None."""
    vs = dict(ReportStore(case).versions(kind))
    if not vs:
        return None
    n = max(vs) if version is None else version
    if n not in vs or not (vs[n] / F.REPORT_FILE).is_file():
        return None
    return n, vs[n], _read_json(vs[n] / F.REPORT_FILE)


def release_record(vdir: Path) -> dict:
    p = vdir / F.RELEASE_FILE
    return _read_json(p) if p.is_file() else {}


def _norm_host(h) -> str | None:
    if not h or not isinstance(h, str):
        return None
    return h.strip().lower().split(".")[0] or None


def _ts(text) -> dt.datetime | None:
    if not text or not isinstance(text, str):
        return None
    try:
        return parse_utc(text)
    except ValueError:
        return None


# ------------------------------------------------------------------------------------------------ overview
def overview(case: Case) -> dict:
    rs = ReportStore(case)
    kinds, approvals = {}, []
    for kind in REPORT_KINDS:
        vs = rs.versions(kind)
        draft_count = len(rs.drafts(kind))
        if not vs:
            kinds[kind] = {**awaiting(f"no released {kind} report"), "released_versions": [],
                           "draft_present": draft_count > 0}
            continue
        n, vdir = vs[-1]
        rel = release_record(vdir)
        body = _read_json(vdir / F.REPORT_FILE)
        appr = rel.get("approval") or {}
        if appr.get("approved_at"):
            approvals.append(appr["approved_at"])
        kinds[kind] = {"status": "released", "released_versions": [v for v, _ in vs], "latest_version": n,
                       "report_sha256": rel.get("report_sha256"), "report_status": body.get("report_status"),
                       "approved_by": appr.get("approver"), "approved_at": appr.get("approved_at"),
                       "provider_cosigned": bool(rel.get("provider_cosigned")), "draft_present": draft_count > 0}

    sources = case.sources()
    received = sorted(s["received_at"] for s in sources if s.get("received_at"))
    registered = sorted(s["registered_at"] for s in sources if s.get("registered_at"))
    hold = case.legal_hold
    window = case.config.get("incident_window") or {}
    out = {
        "case_id": case.case_id,
        "mode": case.mode,
        "title": case.config.get("title") or "",
        "incident_window": {"start": window.get("start"), "end": window.get("end")} if window.get("start")
        else not_assessed("no incident window (readiness case)"),
        "case_status": "closed" if case.is_closed else "open",
        "legal_hold": {"active": bool(hold.get("active")), "set_at": hold.get("set_at"),
                       "reason": scrub_text(hold.get("reason") or "")[:300] or None},
        "team_size": {k: len(case.team().get(k, [])) for k in ("operators", "reviewers", "approvers")},
        "reports": kinds,
        "evidence_state": {
            "sources_registered": len(sources),
            "latest_source_received_at": received[-1] if received else not_assessed("no sources registered"),
            "latest_source_registered_at": registered[-1] if registered else not_assessed("no sources registered"),
            "latest_release_approved_at": max(approvals) if approvals else awaiting("nothing released yet"),
            "declared_gaps": len(case.config.get("declared_gaps") or []),
        },
        "module_b": _module_b_coverage(case),
        "score": None,
        "score_note": "No overall score is computed: the sections below report what each module found and what it "
                      "could not assess.",
    }
    return out


def _module_b_coverage(case: Case) -> dict:
    r = released(case, "paths")
    if r is None:
        return awaiting("no released paths report (Module B)")
    n, _vdir, body = r
    srcs = (body.get("inputs") or {}).get("sources") or []
    present = sorted({s.get("family") for s in srcs if s.get("family")})
    missing = [{"group": g, "families": list(fams)} for g, fams in FAMILY_GROUPS if not set(fams) & set(present)]
    gaps = body.get("gaps") or []
    incomplete = [{"source_id": s.get("source_id"), "family": s.get("family"), "completeness": s.get("completeness"),
                   "problems": s.get("completeness_problems") or []}
                  for s in srcs if s.get("completeness") not in (None, "complete_as_declared")]
    handoff = body.get("forensic_handoff") or {}
    return {
        "status": "released", "report_version": n, "window": body.get("window"),
        "sources": len(srcs), "families_present": present, "missing_source_families": missing,
        "missing_source_families_basis": "families with no source in the released paths report inputs",
        "gaps": {"total": len(gaps), "by_kind": dict(sorted(Counter(g.get("kind") for g in gaps).items()))},
        "sources_not_complete": incomplete,
        "forensic_not_covered": handoff.get("not_covered") or [],
        "paths_by_class": (body.get("classification") or {}).get("paths_by_class") or {},
        "limitations": body.get("limitations") or [],
    }


# ------------------------------------------------------------------------------------------------ timeline
@dataclass(frozen=True)
class TimelineQuery:
    start: dt.datetime | None = None
    end: dt.datetime | None = None
    source: str | None = None
    family: str | None = None
    account: str | None = None
    asset: str | None = None
    klass: str | None = None
    offset: int = 0
    limit: int = TIMELINE_LIMIT_DEFAULT

    def params(self) -> dict:
        return {"start": _iso(self.start), "end": _iso(self.end), "source": self.source, "family": self.family,
                "account": self.account, "asset": self.asset, "class": self.klass}


def _iso(t: dt.datetime | None) -> str | None:
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" if t else None


def parse_timeline_query(params: Mapping[str, list[str]]) -> TimelineQuery:
    """Validate query parameters (each at most once). Raises :class:`BadRequest`."""
    unknown = set(params) - TIMELINE_PARAMS
    if unknown:
        raise BadRequest("unknown query parameter")
    one = {}
    for k, vals in params.items():
        if len(vals) != 1:
            raise BadRequest(f"parameter {k} given more than once")
        v = vals[0]
        if len(v) > 80:
            raise BadRequest(f"parameter {k} too long")
        if v != "":
            one[k] = v

    def when(k):
        if k not in one:
            return None
        try:
            return parse_utc(one[k])
        except (ValueError, TypeError):
            raise BadRequest(f"{k} must be an ISO-8601 timestamp with a time zone") from None

    start, end = when("start"), when("end")
    if start and end and end < start:
        raise BadRequest("end is before start")
    for k, rx in (("source", _SOURCE), ("account", _ACCOUNT), ("asset", _ASSET)):
        if k in one and not rx.match(one[k]):
            raise BadRequest(f"invalid {k}")
    if "family" in one and one["family"] not in FAMILIES:
        raise BadRequest("unknown family")
    if "class" in one and one["class"] not in TIMELINE_CLASSES:
        raise BadRequest("unknown class")
    offset, limit = 0, TIMELINE_LIMIT_DEFAULT
    if "offset" in one:
        if not _INT.match(one["offset"]) or int(one["offset"]) > TIMELINE_OFFSET_MAX:
            raise BadRequest("offset must be a non-negative integer")
        offset = int(one["offset"])
    if "limit" in one:
        if not _INT.match(one["limit"]) or int(one["limit"]) < 1:
            raise BadRequest("limit must be a positive integer")
        limit = min(int(one["limit"]), TIMELINE_LIMIT_MAX)
    return TimelineQuery(start, end, one.get("source"), one.get("family"), one.get("account"), one.get("asset"),
                         one.get("class"), offset, limit)


def asset_map(paths_body: dict) -> dict[str, str]:
    """Normalised host name -> asset id, from the paths report inputs (``host``/``asset_id`` where recorded) and
    its affected-systems list."""
    out: dict[str, str] = {}
    for s in (paths_body.get("inputs") or {}).get("sources") or []:
        h, a = _norm_host(s.get("host")), s.get("asset_id")
        if h and a:
            out.setdefault(h, a)
    for s in (paths_body.get("regulator") or {}).get("affected_systems") or []:
        h, a = _norm_host(s.get("host")), s.get("asset_id")
        if h and a:
            out.setdefault(h, a)
    return out


_EVENT_FIELDS = ("event_id", "source_id", "family", "ts_utc", "ts_utc_earliest", "ts_utc_latest", "tz_original",
                 "time_precision", "host", "account_ref", "account_label", "operation", "observation_type",
                 "objects", "consequence_class", "indicator_match", "outcome", "application", "record_locator")


def _ids(v) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v if x]
    return [x for x in str(v or "").replace(";", ",").split(",") if x.strip()] if v else []


def _event_view(e: dict, amap: dict[str, str]) -> dict:
    out = {k: e.get(k) for k in _EVENT_FIELDS}
    out["asset_id"] = amap.get(_norm_host(e.get("host")) or "")
    out["path_ids"] = _ids(e.get("path_ids"))
    out["anomaly_ids"] = _ids(e.get("anomaly_ids"))
    return out


def _event_matches(e: dict, q: TimelineQuery, amap: dict[str, str]) -> bool:
    if q.source and e.get("source_id") != q.source:
        return False
    if q.family and e.get("family") != q.family:
        return False
    if q.account and e.get("account_ref") != q.account:
        return False
    if q.klass and e.get("consequence_class") != q.klass:
        return False
    if q.asset:
        host = _norm_host(e.get("host"))
        if q.asset.startswith("AST-"):
            if amap.get(host or "") != q.asset:
                return False
        elif host != _norm_host(q.asset):
            return False
    if q.start or q.end:
        lo = _ts(e.get("ts_utc_earliest")) or _ts(e.get("ts_utc"))
        hi = _ts(e.get("ts_utc_latest")) or _ts(e.get("ts_utc"))
        if lo is None and hi is None:
            return False  # no resolvable time: cannot be placed inside a time filter
        lo, hi = lo or hi, hi or lo
        if q.start and hi < q.start:
            return False
        if q.end and lo > q.end:
            return False
    return True


def _gap_overlaps(g: dict, q: TimelineQuery) -> bool:
    gs, ge = _ts(g.get("start")), _ts(g.get("end"))
    if q.end and gs and gs > q.end:
        return False
    if q.start and ge and ge < q.start:
        return False
    return True


_GAP_FIELDS = ("gap_id", "kind", "scope", "source_id", "host", "database", "start", "end", "description", "basis",
               "consequence_class")


def timeline(case: Case, q: TimelineQuery) -> dict:
    r = released(case, "paths")
    if r is None:
        return {**awaiting("no released paths report (Module B)"), "total": None, "offset": q.offset,
                "limit": q.limit, "events": [], "gaps": []}
    n, vdir, body = r
    path = vdir / "attachments" / "timeline.jsonl"
    if not path.is_file():
        return {**not_assessed("the released paths report has no timeline attachment"), "total": None,
                "offset": q.offset, "limit": q.limit, "events": [], "gaps": []}
    amap = asset_map(body)
    total, events = 0, []
    with open(path, encoding="utf-8") as fh:  # streamed: only the requested page is kept
        for line in fh:
            if not line.strip():
                continue
            e = json.loads(line)
            if not _event_matches(e, q, amap):
                continue
            if q.offset <= total < q.offset + q.limit:
                events.append(_event_view(e, amap))
            total += 1
    gaps = [{k: g.get(k) for k in _GAP_FIELDS} for g in body.get("gaps") or [] if _gap_overlaps(g, q)]
    tl = body.get("timeline") or {}
    return {"status": "released", "report_version": n, "total": total, "offset": q.offset, "limit": q.limit,
            "events": events, "gaps": gaps, "filters": q.params(),
            "order": "the released report's order (key events first, then the rest); not re-sorted",
            "truncated_in_report": bool(tl.get("truncated")), "rows_in_window": tl.get("rows_in_window"),
            "content_note": tl.get("content_note"),
            "facets": {"families": FAMILIES, "classes": TIMELINE_CLASSES,
                       "sources": sorted({s.get("source_id") for s in (body.get("inputs") or {}).get("sources") or []
                                          if s.get("source_id")}),
                       "assets": sorted(set(amap.values()))},
            "window": body.get("window")}


# ------------------------------------------------------------------------------------------------ paths
_STAGE_CHAIN = (  # stage -> (from node kind, to node kind)
    ("web_identity", "identity", "network"),
    ("network", "network", "host_application"),
    ("host_application", "host_application", "database_host"),
    ("database", "database_host", "tables"),
    ("staging", "tables", "staging"),
    ("egress", None, "egress"),  # from the last node present (staging or tables)
)


def _edge_label(label) -> str:
    # Never upgrade: anything unexpected is shown as unresolved, never as direct.
    return label if label in EDGE_LABELS else "unresolved"


def path_view(p: dict, amap: dict[str, str]) -> dict:
    pid = p.get("path_id")
    claim = p.get("claim") or {}
    ev = list(claim.get("evidence_ids") or [])
    route = p.get("route") or {}
    acct = route.get("account") or {}
    stages = {s.get("stage"): s for s in p.get("stages") or []}

    def node(kind, label, basis, **values):
        return {"id": f"{pid}:{kind}", "kind": kind, "label": label, "path_id": pid, "evidence_ids": ev,
                "basis": basis, "values": values}

    nodes = [
        node("identity", acct.get("label") or acct.get("account_ref") or "Not established", "observation",
             account_ref=acct.get("account_ref"), account_label=acct.get("label"),
             upstream_accounts=[{"account_ref": a.get("account_ref"), "label": a.get("label")}
                                for a in p.get("upstream_accounts") or []]),
        node("network", route.get("client_ip") or "Not established",
             "observation" if route.get("client_ip") else "unknown", client_ip=route.get("client_ip")),
        node("host_application", route.get("client_host") or route.get("application") or "Not established",
             "observation" if route.get("client_host") or route.get("application") else "unknown",
             client_host=route.get("client_host"), application=route.get("application")),
        node("database_host", route.get("database_host") or "Not established",
             "observation" if route.get("database_host") else "unknown",
             database_host=route.get("database_host"), asset_id=amap.get(_norm_host(route.get("database_host")) or ""),
             source_id=route.get("source_id")),
        node("tables", f"{len(p.get('tables') or [])} table(s)", "observation",
             tables=[{"table": t.get("table"), "consequence_class": t.get("consequence_class"),
                      "evidence_ids": t.get("evidence_ids") or [], "rows_logged": quantity(t.get("rows_logged")),
                      "volume": t.get("volume"), "observation_types": t.get("observation_types") or [],
                      "egress_linked": t.get("egress_linked"), "sensitive": t.get("sensitive"),
                      "corroborations": t.get("corroborations") or []} for t in p.get("tables") or []]),
    ]
    if "staging" in stages:
        nodes.append(node("staging", "Staging on database host", "inference" if
                          stages["staging"].get("label") == "correlated" else "observation"))
    eg = stages.get("egress") or {}
    eg_label = _edge_label(eg.get("label"))
    nodes.append(node("egress", ", ".join(p.get("egress_destinations") or []) or "Not established",
                      "unknown" if eg_label == "unresolved" else ("inference" if eg_label == "correlated"
                                                                   else "observation"),
                      destinations=p.get("egress_destinations") or [],
                      bytes_logged=quantity(p.get("egress_bytes_logged"), "no bytes logged for this route")))
    kinds = [n["kind"] for n in nodes]
    edges = []
    for stage, src, dst in _STAGE_CHAIN:
        s = stages.get(stage)
        if s is None or dst not in kinds:
            continue
        if src is None:
            src = "staging" if "staging" in kinds else "tables"
        edges.append({"id": f"{pid}:{stage}", "from": f"{pid}:{src}", "to": f"{pid}:{dst}", "stage": stage,
                      "label": _edge_label(s.get("label")), "confidence": s.get("confidence"),
                      "reason": s.get("reason"), "alternatives": s.get("alternatives"),
                      "unit_count": s.get("unit_count"), "path_id": pid, "evidence_ids": ev})
    return {"path_id": pid, "rank": p.get("rank"), "consequence_class": p.get("consequence_class"),
            "basis": claim.get("basis"), "statement": claim.get("statement"),
            "chain_confidence": p.get("chain_confidence"), "chain_confidence_reason": p.get("chain_confidence_reason"),
            "confidence": p.get("confidence"), "first_activity": p.get("first_activity"),
            "last_activity": p.get("last_activity"), "earliest_supported": p.get("earliest_supported"),
            "latest_supported": p.get("latest_supported"), "limitations": p.get("limitations") or [],
            "anomaly_ids": p.get("anomalies") or [], "indicator_match_ids": p.get("indicator_matches") or [],
            "evidence_ids": ev, "nodes": nodes, "edges": edges,
            "tables": [{"table": t.get("table"), "consequence_class": t.get("consequence_class"),
                        "evidence_ids": t.get("evidence_ids") or []} for t in p.get("tables") or []]}


def paths(case: Case) -> dict:
    r = released(case, "paths")
    if r is None:
        return awaiting("no released paths report (Module B)")
    n, _vdir, body = r
    amap = asset_map(body)
    cls = body.get("classification") or {}
    anomalies = {a.get("anomaly_id"): {"anomaly_id": a.get("anomaly_id"), "title": a.get("title"),
                                       "severity": a.get("severity"), "detector": a.get("detector"),
                                       "basis": (a.get("claim") or {}).get("basis"),
                                       "consequence_class": (a.get("claim") or {}).get("consequence_class"),
                                       "statement": (a.get("claim") or {}).get("statement"),
                                       "evidence_ids": a.get("evidence_ids") or []}
                 for a in body.get("anomalies") or []}
    nd = body.get("paths_not_detailed") or {}
    return {"status": "released", "report_version": n, "report_status": body.get("report_status"),
            "window": body.get("window"),
            "paths_by_class": cls.get("paths_by_class") or {},
            "sensitive_tables_by_class": cls.get("sensitive_tables_by_class") or {},
            "edges_summary": body.get("edges_summary") or {},
            "evidence_rule": body.get("evidence_rule") or {},
            "limitations": body.get("limitations") or [],
            "paths_not_detailed": nd,
            "paths": [path_view(p, amap) for p in body.get("paths") or []],
            "anomalies": anomalies,
            "legend": {"direct": "joined on an exact shared identifier (solid line)",
                       "observed": "recorded in the log of that system itself (solid line)",
                       "correlated": "linked by time window or attribute similarity: an inference (dashed line)",
                       "unresolved": "the evidence stops here (dotted grey line)"}}


# ------------------------------------------------------------------------------------------------ exposure
def _module_a_refs(paths_body: dict | None) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not paths_body:
        return out
    for rec in (paths_body.get("containment") or {}).get("recommendations") or []:
        for ref in rec.get("module_a_refs") or []:
            fid = ref.get("finding_id") if isinstance(ref, dict) else ref
            if fid:
                out.setdefault(str(fid), [])
                if rec.get("rec_id") not in out[str(fid)]:
                    out[str(fid)].append(rec.get("rec_id"))
    return out


def exposure_view(body: dict, paths_body: dict | None) -> dict:
    findings = []
    for f in body.get("findings") or []:
        findings.append({
            "rank": f.get("rank"), "finding_id": f.get("finding_id"), "control_id": f.get("control_id"),
            "control": f.get("control"), "rule_id": f.get("rule_id"), "title": f.get("title"),
            "severity": f.get("severity"), "state": f.get("state"),
            "asset_id": (f.get("asset") or {}).get("asset_id"), "asset_name": (f.get("asset") or {}).get("name"),
            "location": (f.get("location") or {}).get("display"),
            "suggested_fix": (f.get("suggested_fix") or {}).get("text"),
            "confidence": f.get("confidence"), "confidence_reason": f.get("confidence_reason"),
            "basis": f.get("basis"), "evidence_ids": f.get("evidence_ids") or []})
    coverage = {}
    for cid, c in sorted((body.get("coverage") or {}).items()):
        coverage[cid] = {"control": c.get("control"), "status": c.get("status"),
                         "assessed_units": len(c.get("assessed") or []),
                         "not_assessed": [{"unit": x.get("unit"), "reason": x.get("reason")}
                                          for x in c.get("not_assessed") or []],
                         "unavailable": [{"unit": x.get("unit"), "reason": x.get("reason")}
                                         for x in c.get("unavailable") or []]}
    refs = _module_a_refs(paths_body)
    return {"summary": body.get("summary") or {}, "coverage": coverage, "findings": findings,
            "missing_evidence": body.get("missing_evidence") or [], "limitations": body.get("limitations") or [],
            "statement": body.get("statement"),
            "module_b_cross_references": {
                "label": "cross-referenced by Module B containment advice; not evidence of causation",
                "status": "released" if paths_body else "not_assessed",
                "by_finding": refs}}


def exposure(case: Case) -> dict:
    r = released(case, "exposure")
    if r is None:
        return awaiting("no released exposure report (Module A)")
    n, _vdir, body = r
    p = released(case, "paths")
    return {"status": "released", "report_version": n, **exposure_view(body, p[2] if p else None)}


# ------------------------------------------------------------------------------------------------ people
def _tier(t: dict | None, name: str) -> dict:
    if not t:
        return not_determinable(f"{name} not reported")
    out = {"basis": t.get("basis"), "explanation": t.get("explanation")}
    key = "proposed_count" if "proposed_count" in t else "count"
    out[key] = quantity(t.get(key), f"{name} count not reported")
    for k in ("lower", "upper", "decided_by", "exfiltration_evidence_kind"):
        if k in t:
            out[k] = quantity(t[k]) if k in ("lower", "upper") else t[k]
    if name == "notification_scope":
        out["decided_by"] = t.get("decided_by")
        out["decision_note"] = ("decided by the Information Officer" if t.get("decided_by")
                                else "not decided: a proposal only; the Information Officer decides")
    if isinstance(t.get("people_per_category"), dict):
        out["people_per_category"] = {k: quantity(v) for k, v in t["people_per_category"].items()}
    return out


def _bounds(v) -> dict:
    if isinstance(v, dict):
        return {k: quantity(v.get(k)) for k in ("point", "lower", "upper")}
    if isinstance(v, int | float) and not isinstance(v, bool):
        return {"point": v}
    return {"point": quantity(v)}


def _unresolvable(body: dict) -> dict:
    counts = body.get("counts") or {}
    ur = counts.get("unresolvable_rows")
    per_source = {}
    for sid, s in sorted((body.get("rows_per_source") or {}).items()):
        tabs = s.get("tables") or []
        if any("unresolvable_identity_rows" in t or "unresolvable_dependent_rows" in t for t in tabs):
            per_source[sid] = {
                "identity_rows": sum(int(t.get("unresolvable_identity_rows") or 0) for t in tabs),
                "dependent_rows": sum(int(t.get("unresolvable_dependent_rows") or 0) for t in tabs)}
    if isinstance(ur, dict):
        totals = {k: quantity(v) for k, v in ur.items()}
    else:
        totals = {"total": quantity(ur, "unresolvable rows not reported")}
    return {"totals": totals, "per_source": per_source}


def people_view(prelim: tuple[int, dict] | None, refined: tuple[int, dict] | None) -> dict:
    out: dict = {"person_level_rows": "never shown: counts and categories only"}
    if prelim is None:
        out["preliminary_estimate"] = awaiting("no released preliminary scope report")
    else:
        n, b = prelim
        c = b.get("counts") or {}
        out["preliminary_estimate"] = {
            "report_version": n, "people": _bounds(c.get("unique_people")),
            "people_per_category": {k: _bounds(v) for k, v in (c.get("people_per_category") or {}).items()},
            "unresolvable_rows": _unresolvable(b),
            "uncertainty": (b.get("uncertainty") or {}).get("statement"),
            "scope_tiers": {k: _tier((b.get("scope_tiers") or {}).get(k), k) for k in
                            ("observed_access", "possible_exposure", "confirmed_exfiltration", "notification_scope")},
            "measured_error_pct": quantity((b.get("measured_error_rates") or {}).get("preliminary_estimate_error_pct"),
                                           "not measured")}
    if refined is None:
        out["refined"] = awaiting("no released refined scope report (matching not yet released)")
        return out
    n, b = refined
    c = b.get("counts") or {}
    bounds = c.get("bounds") or {}
    m = b.get("matching") or {}
    out["refined"] = {
        "report_version": n,
        "counts": {
            "unique_people": quantity(c.get("unique_people")),
            "bounds": {"lower": quantity(bounds.get("lower")), "upper": quantity(bounds.get("upper")),
                       "explanation": bounds.get("explanation")},
            "people_per_category": {k: quantity(v) for k, v in (c.get("people_per_category") or {}).items()},
            "notification_routes": {k: quantity(v) for k, v in (c.get("notification_routes") or {}).items()},
            "minors": {k: quantity(v) for k, v in (c.get("minors") or {}).items()},
            "without_contact_details": {k: quantity(v) for k, v in (c.get("without_contact_details") or {}).items()},
            "people_per_confidence": {k: quantity(v) for k, v in (c.get("people_per_confidence") or {}).items()},
        },
        "scope_tiers": {k: _tier((b.get("scope_tiers") or {}).get(k), k) for k in
                        ("observed_access", "possible_exposure", "confirmed_exfiltration", "notification_scope")},
        "unresolvable_rows": _unresolvable(b),
        "matching": {"bands": m.get("bands") or not_assessed("no matching bands reported"),
                     "blocking_rules": len(m.get("blocking_rules") or []),
                     "guards": m.get("guards") or {}, "review_queue": m.get("review_queue") or {},
                     "statistics": m.get("statistics") or {}},
        "review_decisions": b.get("review_decisions") or {},
        "measured_error_rates": b.get("measured_error_rates") or not_assessed("no measured error rates"),
        "limitations": b.get("limitations") or [],
    }
    return out


def people(case: Case) -> dict:
    rs = ReportStore(case)
    prelim = refined = None
    for n, _p in rs.versions("scope"):
        r = released(case, "scope", n)
        if r is None:
            continue
        status = r[2].get("report_status")
        if status == "preliminary":
            prelim = (n, r[2])
        elif status == "refined":
            refined = (n, r[2])
    if prelim is None and refined is None:
        return {**awaiting("no released scope report (Module C)"),
                "preliminary_estimate": awaiting("no released preliminary scope report"),
                "refined": awaiting("no released refined scope report")}
    return {"status": "released", **people_view(prelim, refined)}


# ------------------------------------------------------------------------------------------------ investigation
def _evidence_index(case: Case) -> dict[str, set[str]]:
    idx: dict[str, set[str]] = {"finding": set(), "path": set(), "table_claim": set(), "anomaly": set(),
                                "gap": set(), "corroboration": set(), "recommendation": set()}
    e = released(case, "exposure")
    if e:
        idx["finding"] = {f.get("finding_id") for f in e[2].get("findings") or []}
    p = released(case, "paths")
    if p:
        b = p[2]
        idx["path"] = {x.get("path_id") for x in b.get("paths") or []}
        idx["table_claim"] = {(t.get("claim") or {}).get("claim_id") for t in b.get("tables") or []}
        idx["anomaly"] = {a.get("anomaly_id") for a in b.get("anomalies") or []}
        idx["gap"] = {g.get("gap_id") for g in b.get("gaps") or []}
        idx["corroboration"] = {c.get("corroboration_id") for c in (b.get("inputs") or {}).get("corroborations") or []}
        idx["recommendation"] = {r.get("rec_id") for r in (b.get("containment") or {}).get("recommendations") or []}
    return idx


def _fact_module(fid: str) -> str | None:
    rest = fid[5:].lower()
    for prefix, module in (("exposure", "exposure"), ("a-", "exposure"), ("paths", "paths"), ("b-", "paths"),
                           ("scope", "scope"), ("c-", "scope")):
        if rest.startswith(prefix):
            return module
    return None


def resolve_evidence(eid: str, index: dict[str, set[str]]) -> dict:
    for prefix, (module, typ) in EVIDENCE_PREFIXES.items():
        if eid.startswith(prefix):
            if typ == "quantity":
                return {"id": eid, "module": _fact_module(eid), "type": typ, "found": None,
                        "note": "a quantity declared in the evidence bundle"}
            return {"id": eid, "module": module, "type": typ, "found": eid in index.get(typ, set()),
                    "section": module}
    return {"id": eid, "module": None, "type": "unknown", "found": False}


def referenced_ids(result: dict) -> list[str]:
    ids: list[str] = []

    def add(xs):
        for x in xs or []:
            if isinstance(x, str) and _EVIDENCE_ID.match(x) and x not in ids:
                ids.append(x)

    for h in result.get("hypotheses") or []:
        add(h.get("supporting_evidence"))
        add(h.get("contradicting_evidence"))
        add([q.get("fact_id") for q in h.get("quantities") or [] if isinstance(q, dict)])
    for m in result.get("missing_evidence") or []:
        add(m.get("related_evidence"))
    for s in result.get("investigation_steps") or []:
        add(s.get("evidence_ids"))
    for r in result.get("remediation") or []:
        add(r.get("evidence_ids"))
    return ids


def investigation(case: Case, store) -> dict:
    report = released(case, "investigation")
    result = None
    if store is not None:
        from tripline_scope.investigator import storage

        result = storage.latest_result(store)
    if report is None and result is None:
        return {"status": "not_performed", "reason": "no authorised AI analysis has been run for this case",
                "advisory": True}
    index = _evidence_index(case)
    out: dict = {"status": "available", "advisory": True,
                 "banner": "Advisory — AI-generated hypotheses, not findings"}
    if report is not None:
        n, vdir, body = report
        rel = release_record(vdir)
        out["released_report"] = {"report_version": n, "report_sha256": rel.get("report_sha256"),
                                  "approved_at": (rel.get("approval") or {}).get("approved_at"),
                                  "approved_by": (rel.get("approval") or {}).get("approver"), "body": body}
    else:
        out["released_report"] = awaiting("no released investigation report")
    if result is not None:
        prov = result.get("provenance") or {}
        out["latest_run"] = result
        out["provenance"] = prov
        out["is_model_inference"] = prov.get("is_model_inference")
        out["fixture"] = prov.get("provider_kind") == "fixture" or prov.get("is_model_inference") is False
        out["provenance_note"] = ("Deterministic fixture output — not AI inference" if out["fixture"]
                                  else "Model inference (advisory; validated by Tripline's deterministic validator)")
        out["evidence_links"] = {i: resolve_evidence(i, index) for i in referenced_ids(result)}
    else:
        out["latest_run"] = not_performed_run()
        out["evidence_links"] = {}
    return out


def not_performed_run() -> dict:
    return {"status": "not_performed", "reason": "no validated investigator run is stored for this case"}


# ------------------------------------------------------------------------------------------------ reports
def verification(case: Case, home, kind: str) -> dict:
    rs = ReportStore(case)
    if not rs.versions(kind):
        return awaiting(f"no released {kind} report")
    res = rs.verify(kind, home)
    out = {"ok": bool(res.ok), "checks": len(res.checks),
           "failed": [c.name for c in res.checks if not c.ok]}
    if not res.ok:
        out["render"] = res.render().replace(str(rs.kind_dir(kind)), f"reports/{kind}")
    return out


def reports(case: Case, verified: Mapping[str, dict]) -> dict:
    rs = ReportStore(case)
    kinds = {}
    for kind in REPORT_KINDS:
        vs = rs.versions(kind)
        if not vs:
            kinds[kind] = {**awaiting(f"no released {kind} report"), "versions": []}
            continue
        versions = []
        for n, vdir in vs:
            rel = release_record(vdir)
            appr = rel.get("approval") or {}
            files = [name for name in SERVABLE_FILES if (vdir / name).is_file()]
            versions.append({"version": n, "report_sha256": rel.get("report_sha256"),
                             "previous_report_sha256": rel.get("previous_report_sha256"),
                             "approval": {"approver": appr.get("approver"), "approved_at": appr.get("approved_at"),
                                          "authentication": appr.get("authentication")},
                             "provider_cosigned": bool(rel.get("provider_cosigned")),
                             "artefacts": rel.get("artefacts") or {},
                             "files": {name: f"/reports/{kind}/v{n}/{name}" for name in files}})
        kinds[kind] = {"status": "released", "versions": versions,
                       "verification": verified.get(kind) or not_assessed("not verified yet")}
    return {"kinds": kinds}


def report_file(case: Case, kind: str, version: str, name: str) -> tuple[Path, str] | None:
    """Resolve a downloadable released file from validated parts only, or None. ``kind`` and ``name`` must be in
    fixed allow-lists and ``version`` must be ``v<int>`` naming an existing released version; the path is built
    from the allow-listed constants and the directory ``ReportStore`` lists, never from the request strings."""
    if kind not in REPORT_KINDS:
        return None
    kind_const = REPORT_KINDS[REPORT_KINDS.index(kind)]
    names = {k: k for k in SERVABLE_FILES}
    if name not in names:
        return None
    m = re.fullmatch(r"v(\d{1,6})", version or "")
    if not m:
        return None
    vs = dict(ReportStore(case).versions(kind_const))
    vdir = vs.get(int(m.group(1)))
    if vdir is None:
        return None
    p = vdir / names[name]
    if not p.is_file() or p.is_symlink():
        return None
    return p, SERVABLE_FILES[names[name]]
