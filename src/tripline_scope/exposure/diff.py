"""``tscope exposure diff``: compare two exposure reports of the same case by stable finding id.

* ``new`` - active in TO, not active in FROM;
* ``resolved`` - active in FROM, absent or ``mitigated`` in TO **and** its coverage unit was assessed in TO
  (``verified``); a mitigated delta is only claimed when the same unit was assessed in both reports;
* ``not_reassessed`` - active in FROM, absent in TO, but its coverage unit was not assessed (or only partially);
* ``persisting`` - active in both (``severity_changed`` lists those whose severity moved).

Finding ids are keyed, case-local fingerprints: reports from different cases cannot be matched and are refused.
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

from tripline_scope.core.canonical import sha256_hex
from tripline_scope.core.errors import ConfigError
from tripline_scope.core.reports import ReportStore
from tscope_verify import formats as F

DIFF_SCHEMA = "tripline.exposure-diff/v1"
ACTIVE = ("new", "open", "accepted-risk")


def load_report_ref(ref: str, case) -> dict:
    p = Path(ref)
    path = None
    if p.is_dir() and (p / F.REPORT_FILE).is_file():
        path = p / F.REPORT_FILE
    elif p.is_file():
        path = p
    elif case is not None:
        rs = ReportStore(case)
        m = re.fullmatch(r"v?(\d+)", ref)
        if m:
            path = rs.kind_dir("exposure") / F.version_dirname(int(m.group(1))) / F.REPORT_FILE
        elif ref == "latest":
            last = rs.latest("exposure")
            path = last[1] / F.REPORT_FILE if last else None
        elif ref == "draft":
            path = rs.get_draft("exposure", None).path / F.REPORT_FILE
    if path is None or not Path(path).is_file():
        raise ConfigError("report not found (give a report.json, a version directory, or vN/latest/draft with --case)")
    data = Path(path).read_bytes()
    body = json.loads(data)
    if body.get("kind") != "exposure" or not isinstance(body.get("findings"), list):
        raise ConfigError("not an exposure report")
    return {"body": body, "sha256": sha256_hex(data)}


def _entry(f: dict, **extra) -> dict:
    loc = f.get("location") or {}
    e = {"finding_id": f["finding_id"], "control_id": f["control_id"], "rule_id": f["rule_id"],
         "severity": f["severity"], "title": f["title"], "asset_id": (f.get("asset") or {}).get("asset_id"),
         "location": loc.get("display"), "principal": loc.get("principal"), "coverage_unit": f.get("coverage_unit"),
         "suggested_fix": (f.get("suggested_fix") or {}).get("action")}
    e.update(extra)
    return e


def _assessed_in(body: dict, f: dict) -> tuple[bool, str]:
    unit = f.get("coverage_unit")
    cov = (body.get("coverage") or {}).get(f["control_id"]) or {}
    for u in cov.get("assessed", []):
        if u["unit"] == unit:
            if "partial" in (u.get("detail") or ""):
                return False, f"coverage unit {unit} only partially assessed in the later report"
            return True, f"coverage unit {unit} assessed in both reports"
    return False, f"coverage unit {unit} not assessed in the later report"


def diff_reports(a: dict, b: dict) -> dict:
    A, B = a["body"], b["body"]
    if A["case_id"] != B["case_id"]:
        raise ConfigError("finding ids are keyed per case: reports from different cases cannot be compared")
    fa = {f["finding_id"]: f for f in A["findings"] if f["state"] in ACTIVE}
    fb = {f["finding_id"]: f for f in B["findings"]}
    active_b = {k: f for k, f in fb.items() if f["state"] in ACTIVE}
    new = [_entry(f, state_to=f["state"]) for k, f in active_b.items() if k not in fa]
    persisting, changed, resolved, stale = [], [], [], []
    for k, f in fa.items():
        g = fb.get(k)
        if k in active_b:
            persisting.append(_entry(g, state_from=f["state"], state_to=g["state"]))
            if g["severity"] != f["severity"]:
                changed.append(_entry(g, severity_from=f["severity"], severity_to=g["severity"]))
            continue
        if g is not None and g["state"] == "mitigated":
            resolved.append(_entry(f, verified=True, reason=g.get("verification")))
            continue
        ok, why = _assessed_in(B, f)
        if ok and (g is None or g["state"] != "not-assessed"):
            resolved.append(_entry(f, verified=True, reason=why))
        else:
            stale.append(_entry(f, verified=False, reason=(g or {}).get("verification") or why))
    key = lambda e: (e["control_id"], e["finding_id"])  # noqa: E731
    for lst in (new, persisting, changed, resolved, stale):
        lst.sort(key=key)

    def meta(r, body):
        sc = body.get("scan") or {}
        return {"case_id": body["case_id"], "version": body["version"], "report_sha256": r["sha256"],
                "as_of": sc.get("as_of"), "manifest_sha256": sc.get("manifest_sha256"),
                "config_sha256": body.get("config_sha256")}

    return {
        "schema": DIFF_SCHEMA,
        "from": meta(a, A), "to": meta(b, B),
        "config_changed": A.get("config_sha256") != B.get("config_sha256"),
        "summary": {"new": len(new), "resolved": len(resolved), "persisting": len(persisting),
                    "not_reassessed": len(stale), "severity_changed": len(changed)},
        "new": new, "resolved": resolved, "persisting": persisting, "not_reassessed": stale, "severity_changed": changed,
        "note": "Resolved findings are verified only where the same coverage unit was assessed in both reports. "
                "Finding ids are keyed case-local fingerprints; no secret value is compared.",
    }


def to_csv(d: dict) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["change", "finding_id", "control_id", "rule_id", "severity", "title", "asset_id", "location",
                "verified", "reason"])
    for change in ("new", "resolved", "not_reassessed", "persisting"):
        for e in d[change]:
            w.writerow([change, e["finding_id"], e["control_id"], e["rule_id"], e["severity"], e["title"],
                        e.get("asset_id") or "", e.get("location") or "", e.get("verified", ""), e.get("reason") or ""])
    return buf.getvalue().encode("utf-8")
