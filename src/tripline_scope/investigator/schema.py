"""Strict structural contract for model output, ``tripline.investigation-candidate/v1``.

Hand-written (no schema library at runtime): unknown keys, wrong types, empty required lists and oversized
values are errors. Structural validity says nothing about truth; :mod:`.validate` checks the content.
"""

from __future__ import annotations

import json
import re

CANDIDATE_SCHEMA = "tripline.investigation-candidate/v1"
RESULT_SCHEMA = "tripline.investigation/v1"
CLASSES = ("access_observed", "export_or_staging_observed", "egress_suspected", "exfiltration_evidenced", "undetermined")
CONFIDENCE = ("low", "moderate", "high")
PRIORITY = ("immediate", "next", "later")
MAX_RAW = 512 * 1024
MAX_STR = 600
MAX_LIST = 30
_HID = re.compile(r"^H[1-9]$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.\-]{0,63}$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$")

CONFIDENCE_MEANING = {
    "low": "consistent with the cited evidence but not preferred over the alternatives",
    "moderate": "better supported than the alternatives by the cited evidence",
    "high": "supported by cited observations with no cited contradicting evidence",
}


class SchemaError(ValueError):
    pass


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise SchemaError("duplicate key")
        d[k] = v
    return d


def parse(raw: bytes) -> dict:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) > MAX_RAW:
        raise SchemaError("output missing or larger than the limit")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SchemaError("output is not UTF-8") from exc
    text = text.strip()
    if text.startswith("```"):   # tolerate a single fenced block from chat models; nothing else
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        obj = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_bad_const)
    except (ValueError, RecursionError) as exc:
        raise SchemaError("output is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise SchemaError("output is not a JSON object")
    return obj


def _bad_const(_):
    raise SchemaError("NaN/Infinity not allowed")


def _keys(o, required: set, optional: set, where: str, errs: list) -> bool:
    if not isinstance(o, dict):
        errs.append(f"{where}: not an object")
        return False
    extra = set(o) - required - optional
    missing = required - set(o)
    if extra:
        errs.append(f"{where}: unknown keys")
    if missing:
        errs.append(f"{where}: missing keys")
    return not extra and not missing


def _str(v, where, errs, *, allow_empty=False, limit=MAX_STR):
    if not isinstance(v, str) or (not allow_empty and not v.strip()) or len(v) > limit:
        errs.append(f"{where}: bad string")


def _strs(v, where, errs, *, min_n=0, limit=MAX_STR):
    if not isinstance(v, list) or len(v) < min_n or len(v) > MAX_LIST:
        errs.append(f"{where}: bad list")
        return
    for i, x in enumerate(v):
        _str(x, f"{where}[{i}]", errs, limit=limit)


def _idlist(v, where, errs, *, min_n=0):
    if not isinstance(v, list) or len(v) < min_n or len(v) > MAX_LIST:
        errs.append(f"{where}: bad id list")
        return
    for x in v:
        if not isinstance(x, str) or not _ID.match(x):
            errs.append(f"{where}: bad id")
            return


def _enum(v, allowed, where, errs):
    if v not in allowed:
        errs.append(f"{where}: not one of the allowed values")


def check_candidate(obj: dict) -> list[str]:
    """Structural errors (location + kind only; never the offending content)."""
    errs: list[str] = []
    top_req = {"schema", "case_id", "bundle_sha256", "summary", "hypotheses", "missing_evidence",
               "investigation_steps", "remediation", "unproven_assertions"}
    if not _keys(obj, top_req, set(), "candidate", errs):
        return errs
    if obj["schema"] != CANDIDATE_SCHEMA:
        errs.append("candidate.schema: unexpected")
    _str(obj["case_id"], "case_id", errs, limit=64)
    if not isinstance(obj["bundle_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", obj["bundle_sha256"]):
        errs.append("bundle_sha256: bad")
    _str(obj["summary"], "summary", errs, limit=1200)
    hs = obj["hypotheses"]
    if not isinstance(hs, list) or not 1 <= len(hs) <= 9:
        errs.append("hypotheses: need 1-9")
    else:
        ids, mains = set(), 0
        for i, h in enumerate(hs):
            w = f"hypotheses[{i}]"
            req = {"hypothesis_id", "rank", "statement", "basis", "consequence_class", "supporting_evidence",
                   "contradicting_evidence", "assets", "sources", "time_window", "confidence", "confidence_rationale",
                   "alternative_explanations", "tests", "cannot_conclude", "quantities"}
            if not _keys(h, req, set(), w, errs):
                continue
            if not isinstance(h["hypothesis_id"], str) or not _HID.match(h["hypothesis_id"]) or h["hypothesis_id"] in ids:
                errs.append(f"{w}.hypothesis_id: bad or duplicate")
            ids.add(h["hypothesis_id"])
            _enum(h["rank"], ("main", "alternative"), f"{w}.rank", errs)
            mains += h["rank"] == "main"
            _str(h["statement"], f"{w}.statement", errs)
            _enum(h["basis"], ("hypothesis", "inference"), f"{w}.basis", errs)
            _enum(h["consequence_class"], CLASSES, f"{w}.consequence_class", errs)
            _idlist(h["supporting_evidence"], f"{w}.supporting_evidence", errs, min_n=1)
            _idlist(h["contradicting_evidence"], f"{w}.contradicting_evidence", errs)
            _idlist(h["assets"], f"{w}.assets", errs)
            _idlist(h["sources"], f"{w}.sources", errs)
            tw = h["time_window"]
            if tw is not None:
                if _keys(tw, {"start", "end"}, set(), f"{w}.time_window", errs):
                    for k in ("start", "end"):
                        if tw[k] is not None and (not isinstance(tw[k], str) or not _TS.match(tw[k])):
                            errs.append(f"{w}.time_window.{k}: bad timestamp")
            _enum(h["confidence"], CONFIDENCE, f"{w}.confidence", errs)
            _str(h["confidence_rationale"], f"{w}.confidence_rationale", errs)
            _strs(h["alternative_explanations"], f"{w}.alternative_explanations", errs)
            if not isinstance(h["tests"], list) or len(h["tests"]) > MAX_LIST:
                errs.append(f"{w}.tests: bad list")
            else:
                for j, t in enumerate(h["tests"]):
                    if _keys(t, {"evidence_needed", "would_resolve"}, set(), f"{w}.tests[{j}]", errs):
                        _str(t["evidence_needed"], f"{w}.tests[{j}].evidence_needed", errs)
                        _str(t["would_resolve"], f"{w}.tests[{j}].would_resolve", errs)
            _strs(h["cannot_conclude"], f"{w}.cannot_conclude", errs, min_n=1)
            if not isinstance(h["quantities"], list) or len(h["quantities"]) > MAX_LIST:
                errs.append(f"{w}.quantities: bad list")
            else:
                for j, q in enumerate(h["quantities"]):
                    if _keys(q, {"fact_id", "value"}, set(), f"{w}.quantities[{j}]", errs):
                        if not isinstance(q["fact_id"], str) or not q["fact_id"].startswith("FACT-"):
                            errs.append(f"{w}.quantities[{j}].fact_id: bad")
                        if isinstance(q["value"], bool) or not isinstance(q["value"], (int, float, str)):
                            errs.append(f"{w}.quantities[{j}].value: bad")
        if mains != 1:
            errs.append("hypotheses: exactly one main hypothesis required")
    for name, req, fields in (
        ("missing_evidence", {"description", "source_family", "related_evidence"}, ("description", "source_family")),
        ("investigation_steps", {"step", "priority", "evidence_ids"}, ("step",)),
        ("remediation", {"action", "priority", "evidence_ids", "asset_ids"}, ("action",)),
    ):
        lst = obj[name]
        if not isinstance(lst, list) or len(lst) > MAX_LIST:
            errs.append(f"{name}: bad list")
            continue
        for i, it in enumerate(lst):
            w = f"{name}[{i}]"
            if not _keys(it, req, set(), w, errs):
                continue
            for f in fields:
                _str(it[f], f"{w}.{f}", errs)
            if "priority" in it:
                _enum(it["priority"], PRIORITY, f"{w}.priority", errs)
            if "related_evidence" in it:
                _idlist(it["related_evidence"], f"{w}.related_evidence", errs)
            if "evidence_ids" in it:
                _idlist(it["evidence_ids"], f"{w}.evidence_ids", errs, min_n=1)
            if "asset_ids" in it:
                _idlist(it["asset_ids"], f"{w}.asset_ids", errs)
    _strs(obj["unproven_assertions"], "unproven_assertions", errs)
    return errs


def output_contract() -> dict:
    """The contract given to providers (plain description; the validator is authoritative)."""
    return {
        "schema": CANDIDATE_SCHEMA,
        "rules": [
            "Return ONE JSON object and nothing else. Unknown keys are rejected.",
            "Every hypothesis cites evidence ids from evidence_bundle.evidence or evidence_bundle.facts only.",
            "consequence_class may not be stronger than the strongest consequence_class among the cited supporting evidence.",
            "exfiltration_evidenced requires a cited item with an exfiltration_evidence_kind.",
            "Any number in free text must also appear in quantities with a FACT- id whose value is identical.",
            "No URLs, e-mail addresses, ID numbers, phone numbers, credentials, commands or clinical content.",
            "Missing or disabled logs never show that nothing happened; say what cannot be concluded.",
        ],
        "confidence_labels": CONFIDENCE_MEANING,
        "shape": {
            "schema": CANDIDATE_SCHEMA, "case_id": "str", "bundle_sha256": "hex64", "summary": "str",
            "hypotheses": [{"hypothesis_id": "H1..H9", "rank": "main|alternative (exactly one main)",
                            "statement": "str", "basis": "hypothesis|inference", "consequence_class": "|".join(CLASSES),
                            "supporting_evidence": ["id (>=1)"], "contradicting_evidence": ["id"], "assets": ["asset id"],
                            "sources": ["source id"], "time_window": {"start": "ISO-8601 or null", "end": "ISO-8601 or null"},
                            "confidence": "low|moderate|high", "confidence_rationale": "str",
                            "alternative_explanations": ["str"], "tests": [{"evidence_needed": "str", "would_resolve": "str"}],
                            "cannot_conclude": ["str (>=1)"], "quantities": [{"fact_id": "FACT-...", "value": "number|str"}]}],
            "missing_evidence": [{"description": "str", "source_family": "str", "related_evidence": ["id"]}],
            "investigation_steps": [{"step": "str", "priority": "immediate|next|later", "evidence_ids": ["id (>=1)"]}],
            "remediation": [{"action": "str", "priority": "immediate|next|later", "evidence_ids": ["id (>=1)"], "asset_ids": ["asset id"]}],
            "unproven_assertions": ["str"],
        },
    }
