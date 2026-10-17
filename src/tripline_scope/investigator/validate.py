"""Deterministic validation of provider output against the evidence bundle.

This module, not the model, decides what Tripline accepts. Every item (hypothesis, missing-evidence entry,
investigation step, remediation action, unproven assertion, summary) receives a verdict:

* ``accepted``   — every rule passed;
* ``unverified`` — no hard rule failed, but the text names a table, account, asset or address that none of the
  item's cited evidence mentions (shown labelled, never reported as a finding);
* ``rejected``   — at least one hard rule failed (codes below). Rejected text is dropped from the result.

Codes: ``schema``, ``case_mismatch``, ``bundle_mismatch``, ``unknown_evidence``, ``unknown_asset``,
``unknown_source``, ``promotion``, ``exfiltration_unsupported``, ``exfiltration_scope``, ``missing_logs_as_absence``,
``unsupported_number``, ``prohibited_content``, ``unsupported_conclusion``, ``confidence_label``, ``execution_claim``,
``untraceable_reference`` (unverified only). Diagnostics carry codes and item ids only, never content.

Exfiltration scope: eligible evidence establishes exfiltration only for what it covers (its ``tables``, data
``categories`` and ``fact:`` references). Every sentence that asserts exfiltration, and every unqualified sentence of
an ``exfiltration_evidenced`` hypothesis, must stay inside the scope of the eligible items the hypothesis cites: no
other table, no other data category, no number other than a cited in-scope fact, no "all"/"entire" or population
wording, and at least one in-scope table or category named. Otherwise the item is rejected (``exfiltration_scope``).
Corroboration of one table plus access evidence for another therefore never supports a claim about the second.
"""

from __future__ import annotations

import re

from tripline_scope.core.canonical import canonical_bytes
from tripline_scope.core.evidence import EXFILTRATION_EVIDENCE_KINDS
from tripline_scope.core.redact import find_identifier_like

from .schema import RESULT_SCHEMA, SchemaError, check_candidate, parse

VALIDATOR_VERSION = "investigator-validator/1.1.0"
ORDER = ["access_observed", "export_or_staging_observed", "egress_suspected", "exfiltration_evidenced"]
HARD = {"schema", "case_mismatch", "bundle_mismatch", "unknown_evidence", "unknown_asset", "unknown_source",
        "promotion", "exfiltration_unsupported", "exfiltration_scope", "missing_logs_as_absence", "unsupported_number",
        "prohibited_content", "unsupported_conclusion", "confidence_label", "execution_claim"}

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_DOMAIN = re.compile(r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|org|net|io|za|co|gov|edu|example|info|ru|cn|xyz|onion|local|biz|me|top)\b")
_URL = re.compile(r"(?i)\b(?:https?|ftp|file|smb|ldap|gopher)://|\bwww\.")
_SECRET = re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|private[_ ]key)\s*[=:]|-----BEGIN [A-Z ]*KEY-----|"
                     r"\bAKIA[0-9A-Z]{16}\b|\bsk-[A-Za-z0-9]{16,}")
_ICD = re.compile(r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b")
_CMD = re.compile(r"(?i)(?:^|[\s;|&$(])(?:sudo|rm\s+-|curl\s|wget\s|powershell|pwsh|cmd(?:\.exe)?\s*/c|bash\s+-c|sh\s+-c|"
                  r"nc\s+-|ncat\s|chmod\s|scp\s|ssh\s|Invoke-\w|net\s+user|reg\s+add|python\s+-c|eval\s*\(|base64\s+-d)")
_SQL = re.compile(r"(?i)\b(?:select\s+(?:\*|top\b|distinct\b|[\w\[\]]+\s*,)|insert\s+into|delete\s+from|drop\s+(?:table|database|login)|"
                  r"alter\s+(?:server|database|login)|exec(?:ute)?\s+(?:xp_|sp_)|bcp\s+\S+\s+(?:out|queryout))")
_CODE = re.compile(r"`|<script|\$\(|&&|\|\|")
_MODAL = re.compile(r"(?i)\b(may|might|could|possibly|possible|whether|if|not|no|cannot|unknown|unproven|suspected|"
                    r"compatible|consistent|hypothes\w*|alleged|potential(?:ly)?|unclear|undetermined)\b")
# hedges that turn an assertion of absence into an acknowledgement of uncertainty
_HEDGE = re.compile(r"(?i)\b(may|might|could|cannot|unknown|whether|if|unproven|not determinable|undetermined|unclear)\b")
_THEFT = [
    re.compile(r"(?i)\b(?:confirmed|proven|established|definite|certain|actual)\s+(?:data\s+)?(?:exfiltration|theft|disclosure|leak)"),
    re.compile(r"(?i)\b(?:was|were|has been|have been|had been|got)\s+(?:exfiltrated|stolen|leaked|disclosed|taken out|"
               r"transmitted out|sent out)"),
    re.compile(r"(?i)\b(?:attacker|actor|intruder|they|adversary)\s+(?:exfiltrated|stole|leaked|took|removed)\b"),
    re.compile(r"(?i)\bdata\s+(?:left|was removed from)\s+the\s+(?:hospital|network|laboratory|organisation|organization)"),
    re.compile(r"(?i)\bexfiltration\s+(?:is\s+|was\s+|has been\s+)?(?:evidenced|confirmed|proven|established|occurred|took place)"),
    re.compile(r"(?i)\b(?:evidenced|corroborated)\s+(?:data\s+)?(?:exfiltration|disclosure|theft)"),
]
# qualifiers that keep a sentence of an exfiltration hypothesis outside the exfiltration claim itself
_LIMIT = re.compile(r"(?i)\b(?:may|might|could|possibl\w*|potential\w*|suspected|unknown|undetermined|unproven|cannot|"
                    r"not\s+(?:evidenced|established|shown|determined|determinable|known|corroborated)|no\s+evidence|"
                    r"does\s+not\s+establish)\b")
_SENT = re.compile(r"(?<=[.;!?])\s+")
_BROAD = re.compile(r"(?i)\b(?:all|every|entire|whole|everyone|everything)\b|\bpossible[- ]exposure\b|"
                    r"\bobserved[- ]access\b|\bnotification\b|\bpopulation\b")
# data categories (Module C keys) as they are written in prose; a group word needs one covered member
_CLIN = ("clinical_diagnosis", "clinical_tests", "clinical_results", "clinical_notes")
_CATEGORY_WORDS = [
    (re.compile(r"(?i)\b(?:identity|id|passport)\s+numbers?\b|\bnational\s+ids?\b"), ("identity_number",)),
    (re.compile(r"(?i)(?<!account )(?<!table )(?<!user )(?<!host )(?<!file )(?<!column )\b(?:full\s+)?names?\b"), ("name",)),
    (re.compile(r"(?i)\bdates?\s+of\s+birth\b|\bbirth\s*dates?\b|\bdob\b"), ("date_of_birth",)),
    (re.compile(r"(?i)\bcontact\s+details\b|\b(?:tele)?phone\s+numbers?\b|\be-?mail\s+addresse?s?\b"), ("contact_details",)),
    (re.compile(r"(?i)\b(?:postal|street|home|residential)\s+addresse?s?\b"), ("address",)),
    (re.compile(r"(?i)\bmedical\s+aid\b"), ("medical_aid",)),
    (re.compile(r"(?i)\bdiagnos[ie]s\b|\bdiagnosis\s+codes?\b"), ("clinical_diagnosis",)),
    (re.compile(r"(?i)\b(?:laboratory|lab)\s+tests?\b|\btests?\s+ordered\b"), ("clinical_tests",)),
    (re.compile(r"(?i)\b(?:test|lab|laboratory)\s+results\b"), ("clinical_results",)),
    (re.compile(r"(?i)\bclinical\s+notes\b"), ("clinical_notes",)),
    (re.compile(r"(?i)\b(?:clinical|health|medical)\s+(?:data|information|records|details)\b"), _CLIN),
    (re.compile(r"(?i)\b(?:payment|credit|debit)\s+cards?\b|\bcard\s+numbers?\b"), ("payment_card",)),
    (re.compile(r"(?i)\bbank(?:ing)?\s+(?:account|details)s?\b"), ("bank_account",)),
    (re.compile(r"(?i)\b(?:financial|banking)\s+(?:data|information|records)\b"), ("payment_card", "bank_account")),
]
_ABSENCE = [
    re.compile(r"(?i)\b(?:no|nothing)\s+(?:compromise|access|exfiltration|breach|unauthori[sz]ed access|data loss)\s+"
               r"(?:occurred|happened|took place)"),
    re.compile(r"(?i)\b(?:was|were)\s+not\s+(?:accessed|compromised|exfiltrated|breached|touched)"),
    re.compile(r"(?i)\b(?:rules?|ruled)\s+out\b|\bproves?\s+that\s+no\b|\bconfirms?\s+(?:that\s+)?no\b"),
]
_EXEC = re.compile(r"(?i)\b(?:has|have)\s+(?:already\s+)?been\s+(?:disabled|revoked|rotated|blocked|deleted|isolated|"
                   r"quarantined|reset)\b|\bI\s+(?:have|will|am going to)\s+(?:disable|revoke|block|run|execute|delete|rotate)")
_NUM = re.compile(r"(?<![\w.])\d+(?:[ ,]\d{3})*(?:\.\d+)?%?(?![\w])")
_STRIP = [
    re.compile(r"\bFACT-[\w\-]+"),
    re.compile(r"\b[A-Z]{1,8}-[0-9A-Za-z_]+(?:[:\-][0-9A-Za-z_]+)*\b"),           # AF-, PATH-, SRC-012:631, AST-LABSQL01
    re.compile(r"\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?"),
    re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\b"),
    _IPV4,
    re.compile(r"\b(?=\w*[A-Za-z])(?=\w*\d)\w+\b"),                                   # LabDB03, H1, A4, v0001
    re.compile(r"\b[0-9a-f]{12,64}\b"),
]
_TABLE = re.compile(r"\b[A-Za-z_][\w]*\.[A-Za-z_][\w]*\.[A-Za-z_][\w]*\b")
_ACCT = re.compile(r"\bACCT-[0-9a-f]{10}\b")
_ASSET = re.compile(r"\bAST-[A-Za-z0-9\-]+\b")


def _rank(cls) -> int:
    return ORDER.index(cls) if cls in ORDER else -1


class ExfilScope:
    def __init__(self):
        self.tables: set[str] = set()
        self.categories: set[str] = set()
        self.facts: set[str] = set()


class Context:
    def __init__(self, bundle: dict):
        self.bundle = bundle
        self.items = bundle.get("evidence", {})
        self.facts = bundle.get("facts", {})
        self.assets = set(bundle.get("assets", []))
        self.sources = set(bundle.get("sources", []))
        for it in self.items.values():
            self.sources |= set(it.get("sources") or [])
        blob = canonical_bytes({"e": self.items, "f": self.facts}).decode("utf-8")
        self.ips = set(_IPV4.findall(blob))
        self.domains = {d.lower() for d in _DOMAIN.findall(blob)}
        self.has_gaps = any(i.get("type") in ("gap", "coverage_gap") for i in self.items.values()) or bool(
            bundle.get("missing_source_families"))

    def known(self, i: str) -> bool:
        return i in self.items or i in self.facts

    def _eligible(self, i: str) -> dict | None:
        it = self.items.get(i) or {}
        ok = it.get("exfiltration_evidence_kind") in EXFILTRATION_EVIDENCE_KINDS and \
            it.get("consequence_class") == "exfiltration_evidenced"
        return it if ok else None

    def eligible_exfil(self, ids) -> bool:
        return any(self._eligible(i) for i in ids)

    def exfil_scope(self, ids) -> ExfilScope:
        """What the cited eligible items establish: tables, data categories and the facts that count them."""
        sc = ExfilScope()
        for i in ids:
            it = self._eligible(i)
            if it is None:
                continue
            sc.tables |= {str(t).lower() for t in it.get("tables") or []}
            sc.categories |= set(it.get("categories") or [])
            sc.facts |= {r[5:] for r in it.get("related") or [] if isinstance(r, str) and r.startswith("fact:")
                         and r[5:] in self.facts}
        return sc

    def mentions(self, ids) -> str:
        """Everything the cited items say (for traceability of names in model text)."""
        parts = []
        for i in ids:
            it = self.items.get(i)
            if it:
                parts.append(canonical_bytes(it).decode("utf-8"))
        return "\n".join(parts).lower()


def _content_codes(s: str, ctx: Context) -> set[str]:
    codes = set()
    if find_identifier_like(s) or _SECRET.search(s) or _URL.search(s) or _ICD.search(s) or _CMD.search(s) \
            or _SQL.search(s) or _CODE.search(s):
        codes.add("prohibited_content")
    if any(ip not in ctx.ips for ip in _IPV4.findall(s)):
        codes.add("prohibited_content")
    if any(d.lower() not in ctx.domains for d in _DOMAIN.findall(s)):
        codes.add("prohibited_content")
    return codes


def _numbers(s: str) -> list[float]:
    t = s
    for rx in _STRIP:
        t = rx.sub(" ", t)
    out = []
    for m in _NUM.findall(t):
        v = m.rstrip("%").replace(",", "").replace(" ", "")
        try:
            out.append(float(v))
        except ValueError:
            out.append(float("nan"))
    return out


def _asserts(patterns, s: str, guard=_MODAL) -> bool:
    """True if a pattern matches without a hedge in the preceding words (or, for theft, in the match itself)."""
    for rx in patterns:
        for m in rx.finditer(s):
            before = s[max(0, m.start() - 40):m.start()]
            if not guard.search(before) and not (guard is _MODAL and guard.search(m.group(0))):
                return True
    return False


def _categories(s: str) -> list[tuple[str, ...]]:
    t = _TABLE.sub(" ", s)          # a table called "results" is not the category "test results"
    return [cats for rx, cats in _CATEGORY_WORDS if rx.search(t)]


def _scope_check(s: str, scope: ExfilScope | None, scope_values: list[float], *, class_claim: bool) -> tuple[bool, bool]:
    """(violation, scoped) for one text: every exfiltration sentence (and, for an exfiltration_evidenced hypothesis
    statement, every unqualified sentence) must stay inside ``scope``; ``scoped`` = an in-scope table/category is named."""
    violation = scoped = unscoped_theft = False
    for sent in _SENT.split(s):
        theft = _asserts(_THEFT, sent)
        if not theft and not (class_claim and not _LIMIT.search(sent)):
            continue
        tables = {t.lower() for t in _TABLE.findall(sent)}
        cats = _categories(sent)
        sc = scope or ExfilScope()
        if not tables <= sc.tables or any(not (set(c) & sc.categories) for c in cats):
            violation = True
        if any(n not in scope_values for n in _numbers(sent)) or _BROAD.search(sent):
            violation = True
        named = bool(tables & sc.tables) or any(set(c) & sc.categories for c in cats)
        scoped |= named
        unscoped_theft |= theft and not named
    if unscoped_theft and not scoped:
        violation = True            # "data was exfiltrated" with no table or category is a claim about everything
    return violation, scoped


def _text_codes(strings, ctx: Context, *, quantities: list[float], eligible_exfil: bool, check_theft: bool = True,
                scope: ExfilScope | None = None, scope_values: list[float] = ()) -> set[str]:
    codes = set()
    for s in strings:
        if not s:
            continue
        codes |= _content_codes(s, ctx)
        for n in _numbers(s):
            if not any(n == q for q in quantities):
                codes.add("unsupported_number")
        if check_theft and not eligible_exfil and _asserts(_THEFT, s):
            codes.add("exfiltration_unsupported")
        elif check_theft and _scope_check(s, scope, list(scope_values), class_claim=False)[0]:
            codes.add("exfiltration_scope")
        if ctx.has_gaps and _asserts(_ABSENCE, s, _HEDGE):
            codes.add("missing_logs_as_absence")
    return codes


def _untraceable(strings, ctx: Context, cited: list[str]) -> bool:
    known = ctx.mentions(cited)
    for s in strings:
        for rx in (_TABLE, _ACCT, _ASSET, _IPV4):
            for tok in rx.findall(s or ""):
                if tok.lower() not in known:
                    return True
    return False


def _verdict(codes: set[str], unverified: bool) -> dict:
    hard = sorted(c for c in codes if c in HARD)
    if hard:
        return {"verdict": "rejected", "codes": hard}
    return {"verdict": "unverified", "codes": ["untraceable_reference"]} if unverified else {"verdict": "accepted", "codes": []}


def _hypothesis(h: dict, ctx: Context) -> dict:
    codes: set[str] = set()
    cited = list(h["supporting_evidence"]) + list(h["contradicting_evidence"])
    if not all(ctx.known(i) for i in cited):
        codes.add("unknown_evidence")
    if not set(h["assets"]) <= ctx.assets:
        codes.add("unknown_asset")
    if not set(h["sources"]) <= ctx.sources:
        codes.add("unknown_source")
    support = [ctx.items[i] for i in h["supporting_evidence"] if i in ctx.items]
    strongest = max([_rank(it.get("consequence_class")) for it in support] + [-1])
    asserted = h["consequence_class"]
    eligible = ctx.eligible_exfil(h["supporting_evidence"])
    if _rank(asserted) > strongest:
        codes.add("promotion")
    if asserted == "exfiltration_evidenced" and not eligible:
        codes.add("exfiltration_unsupported")
    # an inference needs positive evidence: a gap only shows that evidence is missing
    if h["basis"] == "inference" and not (any(it.get("basis") in ("observation", "inference")
                                              and it.get("type") not in ("gap", "coverage_gap") for it in support)
                                          or any(i in ctx.facts for i in h["supporting_evidence"])):
        codes.add("unsupported_conclusion")
    if h["confidence"] == "high" and h["contradicting_evidence"]:
        codes.add("confidence_label")
    scope = ctx.exfil_scope(h["supporting_evidence"])
    qvals, svals = [], []
    for q in h["quantities"]:
        f = ctx.facts.get(q["fact_id"])
        if f is None or f["value"] != q["value"] or isinstance(q["value"], str) != isinstance(f["value"], str):
            codes.add("unsupported_number")
        elif isinstance(q["value"], (int, float)):
            qvals.append(float(q["value"]))
            if q["fact_id"] in scope.facts:
                svals.append(float(q["value"]))
    if asserted == "exfiltration_evidenced" and eligible:
        violation, scoped = _scope_check(h["statement"], scope, svals, class_claim=True)
        if violation or not scoped:
            codes.add("exfiltration_scope")
    texts = [h["statement"], h["confidence_rationale"], *h["alternative_explanations"],
             *[t["evidence_needed"] for t in h["tests"]], *[t["would_resolve"] for t in h["tests"]]]
    codes |= _text_codes(texts, ctx, quantities=qvals, eligible_exfil=eligible, scope=scope, scope_values=svals)
    codes |= _text_codes(h["cannot_conclude"], ctx, quantities=qvals, eligible_exfil=eligible, check_theft=False)
    unverified = _untraceable([h["statement"]], ctx, cited)
    return _verdict(codes, unverified)


def _listed(it: dict, ctx: Context, *, ids_key: str, text_keys: tuple, assets_key: str | None = None) -> dict:
    codes: set[str] = set()
    ids = it.get(ids_key) or []
    if not all(ctx.known(i) for i in ids):
        codes.add("unknown_evidence")
    if assets_key and not set(it.get(assets_key) or []) <= ctx.assets:
        codes.add("unknown_asset")
    texts = [it[k] for k in text_keys]
    codes |= _text_codes(texts, ctx, quantities=[], eligible_exfil=ctx.eligible_exfil(ids), scope=ctx.exfil_scope(ids))
    if assets_key and any(_EXEC.search(t) for t in texts):
        codes.add("execution_claim")
    return _verdict(codes, _untraceable(texts, ctx, ids) if ids else False)


def validate(raw: bytes, bundle: dict, *, case_id: str) -> dict:
    """Validate provider output. Returns ``{"envelope": {...}, "candidate": dict|None, "verdicts": {...}}``."""
    from .bundle import bundle_hash

    if bundle_hash(bundle) != bundle.get("bundle_sha256"):     # the bundle itself must be the one that was hashed
        return {"envelope": {"verdict": "rejected", "codes": ["bundle_mismatch"]}, "candidate": None, "verdicts": {}}
    ctx = Context(bundle)
    try:
        cand = parse(raw)
    except SchemaError:
        return {"envelope": {"verdict": "rejected", "codes": ["schema"]}, "candidate": None, "verdicts": {}}
    errs = check_candidate(cand)
    if errs:
        return {"envelope": {"verdict": "rejected", "codes": ["schema"], "schema_errors": len(errs)},
                "candidate": None, "verdicts": {}}
    env_codes = []
    if cand["case_id"] != case_id:
        env_codes.append("case_mismatch")
    if cand["bundle_sha256"] != bundle.get("bundle_sha256"):
        env_codes.append("bundle_mismatch")
    if env_codes:
        return {"envelope": {"verdict": "rejected", "codes": env_codes}, "candidate": None, "verdicts": {}}
    v: dict[str, dict] = {}
    for h in cand["hypotheses"]:
        v[h["hypothesis_id"]] = _hypothesis(h, ctx)
    for i, it in enumerate(cand["missing_evidence"]):
        v[f"M{i + 1}"] = _listed(it, ctx, ids_key="related_evidence", text_keys=("description", "source_family"))
    for i, it in enumerate(cand["investigation_steps"]):
        v[f"S{i + 1}"] = _listed(it, ctx, ids_key="evidence_ids", text_keys=("step",))
    for i, it in enumerate(cand["remediation"]):
        v[f"R{i + 1}"] = _listed(it, ctx, ids_key="evidence_ids", text_keys=("action",), assets_key="asset_ids")
    for i, s in enumerate(cand["unproven_assertions"]):
        c = _text_codes([s], ctx, quantities=[], eligible_exfil=True, check_theft=False)
        v[f"U{i + 1}"] = _verdict(c, False)
    v["summary"] = _verdict(_text_codes([cand["summary"]], ctx, quantities=[], eligible_exfil=False), False)
    return {"envelope": {"verdict": "accepted", "codes": []}, "candidate": cand, "verdicts": v}


def assemble(validation: dict, *, base: dict) -> dict:
    """Build the ``tripline.investigation/v1`` result from a validation outcome (rejected content dropped)."""
    res = dict(base)
    res["schema"] = RESULT_SCHEMA
    res["validator_version"] = VALIDATOR_VERSION
    env, cand, v = validation["envelope"], validation["candidate"], validation["verdicts"]
    counts = {"accepted": 0, "rejected": 0, "unverified": 0}
    for x in v.values():
        counts[x["verdict"]] += 1
    rejections = [{"item": k, "codes": x["codes"]} for k, x in sorted(v.items()) if x["verdict"] == "rejected"]
    res.update({"summary": None, "hypotheses": [], "missing_evidence": [], "investigation_steps": [], "remediation": [],
                "unproven_assertions": []})
    if env["verdict"] != "accepted":
        res["analysis_status"] = "failed"
        res["status_reason"] = "provider output rejected by the validator: " + ", ".join(env["codes"])
        res["validation"] = {"verdict": "rejected", "envelope": env, "counts": counts, "rejections": []}
        return res

    def keep(key, item):
        x = v[key]
        if x["verdict"] == "rejected":
            return None
        return dict(item, item_id=key, validation=x)

    for h in cand["hypotheses"]:
        k = keep(h["hypothesis_id"], h)
        if k:
            res["hypotheses"].append(k)
    for prefix, name in (("M", "missing_evidence"), ("S", "investigation_steps"), ("R", "remediation")):
        for i, it in enumerate(cand[name]):
            k = keep(f"{prefix}{i + 1}", it)
            if k:
                if name == "remediation":
                    k.update(requires_hospital_authorisation=True, executed=False)
                res[name].append(k)
    res["unproven_assertions"] = [{"item_id": f"U{i + 1}", "text": s, "validation": v[f"U{i + 1}"]}
                                  for i, s in enumerate(cand["unproven_assertions"]) if v[f"U{i + 1}"]["verdict"] != "rejected"]
    if v["summary"]["verdict"] != "rejected":
        res["summary"] = cand["summary"]
    accepted_h = [h for h in res["hypotheses"] if h["validation"]["verdict"] == "accepted"]
    main_ok = any(h["rank"] == "main" for h in accepted_h)
    res["analysis_status"] = "completed" if accepted_h else "failed"
    res["status_reason"] = None if main_ok else (
        "the main hypothesis did not pass validation; only alternatives are shown" if accepted_h else
        "no hypothesis passed validation")
    res["validation"] = {"verdict": "completed" if accepted_h else "rejected", "envelope": env, "counts": counts,
                         "rejections": rejections}
    return res
