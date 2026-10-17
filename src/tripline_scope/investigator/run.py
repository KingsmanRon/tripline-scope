"""Investigator runs: evidence bundle → provider → deterministic validation → encrypted result → human review.

A run never modifies module reports, evidence classes, counts, scope or notification records; it only writes
under ``work/investigator/`` (encrypted). Provider absence or failure is recorded as ``unavailable``/``failed`` and
leaves every module untouched. A failed run can be retried: each attempt is a new run id.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import ConfigError, NotReady, PermissionDenied
from tripline_scope.core.redact import find_identifier_like, scrub_text
from tripline_scope.core.timeutil import now_iso

from . import bundle as B
from . import prompt as P
from . import providers as PR
from . import storage as S
from . import synthetic as SY
from . import validate as V
from .schema import MAX_RAW

METHOD_VERSION = "investigator/1.0.0"
DECISIONS = ("accept", "reject")
BRIDGE_SCHEMA = "tripline.investigation-bridge-export/v1"
_URLISH = ("://", "www.")


def _config_sha(home) -> str:
    cfg = (home.config.get("investigator") or {}) if home is not None else {}
    return sha256_hex(canonical_bytes({"investigator": cfg, "method": METHOD_VERSION, "validator": V.VALIDATOR_VERSION}))


def _base(case, home, run_id: str, bundle: dict, prompt: dict) -> dict:
    return {
        "case_id": case.case_id, "run_id": run_id, "created_at": now_iso(),
        "references": [{k: r[k] for k in ("kind", "version", "report_sha256")} for r in bundle["reports"]],
        "not_assessed_modules": bundle["not_assessed"], "bundle_sha256": bundle["bundle_sha256"],
        "prompt_sha256": prompt["prompt_sha256"], "method_version": METHOD_VERSION, "config_sha256": _config_sha(home),
        "provenance": None, "model_output_sha256": None, "human_review": {"required": True, "decisions": {}},
    }


def _empty(res: dict, status: str, reason: str) -> dict:
    res.update({"schema": "tripline.investigation/v1", "validator_version": V.VALIDATOR_VERSION,
                "analysis_status": status, "status_reason": reason, "summary": None, "hypotheses": [],
                "missing_evidence": [], "investigation_steps": [], "remediation": [], "unproven_assertions": [],
                "validation": {"verdict": "not_run", "counts": {"accepted": 0, "rejected": 0, "unverified": 0},
                               "rejections": []}})
    return res


def _save(store, res: dict) -> None:
    rid = res["run_id"]
    store.write_json(f"{S.run_dir(rid)}/result.json", res)
    prov = res.get("provenance") or {}
    S.add_run(store, {"run_id": rid, "created_at": res["created_at"], "provider": prov.get("provider"),
                      "provider_kind": prov.get("provider_kind"), "model_id": prov.get("model_id"),
                      "status": res["analysis_status"]})


def _prepare(case, home, store) -> tuple[str, dict, dict]:
    bundle = B.build(case, home)
    prompt = P.build(bundle)
    run_id = "RUN-" + secrets.token_hex(6)
    d = S.run_dir(run_id)
    store.write_json(f"{d}/bundle.json", bundle)
    store.write_json(f"{d}/prompt.json", prompt)
    return run_id, bundle, prompt


def analyse(case, home, store, *, provider_name: str) -> dict:
    provider = PR.get(provider_name, home)      # unknown names fail before anything is written
    run_id, bundle, prompt = _prepare(case, home, store)
    base = _base(case, home, run_id, bundle, prompt)
    ok, why = provider.available()
    if not ok:
        res = _empty(base, "unavailable", why)
        res["provenance"] = {"provider": provider.name, "provider_kind": provider.kind, "model_id": None,
                             "model_version": None, "is_model_inference": False, "endpoint_class": "none"}
        _save(store, res)
        return res
    try:
        resp = provider.analyse(prompt, bundle=bundle, budget=provider.budget())
    except PR.ProviderFailed as exc:
        res = _empty(base, "failed", str(exc))
        res["provenance"] = {"provider": provider.name, "provider_kind": provider.kind, "model_id": None,
                             "model_version": None, "is_model_inference": False, "endpoint_class": "none"}
        _save(store, res)
        return res
    return _finish(store, base, bundle, resp.raw, resp.provenance, case.case_id)


def _finish(store, base: dict, bundle: dict, raw: bytes, provenance: dict, case_id: str) -> dict:
    store.write_bytes(f"{S.run_dir(base['run_id'])}/response.bin", raw)
    v = V.validate(raw, bundle, case_id=case_id)
    res = V.assemble(v, base=dict(base, provenance=provenance, model_output_sha256=sha256_hex(raw)))
    _save(store, res)
    return res


# ---------------------------------------------------------------------------------------------- review
def _items(res: dict) -> dict[str, dict]:
    out = {h["item_id"]: h for h in res.get("hypotheses", [])}
    for k in ("missing_evidence", "investigation_steps", "remediation", "unproven_assertions"):
        for it in res.get(k, []):
            out[it["item_id"]] = it
    return out


def clean_note(note: str | None) -> str:
    note = " ".join(str(note or "").split())[:300]
    if find_identifier_like(note) or any(u in note.lower() for u in _URLISH):
        raise ConfigError("review notes must not contain identifiers, contact details or URLs")
    return scrub_text(note)


def review(store, run_id: str, item_id: str, decision: str, reviewer: str, note: str | None) -> dict:
    if decision not in DECISIONS:
        raise ConfigError("decision must be accept or reject")
    res = S.load_result(store, run_id)
    if res.get("analysis_status") != "completed":
        raise NotReady("only completed runs can be reviewed")
    if item_id not in _items(res):
        raise ConfigError("no such item in this run (rejected items cannot be reviewed)")
    row = {"item_id": item_id, "decision": decision, "reviewer": reviewer, "at": now_iso(), "note": clean_note(note)}
    S.append_review(store, run_id, row)
    return row


# ---------------------------------------------------------------------------------------------- manual bridge
def _require_synthetic(case, home, store) -> None:
    ok, problems = SY.case_is_synthetic(case, home, store)
    if not ok:
        raise PermissionDenied(f"manual bridge refused: {len(problems)} case input(s) were not produced by an attested "
                               "synthetic generator (first: " + (problems[0] if problems else "none") + "). "
                               "Hospital cases never leave this installation.")


def bridge_export(case, home, store, out: Path) -> dict:
    """Synthetic cases only: write the bounded prompt for a human to evaluate in a separately authorised session."""
    _require_synthetic(case, home, store)
    out = Path(out)
    if out.exists():
        raise ConfigError("output file exists; choose a new path")
    run_id, bundle, prompt = _prepare(case, home, store)
    base = _base(case, home, run_id, bundle, prompt)
    res = _empty(base, "not_assessed", "awaiting a manually imported response (synthetic case)")
    _save(store, res)
    doc = {"schema": BRIDGE_SCHEMA, "case_id": case.case_id, "run_id": run_id, "bundle_sha256": bundle["bundle_sha256"],
           "notice": "SYNTHETIC DATA ONLY. Generated by Tripline's attested synthetic generators. Use only in a session "
                     "you are separately authorised to use for synthetic development data. Paste the messages, then "
                     "save the model's single JSON reply to a file and import it with 'tscope investigator "
                     "bridge-import'. This is a manual, human-mediated step, not an API integration.",
           "messages": prompt["messages"]}
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(canonical_bytes(doc))
    return {"run_id": run_id, "out": str(out), "bundle_sha256": bundle["bundle_sha256"]}


def bridge_import(case, home, store, run_id: str, response: Path, model_label: str) -> dict:
    _require_synthetic(case, home, store)
    res0 = S.load_result(store, run_id)
    if res0.get("analysis_status") != "not_assessed":
        raise ConfigError("this run is not awaiting a bridge response")
    data = Path(response).read_bytes()[:MAX_RAW + 1]
    bundle = store.read_json(f"{S.run_dir(run_id)}/bundle.json")
    label = " ".join(str(model_label or "").split())[:80]
    if not label or find_identifier_like(label) or any(u in label.lower() for u in _URLISH):
        raise ConfigError("give the model label as shown in the session (plain text)")
    base = {k: res0[k] for k in ("case_id", "run_id", "references", "not_assessed_modules", "bundle_sha256",
                                 "prompt_sha256", "method_version", "config_sha256", "human_review")}
    base["created_at"] = now_iso()
    prov = {"provider": "manual-bridge", "provider_kind": "manual_bridge", "model_id": f"user-declared: {label}",
            "model_version": "user-declared", "is_model_inference": True, "endpoint_class": "manual",
            "notice": "Pasted by an operator from a separately authorised session on synthetic data. The model's identity "
                      "is declared by the operator and is not verified by Tripline."}
    return _finish(store, base, bundle, data, prov, case.case_id)
