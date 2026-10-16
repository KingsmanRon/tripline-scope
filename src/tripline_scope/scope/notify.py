"""Notification pack: built on site, encrypted in ``notify/``, exported only by the approver after release.

``build`` (operator) binds the pack to the current refined scope draft: the set of people in the proposed
notification scope must hash to the ``people_set_sha256`` recorded in that draft. Per person it keeps only what a
notice needs: an opaque reference, the route (segment), the name for the salutation, the best contact details
(for children, the guardian's), language preference, the categories exposed and the consequence wording.

``release`` (core) signs the report; the scope release hook marks the pack unlocked when it was built from the
released draft. ``export`` (approver, fresh sign-in) refuses unless a released version matches the pack, writes
``people.csv`` (segmented), one rendered notice per exposure combination × language × audience × consequence,
and the Regulator update summary (JSON + PDF) in the order of the eServices security-compromise form. Nothing is
sent from the tool.
"""

from __future__ import annotations

import csv
import hashlib
import io
import os
from pathlib import Path

import pyarrow as pa
from jinja2 import FileSystemLoader, StrictUndefined, TemplateNotFound, select_autoescape
from jinja2.sandbox import SandboxedEnvironment

from tripline_scope.core.canonical import canonical_bytes, load_canonical, sha256_file, sha256_hex
from tripline_scope.core.errors import ConfigError, IntegrityError, NotReady, PermissionDenied
from tripline_scope.core.pdf import Section, render
from tripline_scope.core.reports import ReportStore
from tripline_scope.core.timeutil import now_iso

from . import constrain as K
from . import data as D
from . import run as R
from .config import EXPOSURE_CATEGORIES
from .data import CAT_BIT
from .report import CATEGORY_LABELS

PACK = "notify/pack.parquet"
PACK_META = "notify/pack.json"
UNLOCK = "notify/unlock.json"
BUILTIN_TEMPLATES = Path(__file__).resolve().parent.parent / "templates" / "notices"

ADVICE = {
    "identity_number": "Consider registering for protective verification with the Southern African Fraud Prevention "
                       "Service (SAFPS) and watch for accounts or credit applications you did not make.",
    "contact_details": "Expect possible scam calls, SMS or e-mails that use your details; do not click links or share "
                       "one-time PINs.",
    "address": "Be alert to post or visitors claiming to be from the hospital or a debt collector.",
    "medical_aid": "Check your medical aid statements for claims you do not recognise and report them to your scheme.",
    "payment_card": "Contact your bank to block or replace the card and check recent transactions.",
    "bank_account": "Tell your bank, watch your statements and be wary of debit orders you did not authorise.",
    "clinical_diagnosis": "If anyone contacts you about your health information or threatens to publish it, do not pay; "
                          "report it to us and to the South African Police Service.",
    "clinical_tests": "If anyone contacts you about your test history or threatens to publish it, do not pay; report it "
                      "to us and to the South African Police Service.",
    "clinical_results": "If anyone contacts you about your test results, do not engage; report it to us.",
    "clinical_notes": "If anyone contacts you about your clinical records, do not engage; report it to us.",
}
CONSEQUENCES = {
    "identity_number": "identity fraud or impersonation (for example credit or accounts opened in the person's name)",
    "name": "targeted scams that use the person's name",
    "date_of_birth": "use in identity fraud together with other details",
    "contact_details": "phishing, scam calls and SMS messages",
    "address": "targeted fraud by post or in person",
    "medical_aid": "medical aid fraud (false claims)",
    "clinical_diagnosis": "distress, discrimination or extortion based on health information",
    "clinical_tests": "distress, discrimination or extortion based on the tests ordered",
    "clinical_results": "distress, discrimination or extortion based on test results",
    "clinical_notes": "distress, discrimination or extortion based on clinical notes",
    "payment_card": "card fraud",
    "bank_account": "debit-order or banking fraud",
}


def people_set_digest(keys: list[str]) -> str:
    return sha256_hex("\n".join(sorted(keys)).encode())


# ------------------------------------------------------------------------------------------------ build
def build(case, store, cfg: dict, *, threads=None) -> dict:
    rs = ReportStore(case)
    try:
        draft = rs.get_draft("scope", None)
    except NotReady:
        raise NotReady("no current scope draft: run 'tscope scope report' first, then build the pack, then release") from None
    body = load_canonical((draft.path / "report.json").read_bytes())
    if body.get("report_status") != "refined":
        raise NotReady("the current scope draft is a preliminary estimate; run 'tscope scope match' and 'scope report'")
    want = body["scope_tiers"]["notification_scope"].get("people_set_sha256")
    tables = store.read_json(R.TABLES)["tables"]
    rules = K.table_rules(K.load_candidates(store), tables, K.load_decisions(store))
    data = D.load(case, store, cfg, threads=threads, include_dependent=False,
                  reference_date=_date(store.read_json(R.MATCH)["reference_date"]))
    con = data.con
    try:
        for name, t in (("people_p", store.read_table(R.PEOPLE)), ("prow", store.read_table(R.PERSON_ROWS)),
                        ("ptab", store.read_table(R.PERSON_TABLES))):
            con.register(f"_{name}", t)
            con.execute(f"CREATE TABLE {name} AS SELECT * FROM _{name}")
            con.unregister(f"_{name}")
        upper = K.scenario_sql(rules["rules"], "upper")
        lower = K.scenario_sql(rules["rules"], "lower")
        has_cands = K.load_candidates(store) is not None
        con.execute(f"CREATE TABLE in_scope AS SELECT DISTINCT person_key FROM ptab WHERE {upper}")
        con.execute(f"CREATE TABLE observed AS SELECT DISTINCT person_key FROM ptab WHERE {lower}")
        keys = [r[0] for r in con.execute("SELECT person_key FROM in_scope ORDER BY 1").fetchall()]
        digest = people_set_digest(keys)
        if want != digest:
            raise IntegrityError("the people in the notification scope differ from the current draft report; "
                                 "re-run 'tscope scope report' before building the pack")
        _define_tc(con)
        fp = store.fingerprinter("person-ref")
        con.execute("CREATE TABLE refs(person_key VARCHAR, person_ref VARCHAR)")
        con.register("_refs", pa.table({"person_key": keys, "person_ref": [fp(k, 16) for k in keys]}))
        con.execute("INSERT INTO refs SELECT * FROM _refs")
        con.unregister("_refs")
        tbl = con.execute(f"""
        WITH r AS (
          SELECT p.person_key, i.*, t.evidence_role FROM prow p JOIN ident i USING (row_key)
          JOIN src_tables t ON t.t_idx = i.t_idx WHERE coalesce(t.evidence_role, '') <> 'leak_sample'),
        nm AS (SELECT person_key, first_disp, last_disp, count(*) AS n, max(coalesce(record_date, DATE '1900-01-01')) AS d,
                      min(row_key) AS k FROM r WHERE last_disp IS NOT NULL GROUP BY ALL),
        name0 AS (SELECT person_key, arg_max(struct_pack(f := first_disp, l := last_disp),
                                             struct_pack(n := n, d := d, k := k)) AS nm FROM nm GROUP BY person_key),
        name AS (SELECT person_key, nm.f AS first_disp, nm.l AS last_disp FROM name0),
        ph AS (SELECT person_key, arg_max(coalesce(phone, phone_alt), coalesce(record_date, DATE '1900-01-01')) AS phone
               FROM r WHERE coalesce(phone, phone_alt) IS NOT NULL GROUP BY ALL),
        em AS (SELECT person_key, arg_max(email, coalesce(record_date, DATE '1900-01-01')) AS email FROM r
               WHERE email IS NOT NULL GROUP BY ALL),
        ad AS (SELECT person_key, arg_max(address || coalesce(', ' || postal, ''), coalesce(record_date, DATE '1900-01-01'))
                 AS postal_address FROM r WHERE address IS NOT NULL GROUP BY ALL),
        gd AS (SELECT person_key, arg_max(struct_pack(n := guardian_name, p := g_phone, e := g_email),
                                          coalesce(record_date, DATE '1900-01-01')) AS g
               FROM r WHERE g_phone IS NOT NULL OR g_email IS NOT NULL GROUP BY ALL)
        SELECT f.person_ref, p.segment,
          CASE WHEN p.segment = 'adult_with_contact' THEN 'person'
               WHEN p.segment = 'minor_guardian_routed' THEN 'guardian'
               WHEN p.segment = 'minor_flagged_no_guardian' THEN 'flagged'
               ELSE 'public_notice' END AS audience,
          CASE WHEN p.in_leak THEN 'confirmed_copy'
               WHEN {'p.person_key IN (SELECT person_key FROM observed)' if has_cands else 'FALSE'} THEN 'access_observed'
               ELSE 'possible' END AS consequence,
          CASE WHEN p.segment IN ('adult_with_contact', 'minor_guardian_routed') THEN title_case_name(n.first_disp) END
            AS first_name,
          CASE WHEN p.segment IN ('adult_with_contact', 'minor_guardian_routed') THEN title_case_name(n.last_disp) END
            AS last_name,
          CASE WHEN p.segment = 'adult_with_contact' THEN ph.phone END AS phone,
          CASE WHEN p.segment = 'adult_with_contact' THEN em.email END AS email,
          CASE WHEN p.segment = 'adult_with_contact' THEN ad.postal_address END AS postal_address,
          CASE WHEN p.segment = 'minor_guardian_routed' THEN gd.g.n END AS guardian_name,
          CASE WHEN p.segment = 'minor_guardian_routed' THEN gd.g.p END AS guardian_phone,
          CASE WHEN p.segment = 'minor_guardian_routed' THEN gd.g.e END AS guardian_email,
          coalesce(p.language, 'en') AS language, p.cat_mask, p.person_key
        FROM in_scope s JOIN people_p p USING (person_key) JOIN refs f USING (person_key)
        LEFT JOIN name n USING (person_key) LEFT JOIN ph USING (person_key) LEFT JOIN em USING (person_key)
        LEFT JOIN ad USING (person_key) LEFT JOIN gd USING (person_key)
        ORDER BY p.segment, f.person_ref""".replace("title_case_name(", "_tc(")).to_arrow_table()
    finally:
        con.close()
    cats = [";".join(c for c in EXPOSURE_CATEGORIES if m & CAT_BIT[c]) for m in tbl.column("cat_mask").to_pylist()]
    tbl = tbl.drop(["cat_mask", "person_key"]).append_column("categories", pa.array(cats, pa.string()))
    store.write_table(PACK, tbl)
    counts = {}
    for s in tbl.column("segment").to_pylist():
        counts[s] = counts.get(s, 0) + 1
    meta = {"schema": "tripline.notification-pack/v1", "report_version": draft.version,
            "report_sha256": draft.report_sha256, "draft_id": draft.draft_id, "people_set_sha256": digest,
            "people": tbl.num_rows, "segments": counts, "built_at": now_iso()}
    store.write_json(PACK_META, meta)
    store.delete(UNLOCK)
    return meta


def _define_tc(con) -> None:
    con.execute("""CREATE OR REPLACE MACRO _tc(s) AS CASE WHEN s IS NULL THEN NULL ELSE array_to_string(list_transform(
        string_split(lower(s), ' '), w -> CASE WHEN w IN ('van', 'der', 'den', 'du', 'de', 'le', 'la', 'von', 'te', 'ter')
                                     THEN w ELSE upper(left(w, 1)) || substr(w, 2) END), ' ') END""")


def _date(s):
    import datetime as dt

    return dt.date.fromisoformat(s)


# ------------------------------------------------------------------------------------------------ release hook
def on_release(case, vdir: Path, approver) -> None:
    """Release hook for kind ``scope``: keep the version's person-level snapshot and unlock a matching pack."""
    import logging

    from tripline_scope.core.home import Home
    from tripline_scope.core.store import open_store

    from .report import SNAPSHOTS, promote_snapshot

    log = logging.getLogger(__name__)
    try:
        store = open_store(case, Home())
        report_sha = sha256_file(vdir / "report.json")
        version = int(vdir.name[1:])
        for rel in store.list(SNAPSHOTS, "meta.json"):
            meta = store.read_json(rel)
            if meta.get("report_sha256") == report_sha:
                promote_snapshot(store, rel.split("/")[-2], version)
        if store.exists(PACK_META):
            meta = store.read_json(PACK_META)
            if meta.get("report_sha256") == report_sha:
                store.write_json(UNLOCK, {"version": version, "report_sha256": report_sha,
                                          "approver": approver.username, "unlocked_at": now_iso()})
    except Exception as exc:  # noqa: BLE001 - the release itself is complete and signed; export re-checks everything
        log.warning("scope release hook could not complete (%s); export will refuse until resolved", type(exc).__name__)


# ------------------------------------------------------------------------------------------------ export
def _check_released(case, store, home) -> tuple[dict, dict, int, dict]:
    if not store.exists(PACK_META):
        raise NotReady("no notification pack: run 'tscope scope notify build' before release")
    meta = store.read_json(PACK_META)
    rs = ReportStore(case)
    latest = rs.latest("scope")
    if latest is None:
        raise PermissionDenied("the scope report has not been released; the notification pack stays locked")
    version, vdir, sha = latest
    if sha != meta["report_sha256"]:
        raise PermissionDenied("the notification pack does not match the latest released scope version; rebuild the "
                               "draft report and pack and release again")
    if not store.exists(UNLOCK) or store.read_json(UNLOCK).get("report_sha256") != sha:
        raise PermissionDenied("the notification pack was not unlocked by the release of this version")
    res = rs.verify("scope", home)
    if not res.ok:
        raise IntegrityError("released scope chain failed verification")
    body = load_canonical((vdir / "report.json").read_bytes())
    if body["scope_tiers"]["notification_scope"].get("people_set_sha256") != meta["people_set_sha256"]:
        raise IntegrityError("pack people set differs from the released notification scope")
    release = load_canonical((vdir / "release.json").read_bytes())
    return meta, body, version, release


def _env(case, home) -> list[Path]:
    dirs = []
    tdir = (case.config.get("notify") or {}).get("templates_dir")
    if tdir:
        dirs.append(Path(tdir))
    if home is not None:
        dirs.append(Path(home.root) / "templates" / "notices")
    dirs.append(BUILTIN_TEMPLATES)
    return [d for d in dirs if d.is_dir()]


def _template(env, lang: str, combo_id: str):
    for name, used in ((f"{lang}/{combo_id}.md.j2", lang), (f"{lang}/notice.md.j2", lang),
                       (f"en/{combo_id}.md.j2", "en"), ("en/notice.md.j2", "en")):
        try:
            return env.get_template(name), used
        except TemplateNotFound:
            continue
    raise ConfigError("no notice template found (expected templates/notices/en/notice.md.j2)")


def export(case, store, home, out_dir: Path) -> dict:
    meta, body, version, release = _check_released(case, store, home)
    out_dir = Path(out_dir)
    if out_dir.exists() and any(out_dir.iterdir()):
        raise ConfigError("export directory exists and is not empty")
    real = os.path.realpath(out_dir)
    for s in case.sources():
        for f in s.get("files", []):
            if f.get("path") and (real + os.sep).startswith(os.path.realpath(f["path"]) + os.sep):
                raise ConfigError("refusing to export inside a registered source")
    pack = store.read_table(PACK)
    rows = pack.to_pylist()
    keys_digest_check = len(rows) == meta["people"]
    if not keys_digest_check:
        raise IntegrityError("pack row count differs from its manifest")
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    nc = case.config.get("notify") or {}
    hospital = nc.get("hospital_name") or (home.config.get("hospital_name") if home else None) or "The hospital"
    win = body.get("incident_window") or {}
    env = SandboxedEnvironment(loader=FileSystemLoader([str(d) for d in _env(case, home)]),
                               autoescape=select_autoescape(["html", "htm", "xml"]), undefined=StrictUndefined,
                               keep_trailing_newline=True)
    measures = nc.get("measures") or ["We contained the incident, reset access credentials and are investigating with "
                                      "forensic specialists.", "We have reported the compromise to the Information Regulator."]
    contact = nc.get("contact") or "Contact the hospital's Information Officer (details to be completed by the hospital)."
    accessed_by = nc.get("accessed_by") or "We do not yet know who accessed the information. We will update you if this changes."
    notices: dict[tuple, str] = {}
    files: dict[str, str] = {}
    for r in rows:
        if r["audience"] not in ("person", "guardian"):
            r["notice_file"] = ""
            r["template_language"] = ""
            continue
        combo = r["categories"]
        combo_id = hashlib.sha256(combo.encode()).hexdigest()[:10]
        key = (r["language"], combo, r["audience"], r["consequence"])
        if key not in notices:
            tpl, used = _template(env, r["language"], combo_id)
            cats = [{"key": c, "label": CATEGORY_LABELS[c], "advice": ADVICE.get(c)} for c in combo.split(";") if c]
            text = tpl.render(hospital_name=hospital, audience=r["audience"], consequence=r["consequence"],
                              incident_start=str(win.get("start") or "unknown")[:10],
                              incident_end=str(win.get("end") or "unknown")[:10], categories=cats, measures=measures,
                              contact=contact, accessed_by=accessed_by)
            rel = f"notices/{used}/{r['audience']}-{r['consequence']}-{combo_id}.md"
            path = out_dir / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            files[rel] = sha256_file(path)
            notices[key] = (rel, used)
        r["notice_file"], r["template_language"] = notices[key]
    cols = ["person_ref", "segment", "audience", "consequence", "first_name", "last_name", "phone", "email",
            "postal_address", "guardian_name", "guardian_phone", "guardian_email", "language", "template_language",
            "notice_file", "categories"]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols)
    for r in rows:
        w.writerow(["" if r.get(c) is None else r[c] for c in cols])
    (out_dir / "people.csv").write_text(buf.getvalue(), encoding="utf-8")
    files["people.csv"] = sha256_file(out_dir / "people.csv")
    summary = regulator_summary(case, body, version, release, nc)
    (out_dir / "regulator_summary.json").write_bytes(canonical_bytes(summary))
    (out_dir / "regulator_summary.pdf").write_bytes(regulator_pdf(summary))
    for f in ("regulator_summary.json", "regulator_summary.pdf"):
        files[f] = sha256_file(out_dir / f)
    manifest = {"schema": "tripline.notification-export/v1", "case_id": case.case_id, "report_version": version,
                "report_sha256": meta["report_sha256"], "people_set_sha256": meta["people_set_sha256"],
                "segments": meta["segments"], "people": meta["people"], "files": files,
                "note": "Nothing is sent by Tripline Scope. Load people.csv into the hospital's mail-merge or SMS system."}
    (out_dir / "export_manifest.json").write_bytes(canonical_bytes(manifest))
    for p in out_dir.rglob("*"):
        if p.is_file():
            os.chmod(p, 0o600)
    return manifest


# ------------------------------------------------------------------------------------------------ regulator summary
def regulator_summary(case, body: dict, version: int, release: dict, nc: dict) -> dict:
    c = body["counts"]
    tiers = body["scope_tiers"]
    cats = [k for k, v in c["people_per_category"].items() if v]
    todo = "To be completed by the Information Officer."
    win = body.get("incident_window") or {}
    sections = [
        {"field": "dates", "incident_start": win.get("start"), "incident_end": win.get("end"),
         "discovered_on": nc.get("discovered_on") or todo, "scope_report_version": version,
         "scope_report_released_at": (release.get("approval") or {}).get("approved_at")},
        {"field": "description", "text": nc.get("description") or todo},
        {"field": "number_of_data_subjects", "notification_scope_proposed": tiers["notification_scope"]["proposed_count"],
         "possible_exposure": tiers["possible_exposure"]["count"], "observed_access": tiers["observed_access"]["count"],
         "confirmed_exfiltration": tiers["confirmed_exfiltration"]["count"], "children_under_18": c["minors"]["total"],
         "without_contact_details_public_notice": c["without_contact_details"]["total"],
         "unresolvable_rows_not_counted_as_people": c["unresolvable_rows"]["total"]},
        {"field": "categories_of_personal_information", "people_per_category": {k: c["people_per_category"][k] for k in cats},
         "special_personal_information": any(k.startswith("clinical") for k in cats)},
        {"field": "likely_consequences", "items": [{"category": k, "consequence": CONSEQUENCES[k]} for k in cats]},
        {"field": "measures_taken", "items": nc.get("measures") or [todo]},
    ]
    return {"schema": "tripline.regulator-summary/v1", "case_id": case.case_id, "report_sha256": release.get("report_sha256"),
            "sections": sections,
            "note": "Laid out in the order of the Information Regulator's eServices security-compromise form. Counts come "
                    "from the released, signed scope report; the Information Officer completes the remaining fields."}


def regulator_pdf(summary: dict) -> bytes:
    secs = []
    for s in summary["sections"]:
        rows = [["Field", "Value"]]
        for k, v in s.items():
            if k == "field":
                continue
            if isinstance(v, list):
                v = "; ".join(x if isinstance(x, str) else f"{x.get('category')}: {x.get('consequence')}" for x in v)
            elif isinstance(v, dict):
                v = ", ".join(f"{CATEGORY_LABELS.get(a, a)} {b}" for a, b in v.items())
            rows.append([k.replace("_", " "), str(v)])
        secs.append(Section(s["field"].replace("_", " ").capitalize(), [], table=rows))
    return render(f"Security compromise update — {summary['case_id']}", [summary["note"]], secs,
                  footer=f"{summary['case_id']} regulator summary")
