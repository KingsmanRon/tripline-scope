"""``tscope drill``: a timed, full synthetic incident shaped like the hospital's mapped schema.

1. Shape: identity tables found in the readiness case's column mappings (``case.yaml`` overrides, discovery output
   or an applied profile) become the column layouts of the synthetic databases (column names and categories only).
2. Generate synthetic data with ground truth, open a throw-away incident case, register the synthetic databases and
   a leak sample, extract them, then run the real commands in order: ``estimate``, ``scope match``,
   ``scope decide --simulate-reviewer``, ``scope match``, ``scope report``, ``scope notify build`` and — when an
   approver signs in — ``release`` and ``scope notify export``.
3. Time every step, measure accuracy against the ground truth, and save a ``drill`` report draft in the readiness
   case. The throw-away case and its key are destroyed afterwards (synthetic data only).
"""

from __future__ import annotations

import copy
import datetime as dt
import json
import os
import secrets
import shutil
import tempfile
import time
from pathlib import Path

from tripline_scope import METHOD_VERSION, testing
from tripline_scope.core.case import Case
from tripline_scope.core.context import command
from tripline_scope.core.pdf import Section, render
from tripline_scope.core.reports import ReportStore
from tripline_scope.core.store import open_store
from tripline_scope.synth.schema import STYLES

CATEGORY_TO_FIELD = {
    "sa_id": "sa_id", "passport": "passport_no", "first_name": "first_name", "last_name": "last_name",
    "full_name": "full_name", "maiden_name": "maiden_name", "dob": "dob", "sex": "sex", "phone": "phone",
    "email": "email", "address": "address", "postal_code": "postal_code", "medical_aid_no": "medical_aid_no",
    "patient_key": "local_patient_key", "language": "language", "guardian_name": "guardian_name",
    "guardian_phone": "guardian_phone", "guardian_sa_id": "guardian_sa_id", "record_date": "record_date",
}


def hospital_styles(case, store) -> tuple[list[dict], list[dict]]:
    """Synthetic column layouts mirroring the identity tables of the hospital's column mappings."""
    from .profile import collect

    mappings = collect(case, store)["column_mappings"]
    styles, shape = [], []
    for src, tables in sorted(mappings.items()):
        for table, cols in sorted(tables.items()):
            fields = {}
            for col, cat in cols.items():
                f = CATEGORY_TO_FIELD.get(cat)
                if f and f not in fields:
                    fields[f] = col
            if len({"first_name", "last_name", "full_name", "dob", "sa_id"} & set(fields)) < 2:
                continue
            st = copy.deepcopy(STYLES["A"])
            st["patients"] = {"local_patient_key": fields.pop("local_patient_key", "patient_id"), **fields}
            if "full_name" in fields and not ({"first_name", "last_name"} & set(fields)):
                st["name_format"] = "full_name_comma"
            st["key_style"] = "A"
            styles.append(st)
            shape.append({"source": src, "table": table, "identity_columns": len(st["patients"])})
            if len(styles) == 10:
                return styles, shape
    return styles, shape


def run(args, home, case, ctx) -> dict:
    rows = int(args.rows)
    styles, shape = hospital_styles(case, ctx.store)
    work = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="tscope-drill-"))
    work.mkdir(parents=True, exist_ok=True)
    prefix = ["--home", str(home.root)] if getattr(args, "home", None) else []
    steps: list[dict] = []
    drill_case = None
    t_all = time.time()

    def step(name, fn):
        t0 = time.time()
        ok, note = True, None
        try:
            out = fn()
        except Exception as exc:  # noqa: BLE001 - recorded in the drill report, never with values
            ok, note, out = False, type(exc).__name__, None
        steps.append({"step": name, "seconds": round(time.time() - t0, 3), "ok": ok, **({"error": note} if note else {})})
        return out

    def cli(name, argv):
        def go():
            rc, out, err = testing.run_cli(prefix + argv)
            if rc != 0:
                raise RuntimeError(f"{name} exit {rc}")
            return out
        return step(name, go)

    try:
        from tripline_scope.synth.generate import generate

        ref = dt.date(2026, 9, 14)
        synth_dir = work / "synth"
        meta = step("synth", lambda: generate(synth_dir, rows, styles=styles or None, databases=max(1, len(styles)) if styles
                                             else 10, reference_date=ref))
        if meta is None:
            raise RuntimeError("synthetic generation failed")
        case_id = f"DRILL-{secrets.token_hex(4).upper()}"
        approvers = case.team().get("approvers") or []

        def open_drill():
            c = Case.init(work / "case", home, case_id=case_id, mode="incident",
                          incident_start=(ref - dt.timedelta(days=13)).isoformat() + "T00:00:00Z",
                          incident_end=ref.isoformat() + "T23:59:59Z", operators=[ctx.actor], reviewers=[ctx.actor],
                          approvers=approvers, title="synthetic drill")
            return c

        drill_case = step("open drill case", open_drill)

        def ingest():
            from tripline_scope.scope.fixtures import load_synth_as_extract, register_synth_sources

            with command("drill ingest (synthetic)", home=home, case=drill_case, role="operator", params={}) as c2:
                smap = register_synth_sources(drill_case, c2.store, synth_dir, actor=c2.actor)
                load_synth_as_extract(drill_case, c2.store, synth_dir, source_map=smap)
            return smap

        smap = step("register and extract", ingest)
        cdir = str(work / "case")
        cli("estimate", ["estimate", "--case", cdir])
        cli("match", ["scope", "match", "--case", cdir])
        cli("review (simulated)", ["scope", "decide", "--case", cdir, "--simulate-reviewer",
                                   str(synth_dir / "ground_truth.parquet")])
        cli("re-match with decisions", ["scope", "match", "--case", cdir])
        cli("report", ["scope", "report", "--case", cdir])
        cli("notify build", ["scope", "notify", "build", "--case", cdir])
        if args.approver and os.environ.get("TSCOPE_APPROVER_PASSWORD"):
            cli("release (approver)", ["release", "--case", cdir, "--kind", "scope", "--approver", args.approver])
            cli("notify export (approver)", ["scope", "notify", "export", "--case", cdir, "--out", str(work / "export"),
                                            "--approver", args.approver])
        else:
            steps.append({"step": "release and export", "seconds": 0.0, "ok": True,
                          "skipped": "no approver sign-in supplied (--approver with TSCOPE_APPROVER_PASSWORD)"})
        accuracy = step("accuracy against ground truth", lambda: _accuracy(drill_case, home, synth_dir, smap))
        counts = _counts(drill_case, home)
    finally:
        if drill_case is not None:
            try:
                wrapped = home.wrapped_dek_path(drill_case.case_id)
                if wrapped.exists():
                    wrapped.unlink()
            except OSError:
                pass
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    return {"rows": rows, "schema_shape": shape or [{"source": "default synthetic layout", "table": "patients",
                                                       "identity_columns": len(STYLES["A"]["patients"])}],
            "steps": steps, "total_seconds": round(time.time() - t_all, 3), "accuracy": accuracy, "counts": counts}


def _accuracy(drill_case, home, synth_dir: Path, smap) -> dict:
    from tripline_scope.scope import config as C
    from tripline_scope.scope import data as D
    from tripline_scope.scope import run as R
    from tripline_scope.scope.simulate import row_truth

    store = open_store(drill_case, home)
    data = D.load(drill_case, store, C.load(drill_case), include_dependent=False)
    con = data.con
    try:
        row_truth(con, synth_dir / "ground_truth.parquet")
        con.register("_pr", store.read_table(R.PERSON_ROWS))
        con.execute("CREATE TABLE pr AS SELECT * FROM _pr")
        con.execute("CREATE TABLE ev AS SELECT t.person_id, p.person_key FROM pr p JOIN truth t USING (row_key)")
        q = lambda sql: con.execute(sql).fetchone()[0]  # noqa: E731
        tp = q("SELECT coalesce(sum(n*(n-1)/2),0) FROM (SELECT count(*) n FROM ev GROUP BY person_id, person_key)")
        pred = q("SELECT coalesce(sum(n*(n-1)/2),0) FROM (SELECT count(*) n FROM ev GROUP BY person_key)")
        true = q("SELECT coalesce(sum(n*(n-1)/2),0) FROM (SELECT count(*) n FROM ev GROUP BY person_id)")
        tpeople = q("SELECT count(DISTINCT person_id) FROM ev")
        ppeople = q("SELECT count(DISTINCT person_key) FROM ev")
    finally:
        con.close()
    return {"pairwise_precision": round(float(tp) / float(pred), 6) if pred else 1.0,
            "pairwise_recall": round(float(tp) / float(true), 6) if true else 1.0,
            "true_people": int(tpeople), "predicted_people": int(ppeople),
            "person_count_error": round(abs(ppeople - tpeople) / tpeople, 6) if tpeople else 0.0}


def _counts(drill_case, home) -> dict:
    from tripline_scope.scope import run as R

    store = open_store(drill_case, home)
    if not store.exists(R.MATCH):
        return {}
    m = store.read_json(R.MATCH)
    return {"people": m["people"], "review_items_after_simulated_review": m["review_queue"]["items"],
            "deterministic_links": m["stats"].get("deterministic_links"), "auto_links": m["stats"].get("pairs_auto")}


def save_report(case, result: dict, hardware: dict) -> object:
    rs = ReportStore(case)
    body = rs.new_body("drill", report_status="drill", method_version=METHOD_VERSION, synthetic_rows=result["rows"],
                       schema_shape=result["schema_shape"], steps=result["steps"], total_seconds=result["total_seconds"],
                       accuracy=result["accuracy"], counts=result["counts"], hardware=hardware,
                       note="Synthetic drill: no patient data was used. Timings depend on the hardware recorded here.")
    rows = [["Step", "Seconds", "Result"]] + [[s["step"], f"{s['seconds']:.1f}",
                                              "skipped" if s.get("skipped") else ("ok" if s["ok"] else "FAILED")]
                                             for s in result["steps"]]
    acc = result["accuracy"] or {}
    pdf = render(f"Breach drill report — {case.case_id}", ["Synthetic incident run end to end; no patient data."], [
        Section("Summary", [f"{result['rows']:,} synthetic admission rows were scoped in {result['total_seconds']:.0f} "
                            "seconds.".replace(",", " "),
                            f"People found: {acc.get('predicted_people')} (truth {acc.get('true_people')}); pairwise "
                            f"precision {acc.get('pairwise_precision')}, recall {acc.get('pairwise_recall')}."]),
        Section("Timed steps", [], table=rows),
        Section("Hardware", [json.dumps(hardware, sort_keys=True)]),
    ], footer=f"{case.case_id} drill")
    return rs.save_draft("drill", body, pdf=pdf)


def hardware() -> dict:
    mem = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                mem = round(int(line.split()[1]) / 1024 / 1024, 1)
    except OSError:
        pass
    return {"cpus": os.cpu_count(), "memory_gb": mem}
