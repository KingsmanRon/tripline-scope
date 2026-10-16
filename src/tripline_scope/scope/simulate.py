"""Simulated reviewer for drills and demos: decides pending review items from synthetic ground truth.

Never for real cases: decisions are recorded with ``simulated: true`` and every report built on them says so.

Ground truth rows ``(source_db, table, local_patient_key) → person_id`` are mapped onto extracted identity rows:
the database name matches case-insensitively, or by its trailing number (``db01`` ↔ ``LabDB01``); the table
matches on its last dotted component (``patients`` ↔ ``dbo.patients``); leak-sample rows match the source whose
evidence role is ``leak_sample`` by 1-based row number.
"""

from __future__ import annotations

import re
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from . import data as D
from . import decisions as DEC


def _db_token(name: str | None) -> str:
    s = (name or "").strip().lower()
    m = re.search(r"(\d+)$", s)
    return m.group(1).lstrip("0") or "0" if m else s


def row_truth(con, gt_path: Path) -> None:
    """Create ``truth(row_key, person_id)`` for identity rows in the session."""
    gt = pq.read_table(gt_path, columns=["source_db", "table", "local_patient_key", "person_id"])
    con.register("_gt", gt)
    con.execute("CREATE OR REPLACE TABLE gt AS SELECT * FROM _gt")
    con.unregister("_gt")
    tables = con.execute('SELECT t_idx, database, "table", evidence_role FROM src_tables WHERE role = \'identity\'').fetchall()
    rows = {"t_idx": [], "db_tok": [], "tbl": [], "leak": []}
    for t_idx, db, tb, role in tables:
        rows["t_idx"].append(int(t_idx))
        rows["db_tok"].append(_db_token(db))
        rows["tbl"].append((tb or "").lower().split(".")[-1])
        rows["leak"].append(role == "leak_sample")
    con.register("_tm", pa.table(rows))
    con.execute("CREATE OR REPLACE TABLE tmap AS SELECT * FROM _tm")
    con.unregister("_tm")
    gtdbs = {r[0]: _db_token(r[0]) for r in con.execute("SELECT DISTINCT source_db FROM gt").fetchall()}
    con.register("_gd", pa.table({"source_db": list(gtdbs), "db_tok": list(gtdbs.values())}))
    con.execute("CREATE OR REPLACE TABLE gdb AS SELECT * FROM _gd")
    con.unregister("_gd")
    # Two equi-joins (an OR inside one join condition degenerates into a nested-loop join on large estates).
    con.execute("""
    CREATE OR REPLACE TABLE truth AS
    SELECT row_key, any_value(person_id) AS person_id FROM (
      SELECT i.row_key, g.person_id
      FROM ident i JOIN tmap m ON m.t_idx = i.t_idx AND m.leak
      JOIN gt g ON g."table" = 'leak_sample' AND g.local_patient_key = (i.ordinal + 1)::VARCHAR
      UNION ALL
      SELECT i.row_key, g.person_id
      FROM ident i JOIN tmap m ON m.t_idx = i.t_idx AND NOT m.leak
      JOIN gdb d ON d.db_tok = m.db_tok
      JOIN gt g ON g.source_db = d.source_db AND g."table" = m.tbl AND g.local_patient_key = i.local_key)
    GROUP BY row_key""")


def simulate_decisions(case, store, cfg: dict, items: list[dict], gt_path: Path, reviewer: str) -> list[dict]:
    if not items:
        return []
    data = D.load(case, store, cfg, include_dependent=False)
    con = data.con
    try:
        row_truth(con, gt_path)
        keys = sorted({q["key_l"] for q in items} | {q["key_r"] for q in items})
        con.register("_k", pa.table({"row_key": keys}))
        truth = dict(con.execute("SELECT t.row_key, t.person_id FROM truth t JOIN _k USING (row_key)").fetchall())
        con.unregister("_k")
    finally:
        con.close()
    out = []
    for q in items:
        a, b = truth.get(q["key_l"]), truth.get(q["key_r"])
        decision = "skip" if a is None or b is None else ("same" if a == b else "different")
        out.append(DEC.entry(q, decision, reviewer, "simulated", simulated=True))
    return out
