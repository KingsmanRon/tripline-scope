"""The sliced estimate (bounded memory) gives exactly the full-load estimate, however finely it is sliced."""

from conftest import c, cli
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.store import open_store
from tripline_scope.scope import config, data, estimate

# The estimate as first written: string keys over the fully loaded data (reference for the hashed, sliced form).
REFERENCE_SQL = """
WITH r AS (
  SELECT i.sa_id,
    CASE WHEN i.sa_id IS NOT NULL THEN NULL
         WHEN i.passport IS NOT NULL THEN 'P:' || i.passport
         ELSE 'N:' || coalesce(least(i.sx_first, i.sx_last), '') || '|' || coalesce(greatest(i.sx_first, i.sx_last), '')
              || '|' || coalesce(strftime(i.dob_eff, '%Y%m%d'), '') END AS k_point,
    'N:' || coalesce(least(i.sx_first, i.sx_last), '') || '|' || coalesce(greatest(i.sx_first, i.sx_last), '')
         || '|' || coalesce(strftime(i.dob_eff, '%Y%m%d'), '') AS k_name,
    coalesce('P:' || i.passport, 'F:' || coalesce(i.first, '') || '|' || coalesce(i.last, '') || '|'
         || coalesce(strftime(i.dob_eff, '%Y%m%d'), '')) AS k_fine
  FROM ident i WHERE i.usable)
SELECT count(DISTINCT sa_id)
       + count(DISTINCT k_point) FILTER (WHERE sa_id IS NULL
                                        AND k_point NOT IN (SELECT k_name FROM r WHERE sa_id IS NOT NULL)),
       count(DISTINCT sa_id) + count(DISTINCT k_fine) FILTER (WHERE sa_id IS NULL)
FROM r"""


def test_sliced_estimate_equals_full_load(scoped):
    case_dir, _ = scoped
    case = Case(case_dir)
    store = open_store(case, Home())
    cfg = config.load(case)
    full = data.load(case, store, cfg)
    ref_point, ref_upper = full.con.execute(REFERENCE_SQL).fetchone()
    want = estimate.estimate(full, cfg)
    full.con.close()
    assert (want["point"], want["upper"]) == (ref_point, ref_upper)
    assert want["point"] > 0 and want["per_category"]
    for rows_per_pass in (10**9, 500, 97):
        got = estimate.estimate_sliced(case, store, cfg | {"estimate": cfg["estimate"] | {"rows_per_pass": rows_per_pass}})
        assert got["estimate"] == want, rows_per_pass
        if rows_per_pass == 10**9:
            assert got["slices"] == len(got["sources"])
    assert got["slices"] > len(got["sources"])  # the finest run really split sources by patient key


def test_estimate_command_reports_slices(scoped):
    case_dir, _ = scoped
    rc, out, err = cli(["estimate"] + c(case_dir), "olivia")
    assert out["lower"] <= out["people_estimate"] <= out["upper"]
    case = Case(case_dir)
    est = open_store(case, Home()).read_json("work/scope/estimate.json")
    assert est["slices"] >= len(est["extract_manifests_sha256"])
    assert est["unresolvable"]["identity_rows_without_identifiers"] >= 0
