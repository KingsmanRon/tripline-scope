"""Rows to people: deterministic links, Fellegi–Sunter scoring in Splink, guards, bands, review and clustering.

Steps (all inside one in-memory DuckDB session, see :mod:`tripline_scope.scope.data`):

1. **Records.** Usable identity rows become match records. Rows that are identical in every matching field
   *and* carry a valid SA ID consistent with their date of birth are collapsed into one record (they would be
   linked deterministically anyway); every other row is its own record.
2. **Deterministic links.** Records with the same valid SA ID whose date of birth is consistent with the ID's
   embedded date (or absent) are linked.
3. **Probabilistic links.** Splink (DuckDB backend, in memory, table materialisation) scores record pairs found by
   the blocking rules; u-probabilities by deterministic random sampling, m-probabilities by expectation
   maximisation on the date-of-birth and ID blocks, the prior from the ID rule. Training runs single-threaded and
   parameters are rounded so identical inputs give identical models.
4. **Guards** (rules that override the score, recorded per pair): contradictory first names, two different valid
   ID numbers or a recorded guardian relationship → non-link; contradictory dates of birth → at most review.
5. **Bands.** auto-link ≥ ``bands.auto_link``; review between ``bands.review`` and auto-link; non-link below.
6. **Review decisions** are keyed by an HMAC of the record-key pair and replayed on every run: "same" adds a link,
   "different" removes one (and is enforced as a cannot-link constraint on clusters).
7. **Clustering.** Connected components over deterministic, auto and accepted links. The over-merge guard flags a
   cluster holding more than one valid SA ID, contradictory dates of birth, more than ``max_records`` records or a
   cannot-link pair: it is split conservatively (only deterministic and reviewed links kept) and its probabilistic
   links are queued for review.
"""

from __future__ import annotations

import logging
import time

from .data import ScopeData

log = logging.getLogger(__name__)

PAIR_PURPOSE = "review-pair"


def _quiet_splink():
    for name in ("splink", "splink.internals"):
        lg = logging.getLogger(name)
        lg.setLevel(logging.ERROR)
        lg.propagate = False


class Matcher:
    def __init__(self, data: ScopeData, cfg: dict, *, pair_key, decisions: dict[str, dict] | None = None,
                 threads: int | None = None):
        self.d = data
        self.con = data.con
        self.cfg = cfg
        self.pair_key = pair_key
        self.decisions = decisions or {}
        self.threads = threads
        self.timings: dict[str, float] = {}
        self.model: dict = {}
        self.stats: dict = {}

    def _t(self, name: str, t0: float) -> None:
        self.timings[name] = round(time.time() - t0, 3)

    # ------------------------------------------------------------------------------------------ records
    def build_records(self) -> None:
        t0 = time.time()
        con = self.con
        maxb = int(self.cfg["blocking"]["max_block_size"])
        con.execute("""
        CREATE OR REPLACE TABLE rec_rows AS
        SELECT row_id, CASE WHEN sa_id IS NOT NULL AND dob_consistent THEN
               min(row_id) OVER (PARTITION BY first, middle, last, maiden, sa_id, passport, dob_eff, sex, phone,
                                 phone_alt, email, postal, med, guardian_sa_id) ELSE row_id END AS rid
        FROM ident WHERE usable ORDER BY row_id""")
        con.execute(f"""
        CREATE OR REPLACE TABLE recs AS
        WITH r AS (
          SELECT i.row_id AS rid, i.row_key, i.first, i.first_c, i.middle, i.last, i.maiden, i.sa_id, i.passport,
                 i.dob_eff, i.dob_chk, i.dob_consistent, i.sex, i.phone, i.phone_alt, i.email, i.postal, i.med, i.guardian_sa_id,
                 i.sx_first, i.sx_last, i.sx_maiden,
                 least(i.sx_first, i.sx_last) || greatest(i.sx_first, i.sx_last) AS sx_pair,
                 year(i.dob_eff) AS birth_year, strftime(i.dob_eff, '%m%d') AS birthday
          FROM ident i JOIN (SELECT DISTINCT rid FROM rec_rows) k ON k.rid = i.row_id)
        SELECT r.*,
          CASE WHEN count(*) OVER (PARTITION BY phone) <= {maxb} THEN phone END AS phone_blk,
          CASE WHEN count(*) OVER (PARTITION BY email) <= {maxb} THEN email END AS email_blk
        FROM r ORDER BY rid""")
        self.stats["records"] = con.execute("SELECT count(*) FROM recs").fetchone()[0]
        self.stats["usable_rows"] = con.execute("SELECT count(*) FROM rec_rows").fetchone()[0]
        self._t("records", t0)

    # ------------------------------------------------------------------------------------------ deterministic
    def deterministic(self) -> None:
        t0 = time.time()
        self.con.execute("""
        CREATE OR REPLACE TABLE det_edges AS
        SELECT rid AS a, min(rid) OVER (PARTITION BY sa_id) AS b FROM recs
        WHERE sa_id IS NOT NULL AND dob_consistent
        QUALIFY a <> b ORDER BY a""")
        self.stats["deterministic_links"] = self.con.execute("SELECT count(*) FROM det_edges").fetchone()[0]
        self._t("deterministic", t0)

    # ------------------------------------------------------------------------------------------ splink
    def _settings(self):
        import splink.comparison_level_library as cll
        import splink.comparison_library as cl
        from splink import SettingsCreator, block_on

        hi = float(self.cfg["comparisons"]["jw_high"])
        lo = float(self.cfg["comparisons"]["jw_low"])
        tf = set(self.cfg["comparisons"].get("term_frequency") or [])

        def null_any(*cols):
            cond = " OR ".join(f"({c}_l IS NULL AND {c}_r IS NULL)" for c in cols)
            lvl = cll.CustomLevel(f"({' AND '.join(c + '_l IS NULL' for c in cols)}) OR "
                                  f"({' AND '.join(c + '_r IS NULL' for c in cols)})", label_for_charts="null")
            lvl.configure(is_null_level=True)
            del cond
            return lvl

        swapped = swapped_sql("first_l", "last_l", "first_r", "last_r", lo, hi)
        comparisons = [
            cl.CustomComparison(output_column_name="sa_id", comparison_levels=[
                cll.NullLevel("sa_id"), cll.ExactMatchLevel("sa_id"), cll.ElseLevel()]),
            cl.CustomComparison(output_column_name="passport", comparison_levels=[
                cll.NullLevel("passport"), cll.ExactMatchLevel("passport"), cll.ElseLevel()]),
            cl.CustomComparison(output_column_name="first", comparison_levels=[
                cll.NullLevel("first"),
                cll.ExactMatchLevel("first_c", term_frequency_adjustments="first" in tf),
                cll.CustomLevel(swapped, label_for_charts="first name and surname swapped"),
                cll.CustomLevel("list_contains(string_split(coalesce(middle_r, ''), ' '), first_l) OR "
                                "list_contains(string_split(coalesce(middle_l, ''), ' '), first_r)",
                                label_for_charts="first name is the other's middle name"),
                cll.JaroWinklerLevel("first", hi),
                cll.JaroWinklerLevel("first", lo),
                cll.CustomLevel("(length(first_l) = 1 OR length(first_r) = 1) AND left(first_l, 1) = left(first_r, 1)",
                                label_for_charts="initial matches"),
                cll.ElseLevel()]),
            cl.CustomComparison(output_column_name="last", comparison_levels=[
                cll.NullLevel("last"),
                cll.ExactMatchLevel("last", term_frequency_adjustments="last" in tf),
                cll.CustomLevel(swapped, label_for_charts="first name and surname swapped"),
                cll.CustomLevel("last_l = maiden_r OR maiden_l = last_r OR maiden_l = maiden_r",
                                label_for_charts="surname matches a maiden or married surname"),
                cll.JaroWinklerLevel("last", hi),
                cll.JaroWinklerLevel("last", lo),
                cll.ElseLevel()]),
            cl.CustomComparison(output_column_name="dob", comparison_levels=[
                cll.NullLevel("dob_eff"),
                cll.ExactMatchLevel("dob_eff"),
                cll.CustomLevel("tscope_dob_slip(dob_eff_l, dob_eff_r)",
                                label_for_charts="slip: one character, one day, day/month swap or one year"),
                cll.CustomLevel("year(dob_eff_l) = year(dob_eff_r)", label_for_charts="same year"),
                cll.ElseLevel()]),
            cl.CustomComparison(output_column_name="sex", comparison_levels=[
                cll.NullLevel("sex"), cll.ExactMatchLevel("sex"), cll.ElseLevel()]),
            cl.CustomComparison(output_column_name="phone", comparison_levels=[
                null_any("phone", "phone_alt"),
                cll.ExactMatchLevel("phone", term_frequency_adjustments="phone" in tf),
                cll.CustomLevel("phone_l = phone_alt_r OR phone_alt_l = phone_r OR phone_alt_l = phone_alt_r",
                                label_for_charts="alternative number matches"),
                cll.ElseLevel()]),
            cl.CustomComparison(output_column_name="email", comparison_levels=[
                cll.NullLevel("email"), cll.ExactMatchLevel("email"), cll.ElseLevel()]),
            cl.CustomComparison(output_column_name="med", comparison_levels=[
                cll.NullLevel("med"), cll.ExactMatchLevel("med"), cll.ElseLevel()]),
            cl.CustomComparison(output_column_name="postal", comparison_levels=[
                cll.NullLevel("postal"), cll.ExactMatchLevel("postal"), cll.ElseLevel()]),
        ]
        rules_map = {
            "sa_id": [block_on("sa_id")],
            "passport": [block_on("passport")],
            "soundex_last_dob": [block_on("sx_last", "dob_eff")],
            "soundex_names_sorted_dob": [block_on("sx_pair", "dob_eff")],
            "maiden_dob": ["l.sx_maiden = r.sx_last AND l.dob_eff = r.dob_eff",
                           "l.sx_last = r.sx_maiden AND l.dob_eff = r.dob_eff"],
            "phone": [block_on("phone_blk")],
            "email": [block_on("email_blk")],
            "soundex_names_birth_year": [block_on("sx_pair", "birth_year")],
            "soundex_first_dob": [block_on("sx_first", "dob_eff")],
            "soundex_names_birthday": [block_on("sx_pair", "birthday")],
        }
        rules = []
        for r in self.cfg["blocking"]["rules"]:
            rules += rules_map[r]
        if "passport" not in self.cfg["blocking"]["rules"]:
            rules += rules_map["passport"]
        return SettingsCreator(
            link_type="dedupe_only", unique_id_column_name="rid", comparisons=comparisons,
            blocking_rules_to_generate_predictions=rules, retain_matching_columns=False,
            retain_intermediate_calculation_columns=False, additional_columns_to_retain=[],
            em_convergence=0.0001, max_iterations=int(self.cfg["training"]["em_max_iterations"]),
        )

    def _set_threads(self, n: int | None) -> None:
        if n:
            self.con.execute(f"SET threads = {int(n)}")
        else:
            self.con.execute("RESET threads")

    def score(self) -> None:
        """Train the model (deterministically) and score blocked pairs above the review threshold."""
        from splink import DuckDBAPI, Linker, block_on

        _quiet_splink()
        t0 = time.time()
        tr = self.cfg["training"]
        db = DuckDBAPI(connection=self.con, materialisation="table")
        sdf = db.register("recs")
        settings = self._settings()
        n = self.stats["records"]
        self._set_threads(1)
        linker = Linker(sdf, settings, log_level=None)
        if n < 2:
            self.con.execute("CREATE OR REPLACE TABLE pred(rid_l BIGINT, rid_r BIGINT, match_weight DOUBLE, "
                             "match_probability DOUBLE)")
            self._set_threads(self.threads)
            self._t("training", t0)
            self._t("scoring", time.time())
            return
        linker.training.estimate_u_using_random_sampling(max_pairs=float(tr["u_max_pairs"]), seed=int(tr["u_seed"]))
        try:
            linker.training.estimate_probability_two_random_records_match([block_on("sa_id")],
                                                                          recall=float(tr["prior_recall"]))
        except Exception:  # noqa: BLE001 - too few ID links (tiny data): fall back to a conservative prior
            linker._settings_obj._probability_two_random_records_match = 1.0 / max(n * 10, 100)
        em_pairs = float(tr.get("em_max_pairs", 2_000_000))
        for br in (block_on("dob_eff"), block_on("sa_id")):
            try:
                linker.training.estimate_parameters_using_expectation_maximisation(
                    br, estimate_without_term_frequencies=True, max_pairs=em_pairs)
            except Exception as exc:  # noqa: BLE001 - e.g. no pairs in a block on tiny data
                log.warning("EM session skipped (%s)", type(exc).__name__)
        model = linker.misc.save_model_to_json()
        model = _round_model(model, int(tr["parameter_digits"]))
        self.model = model
        self._t("training", t0)
        t1 = time.time()
        self._set_threads(self.threads)
        db2 = DuckDBAPI(connection=self.con, materialisation="table")
        linker2 = Linker(db2.register("recs"), model, log_level=None)
        thr = float(self.cfg["bands"]["review"])
        pred = linker2.inference.predict(threshold_match_probability=thr)
        self.con.execute(f"""CREATE OR REPLACE TABLE pred AS
            SELECT least(rid_l, rid_r) AS rid_l, greatest(rid_l, rid_r) AS rid_r, match_weight, match_probability
            FROM {pred.physical_name} ORDER BY rid_l, rid_r""")
        for t in [r[0] for r in self.con.execute("SHOW TABLES").fetchall() if r[0].startswith("__splink")]:
            self.con.execute(f'DROP TABLE IF EXISTS "{t}"')
        self.con.execute("DROP VIEW IF EXISTS recs_view")
        self.stats["scored_pairs_above_review"] = self.con.execute("SELECT count(*) FROM pred").fetchone()[0]
        self._t("scoring", t1)

    # ------------------------------------------------------------------------------------------ guards, bands
    def classify(self) -> None:
        t0 = time.time()
        g = self.cfg["guards"]
        b = self.cfg["bands"]
        lo = float(self.cfg["comparisons"]["jw_low"])
        hi = float(self.cfg["comparisons"]["jw_high"])
        con = self.con
        con.execute(f"""
        CREATE OR REPLACE TABLE pairs AS
        SELECT p.rid_l, p.rid_r, p.match_probability, l.row_key AS key_l, r.row_key AS key_r,
          (l.sa_id IS NOT NULL AND r.sa_id IS NOT NULL AND l.sa_id <> r.sa_id) AS g_sa,
          (l.first IS NOT NULL AND r.first IS NOT NULL AND NOT ({first_compatible_sql("l", "r", lo, hi)})) AS g_first,
          (l.dob_chk IS NOT NULL AND r.dob_chk IS NOT NULL AND NOT tscope_dob_slip(l.dob_chk, r.dob_chk)
            AND NOT coalesce(l.sa_id = r.sa_id, false)) AS g_dob_any,
          (l.guardian_sa_id IS NOT NULL AND l.guardian_sa_id = r.sa_id)
            OR (r.guardian_sa_id IS NOT NULL AND r.guardian_sa_id = l.sa_id) AS g_guardian,
          abs(year(l.dob_chk) - year(r.dob_chk)) >= 2 AS years_apart
        FROM pred p JOIN recs l ON l.rid = p.rid_l JOIN recs r ON r.rid = p.rid_r""")
        con.execute("""CREATE OR REPLACE TABLE pairs AS SELECT * EXCLUDE (g_dob_any, years_apart),
                       coalesce(g_dob_any AND NOT coalesce(years_apart, false), false) AS g_dob,
                       coalesce(g_dob_any AND coalesce(years_apart, false), false) AS g_dob_years
                       FROM pairs""")

        def act(name, col):
            v = g.get(name, "off")
            return v, col

        guards = [act("first_name_contradiction", "g_first"), act("different_valid_sa_id", "g_sa"),
                  act("guardian_relationship", "g_guardian"), act("dob_contradiction", "g_dob"),
                  act("dob_years_apart", "g_dob_years")]
        non_link = [c for v, c in guards if v == "non_link"]
        to_review = [c for v, c in guards if v == "review"]
        nl = " OR ".join(non_link) or "FALSE"
        rv = " OR ".join(to_review) or "FALSE"
        con.execute(f"""
        CREATE OR REPLACE TABLE pairs2 AS
        SELECT *,
          CASE WHEN {nl} THEN 'non_link'
               WHEN match_probability >= {float(b['auto_link'])} AND NOT ({rv}) THEN 'auto'
               WHEN match_probability >= {float(b['review'])} THEN 'review'
               ELSE 'non_link' END AS band,
          CASE WHEN {nl} OR ({rv}) THEN
            array_to_string(list_filter(['first_name_contradiction', 'different_valid_sa_id', 'guardian_relationship',
                                         'dob_contradiction', 'dob_years_apart'],
                                        (x, i) -> [g_first, g_sa, g_guardian, g_dob, g_dob_years][i]), ',')
          END AS guard
        FROM pairs ORDER BY rid_l, rid_r""")
        con.execute("DROP TABLE pairs")
        con.execute("ALTER TABLE pairs2 RENAME TO pairs")
        # replay review decisions (identified by an HMAC of the record-key pair; matched on the key pair)
        self._load_decisions()
        con.execute("""
        CREATE OR REPLACE TABLE pairs_final AS
        SELECT p.*, d.pair_key, d.decision FROM pairs p
        LEFT JOIN decisions d ON d.key_a = least(p.key_l, p.key_r) AND d.key_b = greatest(p.key_l, p.key_r)
        ORDER BY p.rid_l, p.rid_r""")
        s = dict(con.execute("SELECT band, count(*) FROM pairs_final GROUP BY band").fetchall())
        self.stats["pairs_auto"] = int(s.get("auto", 0))
        self.stats["pairs_review"] = int(s.get("review", 0))
        self.stats["pairs_guarded_non_link"] = con.execute(
            "SELECT count(*) FROM pairs_final WHERE band = 'non_link' AND guard IS NOT NULL").fetchone()[0]
        self._t("classify", t0)

    def _load_decisions(self) -> None:
        import pyarrow as pa

        rows = {"key_a": [], "key_b": [], "pair_key": [], "decision": []}
        for pk, d in sorted(self.decisions.items()):
            if d.get("decision") not in ("same", "different"):
                continue
            a, b = sorted((d["key_l"], d["key_r"]))
            rows["key_a"].append(a)
            rows["key_b"].append(b)
            rows["pair_key"].append(pk)
            rows["decision"].append(d["decision"])
        tb = pa.table(rows, schema=pa.schema([(k, pa.string()) for k in rows]))
        self.con.register("_dec", tb)
        self.con.execute("CREATE OR REPLACE TABLE decisions AS SELECT * FROM _dec")
        self.con.unregister("_dec")

    # ------------------------------------------------------------------------------------------ clustering
    def _components(self, edges_sql: str, out: str) -> None:
        """Connected components by min-label propagation with pointer jumping."""
        con = self.con
        con.execute(f"CREATE OR REPLACE TEMP TABLE _e AS SELECT a, b FROM ({edges_sql}) UNION SELECT b, a FROM ({edges_sql})")
        con.execute("CREATE OR REPLACE TEMP TABLE _cc AS SELECT rid AS node, rid AS comp FROM recs")
        for _ in range(200):
            con.execute("""
            CREATE OR REPLACE TEMP TABLE _cc2 AS
            WITH m AS (SELECT e.a AS node, min(c.comp) AS nb FROM _e e JOIN _cc c ON c.node = e.b GROUP BY e.a)
            SELECT c.node, least(c.comp, coalesce(m.nb, c.comp)) AS comp FROM _cc c LEFT JOIN m USING (node)""")
            con.execute("""
            CREATE OR REPLACE TEMP TABLE _cc3 AS
            SELECT c.node, least(c.comp, p.comp) AS comp FROM _cc2 c JOIN _cc2 p ON p.node = c.comp""")
            changed = con.execute("SELECT count(*) FROM _cc3 n JOIN _cc o USING (node) WHERE n.comp <> o.comp").fetchone()[0]
            con.execute("DROP TABLE _cc")
            con.execute("ALTER TABLE _cc3 RENAME TO _cc")
            if changed == 0:
                break
        else:  # pragma: no cover - would need a chain longer than 2^200
            raise RuntimeError("connected components did not converge")
        con.execute(f"CREATE OR REPLACE TABLE {out} AS SELECT node AS rid, comp FROM _cc ORDER BY node")
        con.execute("DROP TABLE IF EXISTS _cc2")
        con.execute("DROP TABLE IF EXISTS _e")

    def cluster(self) -> None:
        t0 = time.time()
        con = self.con
        om = self.cfg["over_merge"]
        accepted = """SELECT rid_l AS a, rid_r AS b FROM pairs_final
                      WHERE (band = 'auto' AND coalesce(decision, '') <> 'different') OR decision = 'same'"""
        con.execute(f"""CREATE OR REPLACE TABLE edges AS
            SELECT a, b, 'deterministic' AS kind FROM det_edges
            UNION ALL SELECT rid_l, rid_r, CASE WHEN decision = 'same' THEN 'reviewed' ELSE 'auto' END FROM ({
            accepted.replace('SELECT rid_l AS a, rid_r AS b', 'SELECT rid_l, rid_r, decision')})""")
        self._components("SELECT a, b FROM edges", "comp1")
        # over-merge guard
        con.execute("""
        CREATE OR REPLACE TABLE comp_flags AS
        WITH c AS (SELECT c.comp, r.* FROM comp1 c JOIN recs r USING (rid)),
        dobs AS (SELECT DISTINCT comp, dob_chk FROM c WHERE dob_chk IS NOT NULL),
        contra AS (
          SELECT DISTINCT x.comp FROM dobs x JOIN dobs y ON x.comp = y.comp AND x.dob_chk < y.dob_chk
          WHERE NOT tscope_dob_slip(x.dob_chk, y.dob_chk)),
        diff AS (
          SELECT DISTINCT a.comp FROM pairs_final p JOIN comp1 a ON a.rid = p.rid_l JOIN comp1 b ON b.rid = p.rid_r
          WHERE p.decision = 'different' AND a.comp = b.comp)
        SELECT c.comp, count(*) AS n_recs, count(DISTINCT sa_id) AS n_ids,
          c.comp IN (SELECT comp FROM contra) AS dob_contra, c.comp IN (SELECT comp FROM diff) AS cannot_link
        FROM c GROUP BY c.comp""")
        cond = [f"n_recs > {int(om['max_records'])}", f"n_ids > {int(om['max_distinct_sa_id'])}", "cannot_link"]
        if om.get("contradictory_dob", True):
            cond.append("dob_contra")
        con.execute(f"""CREATE OR REPLACE TABLE flagged AS SELECT comp FROM comp_flags WHERE {' OR '.join(cond)}""")
        # probabilistic links inside flagged clusters: queued for review unless already decided
        con.execute("""
        CREATE OR REPLACE TABLE cluster_review AS
        SELECT p.rid_l, p.rid_r, p.key_l, p.key_r, p.match_probability, a.comp
        FROM pairs_final p JOIN comp1 a ON a.rid = p.rid_l JOIN comp1 b ON b.rid = p.rid_r
        WHERE a.comp = b.comp AND a.comp IN (SELECT comp FROM flagged) AND p.band = 'auto' AND p.decision IS NULL
        ORDER BY p.rid_l, p.rid_r""")
        con.execute("""CREATE OR REPLACE TABLE edges_final AS
            SELECT e.* FROM edges e JOIN comp1 c ON c.rid = e.a
            WHERE NOT (e.kind = 'auto' AND c.comp IN (SELECT comp FROM flagged))""")
        self._components("SELECT a, b FROM edges_final", "comp")
        self.stats["over_merge_flagged_clusters"] = con.execute("SELECT count(*) FROM flagged").fetchone()[0]
        self.stats["cluster_review_pairs"] = con.execute("SELECT count(*) FROM cluster_review").fetchone()[0]
        self._t("cluster", t0)

    # ------------------------------------------------------------------------------------------ review queue
    def review_queue(self) -> list[dict]:
        rows = self.con.execute("""
        SELECT key_l, key_r, match_probability, 'review_band' AS reason, guard FROM pairs_final
        WHERE band = 'review' AND decision IS NULL
        UNION ALL
        SELECT c.key_l, c.key_r, c.match_probability, 'over_merge_guard', NULL FROM cluster_review c
        ORDER BY 1, 2""").fetchall()
        out = []
        for kl, kr, p, reason, guard in rows:
            out.append({"pair_key": self.pair_key(kl, kr), "key_l": kl, "key_r": kr,
                        "match_probability": round(float(p), 6), "reason": reason, "guard": guard})
        return out

    def run(self) -> None:
        self.build_records()
        self.deterministic()
        self.score()
        self.classify()
        self.cluster()


def swapped_sql(fl: str, ll: str, fr: str, lr: str, lo: float, hi: float) -> str:
    """First name and surname recorded the other way round (each side similar, at least one closely)."""
    a = f"jaro_winkler_similarity({fl}, {lr})"
    b = f"jaro_winkler_similarity({ll}, {fr})"
    return f"({a} >= {lo} AND {b} >= {lo} AND ({a} >= {hi} OR {b} >= {hi}))"


def first_compatible_sql(l: str, r: str, lo: float, hi: float) -> str:  # noqa: E741
    """First names that do not contradict: equal or variant, similar (Jaro-Winkler or one edit), swapped with the
    surname, one is the other's middle name, or one is an initial of the other."""
    return (f"{l}.first_c = {r}.first_c OR jaro_winkler_similarity({l}.first, {r}.first) >= {lo} "
            f"OR damerau_levenshtein({l}.first, {r}.first) <= 1 "
            f"OR {swapped_sql(l + '.first', l + '.last', r + '.first', r + '.last', lo, hi)} "
            f"OR list_contains(string_split(coalesce({r}.middle, ''), ' '), {l}.first) "
            f"OR list_contains(string_split(coalesce({l}.middle, ''), ' '), {r}.first) "
            f"OR ((length({l}.first) = 1 OR length({r}.first) = 1) AND left({l}.first, 1) = left({r}.first, 1))")


def _round_model(model: dict, digits: int) -> dict:
    def sig(x):
        if isinstance(x, float) and x != 0.0:
            return float(f"{x:.{digits}g}")
        return x

    def walk(o):
        if isinstance(o, dict):
            return {k: walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return sig(o)

    out = walk(model)
    out.pop("linker_uid", None)
    return out


def make_pair_key(fingerprinter):
    def pair_key(a: str, b: str) -> str:
        x, y = (a, b) if a <= b else (b, a)
        return fingerprinter(x + "\x1f" + y, 32)

    return pair_key
