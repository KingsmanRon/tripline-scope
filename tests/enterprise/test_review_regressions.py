"""Regression tests for the PR review of the enterprise profile:

* P0 — a ``direct`` identity link is only made after validating the records joined on the shared identifier
  (same account, not failed, plausible time, unambiguous); otherwise the link is ``unresolved`` with the conflict.
* P0 — the financial analysis only runs over the exact Module B event set the released paths report was signed
  over; a re-ingest or new source after the paths release is refused until paths is re-run and re-released.
(The two P1 items — ledger postings vs settlements, session-specific privilege links — are in test_transactions.)
"""

import datetime as dt
import json
import shutil

import pytest
import yaml

from conftest import WINDOW, build, cli, clone, report
from tripline_scope.enterprise.financial import ID_JOIN_SKEW_S, _validate_id_join
from tripline_scope.paths.util import acct_key

T0 = dt.datetime(2026, 9, 5, 22, 0, tzinfo=dt.UTC)
K = lambda a: acct_key(a, ["utility.example"])  # noqa: E731
ACCT = K("vendor01@utility.example")


def si(n, *, account="vendor01@utility.example", outcome="success", minutes_before=2, mfa="false",
       ip="203.0.113.77", corr="C-1"):
    return {"event_id": f"SRC-IDP:{n}", "account": account, "outcome": outcome, "mfa": mfa, "remote_ip": ip,
            "correlation_id": corr, "request_id": f"R-{n}", "ts_utc": T0 - dt.timedelta(minutes=minutes_before),
            "ordinal": n}


def join(cands):
    return _validate_id_join(cands, ACCT, T0, K, window_s=3600, agree=("mfa", "remote_ip"), what="sign-in")


# ------------------------------------------------------------------------------------------- P0: direct links
def test_valid_single_join_is_direct():
    rec, label, reason, conflicts = join([si(1)])
    assert label == "direct" and rec["event_id"] == "SRC-IDP:1" and conflicts == []


def test_same_correlation_id_on_a_different_account_is_not_direct():
    rec, label, reason, conflicts = join([si(1), si(2, account="clerk01@utility.example", mfa="true", ip="10.60.5.41")])
    assert rec is None and label == "unresolved" and "different account" in reason
    assert any("names a different account" in c["problems"] for c in conflicts)
    # also when the only record carrying the id belongs to someone else
    rec, label, _, conflicts = join([si(2, account="clerk01@utility.example")])
    assert rec is None and label == "unresolved" and conflicts[0]["event"] == "SRC-IDP:2"


def test_failed_signin_is_not_a_direct_link():
    rec, label, reason, conflicts = join([si(1, outcome="failure")])
    assert rec is None and label == "unresolved" and conflicts[0]["problems"] == ["outcome failure"]


def test_failed_then_successful_retry_of_same_account_is_direct_with_the_failure_listed():
    rec, label, reason, conflicts = join([si(1, outcome="failure", minutes_before=3), si(2, minutes_before=2)])
    assert label == "direct" and rec["event_id"] == "SRC-IDP:2"
    assert [c["event"] for c in conflicts] == ["SRC-IDP:1"] and "did not qualify" in reason


def test_implausible_timestamps_are_not_direct():
    for mins in (-(ID_JOIN_SKEW_S // 60 + 5), 61 + 60):          # well after the session start; > window before it
        rec, label, _, conflicts = join([si(1, minutes_before=mins)])
        assert rec is None and label == "unresolved" and "time not plausible" in conflicts[0]["problems"][0], mins
    rec, label, _, conflicts = join([dict(si(1), ts_utc=None)])
    assert rec is None and conflicts[0]["problems"] == ["time not resolvable"]


def test_multiple_matching_records_direct_only_when_consistent():
    rec, label, reason, _ = join([si(1, minutes_before=3), si(2, minutes_before=2)])
    assert label == "direct" and rec["event_id"] == "SRC-IDP:1" and "2 consistent records" in reason
    rec, label, reason, conflicts = join([si(1, minutes_before=3), si(2, minutes_before=2, mfa="true")])
    assert rec is None and label == "unresolved" and "ambiguous" in reason and len(conflicts) == 2
    # the same record seen twice (one event id) is one record, not two
    rec, label, _, _ = join([si(1), si(1)])
    assert label == "direct"


def _reuse_supplier_correlation_id(gen):
    """Adversarial input: a second sign-in, by another account, carrying the supplier sign-in's correlation id."""
    p = gen / "logs" / "identity" / "entra_signins.json"
    doc = json.loads(p.read_text())
    sup = next(r for r in doc["value"] if r["userPrincipalName"].startswith("vendor01@"))
    other = json.loads(json.dumps(sup))
    other.update(id="00000000-0000-4000-8000-0000000000aa", userPrincipalName="clerk01@utility.example",
                 ipAddress="10.60.5.41", authenticationRequirement="multiFactorAuthentication",
                 mfaDetail={"authMethod": "Mobile app notification", "authDetail": None})
    doc["value"].append(other)
    p.write_text(json.dumps(doc))


def test_reused_correlation_id_in_the_pipeline_is_unresolved_not_direct(tmp_path):
    ns = build(tmp_path, "c", mutate=_reuse_supplier_correlation_id)
    r = report(ns.case_dir, "financial")
    s = next(s for s in r["sessions"] if "supplier_outside_window" in s["suspicious_reasons"])
    ident = s["links"]["identity"]
    assert ident["label"] == "unresolved" and ident["evidence"] == []
    assert any("names a different account" in c["problems"] for c in ident["conflicts"])
    # nothing is attributed from the contradictory sign-ins: no MFA or address reasons, VPN not joined through them
    assert not {"signin_without_mfa", "external_signin"} & set(s["suspicious_reasons"])
    assert s["links"]["remote_access"]["label"] != "direct"
    # the rest of the evidence is unaffected
    assert r["financial_impact"]["status"] == "settlement_corroborated"


# ------------------------------------------------------------------------------------------- P0: provenance
def _rerun_and_release_paths(ns):
    cli(["paths", "analyse", *ns.c, "--window", WINDOW], "olivia")
    cli(["paths", "report", *ns.c, "--exposure-report", str(ns.case_dir / "reports" / "exposure" / "v0001")])
    cli(["release", *ns.c, "--kind", "paths", "--approver", "ines"])


def _financial(ns, ok=True):
    return cli(["financial", "analyse", *ns.c, "--config", str(ns.gen / "financial.yaml")], "olivia", ok=ok)


def test_released_paths_report_binds_the_event_set(scenarios):
    r = report(scenarios["c"].case_dir, "paths")
    for s in r["inputs"]["sources"]:
        assert len(s["events_file_sha256"]) == 64, s["source_id"]
    f = report(scenarios["c"].case_dir, "financial")
    bound = {b["source_id"]: b["events_file_sha256"] for b in f["inputs"]["paths_binding"]["sources"]}
    assert bound == {s["source_id"]: s["events_file_sha256"] for s in r["inputs"]["sources"]}
    ref = next(x for x in f["references"] if x["kind"] == "paths")
    assert f["inputs"]["paths_binding"]["paths_report_sha256"] == ref["report_sha256"]


def test_reingest_after_paths_release_is_refused_until_paths_is_rerun(scenarios, tmp_path):
    ns = clone(scenarios["c"], tmp_path)
    ns.env.apply()
    cli(["paths", "ingest", *ns.c, "--manifest", str(ns.gen / "logs" / "logs.yaml")], "olivia")
    rc, out, err = _financial(ns, ok=False)
    assert rc != 0 and "does not match the released paths report" in (err + str(out))
    assert "stored event set" in (err + str(out))
    _rerun_and_release_paths(ns)
    rc, out, _ = _financial(ns)
    assert rc == 0


def test_new_source_after_paths_release_is_refused_until_paths_is_rerun(scenarios, tmp_path):
    ns = clone(scenarios["c"], tmp_path)
    ns.env.apply()
    logs = tmp_path / "extra"
    shutil.copytree(ns.gen / "logs", logs)
    doc = yaml.safe_load((logs / "logs.yaml").read_text())
    extra = next(s for s in doc["sources"] if s["family"] == "fin_app_audit")
    doc["sources"] = [dict(extra, id="erp-audit-late", label="late financial export")]
    (logs / "logs.yaml").write_text(yaml.safe_dump(doc, sort_keys=False))
    cli(["paths", "ingest", *ns.c, "--manifest", str(logs / "logs.yaml")], "olivia")
    rc, out, err = _financial(ns, ok=False)
    assert rc != 0 and "not in the released paths report" in (err + str(out))
    _rerun_and_release_paths(ns)
    assert _financial(ns)[0] == 0


@pytest.mark.parametrize("field", ["events_file_sha256", "events"])
def test_binding_checks_each_bound_field(scenarios, field):
    """Direct check of the binding function against a released body altered in one field."""
    from tripline_scope.core.case import Case
    from tripline_scope.core.errors import IntegrityError
    from tripline_scope.core.home import Home
    from tripline_scope.core.store import open_store
    from tripline_scope.enterprise.financial import bind_to_released_paths
    ns = scenarios["c"]
    ns.env.apply()
    store = open_store(Case(ns.case_dir), Home())
    body = report(ns.case_dir, "paths")
    srcs = store.read_json("work/paths/sources.json")
    assert bind_to_released_paths(store, body, srcs)["sources"]
    src = next(s for s in body["inputs"]["sources"] if s["family"] == "fin_app_audit")
    src[field] = "0" * 64 if field == "events_file_sha256" else src[field] + 1
    with pytest.raises(IntegrityError):
        bind_to_released_paths(store, body, srcs)


def test_vpn_join_accepts_a_start_record_without_outcome_but_never_a_failure():
    vpn = lambda outcome: dict(si(1, minutes_before=1), outcome=outcome, assigned_ip="10.60.200.23")  # noqa: E731
    kw = dict(window_s=3600, agree=("remote_ip", "assigned_ip"), what="VPN session",
              ok_outcomes=frozenset({"success", "unknown"}))
    assert _validate_id_join([vpn("unknown")], ACCT, T0, K, **kw)[1] == "direct"
    rec, label, _, conflicts = _validate_id_join([vpn("failure")], ACCT, T0, K, **kw)
    assert rec is None and label == "unresolved" and conflicts[0]["problems"] == ["outcome failure"]
