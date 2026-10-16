import json
import os
import shutil

import pytest

from tripline_scope import testing
from tripline_scope.core.canonical import canonical_bytes
from tripline_scope.core.case import Case
from tripline_scope.core.home import Home
from tripline_scope.core.reports import ReportStore
from tscope_verify.report import verify_chain, verify_version


def _draft(case_dir, n_people=10, **extra):
    case = Case(case_dir)
    rs = ReportStore(case)
    body = rs.new_body("scope", report_status="preliminary", counts={"unique_people": n_people}, **extra)
    return rs.save_draft("scope", body, pdf=b"%PDF-1.4 test", attachments={"diff.json": b"{}"})


def _release(case_dir, approver="ines"):
    return testing.run_cli(["--json", "release", "--case", str(case_dir), "--kind", "scope", "--approver", approver])


def _keys():
    return Home().trusted_hospital_keys()


def test_release_requires_approver_and_separation(case_dir):
    _draft(case_dir)
    testing.login("olivia")
    rc, out, err = _release(case_dir, approver="olivia")
    assert rc == 3  # operator is not an approver
    os.environ["TSCOPE_APPROVER_PASSWORD"] = "wrong-password-xyz"
    rc, out, err = _release(case_dir)
    assert rc == 3  # sign-in fails
    os.environ["TSCOPE_APPROVER_PASSWORD"] = testing.PASSWORD
    rc, out, err = _release(case_dir)
    assert rc == 0, err
    case = Case(case_dir)
    # same person cannot later be made operator
    with pytest.raises(Exception):
        case.assign("ines", "operator")


def test_approver_who_acted_as_operator_is_refused(case_dir):
    testing.login("admin")
    rc, out, err = testing.run_cli(["case", "assign", "--case", str(case_dir), "--user", "rami", "--role", "operator"])
    assert rc == 0, err
    testing.login("rami")
    rc, out, err = testing.run_cli(["case", "gap", "--case", str(case_dir), "--description", "firewall logs rotated"])
    assert rc == 0, err
    # remove the operator role, then try to make rami approver: refused because rami acted as operator
    case = Case(case_dir)
    case.unassign("rami", "operator")
    with pytest.raises(Exception):
        case.assign("rami", "approver")


def test_chain_verifies_and_tamper_fails(case_dir, tmp_path):
    _draft(case_dir, 10)
    assert _release(case_dir)[0] == 0
    _draft(case_dir, 12)
    assert _release(case_dir)[0] == 0
    kind_dir = case_dir / "reports" / "scope"
    assert verify_chain(kind_dir, hospital_keys=_keys()).ok
    rc, out, err = testing.run_cli(["verify", "--case", str(case_dir)])
    assert rc == 0, out + err

    def tampered(mutator):
        t = tmp_path / f"t{len(list(tmp_path.iterdir()))}"
        shutil.copytree(kind_dir, t)
        for p in t.rglob("*"):
            os.chmod(p, 0o755 if p.is_dir() else 0o644)
        mutator(t)
        return verify_chain(t, hospital_keys=_keys()).ok

    def alter_field(t):
        p = t / "v0002" / "report.json"
        d = json.loads(p.read_bytes())
        d["counts"]["unique_people"] = 11
        p.write_bytes(canonical_bytes(d))

    def alter_signature(t):
        p = t / "v0002" / "signatures.json"
        d = json.loads(p.read_bytes())
        sig = d["signatures"][-1]["signature"]
        d["signatures"][-1]["signature"] = ("A" if sig[0] != "A" else "B") + sig[1:]
        p.write_bytes(canonical_bytes(d))

    def break_link(t):
        p = t / "v0001" / "report.json"
        d = json.loads(p.read_bytes())
        d["counts"]["unique_people"] = 9
        p.write_bytes(canonical_bytes(d))

    def drop_version(t):
        shutil.rmtree(t / "v0001")

    def alter_pdf(t):
        (t / "v0002" / "report.pdf").write_bytes(b"%PDF-1.4 changed")

    def non_canonical(t):
        p = t / "v0002" / "report.json"
        p.write_bytes(json.dumps(json.loads(p.read_bytes()), indent=1).encode())

    def approval_changed(t):
        p = t / "v0002" / "release.json"
        d = json.loads(p.read_bytes())
        d["approval"]["approver"] = "someone-else"
        p.write_bytes(canonical_bytes(d))

    for m in (alter_field, alter_signature, break_link, drop_version, alter_pdf, non_canonical, approval_changed):
        assert not tampered(m), m.__name__
    # a foreign key is not trusted
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    assert not verify_version(kind_dir / "v0002", hospital_keys=[Ed25519PrivateKey.generate().public_key()]).ok
    # released files are read-only (mode bits; root bypasses them, so check the bits themselves)
    import stat

    assert stat.S_IMODE((kind_dir / "v0001" / "report.json").stat().st_mode) & 0o222 == 0


def test_identical_inputs_byte_identical_report(install, tmp_path):
    a = testing.open_case(tmp_path / "a", "CASE-SAME")
    shutil.rmtree(a)
    Home().wrapped_dek_path("CASE-SAME").unlink()
    a = testing.open_case(tmp_path / "a", "CASE-SAME")
    d1 = _draft(a, 42)
    b1 = (d1.path / "report.json").read_bytes()
    shutil.rmtree(a)
    Home().wrapped_dek_path("CASE-SAME").unlink()
    b = testing.open_case(tmp_path / "b", "CASE-SAME")
    d2 = _draft(b, 42)
    assert (d2.path / "report.json").read_bytes() == b1


def test_report_refuses_identifier_like_values(case_dir):
    from tripline_scope.core.errors import IntegrityError

    with pytest.raises(IntegrityError):
        _draft(case_dir, note="contact thandi@example.com")


def test_close_destroys_key_and_data_and_certificate_verifies(case_dir, tmp_path):
    from tripline_scope.core.store import open_store
    from tscope_verify.certificate import verify_certificate

    case = Case(case_dir)
    store = open_store(case, Home())
    store.write_json("work/scope/people.json", {"x": "MARKER"})
    store.write_json("notify/people.json", {"x": "MARKER"})
    _draft(case_dir)
    assert _release(case_dir)[0] == 0
    # legal hold blocks closure
    testing.login("ines")
    assert testing.run_cli(["case", "hold", "--case", str(case_dir), "on", "--reason", "litigation"])[0] == 0
    rc, out, err = testing.run_cli(["case", "close", "--case", str(case_dir), "--approver", "ines"])
    assert rc == 5, err
    assert testing.run_cli(["case", "hold", "--case", str(case_dir), "off"])[0] == 0
    # operator cannot close
    rc, out, err = testing.run_cli(["case", "close", "--case", str(case_dir), "--approver", "olivia"])
    assert rc == 3
    rc, out, err = testing.run_cli(["--json", "case", "close", "--case", str(case_dir), "--approver", "ines",
                                    "--external-backup", "nightly keystore backup, 30-day retention"])
    assert rc == 0, err
    cert = json.loads(out)["certificate"]
    assert verify_certificate(cert, hospital_keys=_keys()).ok
    assert not Home().wrapped_dek_path(case.case_id).exists()
    assert not list((case_dir / "work").rglob("*.tse")) and not list((case_dir / "notify").rglob("*.tse"))
    with pytest.raises(Exception):
        open_store(Case(case_dir), Home())
    rc, out, err = testing.run_cli(["case", "gap", "--case", str(case_dir), "--description", "x"])
    assert rc == 6
    # signed reports, audit log and certificate remain verifiable after closure
    rc, out, err = testing.run_cli(["verify", "--case", str(case_dir)])
    assert rc == 0, out + err
    # tampered certificate fails
    d = json.loads(open(cert, "rb").read())
    d["destroyed"]["working_files"]["count"] = 0
    t = tmp_path / "cert"
    t.mkdir()
    (t / "certificate.json").write_bytes(canonical_bytes(d))
    shutil.copy(os.path.join(os.path.dirname(cert), "certificate.sig.json"), t)
    assert not verify_certificate(t / "certificate.json", hospital_keys=_keys()).ok
