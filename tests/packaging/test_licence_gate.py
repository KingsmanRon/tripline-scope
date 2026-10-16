"""Licence gate: synthetic metadata (GPL, unknown, LGPL without exception fail) and the real runtime wheels."""

import email
import json
import zipfile
from pathlib import Path

import check_licences as cl
import pytest

ROOT = Path(__file__).resolve().parents[2]
MIT_TEXT = ("Permission is hereby granted, free of charge, to any person obtaining a copy ... The above copyright "
            "notice and this permission notice shall be included in all copies or substantial portions.")
BSD3_TEXT = ("Redistribution and use in source and binary forms, with or without modification, are permitted ... "
             "Neither the name of the copyright holder nor the names of its contributors may be used to endorse")
BSD4_TEXT = BSD3_TEXT + " All advertising materials mentioning features or use of this software must display"
GPL_TEXT = "GNU GENERAL PUBLIC LICENSE\n Version 3, 29 June 2007\n ..."


def dist(name="pkg", version="1.0", *, expr=None, lic=None, classifiers=(), own=None, bundled=None):
    lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    if expr:
        lines.append(f"License-Expression: {expr}")
    if lic:
        lines.append(f"License: {lic}")
    lines += [f"Classifier: {c}" for c in classifiers]
    meta = email.message_from_string("\n".join(lines) + "\n\n")
    return cl.Dist(name, version, meta, own or {}, bundled or {})


def status(d):
    return cl.evaluate_dist(d)["status"]


@pytest.mark.parametrize("kwargs, expected", [
    ({"expr": "MIT"}, "allowed"),
    ({"expr": "Apache-2.0 OR BSD-3-Clause"}, "allowed"),
    ({"expr": "MIT OR GPL-2.0-only"}, "allowed"),            # licensee may choose the permissive branch
    ({"expr": "MIT AND GPL-2.0-only"}, "denied"),            # both apply
    ({"expr": "GPL-3.0-or-later"}, "denied"),
    ({"expr": "AGPL-3.0-only"}, "denied"),
    ({"expr": "SSPL-1.0"}, "denied"),
    ({"expr": "LGPL-2.1-or-later"}, "denied"),               # LGPL needs an explicit exception
    ({"expr": "GPL-2.0-or-later WITH Classpath-exception-2.0"}, "denied"),
    ({"expr": "Apache-2.0 WITH LLVM-exception"}, "allowed"),
    ({"expr": "MPL-2.0"}, "unknown"),
    ({"expr": "LicenseRef-Proprietary"}, "unknown"),
    ({"lic": "MIT License"}, "allowed"),
    ({"lic": "BSD 3-Clause License"}, "allowed"),
    ({"lic": "GPLv3"}, "denied"),
    ({"lic": "GPL-2.0-only"}, "denied"),
    ({"classifiers": ["License :: OSI Approved :: MIT License"]}, "allowed"),
    ({"classifiers": ["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"]}, "denied"),
    ({"classifiers": ["License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)"]}, "denied"),
    ({"classifiers": ["License :: OSI Approved :: BSD License"], "own": {"x.dist-info/LICENSE": BSD3_TEXT}},
     "allowed"),
    ({"classifiers": ["License :: OSI Approved :: BSD License"], "own": {"x.dist-info/LICENSE": BSD4_TEXT}},
     "unknown"),
    ({"classifiers": ["License :: OSI Approved :: BSD License"]}, "unknown"),   # variant unknowable
    ({"own": {"x.dist-info/LICENSE": MIT_TEXT}}, "allowed"),
    ({"own": {"x.dist-info/COPYING": GPL_TEXT}}, "denied"),
    ({}, "unknown"),                                          # no licence information at all
    ({"lic": "Proprietary"}, "unknown"),
])
def test_synthetic_metadata(kwargs, expected):
    assert status(dist(**kwargs)) == expected


def test_conflicting_classifier_is_denied():
    d = dist(expr="MIT", classifiers=["License :: OSI Approved :: GNU General Public License v2 (GPLv2)"])
    r = cl.evaluate_dist(d)
    assert r["status"] == "denied" and "classifier declares GPL" in r["reason"]


def test_lgpl_only_with_explicit_exception(monkeypatch):
    d = dist("libfoo", expr="LGPL-2.1-only")
    assert status(d) == "denied"
    monkeypatch.setitem(cl.LGPL_EXCEPTIONS, "libfoo", "unmodified, dynamically linked shared library")
    assert status(d) == "allowed-by-exception"
    assert status(dist("libbar", expr="LGPL-2.1-only")) == "denied"


def test_lgpl_exception_list_is_empty():
    assert cl.LGPL_EXCEPTIONS == {}


def test_pillow_allowance_is_package_specific():
    assert status(dist("pillow", expr="MIT-CMU")) == "allowed-by-exception"
    assert status(dist("pillow", expr="HPND")) == "allowed-by-exception"
    assert status(dist("otherpkg", expr="MIT-CMU")) == "unknown"


def test_bundled_gpl_licence_file_fails_unless_reviewed():
    grant = "This font is free software; you can redistribute it under the terms of the GNU General Public License"
    d = dist("somepkg", expr="MIT", bundled={"somepkg/fonts/x-copying.txt": grant})
    r = cl.evaluate_dist(d)
    assert r["status"] == "denied" and r["bundled"][0]["family"] == "GPL"
    rl = dist("reportlab", expr="BSD-3-Clause", bundled={"reportlab/fonts/DarkGarden-copying.txt": grant})
    r = cl.evaluate_dist(rl)
    assert r["status"] == "allowed" and r["bundled"][0]["status"] == "allowed-by-exception"
    # the exception is path-specific
    rl2 = dist("reportlab", expr="BSD-3-Clause", bundled={"reportlab/other/COPYING": grant})
    assert status(rl2) == "denied"


def test_licence_mentions_are_not_grants():
    # PSF history table, FreeType dual licence note and SSLeay clause mention the GPL without granting it.
    for text in ("releases have also been GPL-compatible; the table below summarizes",
                 "The GNU General Public License version 2, found in docs/GPLv2.TXT, for programs which use the GPL",
                 "cannot simply be copied and put under another distribution licence [including the GNU Public Licence.]"):
        assert cl.copyleft_grant(text) is None, text
    assert cl.copyleft_grant(GPL_TEXT) == "GPL"
    assert cl.copyleft_grant("GNU LESSER GENERAL PUBLIC LICENSE\nVersion 2.1") == "LGPL"
    assert cl.copyleft_grant("under the terms of the GNU Affero General Public License as published") == "AGPL"


def test_spdx_parser():
    assert cl.parse_expression("MIT") == ("id", "MIT", None)
    assert cl.parse_expression("(MIT OR Apache-2.0) AND Unicode-3.0")[0] == "and"
    assert cl.parse_expression("Apache-2.0 WITH LLVM-exception") == ("id", "Apache-2.0", "LLVM-exception")
    for bad in ("MIT OR", "(MIT", "MIT Apache-2.0", ""):
        with pytest.raises((ValueError, IndexError)):
            cl.parse_expression(bad)


def _lock(tmp_path, entries):
    p = tmp_path / "lock.txt"
    p.write_text("".join(f"{n}=={v} \\\n    --hash=sha256:{'0' * 64}\n" for n, v in entries))
    return p


def _wheel(directory: Path, name, version, *, expr=None, lic=None, classifiers=(), files=None):
    directory.mkdir(parents=True, exist_ok=True)
    w = directory / f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    di = f"{name.replace('-', '_')}-{version}.dist-info"
    meta = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    meta += [f"License-Expression: {expr}"] if expr else []
    meta += [f"License: {lic}"] if lic else []
    meta += [f"Classifier: {c}" for c in classifiers]
    with zipfile.ZipFile(w, "w") as z:
        z.writestr(f"{di}/METADATA", "\n".join(meta) + "\n\n")
        for path, text in (files or {}).items():
            z.writestr(path, text)
    return w


def test_cli_fails_on_gpl_and_unknown(tmp_path):
    wh = tmp_path / "wheels"
    _wheel(wh, "good", "1.0", expr="MIT")
    _wheel(wh, "copyleft", "2.0", classifiers=["License :: OSI Approved :: GNU General Public License v3 (GPLv3)"])
    _wheel(wh, "mystery", "3.0")
    _wheel(wh, "lesser", "4.0", expr="LGPL-3.0-only")
    lock = _lock(tmp_path, [("good", "1.0"), ("copyleft", "2.0"), ("mystery", "3.0"), ("lesser", "4.0")])
    out = tmp_path / "report.json"
    rc = cl.main(["--requirements", str(lock), "--wheels", str(wh), "--json-out", str(out), "--quiet"])
    assert rc == 1
    report = json.loads(out.read_text())
    assert report["schema"] == "tripline.licence-check/v1" and report["ok"] is False
    by = {p["name"]: p["status"] for p in report["packages"]}
    assert by == {"good": "allowed", "copyleft": "denied", "mystery": "unknown", "lesser": "denied"}


def test_cli_closure_must_equal_lock(tmp_path):
    wh = tmp_path / "wheels"
    _wheel(wh, "good", "1.0", expr="MIT")
    _wheel(wh, "extra", "1.0", expr="MIT")
    _wheel(wh, "opentelemetry-sdk", "1.0", expr="Apache-2.0")
    lock = _lock(tmp_path, [("good", "1.1"), ("missing", "1.0")])
    rep = cl.check(cl.parse_lock(lock), [cl.dist_from_wheel(w) for w in wh.glob("*.whl")])
    text = "\n".join(rep["errors"])
    assert "does not match lock 1.1" in text
    assert "missing: no distribution found" in text
    assert "extra 1.0: present but not in the lock" in text
    assert "forbidden telemetry package present" in text


def test_cli_passes_for_permissive_closure(tmp_path):
    wh = tmp_path / "wheels"
    _wheel(wh, "a", "1.0", expr="MIT")
    _wheel(wh, "b", "1.0", lic="Apache 2.0")
    _wheel(wh, "c", "1.0", classifiers=["License :: OSI Approved :: ISC License (ISCL)"])
    _wheel(wh, "d", "1.0", expr="PSF-2.0")
    _wheel(wh, "tripline-scope-verify", "0.1.0", expr="Apache-2.0")  # first party: not evaluated
    lock = _lock(tmp_path, [("a", "1.0"), ("b", "1.0"), ("c", "1.0"), ("d", "1.0")])
    assert cl.main(["--requirements", str(lock), "--wheels", str(wh), "--quiet"]) == 0


def test_cli_usage_error(tmp_path):
    lock = _lock(tmp_path, [("a", "1.0")])
    assert cl.main(["--requirements", str(lock), "--wheels", str(tmp_path / "nowheels")]) == 2


def test_native_audit_review_and_failures():
    lock = {"x": {"name": "x", "version": "1.0", "hashes": [], "pinned": True}}
    audit = {"packages": {"x": {"version": "1.0", "rust": {"crates": [
        {"name": "ok", "version": "1", "license": "MIT/Apache-2.0", "evidence": ["binary"]},
        {"name": "uni", "version": "1", "license": "Unicode-3.0", "evidence": ["binary"]},
        {"name": "gpl", "version": "1", "license": "GPL-3.0-only", "evidence": ["Cargo.lock"]},
        {"name": "none", "version": "1", "license": None, "evidence": ["Cargo.lock"]},
    ]}}}}
    rep = cl.check_native(audit, lock)
    assert [r["crate"] for r in rep["review"]] == ["uni"] and rep["review"][0]["linked"]
    assert any("crate gpl" in e for e in rep["errors"]) and any("crate none" in e for e in rep["errors"])
    stale = cl.check_native({"packages": {"x": {"version": "0.9"}}}, lock)
    assert "re-run make native-audit" in stale["errors"][0]


# ------------------------------------------------------------------------------------------- real closure
def test_real_runtime_wheels_pass_the_gate(wheelhouse, tmp_path):
    out = tmp_path / "licences.json"
    rc = cl.main(["--requirements", str(ROOT / "requirements" / "runtime.txt"), "--wheels", str(wheelhouse),
                  "--native-audit", str(ROOT / "requirements" / "native-audit.json"), "--json-out", str(out),
                  "--quiet"])
    report = json.loads(out.read_text())
    assert rc == 0, report["errors"]
    lock = cl.parse_lock(ROOT / "requirements" / "runtime.txt")
    assert {cl.normalize_name(p["name"]) for p in report["packages"]} == set(lock)
    assert all(p["status"] in ("allowed", "allowed-by-exception") for p in report["packages"])
    assert {p["name"] for p in report["packages"] if p["status"] == "allowed-by-exception"} == {"pillow"}


def test_native_audit_matches_lock_and_wheels(wheelhouse):
    audit = json.loads((ROOT / "requirements" / "native-audit.json").read_text())
    lock = cl.parse_lock(ROOT / "requirements" / "runtime.txt")
    for name, info in audit["packages"].items():
        assert lock[cl.normalize_name(name)]["version"] == info["version"], name
    native = {cl.normalize_name(w.name.split("-")[0]) for w in wheelhouse.glob("*.whl")
              if not w.name.endswith("-none-any.whl") and cl.normalize_name(w.name.split("-")[0]) in lock}
    assert native <= {cl.normalize_name(k) for k in audit["packages"]}, "native wheel without audit entry"
    for rust_pkg in ("cryptography", "pydantic-core", "evtx"):
        crates = audit["packages"][rust_pkg]["rust"]["crates"]
        assert crates and all(c["license"] for c in crates), rust_pkg
