"""CycloneDX SBOM: the checker on synthetic documents, and the bundle's SBOM against the runtime lock."""

import json
from pathlib import Path

import sbom
from check_licences import normalize_name, parse_lock

ROOT = Path(__file__).resolve().parents[2]
H1, H2 = "1" * 64, "2" * 64


def _lock(tmp_path):
    p = tmp_path / "lock.txt"
    p.write_text(f"alpha==1.0 \\\n    --hash=sha256:{H1}\nbeta-pkg==2.0 \\\n    --hash=sha256:{H2}\n")
    return p


def _bom(components, root=True):
    comps = [{"name": n, "version": v, "purl": f"pkg:pypi/{n}@{v}", "licenses": [{"license": {"id": "MIT"}}],
              "hashes": [{"alg": "SHA-256", "content": h}]} for n, v, h in components]
    comps.append({"name": "tripline-scope-verify", "version": "0.1.0", "hashes": [{"alg": "SHA-256", "content": "f" * 64}]})
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": comps, "metadata": {}}
    if root:
        doc["metadata"]["component"] = {"name": "tripline-scope", "version": "0.1.0",
                                        "hashes": [{"alg": "SHA-256", "content": "e" * 64}]}
    return doc


def _check(tmp_path, doc):
    p = tmp_path / "sbom.json"
    p.write_text(json.dumps(doc))
    return sbom.check(p, _lock(tmp_path))


def test_complete_sbom_passes(tmp_path):
    assert _check(tmp_path, _bom([("alpha", "1.0", H1), ("beta-pkg", "2.0", H2)])) == []


def test_missing_wrong_version_wrong_hash_and_extra(tmp_path):
    errors = _check(tmp_path, _bom([("alpha", "1.1", H1), ("gamma", "1.0", H1)], root=False))
    text = "\n".join(errors)
    assert "beta-pkg: missing from SBOM" in text
    assert "alpha: SBOM version 1.1 != lock 1.0" in text
    assert "gamma 1.0: in SBOM but not in the runtime lock" in text
    assert "first-party tripline-scope missing" in text
    errors = _check(tmp_path, _bom([("alpha", "1.0", "9" * 64), ("beta-pkg", "2.0", H2)]))
    assert errors == ["alpha: SBOM hash is not one of the lock's hashes"]


def test_bundle_sbom_covers_every_runtime_dependency(bundle_dir):
    assert sbom.check(bundle_dir / "sbom.cdx.json", ROOT / "requirements" / "runtime.txt") == []
    doc = json.loads((bundle_dir / "sbom.cdx.json").read_text())
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] in ("1.5", "1.6", "1.7")
    lock = parse_lock(ROOT / "requirements" / "runtime.txt")
    comps = {normalize_name(c["name"]): c for c in doc["components"]}
    for key, e in lock.items():
        c = comps[key]
        assert c["version"] == e["version"] and c["purl"].startswith("pkg:pypi/")
        assert any(f"sha256:{h['content']}" in e["hashes"] for h in c["hashes"])
        bundle_file = next(p["value"] for p in c["properties"] if p["name"] == "tripline:bundle-file")
        assert (bundle_dir / bundle_file).is_file()
    root = doc["metadata"]["component"]
    assert root["name"] == "tripline-scope" and root["hashes"]
    # statically linked Rust crates are recorded as nested cargo components
    for pkg in ("evtx", "pydantic-core", "cryptography"):
        nested = comps[pkg].get("components", [])
        assert nested and all(n["purl"].startswith("pkg:cargo/") for n in nested), pkg
    assert any(n["name"].startswith("libjpeg") for n in comps["pillow"]["components"])
