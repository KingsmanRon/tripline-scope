"""Scale measurement on a representative synthetic tree (default 20 000 files; EXPOSURE_SCALE_FILES to change).

Reports measured throughput, peak RSS, disk use, file count and parser failures. No time guarantee is asserted.
Set EXPOSURE_BENCH_OUT to a file path to keep the measurements as JSON.
"""

import json
import os
import time

import pytest

from tripline_scope import testing
from tripline_scope.exposure.synthetic import build_scale_tree


def _du(path):
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file() and not p.is_symlink())


@pytest.mark.slow
def test_scale_tree_throughput(install, tmp_path):
    n = int(os.environ.get("EXPOSURE_SCALE_FILES", "20000"))
    t0 = time.monotonic()
    manifest = build_scale_tree(tmp_path / "scale", n)
    gen_s = time.monotonic() - t0
    case_dir = testing.open_case(tmp_path, "READY-SCALE", mode="readiness")
    testing.login("olivia")
    t1 = time.monotonic()
    rc, out, err = testing.run_cli(["--json", "exposure", "scan", "--case", str(case_dir), "--inputs", str(manifest)])
    total_s = time.monotonic() - t1
    assert rc == 0, err
    res = json.loads(out)
    m = res["metrics"]
    assert m["files_examined"] == n and m["parser_failures"] == 0
    expected_secrets = len([i for i in range(n) if i % 997 == 0])
    expected_exports = len([i for i in range(n) if i % 1499 == 0 and i % 997 != 0])
    assert res["by_control"].get("A1") == expected_secrets
    assert res["by_control"].get("A3") == expected_exports
    t2 = time.monotonic()
    rc, out, err = testing.run_cli(["exposure", "report", "--case", str(case_dir)])
    report_s = time.monotonic() - t2
    assert rc == 0, err
    bench = {
        "files": n, "input_bytes": _du(tmp_path / "scale" / "snapshot"), "generate_s": round(gen_s, 2),
        "scan_command_s": round(total_s, 2), "scan_wall_s_incl_custody_registration": m["wall_seconds"],
        "files_per_second": m["files_per_second"], "mb_per_second": m["mb_per_second"],
        "files_per_second_end_to_end": round(n / total_s, 1), "peak_rss_mb": m["peak_rss_mb"],
        "parser_failures": m["parser_failures"], "report_s": round(report_s, 2),
        "case_disk_bytes": _du(case_dir), "findings": res["findings"],
    }
    print("\nEXPOSURE-SCALE " + json.dumps(bench, sort_keys=True))
    out_path = os.environ.get("EXPOSURE_BENCH_OUT")
    if out_path:
        with open(out_path, "w") as fh:
            json.dump(bench, fh, indent=1, sort_keys=True)


@pytest.mark.slow
def test_large_export_throughput(install, tmp_path):
    """Byte-heavy case: multi-MB CSV exports with valid SA IDs (MB/s and bounded row counting)."""
    import datetime as dt
    import random

    import yaml

    from tripline_scope.core.identifiers import make_sa_id

    rng = random.Random(3)
    root = tmp_path / "big" / "share"
    root.mkdir(parents=True)
    ids = [make_sa_id(dt.date(1950, 1, 1) + dt.timedelta(days=rng.randrange(25000)), rng.randrange(10000))
           for _ in range(5000)]
    for i in range(int(os.environ.get("EXPOSURE_BIG_FILES", "5"))):
        lines = ["ID Number,Surname,Result"] + [f"{rng.choice(ids)},Name{rng.randrange(999)},{rng.random():.3f}"
                                                 for _ in range(120_000)]
        (root / f"export_{i}.csv").write_text("\n".join(lines) + "\n")
    doc = {"schema": "tripline.exposure-manifest/v1", "owner": "IT", "legal_basis": "measurement",
           "received_at": "2026-10-01T00:00:00Z", "budget": {"max_file_bytes": "16MiB"},
           "roots": [{"id": "share", "path": "big/share", "kind": "share"}]}
    (tmp_path / "m.yaml").write_text(yaml.safe_dump(doc))
    case_dir = testing.open_case(tmp_path, "READY-BIG", mode="readiness")
    testing.login("olivia")
    t1 = time.monotonic()
    rc, out, err = testing.run_cli(["--json", "exposure", "scan", "--case", str(case_dir), "--inputs", str(tmp_path / "m.yaml")])
    total_s = time.monotonic() - t1
    assert rc == 0, err
    res = json.loads(out)
    m = res["metrics"]
    assert res["by_control"]["A3"] == len(list(root.iterdir()))
    bench = {"files": m["files_examined"], "input_bytes": m["bytes_read"], "scan_command_s": round(total_s, 2),
             "mb_per_second": m["mb_per_second"], "peak_rss_mb": m["peak_rss_mb"], "parser_failures": m["parser_failures"]}
    print("\nEXPOSURE-LARGE " + json.dumps(bench, sort_keys=True))
