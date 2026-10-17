#!/usr/bin/env python3
"""Build demo SQL Server backups (.bak) from a synthetic dataset. Demo / test tooling, not a product command.

Input layout (written by ``tscope synth``)::

    <synth>/sources/db01/patients.parquet admissions.parquet billing.parquet results.parquet
    <synth>/sources/db02/...                                     (schemas vary slightly per database)

For each ``dbNN`` directory this creates database ``<prefix>LabDBNN`` (tables in schema ``dbo``) on the given
SQL Server, bulk-loads the Parquet tables (python-tds bulk copy into an NVARCHAR staging table, converted
server-side), runs ``BACKUP DATABASE ... TO DISK`` inside the container, copies ``<prefix>LabDBNN.bak`` to
``--out`` with ``docker cp`` and drops the build database.

SQL Server Developer Edition is licensed for development and test only: use this with synthetic data only.

``--attest`` (generator ``lab-bak``): before building, every input Parquet file must already be in the
installation's synthetic-origin registry as output of ``tscope synth --attest``; the inputs are re-hashed after
the build, and only then is each written ``.bak`` recorded in the registry. SQL Server backups are not
byte-reproducible, so a ``.bak`` is attested by this builder from attested synthetic inputs, never by
re-deriving its bytes. Needs ``TSCOPE_HOME`` and the KEK passphrase.

Usage::

    python demo/lab-breach/build_baks.py --synth DIR --out DIR --host 127.0.0.1 --port 14330 \\
        --container mssql-test --password-env TSCOPE_DEMO_MSSQL_PASSWORD [--login sa] [--db-prefix ""] [--attest]
"""

from __future__ import annotations

import argparse
import datetime as dt
import decimal
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

STAGE_ROWS = 20_000
_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,100}$")


def q(name: str) -> str:
    return "[" + name.replace("]", "]]") + "]"


def sql_type(field: pa.Field, column: pa.ChunkedArray) -> tuple[str, str]:
    """(column type, CONVERT expression template using {c})."""
    t = field.type
    if pa.types.is_dictionary(t):
        t = t.value_type
    if pa.types.is_boolean(t):
        return "BIT", "CONVERT(BIT, {c})"
    if pa.types.is_integer(t):
        big = pa.types.is_int64(t) or pa.types.is_uint32(t) or pa.types.is_uint64(t)
        return ("BIGINT", "CONVERT(BIGINT, {c})") if big else ("INT", "CONVERT(INT, {c})")
    if pa.types.is_floating(t):
        return "FLOAT", "CONVERT(FLOAT, {c})"
    if pa.types.is_decimal(t):
        return f"DECIMAL({t.precision},{t.scale})", f"CONVERT(DECIMAL({t.precision},{t.scale}), {{c}})"
    if pa.types.is_date(t):
        return "DATE", "CONVERT(DATE, {c}, 23)"
    if pa.types.is_timestamp(t):
        return "DATETIME2(3)", "CONVERT(DATETIME2(3), {c}, 121)"
    maxlen = 1
    for chunk in column.chunks:
        if len(chunk):
            lengths = pc.utf8_length(chunk.cast(pa.string()))
            m = pc.max(lengths).as_py()
            maxlen = max(maxlen, m or 1)
    size = "MAX" if maxlen > 4000 else str(min(4000, max(16, -(-maxlen // 16) * 16)))
    return f"NVARCHAR({size})", "{c}"


def to_text(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return "1" if v else "0"
    if isinstance(v, dt.datetime):
        return v.replace(tzinfo=None).isoformat(sep=" ", timespec="milliseconds")
    if isinstance(v, dt.date):
        return v.isoformat()
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, decimal.Decimal):
        return str(v)
    return str(v)


def docker(args: list[str]) -> None:
    res = subprocess.run(["docker", *args], capture_output=True, timeout=1800, check=False)
    if res.returncode != 0:
        raise SystemExit(f"docker {args[0]} failed (exit {res.returncode})")


def connect(host: str, port: int, login: str, password: str, database: str = "master"):
    import pytds

    return pytds.connect(dsn=host, port=port, user=login, password=password, database=database,
                         autocommit=True, login_timeout=15, timeout=3600, appname="tripline-demo-builder")


def load_table(cur, table: str, path: Path) -> int:
    pt = pq.read_table(path)
    cols, converts = [], []
    for f in pt.schema:
        if not _NAME.match(f.name):
            raise SystemExit(f"unsupported column name in {path.name}")
        typ, conv = sql_type(f, pt.column(f.name))
        cols.append((f.name, typ))
        converts.append(conv.format(c=q(f.name)))
    first = pt.column(0)
    pk = ""
    if pt.num_rows and first.null_count == 0 and pc.count_distinct(first).as_py() == pt.num_rows \
            and cols[0][1] != "NVARCHAR(MAX)":
        pk = f", CONSTRAINT {q('pk_' + table)} PRIMARY KEY ({q(cols[0][0])})"
    ddl = ", ".join(f"{q(n)} {t} {'NOT NULL' if pk and i == 0 else 'NULL'}" for i, (n, t) in enumerate(cols))
    cur.execute(f"CREATE TABLE dbo.{q(table)} ({ddl}{pk})")
    stage = f"__stage_{table}"
    cur.execute(f"CREATE TABLE dbo.{q(stage)} ({', '.join(f'{q(n)} NVARCHAR(4000) NULL' for n, _ in cols)})")
    names = [n for n, _ in cols]
    for batch in pt.to_batches(STAGE_ROWS):
        pyc = [batch.column(i).to_pylist() for i in range(batch.num_columns)]
        rows = [tuple(to_text(pyc[j][i]) for j in range(len(pyc))) for i in range(batch.num_rows)]
        if rows:
            cur.copy_to(data=rows, table_or_view=stage, schema="dbo", columns=names, keep_nulls=True)
    cur.execute(f"INSERT INTO dbo.{q(table)} ({', '.join(q(n) for n in names)}) "
                f"SELECT {', '.join(converts)} FROM dbo.{q(stage)}")
    cur.execute(f"DROP TABLE dbo.{q(stage)}")
    return pt.num_rows


def build(args) -> list[Path]:
    password = os.environ.get(args.password_env)
    if not password:
        raise SystemExit(f"set {args.password_env} to the SQL Server password")
    src = Path(args.synth) / "sources"
    dbdirs = sorted(d for d in src.iterdir() if d.is_dir() and re.fullmatch(r"db\d{2}", d.name))
    if not dbdirs:
        raise SystemExit(f"no dbNN directories under {src}")
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    server_dir = args.server_backup_dir.rstrip("/")
    docker(["exec", "-u", "root", args.container, "mkdir", "-p", server_dir])
    docker(["exec", "-u", "root", args.container, "chown", "mssql", server_dir])
    made = []
    con = connect(args.host, args.port, args.login, password)
    cur = con.cursor()
    try:
        for d in dbdirs:
            t0 = time.monotonic()
            db = f"{args.db_prefix}LabDB{d.name[2:]}"
            if not _NAME.match(db):
                raise SystemExit("invalid database prefix")
            cur.execute("SELECT DB_ID(%(n)s)", {"n": db})
            if cur.fetchone()[0] is not None:
                cur.execute(f"ALTER DATABASE {q(db)} SET SINGLE_USER WITH ROLLBACK IMMEDIATE")
                cur.execute(f"DROP DATABASE {q(db)}")
            cur.execute(f"CREATE DATABASE {q(db)}")
            cur.execute(f"ALTER DATABASE {q(db)} SET RECOVERY SIMPLE")
            try:
                dcon = connect(args.host, args.port, args.login, password, db)
                dcur = dcon.cursor()
                rows = 0
                for pf in sorted(d.glob("*.parquet")):
                    if not _NAME.match(pf.stem):
                        raise SystemExit(f"unsupported table file name {pf.name}")
                    rows += load_table(dcur, pf.stem, pf)
                dcon.close()
                bak_server = f"{server_dir}/{db}.bak"
                cur.execute(f"BACKUP DATABASE {q(db)} TO DISK = N'{bak_server}' WITH INIT, FORMAT, CHECKSUM, "
                            "COMPRESSION")
                while cur.nextset():
                    pass
                docker(["cp", f"{args.container}:{bak_server}", str(out / f"{db}.bak")])
                docker(["exec", "-u", "root", args.container, "rm", "-f", bak_server])
                made.append(out / f"{db}.bak")
                print(f"{db}: {rows} rows, backup {(out / f'{db}.bak').stat().st_size} bytes, "
                      f"{time.monotonic() - t0:.1f}s")
            finally:
                cur.execute(f"IF DB_ID(N'{db}') IS NOT NULL BEGIN "
                            f"ALTER DATABASE {q(db)} SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE {q(db)} END")
    finally:
        con.close()
    return made


def input_parquets(synth: Path) -> list[Path]:
    return sorted(p for d in sorted((Path(synth) / "sources").glob("db[0-9][0-9]")) if d.is_dir()
                  for p in d.glob("*.parquet"))


def attested_input_hashes(synth: Path, home) -> dict[str, str]:
    """{file: sha256} of every input Parquet file; exits unless each one is registered output of ``synth``."""
    from tripline_scope.core.canonical import sha256_file
    from tripline_scope.investigator.synthetic import registered

    reg = registered(home)
    files = input_parquets(synth)
    if not files:
        raise SystemExit("no input Parquet files to attest from")
    hashes = {str(f): sha256_file(f) for f in files}
    bad = [f for f, h in hashes.items() if reg.get(h, {}).get("generator") != "synth"]
    if bad:
        raise SystemExit(f"--attest refused: {len(bad)} of {len(files)} input file(s) are not attested output of "
                         "'tscope synth --attest' on this installation")
    return hashes


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--synth", required=True, help="synthetic dataset directory (contains sources/dbNN/)")
    p.add_argument("--out", required=True, help="directory for the .bak files")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=14330)
    p.add_argument("--login", default="sa")
    p.add_argument("--password-env", required=True, help="environment variable holding the password")
    p.add_argument("--container", required=True, help="Docker container running SQL Server")
    p.add_argument("--server-backup-dir", default="/var/opt/mssql/backup/tscope-build")
    p.add_argument("--db-prefix", default="", help="prefix for build database names (e.g. ingest_ in tests)")
    p.add_argument("--attest", action="store_true",
                   help="require attested synthetic inputs and record each written .bak in the synthetic-origin "
                        "registry (needs TSCOPE_HOME and the KEK passphrase)")
    args = p.parse_args(argv)
    home = inputs = None
    if args.attest:
        from tripline_scope.core.home import Home

        home = Home()
        inputs = attested_input_hashes(Path(args.synth), home)
    made = build(args)
    print(f"{len(made)} backup(s) written to {args.out}")
    if args.attest:
        from tripline_scope.core.canonical import canonical_bytes, sha256_hex
        from tripline_scope.investigator.synthetic import attest_outputs

        if attested_input_hashes(Path(args.synth), home) != inputs:
            raise SystemExit("--attest refused: input files changed during the build")
        n = attest_outputs(home, "lab-bak", {"inputs_sha256": sha256_hex(canonical_bytes(sorted(inputs.values()))),
                                             "db_prefix": args.db_prefix}, made)
        print(f"attested {n} backup(s) built from {len(inputs)} attested synthetic input file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
