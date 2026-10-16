"""Hardened DuckDB connections.

* in-memory only; ``temp_directory`` is empty so nothing spills to disk in plaintext, unless the installation
  config names a spill directory **and** attests that it is on an encrypted volume;
* extension auto-install/auto-load and community extensions are off (no network, ever);
* external access is off: DuckDB can read only the files passed in ``read_paths`` and can write nothing;
* configuration is locked after setup so later SQL cannot loosen it.

DuckDB's own database/Parquet encryption is deliberately not used: in the pinned 1.5.x it needs the
``httpfs`` extension (downloaded at runtime) for secure writes, and its fallback is documented as insecure.
"""

from __future__ import annotations

import os
from collections.abc import Iterable

import duckdb

from .identifiers import DUCKDB_MACROS


def connect(
    *,
    read_paths: Iterable[str | os.PathLike] = (),
    memory_limit: str | None = None,
    threads: int | None = None,
    spill_dir: str | None = None,
    spill_dir_encrypted: bool = False,
    lock: bool = True,
) -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(
        ":memory:",
        config={
            "autoinstall_known_extensions": False,
            "autoload_known_extensions": False,
            "allow_community_extensions": False,
            "temp_directory": spill_dir if (spill_dir and spill_dir_encrypted) else "",
        },
    )
    if memory_limit:
        con.execute("SET memory_limit = ?", [memory_limit])
    if threads:
        con.execute(f"SET threads = {int(threads)}")
    con.execute("SET enable_progress_bar = false")
    con.execute("SET preserve_insertion_order = true")
    for stmt in DUCKDB_MACROS.strip().split(";\n"):
        if stmt.strip():
            con.execute(stmt)
    paths = [os.fspath(p) for p in read_paths]
    if paths:
        con.execute("SET allowed_paths = ?", [paths])
    con.execute("SET enable_external_access = false")
    if lock:
        con.execute("SET lock_configuration = true")
    return con


def connect_for_home(home, **kw) -> duckdb.DuckDBPyConnection:
    d = (home.config.get("duckdb") or {}) if home is not None else {}
    return connect(
        memory_limit=kw.pop("memory_limit", None) or d.get("memory_limit"),
        threads=kw.pop("threads", None) or d.get("threads"),
        spill_dir=d.get("spill_dir"),
        spill_dir_encrypted=bool(d.get("spill_dir_encrypted")),
        **kw,
    )
