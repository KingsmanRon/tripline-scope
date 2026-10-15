"""Reader model shared by every ingest path (files, restored SQL Server / PostgreSQL copies, live reads).

A reader lists tables and yields Arrow record batches in a **deterministic row order** (so ``_row_key``
ordinals are stable across runs). Every value is delivered as a string (or null), in memory only; batches carry
positional column names ``c0..cN`` (index into :attr:`TableRef.columns`) so arbitrary source column names
never reach SQL text. Binary / unsupported columns are never read (all-null in batches).
"""

from __future__ import annotations

import datetime as dt
import decimal
import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol

import pyarrow as pa


@dataclass
class ColumnInfo:
    name: str
    data_type: str = "text"
    numeric: bool = False
    readable: bool = True


@dataclass
class TableRef:
    name: str
    columns: list[ColumnInfo]
    database: str | None = None
    schema: str | None = None
    key: list[str] = field(default_factory=list)   # columns that give a unique, deterministic order
    handle: object = None                           # reader-specific (file name, sheet, quoted identifier)
    slug: str = ""
    estimated_rows: int | None = None
    kind: str = "table"

    @property
    def label(self) -> str:
        return ".".join(p for p in (self.database, self.schema, self.name) if p)

    def matches(self, wanted: str) -> bool:
        w = wanted.strip().lower()
        names = {self.name.lower(), self.label.lower(), self.slug.lower()}
        if self.schema:
            names.add(f"{self.schema}.{self.name}".lower())
        return w in names


class Reader(Protocol):
    engine: str

    def tables(self) -> list[TableRef]: ...

    def iter_batches(self, table: TableRef, batch_rows: int, limit: int | None = None) -> Iterator[pa.RecordBatch]: ...

    def count_rows(self, table: TableRef) -> int | None: ...

    def close(self) -> None: ...


# ------------------------------------------------------------------------------------------ conversion
def to_str(v: object) -> str | None:
    """Canonical string form of a source value (memory only)."""
    if v is None:
        return None
    if isinstance(v, str):
        return v if v.strip() != "" else None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            return None
        return str(int(v)) if v.is_integer() and abs(v) < 1e18 else repr(v)
    if isinstance(v, decimal.Decimal):
        if v == v.to_integral_value() and abs(v) < 10**20:
            return str(int(v))
        return str(v)
    if isinstance(v, dt.datetime):
        if v.hour == v.minute == v.second == v.microsecond == 0:
            return v.date().isoformat()
        return v.replace(tzinfo=None).isoformat(sep=" ")
    if isinstance(v, dt.date):
        return v.isoformat()
    if isinstance(v, dt.time):
        return v.isoformat()
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, bytes | bytearray | memoryview):
        return None
    if isinstance(v, dict | list):
        import json

        return json.dumps(v, sort_keys=True, default=str)
    return str(v)


def batch_from_columns(cols: list[list[str | None]], ncols: int) -> pa.RecordBatch:
    arrays = [pa.array(cols[i] if i < len(cols) else [], type=pa.string()) for i in range(ncols)]
    if cols and any(len(c) != len(cols[0]) for c in cols):
        raise ValueError("ragged batch")
    return pa.RecordBatch.from_arrays(arrays, names=[f"c{i}" for i in range(ncols)])


def batch_from_rows(rows: list[tuple | list], table: TableRef, converters=None) -> pa.RecordBatch:
    n = len(table.columns)
    cols: list[list[str | None]] = [[] for _ in range(n)]
    readable = [c.readable for c in table.columns]
    for row in rows:
        for i in range(n):
            cols[i].append(to_str(row[i]) if readable[i] and i < len(row) else None)
    return batch_from_columns(cols, n)


def empty_batch(table: TableRef) -> pa.RecordBatch:
    return batch_from_columns([[] for _ in table.columns], len(table.columns))


# ------------------------------------------------------------------------------------------ slugs
def slugify(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return s[:60] or "table"


def assign_slugs(tables: list[TableRef]) -> None:
    """Unique, filesystem-safe slugs within one source (``dbo.patients`` -> ``dbo_patients``)."""
    seen: dict[str, int] = {}
    for t in tables:
        base = slugify(".".join(p for p in (t.schema, t.name) if p) if t.kind == "table" else t.name)
        n = seen.get(base, 0)
        seen[base] = n + 1
        t.slug = base if n == 0 else f"{base}_{n + 1}"
