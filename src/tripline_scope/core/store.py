"""Encrypted case store: every file under ``work/``, ``review/``, ``notify/`` and encrypted source copies is
an authenticated envelope (see :mod:`tripline_scope.core.crypto`). Parquet is written and read through the
envelope stream, so no plaintext Parquet ever touches disk.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from .canonical import canonical_bytes, sha256_file
from .case import Case
from .crypto import EnvelopeReader, EnvelopeWriter, Fingerprinter
from .errors import ConfigError

SUFFIX = ".tse"
_WRITABLE_ROOTS = ("work", "review", "notify", "sources")


class CaseStore:
    def __init__(self, case: Case, dek: bytes):
        self.case = case
        self._dek = dek

    # ------------------------------------------------------------------ paths
    def path(self, rel: str) -> Path:
        rel = rel.strip("/")
        if not rel.endswith(SUFFIX):
            rel += SUFFIX
        parts = Path(rel).parts
        if not parts or parts[0] not in _WRITABLE_ROOTS or ".." in parts:
            raise ConfigError(f"store path must live under {_WRITABLE_ROOTS}: {rel}")
        return self.case.root / rel

    def logical(self, rel: str) -> str:
        rel = rel.strip("/")
        return rel if rel.endswith(SUFFIX) else rel + SUFFIX

    def exists(self, rel: str) -> bool:
        return self.path(rel).exists()

    def list(self, rel_dir: str, pattern: str = "*") -> list[str]:
        base = self.case.root / rel_dir.strip("/")
        if not base.exists():
            return []
        return sorted(
            p.relative_to(self.case.root).as_posix()
            for p in base.rglob(pattern + SUFFIX if not pattern.endswith(SUFFIX) else pattern)
            if p.is_file()
        )

    def delete(self, rel: str) -> None:
        self.path(rel).unlink(missing_ok=True)

    def file_sha256(self, rel: str) -> str:
        """SHA-256 of the encrypted file (what the audit log records as an output hash)."""
        return sha256_file(self.path(rel))

    def fingerprinter(self, purpose: str = "default") -> Fingerprinter:
        return Fingerprinter(self._dek, purpose)

    # ------------------------------------------------------------------ bytes / json
    @contextmanager
    def open_write(self, rel: str) -> Iterator[EnvelopeWriter]:
        w = EnvelopeWriter(self.path(rel), self._dek, self.logical(rel))
        with w:
            yield w

    def open_read(self, rel: str) -> EnvelopeReader:
        return EnvelopeReader(self.path(rel), self._dek, self.logical(rel))

    def write_bytes(self, rel: str, data: bytes) -> str:
        with self.open_write(rel) as w:
            w.write(data)
        return self.file_sha256(rel)

    def read_bytes(self, rel: str) -> bytes:
        with self.open_read(rel) as r:
            return r.readall()

    def write_json(self, rel: str, obj) -> str:
        return self.write_bytes(rel, canonical_bytes(obj))

    def read_json(self, rel: str):
        return json.loads(self.read_bytes(rel))

    def write_jsonl(self, rel: str, rows) -> str:
        with self.open_write(rel) as w:
            for row in rows:
                w.write(canonical_bytes(row) + b"\n")
        return self.file_sha256(rel)

    def read_jsonl(self, rel: str) -> Iterator[dict]:
        with self.open_read(rel) as r:
            for line in io.BufferedReader(r).read().split(b"\n"):
                if line:
                    yield json.loads(line)

    # ------------------------------------------------------------------ parquet
    def write_table(self, rel: str, table: pa.Table, *, row_group_size: int = 256_000) -> str:
        with self.open_write(rel) as w:
            pq.write_table(table, pa.PythonFile(w, mode="w"), row_group_size=row_group_size, compression="zstd")
        return self.file_sha256(rel)

    @contextmanager
    def table_writer(self, rel: str, schema: pa.Schema) -> Iterator[pq.ParquetWriter]:
        """Stream record batches into one encrypted Parquet file."""
        with self.open_write(rel) as w:
            pw = pq.ParquetWriter(pa.PythonFile(w, mode="w"), schema, compression="zstd")
            try:
                yield pw
            finally:
                pw.close()

    def read_table(self, rel: str, columns: list[str] | None = None) -> pa.Table:
        with self.open_read(rel) as r:
            return pq.read_table(pa.PythonFile(r, mode="r"), columns=columns)

    def iter_batches(self, rel: str, columns: list[str] | None = None, batch_size: int = 65536) -> Iterator[pa.RecordBatch]:
        with self.open_read(rel) as r:
            pf = pq.ParquetFile(pa.PythonFile(r, mode="r"))
            yield from pf.iter_batches(batch_size=batch_size, columns=columns)

    def read_tables(self, rels: list[str], columns: list[str] | None = None) -> pa.Table:
        tables = [self.read_table(r, columns) for r in rels]
        return pa.concat_tables(tables, promote_options="default") if tables else pa.table({})


def open_store(case: Case, home) -> CaseStore:
    return CaseStore(case, case.dek(home))
