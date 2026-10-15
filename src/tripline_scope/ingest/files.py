"""Readers for vendor-system exports and leak samples: CSV, TSV, XLSX, JSON Lines and JSON arrays.

* Reference sources are opened read-only (``rb``); encrypted copies are decrypted as a stream through the case
  store. No plaintext copy is ever written.
* Bounded: maximum bytes per file, rows per table, bytes per field, XLSX uncompressed size / compression ratio
  and JSON-array size (installation ``ingest`` limits). Exceeding a limit stops the command with an error
  instead of silently undercounting.
* Malformed rows (wrong field count, invalid JSON, non-object lines) are counted, never echoed.
* Each file is one table (each worksheet for XLSX); row order is file order.
"""

from __future__ import annotations

import codecs
import csv
import io
import json
import zipfile
from collections.abc import Iterator
from pathlib import PurePath

import pyarrow as pa

from tripline_scope.core import custody
from tripline_scope.core.errors import ConfigError

from .config import IngestLimits
from .model import ColumnInfo, TableRef, batch_from_columns, to_str

FILE_KINDS = ("csv", "tsv", "xlsx", "jsonl", "json")
_DELIMS = (",", ";", "|", "\t")


def _dedupe(names: list[str]) -> list[str]:
    out, seen = [], {}
    for i, raw in enumerate(names):
        n = (raw or "").strip() or f"column_{i + 1}"
        k = n.lower()
        if k in seen:
            seen[k] += 1
            n = f"{n}_{seen[k]}"
        else:
            seen[k] = 1
        out.append(n[:128])
    return out


def _sniff_encoding(head: bytes) -> str:
    if head.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    try:
        head.decode("utf-8")
        return "utf-8"
    except UnicodeDecodeError as exc:
        # a multi-byte character cut at the end of the probe is still UTF-8
        if exc.start >= len(head) - 3:
            return "utf-8"
        return "cp1252"


def _sniff_delimiter(line: str) -> str:
    counts = {}
    for d in _DELIMS:
        inq, n = False, 0
        for ch in line:
            if ch == '"':
                inq = not inq
            elif ch == d and not inq:
                n += 1
        counts[d] = n
    best = max(_DELIMS, key=lambda d: (counts[d], -_DELIMS.index(d)))
    return best if counts[best] > 0 else ","


class FileReader:
    engine = "file"

    def __init__(self, case, store, source: dict, limits: IngestLimits):
        self.case, self.store, self.source, self.limits = case, store, source, limits
        self.kind = source["kind"]
        if self.kind not in FILE_KINDS:
            raise ConfigError(f"source kind {self.kind} is not a file export")
        self._stats: dict[str, dict] = {}
        self._tables: list[TableRef] | None = None
        csv.field_size_limit(max(limits.max_field_bytes, 1024))

    # ------------------------------------------------------------------ plumbing
    def _open(self, fentry: dict):
        size = int(fentry.get("size") or 0)
        if size > self.limits.max_bytes_per_file:
            raise ConfigError(f"file {fentry['name']} is larger than the configured limit "
                              f"({self.limits.max_bytes_per_file} bytes); raise ingest.max_bytes_per_file")
        raw = custody.open_source_file(self.case, self.store, self.source["source_id"], fentry["name"])
        if isinstance(raw, io.BufferedReader):
            return raw
        return io.BufferedReader(raw, buffer_size=1 << 20)

    def _files(self) -> list[dict]:
        files = [f for f in self.source.get("files", []) if f.get("kind") != "directory"]
        if not files:
            raise ConfigError(f"source {self.source['source_id']} has no files")
        return files

    def table_stats(self, table: TableRef) -> dict:
        return self._stats.get(table.slug or table.name, {})

    def _set_stats(self, table: TableRef, **kw) -> None:
        self._stats[table.slug or table.name] = kw

    def count_rows(self, table: TableRef) -> int | None:
        n = 0
        for b in self.iter_batches(table, self.limits.batch_rows):
            n += b.num_rows
        return n

    def close(self) -> None:
        return None

    # ------------------------------------------------------------------ listing
    def tables(self) -> list[TableRef]:
        if self._tables is not None:
            return list(self._tables)
        out: list[TableRef] = []
        for f in self._files():
            stem = PurePath(f["name"]).stem
            if self.kind in ("csv", "tsv"):
                out.append(self._csv_table(f, stem))
            elif self.kind == "xlsx":
                out.extend(self._xlsx_tables(f, stem))
            elif self.kind == "jsonl":
                out.append(self._jsonl_table(f, stem))
            else:
                out.append(self._json_table(f, stem))
        self._tables = out
        return list(out)

    def iter_batches(self, table: TableRef, batch_rows: int, limit: int | None = None) -> Iterator[pa.RecordBatch]:
        kind = self.kind
        if kind in ("csv", "tsv"):
            yield from self._csv_batches(table, batch_rows, limit)
        elif kind == "xlsx":
            yield from self._xlsx_batches(table, batch_rows, limit)
        elif kind == "jsonl":
            yield from self._jsonl_batches(table, batch_rows, limit)
        else:
            yield from self._json_batches(table, batch_rows, limit)

    # ------------------------------------------------------------------ CSV / TSV
    def _csv_text(self, fentry: dict):
        fh = self._open(fentry)
        head = fh.peek(1 << 20)[: 1 << 20]
        enc = _sniff_encoding(head)
        return fh, io.TextIOWrapper(fh, encoding=enc, errors="replace", newline="")

    def _csv_table(self, f: dict, stem: str) -> TableRef:
        fh, text = self._csv_text(f)
        try:
            first = text.readline(self.limits.max_field_bytes)
        finally:
            text.close()
        delim = "\t" if self.kind == "tsv" else _sniff_delimiter(first)
        try:
            header = next(csv.reader([first], delimiter=delim))
        except (csv.Error, StopIteration):
            raise ConfigError(f"file {f['name']}: header row could not be parsed") from None
        cols = [ColumnInfo(n, "text") for n in _dedupe(header)]
        if not cols:
            raise ConfigError(f"file {f['name']}: no header row")
        return TableRef(stem, cols, handle={"file": f, "delimiter": delim}, kind="file")

    def _csv_batches(self, table: TableRef, batch_rows: int, limit: int | None):
        f, delim = table.handle["file"], table.handle["delimiter"]
        ncols = len(table.columns)
        fh, text = self._csv_text(f)
        rows = malformed = 0
        cols: list[list[str | None]] = [[] for _ in range(ncols)]
        try:
            reader = csv.reader(text, delimiter=delim, quotechar='"', strict=False)
            try:
                next(reader)  # header
            except StopIteration:
                return
            while True:
                try:
                    rec = next(reader)
                except StopIteration:
                    break
                except csv.Error:
                    raise ConfigError(f"file {f['name']}: unreadable CSV structure after data row {rows} "
                                      "(field too large or broken quoting)") from None
                if not rec:
                    continue
                if len(rec) != ncols:
                    malformed += 1
                    rec = (rec + [None] * ncols)[:ncols]
                for i in range(ncols):
                    v = rec[i]
                    cols[i].append(v if v is not None and v.strip() != "" else None)
                rows += 1
                if rows > self.limits.max_rows_per_table:
                    raise ConfigError(f"file {f['name']} has more rows than the configured limit "
                                      f"({self.limits.max_rows_per_table}); raise ingest.max_rows_per_table")
                if limit is not None and rows >= limit:
                    break
                if len(cols[0]) >= batch_rows:
                    yield batch_from_columns(cols, ncols)
                    cols = [[] for _ in range(ncols)]
            if cols and cols[0]:
                yield batch_from_columns(cols, ncols)
        finally:
            text.close()
        if limit is None:
            self._set_stats(table, rows=rows, malformed_rows=malformed, encoding=None)

    # ------------------------------------------------------------------ XLSX
    def _xlsx_guard(self, f: dict) -> None:
        fh = self._open(f)
        try:
            try:
                zf = zipfile.ZipFile(fh)
            except zipfile.BadZipFile:
                raise ConfigError(f"file {f['name']} is not a valid XLSX workbook") from None
            total = comp = 0
            for info in zf.infolist():
                total += info.file_size
                comp += info.compress_size
            if total > self.limits.xlsx_max_uncompressed_bytes:
                raise ConfigError(f"workbook {f['name']} expands beyond the configured limit; "
                                  "raise ingest.xlsx_max_uncompressed_bytes")
            if comp and total / comp > self.limits.xlsx_max_ratio:
                raise ConfigError(f"workbook {f['name']} has a suspicious compression ratio (refused)")
        finally:
            fh.close()

    def _workbook(self, f: dict):
        import openpyxl

        fh = self._open(f)
        wb = openpyxl.load_workbook(fh, read_only=True, data_only=True, keep_links=False)
        return fh, wb

    def _xlsx_tables(self, f: dict, stem: str) -> list[TableRef]:
        self._xlsx_guard(f)
        fh, wb = self._workbook(f)
        out = []
        try:
            sheets = wb.sheetnames
            for sheet in sheets:
                ws = wb[sheet]
                header, peek = None, []
                for row in ws.iter_rows(values_only=True):
                    if header is None:
                        if row and any(v is not None and str(v).strip() for v in row):
                            header = [to_str(v) or "" for v in row]
                        continue
                    peek.append(row)
                    if len(peek) >= 200:
                        break
                if header is None:
                    continue
                while header and not header[-1]:
                    header.pop()
                names = _dedupe(header)
                cols = []
                for i, n in enumerate(names):
                    vals = [r[i] for r in peek if i < len(r) and r[i] is not None]
                    numeric = bool(vals) and sum(isinstance(v, int | float) and not isinstance(v, bool)
                                                 for v in vals) / len(vals) >= 0.5
                    cols.append(ColumnInfo(n, "number" if numeric else "cell", numeric=numeric))
                name = stem if len(sheets) == 1 else f"{stem}.{sheet}"
                out.append(TableRef(name, cols, handle={"file": f, "sheet": sheet}, kind="file"))
        finally:
            wb.close()
            fh.close()
        return out

    def _xlsx_batches(self, table: TableRef, batch_rows: int, limit: int | None):
        f, sheet = table.handle["file"], table.handle["sheet"]
        ncols = len(table.columns)
        fh, wb = self._workbook(f)
        rows = malformed = 0
        cols: list[list[str | None]] = [[] for _ in range(ncols)]
        try:
            ws = wb[sheet]
            seen_header = False
            for row in ws.iter_rows(values_only=True):
                if not seen_header:
                    if row and any(v is not None and str(v).strip() for v in row):
                        seen_header = True
                    continue
                if not row or all(v is None for v in row):
                    continue
                if len(row) > ncols and any(v is not None for v in row[ncols:]):
                    malformed += 1
                for i in range(ncols):
                    cols[i].append(to_str(row[i]) if i < len(row) else None)
                rows += 1
                if rows > self.limits.max_rows_per_table:
                    raise ConfigError(f"worksheet in {f['name']} has more rows than the configured limit")
                if limit is not None and rows >= limit:
                    break
                if len(cols[0]) >= batch_rows:
                    yield batch_from_columns(cols, ncols)
                    cols = [[] for _ in range(ncols)]
            if cols[0]:
                yield batch_from_columns(cols, ncols)
        finally:
            wb.close()
            fh.close()
        if limit is None:
            self._set_stats(table, rows=rows, malformed_rows=malformed)

    # ------------------------------------------------------------------ JSON Lines / JSON
    @staticmethod
    def _flatten(obj: dict, prefix: str = "", depth: int = 0, out: dict | None = None) -> dict:
        out = {} if out is None else out
        for k, v in obj.items():
            key = f"{prefix}{k}"
            if isinstance(v, dict) and depth < 3:
                FileReader._flatten(v, key + ".", depth + 1, out)
            else:
                out[key] = v
        return out

    def _jsonl_records(self, f: dict) -> Iterator[dict | None]:
        fh = self._open(f)
        try:
            for raw in fh:
                if len(raw) > self.limits.max_field_bytes * 16:
                    yield None
                    continue
                line = raw.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    yield None
                    continue
                yield self._flatten(obj) if isinstance(obj, dict) else None
        finally:
            fh.close()

    def _keys_table(self, f: dict, stem: str, records: Iterator[dict | None]) -> TableRef:
        keys: dict[str, None] = {}
        n = 0
        for rec in records:
            n += 1
            if n > self.limits.max_rows_per_table:
                raise ConfigError(f"file {f['name']} has more records than the configured limit")
            if rec:
                for k in rec:
                    if k not in keys:
                        if len(keys) >= 2000:
                            raise ConfigError(f"file {f['name']} has more than 2000 distinct fields (refused)")
                        keys[k] = None
        if not keys:
            raise ConfigError(f"file {f['name']}: no JSON objects found")
        names = list(keys)
        return TableRef(stem, [ColumnInfo(k[:128], "json") for k in names], handle={"file": f, "keys": names},
                        kind="file")

    def _jsonl_table(self, f: dict, stem: str) -> TableRef:
        return self._keys_table(f, stem, self._jsonl_records(f))

    def _record_batches(self, table: TableRef, records, batch_rows: int, limit: int | None):
        keys = table.handle["keys"]
        ncols = len(keys)
        rows = malformed = 0
        cols: list[list[str | None]] = [[] for _ in range(ncols)]
        for rec in records:
            if rec is None:
                malformed += 1
                continue
            for i, k in enumerate(keys):
                cols[i].append(to_str(rec.get(k)))
            rows += 1
            if limit is not None and rows >= limit:
                break
            if len(cols[0]) >= batch_rows:
                yield batch_from_columns(cols, ncols)
                cols = [[] for _ in range(ncols)]
        if cols[0]:
            yield batch_from_columns(cols, ncols)
        if limit is None:
            self._set_stats(table, rows=rows, malformed_rows=malformed)

    def _jsonl_batches(self, table: TableRef, batch_rows: int, limit: int | None):
        yield from self._record_batches(table, self._jsonl_records(table.handle["file"]), batch_rows, limit)

    def _json_records(self, f: dict) -> Iterator[dict | None]:
        if int(f.get("size") or 0) > self.limits.json_array_max_bytes:
            raise ConfigError(f"JSON file {f['name']} is larger than ingest.json_array_max_bytes; "
                              "convert it to JSON Lines")
        fh = self._open(f)
        try:
            data = fh.read(self.limits.json_array_max_bytes + 1)
        finally:
            fh.close()
        if len(data) > self.limits.json_array_max_bytes:
            raise ConfigError(f"JSON file {f['name']} is larger than ingest.json_array_max_bytes")
        try:
            doc = json.loads(data)
        except ValueError:
            raise ConfigError(f"file {f['name']} is not valid JSON") from None
        del data
        if isinstance(doc, dict):
            lists = [v for v in doc.values() if isinstance(v, list)]
            doc = lists[0] if len(lists) == 1 else None
        if not isinstance(doc, list):
            raise ConfigError(f"file {f['name']}: expected a JSON array of objects")
        for item in doc:
            yield self._flatten(item) if isinstance(item, dict) else None

    def _json_table(self, f: dict, stem: str) -> TableRef:
        return self._keys_table(f, stem, self._json_records(f))

    def _json_batches(self, table: TableRef, batch_rows: int, limit: int | None):
        yield from self._record_batches(table, self._json_records(table.handle["file"]), batch_rows, limit)
