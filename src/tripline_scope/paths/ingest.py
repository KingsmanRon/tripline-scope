"""``tscope paths ingest``: register hospital-exported logs as custody sources and normalise them.

For each manifest source: register it via :mod:`tripline_scope.core.custody` (kind ``log``, evidence role
``log`` or ``reference_data`` for indicators; reused when the same path is already registered), read every file
read-only while re-computing its SHA-256 (a mismatch with the custody hash aborts the ingest), parse it with
the family parser, and write ``work/paths/events/<SRC>.parquet`` (encrypted) and
``work/paths/coverage/<SRC>.json``. Indicators go to ``work/paths/indicators/<SRC>.json``; corroborations to
``work/paths/corroborations.json``.
"""

from __future__ import annotations

import hashlib
import io
import os
import time
from collections import Counter
from pathlib import Path

import pyarrow as pa

from tripline_scope.core import custody
from tripline_scope.core.canonical import canonical_bytes, sha256_file, sha256_hex
from tripline_scope.core.errors import ConfigError, IntegrityError

from . import parsers
from .config import load_config, validate
from .manifest import Corroboration, Manifest, SourceSpec, load_manifest
from .parsers.base import ParseContext, raw_hash
from .schema import DATA_OBSERVATIONS, EVENT_SCHEMA, FIELD_NAMES, NOT_APPLICABLE, OBS_CONSEQUENCE
from .timenorm import normalise, to_iso

BATCH = 50_000


class _HashingReader(io.RawIOBase):
    def __init__(self, raw):
        super().__init__()
        self._raw = raw
        self.sha = hashlib.sha256()
        self.size = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b) -> int:
        data = self._raw.read(len(b))
        if not data:
            return 0
        n = len(data)
        b[:n] = data
        self.sha.update(data)
        self.size += n
        return n

    def drain(self) -> None:
        while True:
            data = self._raw.read(1 << 20)
            if not data:
                break
            self.sha.update(data)
            self.size += len(data)

    # close() (from wrappers inside parsers) leaves the underlying file open: the driver drains and closes it.


def event_consequence(obs: str, objects: list, outcome: str) -> str:
    if outcome == "failure" and (obs in DATA_OBSERVATIONS or obs in ("auditing_disabled", "log_cleared")):
        return NOT_APPLICABLE
    if obs in ("select", "modify", "execute") and not objects:
        return NOT_APPLICABLE
    return OBS_CONSEQUENCE.get(obs, NOT_APPLICABLE)


class _Columns:
    def __init__(self, writer, spec: SourceSpec, source_id: str, parser: str, staging_exts: set[str]):
        self.writer = writer
        self.spec = spec
        self.sid = source_id
        self.parser = parser
        self.staging = staging_exts
        self.cols: dict[str, list] = {n: [] for n in FIELD_NAMES}
        self.count = 0
        self.first = None
        self.last = None
        self.unplaced = 0
        self.flag_counts: Counter = Counter()
        self.obs_counts: Counter = Counter()
        self.class_counts: Counter = Counter()

    def add(self, rec: dict, ordinal: int) -> None:
        ts, prec, abbr = rec.pop("_ts")
        tr = normalise(ts, prec, self.spec.zone, record_abbrev=abbr)
        raw = rec.pop("_raw")
        loc = rec.pop("_loc")
        obs = rec.get("observation_type") or "other"
        if obs == "file_write":
            ref = rec.get("object_name") or ""
            ext = ref.split(":")[1] if ref.startswith("file:") else ""
            if ext in self.staging:
                obs = "file_staged"
        objects = [o for o in (rec.get("objects") or []) if o]
        outcome = rec.get("outcome") or "unknown"
        cls = event_consequence(obs, objects, outcome)
        flags = sorted(set(rec.get("flags") or []) | set(tr.flags))
        if outcome == "failure" and obs in DATA_OBSERVATIONS:
            flags = sorted(set(flags) | {"failed_attempt"})
        row = {
            "event_id": f"{self.sid}:{ordinal}", "source_id": self.sid, "source_family": self.spec.family,
            "ordinal": ordinal, "ts_original_text": None, "tz_original": tr.tz_original, "ts_utc": tr.ts_utc,
            "clock_offset_s": float(self.spec.zone.clock_offset_s or 0.0), "ts_uncertainty_s": tr.uncertainty_s,
            "time_precision": tr.precision, "parser": self.parser, "raw_sha256": raw_hash(raw),
            "consequence_class": cls, "record_locator": loc, "tz_basis": tr.tz_basis, "ts_utc_min": tr.ts_min,
            "ts_utc_max": tr.ts_max, "objects": objects, "flags": flags, "observation_type": obs,
            "outcome": outcome, "mfa": rec.get("mfa") or "unknown",
        }
        if ts is not None:
            row["ts_original_text"] = _original_text(ts, prec, abbr)
        for k in FIELD_NAMES:
            if k not in row:
                v = rec.get(k)
                row[k] = v[:512] if isinstance(v, str) else v
        if row["object_name"] is None and objects:
            row["object_name"] = objects[0]
        for k in FIELD_NAMES:
            self.cols[k].append(row[k])
        self.count += 1
        if tr.ts_utc is None:
            self.unplaced += 1
        else:
            if self.first is None or tr.ts_utc < self.first:
                self.first = tr.ts_utc
            if self.last is None or tr.ts_utc > self.last:
                self.last = tr.ts_utc
        for f in tr.flags:
            self.flag_counts[f] += 1
        self.obs_counts[obs] += 1
        self.class_counts[cls] += 1
        if len(self.cols["event_id"]) >= BATCH:
            self.flush()

    def flush(self) -> None:
        if not self.cols["event_id"]:
            return
        batch = pa.RecordBatch.from_pydict(self.cols, schema=EVENT_SCHEMA)
        self.writer.write_batch(batch)
        self.cols = {n: [] for n in FIELD_NAMES}


def _original_text(ts, prec, abbr) -> str:
    """The timestamp as the record expressed it (re-rendered from the parsed value, zone kept)."""
    text = ts.isoformat(sep=" ", timespec="milliseconds" if prec == "millisecond" else "seconds")
    return f"{text} {abbr}" if abbr else text


# ---------------------------------------------------------------------------------------------- custody
def _find_registered(case, spec: SourceSpec) -> dict | None:
    if spec.source_id:
        return case.source(spec.source_id)
    target = str(spec.path)
    for s in case.sources():
        for f in s.get("files", []):
            if f.get("path") and os.path.realpath(f["path"]) == target:
                return s
        if spec.copy and (s.get("paths") or {}).get("label") == spec.label:
            return s
    return None


def _register(case, store, spec: SourceSpec, actor: str) -> tuple[dict, bool]:
    existing = _find_registered(case, spec)
    if existing is not None:
        return existing, False
    rec = custody.add_source(
        case, store, kind="log", paths=[spec.path], label=f"{spec.family}:{spec.label}",
        evidence_role=spec.evidence_role, legal_basis=spec.legal_basis, supplied_by=spec.supplied_by,
        received_at=spec.received_at, registered_by=actor, mode="encrypted_copy" if spec.copy else "reference",
        extra={"paths": {"label": spec.label, "family": spec.family, "format": spec.format}},
    )
    return rec, True


def _files(case, store, source: dict):
    """Yield (relname, expected sha256, opener) for every regular file of a registered source."""
    sid = source["source_id"]
    for f in source.get("files", []):
        if f.get("kind") == "directory":
            tree = store.read_json(f"sources/{sid}/tree.json")
            root = Path(f["path"])
            for e in tree["files"]:
                if e.get("symlink"):
                    continue
                p = root / e["name"]
                yield e["name"], e["sha256"], (lambda p=p: open(p, "rb"))  # noqa: SIM115
        else:
            yield f["name"], f["sha256"], (lambda n=f["name"]: custody.open_source_file(case, store, sid, n))


# ---------------------------------------------------------------------------------------------- main
def run_ingest(ctx, manifest_path) -> dict:
    case, store = ctx.case, ctx.store
    manifest: Manifest = load_manifest(manifest_path)
    ctx.input("logs_manifest", sha256_file(manifest.path))
    applied = _apply_manifest_config(case, manifest)
    if applied:
        ctx.note("manifest supplied case.yaml paths keys: " + ",".join(applied))
    cfg = load_config(case)
    staging = {str(x).lower() for x in cfg["staging_extensions"]}
    sql_fp = store.fingerprinter("paths-sql")
    file_fp = store.fingerprinter("paths-file")
    summary = {"sources": [], "events": 0, "parse_failures": 0, "indicators": 0, "indicators_rejected": 0}
    index = store.read_json("work/paths/sources.json") if store.exists("work/paths/sources.json") else {}
    label_to_sid: dict[str, str] = {}
    started = time.perf_counter()
    for spec in manifest.sources:
        source, created = _register(case, store, spec, ctx.actor)
        sid = source["source_id"]
        label_to_sid[spec.label] = sid
        pname = parsers.parser_name(spec.family)
        pctx = ParseContext(source_id=sid, family=spec.family, fmt=spec.format, host=spec.host,
                            options=spec.options, mapping=spec.mapping, sql_fp=sql_fp, file_fp=file_fp, parser=pname)
        mod = parsers.REGISTRY[spec.family]
        file_hashes = []
        t0 = time.perf_counter()
        if spec.family == "indicators":
            indicators = []
            for relname, expected, opener in _files(case, store, source):
                raw = opener()
                try:
                    hr = _HashingReader(raw)
                    indicators += mod.parse(pctx, io.BufferedReader(hr, 1 << 20), relname)
                    hr.drain()
                finally:
                    raw.close()
                _check_hash(sid, relname, hr, expected)
                file_hashes.append({"name": relname, "sha256": expected, "size": hr.size})
            doc = {"source_id": sid, "provenance_required": True, "indicators": indicators,
                   "rejected": pctx.rejected, "parser": pname}
            ctx.output(f"indicators/{sid}", store.write_json(f"work/paths/indicators/{sid}.json", doc))
            cov = {"source_id": sid, "label": spec.label, "family": spec.family, "format": spec.format,
                   "parser": pname, "files": file_hashes, "indicators": len(indicators),
                   "rejected": len(pctx.rejected), "rejected_samples": pctx.rejected[:50],
                   "parse_failures": pctx.failures}
            summary["indicators"] += len(indicators)
            summary["indicators_rejected"] += len(pctx.rejected)
        else:
            ordinal = 0
            with store.table_writer(f"work/paths/events/{sid}.parquet", EVENT_SCHEMA) as pw:
                cols = _Columns(pw, spec, sid, pname, staging)
                for relname, expected, opener in _files(case, store, source):
                    raw = opener()
                    try:
                        hr = _HashingReader(raw)
                        for rec in mod.parse(pctx, io.BufferedReader(hr, 1 << 20), relname):
                            ordinal += 1
                            cols.add(rec, ordinal)
                        hr.drain()
                    finally:
                        raw.close()
                    _check_hash(sid, relname, hr, expected)
                    file_hashes.append({"name": relname, "sha256": expected, "size": hr.size})
                cols.flush()
            ctx.output(f"events/{sid}", store.file_sha256(f"work/paths/events/{sid}.parquet"))
            cov = _coverage(spec, sid, pname, cols, pctx, file_hashes)
            summary["events"] += cols.count
            summary["parse_failures"] += pctx.failures
        elapsed = time.perf_counter() - t0
        cov["timing"] = {"seconds": round(elapsed, 3)}
        store.write_json(f"work/paths/coverage/{sid}.json", cov)
        index[sid] = {**spec.describe(), "source_id": sid, "parser": pname, "files": file_hashes,
                      "manifest_sha256": source.get("manifest_sha256"), "evidence_role": source.get("evidence_role"),
                      "newly_registered": created}
        summary["sources"].append({"source_id": sid, "family": spec.family, "events": cov.get("events", 0),
                                   "indicators": cov.get("indicators"), "parse_failures": pctx.failures,
                                   "newly_registered": created})
    corr = _corroborations(case, store, manifest.corroborations, label_to_sid, ctx.actor)
    if corr is not None:
        ctx.output("corroborations", store.write_json("work/paths/corroborations.json", corr))
        summary["corroborations"] = len(corr["corroborations"])
    ctx.output("sources_index", store.write_json("work/paths/sources.json", index))
    summary["seconds"] = round(time.perf_counter() - started, 3)
    return summary


def _check_hash(sid: str, relname: str, hr: _HashingReader, expected: str | None) -> None:
    if expected and hr.sha.hexdigest() != expected:
        raise IntegrityError(f"{sid}: a log file changed since registration (hash mismatch); ingest aborted")


def _coverage(spec: SourceSpec, sid: str, pname: str, cols: _Columns, pctx: ParseContext, files) -> dict:
    declared = spec.coverage or {}
    problems = []
    if pctx.failures:
        problems.append("parser_failures")
    if cols.unplaced:
        problems.append("records_without_resolvable_time")
    if declared.get("missing"):
        problems.append("declared_missing_periods")
    if not declared:
        completeness = "undeclared"
    elif problems:
        completeness = "partial"
    else:
        completeness = "complete_as_declared"
    return {
        "source_id": sid, "label": spec.label, "family": spec.family, "format": spec.format, "parser": pname,
        "files": files, "events": cols.count, "parse_failures": pctx.failures,
        "failure_samples": pctx.failure_samples, "first_event_utc": to_iso(cols.first),
        "last_event_utc": to_iso(cols.last), "events_without_resolvable_time": cols.unplaced,
        "time_flags": dict(sorted(cols.flag_counts.items())), "observations": dict(sorted(cols.obs_counts.items())),
        "consequence_classes": dict(sorted(cols.class_counts.items())), "declared_coverage": declared,
        "zone": {"timezone": spec.zone.zone, "basis": spec.zone.basis, "note": spec.tz_note,
                 "clock_offset_s": spec.zone.clock_offset_s, "clock_uncertainty_s": spec.zone.clock_uncertainty_s},
        "host": spec.host, "host_ips": spec.host_ips, "asset_id": spec.asset_id,
        "completeness": completeness, "completeness_problems": problems,
    }


def _apply_manifest_config(case, manifest: Manifest) -> list[str]:
    """``paths:`` in logs.yaml fills case.yaml ``paths`` keys the operator has not set (never overrides)."""
    supplied = manifest.raw.get("paths")
    if not supplied:
        return []
    if not isinstance(supplied, dict):
        raise ConfigError("logs manifest 'paths' must be a mapping of case.yaml paths settings")
    current = dict(case.config.get("paths") or {})
    applied = []
    for k, v in supplied.items():
        if k not in current:
            current[k] = v
            applied.append(k)
    if applied:
        from .config import DEFAULTS, _merge

        validate(_merge(DEFAULTS, current))
        case.config["paths"] = current
        case.save()
    return sorted(applied)


_KIND_BY_EXT = {".csv": "csv", ".tsv": "tsv", ".xlsx": "xlsx", ".jsonl": "jsonl", ".json": "json"}


def _corroborations(case, store, corrs: list[Corroboration], label_to_sid: dict, actor: str) -> dict | None:
    existing = store.read_json("work/paths/corroborations.json") if store.exists("work/paths/corroborations.json") else None
    if not corrs:
        return existing
    out = {c["corroboration_id"]: c for c in (existing or {}).get("corroborations", [])}
    known = {s["source_id"]: s for s in case.sources()}
    for c in corrs:
        evidence = []
        if c.path is not None:
            reg = None
            for s in case.sources():
                if any(f.get("path") and os.path.realpath(f["path"]) == str(c.path) for f in s.get("files", [])):
                    reg = s
            if reg is None:
                if c.evidence_role not in custody.EVIDENCE_ROLES:
                    raise ConfigError("corroboration evidence_role is not a known evidence role")
                kind = "directory" if c.path.is_dir() else _KIND_BY_EXT.get(c.path.suffix.lower(), "log")
                reg = custody.add_source(case, store, kind=kind, paths=[c.path], label=f"corroboration:{c.corroboration_id}",
                                         evidence_role=c.evidence_role, legal_basis="cited corroborating evidence",
                                         supplied_by="see corroboration record", received_at=_now_iso(),
                                         registered_by=actor)
                known[reg["source_id"]] = reg
            evidence.append(reg["source_id"])
        for ref in c.evidence_refs:
            sid = label_to_sid.get(ref, ref)
            if sid not in known:
                raise ConfigError(f"corroboration {c.corroboration_id} cites evidence that is not a registered source")
            evidence.append(sid)
        d = c.describe()
        d["evidence_ids"] = sorted(set(evidence))
        d["evidence_roles"] = sorted({known[s].get("evidence_role") for s in d["evidence_ids"] if s in known})
        d["evidence_sha256"] = {s: sha256_hex(canonical_bytes([f.get("sha256") or f.get("tree_sha256")
                                                              for f in known[s].get("files", [])]))
                                for s in d["evidence_ids"] if s in known}
        out[c.corroboration_id] = d
    return {"corroborations": [out[k] for k in sorted(out)]}


def _now_iso() -> str:
    from tripline_scope.core.timeutil import now_iso

    return now_iso()
