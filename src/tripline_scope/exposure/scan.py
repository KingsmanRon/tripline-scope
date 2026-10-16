"""``tscope exposure scan``: run every Module A detector over the inputs a manifest declares.

Each declared input is registered as a case source through :func:`core.custody.add_source` (reference mode;
reused when the same path with the same content is already registered), so the write guard and integrity checks
cover it. The scan runs inside :func:`guard.offline`; results are written encrypted under ``work/exposure/``.
Throughput metrics go to the scan metadata and the console, never into the (deterministic) report.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import resource
import time
import zlib
from pathlib import Path

from tripline_scope.core import custody
from tripline_scope.core.canonical import canonical_bytes, sha256_file, sha256_hex
from tripline_scope.core.redact import scrub_text

from . import DETECTOR_VERSION, METHOD_VERSION, guard
from .catalog import analyse_database, catalog_from_doc, load_catalog
from .coverage import Recorder
from .datacopies import (
    BACKUP_FORMATS,
    ArchiveBomb,
    backup_finding,
    copy_finding,
    opaque_archive_finding,
    profile_delimited,
    profile_json,
    profile_sql_dump,
    profile_xlsx,
)
from .filetypes import decode_text, ext_of, sniff, text_kind
from .identity import Identity, analyse_identity
from .manifest import Manifest, config_sha256, load_manifest
from .model import Finding, Keys, bump, rank
from .secrets import (
    DETECTOR as SECRETS_DETECTOR,
)
from .secrets import (
    FAMILY_FIX,
    FAMILY_IMPACT,
    FAMILY_TITLES,
    Lines,
    detect,
    entropy,
    is_test_fixture_path,
    location_likelihood,
    redacted_context,
)
from .state import ScanState, norm_principal, principal_aliases
from .walker import FILE_CONTROLS, Budget, BudgetExhausted, Item, Walker, scrub_rel

SCAN_SCHEMA = "tripline.exposure-scan/v1"
WORK_DIR = "work/exposure"
SCAN_FILE = f"{WORK_DIR}/scan.json"
FINDINGS_FILE = f"{WORK_DIR}/findings.json"
_GIT_LOOSE = re.compile(r"(^|/)\.git/objects/[0-9a-f]{2}/[0-9a-f]{38}$")
_GIT_PACK = re.compile(r"(^|/)\.git/objects/pack/[^/]+\.pack$")
_ARCHIVES = ("zip", "tar", "gzip", "bzip2", "xz")
_PRINCIPAL_A4 = {"A4.mssql-excess-capability", "A4.pg-copy-program", "A4.pg-excess-capability"}

DETECTOR_CONFIG = {
    "detector_version": DETECTOR_VERSION,
    "method_version": METHOD_VERSION,
    "generic_token_min_length": 12,
    "generic_token_min_entropy": 3.0,
    "password_min_length": 4,
    "sa_id_column_min_valid_rate": 0.8,
    "thirteen_digit_column_rate": 0.5,
    "count_bands": ["0", "1-9", "10-99", "100-999", "1k-10k", "10k+"],
}


# ------------------------------------------------------------------------------------------ sources
def _existing(case, kind: str, path: Path) -> dict | None:
    for s in case.sources():
        if s.get("kind") != kind:
            continue
        for f in s.get("files", []):
            if f.get("path") == str(path):
                return s
    return None


def _content_hash(path: Path) -> str:
    if path.is_dir():
        return sha256_hex(canonical_bytes(custody._walk_tree(path)))
    return sha256_file(path)


def register_inputs(ctx, m: Manifest) -> dict[str, dict]:
    """Register (or reuse) a custody source per declared input. Returns {unit: source record}."""
    case, store = ctx.case, ctx.store
    out: dict[str, dict] = {}
    plan: list[tuple[str, str, Path | None, str, str, dict | None]] = []
    for r in m.roots:
        plan.append((f"root:{r.id}", "directory", r.path, "readiness_copy", f"exposure root {r.id} ({r.kind})", None))
    for d in m.databases:
        if d.export:
            plan.append((f"db:{d.id}", "catalog_export", d.export, "reference_data",
                         f"catalogue export {d.id} ({d.engine})", None))
        else:
            live = {k: d.live[k] for k in ("host", "port", "user", "database")}
            plan.append((f"db:{d.id}", "live_pg" if d.engine == "postgres" else "live_mssql", None, "reference_data",
                         f"metadata-only login {d.id} ({d.engine})", {"live_metadata": live, "engine": d.engine}))
    for key, p in sorted(m.identity.items()):
        plan.append((f"identity:{key}", "directory_export", p, "reference_data", f"identity input {key}", None))
    for unit, kind, path, role, label, extra in plan:
        rec = None
        if path is not None:
            prev = _existing(case, kind, path)
            if prev is not None:
                f = prev["files"][0]
                if _content_hash(path) == (f.get("tree_sha256") or f.get("sha256")):
                    rec = prev
        else:
            for s in case.sources():
                if s.get("kind") == kind and s.get("live_metadata") == extra["live_metadata"]:
                    rec = s
        if rec is None:
            rec = custody.add_source(case, store, kind=kind, paths=[path] if path else None, label=label,
                                     evidence_role=role, legal_basis=m.legal_basis, supplied_by=m.supplied_by,
                                     received_at=m.received_at, registered_by=ctx.actor, extra=extra)
            ctx.note(f"registered {rec['source_id']} for {unit}")
        out[unit] = rec
    return out


# ------------------------------------------------------------------------------------------ file processing
class FileScanner:
    def __init__(self, state: ScanState, walker: Walker):
        self.state = state
        self.walker = walker
        self.docs_not_inspected: dict[str, int] = {}
        self.packs: dict[str, int] = {}

    def process(self, item: Item) -> None:
        st, rec = self.state, self.state.rec
        st.scanned_paths.setdefault(item.root.id, set()).add(st.keys.path(item.unit, item.rel))
        rec.count("A1", "files_examined")
        if _GIT_PACK.search(item.rel):
            self.packs[item.root.id] = self.packs.get(item.root.id, 0) + 1
            return
        if item.complete and _GIT_LOOSE.search(item.rel):
            self._git_object(item)
            return
        kind = sniff(item.rel, item.header)
        if kind in BACKUP_FORMATS:
            backup_finding(st, item, kind)
            return
        if not item.complete:
            if kind in ("7z", "rar"):
                opaque_archive_finding(st, item, kind)
            return
        if kind in _ARCHIVES:
            rec.count("A3", "archives_expanded")
            for member in self.walker.expand(item, kind):
                self.process(member)
            return
        if kind in ("7z", "rar"):
            rec.not_assess(FILE_CONTROLS, item.unit, f"{kind} archives are not supported: contents not inspected",
                           item.display)
            opaque_archive_finding(st, item, kind)
            return
        if kind == "xlsx":
            try:
                for sheet, prof in profile_xlsx(item.data, st.m.budget):
                    copy_finding(st, item, "xlsx", prof, sheet)
                rec.count("A3", "spreadsheets_profiled")
            except ArchiveBomb:
                rec.unavail(FILE_CONTROLS, item.unit, "spreadsheet decompresses beyond the budget (possible archive "
                            "bomb): not inspected", item.display)
            except Exception as exc:  # noqa: BLE001 - malformed workbook: parser failure, class only
                rec.parser_failure("xlsx", item.unit, item.display, type(exc).__name__)
            return
        if kind == "office":
            self.docs_not_inspected[item.root.id] = self.docs_not_inspected.get(item.root.id, 0) + 1
            return
        if kind in ("binary", "mssql_backup"):
            rec.count("A1", "binary_files_not_text_scanned")
            return
        self._text(item, decode_text(item.data))

    def _git_object(self, item: Item) -> None:
        rec = self.state.rec
        try:
            d = zlib.decompressobj()
            raw = d.decompress(item.data, self.state.m.budget["max_file_bytes"] + 1)
        except zlib.error as exc:
            rec.parser_failure("git-object", item.unit, item.display, type(exc).__name__)
            return
        if len(raw) > self.state.m.budget["max_file_bytes"]:
            rec.unavail(FILE_CONTROLS, item.unit, "git object exceeds the per-file size budget", item.display)
            return
        head, _, body = raw.partition(b"\x00")
        if not head.startswith(b"blob "):
            return  # commits and trees carry no file content
        rec.count("A1", "git_blobs_scanned")
        blob = Item(item.root, f"{item.rel}!blob", body, body[:4096], len(body), item.mtime, item.depth)
        if b"\x00" in body[:8192]:
            return
        self._text(blob, decode_text(body), a3=False)

    def _text(self, item: Item, text: str, a3: bool = True) -> None:
        st = self.state
        self._secrets(item, text)
        if not a3:
            return
        tk = text_kind(item.rel, text[:4096])
        try:
            if tk == "delimited":
                copy_finding(st, item, "delimited", profile_delimited(text, ext_of(item.rel), st.m.budget))
            elif tk in ("json", "jsonl"):
                copy_finding(st, item, tk, profile_json(text, st.m.budget, lines=tk == "jsonl"))
            elif tk == "sql_dump":
                copy_finding(st, item, "sql_dump", profile_sql_dump(text, st.m.budget))
            else:
                return
            st.rec.count("A3", "tabular_files_profiled")
        except Exception as exc:  # noqa: BLE001 - malformed export: parser failure, class only
            st.rec.parser_failure(tk, item.unit, item.display, type(exc).__name__)

    def _secrets(self, item: Item, text: str) -> None:
        st, rec, m = self.state, self.state.rec, self.state.m
        cands = detect(text, item.rel)
        if not cands:
            return
        fixture = m.suppress_test_fixtures and is_test_fixture_path(item.rel)
        lines = Lines(text)
        root_rel, _, member = item.rel.partition("!")
        for c in cands:
            if c.suppressed:
                rec.suppress("A1", c.suppressed)
                continue
            if fixture:
                rec.suppress("A1", "test fixture or example file")
                continue
            fp = st.keys.secret(c.value)
            ctx_text = redacted_context(text, lines, c, cands)
            ln, col, _, _ = lines.pos(c.start)
            fam = c.family
            target = None
            user = (c.target or {}).get("user")
            if c.target:
                target = st.resolve_target(c.target.get("server"), c.target.get("database"))
            impact = FAMILY_IMPACT[fam]
            impact_reason = {
                "private-key": "an unencrypted private key allows impersonation or decryption",
                "private-key-encrypted": "an encrypted private key can be attacked offline",
                "cloud-key": "cloud provider secret: can reach hosted data and services",
                "cloud-key-id": "identifier only; the paired secret may be elsewhere",
                "signing-key": "signing/encryption key: allows forging sessions/tokens or decrypting protected data",
                "password-hash": "hash can be attacked offline",
            }.get(fam, "credential for an unidentified system")
            if fam in ("db-credential", "password", "secret") and target is not None:
                if st.is_patient_asset(target):
                    impact, impact_reason = "high", f"grants access to patient-data store {target.get('asset_id') or target.get('name')}"
                else:
                    impact_reason = f"grants access to {target.get('asset_id') or target.get('name')}"
            elif fam == "db-credential":
                impact_reason = "database credential (target not identified in the asset map)"
            likelihood, lreason = location_likelihood(item.root.kind, item.rel)
            asset = st.root_asset(item.root)
            loc = {"type": "file", "root": item.root.id, "path": scrub_rel(root_rel), "member": scrub_rel(member) or None,
                   "line": ln, "column": col, "key": scrub_text(c.key)[:80] if c.key else None,
                   "display": f"{item.display}:{ln}"}
            caveats = ["Validity was not tested: no authentication was attempted; the credential may be stale or rotated.",
                       "A plaintext secret is an exposure condition, not evidence of compromise."]
            if c.rule_id.startswith("A1.generic"):
                caveats.append("Matched by key name and value checks; confirm it is a live secret.")
            if member == "blob":
                caveats.append("Found in repository history (git object): removing the file does not remove it.")
            f = Finding(
                control_id="A1", rule_id=c.rule_id, title=c.title or FAMILY_TITLES[fam], impact=impact,
                likelihood=likelihood, rationale={"impact": impact_reason, "likelihood": lreason}, asset=asset,
                target_asset=target, location=loc, coverage_unit=item.unit, id_parts=[item.root.id, item.rel, fp],
                basis="observation", confidence=c.confidence if entropy(c.value) >= 2.0 else min(c.confidence, 0.6),
                confidence_reason="provider format" if not c.rule_id.startswith("A1.generic") else "key name and value checks",
                fix_action=FAMILY_FIX.get(fam, "rotate-and-vault-credential"),
                source_ids=[st.source_for[item.unit]] if item.unit in st.source_for else [],
                evidence_ids=[st.evidence(item.unit, item.rel, ln)], caveats=caveats,
                details={"family": fam, "occurrences": 1, "lines": [ln],
                         "credential_principal": scrub_text(user)[:80] if user else None,
                         "target_server": scrub_text((c.target or {}).get("server") or "")[:80] or None,
                         "target_database": scrub_text((c.target or {}).get("database") or "")[:80] or None},
                ownership=st.owner_for(item.root.owner, asset.get("asset_id")), redacted_context=ctx_text,
                secret_fingerprint=fp, detector=SECRETS_DETECTOR,
            )
            f = st.add(f)
            ids = st.secret_index.setdefault(fp, [])
            if f.finding_id not in ids:
                ids.append(f.finding_id)
            if user:
                st.credential_principals.append({"principal": user, "target": target, "finding_id": f.finding_id})
            rec.count("A1", "secret_candidates_reported")

    def finish_root(self, root_id: str, unit: str) -> None:
        n = self.docs_not_inspected.get(root_id)
        if n:
            self.state.rec.not_assess("A3", f"{unit}:documents", f"{n} office/PDF documents not inspected for personal "
                                      "information (format not supported)")
        p = self.packs.get(root_id)
        if p:
            self.state.rec.not_assess("A1", f"{unit}:git-packfiles", f"{p} git packfile(s) not decoded: repository "
                                      "history inside packs was not scanned (loose objects were)")


# ------------------------------------------------------------------------------------------ cross-links
def cross_link(state: ScanState) -> None:
    f_by_id = state.findings
    # 1. the same secret in several locations: more places to leak from, and a shared credential
    for ids in state.secret_index.values():
        if len(ids) < 2:
            continue
        for fid in ids:
            f = f_by_id[fid]
            f.likelihood = bump(f.likelihood)
            f.rationale["likelihood"] += f"; the same secret appears in {len(ids)} locations"
            f.details["reused_in_locations"] = len(ids)
            f.related_findings = sorted(set(f.related_findings) | (set(ids) - {fid}))
    # 2. plaintext credential for a principal that holds rights on a patient database
    for cp in state.credential_principals:
        aliases = principal_aliases(cp["principal"])
        for r in state.principal_rights:
            if not (aliases & principal_aliases(r["principal"])):
                continue
            tgt = cp["target"]
            if tgt and tgt.get("asset_id") and r["asset_id"] and tgt["asset_id"] != r["asset_id"]:
                continue
            a1 = f_by_id[cp["finding_id"]]
            if r["patient"] and r["level"] in ("admin", "write"):
                a1.impact = "high"
                a1.rationale["impact"] = (f"credential for {r['principal']}, which holds {r['level']} rights on "
                                          f"patient database {r['database']}")
            for f in f_by_id.values():
                if (f.control_id in ("A2", "A5") or f.rule_id in _PRINCIPAL_A4) and f.location.get("database") == r["database"] and \
                        norm_principal(f.location.get("principal")) == norm_principal(r["principal"]):
                    f.likelihood = "high"
                    if "plaintext credential" not in f.rationale.get("likelihood", ""):
                        f.rationale["likelihood"] += "; a plaintext credential for this principal was found"
                    f.related_findings = sorted(set(f.related_findings) | {a1.finding_id})
                    a1.related_findings = sorted(set(a1.related_findings) | {f.finding_id})


# ------------------------------------------------------------------------------------------ driver
def _iso(t: dt.datetime) -> str:
    return t.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_scan(ctx, manifest_path: Path | str) -> dict:
    t0, cpu0 = time.monotonic(), time.process_time()
    m = load_manifest(manifest_path)
    store = ctx.store
    keys = Keys(store)
    rec = Recorder()
    state = ScanState(m, keys, rec)
    sources = register_inputs(ctx, m)
    state.source_for = {u: s["source_id"] for u, s in sources.items()}
    custody.protect_case_sources(ctx.case)
    cfg_sha = config_sha256(m, DETECTOR_CONFIG)
    ctx.input("manifest", m.sha256)
    ctx.input("scan_config", cfg_sha)
    budget = Budget(m.budget)
    walker = Walker(m, budget, rec)
    scanner = FileScanner(state, walker)
    allowed = {(d.live["host"], d.live["port"]) for d in m.databases if d.mode == "live_metadata"}
    blocked_before = guard.blocked_attempts()
    with guard.offline(allowed):
        ident = Identity(state)
        ident.load()
        for root in m.roots:
            unit = f"root:{root.id}"
            n0 = budget.files
            complete = True
            try:
                for item in walker.walk(root):
                    scanner.process(item)
            except BudgetExhausted as exc:
                complete = False
                rec.unavail(FILE_CONTROLS, unit, f"{exc.reason}: the rest of this root was not scanned")
                rec.missing_evidence("A1", unit, f"scan budget exhausted ({exc.reason}); root partially assessed")
            state.root_complete[root.id] = complete
            files = budget.files - n0
            if files or complete:
                rec.assess(FILE_CONTROLS, unit, f"{files} files examined" + ("" if complete else " (partial: budget)"))
            scanner.finish_root(root.id, unit)
        for db in m.databases:
            unit = f"db:{db.id}"
            cat, err = None, None
            try:
                if db.mode == "live_metadata":
                    from .collect import collect

                    pw = os.environ.get(db.live["password_env"])
                    if pw is None:
                        raise PermissionError("password environment variable not set")
                    doc = collect(db.engine, host=db.live["host"], port=db.live["port"], user=db.live["user"],
                                  password=pw, database=db.live["database"], timeout_s=db.live["timeout_s"],
                                  max_rows=db.live["max_rows"])
                    cat = catalog_from_doc(doc)
                elif db.engine in ("mssql", "postgres"):
                    cat = load_catalog(db.export, m.budget["max_file_bytes"])
            except Exception as exc:  # noqa: BLE001 - malformed export or refused login: class only
                rec.parser_failure("catalogue", unit, db.id, type(exc).__name__)
                err = f"catalogue could not be read ({type(exc).__name__})"
            analyse_database(state, db, cat, ident, err)
        analyse_identity(state, ident)
        cross_link(state)
    if not m.roots:
        for c in FILE_CONTROLS:
            rec.not_assess(c, "roots", "no snapshot roots declared")
    if not m.databases:
        for c in ("A2", "A4"):
            rec.not_assess(c, "databases", "no database catalogue declared")
    findings = rank([f.to_dict() for f in state.findings.values()])
    wall = time.monotonic() - t0
    ru = resource.getrusage(resource.RUSAGE_SELF)
    metrics = {
        "wall_seconds": round(wall, 3), "cpu_seconds": round(time.process_time() - cpu0, 3),
        "files_examined": budget.files, "bytes_read": budget.bytes,
        "files_per_second": round(budget.files / wall, 1) if wall > 0 else None,
        "mb_per_second": round(budget.bytes / wall / 1e6, 2) if wall > 0 else None,
        "peak_rss_mb": round(ru.ru_maxrss / 1024, 1),
        "parser_failures": sum(rec.parser_failure_counts.values()),
        "network_attempts_blocked": guard.blocked_attempts() - blocked_before,
    }
    cov = rec.to_dict()
    cov["root_complete"] = dict(sorted(state.root_complete.items()))
    scan_doc = {
        "schema": SCAN_SCHEMA,
        "method_version": METHOD_VERSION,
        "detector_version": DETECTOR_VERSION,
        "scan_id": m.scan_id,
        "as_of": _iso(m.as_of),
        "manifest_sha256": m.sha256,
        "config_sha256": cfg_sha,
        "manifest": {
            "owner": m.owner, "legal_basis": m.legal_basis, "supplied_by": m.supplied_by, "received_at": m.received_at,
            "budget": m.budget, "observation_window": m.observation_window, "stale_after_days": m.stale_after_days,
            "roots": [{"id": r.id, "kind": r.kind, "asset_id": r.asset, "owner": r.owner, "declared_path": r.declared_path,
                       "exclusions": r.exclusions} for r in m.roots],
            "databases": [{"id": d.id, "engine": d.engine, "catalog_name": d.name, "mode": d.mode, "asset_id": d.asset,
                           "owner": d.owner, "patient_data": d.patient_data} for d in m.databases],
            "identity_inputs": sorted(m.identity), "exclusions": m.exclusions, "assets_sha256": m.assets_sha256,
            "accepted_risks_sha256": m.accepted_risks_sha256, "patient_data_assets": sorted(m.patient_data_assets),
            "suppress_test_fixtures": m.suppress_test_fixtures,
        },
        "accepted_risks": m.accepted_risks,
        "sources": [{"unit": u, "source_id": s["source_id"], "kind": s["kind"], "label": s["label"],
                     "evidence_role": s["evidence_role"], "manifest_sha256": s.get("manifest_sha256"),
                     "content_sha256": (s["files"][0].get("tree_sha256") or s["files"][0].get("sha256")) if s.get("files") else None,
                     "file_count": s["files"][0].get("file_count") if s.get("files") else None}
                    for u, s in sorted(sources.items())],
        "coverage": cov,
        "scanned_paths": {k: sorted(v) for k, v in sorted(state.scanned_paths.items())},
        "metrics": metrics,
    }
    ctx.output("scan.json", store.write_json(SCAN_FILE, scan_doc))
    ctx.output("findings.json", store.write_json(FINDINGS_FILE, findings))
    return {"scan": scan_doc, "findings": findings}
