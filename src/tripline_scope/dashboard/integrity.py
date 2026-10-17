"""Integrity gate: no released report data reaches the workbench before its report chain verifies.

For each report kind the gate runs the standalone verifier's chain check (hospital signature over every version,
signed artefact hashes, no unsigned files, contiguous versions linked by ``previous_report_sha256``, one case id)
and records the SHA-256 of every file it verified. Data is then read only through the gate, and every read is
bound to those hashes: a file whose bytes differ from what was verified is refused, even if it changed after
verification.

Verification is cached per kind against a fingerprint of the kind's released version directories (path, type,
size, mtime, ctime and inode of every file). Any change, including one that restores the mtime, changes the ctime
and so invalidates the cache on the next request. On failure the affected kind is refused with an explicit warning
(:class:`IntegrityFailure`); other kinds stay available.
"""

from __future__ import annotations

import hashlib
import stat
import threading
from dataclasses import dataclass, field
from pathlib import Path

from tripline_scope.core.canonical import load_canonical
from tripline_scope.core.reports import ReportStore
from tscope_verify import formats as F

WARNING = ("INTEGRITY FAILURE: the released {kind} report chain failed verification (signature, file hash or "
           "chain link). Its findings are not displayed and its files are not served. Do not rely on them: run "
           "'tscope verify' and investigate who changed the files.")


class IntegrityFailure(Exception):
    def __init__(self, kind: str, detail: str):
        super().__init__(f"{kind}: {detail}")
        self.kind, self.detail = kind, detail


@dataclass(frozen=True)
class Trust:
    kind: str
    present: bool                       # at least one released version exists
    ok: bool
    checks: int = 0
    failed: tuple[str, ...] = ()
    render: str | None = None
    hashes: dict[int, dict[str, str]] = field(default_factory=dict)   # version -> {relative path: sha256}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TrustGate:
    def __init__(self, case, home):
        self.case, self.home = case, home
        self._lock = threading.RLock()
        self._cache: dict[str, tuple[tuple, Trust]] = {}
        self.verifications = 0          # number of chain verifications run (observable in tests)

    # ------------------------------------------------------------------ verification
    def fingerprint(self, kind: str) -> tuple:
        rows = []
        for n, vdir in ReportStore(self.case).versions(kind):
            for p in [vdir, *sorted(vdir.rglob("*"))]:
                st = p.lstat()
                rows.append((n, p.relative_to(vdir).as_posix(), stat.S_IFMT(st.st_mode), st.st_size, st.st_mtime_ns,
                             st.st_ctime_ns, st.st_ino))
        return tuple(rows)

    def _verify(self, kind: str) -> Trust:
        rs = ReportStore(self.case)
        vs = rs.versions(kind)
        if not vs:
            return Trust(kind, present=False, ok=True)
        self.verifications += 1
        res = rs.verify(kind, self.home)
        failed = tuple(c.name for c in res.checks if not c.ok)
        render = res.render().replace(str(rs.kind_dir(kind)), f"reports/{kind}") if not res.ok else None
        if not res.ok:
            return Trust(kind, True, False, len(res.checks), failed or ("verification failed",), render)
        hashes: dict[int, dict[str, str]] = {}
        for n, vdir in vs:
            files = {p.relative_to(vdir).as_posix(): _sha(p.read_bytes()) for p in sorted(vdir.rglob("*")) if p.is_file()}
            rel = load_canonical((vdir / F.RELEASE_FILE).read_bytes())
            signed = dict(rel.get("artefacts") or {}, **{F.REPORT_FILE: rel.get("report_sha256")})
            if any(files.get(name) != digest for name, digest in signed.items()):
                return Trust(kind, True, False, len(res.checks), (f"v{n:04d}: files changed after verification",))
            hashes[n] = files
        return Trust(kind, True, True, len(res.checks), (), None, hashes)

    def check(self, kind: str, *, refresh: bool = False) -> Trust:
        """The kind's trust state, re-verified whenever its released files changed (or on ``refresh``)."""
        with self._lock:
            fp = self.fingerprint(kind)
            hit = self._cache.get(kind)
            if hit and hit[0] == fp and not refresh:
                return hit[1]
            trust = self._verify(kind)
            if self.fingerprint(kind) != fp:     # changed while verifying: refuse now, verify again next time
                self._cache.pop(kind, None)
                return Trust(kind, True, False, trust.checks, ("report files changed during verification",))
            self._cache[kind] = (fp, trust)
            return trust

    def require(self, kind: str) -> Trust:
        t = self.check(kind)
        if t.present and not t.ok:
            raise IntegrityFailure(kind, "; ".join(t.failed[:5]))
        return t

    def invalidate(self, kind: str) -> None:
        with self._lock:
            self._cache.pop(kind, None)

    # ------------------------------------------------------------------ reads bound to verified hashes
    def expected(self, kind: str, version: int, name: str) -> str:
        digest = self.require(kind).hashes.get(version, {}).get(name)
        if digest is None:
            raise IntegrityFailure(kind, f"v{version:04d}/{name} was not part of the verified release")
        return digest

    def mismatch(self, kind: str, version: int, name: str) -> IntegrityFailure:
        self.invalidate(kind)
        return IntegrityFailure(kind, f"v{version:04d}/{name} does not match the verified release")

    def read_bytes(self, kind: str, version: int, vdir: Path, name: str) -> bytes:
        want = self.expected(kind, version, name)
        data = (vdir / name).read_bytes()
        if _sha(data) != want:
            raise self.mismatch(kind, version, name)
        return data

    def read_json(self, kind: str, version: int, vdir: Path, name: str = F.REPORT_FILE):
        from . import data as D

        want = self.expected(kind, version, name)
        digest, obj = D.load_json_hashed(vdir / name)
        if digest != want:
            raise self.mismatch(kind, version, name)
        return obj

    # ------------------------------------------------------------------ views
    def failure(self, kind: str, exc: IntegrityFailure | None = None) -> dict:
        t = self.check(kind)
        return {"status": "integrity_failure", "kind": kind, "warning": WARNING.format(kind=kind),
                "reason": (exc.detail if exc else "; ".join(t.failed[:5])) or "verification failed",
                "failed_checks": list(t.failed[:20])}

    def summary(self, kind: str) -> dict:
        t = self.check(kind)
        if not t.present:
            return {"status": "awaiting_analysis", "reason": f"no released {kind} report"}
        out = {"ok": t.ok, "checks": t.checks, "failed": list(t.failed)}
        if t.render:
            out["render"] = t.render
        return out

    def alerts(self, kinds) -> list[dict]:
        out = []
        for kind in kinds:
            t = self.check(kind)
            if t.present and not t.ok:
                out.append({"kind": kind, "warning": WARNING.format(kind=kind)})
        return out
