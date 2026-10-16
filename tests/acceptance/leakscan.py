"""Leak scanning for the acceptance tests and the demo.

Scans directories, captured console text, audit logs, JSON/CSV/text, Parquet, XLSX/ZIP members and PDF text
for (a) the identifiers listed in a ground-truth file (SA IDs, passports, phones, emails, medical-aid and
other record numbers, full names) and (b) identifier-like patterns (``core.redact.find_identifier_like``:
valid SA IDs, card-like numbers, emails, SA phone numbers) after masking hashes, keys and signatures.

Only the notification pack (``notify/`` at a case root) and approver export directories passed explicitly
are exempt.
Symlinks are never followed (a case's ``sources/`` holds links to the originals, which are inputs, not
outputs). Findings carry masked values only, so a failing test does not itself print identifiers.

    from leakscan import GroundTruth, LeakScanner
    scanner = LeakScanner(GroundTruth.load("synth/ground_truth.json"), exempt=["notify", export_dir])
    report = scanner.scan_tree(case_dir); report.extend(scanner.scan_text(console, "console: tscope ..."))
    report.assert_clean()

CLI: python tests/acceptance/leakscan.py --ground-truth GT [--exempt DIR ...] [--console FILE ...] PATH...
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import os
import re
import sys
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from tripline_scope.core.identifiers import normalise_email, normalise_name, normalise_phone, normalise_sa_id
from tripline_scope.core.pdf import pdf_text
from tripline_scope.core.redact import find_identifier_like, mask

DEFAULT_EXEMPT = ("notify",)

# Ground-truth field name -> identifier kind. Unknown fields are ignored (dates, codes, free text).
FIELD_KINDS = {
    "sa_id": "sa_id", "id_number": "sa_id", "national_id": "sa_id", "guardian_sa_id": "sa_id",
    "passport": "passport", "passport_no": "passport", "passport_number": "passport",
    "phone": "phone", "phone_alt": "phone", "mobile": "phone", "cell": "phone", "telephone": "phone",
    "contact_number": "phone", "guardian_phone": "phone",
    "email": "email", "email_address": "email", "guardian_email": "email",
    "medical_aid_no": "record_number", "medical_aid_number": "record_number", "member_number": "record_number",
    "local_patient_key": "record_number", "patient_key": "record_number", "mrn": "record_number",
    "folder_number": "record_number", "patient_ref": "record_number", "card_number": "card",
    "bank_account": "bank_account",
    "full_name": "name", "patient_name": "name", "guardian_name": "name", "name": "name",
}
NAME_PARTS = ("first_name", "middle_names", "last_name", "surname", "maiden_name")

_DIGIT_RUN = re.compile(r"\+?\d[\d \-().]{5,24}\d")
_EMAIL = re.compile(r"[A-Za-z0-9._%+'\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9/\-]{4,40}")
_WORD = re.compile(r"[^\W\d_][^\W\d_'’\-]*(?:['’\-][^\W\d_]+)*")
# Hashes, keys, signatures and other long encoded blobs: masked before the identifier-like pattern scan
# (a SHA-256 hex digest regularly contains 13+ digit runs that can pass the SA ID or Luhn checks by chance).
_BLOBS = re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{32,}|[A-Za-z0-9+/_\-]{40,}={0,2})(?![0-9A-Za-z])")


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s)


def _phone_key(value: str) -> str | None:
    e164 = normalise_phone(value)
    return e164[1:] if e164 else None


def _name_key(value: str) -> tuple[str, ...] | None:
    n = normalise_name(value)
    if not n:
        return None
    toks = tuple(n.lower().split())
    return toks if len(toks) >= 2 and sum(map(len, toks)) >= 6 else None


@dataclass
class GroundTruth:
    """Identifiers to search for, normalised for fast set lookups (linear in the scanned text)."""

    digits: dict[str, str] = field(default_factory=dict)      # digit string -> kind
    phones: dict[str, str] = field(default_factory=dict)      # E.164 without "+" -> kind
    emails: dict[str, str] = field(default_factory=dict)
    tokens: dict[str, str] = field(default_factory=dict)      # upper-case alphanumeric record numbers
    names: dict[tuple[str, ...], str] = field(default_factory=dict)
    max_name_tokens: int = 2

    def __len__(self) -> int:
        return len(self.digits) + len(self.phones) + len(self.emails) + len(self.tokens) + len(self.names)

    def add(self, kind: str, value: object) -> None:
        if value is None:
            return
        s = str(value).strip()
        if not s:
            return
        if kind == "sa_id":
            v = normalise_sa_id(s) or _digits(s)
            if len(v) >= 6:
                self.digits[v] = kind
        elif kind == "phone":
            k = _phone_key(s)
            if k:
                self.phones[k] = kind
        elif kind == "email":
            e = normalise_email(s)
            if e:
                self.emails[e] = kind
        elif kind == "name":
            k = _name_key(s)
            if k:
                self.names[k] = kind
                self.names[k[1:] + k[:1]] = kind  # "Surname Firstname" / "SURNAME, Firstname"
                self.max_name_tokens = max(self.max_name_tokens, len(k))
        elif kind in ("card", "bank_account"):
            if len(_digits(s)) >= 6:
                self.digits[_digits(s)] = kind
        else:  # passport, record numbers: alphanumeric tokens (pure digits also go to the digit table)
            tok = re.sub(r"[\s/\-]", "", s).upper()
            if len(tok) >= 6 and any(c.isdigit() for c in tok):
                self.tokens[tok] = kind
                if tok.isdigit():
                    self.digits[tok] = kind

    def add_record(self, rec: dict) -> None:
        for k, v in rec.items():
            kind = FIELD_KINDS.get(str(k).lower())
            if kind:
                self.add(kind, v)
        lower = {str(k).lower(): v for k, v in rec.items()}
        first, last = lower.get("first_name"), lower.get("last_name") or lower.get("surname")
        if first and last:
            self.add("name", f"{first} {last}")
            if lower.get("maiden_name"):
                self.add("name", f"{first} {lower['maiden_name']}")

    @classmethod
    def from_records(cls, records: Iterable[dict]) -> GroundTruth:
        gt = cls()
        for r in records:
            gt.add_record(r)
        return gt

    @classmethod
    def load(cls, path: str | Path) -> GroundTruth:
        """JSON (list of records, {"people"|"persons"|"records": [...]}, or {kind: [values]}), JSON Lines,
        CSV with a header, or plain text with one identifier per line."""
        path = Path(path)
        text = path.read_text(encoding="utf-8")
        gt = cls()
        if path.suffix == ".jsonl":
            for line in text.splitlines():
                if line.strip():
                    gt.add_record(json.loads(line))
        elif path.suffix == ".json":
            gt._add_json(json.loads(text))
        elif path.suffix in (".csv", ".tsv"):
            for rec in csv.DictReader(io.StringIO(text), delimiter="\t" if path.suffix == ".tsv" else ","):
                gt.add_record(rec)
        else:
            for line in text.splitlines():
                gt.add_guess(line)
        if not len(gt):
            raise ValueError(f"no identifiers found in ground truth {path.name}")
        return gt

    def _add_json(self, doc) -> None:
        if isinstance(doc, list):
            for item in doc:
                if isinstance(item, dict):
                    self.add_record(item)
                else:
                    self.add_guess(str(item))
        elif isinstance(doc, dict):
            for key, val in doc.items():
                if key in ("people", "persons", "records", "patients", "rows") and isinstance(val, list):
                    self._add_json(val)
                elif key in FIELD_KINDS and isinstance(val, list):
                    for v in val:
                        self.add(FIELD_KINDS[key], v)
                elif isinstance(val, (list, dict)) and key not in ("meta", "metadata"):
                    self._add_json(val)

    def add_guess(self, value: str) -> None:
        s = value.strip()
        if not s or s.startswith("#"):
            return
        if "@" in s:
            self.add("email", s)
        elif normalise_sa_id(s):
            self.add("sa_id", s)
        elif _phone_key(s) and len(_digits(s)) in (9, 10, 11):
            self.add("phone", s)
        elif any(c.isdigit() for c in s):
            self.add("record_number", s)
        else:
            self.add("name", s)


@dataclass
class Finding:
    where: str
    line: int | None
    kind: str          # "identifier:<kind>" or "pattern:<kind>"
    masked: str

    def __str__(self) -> str:
        return f"{self.where}{':' + str(self.line) if self.line else ''}: {self.kind} {self.masked}"


@dataclass
class ScanReport:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    texts_scanned: int = 0
    skipped: list[str] = field(default_factory=list)

    def extend(self, other: ScanReport | list[Finding]) -> None:
        if isinstance(other, ScanReport):
            self.findings += other.findings
            self.files_scanned += other.files_scanned
            self.bytes_scanned += other.bytes_scanned
            self.texts_scanned += other.texts_scanned
            self.skipped += other.skipped
        else:
            self.findings += other
            self.texts_scanned += 1

    @property
    def clean(self) -> bool:
        return not self.findings

    def summary(self) -> str:
        head = (f"leak scan: {self.files_scanned} files ({self.bytes_scanned} bytes), {self.texts_scanned} texts, "
                f"{len(self.skipped)} skipped, {len(self.findings)} findings")
        return "\n".join([head] + [f"  {f}" for f in self.findings[:50]])

    def assert_clean(self) -> None:
        if self.findings:
            raise AssertionError(self.summary())


class LeakScanner:
    def __init__(self, ground_truth: GroundTruth | None, *, exempt: Iterable[str | Path] = DEFAULT_EXEMPT,
                 patterns: bool = True, allow_values: Iterable[str] = ()):
        self.gt = ground_truth or GroundTruth()
        self.exempt = [str(e) for e in exempt]
        self.patterns = patterns
        self.allow_values = [v for v in allow_values if v]

    # ------------------------------------------------------------------ text
    def scan_text(self, text: str, where: str) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[int, str]] = set()

        def hit(pos: int, kind: str, value: str) -> None:
            line = text.count("\n", 0, pos) + 1
            if (line, kind) not in seen:
                seen.add((line, kind))
                out.append(Finding(where, line, kind, mask(value)))

        gt = self.gt
        if gt.digits or gt.phones:
            for m in _DIGIT_RUN.finditer(text):
                d = _digits(m.group(0))
                if d in gt.digits:
                    hit(m.start(), f"identifier:{gt.digits[d]}", d)
                elif gt.phones and 9 <= len(d) <= 12 and (k := _phone_key(m.group(0))) in gt.phones:
                    hit(m.start(), "identifier:phone", k)
        if gt.emails:
            for m in _EMAIL.finditer(text):
                e = m.group(0).lower()
                if e in gt.emails:
                    hit(m.start(), "identifier:email", e)
        if gt.tokens:
            for m in _TOKEN.finditer(text):
                tok = re.sub(r"[/\-]", "", m.group(0)).upper()
                if tok in gt.tokens:
                    hit(m.start(), f"identifier:{gt.tokens[tok]}", tok)
        if gt.names:
            words = [(m.start(), (normalise_name(m.group(0)) or "").lower()) for m in _WORD.finditer(text)]
            for i in range(len(words)):
                for n in range(2, gt.max_name_tokens + 1):
                    if i + n <= len(words):
                        key = tuple(w for _, w in words[i:i + n])
                        if key in gt.names:
                            hit(words[i][0], "identifier:name", " ".join(key))
        if self.patterns:
            masked = _BLOBS.sub(" ", text)
            for v in self.allow_values:
                masked = masked.replace(v, " ")
            for lineno, line in enumerate(masked.splitlines(), start=1):
                for kind in dict.fromkeys(find_identifier_like(line)):
                    if (lineno, f"pattern:{kind}") not in seen:
                        seen.add((lineno, f"pattern:{kind}"))
                        out.append(Finding(where, lineno, f"pattern:{kind}", "(identifier-like value)"))
        return out

    # ------------------------------------------------------------------ files
    def _texts_of(self, path: Path, data: bytes) -> list[tuple[str, str]]:
        name = path.name.lower()
        if data.startswith(b"%PDF"):
            return [(str(path), pdf_text(data) + "\n" + _pdf_strings(data))]
        if data.startswith(b"PAR1"):
            return [(str(path), _parquet_text(data))]
        if data.startswith(b"PK\x03\x04"):
            out = []
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    for member in z.namelist():
                        if not member.endswith("/"):
                            out += self._texts_of(Path(f"{path}!{member}"), z.read(member))
                return out
            except zipfile.BadZipFile:
                pass
        if data.startswith(b"\x1f\x8b") or name.endswith(".gz"):
            try:
                return self._texts_of(Path(str(path).removesuffix(".gz")), gzip.decompress(data))
            except OSError:
                pass
        return [(str(path), data.decode("utf-8", "replace"))]

    def scan_file(self, path: str | Path) -> ScanReport:
        path = Path(path)
        rep = ScanReport()
        data = path.read_bytes()
        rep.files_scanned, rep.bytes_scanned = 1, len(data)
        for where, text in self._texts_of(path, data):
            rep.findings += self.scan_text(text, where)
        return rep

    def is_exempt(self, path: Path, root: Path) -> bool:
        """Absolute exemptions match that directory anywhere. A relative name (``notify``) matches only the
        directory of that name at a case root (its parent holds ``case.yaml``) or at the scan root."""
        real = os.path.realpath(path)
        for e in self.exempt:
            if os.path.isabs(e):
                ap = os.path.realpath(e)
                if real == ap or real.startswith(ap + os.sep):
                    return True
                continue
            for anc in [path, *path.parents]:
                if anc == root.parent or root not in [anc, *anc.parents]:
                    break
                if anc.name == e.strip("/") and anc.is_dir() and (anc.parent == root or
                                                                   (anc.parent / "case.yaml").is_file()):
                    return True
        return False

    def scan_tree(self, root: str | Path) -> ScanReport:
        root = Path(root)
        rep = ScanReport()
        if root.is_file():
            return self.scan_file(root)
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            d = Path(dirpath)
            for dn in list(dirnames):
                p = d / dn
                if p.is_symlink() or self.is_exempt(p, root):
                    rep.skipped.append(f"{p} ({'symlink' if p.is_symlink() else 'exempt'})")
                    dirnames.remove(dn)
            for fn in sorted(filenames):
                p = d / fn
                if p.is_symlink():
                    rep.skipped.append(f"{p} (symlink)")
                    continue
                if self.is_exempt(p, root):
                    rep.skipped.append(f"{p} (exempt)")
                    continue
                rep.extend(self.scan_file(p))
        return rep


def _pdf_strings(data: bytes) -> str:
    """Literal strings from PDF text operators, joined with spaces (catches values split across Tj/TJ)."""
    text = pdf_text(data)
    parts = re.findall(r"\(((?:\\.|[^\\)])*)\)", text)
    return " ".join(re.sub(r"\\(.)", r"\1", p) for p in parts)


def _parquet_text(data: bytes) -> str:
    try:
        import pyarrow.parquet as pq

        table = pq.read_table(io.BytesIO(data))
        return "\n".join(" ".join("" if v is None else str(v) for v in row.values()) for row in table.to_pylist())
    except Exception:  # noqa: BLE001 - unreadable Parquet is scanned as raw bytes
        return data.decode("utf-8", "replace")


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Scan outputs for ground-truth and identifier-like values.")
    ap.add_argument("paths", nargs="*", type=Path)
    ap.add_argument("--ground-truth", type=Path)
    ap.add_argument("--exempt", action="append", default=list(DEFAULT_EXEMPT))
    ap.add_argument("--console", action="append", type=Path, default=[], help="captured console output file")
    ap.add_argument("--no-patterns", action="store_true")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    gt = GroundTruth.load(args.ground_truth) if args.ground_truth else None
    scanner = LeakScanner(gt, exempt=args.exempt, patterns=not args.no_patterns)
    rep = ScanReport()
    for p in args.paths:
        rep.extend(scanner.scan_tree(p))
    for c in args.console:
        rep.extend(scanner.scan_text(c.read_text(errors="replace"), f"console:{c}"))
    if args.json:
        print(json.dumps({"clean": rep.clean, "files": rep.files_scanned, "findings": [vars(f) for f in rep.findings],
                          "skipped": rep.skipped}, indent=2))
    else:
        print(rep.summary())
    return 0 if rep.clean else 1


if __name__ == "__main__":
    sys.exit(main())
