#!/usr/bin/env python3
"""Licence gate for the runtime dependency closure.

Policy (docs/SUPPLY_CHAIN.md): runtime dependencies must be MIT, MIT-0, BSD-2-Clause, BSD-3-Clause, Apache-2.0,
ISC or PSF-2.0. LGPL is allowed only for unmodified, dynamically linked libraries named in ``LGPL_EXCEPTIONS``
(currently none). GPL, AGPL, SSPL, unknown or missing licences fail. Package-specific allowances are explicit
and documented in ``PACKAGE_ALLOW``. Telemetry SDKs/exporters are forbidden outright (no telemetry, ever).

Inputs: the hashed lock (defines the closure) plus the distributions themselves, either a directory of wheels
(``--wheels``) or an installed site-packages (``--site-packages``). Every lock entry must be present with the
locked version. For each distribution the gate reads License-Expression (PEP 639), License, the trove
classifiers and the licence files shipped with it; it also scans every licence-like file bundled anywhere in
the distribution for GPL-family licence grants (``BUNDLED_FILE_EXCEPTIONS`` clears reviewed ones).
With ``--native-audit`` it also checks the Rust crates statically linked into native wheels.

Exit status: 0 pass, 1 policy failure, 2 usage error. ``--json-out`` writes a machine-readable report.
"""

from __future__ import annotations

import argparse
import email
import email.message
import fnmatch
import json
import re
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

SCHEMA = "tripline.licence-check/v1"

ALLOWED = {"MIT", "MIT-0", "BSD-2-Clause", "BSD-3-Clause", "Apache-2.0", "ISC", "PSF-2.0"}

# Explicit, reviewed package-specific allowances (documented in docs/SUPPLY_CHAIN.md).
PACKAGE_ALLOW: dict[str, dict[str, str]] = {
    "pillow": {
        "MIT-CMU": "Pillow's licence (the historical PIL licence) is the MIT-CMU / HPND permissive notice: "
                   "use, copy, modify and distribute for any purpose with the notice retained. Treated as an "
                   "MIT-style permissive licence (reviewed).",
        "HPND": "Same PIL licence text under its older SPDX identifier (reviewed).",
    },
}

# LGPL: allowed only for unmodified, dynamically linked libraries listed here with a reason. Expected: none.
LGPL_EXCEPTIONS: dict[str, str] = {}

# Reviewed licence files bundled inside an otherwise permissive distribution: (package, path glob, licence, reason).
BUNDLED_FILE_EXCEPTIONS: list[tuple[str, str, str, str]] = [
    (
        "reportlab", "reportlab/fonts/DarkGarden-copying*.txt", "GPL-2.0-or-later WITH Font-exception-2.0",
        "Licence of the DarkGarden sample font (font data, not code) shipped in reportlab's fonts directory. "
        "Tripline Scope never loads it (PDFs use only the standard PDF fonts); the installers delete the "
        "DarkGarden files from the installed environment (bundle/prune.list). Owner sign-off recorded in "
        "docs/SUPPLY_CHAIN.md.",
    ),
]

# SPDX exceptions that only add permissions to an allowed licence.
PERMISSIVE_EXCEPTIONS = {"LLVM-exception"}

# No telemetry, ever: these must never be in the runtime closure, whatever their licence.
FORBIDDEN_PACKAGES = [
    "opentelemetry-sdk", "opentelemetry-exporter-*", "opentelemetry-instrumentation*", "opentelemetry-distro",
    "sentry-sdk", "ddtrace", "datadog", "newrelic", "posthog", "mixpanel", "segment-analytics-python",
    "rollbar", "bugsnag", "elastic-apm", "honeybadger", "logfire",
]

FIRST_PARTY = {"tripline-scope", "tripline-scope-verify"}

# ------------------------------------------------------------------------------------------- SPDX handling
_ALIASES = {
    "mit": "MIT", "mit license": "MIT", "the mit license": "MIT", "mit licence": "MIT", "expat": "MIT",
    "mit-0": "MIT-0", "mit no attribution": "MIT-0", "mit no attribution license (mit-0)": "MIT-0",
    "apache-2.0": "Apache-2.0", "apache 2.0": "Apache-2.0", "apache 2": "Apache-2.0", "apache2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0", "apache license, version 2.0": "Apache-2.0",
    "apache license version 2.0": "Apache-2.0", "apache software license 2.0": "Apache-2.0",
    "bsd-3-clause": "BSD-3-Clause", "bsd 3-clause": "BSD-3-Clause", "bsd 3-clause license": "BSD-3-Clause",
    "3-clause bsd": "BSD-3-Clause", "3-clause bsd license": "BSD-3-Clause", "new bsd": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause", "modified bsd": "BSD-3-Clause", "bsd-3": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause", "bsd 2-clause": "BSD-2-Clause", "bsd 2-clause license": "BSD-2-Clause",
    "simplified bsd": "BSD-2-Clause", "2-clause bsd": "BSD-2-Clause", "freebsd": "BSD-2-Clause",
    "isc": "ISC", "isc license": "ISC", "iscl": "ISC", "isc license (iscl)": "ISC",
    "psf": "PSF-2.0", "psfl": "PSF-2.0", "psf-2.0": "PSF-2.0", "psf license": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    "mit-cmu": "MIT-CMU", "hpnd": "HPND",
}
# Classifier suffix (after "License :: OSI Approved :: " or "License :: ") -> SPDX id, or None when the
# classifier names a family without a version/variant (resolved from the licence text).
_CLASSIFIERS = {
    "MIT License": "MIT", "MIT No Attribution License (MIT-0)": "MIT-0", "ISC License (ISCL)": "ISC",
    "Apache Software License": None, "BSD License": None,
    "Python Software Foundation License": "PSF-2.0",
    "Historical Permission Notice and Disclaimer (HPND)": "HPND",
    "GNU General Public License (GPL)": "GPL", "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "GNU Lesser General Public License v2 (LGPLv2)": "LGPL-2.0-only",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.0-or-later",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "GNU Lesser General Public License v3 or later (LGPLv3+)": "LGPL-3.0-or-later",
    "GNU Library or Lesser General Public License (LGPL)": "LGPL",
    "GNU Affero General Public License v3": "AGPL-3.0-only",
    "GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "The Unlicense (Unlicense)": "Unlicense", "zlib/libpng License": "Zlib",
    "Public Domain": "LicenseRef-Public-Domain",
}
_CANON = {k.lower(): k for k in list(ALLOWED) + ["MIT-CMU", "HPND", "MPL-2.0", "Zlib", "Unlicense", "0BSD",
                                                  "BSL-1.0", "CC0-1.0", "Unicode-3.0", "Unicode-DFS-2016",
                                                  "BSD-4-Clause", "SSPL-1.0"]}


def copyleft_family(spdx_id: str) -> str | None:
    s = spdx_id.upper()
    if s.startswith("AGPL"):
        return "AGPL"
    if s.startswith("LGPL"):
        return "LGPL"
    if s.startswith("GPL"):
        return "GPL"
    if s.startswith("SSPL"):
        return "SSPL"
    return None


def canonical_id(token: str) -> str:
    t = token.strip()
    return _ALIASES.get(t.lower()) or _CANON.get(t.lower()) or t


_TOKEN = re.compile(r"\s*(\(|\)|[A-Za-z0-9.+\-:]+)")


def parse_expression(expr: str):
    """Parse an SPDX licence expression into ("or"|"and", [nodes]) / ("id", id, exception) nodes."""
    tokens = []
    pos = 0
    expr = expr.strip()
    while pos < len(expr):
        m = _TOKEN.match(expr, pos)
        if not m:
            raise ValueError(f"cannot parse licence expression: {expr!r}")
        tokens.append(m.group(1))
        pos = m.end()
        while pos < len(expr) and expr[pos].isspace():
            pos += 1
    i = 0

    def peek():
        return tokens[i] if i < len(tokens) else None

    def take():
        nonlocal i
        i += 1
        return tokens[i - 1]

    def factor():
        if peek() == "(":
            take()
            node = disjunction()
            if take() != ")":
                raise ValueError(f"unbalanced parentheses in {expr!r}")
            return node
        tok = take()
        if tok is None or tok.upper() in ("AND", "OR", "WITH", ")"):
            raise ValueError(f"unexpected token in {expr!r}")
        exc = None
        if peek() and peek().upper() == "WITH":
            take()
            exc = take()
        return ("id", canonical_id(tok), exc)

    def conjunction():
        nodes = [factor()]
        while peek() and peek().upper() == "AND":
            take()
            nodes.append(factor())
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def disjunction():
        nodes = [conjunction()]
        while peek() and peek().upper() == "OR":
            take()
            nodes.append(conjunction())
        return nodes[0] if len(nodes) == 1 else ("or", nodes)

    node = disjunction()
    if i != len(tokens):
        raise ValueError(f"trailing tokens in {expr!r}")
    return node


_RANK = {"allowed": 0, "allowed-by-exception": 1, "unknown": 2, "denied": 3}


def classify_id(spdx_id: str, exception: str | None, package: str) -> tuple[str, str]:
    fam = copyleft_family(spdx_id)
    if fam == "LGPL":
        if package in LGPL_EXCEPTIONS:
            return "allowed-by-exception", f"{spdx_id}: {LGPL_EXCEPTIONS[package]}"
        return "denied", f"{spdx_id}: LGPL only for listed unmodified, dynamically linked libraries"
    if fam:
        return "denied", f"{spdx_id}: {fam} is not allowed" + (f" (even WITH {exception})" if exception else "")
    if spdx_id in ALLOWED and (not exception or exception in PERMISSIVE_EXCEPTIONS):
        return "allowed", spdx_id + (f" WITH {exception}" if exception else "")
    if spdx_id in PACKAGE_ALLOW.get(package, {}) and not exception:
        return "allowed-by-exception", f"{spdx_id}: {PACKAGE_ALLOW[package][spdx_id]}"
    return "unknown", f"{spdx_id}{' WITH ' + exception if exception else ''}: not on the allow-list"


def evaluate_expression(node, package: str) -> tuple[str, str]:
    kind = node[0]
    if kind == "id":
        return classify_id(node[1], node[2], package)
    results = [evaluate_expression(n, package) for n in node[1]]
    if kind == "or":  # the licensee may choose any branch: take the best
        return min(results, key=lambda r: _RANK[r[0]])
    return max(results, key=lambda r: _RANK[r[0]])  # AND: every branch applies


# ------------------------------------------------------------------------------------------- licence texts
def _norm(text: str) -> str:
    return re.sub(r"[\s#*]+", " ", text).strip().lower()


def detect_text(text: str) -> str | None:
    """Identify a licence from its text (the distribution's own licence file). None when unrecognised."""
    t = _norm(text)
    head = t[:600]
    if "gnu affero general public license" in head:
        return "AGPL"
    if "gnu lesser general public license" in head or "gnu library general public license" in head:
        return "LGPL"
    if "gnu general public license" in head:
        return "GPL"
    if "server side public license" in head:
        return "SSPL-1.0"
    if "apache license" in t and "version 2.0" in t:
        return "Apache-2.0"
    if "python software foundation license" in t:
        return "PSF-2.0"
    if "permission is hereby granted, free of charge" in t:
        return "MIT" if "above copyright notice and this permission notice shall be included" in t else "MIT-0"
    if "redistribution and use in source and binary forms" in t:
        if "advertising materials" in t:
            return "BSD-4-Clause"
        if "neither the name" in t or "endorse or promote" in t:
            return "BSD-3-Clause"
        return "BSD-2-Clause"
    if "permission to use, copy, modify, and/or distribute this software for any purpose with or without fee" in t:
        return "ISC"
    return None


_GRANT = re.compile(
    r"under the terms of the gnu (?:lesser |library |affero )?general public licen[cs]e"
    r"|licensed under the (?:gnu )?(?:a|l)?gpl\b|server side public license", re.I)
# A file that *is* a copyleft licence text starts with its heading, e.g. "GNU GENERAL PUBLIC LICENSE Version 2".
_HEADING = re.compile(r"^(?:gnu (lesser |library |affero )?general public licen[cs]e,? version \d"
                      r"|server side public license,? version \d)")
_LICENCE_FILE = re.compile(r"(licen[cs]e|copying|notice|copyright)", re.I)


def copyleft_grant(text: str) -> str | None:
    """Return the copyleft family when ``text`` is (or grants) a GPL/LGPL/AGPL/SSPL licence."""
    m = _HEADING.match(_norm(text))
    if m:
        kind = (m.group(1) or "").strip()
        return {"affero": "AGPL", "lesser": "LGPL", "library": "LGPL"}.get(kind, "SSPL" if "server" in m.group(0)
                                                                          else "GPL")
    m = _GRANT.search(re.sub(r"\s+", " ", text))
    if not m:
        return None
    s = m.group(0).lower()
    return ("AGPL" if "affero" in s or "agpl" in s else "LGPL" if ("lesser" in s or "library" in s or "lgpl" in s)
            else "SSPL" if "server side" in s else "GPL")


# ------------------------------------------------------------------------------------------- distributions
def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass
class Dist:
    name: str
    version: str
    metadata: email.message.Message
    own_licence_texts: dict[str, str] = field(default_factory=dict)   # dist-info licence files
    bundled_texts: dict[str, str] = field(default_factory=dict)       # every other licence-like file

    @property
    def key(self) -> str:
        return normalize_name(self.name)


def _is_licence_file(path: str) -> bool:
    base = path.rstrip("/").rsplit("/", 1)[-1]
    return bool(_LICENCE_FILE.search(base)) and not base.endswith((".py", ".pyc", ".so", ".pyi"))


def _split_texts(dist_info: str, items: list[tuple[str, bytes]]) -> tuple[dict, dict]:
    own, bundled = {}, {}
    for path, data in items:
        text = data.decode("utf-8", "replace")
        (own if path.startswith(dist_info + "/") else bundled)[path] = text
    return own, bundled


def dist_from_wheel(path: Path) -> Dist:
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        meta_name = next(n for n in names if n.count("/") == 1 and n.endswith(".dist-info/METADATA"))
        dist_info = meta_name.split("/")[0]
        meta = email.message_from_bytes(z.read(meta_name))
        items = [(n, z.read(n)) for n in names if not n.endswith("/") and _is_licence_file(n)]
    own, bundled = _split_texts(dist_info, items)
    return Dist(meta["Name"], meta["Version"], meta, own, bundled)


def dists_from_site_packages(site: Path) -> list[Dist]:
    import importlib.metadata as im

    out = []
    for d in im.distributions(path=[str(site)]):
        meta = email.message_from_string(d.read_text("METADATA") or "")
        dist_info = Path(str(d._path)).name  # noqa: SLF001 - stdlib PathDistribution keeps its directory
        items = []
        for f in d.files or []:
            p = str(f)
            if _is_licence_file(p):
                try:
                    items.append((p, (site / p).read_bytes()))
                except OSError:
                    continue
        own, bundled = _split_texts(dist_info, items)
        out.append(Dist(meta["Name"], meta["Version"], meta, own, bundled))
    return out


def parse_lock(path: Path) -> dict[str, dict]:
    """Parse a hashed requirements file: {normalised name: {"name", "version", "hashes": [...]}}."""
    entries: dict[str, dict] = {}
    logical: list[str] = []
    buf = ""
    for raw in path.read_text().splitlines():
        line = raw.split(" #", 1)[0].rstrip() if not raw.lstrip().startswith("#") else ""
        if not line.strip():
            if buf:
                logical.append(buf)
                buf = ""
            continue
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        logical.append(buf + line)
        buf = ""
    if buf:
        logical.append(buf)
    for line in logical:
        parts = line.split()
        if not parts or parts[0].startswith("-"):
            continue
        req = parts[0].split(";")[0]
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)(\[[^\]]*\])?(==|===)?([^\s;]+)?$", req)
        if not m:
            raise ValueError(f"unparseable requirement: {req}")
        hashes = [p.split("=", 1)[1] for p in parts[1:] if p.startswith("--hash=")]
        entries[normalize_name(m.group(1))] = {
            "name": m.group(1), "pinned": m.group(3) in ("==", "===") and bool(m.group(4)),
            "version": m.group(4) if m.group(3) else None, "hashes": hashes,
        }
    return entries


# ------------------------------------------------------------------------------------------- evaluation
def _bsd_variant(dist: Dist) -> str:
    """The "BSD License" classifier names a family; the variant comes from the shipped licence text."""
    for text in list(dist.own_licence_texts.values()) + [dist.metadata.get("License") or ""]:
        t = _norm(text)
        if "redistribution and use in source and binary forms" in t:
            if "advertising materials" in t:
                return "BSD-4-Clause"
            return "BSD-3-Clause" if ("neither the name" in t or "endorse or promote" in t) else "BSD-2-Clause"
    return "LicenseRef-BSD-variant-unknown"


def _apache_version(dist: Dist) -> str:
    texts = " ".join(_norm(t) for t in list(dist.own_licence_texts.values()) + [dist.metadata.get("License") or ""])
    if "apache license" in texts and "version 1.1" in texts and "version 2.0" not in texts:
        return "Apache-1.1"
    return "Apache-2.0"


def declared_licence(dist: Dist) -> tuple[str | None, str, list[str]]:
    """Return (SPDX expression or None, source, evidence lines)."""
    m = dist.metadata
    evidence = []
    expr = (m.get("License-Expression") or "").strip()
    lic = (m.get("License") or "").strip()
    classifiers = [c for c in (m.get_all("Classifier") or []) if c.startswith("License ::")]
    own_text = next((detect_text(t) for t in dist.own_licence_texts.values() if detect_text(t)), None)
    if expr:
        evidence.append(f"License-Expression: {expr}")
    if lic:
        evidence.append(f"License: {lic.splitlines()[0][:80]}")
    evidence += [f"Classifier: {c}" for c in classifiers]
    if own_text:
        evidence.append(f"licence text: {own_text}")
    if expr:
        return expr, "License-Expression", evidence
    if lic and len(lic) < 80 and lic.lower() in _ALIASES:
        return _ALIASES[lic.lower()], "License", evidence
    if lic and len(lic) < 80:
        try:
            node = parse_expression(lic)
            if node[0] != "id" or node[1] in _CANON.values() or copyleft_family(node[1]):
                return lic, "License", evidence
        except ValueError:
            pass
    ids = []
    for c in classifiers:
        suffix = c.split(" :: ")[-1]
        if suffix == "Apache Software License":
            ids.append(_apache_version(dist))
        elif suffix == "BSD License":
            ids.append(_bsd_variant(dist))
        elif suffix in _CLASSIFIERS:
            ids.append(_CLASSIFIERS[suffix])
        elif suffix != "OSI Approved":
            ids.append(f"LicenseRef-classifier-{re.sub(r'[^A-Za-z0-9.]+', '-', suffix)}")
    ids = [i for i in ids if i]
    if ids:
        return " OR ".join(dict.fromkeys(ids)), "classifier" + (" + licence text" if own_text else ""), evidence
    if lic:
        detected = detect_text(lic)
        if detected:
            return detected, "License (text)", evidence
    if own_text:
        return own_text, "licence text", evidence
    return None, "none", evidence


def evaluate_dist(dist: Dist) -> dict:
    out = {"name": dist.name, "version": dist.version, "licence": None, "source": None, "status": "unknown",
           "reason": "", "evidence": [], "bundled": []}
    expr, source, evidence = declared_licence(dist)
    out.update(licence=expr, source=source, evidence=evidence)
    if expr is None:
        out.update(status="unknown", reason="no licence metadata or recognisable licence text")
    else:
        try:
            out["status"], out["reason"] = evaluate_expression(parse_expression(expr), dist.key)
        except ValueError as exc:
            out.update(status="unknown", reason=str(exc))
    # A classifier naming a copyleft licence that the chosen expression does not mention is a conflict.
    for line in evidence:
        if line.startswith("Classifier:"):
            fam = copyleft_family(_CLASSIFIERS.get(line.split(" :: ")[-1]) or "")
            if fam and (expr is None or fam not in expr.upper()):
                out.update(status="denied", reason=f"classifier declares {fam} but licence resolved to {expr}")
    for path, text in sorted(dist.bundled_texts.items()):
        fam = copyleft_grant(text)
        if not fam:
            continue
        exc = next((e for e in BUNDLED_FILE_EXCEPTIONS if e[0] == dist.key and fnmatch.fnmatch(path, e[1])), None)
        entry = {"path": path, "family": fam, "status": "allowed-by-exception" if exc else "denied",
                 "licence": exc[2] if exc else fam, "reason": exc[3] if exc else f"bundled {fam} licence grant"}
        out["bundled"].append(entry)
        if not exc and out["status"] != "denied":
            out.update(status="denied", reason=f"bundled file {path} carries a {fam} licence")
    return out


def forbidden(name: str) -> str | None:
    key = normalize_name(name)
    return next((p for p in FORBIDDEN_PACKAGES if fnmatch.fnmatch(key, p)), None)


def check(lock: dict[str, dict], dists: list[Dist], native_audit: dict | None = None) -> dict:
    by_key: dict[str, Dist] = {}
    for d in dists:
        by_key.setdefault(d.key, d)
    packages, errors = [], []
    for key, entry in sorted(lock.items()):
        if key in FIRST_PARTY:
            continue
        if forbidden(key):
            errors.append(f"{entry['name']}: forbidden telemetry package ({forbidden(key)})")
        d = by_key.get(key)
        if d is None:
            packages.append({"name": entry["name"], "version": entry["version"], "status": "missing",
                             "reason": "locked but no distribution found", "licence": None, "bundled": []})
            errors.append(f"{entry['name']}: no distribution found for locked version {entry['version']}")
            continue
        r = evaluate_dist(d)
        if entry["version"] and d.version != entry["version"]:
            r.update(status="denied", reason=f"version {d.version} does not match lock {entry['version']}")
        packages.append(r)
        if r["status"] in ("denied", "unknown"):
            errors.append(f"{d.name} {d.version}: {r['status']}: {r['reason']}")
    for key, d in sorted(by_key.items()):
        if key in lock or key in FIRST_PARTY:
            continue
        if forbidden(key):
            errors.append(f"{d.name}: forbidden telemetry package present ({forbidden(key)})")
        errors.append(f"{d.name} {d.version}: present but not in the lock (closure must equal the lock)")
    native = check_native(native_audit, lock) if native_audit is not None else None
    if native:
        errors += native["errors"]
    return {
        "schema": SCHEMA,
        "ok": not errors,
        "policy": {"allowed": sorted(ALLOWED), "package_allow": {k: sorted(v) for k, v in PACKAGE_ALLOW.items()},
                   "lgpl_exceptions": LGPL_EXCEPTIONS, "forbidden_packages": FORBIDDEN_PACKAGES,
                   "bundled_file_exceptions": [{"package": a, "path": b, "licence": c} for a, b, c, _ in
                                               BUNDLED_FILE_EXCEPTIONS]},
        "packages": packages,
        "native": native,
        "errors": errors,
        "summary": {s: sum(1 for p in packages if p["status"] == s) for s in
                    ("allowed", "allowed-by-exception", "unknown", "denied", "missing")},
    }


# Statically linked native components (Rust crates) may carry permissive licences outside the short list
# above; those are reported for review, never silently passed. Copyleft or unknown fails.
NATIVE_REVIEWED = {
    "Unicode-3.0": "Unicode data licence (permissive notice); tables in unicode-ident and ICU-derived crates",
    "Unicode-DFS-2016": "Unicode data licence (permissive notice)",
    "Zlib": "zlib licence (permissive)",
    "BSL-1.0": "Boost Software Licence (permissive)",
    "CC0-1.0": "public-domain dedication",
    "0BSD": "zero-clause BSD (permissive)",
    "Unlicense": "public-domain dedication",
    "MPL-2.0": "file-level weak copyleft: allowed only for unmodified crates (we ship upstream binaries)",
}


def check_native(audit: dict, lock: dict[str, dict]) -> dict:
    errors, review = [], []
    for pkg, info in sorted((audit.get("packages") or {}).items()):
        locked = lock.get(normalize_name(pkg))
        if locked is None:
            continue
        if info.get("version") != locked["version"]:
            errors.append(f"native audit for {pkg} covers {info.get('version')}, lock has {locked['version']} "
                          "(re-run make native-audit)")
            continue
        for crate in (info.get("rust") or {}).get("crates", []):
            lic = crate.get("license")
            label = f"{pkg}: crate {crate['name']} {crate['version']}"
            if not lic:
                errors.append(f"{label}: no licence recorded")
                continue
            try:
                node = parse_expression(lic.replace("/", " OR "))
            except ValueError:
                errors.append(f"{label}: unparseable licence {lic!r}")
                continue
            status, reason = evaluate_expression(node, normalize_name(crate["name"]))
            if status in ("allowed", "allowed-by-exception"):
                continue
            ids = _ids(node)
            if status == "unknown" and all(i in ALLOWED or i in NATIVE_REVIEWED for i in ids):
                review.append({"package": pkg, "crate": crate["name"], "version": crate["version"], "license": lic,
                               "linked": "binary" in crate.get("evidence", []),
                               "note": "; ".join(NATIVE_REVIEWED[i] for i in ids if i in NATIVE_REVIEWED)})
                continue
            errors.append(f"{label}: {status}: {reason}")
    for pkg in sorted(k for k, v in lock.items() if (audit.get("packages") or {}).get(v["name"]) is None
                      and k in {normalize_name(n) for n in audit.get("expected_native", [])}):
        errors.append(f"native audit missing for {pkg}")
    return {"errors": errors, "review": review}


def _ids(node) -> list[str]:
    if node[0] == "id":
        return [node[1]]
    return [i for n in node[1] for i in _ids(n)]


# ------------------------------------------------------------------------------------------- CLI
def render(report: dict) -> str:
    lines = []
    for p in report["packages"]:
        extra = "".join(f"\n      bundled {b['path']}: {b['licence']} [{b['status']}]" for b in p.get("bundled", []))
        lines.append(f"{p['status']:22} {p['name']:24} {str(p.get('version')):14} {p.get('licence')}"
                     f"{'  (' + p['source'] + ')' if p.get('source') else ''}{extra}")
    if report.get("native"):
        for r in report["native"]["review"]:
            lines.append(f"{'native-review':22} {r['package']:24} crate {r['crate']} {r['version']}: {r['license']}"
                         f"{' (linked)' if r['linked'] else ' (in Cargo.lock)'}")
    s = report["summary"]
    lines.append(f"\n{len(report['packages'])} runtime distributions: " + ", ".join(f"{k}={v}" for k, v in s.items()))
    for e in report["errors"]:
        lines.append(f"FAIL {e}")
    lines.append("licence gate: " + ("PASS" if report["ok"] else "FAIL"))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--requirements", required=True, type=Path, help="hashed lock defining the runtime closure")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--wheels", type=Path, help="directory of wheels (one per locked package)")
    src.add_argument("--site-packages", type=Path, help="site-packages of a clean venv installed from the lock")
    ap.add_argument("--native-audit", type=Path, help="requirements/native-audit.json (Rust crates in native wheels)")
    ap.add_argument("--json-out", type=Path, help="write the machine-readable report here")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)
    try:
        lock = parse_lock(args.requirements)
        if args.wheels:
            wheels = sorted(args.wheels.glob("*.whl"))
            if not wheels:
                raise FileNotFoundError(f"no wheels in {args.wheels}")
            dists = [dist_from_wheel(w) for w in wheels]
        else:
            dists = dists_from_site_packages(args.site_packages)
        audit = json.loads(args.native_audit.read_text()) if args.native_audit else None
    except (OSError, ValueError, StopIteration) as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return 2
    report = check(lock, dists, audit)
    if args.json_out:
        args.json_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not args.quiet or not report["ok"]:
        print(render(report))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
