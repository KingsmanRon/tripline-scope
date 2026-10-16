"""Finding model shared by every Module A detector: severity, stable keyed ids, count bands and ranking.

A finding never carries a secret value or a patient record. Identifiers that are derived from sensitive inputs
(secret fingerprints, finding ids, evidence ids) are keyed HMACs under the case key (``core.crypto.Fingerprinter``)
rendered in lowercase base32, which keeps them case-local and avoids long digit runs that look like identifiers.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from tripline_scope.core.canonical import canonical_bytes

CONTROLS = {
    "A1": "Plaintext secrets",
    "A2": "Excessive privileges",
    "A3": "Uncontrolled patient-data copies",
    "A4": "Risky database configuration",
    "A5": "Supplier access",
}
SEVERITIES = ("critical", "high", "medium", "low", "info")
LEVELS = ("low", "medium", "high")
STATES = ("new", "open", "mitigated", "accepted-risk", "not-assessed")
BASES = ("observation", "inference", "unknown")

# (impact, likelihood) -> severity
_MATRIX = {
    ("high", "high"): "critical",
    ("high", "medium"): "high",
    ("medium", "high"): "high",
    ("high", "low"): "medium",
    ("medium", "medium"): "medium",
    ("low", "high"): "medium",
    ("medium", "low"): "low",
    ("low", "medium"): "low",
    ("low", "low"): "low",
}
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
LEVEL_RANK = {"high": 0, "medium": 1, "low": 2}

# Stable remediation action codes (documented contract; Module B keys containment advice on them).
FIX_ACTIONS = {
    "rotate-and-vault-credential": "Rotate the credential, move it to a secrets vault or protected configuration store "
                                   "and remove the plaintext copy (including repository history and backups).",
    "rotate-signing-key": "Generate a new key, deploy it from protected storage, retire the exposed key and invalidate "
                          "anything it signed where feasible.",
    "reduce-database-role-grants": "Reduce the principal's role memberships and grants to what its documented function "
                                   "needs (least privilege); prefer a dedicated role per function.",
    "remove-or-protect-copy": "Confirm ownership and purpose; move the copy to controlled storage or remove it under the "
                              "records-retention schedule (never delete evidence automatically), restrict access and "
                              "record the decision.",
    "restore-auditing": "Enable and protect database auditing (logins, permission changes and access to patient "
                        "tables), retain logs centrally and monitor them.",
    "disable-shell-execution": "Disable database-originated shell or external-code execution and remove principals that "
                               "can enable it, unless a documented, approved need exists.",
    "remove-cross-server-link": "Remove the cross-server link or restrict it to a dedicated least-privilege remote login "
                                "with a documented purpose.",
    "revoke-public-access": "Revoke guest/PUBLIC access to the database and patient objects; grant access only to named "
                            "roles.",
    "review-service-account": "Run the service under a dedicated least-privilege account and protect its credentials.",
    "disable-or-remove-account": "Confirm with the account owner; disable, then remove the account and its grants under "
                                 "the joiner-mover-leaver process.",
    "assign-individual-accounts": "Replace the shared identity with individual named accounts so access is attributable.",
    "enforce-mfa": "Require and verify MFA for the account (conditional access or equivalent) and keep evidence of it.",
    "review-supplier-access": "Review the supplier account against the contract: limit rights to the contracted scope, "
                              "time-box access and record the review.",
    "link-account-to-contract": "Link the external account to a current supplier contract and owner, or disable it.",
    "enforce-password-policy": "Enforce the password policy and expiry for SQL-authenticated logins or replace them with "
                               "directory-integrated accounts.",
}


def b32(hexstr: str, length: int = 20) -> str:
    """Lowercase RFC 4648 base32 of a hex digest, truncated (no padding)."""
    return base64.b32encode(bytes.fromhex(hexstr)).decode("ascii").lower().rstrip("=")[:length]


def severity_of(impact: str, likelihood: str) -> str:
    return _MATRIX[(impact, likelihood)]


def bump(level: str, n: int = 1) -> str:
    """Raise (n > 0) or lower (n < 0) a low/medium/high level, saturating."""
    i = LEVELS.index(level) + n
    return LEVELS[max(0, min(len(LEVELS) - 1, i))]


def count_band(n: int | None) -> str:
    if n is None:
        return "unknown"
    if n <= 0:
        return "0"
    if n < 10:
        return "1-9"
    if n < 100:
        return "10-99"
    if n < 1000:
        return "100-999"
    if n < 10_000:
        return "1k-10k"
    return "10k+"


def size_band(n: int | None) -> str:
    if n is None:
        return "unknown"
    for limit, label in ((1 << 10, "<1 KiB"), (1 << 20, "1 KiB-1 MiB"), (100 << 20, "1-100 MiB"), (1 << 30, "100 MiB-1 GiB")):
        if n < limit:
            return label
    return ">=1 GiB"


class Keys:
    """Case-local keyed fingerprints used for ids (never plain hashes of secrets or low-entropy values)."""

    def __init__(self, store):
        self._secret = store.fingerprinter("exposure-secret")
        self._finding = store.fingerprinter("exposure-finding")
        self._evidence = store.fingerprinter("exposure-evidence")
        self._file = store.fingerprinter("exposure-file")

    def secret(self, value: str) -> str:
        return b32(self._secret(value, 64), 20)

    def file(self, data: bytes) -> str:
        return b32(self._file(data, 64), 26)

    def path(self, unit: str, rel: str) -> str:
        return b32(self._file(f"path|{unit}|{rel}", 64), 20)

    def finding_id(self, parts: list) -> str:
        return "AF-" + b32(self._finding(canonical_bytes(parts), 64), 20)

    def evidence_id(self, parts: list) -> str:
        return "EV-" + b32(self._evidence(canonical_bytes(parts), 64), 16)


@dataclass
class Finding:
    control_id: str
    rule_id: str
    title: str
    impact: str
    likelihood: str
    rationale: dict
    asset: dict
    location: dict
    coverage_unit: str
    id_parts: list
    basis: str
    confidence: float
    confidence_reason: str
    fix_action: str
    source_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    ownership: dict = field(default_factory=dict)
    target_asset: dict | None = None
    redacted_context: str | None = None
    secret_fingerprint: str | None = None
    detector: str = ""
    finding_id: str = ""
    related_findings: list[str] = field(default_factory=list)

    def __post_init__(self):
        if self.control_id not in CONTROLS:
            raise ValueError("unknown control")
        if self.impact not in LEVELS or self.likelihood not in LEVELS:
            raise ValueError("impact/likelihood must be low|medium|high")
        if self.basis not in BASES:
            raise ValueError("basis must be observation|inference|unknown")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")
        if self.fix_action not in FIX_ACTIONS:
            raise ValueError("unknown fix action")

    @property
    def severity(self) -> str:
        return severity_of(self.impact, self.likelihood)

    def to_dict(self) -> dict:
        d = {
            "finding_id": self.finding_id,
            "control_id": self.control_id,
            "control": CONTROLS[self.control_id],
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "severity_rationale": dict(self.rationale),
            "asset": dict(self.asset),
            "target_asset": dict(self.target_asset) if self.target_asset else None,
            "location": dict(self.location),
            "coverage_unit": self.coverage_unit,
            "evidence_ids": sorted(set(self.evidence_ids)),
            "source_ids": sorted(set(self.source_ids)),
            "basis": self.basis,
            "provenance": {"detector": self.detector, "rule_id": self.rule_id, "source_ids": sorted(set(self.source_ids))},
            "confidence": round(self.confidence, 2),
            "confidence_reason": self.confidence_reason,
            "caveats": list(dict.fromkeys(self.caveats)),
            "ownership": dict(self.ownership),
            "suggested_fix": {"action": self.fix_action, "text": FIX_ACTIONS[self.fix_action]},
            "details": dict(self.details),
            "redacted_context": self.redacted_context,
            "secret_fingerprint": self.secret_fingerprint,
            "related_findings": sorted(set(self.related_findings)),
        }
        return d


def rank_key(f: dict):
    return (SEVERITY_RANK[f["severity"]], LEVEL_RANK[f["impact"]], LEVEL_RANK[f["likelihood"]], -f["confidence"],
            f["control_id"], f["title"], f["finding_id"])


def rank(findings: list[dict]) -> list[dict]:
    out = sorted(findings, key=rank_key)
    for i, f in enumerate(out, 1):
        f["rank"] = i
    return out
