"""Shared evidence model.

Two independent axes are recorded for every claim, event, path, finding and scope decision:

* **basis** — how we know: ``observation`` (directly logged/detected), ``inference`` (correlated from partial
  evidence), ``hypothesis`` (unverified explanation) or ``unknown``.
* **consequence_class** — what the evidence supports happened to the data (the mandatory
  evidence-of-access versus evidence-of-theft rule): ``access_observed`` < ``export_or_staging_observed`` <
  ``egress_suspected`` < ``exfiltration_evidenced``; or ``undetermined`` when gaps prevent a determination.

And four separate scope tiers, each a different evidence threshold, are kept apart in every report:
``observed_access``, ``possible_exposure``, ``confirmed_exfiltration`` and ``notification_scope`` (the last is
decided by the Information Officer with counsel; software proposes and explains only).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum


class Basis(StrEnum):
    OBSERVATION = "observation"
    INFERENCE = "inference"
    HYPOTHESIS = "hypothesis"
    UNKNOWN = "unknown"


class Consequence(StrEnum):
    ACCESS_OBSERVED = "access_observed"
    EXPORT_OR_STAGING_OBSERVED = "export_or_staging_observed"
    EGRESS_SUSPECTED = "egress_suspected"
    EXFILTRATION_EVIDENCED = "exfiltration_evidenced"
    UNDETERMINED = "undetermined"


class ScopeTier(StrEnum):
    OBSERVED_ACCESS = "observed_access"
    POSSIBLE_EXPOSURE = "possible_exposure"
    CONFIRMED_EXFILTRATION = "confirmed_exfiltration"
    NOTIFICATION_SCOPE = "notification_scope"


class EdgeLabel(StrEnum):
    DIRECT = "direct"            # joined on an exact shared identifier (session/request/logon id)
    CORRELATED = "correlated"    # joined by bounded time window / attribute similarity: an inference
    UNRESOLVED = "unresolved"    # evidence stops here


class TimePrecision(StrEnum):
    MILLISECOND = "millisecond"
    SECOND = "second"
    MINUTE = "minute"
    DAY = "day"
    UNKNOWN = "unknown"


NOT_DETERMINABLE = "not determinable"

# Evidence that can establish exfiltration on its own. Traffic volume or correlation never qualifies.
EXFILTRATION_EVIDENCE_KINDS = {
    "independently_confirmed_external_copy",   # e.g. leak sample received via lawyers, matched to records
    "captured_transfer_validated_content",     # a captured transfer whose content and destination were validated
    "corroborated_forensic_artefact",          # forensic artefacts corroborated by an independent source
}

_ORDER = [Consequence.ACCESS_OBSERVED, Consequence.EXPORT_OR_STAGING_OBSERVED, Consequence.EGRESS_SUSPECTED,
          Consequence.EXFILTRATION_EVIDENCED]


@dataclass
class Claim:
    claim_id: str
    statement: str                       # templated text; never identifiers or secret values
    basis: Basis
    source_ids: list[str]
    evidence_ids: list[str]
    parser: str                          # "<parser-name>/<version>" or "<detector>/<version>"
    time_precision: TimePrecision
    confidence: float                    # 0..1
    confidence_reason: str
    observation_type: str | None = None
    consequence_class: Consequence | None = None
    source_time_window: list[str | None] = field(default_factory=lambda: [None, None])
    limitations: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    exfiltration_evidence_kind: str | None = None

    def __post_init__(self):
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")
        validate_consequence(self.consequence_class, self.exfiltration_evidence_kind, self.evidence_ids)
        if self.basis in (Basis.INFERENCE, Basis.HYPOTHESIS) and self.consequence_class == Consequence.EXFILTRATION_EVIDENCED:
            raise ValueError("an inference or hypothesis cannot evidence exfiltration")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["basis"] = str(self.basis)
        d["time_precision"] = str(self.time_precision)
        d["consequence_class"] = str(self.consequence_class) if self.consequence_class else None
        d["confidence"] = round(self.confidence, 4)
        return d


def validate_consequence(cls: Consequence | None, evidence_kind: str | None, evidence_ids: list[str]) -> None:
    """Exfiltration must be backed by a qualifying, cited piece of independently verifiable evidence."""
    if cls == Consequence.EXFILTRATION_EVIDENCED:
        if evidence_kind not in EXFILTRATION_EVIDENCE_KINDS:
            raise ValueError("exfiltration_evidenced requires an independently verifiable evidence kind")
        if not evidence_ids:
            raise ValueError("exfiltration_evidenced requires cited evidence ids")


def strongest(classes) -> Consequence:
    """The strongest supported consequence among ``classes`` (``undetermined`` only if nothing else)."""
    best = None
    for c in classes:
        c = Consequence(c)
        if c == Consequence.UNDETERMINED:
            continue
        if best is None or _ORDER.index(c) > _ORDER.index(best):
            best = c
    return best or Consequence.UNDETERMINED
