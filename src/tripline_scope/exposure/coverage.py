"""Coverage, exclusions, parser failures and missing evidence recorded while a scan runs.

Every unit of work (a root, a database check, an identity input) ends up ``assessed``, ``not assessed`` (no
capability or no input: e.g. an unsupported engine or format) or ``unavailable`` (input present but could not be
used: too large, unreadable, malformed, over budget). Locations are display strings already scrubbed by the
caller; reasons are fixed templates. Lists are bounded; overflow is counted, never silently dropped.
"""

from __future__ import annotations

from collections import Counter, defaultdict

from tripline_scope.core.redact import scrub_text

LIST_CAP = 400


def _clean(s: str | None, n: int = 240) -> str | None:
    return None if s is None else scrub_text(str(s))[:n]


class Recorder:
    def __init__(self, cap: int = LIST_CAP):
        self.cap = cap
        self.assessed: dict[str, dict[str, dict]] = defaultdict(dict)
        self.not_assessed: list[dict] = []
        self.unavailable: list[dict] = []
        self.overflow: Counter = Counter()
        self.exclusions: list[dict] = []
        self.exclusion_counts: Counter = Counter()
        self.suppressed: Counter = Counter()
        self.parser_failures: list[dict] = []
        self.parser_failure_counts: Counter = Counter()
        self.missing: list[dict] = []
        self.counts: dict[str, Counter] = defaultdict(Counter)

    # ------------------------------------------------------------------ units
    def assess(self, controls, unit: str, detail: str | None = None) -> None:
        for c in _ctl(controls):
            cur = self.assessed[c].get(unit)
            if cur is None:
                self.assessed[c][unit] = {"unit": unit, "detail": _clean(detail)}
            elif detail:
                cur["detail"] = _clean(detail)

    def is_assessed(self, control: str, unit: str) -> bool:
        return unit in self.assessed.get(control, {})

    def _add(self, lst: list, key: str, item: dict) -> None:
        if len(lst) >= self.cap:
            self.overflow[(key, item.get("reason"))] += 1
            return
        lst.append(item)

    def not_assess(self, controls, unit: str, reason: str, location: str | None = None) -> None:
        self._add(self.not_assessed, "not_assessed",
                  {"controls": _ctl(controls), "unit": unit, "location": _clean(location), "reason": _clean(reason)})

    def unavail(self, controls, unit: str, reason: str, location: str | None = None) -> None:
        self._add(self.unavailable, "unavailable",
                  {"controls": _ctl(controls), "unit": unit, "location": _clean(location), "reason": _clean(reason)})

    # ------------------------------------------------------------------ other records
    def exclude(self, kind: str, unit: str, location: str | None, reason: str) -> None:
        self.exclusion_counts[(kind, unit)] += 1
        if len(self.exclusions) < self.cap:
            self.exclusions.append({"kind": kind, "unit": unit, "location": _clean(location), "reason": _clean(reason)})
        else:
            self.overflow[("exclusions", kind)] += 1

    def suppress(self, control: str, reason: str, n: int = 1) -> None:
        self.suppressed[(control, reason)] += n

    def parser_failure(self, fmt: str, unit: str, location: str | None, error_class: str) -> None:
        """Only the exception *class* is kept: messages from parsers can echo file content."""
        self.parser_failure_counts[(fmt, error_class)] += 1
        if len(self.parser_failures) < self.cap:
            self.parser_failures.append({"format": fmt, "unit": unit, "location": _clean(location),
                                         "error_class": error_class})
        else:
            self.overflow[("parser_failures", fmt)] += 1

    def missing_evidence(self, control: str, item: str, reason: str, count: int | None = None) -> None:
        entry = {"control": control, "item": _clean(item), "reason": _clean(reason), "count": count}
        if entry not in self.missing:
            self.missing.append(entry)

    def count(self, control: str, key: str, n: int = 1) -> None:
        self.counts[control][key] += n

    # ------------------------------------------------------------------ export
    def to_dict(self) -> dict:
        return {
            "assessed": {c: sorted(v.values(), key=lambda x: x["unit"]) for c, v in sorted(self.assessed.items())},
            "not_assessed": self.not_assessed,
            "unavailable": self.unavailable,
            "overflow": [{"list": k[0], "reason": k[1], "count": n} for k, n in sorted(self.overflow.items(), key=str)],
            "exclusions": self.exclusions,
            "exclusion_counts": [{"kind": k[0], "unit": k[1], "count": n}
                                 for k, n in sorted(self.exclusion_counts.items())],
            "suppressed": [{"control": k[0], "reason": k[1], "count": n} for k, n in sorted(self.suppressed.items())],
            "parser_failures": self.parser_failures,
            "parser_failure_counts": [{"format": k[0], "error_class": k[1], "count": n}
                                      for k, n in sorted(self.parser_failure_counts.items())],
            "missing_evidence": self.missing,
            "counts": {c: dict(sorted(v.items())) for c, v in sorted(self.counts.items())},
        }


def _ctl(controls) -> list[str]:
    return [controls] if isinstance(controls, str) else sorted(controls)
