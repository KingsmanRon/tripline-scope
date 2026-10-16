"""Column classification rules.

Every decision combines a **name hint** (:mod:`hints`) with **value evidence** from the sample
(:mod:`values`), and records its basis in ``reasons``:

* ``hint`` – the column name points to the category and the values do not contradict it;
* ``values`` – the values alone point to the category (stricter thresholds, lower confidence);
* ``override`` – ``case.yaml column_overrides`` (always wins, confidence 1.0).

Context guards against false positives: arbitrary 13-digit numbers are not ID numbers unless a high share are
valid SA IDs (date, citizenship digit and Luhn) or the name says so; Luhn-valid numbers are card numbers only
with a card prefix and a very high match rate (or a card name hint); bank accounts need a bank name hint.
The full scan then confirms (or demotes) the sample decision.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .categories import IDENTITY_GROUPS, SPECS
from .hints import name_hint, tokenise
from .values import Profile


@dataclass
class Decision:
    category: str
    confidence: float
    basis: str                      # hint | values | override | table
    reasons: list[str] = field(default_factory=list)
    hint: str | None = None
    standard_field: str | None = None
    date_parser: str | None = None
    id_pad: bool = False

    def set(self, category: str, confidence: float, basis: str, reason: str) -> Decision:
        self.category, self.confidence, self.basis = category, round(confidence, 3), basis
        self.reasons.append(reason)
        self.standard_field = SPECS[category].standard_field
        return self


# Minimum confirmed (full-scan) match rate per category and basis; below it the decision is demoted.
MIN_FULL_RATE = {
    ("sa_id", "values"): 0.8, ("sa_id", "hint"): 0.05, ("guardian_sa_id", "hint"): 0.05,
    ("card_number", "values"): 0.7,
    ("phone", "values"): 0.8, ("phone", "hint"): 0.05, ("guardian_phone", "hint"): 0.05,
    ("email", "values"): 0.7, ("email", "hint"): 0.05, ("guardian_email", "hint"): 0.05,
    ("icd10", "values"): 0.8, ("sex", "values"): 0.9, ("dob", "hint"): 0.05, ("record_date", "hint"): 0.05,
    ("passport", "hint"): 0.05, ("medical_aid_no", "hint"): 0.0,
}

_GENERIC_NAME_TOKENS = {"name", "names", "naam"}


def hint_for(column: str, table: str) -> str | None:
    return name_hint(column, table)


def needs_id_pad(hint: str | None, numeric: bool) -> bool:
    """Numeric storage (or Excel) drops the leading zero of IDs of people born 2000-2009."""
    return numeric or hint in ("sa_id", "guardian_sa_id")


def classify_column(column: str, table: str, prof: Profile, *, numeric: bool = False,
                    readable: bool = True) -> Decision:
    hint = hint_for(column, table)
    d = Decision("other", 0.5, "values", hint=hint, date_parser=prof.date_parser, id_pad=needs_id_pad(hint, numeric))
    if not readable:
        return d.set("other", 0.3, "values", "not_read_binary_or_unsupported_type")
    r = prof.rate
    n = prof.nonnull
    if n == 0:
        if hint and hint in SPECS:
            return d.set(hint, 0.3, "hint", "name_hint_no_values")
        return d.set("other", 0.3, "values", "no_values")

    # 1. payment data first, so card/bank values are never mistaken for anything that is extracted
    if hint == "card_number":
        return d.set("card_number", 0.95 if r("card") >= 0.5 else 0.7, "hint", "name_hint")
    if r("card") >= 0.8 and r("digits") >= 0.9 and hint not in ("sa_id", "guardian_sa_id", "patient_key"):
        return d.set("card_number", 0.9, "values", "card_prefix_luhn_length")
    if hint == "bank_account":
        return d.set("bank_account", 0.9 if r("bank") >= 0.8 else 0.6, "hint", "name_hint")

    # 2. guardians / next of kin
    if hint == "guardian_sa_id":
        if r("sa_id") >= 0.1:
            return d.set("guardian_sa_id", 0.95 if r("sa_id") >= 0.9 else 0.75, "hint", "name_hint+valid_sa_id")
        return d.set("other_identifier", 0.5, "hint", "name_hint_but_no_valid_sa_id")
    if hint == "guardian_phone":
        if r("email") >= 0.5:      # "parent_contact" holding e-mail addresses
            return d.set("guardian_email", 0.9, "hint", "guardian_context+email_values")
        return d.set("guardian_phone", 0.95 if r("phone") >= 0.5 else 0.6, "hint", "name_hint")
    if hint == "guardian_email":
        return d.set("guardian_email", 0.95 if r("email") >= 0.5 else 0.6, "hint", "name_hint")
    if hint == "guardian_name":
        return d.set("guardian_name", 0.85 if r("name") >= 0.6 else 0.5, "hint", "name_hint")

    # 3. identity numbers
    if hint == "sa_id":
        if r("sa_id") >= 0.98:
            return d.set("sa_id", 0.99, "hint", "name_hint+valid_sa_id")
        if r("sa_id") >= 0.5:
            return d.set("sa_id", 0.9, "hint", "name_hint+mostly_valid_sa_id")
        if r("sa_id") >= 0.1:
            return d.set("sa_id", 0.6, "hint", "name_hint+some_valid_sa_id")
        if r("passport") >= 0.5:
            return d.set("passport", 0.6, "hint", "id_column_holds_passport_like_values")
        return d.set("other_identifier", 0.5, "hint", "name_hint_but_no_valid_sa_id")
    if r("sa_id") >= 0.9 and hint not in ("patient_key", "medical_aid_no", "phone"):
        return d.set("sa_id", 0.85, "values", "high_valid_sa_id_rate_without_name_hint")
    if hint == "passport":
        return d.set("passport", 0.9 if r("passport") >= 0.5 else 0.6, "hint", "name_hint")

    # 4. contact
    if r("email") >= 0.8:
        return d.set("email", 0.95, "hint" if hint == "email" else "values", "email_format")
    if hint == "email":
        return d.set("email", 0.8 if r("email") >= 0.3 else 0.5, "hint", "name_hint")
    if hint == "phone":
        return d.set("phone", 0.95 if r("phone") >= 0.5 else 0.6, "hint", "name_hint")
    if hint == "contact":
        if r("email") >= 0.5:
            return d.set("email", 0.85, "hint", "contact_column_with_email_values")
        return d.set("phone", 0.85 if r("phone") >= 0.5 else 0.5, "hint", "contact_column_with_phone_values")
    if r("phone_formatted") >= 0.9 and prof.distinct_ratio >= 0.3 and hint is None:
        return d.set("phone", 0.75, "values", "sa_phone_format_without_name_hint")

    # 5. dates
    if hint == "dob":
        return d.set("dob", 0.95 if r("date") >= 0.5 else 0.5, "hint", "name_hint+date_values")
    if hint in ("record_date", "record_date_strong") and r("date") >= 0.5:
        return d.set("record_date", 0.85, "hint", "name_hint+date_values")

    # 6. names and demographics
    if hint in ("first_name", "middle_name", "last_name", "full_name", "maiden_name", "other_names"):
        # "other names" are resolved per table (resolve_names): middle names, given names or a full name
        cat = {"middle_name": "first_name", "other_names": "full_name"}.get(hint, hint)
        d.set(cat, 0.9 if r("name") >= 0.6 else 0.5, "hint", "name_hint")
        if hint == "middle_name":
            d.standard_field = "middle_names"
        return d
    if hint == "sex":
        # letters (M/F, Male/Female) or ISO 5218 digits (1 male, 2 female, 0/9 unknown) behind a sex hint
        return d.set("sex", 0.95 if r("sex") + r("sex_iso") >= 0.8 else 0.5, "hint", "name_hint")
    if r("sex") >= 0.98 and prof.distinct <= 6 and prof.nonnull >= 20 and hint is None:
        return d.set("sex", 0.7, "values", "sex_codes_without_name_hint")
    if hint == "postal_code":
        return d.set("postal_code", 0.9 if r("postal") >= 0.7 else 0.6, "hint", "name_hint")
    if hint == "address":
        return d.set("address", 0.8, "hint", "name_hint")
    if hint == "language":
        return d.set("language", 0.8, "hint", "name_hint")

    # 7. medical aid
    if hint == "medical_aid_no":
        return d.set("medical_aid_no", 0.9 if r("med_aid") >= 0.5 else 0.6, "hint", "name_hint+format")
    if hint == "medical_aid_scheme":
        return d.set("medical_aid_scheme", 0.8, "hint", "name_hint")

    # 8. clinical (flagged, never extracted)
    if hint == "icd10":
        if r("icd10") >= 0.5:
            return d.set("icd10", 0.95, "hint", "name_hint+icd10_pattern")
        return d.set("icd10", 0.7, "hint", "name_hint_diagnosis_text")
    if hint == "test_result":
        return d.set("test_result", 0.8, "hint", "name_hint")
    if hint == "test_code":
        return d.set("test_code", 0.8, "hint", "name_hint")
    if (r("icd10") >= 0.9 and prof.distinct >= 3 and hint is None and prof.avg_len <= 8
            and prof.distinct_ratio <= 0.5):
        return d.set("icd10", 0.75, "values", "icd10_pattern_without_name_hint")
    if hint == "clinical_free_text":
        return d.set("clinical_free_text", 0.85 if r("free_text") >= 0.2 else 0.6, "hint", "name_hint")
    if r("free_text") >= 0.5 and hint in (None, "other_identifier"):
        return d.set("clinical_free_text", 0.5, "values", "free_text_possibly_clinical")

    # 9. record keys (role resolved per table) and other identifiers
    if hint == "patient_key":
        return d.set("patient_key", 0.8, "hint", "name_hint")
    if hint in ("record_date", "record_date_strong"):
        return d.set("other", 0.5, "hint", "date_hint_but_values_not_dates")
    if hint == "other_identifier":
        return d.set("other_identifier", 0.6, "hint", "name_hint")
    if hint == "account_no":
        if r("bank") >= 0.8:      # flagged conservatively: an account number that looks like a bank account
            return d.set("bank_account", 0.6, "hint", "account_number_with_bank_like_values")
        return d.set("other_identifier", 0.6, "hint", "patient_billing_account_number")
    if hint == "not_result":
        return d.set("other", 0.6, "hint", "workflow_status_not_a_result")
    if r("digits") >= 0.9 and prof.avg_len >= 6:
        return d.set("other_identifier", 0.5, "values", "numeric_identifier_like")
    return d.set("other", 0.5, "values", "no_rule_matched")


def confirm(d: Decision, full_match_rate: float | None, numeric_like: bool) -> Decision:
    """Apply the full-scan match rate to a sample decision (demote when it is not confirmed)."""
    if d.basis == "override" or full_match_rate is None:
        return d
    floor = MIN_FULL_RATE.get((d.category, d.basis))
    if floor is not None and full_match_rate < floor:
        demoted = "other_identifier" if numeric_like else "other"
        d.reasons.append(f"demoted_after_full_scan_from_{d.category}")
        return d.set(demoted, 0.4, d.basis, "full_scan_match_rate_below_threshold")
    return d


@dataclass
class ColumnState:
    """Per-column working state inside the discovery engine."""

    index: int
    name: str
    data_type: str
    numeric: bool
    readable: bool
    decision: Decision
    profile: Profile | None = None
    override: bool = False
    full_rows: int = 0
    full_nonnull: int = 0
    full_match: int = 0

    @property
    def token(self) -> str:
        return tokenise(self.name)


def apply_override(cs: ColumnState, category: str) -> None:
    d = cs.decision
    d.set(category, 1.0, "override", "case_yaml_column_override")
    cs.override = True


def resolve_names(cols: list[ColumnState]) -> None:
    """Resolve name columns that depend on their neighbours.

    * ``Names`` + ``Surname`` (common SA form layout): the generic name column holds first names;
    * ``other_names`` beside a forename and a family-name column holds middle names; beside a family name only it
      holds the given names; alone it is a full name. A full name is used only without separate first/last columns.
    """
    has_last = any(c.decision.category == "last_name" for c in cols)
    has_first = any(c.decision.category == "first_name" and c.decision.standard_field == "first_name"
                    and c.decision.hint != "other_names" for c in cols)
    for c in cols:
        if c.override or c.decision.category != "full_name":
            continue
        conf = min(c.decision.confidence, 0.85)
        if c.decision.hint == "other_names":
            if has_first and has_last:
                c.decision.set("first_name", conf, "table", "other_names_beside_first_and_last_name")
                c.decision.standard_field = "middle_names"
            elif has_last:
                c.decision.set("first_name", conf, "table", "other_names_beside_surname_are_given_names")
            continue
        if has_last and not has_first and c.token in _GENERIC_NAME_TOKENS:
            c.decision.set("first_name", conf, "table", "generic_name_column_beside_surname")


def identity_groups(cols: list[ColumnState]) -> set[str]:
    return {IDENTITY_GROUPS[c.decision.category] for c in cols
            if c.decision.category in IDENTITY_GROUPS and c.decision.confidence >= 0.5}


def is_identity_table(cols: list[ColumnState]) -> bool:
    return len(identity_groups(cols)) >= 2


def _key_quality(c: ColumnState) -> float:
    p = c.profile
    if p is None or p.nonnull == 0:
        return 0.0
    if p.distinct_capped:
        return 1.0 - p.null_rate
    return min(p.distinct_ratio, 1.0) * (1.0 - p.null_rate)


def resolve_keys(cols: list[ColumnState], identity: bool, table_key: list[str]) -> ColumnState | None:
    """Choose the identity table's local patient key, or turn key-like columns into patient references.

    Returns the chosen patient-key column (identity tables only)."""
    overridden = [c for c in cols if c.override and c.decision.category == "patient_key"]
    if not identity:
        for c in cols:
            if c.decision.category == "patient_key" and not c.override:
                c.decision.set("patient_ref", 0.75, "table", "patient_key_like_column_in_non_identity_table")
        return overridden[0] if overridden else None
    if overridden:
        chosen = overridden[0]
    else:
        cands = [c for c in cols if c.decision.category == "patient_key"]
        cands += [c for c in cols if c.token in ("id", "uid") and c.decision.category in ("other_identifier", "other")]
        if len(table_key) == 1:
            cands += [c for c in cols if c.name == table_key[0] and c not in cands
                      and c.decision.category in ("other_identifier", "other")]
        cands = [c for c in cands if _key_quality(c) >= 0.95]
        chosen = max(cands, key=lambda c: (c.decision.category == "patient_key", _key_quality(c)), default=None)
    for c in cols:
        if c is chosen:
            if not c.override:
                c.decision.set("patient_key", 0.9 if c.decision.category == "patient_key" else 0.7, "table",
                               "unique_key_of_identity_table")
        elif c.decision.category == "patient_key" and not c.override:
            if _key_quality(c) < 0.95:
                c.decision.set("patient_ref", 0.75, "table", "repeating_patient_key_like_column")
            else:
                c.decision.set("other_identifier", 0.6, "table", "secondary_key_in_identity_table")
    return chosen
