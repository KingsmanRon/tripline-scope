"""Column categories, what each one is used for, and where it lands in the standard extract schema (PLAN §5).

A category decides three things:

* ``purpose``: ``matching`` (used to link rows to people), ``contact`` (used to reach people), ``exposure``
  (only its presence matters: what kind of data was exposed) or ``none``;
* ``standard_field``: the column of the standard extract schema it feeds (``None`` = never extracted);
* ``exposure``: the exposure category it contributes to (row-level ``_has_<exposure>`` flags and reports).

Clinical, card and bank categories have no standard field: their values are never copied anywhere, only the
presence flags are.
"""

from __future__ import annotations

from dataclasses import dataclass

DISCOVERY_SCHEMA = "tripline.discovery/v1"
DISCOVERY_METHOD = "discovery/0.1.0"

EXPOSURE_CATEGORIES = (
    "identity_number", "name", "date_of_birth", "contact_details", "address", "medical_aid",
    "clinical_diagnosis", "clinical_tests", "clinical_results", "clinical_notes", "payment_card", "bank_account",
)


@dataclass(frozen=True)
class CategorySpec:
    purpose: str
    standard_field: str | None
    exposure: str | None
    map_group: str          # readiness data-map grouping


SPECS: dict[str, CategorySpec] = {
    "sa_id": CategorySpec("matching", "sa_id", "identity_number", "identity_numbers"),
    "passport": CategorySpec("matching", "passport_no", "identity_number", "identity_numbers"),
    "phone": CategorySpec("contact", "phone", "contact_details", "contact"),
    "email": CategorySpec("contact", "email", "contact_details", "contact"),
    "first_name": CategorySpec("matching", "first_name", "name", "names"),
    "last_name": CategorySpec("matching", "last_name", "name", "names"),
    "full_name": CategorySpec("matching", "full_name", "name", "names"),
    "maiden_name": CategorySpec("matching", "maiden_name", "name", "names"),
    "dob": CategorySpec("matching", "dob", "date_of_birth", "date_of_birth"),
    "sex": CategorySpec("matching", "sex", None, "demographics"),
    "address": CategorySpec("contact", "address", "address", "contact"),
    "postal_code": CategorySpec("contact", "postal_code", "address", "contact"),
    "medical_aid_no": CategorySpec("matching", "medical_aid_no", "medical_aid", "medical_aid"),
    "medical_aid_scheme": CategorySpec("exposure", None, "medical_aid", "medical_aid"),
    "patient_key": CategorySpec("matching", "local_patient_key", None, "record_keys"),
    "patient_ref": CategorySpec("matching", "patient_ref", None, "record_keys"),
    "guardian_name": CategorySpec("contact", "guardian_name", "name", "names"),
    "guardian_phone": CategorySpec("contact", "guardian_phone", "contact_details", "contact"),
    "guardian_email": CategorySpec("contact", "guardian_email", "contact_details", "contact"),
    "guardian_sa_id": CategorySpec("matching", "guardian_sa_id", "identity_number", "identity_numbers"),
    "language": CategorySpec("contact", "language", None, "demographics"),
    "record_date": CategorySpec("matching", "record_date", None, "record_dates"),
    "icd10": CategorySpec("exposure", None, "clinical_diagnosis", "clinical"),
    "test_code": CategorySpec("exposure", None, "clinical_tests", "clinical"),
    "test_result": CategorySpec("exposure", None, "clinical_results", "clinical"),
    "clinical_free_text": CategorySpec("exposure", None, "clinical_notes", "clinical"),
    "card_number": CategorySpec("exposure", None, "payment_card", "payment"),
    "bank_account": CategorySpec("exposure", None, "bank_account", "payment"),
    "other_identifier": CategorySpec("none", None, None, "other"),
    "other": CategorySpec("none", None, None, "other"),
}

CATEGORIES = tuple(SPECS)

# Categories whose values must never leave the source, not even into encrypted working files.
NEVER_EXTRACTED = frozenset({"icd10", "test_code", "test_result", "clinical_free_text", "card_number",
                             "bank_account", "medical_aid_scheme", "other_identifier", "other"})

# Identity groups used to decide whether a table describes people (>= 2 groups => identity table).
IDENTITY_GROUPS = {
    "first_name": "name", "last_name": "name", "full_name": "name", "maiden_name": "name",
    "dob": "dob", "sa_id": "id", "passport": "passport",
}

# The standard extract schema (PLAN §5), in column order. Types: s = string, d = date, b = bool.
STANDARD_FIELDS: tuple[tuple[str, str], ...] = (
    ("_row_key", "s"), ("_source_id", "s"), ("_table", "s"),
    ("sa_id", "s"), ("passport_no", "s"), ("first_name", "s"), ("middle_names", "s"), ("last_name", "s"),
    ("full_name", "s"), ("maiden_name", "s"), ("dob", "d"), ("sex", "s"), ("medical_aid_no", "s"),
    ("local_patient_key", "s"), ("patient_ref", "s"), ("phone", "s"), ("phone_alt", "s"), ("email", "s"),
    ("address", "s"), ("postal_code", "s"), ("language", "s"), ("guardian_name", "s"), ("guardian_phone", "s"),
    ("guardian_email", "s"), ("guardian_sa_id", "s"), ("record_date", "d"),
) + tuple((f"_has_{e}", "b") for e in EXPOSURE_CATEGORIES)

PERSON_FIELDS = tuple(f for f, _ in STANDARD_FIELDS if not f.startswith("_"))
FLAG_FIELDS = tuple(f"_has_{e}" for e in EXPOSURE_CATEGORIES)


def spec(category: str) -> CategorySpec:
    return SPECS[category]


def is_extracted_category(category: str) -> bool:
    return category not in NEVER_EXTRACTED and SPECS[category].standard_field is not None


def validate_category(category: str) -> str:
    from tripline_scope.core.errors import ConfigError

    if category not in SPECS:
        raise ConfigError(f"unknown column category {category!r} (see PLAN §5 for the list)")
    return category
