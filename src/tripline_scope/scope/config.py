"""Module C matching configuration: defaults (PLAN §6), merging and hashing.

Precedence (lowest first): built-in defaults → ``case.yaml`` ``matching:`` (written by ``tscope profile apply``)
→ ``--config FILE``. The merged configuration is canonicalised and its SHA-256 is recorded in every scope report,
so a count can always be traced to the exact rules and thresholds that produced it.
"""

from __future__ import annotations

import copy
from pathlib import Path

import yaml

from tripline_scope.core.canonical import canonical_bytes, sha256_hex
from tripline_scope.core.errors import ConfigError

CONFIG_SCHEMA = "tripline.scope-config/v1"

# Exposure categories reported everywhere (PLAN §5), in report order.
EXPOSURE_CATEGORIES = [
    "identity_number", "name", "date_of_birth", "contact_details", "address", "medical_aid",
    "clinical_diagnosis", "clinical_tests", "clinical_results", "clinical_notes", "payment_card", "bank_account",
]

# Standard extract fields that, when present on a row, expose a category.
FIELD_CATEGORIES = {
    "sa_id": "identity_number", "passport_no": "identity_number",
    "first_name": "name", "middle_names": "name", "last_name": "name", "full_name": "name", "maiden_name": "name",
    "dob": "date_of_birth",
    "phone": "contact_details", "phone_alt": "contact_details", "email": "contact_details",
    "address": "address", "postal_code": "address",
    "medical_aid_no": "medical_aid",
    "guardian_name": "name", "guardian_phone": "contact_details", "guardian_email": "contact_details",
    "guardian_sa_id": "identity_number",
}

# ``_has_<x>`` presence flags in the extract: discovery column categories and exposure categories both accepted.
FLAG_CATEGORIES = {
    "icd10": "clinical_diagnosis", "clinical_diagnosis": "clinical_diagnosis",
    "test_code": "clinical_tests", "clinical_tests": "clinical_tests",
    "test_result": "clinical_results", "clinical_results": "clinical_results",
    "clinical_free_text": "clinical_notes", "clinical_notes": "clinical_notes",
    "card_number": "payment_card", "payment_card": "payment_card",
    "bank_account": "bank_account",
    "sa_id": "identity_number", "passport": "identity_number", "identity_number": "identity_number",
    "medical_aid_no": "medical_aid", "medical_aid": "medical_aid", "medical_aid_scheme": "medical_aid",
    "phone": "contact_details", "email": "contact_details", "contact_details": "contact_details",
    "address": "address", "postal_code": "address",
    "dob": "date_of_birth", "date_of_birth": "date_of_birth",
    "first_name": "name", "last_name": "name", "full_name": "name", "maiden_name": "name", "name": "name",
}

DEFAULTS: dict = {
    "schema": CONFIG_SCHEMA,
    "bands": {"auto_link": 0.995, "review": 0.80},
    "blocking": {
        "rules": ["sa_id", "soundex_last_dob", "soundex_first_dob", "soundex_names_sorted_dob", "maiden_dob",
                  "phone", "email", "soundex_names_birth_year", "soundex_names_birthday"],
        "max_block_size": 50,
    },
    "comparisons": {"jw_high": 0.92, "jw_low": 0.80, "term_frequency": ["first", "last", "phone"]},
    "training": {
        "u_max_pairs": 3_000_000, "u_seed": 7, "em_sample_modulus": 8, "em_max_iterations": 25,
        "prior_recall": 0.6, "parameter_digits": 8,
    },
    "guards": {
        # pairs whose first names contradict (not equal, not similar, not swapped, not a middle name or variant)
        "first_name_contradiction": "non_link",
        # both dates of birth recorded, not a slip (one character, one day, day/month swap or one year) and the
        # records do not share a valid SA ID: within a year of each other → at most review ...
        "dob_contradiction": "review",
        # ... two or more years apart (a parent and child or two siblings sharing a name) → non-link
        "dob_years_apart": "non_link",
        # two valid but different SA ID numbers (Luhn catches every single-digit typo, so these are two IDs)
        "different_valid_sa_id": "non_link",
        # a pair with a recorded guardian relationship (one record's guardian ID is the other's ID)
        "guardian_relationship": "non_link",
    },
    "over_merge": {"max_records": 25, "max_distinct_sa_id": 1, "contradictory_dob": True},
    "identity": {
        "min_identifiers": 2,
        "name_placeholders": ["UNKNOWN", "UNK", "NONAME", "NO NAME", "NONE", "NA", "N A", "TEST", "UNIDENTIFIED",
                              "BABY", "BABY OF", "INFANT", "PATIENT", "X", "XX", "XXX"],
        "surname_particles": ["VAN", "DER", "DEN", "DU", "DE", "LE", "LA", "JANSE", "VON", "TE", "TER"],
    },
    # first-name variant groups; the first entry is the canonical form used for comparison
    # first-name variant groups (spellings and diminutives rarely given as separate names); the first entry is the
    # canonical form. Tuned per hospital with ``tscope profile``.
    "name_variants": [
        ["ELIZABETH", "ELISABETH", "LIZ", "LIZZY", "BETTY"],
        ["MOHAMMED", "MOHAMED", "MUHAMMAD", "MOHAMMAD", "MOHAMAD"],
        ["SIBUSISO", "SBUSISO"],
        ["CATHARINA", "CATHERINE", "KATHERINE", "CATHRINE", "KATHRYN"],
        ["JOHANNES", "HANNES"],
        ["JACOBUS", "KOOS"],
        ["NOMPUMELELO", "MPUMI"],
        ["THANDEKA", "THANDI"],
    ],
    "minor_age_years": 18,
    "contact": {"address_requires_postal_code": True},
    "estimate": {"bounds": "fine_and_coarse_keys"},
}


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def validate(cfg: dict) -> dict:
    b = cfg["bands"]
    if not 0.0 < float(b["review"]) < float(b["auto_link"]) <= 1.0:
        raise ConfigError("bands must satisfy 0 < review < auto_link <= 1")
    if int(cfg["blocking"]["max_block_size"]) < 2:
        raise ConfigError("blocking.max_block_size must be at least 2")
    for k, v in cfg["guards"].items():
        if v not in ("non_link", "review", "off"):
            raise ConfigError(f"guard {k} must be non_link, review or off")
    known = {"sa_id", "soundex_last_dob", "soundex_names_sorted_dob", "maiden_dob", "phone", "email",
             "soundex_names_birth_year", "passport", "soundex_first_dob", "soundex_names_birthday"}
    bad = set(cfg["blocking"]["rules"]) - known
    if bad:
        raise ConfigError(f"unknown blocking rule(s): {sorted(bad)}")
    return cfg


def load(case=None, config_file: str | Path | None = None) -> dict:
    cfg = DEFAULTS
    if case is not None and case.config.get("matching"):
        cfg = deep_merge(cfg, case.config["matching"])
    if config_file:
        try:
            over = yaml.safe_load(Path(config_file).read_text()) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigError(f"cannot read matching config: {type(exc).__name__}") from None
        if not isinstance(over, dict):
            raise ConfigError("matching config must be a mapping")
        cfg = deep_merge(cfg, over.get("matching", over))
    cfg["schema"] = CONFIG_SCHEMA
    return validate(cfg)


def config_sha256(cfg: dict) -> str:
    return sha256_hex(canonical_bytes(cfg))
