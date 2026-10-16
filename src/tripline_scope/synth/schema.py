"""Column layouts of the synthetic lab databases.

Five naming styles rotate over the databases so discovery sees realistic variation (``first_name`` vs
``given_names`` vs one ``patient_name`` column, dates stored as DATE or as text, sex coded M/F, Male/Female or
1/2, different key names). ``synth_meta.json`` records, per database and table, which column holds which
standard field (the answer discovery is expected to find) and how values are formatted.
"""

from __future__ import annotations

# Standard-field -> column name, per style. Fields absent from a style are not stored in that database.
STYLES: dict[str, dict] = {
    "A": {
        "name_format": "split", "dob_format": "date", "sex_format": "MF", "case": "upper", "id_format": "plain",
        "patients": {"local_patient_key": "patient_id", "sa_id": "id_number", "first_name": "first_name",
                     "middle_names": "middle_name", "last_name": "surname", "maiden_name": "maiden_name",
                     "dob": "date_of_birth", "sex": "sex", "phone": "cell_phone", "email": "email",
                     "address": "address_line", "postal_code": "postal_code", "medical_aid_no": "medical_aid_no",
                     "language": "home_language", "guardian_name": "guardian_name", "guardian_phone": "guardian_phone",
                     "guardian_sa_id": "guardian_id_number", "passport_no": "passport_no", "record_date": "registered_on"},
        "admissions": {"key": "admission_id", "patient_ref": "patient_id", "record_date": "admit_date",
                       "discharge": "discharge_date", "ward": "ward", "icd10": "icd10_code", "note": "clinical_note"},
        "billing": {"key": "invoice_id", "patient_ref": "patient_id", "admission_ref": "admission_id",
                    "record_date": "invoice_date", "amount": "amount", "medical_aid_no": "medical_aid_no",
                    "card_number": "card_number", "bank_account": "bank_account"},
        "results": {"key": "result_id", "admission_ref": "admission_id", "patient_ref": "patient_id",
                    "record_date": "collected_on", "test_code": "test_code", "status": "status"},
    },
    "B": {
        "name_format": "given_names", "dob_format": "date", "sex_format": "MaleFemale", "case": "title",
        "id_format": "plain",
        "patients": {"local_patient_key": "pat_no", "sa_id": "sa_id_no", "first_name": "given_names",
                     "last_name": "last_name", "maiden_name": "maiden_surname", "dob": "dob", "sex": "gender",
                     "phone": "mobile", "email": "email_address", "address": "street_address", "postal_code": "post_code",
                     "medical_aid_no": "scheme_member_no", "guardian_name": "next_of_kin", "guardian_phone": "nok_contact",
                     "passport_no": "passport", "record_date": "created_date"},
        "admissions": {"key": "adm_no", "patient_ref": "pat_no", "record_date": "admitted", "discharge": "discharged",
                       "ward": "ward_code", "icd10": "diagnosis_code", "note": "notes"},
        "billing": {"key": "bill_no", "patient_ref": "pat_no", "admission_ref": "adm_no", "record_date": "billed_on",
                    "amount": "total", "medical_aid_no": "scheme_member_no", "card_number": "payment_card",
                    "bank_account": "account_no"},
        "results": {"key": "res_id", "admission_ref": "adm_no", "patient_ref": "pat_no", "record_date": "specimen_date",
                    "test_code": "test", "status": "result_status"},
    },
    "C": {
        "name_format": "full_name_comma", "dob_format": "%d/%m/%Y", "sex_format": "12", "case": "upper",
        "id_format": "grouped",
        "patients": {"local_patient_key": "mrn", "sa_id": "identity_no", "full_name": "patient_name",
                     "dob": "birth_date", "sex": "sex_code", "phone": "contact_no", "email": "email",
                     "address": "physical_address", "postal_code": "postal", "medical_aid_no": "med_aid_number",
                     "language": "lang", "guardian_name": "parent_guardian", "guardian_phone": "parent_contact",
                     "passport_no": "foreign_id", "record_date": "reg_date"},
        "admissions": {"key": "visit_id", "patient_ref": "mrn", "record_date": "visit_date", "discharge": "end_date",
                       "ward": "unit", "icd10": "icd10", "note": "comment"},
        "billing": {"key": "txn_id", "patient_ref": "mrn", "admission_ref": "visit_id", "record_date": "txn_date",
                    "amount": "amount_zar", "medical_aid_no": "med_aid_number", "card_number": "cc_number",
                    "bank_account": "bank_acc"},
        "results": {"key": "lab_no", "admission_ref": "visit_id", "patient_ref": "mrn", "record_date": "collected",
                    "test_code": "test_cd", "status": "state"},
    },
    "D": {
        "name_format": "split", "dob_format": "%Y%m%d", "sex_format": "MF", "case": "title", "id_format": "plain",
        "patients": {"local_patient_key": "PatientKey", "sa_id": "IDNo", "first_name": "FirstName",
                     "middle_names": "MiddleNames", "last_name": "LastName", "maiden_name": "MaidenName", "dob": "DOB",
                     "sex": "Gender", "phone": "Phone", "phone_alt": "AltPhone", "email": "Email", "address": "Address",
                     "postal_code": "PostalCode", "medical_aid_no": "MedicalAidNo", "language": "PreferredLanguage",
                     "guardian_name": "GuardianName", "guardian_phone": "GuardianPhone", "passport_no": "PassportNo",
                     "record_date": "CreatedOn"},
        "admissions": {"key": "AdmissionKey", "patient_ref": "PatientKey", "record_date": "AdmitDate",
                       "discharge": "DischargeDate", "ward": "Ward", "icd10": "PrimaryICD10", "note": "Note"},
        "billing": {"key": "InvoiceKey", "patient_ref": "PatientKey", "admission_ref": "AdmissionKey",
                    "record_date": "InvoiceDate", "amount": "Amount", "medical_aid_no": "MedicalAidNo",
                    "card_number": "CardNo", "bank_account": "BankAccountNo"},
        "results": {"key": "ResultKey", "admission_ref": "AdmissionKey", "patient_ref": "PatientKey",
                    "record_date": "CollectedOn", "test_code": "TestCode", "status": "Status"},
    },
    "E": {
        "name_format": "split", "dob_format": "date", "sex_format": "MF", "case": "mixed", "id_format": "plain",
        "patients": {"local_patient_key": "client_ref", "sa_id": "rsa_id", "first_name": "forename",
                     "middle_names": "other_names", "last_name": "family_name", "maiden_name": "birth_surname",
                     "dob": "birthdate", "sex": "sex", "phone": "tel", "email": "e_mail", "address": "addr",
                     "postal_code": "zip", "medical_aid_no": "member_no", "language": "language",
                     "guardian_name": "guardian", "guardian_phone": "guardian_tel", "guardian_sa_id": "guardian_rsa_id",
                     "passport_no": "passport_number", "record_date": "opened"},
        "admissions": {"key": "episode_id", "patient_ref": "client_ref", "record_date": "episode_start",
                       "discharge": "episode_end", "ward": "location", "icd10": "dx_code", "note": "free_text"},
        "billing": {"key": "claim_id", "patient_ref": "client_ref", "admission_ref": "episode_id",
                    "record_date": "claim_date", "amount": "claim_amount", "medical_aid_no": "member_no",
                    "card_number": "card_pan", "bank_account": "debit_account"},
        "results": {"key": "order_id", "admission_ref": "episode_id", "patient_ref": "client_ref",
                    "record_date": "order_date", "test_code": "order_code", "status": "order_status"},
    },
}

DB_STYLES = ["A", "B", "C", "D", "E", "A", "B", "C", "D", "E"]

# Standard field -> discovery column category (PLAN §5) for the dependent tables' non-identity columns.
FIELD_CATEGORY = {
    "icd10": "icd10", "note": "clinical_free_text", "test_code": "test_code", "card_number": "card_number",
    "bank_account": "bank_account", "medical_aid_no": "medical_aid_no", "status": "other", "ward": "other",
    "amount": "other", "discharge": "record_date", "record_date": "record_date", "key": "other",
    "admission_ref": "other", "patient_ref": "patient_ref",
}

TABLES = ("patients", "admissions", "billing", "results")


def style_of(db_index: int) -> str:
    """Style letter for database number ``db_index`` (1-based)."""
    return DB_STYLES[(db_index - 1) % len(DB_STYLES)]


def db_name(db_index: int) -> str:
    return f"db{db_index:02d}"
