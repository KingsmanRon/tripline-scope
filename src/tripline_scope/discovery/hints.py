"""Column-name hints: English and common South African hospital / lab / vendor naming.

Column names are tokenised (``PatientIDNumber`` -> ``patient_id_number``, ``CellNo`` -> ``cell_no``) and
matched against ordered rules; the first matching rule wins, so specific rules (guardian contact, medical-aid
number, ID number) come before generic ones (name, date, other identifiers). A hint alone never makes a
column an identifier: :mod:`tripline_scope.discovery.classify` combines it with value evidence.
"""

from __future__ import annotations

import re
from functools import lru_cache

_B = r"(?:^|_)"
_E = r"(?:_|$)"
_NO = r"(?:no|num|number|nr|nmbr|nbr)"
_GUARD = (r"(?:guardian|parent|mother|father|nok|next_?of_?kin|kin|guarantor|resp(?:onsible)?_?(?:party|person)|"
          r"main_?member|principal_?member|emergency(?:_?contact)?|spouse|ouer|voog)")
_IDNO = rf"(?:id_?{_NO}|idno|idnum|idnumber|identity(?:_?{_NO})?|rsa_?id(?:_?{_NO})?|sa_?id(?:_?{_NO})?|said|" \
        rf"national_?id(?:_?{_NO})?|nat_?id|id_?doc(?:ument)?(?:_?{_NO})?|id_?nommer|identiteits?_?nommer)"
_PHONE = rf"(?:phone|tel|telephone|tele|telno|cell|cellphone|cell_?{_NO}|cellno|mobile|mob|contact_?{_NO}|" \
         rf"contactno|msisdn|whatsapp|fax|landline|selfoon|sel)"
_EMAIL = r"(?:e_?mail(?:_?addr(?:ess)?)?|email_?addr|epos)"
_NAME = r"(?:name|names|naam|surname|first_?names?|full_?name)"

# (category, regex over the tokenised name). Order matters.
_RULES: list[tuple[str, str]] = [
    # guardians / next of kin before the patient's own fields
    ("guardian_sa_id", rf"{_B}{_GUARD}(?:_\w+)?_{_IDNO}{_E}"),
    ("guardian_phone", rf"{_B}{_GUARD}(?:_\w+)?_{_PHONE}{_E}"),
    ("guardian_email", rf"{_B}{_GUARD}(?:_\w+)?_{_EMAIL}{_E}"),
    ("guardian_name", rf"{_B}{_GUARD}(?:_{_NAME})?$"),
    # medical aid number before card / generic numbers ("medical aid card number" is a membership number)
    ("medical_aid_no", rf"{_B}(?:med(?:ical)?_?aid|medaid|scheme|ma|member(?:ship)?|policy|insur(?:ance|er)?|"
                       rf"fund|lid)(?:_?card)?_?(?:{_NO}|id|code){_E}"),
    ("medical_aid_no", rf"{_B}(?:membership|member_?{_NO}|memberno|med_?aid_?mem(?:ber)?){_E}"),
    ("medical_aid_scheme", rf"{_B}(?:med(?:ical)?_?aid(?:_?(?:name|scheme|plan|option))?|medaid|"
                           rf"scheme(?:_?(?:name|option|plan))?|medical_?scheme|funder|insurer|plan_?option|"
                           rf"mediese_?fonds){_E}"),
    # payment data (never extracted)
    ("card_number", rf"{_B}(?:(?:credit|debit|bank|payment)_?card(?:_?{_NO})?|card_?{_NO}|cardno|card|cc(?:_?{_NO})?|"
                    rf"ccnum|pan|card_?pan|kaart(?:_?nommer)?){_E}"),
    ("bank_account", rf"{_B}(?:bank(?:_?acc(?:ount)?)?(?:_?{_NO})?|bank_?details|iban|branch_?code|"
                     rf"debit_?order(?:_?acc(?:ount)?)?(?:_?{_NO})?|bankrekening(?:_?nommer)?){_E}"),
    # identity numbers
    ("sa_id", rf"{_B}{_IDNO}{_E}"),
    ("passport", rf"{_B}(?:passport(?:_?{_NO})?|pp_?{_NO}|ppno|travel_?doc(?:ument)?|paspoort(?:_?nommer)?){_E}"),
    # contact
    ("email", rf"{_B}{_EMAIL}{_E}"),
    ("phone", rf"{_B}{_PHONE}{_E}"),
    # dates (date of birth before generic record dates)
    ("dob", rf"{_B}(?:dob|d_?o_?b|date_?of_?birth|birth_?(?:date|dt|day)|birthdate|born|geb(?:oorte)?_?datum|"
            rf"geboortedatum){_E}"),
    # names
    ("maiden_name", rf"{_B}(?:maiden(?:_?name)?|nee|birth_?surname|previous_?surname|former_?surname|nooiensvan){_E}"),
    ("middle_name", rf"{_B}(?:middle|second)_?names?{_E}"),
    ("first_name", rf"{_B}(?:first_?names?|fname|given_?names?|forenames?|christian_?names?|voorname?|"
                   rf"name_?first|firstnames?){_E}"),
    ("last_name", rf"{_B}(?:surname|last_?name|lname|family_?name|van|name_?last|lastname){_E}"),
    ("full_name", rf"{_B}(?:full_?name|fullname|patient_?name|pat_?name|client_?name|member_?name|name|names|naam|"
                  rf"pt_?name|person_?name){_E}"),
    ("sex", rf"{_B}(?:sex|gender|geslag){_E}"),
    ("postal_code", rf"{_B}(?:postal_?code|post_?code|postcode|zip(?:_?code)?|poskode|pcode){_E}"),
    ("not_address", rf"{_B}(?:ip|mac|web|url|server|host)_?addr(?:ess)?{_E}"),
    ("address", rf"{_B}(?:address|addr|street|suburb|city|town|province|res(?:idential)?_?addr|physical|"
                rf"postal_?addr(?:ess)?|address_?line|line_?\d|unit|complex|village|adres|straat|voorstad){_E}"),
    ("language", rf"{_B}(?:lang|language|home_?lang(?:uage)?|pref(?:erred)?_?lang(?:uage)?|taal){_E}"),
    # clinical (results before tests: "test_result")
    ("record_date_strong", rf"{_B}(?:result|test|collection|specimen|request|report)_?(?:date|dt|time|ts){_E}"),
    ("icd10", rf"{_B}(?:icd(?:_?10)?(?:_?code)?|icd10|diag(?:nosis)?(?:_?(?:code|cd))?|dx(?:_?code)?|"
              rf"primary_?diag(?:nosis)?|diagnose|diagnosis_?desc(?:ription)?){_E}"),
    ("test_result", rf"{_B}(?:result(?:_?(?:value|text|val|flag|status))?|results|res_?val|finding|findings|"
                    rf"interpretation|abnormal_?flag|ref(?:erence)?_?range|uitslag){_E}"),
    ("test_code", rf"{_B}(?:test(?:_?(?:code|id|name|cd|type))?|loinc(?:_?code)?|assay|panel|analyte|"
                  rf"investigation|toets){_E}"),
    ("clinical_free_text", rf"{_B}(?:notes?|comments?|clinical_?notes?|clinical|history|remarks?|memo|observations?|"
                           rf"narrative|free_?text|report_?text|symptoms?|complaint|discharge_?summary|summary|"
                           rf"description|desc|aantekeninge?|kommentaar){_E}"),
    # record dates
    ("record_date", rf"{_B}(?:(?:admission|admit|visit|collect(?:ion|ed)?|encounter|invoice|service|discharge|txn|"
                    rf"transaction|episode|registered|reg|event|appointment|billing|order|booking)_?(?:date|dt|time|ts|on|at)|"
                    rf"date|datum|timestamp|ts|dt|created(?:_?(?:at|on|date|dt)|$)){_E}"),
    # local record keys (role decided per table: patient_key in identity tables, patient_ref elsewhere)
    ("patient_key", rf"{_B}(?:patient(?:_?(?:id|{_NO}|key|code|ref))?|pat_?(?:id|{_NO}|key|ref)|patid|patno|pid|mrn|"
                    rf"folder(?:_?{_NO})?|folderno|hosp(?:ital)?_?(?:{_NO}|id)|file_?{_NO}|record_?{_NO}|"
                    rf"chart_?{_NO}|uhid|client_?(?:id|{_NO})|lêer_?nommer|pasient(?:_?nommer)?){_E}"),
    ("other_identifier", rf"(?:{_B}(?:id|uuid|guid|key|ref|accession|barcode|lab_?{_NO}|specimen(?:_?(?:id|{_NO}))?|"
                         rf"episode_?(?:id|{_NO})|invoice_?{_NO}|account(?:_?{_NO})?|acc_?{_NO}|visit_?(?:id|{_NO})|"
                         rf"admission_?(?:id|{_NO})|order_?(?:id|{_NO})|request_?(?:id|{_NO})){_E})|"
                         rf"(?:_(?:id|{_NO}|code|ref|key)$)"),
]
_COMPILED = [(cat, re.compile(rx)) for cat, rx in _RULES]

# Table-name context that turns generic column names into clinical results.
_RESULT_TABLE = re.compile(r"(?:^|_)(?:results?|lab|labs|path(?:ology)?|tests?|observations?|obs|uitslae)(?:_|$)")
_RESULT_COLS = re.compile(r"^(?:value|val|units?|unit|flag|range|res|reading)$")


def tokenise(name: str) -> str:
    """``PatientIDNumber`` -> ``patient_id_number``; ``address1`` -> ``address_1``."""
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", str(name))
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    s = re.sub(r"([A-Za-z])([0-9])", r"\1_\2", s)
    s = s.lower()
    return "_".join(t for t in re.split(r"[^a-z0-9]+", s) if t)


@lru_cache(maxsize=4096)
def name_hint(column: str, table: str = "") -> str | None:
    """Hinted category for a column name (or ``None``). Returns pseudo-categories ``middle_name``,
    ``record_date_strong`` and ``not_address`` that :mod:`classify` resolves."""
    tok = tokenise(column)
    if not tok:
        return None
    ttok = tokenise(table)
    if _RESULT_TABLE.search(ttok) and _RESULT_COLS.match(tok):
        return "test_result"
    for cat, rx in _COMPILED:
        if rx.search(tok):
            return cat
    return None
