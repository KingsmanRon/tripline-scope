"""Synthetic lab data and helpers for the ingest / discovery / map tests (synthetic values only)."""

from __future__ import annotations

import csv
import datetime as dt
import json
import random
import re
from pathlib import Path

from tripline_scope import testing
from tripline_scope.core.identifiers import luhn_check_digit, make_sa_id

FIRST = ["Nomvula", "Thabo", "Lerato", "Sipho", "Ayanda", "Pieter", "Annelie", "Johan", "Zanele", "Kagiso", "Fatima",
         "Rajesh", "Precious", "Bongani", "Lindiwe", "Mpho", "Naledi", "Tshepo", "Refilwe", "Karabo"]
LAST = ["Dlamini", "Nkosi", "Botha", "van der Merwe", "Mokoena", "Naidoo", "Pillay", "Khumalo", "Mahlangu", "Zulu",
        "Smith", "Pretorius", "Ndlovu", "Mabaso", "Ngcobo", "Molefe", "Sithole", "Venter", "Govender", "Maseko"]
SCHEMES = ["Discovery Health", "Bonitas", "GEMS", "Momentum", "Medshield"]
TESTS = [("HB", "Haemoglobin"), ("FBC", "Full blood count"), ("HBA1C", "HbA1c"), ("CD4", "CD4 count"),
         ("CRP", "C-reactive protein"), ("TSH", "Thyroid stimulating hormone")]
ICD = ["E11.9", "I10", "B20", "J45.9", "N39.0", "O24.4", "Z00.0", "K21.9"]
NOTE_WORDS = ["patient", "reports", "intermittent", "chest", "pain", "follow", "up", "in", "two", "weeks", "fasting",
              "glucose", "elevated", "refer", "to", "clinic", "for", "review", "advised", "rest"]


def card_number(rng: random.Random) -> str:
    base = "4" + "".join(rng.choice("0123456789") for _ in range(14))
    return base + luhn_check_digit(base)


def luhn_random(rng: random.Random, length: int) -> str:
    base = "".join(rng.choice("123456789")) + "".join(rng.choice("0123456789") for _ in range(length - 2))
    return base + luhn_check_digit(base)


def make_dataset(n_patients: int = 300, seed: int = 7) -> dict[str, list[dict]]:
    """patients (identity), results (dependent, clinical), billing (dependent, card/bank), misc (negatives)."""
    rng = random.Random(seed)
    patients, results, billing, misc = [], [], [], []
    for i in range(1, n_patients + 1):
        dob = dt.date(1940, 1, 1) + dt.timedelta(days=rng.randrange(0, 365 * 80))
        sid = make_sa_id(dob, rng.randrange(0, 10000), citizenship=rng.choice([0, 0, 0, 1]))
        first, last = rng.choice(FIRST), rng.choice(LAST)
        cell = f"0{rng.choice([6, 7, 8])}{rng.randrange(0, 10)} {rng.randrange(100, 1000)} {rng.randrange(1000, 10000)}"
        patients.append({
            "PatientID": f"P{i:06d}",
            "FirstNames": first,
            "Surname": last,
            "IDNumber": sid if i % 25 else "",  # some missing IDs
            "DateOfBirth": dob.strftime("%d/%m/%Y"),
            "Gender": rng.choice(["M", "F"]),
            "CellNo": cell,
            "Email": f"{first.lower()}.{last.lower().replace(' ', '')}{i}@example.co.za",
            "Address1": f"{rng.randrange(1, 300)} {rng.choice(['Church', 'Main', 'Long', 'Voortrekker'])} Street",
            "Suburb": rng.choice(["Hatfield", "Soweto", "Umlazi", "Bellville", "Sandton"]),
            "PostalCode": f"{rng.randrange(1, 9999):04d}",
            "MedAidNo": f"{rng.randrange(10**8, 10**9)}",
            "Scheme": rng.choice(SCHEMES),
        })
        for j in range(rng.randrange(1, 4)):
            code, _name = rng.choice(TESTS)
            results.append({
                "ResultID": len(results) + 1,
                "PatientID": f"P{i:06d}",
                "TestCode": code,
                "Result": f"{rng.uniform(1, 200):.1f}",
                "ICD10": rng.choice(ICD),
                "Notes": " ".join(rng.choice(NOTE_WORDS) for _ in range(rng.randrange(6, 14))),
                "CollectedDate": (dt.date(2026, 1, 1) + dt.timedelta(days=rng.randrange(0, 250))).isoformat(),
            })
        billing.append({
            "InvoiceNo": f"INV{i:07d}",
            "PatientID": f"P{i:06d}",
            "CardNumber": card_number(rng),
            "BankAccountNo": f"{rng.randrange(10**9, 10**10)}",
            "Amount": f"{rng.uniform(100, 5000):.2f}",
            "AccountNo": f"A{rng.randrange(10**6, 10**7)}",
        })
        misc.append({
            "RecordNo": i,
            "Ref13": f"{rng.randrange(10**12, 10**13)}",            # arbitrary 13-digit numbers, not IDs
            "BatchCode": luhn_random(rng, 13),                     # Luhn-valid 13-digit numbers, no context
            "Token16": luhn_random(rng, 16),                       # Luhn-valid 16-digit numbers, random prefixes
            "Comment": " ".join(rng.choice(NOTE_WORDS) for _ in range(rng.randrange(5, 12))),
            "Ward": rng.choice(["A1", "B2", "C3", "ICU"]),
        })
    return {"patients": patients, "results": results, "billing": billing, "misc": misc}


def write_csv(path: Path, rows: list[dict], delimiter: str = ",") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]), delimiter=delimiter)
        w.writeheader()
        w.writerows(rows)
    return path


def write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return path


def write_xlsx(path: Path, sheets: dict[str, list[dict]]) -> Path:
    import openpyxl

    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    for name, rows in sheets.items():
        ws = wb.create_sheet(name)
        ws.append(list(rows[0]))
        for r in rows:
            ws.append([r[k] for k in rows[0]])
    path.parent.mkdir(parents=True, exist_ok=True)
    wb.save(path)
    return path


def add_source(case_dir: Path, paths: list[Path] | Path, kind: str, *, role: str = "system_copy",
               copy: bool = False, label: str = "synthetic export") -> str:
    if isinstance(paths, Path):
        paths = [paths]
    args = ["--json", "source", "add", "--case", str(case_dir), "--kind", kind, "--label", label,
            "--evidence-role", role, "--legal-basis", "POPIA s22 incident response",
            "--supplied-by", "Hospital IT", "--received-at", "2026-09-15T08:00:00Z"]
    for p in paths:
        args += ["--path", str(p)]
    if copy:
        args.append("--copy")
    rc, out, err = testing.run_cli(args)
    assert rc == 0, err
    return json.loads(out)["source_id"]


def all_values(dataset: dict[str, list[dict]], keys: list[str]) -> set[str]:
    out = set()
    for rows in dataset.values():
        for r in rows:
            for k in keys:
                if k in r and r[k] not in (None, ""):
                    out.add(str(r[k]))
    return out


def scan_text_for(text: str, values: set[str]) -> list[str]:
    """Which of ``values`` occur in ``text`` (exact substring; values shorter than 6 chars are skipped)."""
    return sorted(v for v in values if len(v) >= 6 and v in text)


DIGITS = re.compile(r"\d")
