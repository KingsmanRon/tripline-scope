import datetime as dt
import random

import pytest

from tripline_scope.core import duck
from tripline_scope.core.identifiers import (
    card_number_like,
    icd10_like,
    luhn_ok,
    make_sa_id,
    normalise_email,
    normalise_name,
    normalise_phone,
    parse_sa_id,
    sa_id_dob_consistent,
    soundex,
)


def test_sa_id_valid_and_invalid():
    sid = make_sa_id(dt.date(1985, 3, 14), 5123)
    p = parse_sa_id(sid)
    assert p.valid and p.sex == "M" and p.citizenship == "citizen"
    assert dt.date(1985, 3, 14) in p.dob_candidates
    assert sa_id_dob_consistent(sid, dt.date(1985, 3, 14))
    assert not sa_id_dob_consistent(sid, dt.date(1985, 3, 15))
    bad_luhn = sid[:-1] + str((int(sid[-1]) + 1) % 10)
    assert not parse_sa_id(bad_luhn).valid
    assert not parse_sa_id("8513145123083").valid or parse_sa_id("8513145123083").valid is False  # month 13
    assert not parse_sa_id(sid[:10] + "3" + sid[11:]).valid  # citizenship digit 3
    assert not parse_sa_id("123456789012").valid
    assert parse_sa_id(sid[:6] + " " + sid[6:]).valid


def test_thirteen_digit_non_ids_rejected():
    rng = random.Random(4)
    rejected = 0
    for _ in range(2000):
        s = "".join(rng.choice("0123456789") for _ in range(13))
        if not parse_sa_id(s).valid:
            rejected += 1
    assert rejected > 1900  # random 13-digit strings are overwhelmingly not valid IDs


def test_leap_day_and_century():
    assert parse_sa_id(make_sa_id(dt.date(2000, 2, 29), 1)).valid
    p = parse_sa_id(make_sa_id(dt.date(1924, 6, 1), 1))
    assert p.dob_candidates == (dt.date(1924, 6, 1), dt.date(2024, 6, 1))


def test_phone_email_names():
    assert normalise_phone("082 123 4567") == "+27821234567"
    assert normalise_phone("+27 (82) 123-4567") == "+27821234567"
    assert normalise_phone("0027821234567") == "+27821234567"
    assert normalise_phone("27821234567") == "+27821234567"
    assert normalise_phone("821234567") == "+27821234567"
    assert normalise_phone("+44 20 7946 0958") == "+442079460958"
    assert normalise_phone("12345") is None
    assert normalise_phone("+2712") is None
    assert normalise_email(" Thandi.N@Example.CO.ZA ") == "thandi.n@example.co.za"
    assert normalise_email("not-an-email") is None
    assert normalise_name("  du Plessis-Smith ") == "DU PLESSISSMITH"
    assert normalise_name("Zoë") == "ZOE"
    assert soundex("Robert") == soundex("Rupert") == "R163"
    assert soundex("Nkosi") == "N220"


def test_other_formats():
    assert luhn_ok("4111111111111111") and card_number_like("4111 1111 1111 1111")
    assert not card_number_like("4111111111111112")
    assert icd10_like("J45.9") and icd10_like("E11") and not icd10_like("U99") and not icd10_like("hello")


def test_duckdb_macros_agree_with_python():
    rng = random.Random(7)
    values = []
    for i in range(400):
        d = dt.date(1930, 1, 1) + dt.timedelta(days=rng.randrange(0, 34000))
        sid = make_sa_id(d, rng.randrange(0, 9999), rng.choice([0, 1, 2]))
        values.append(sid)
        values.append(sid[:-1] + str((int(sid[-1]) + 1) % 10))
        values.append("".join(rng.choice("0123456789") for _ in range(13)))
    phones = ["082 123 4567", "+27821234567", "0027821234567", "821234567", "+442079460958", "12", None, "+2712345"]
    con = duck.connect()
    con.execute("CREATE TABLE v(s VARCHAR)")
    con.executemany("INSERT INTO v VALUES (?)", [[v] for v in values])
    rows = con.execute("SELECT s, tscope_sa_id_ok(s) FROM v").fetchall()
    for s, ok in rows:
        assert ok == parse_sa_id(s).valid, s
    con.execute("CREATE TABLE p(s VARCHAR)")
    con.executemany("INSERT INTO p VALUES (?)", [[v] for v in phones])
    for s, e in con.execute("SELECT s, tscope_phone_e164(s) FROM p").fetchall():
        assert e == normalise_phone(s), s
    for raw in ["  du Plessis-Smith ", "Zoë", "O'Neill", "van der MERWE"]:
        assert con.execute("SELECT tscope_name_norm(?)", [raw]).fetchone()[0] == normalise_name(raw)
    assert con.execute("SELECT tscope_card_like('4111111111111111'), tscope_card_like('4111111111111112')").fetchone() == (True, False)


def test_duckdb_is_sandboxed(tmp_path):
    allowed = tmp_path / "ok.csv"
    allowed.write_text("a\n1\n")
    other = tmp_path / "other.csv"
    other.write_text("a\n2\n")
    con = duck.connect(read_paths=[allowed])
    assert con.execute(f"SELECT * FROM read_csv('{allowed}')").fetchall() == [(1,)]
    for q in [f"SELECT * FROM read_csv('{other}')", f"COPY (SELECT 1) TO '{tmp_path}/out.csv'", "INSTALL httpfs",
              f"ATTACH '{tmp_path}/x.db'", "SET enable_external_access = true", "SET temp_directory = '/tmp'"]:
        with pytest.raises(Exception):
            con.execute(q).fetchall()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ok.csv", "other.csv"]


def test_hash_tokens_are_not_identifiers():
    import hashlib

    from tripline_scope.core.redact import find_identifier_like, scrub_text

    flagged = [h for h in (hashlib.sha256(str(i).encode()).hexdigest() for i in range(20000)) if find_identifier_like(h)]
    assert flagged == []
    h = hashlib.sha256(b"tripline").hexdigest()
    assert scrub_text(f"sha {h} end") == f"sha {h} end"
    # real identifiers next to hashes are still found and scrubbed
    assert "sa_id" in find_identifier_like(f"{h} 8001015009087")
    assert "card" in find_identifier_like("4111 1111 1111 1111 " + h)
    assert "phone" in find_identifier_like(h + " 082 555 1234")
    assert "8001015009087" not in scrub_text(f"{h} 8001015009087")
    # a short hex-ish token is not treated as a hash
    assert "card" in find_identifier_like("a4111111111111111b")
