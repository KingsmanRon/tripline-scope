import os

import pyarrow as pa
import pytest

from tripline_scope.core import crypto
from tripline_scope.core.errors import ConfigError, IntegrityError


def test_kek_roundtrip_and_wrong_passphrase(tmp_path):
    kek = crypto.create_kek_file(tmp_path / "kek.json", "pass phrase one", n=2**12)
    assert crypto.load_kek(tmp_path / "kek.json", "pass phrase one") == kek
    with pytest.raises(ConfigError):
        crypto.load_kek(tmp_path / "kek.json", "wrong")
    assert oct(os.stat(tmp_path / "kek.json").st_mode & 0o777) == "0o600"


def test_dek_wrap_binds_case_id():
    kek, dek = crypto.random_key(), crypto.random_key()
    doc = crypto.wrap_dek(kek, dek, "CASE-A")
    assert crypto.unwrap_dek(kek, doc, "CASE-A") == dek
    doc2 = dict(doc, case_id="CASE-B")
    with pytest.raises(IntegrityError):
        crypto.unwrap_dek(kek, doc2, "CASE-B")
    with pytest.raises(IntegrityError):
        crypto.unwrap_dek(crypto.random_key(), doc, "CASE-A")


@pytest.mark.parametrize("size", [0, 1, 1000, (1 << 20) - 1, 1 << 20, (1 << 20) + 1, 3 * (1 << 20) + 17])
def test_envelope_roundtrip_sizes(tmp_path, size):
    dek = crypto.random_key()
    data = os.urandom(size)
    p = tmp_path / "f.tse"
    crypto.encrypt_bytes_to(p, dek, "work/f.tse", data)
    assert crypto.decrypt_file(p, dek, "work/f.tse") == data
    if size >= 32:
        assert data[:32] not in p.read_bytes()


def test_envelope_random_access(tmp_path):
    dek = crypto.random_key()
    data = os.urandom(3 * (1 << 20) + 5)
    p = tmp_path / "f.tse"
    crypto.encrypt_bytes_to(p, dek, "x", data)
    with crypto.EnvelopeReader(p, dek, "x") as r:
        assert r.size == len(data)
        r.seek((1 << 20) - 3)
        assert r.read(10) == data[(1 << 20) - 3:(1 << 20) + 7]
        r.seek(-4, 2)
        assert r.read() == data[-4:]


def test_envelope_detects_tamper_truncation_substitution(tmp_path):
    dek = crypto.random_key()
    data = os.urandom(2 * (1 << 20) + 100)
    p = tmp_path / "f.tse"
    crypto.encrypt_bytes_to(p, dek, "work/a", data)
    raw = bytearray(p.read_bytes())
    # flip one ciphertext bit
    t = tmp_path / "t.tse"
    raw2 = bytearray(raw)
    raw2[-50] ^= 1
    t.write_bytes(raw2)
    with pytest.raises(IntegrityError):
        crypto.decrypt_file(t, dek)
    # truncate at a chunk boundary (drops the final chunk)
    header_end = len(raw) - (2 * ((1 << 20) + 16) + 100 + 16)
    t.write_bytes(bytes(raw[: header_end + 2 * ((1 << 20) + 16)]))
    with pytest.raises(IntegrityError):
        crypto.decrypt_file(t, dek)
    # wrong logical name (file moved / substituted)
    with pytest.raises(IntegrityError):
        crypto.decrypt_file(p, dek, "work/b")
    # wrong key
    with pytest.raises(IntegrityError):
        crypto.decrypt_file(p, crypto.random_key())


def test_aborted_writer_leaves_nothing(tmp_path):
    dek = crypto.random_key()
    p = tmp_path / "f.tse"
    with pytest.raises(RuntimeError):
        with crypto.EnvelopeWriter(p, dek, "x") as w:
            w.write(b"abc")
            raise RuntimeError("boom")
    assert not p.exists()
    assert not list(tmp_path.iterdir())


def test_fingerprints_are_keyed():
    a, b = crypto.random_key(), crypto.random_key()
    assert crypto.Fingerprinter(a)("secret") == crypto.Fingerprinter(a)("secret")
    assert crypto.Fingerprinter(a)("secret") != crypto.Fingerprinter(b)("secret")
    assert crypto.Fingerprinter(a, "x")("secret") != crypto.Fingerprinter(a, "y")("secret")


def test_store_parquet_roundtrip_no_plaintext(install, case_dir):
    from tripline_scope.core.case import Case
    from tripline_scope.core.home import Home
    from tripline_scope.core.store import open_store

    case = Case(case_dir)
    store = open_store(case, Home())
    t = pa.table({"name": ["MARKER_NAME_" + str(i) for i in range(5000)], "n": list(range(5000))})
    store.write_table("work/test/t.parquet", t)
    assert store.read_table("work/test/t.parquet").equals(t)
    raw = (case_dir / "work/test/t.parquet.tse").read_bytes()
    assert b"MARKER_NAME_" not in raw and b"PAR1" not in raw
    with store.table_writer("work/test/s.parquet", t.schema) as w:
        for b in t.to_batches(max_chunksize=700):
            w.write_batch(b)
    assert sum(b.num_rows for b in store.iter_batches("work/test/s.parquet")) == 5000
    store.write_json("work/x.json", {"a": 1})
    assert store.read_json("work/x.json") == {"a": 1}
    with pytest.raises(ConfigError):
        store.path("reports/evil")
    with pytest.raises(ConfigError):
        store.path("work/../../etc/passwd")
