"""Key hierarchy and authenticated file envelopes.

Hierarchy
---------
* **Hospital KEK** (key-encryption key, 256-bit): held by the hospital *outside* any case directory
  (``kek.json``, normally passphrase-wrapped with scrypt + AES-256-GCM).
* **Case DEK** (data-encryption key, 256-bit, one per case): random, wrapped by the KEK with AES-256-GCM
  (AAD binds the case id) and stored in the hospital keystore, also outside the case directory.
  Destroying the wrapped DEK makes every envelope of that case unreadable.
* **Per-file keys**: HKDF-SHA256(DEK, info = "tripline-file" || file_id) so nonces never repeat across files.
* **Fingerprint key**: HKDF-SHA256(DEK, info = "tripline-fingerprint") for keyed, case-local fingerprints
  (HMAC-SHA256) of secrets and record keys. These are not reversible plain hashes.

Envelope (``TSENC1``)
---------------------
``magic(8) | header_len(u32 BE) | header(canonical JSON) | chunk_0 | chunk_1 | ...``. Each chunk is
AES-256-GCM over at most ``chunk`` plaintext bytes with nonce ``prefix(7) || index(u32 BE) || final(1)`` and
AAD ``SHA-256(header) || index``. The final flag detects truncation; the index detects reordering; the header
hash binds the logical path and key id. Every chunk except the last is exactly ``chunk + 16`` bytes, so
readers can seek without decrypting earlier chunks.

Only primitives from ``cryptography`` (OpenSSL) are used; nothing here relies on DuckDB or Parquet encryption.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
import struct
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .canonical import canonical_bytes
from .errors import ConfigError, IntegrityError

MAGIC = b"TSENC1\x00\x00"
DEFAULT_CHUNK = 1 << 20
TAG = 16
KEK_SCHEMA = "tripline.kek/v1"
WRAPPED_DEK_SCHEMA = "tripline.wrapped-dek/v1"


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def random_key() -> bytes:
    return os.urandom(32)


def key_id(key: bytes) -> str:
    """Identifier for a symmetric key: a domain-separated hash prefix (does not reveal the key)."""
    return hashlib.sha256(b"tripline-key-id:" + key).hexdigest()[:24]


def hkdf(key: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(key)


# --------------------------------------------------------------------------- KEK ---------------------------


def _scrypt(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def create_kek_file(path: Path, passphrase: str | None, *, n: int = 2**15, r: int = 8, p: int = 1) -> bytes:
    """Create a new hospital KEK. With a passphrase the key is wrapped (scrypt + AES-GCM); without, it is
    stored raw and must be protected by filesystem permissions or external media (a warning is recorded)."""
    path = Path(path)
    if path.exists():
        raise ConfigError("KEK file already exists; refusing to overwrite")
    kek = random_key()
    if passphrase:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        wrap = _scrypt(passphrase, salt, n, r, p)
        ct = AESGCM(wrap).encrypt(nonce, kek, b"tripline-kek")
        doc = {"schema": KEK_SCHEMA, "kdf": "scrypt", "n": n, "r": r, "p": p, "salt": b64e(salt),
               "nonce": b64e(nonce), "ciphertext": b64e(ct), "key_id": key_id(kek)}
    else:
        doc = {"schema": KEK_SCHEMA, "kdf": "none", "key": b64e(kek), "key_id": key_id(kek)}
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(canonical_bytes(doc))
    return kek


def load_kek(path: Path, passphrase: str | None) -> bytes:
    try:
        doc = json.loads(Path(path).read_bytes())
    except FileNotFoundError:
        raise ConfigError("hospital KEK file not found (check config kek.path / mounted key media)") from None
    if doc.get("schema") != KEK_SCHEMA:
        raise ConfigError("unrecognised KEK file")
    if doc["kdf"] == "none":
        kek = b64d(doc["key"])
    elif doc["kdf"] == "scrypt":
        if not passphrase:
            raise ConfigError("KEK passphrase required (prompt or TSCOPE_KEK_PASSPHRASE)")
        wrap = _scrypt(passphrase, b64d(doc["salt"]), doc["n"], doc["r"], doc["p"])
        try:
            kek = AESGCM(wrap).decrypt(b64d(doc["nonce"]), b64d(doc["ciphertext"]), b"tripline-kek")
        except InvalidTag:
            raise ConfigError("KEK passphrase incorrect or KEK file corrupted") from None
    else:
        raise ConfigError("unsupported KEK kdf")
    if key_id(kek) != doc.get("key_id"):
        raise IntegrityError("KEK key id mismatch")
    return kek


# --------------------------------------------------------------------------- DEK wrapping ------------------


def wrap_dek(kek: bytes, dek: bytes, case_id: str) -> dict:
    nonce = os.urandom(12)
    ct = AESGCM(kek).encrypt(nonce, dek, b"tripline-dek:" + case_id.encode())
    return {"schema": WRAPPED_DEK_SCHEMA, "case_id": case_id, "kek_id": key_id(kek), "dek_id": key_id(dek),
            "nonce": b64e(nonce), "ciphertext": b64e(ct)}


def unwrap_dek(kek: bytes, doc: dict, case_id: str) -> bytes:
    if doc.get("schema") != WRAPPED_DEK_SCHEMA or doc.get("case_id") != case_id:
        raise IntegrityError("wrapped case key does not belong to this case")
    try:
        dek = AESGCM(kek).decrypt(b64d(doc["nonce"]), b64d(doc["ciphertext"]), b"tripline-dek:" + case_id.encode())
    except InvalidTag:
        raise IntegrityError("case key cannot be unwrapped with this hospital KEK") from None
    if key_id(dek) != doc.get("dek_id"):
        raise IntegrityError("case key id mismatch")
    return dek


# --------------------------------------------------------------------------- fingerprints ------------------


class Fingerprinter:
    """Keyed, case-local fingerprints (HMAC-SHA256). Safe for low-entropy values because the key is secret
    and is destroyed with the case."""

    def __init__(self, dek: bytes, purpose: str = "default"):
        self._key = hkdf(dek, b"tripline-fingerprint:" + purpose.encode())

    def __call__(self, value: str | bytes, length: int = 32) -> str:
        if isinstance(value, str):
            value = value.encode("utf-8")
        return hmac.new(self._key, value, hashlib.sha256).hexdigest()[:length]


# --------------------------------------------------------------------------- envelopes ---------------------


def _nonce(prefix: bytes, index: int, final: bool) -> bytes:
    return prefix + struct.pack(">I", index) + (b"\x01" if final else b"\x00")


def _aad(header_hash: bytes, index: int) -> bytes:
    return header_hash + struct.pack(">Q", index)


class EnvelopeWriter(io.RawIOBase):
    """Streaming encrypting writer. Use as a context manager; ``close()`` writes the final chunk."""

    def __init__(self, path: Path, dek: bytes, logical_name: str, *, chunk: int = DEFAULT_CHUNK):
        super().__init__()
        self._path = Path(path)
        self._tmp = self._path.with_name(self._path.name + ".partial")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(self._tmp, "wb")  # noqa: SIM115 - closed in close()
        os.chmod(self._tmp, 0o600)
        file_id = os.urandom(16)
        self._prefix = os.urandom(7)
        self._chunk = chunk
        header = {"v": 1, "alg": "AES-256-GCM", "chunk": chunk, "file_id": b64e(file_id),
                  "nonce_prefix": b64e(self._prefix), "name": logical_name, "dek_id": key_id(dek)}
        hb = canonical_bytes(header)
        self._hh = hashlib.sha256(hb).digest()
        self._aes = AESGCM(hkdf(dek, b"tripline-file" + file_id))
        self._fh.write(MAGIC + struct.pack(">I", len(hb)) + hb)
        self._buf = bytearray()
        self._index = 0
        self._digest = hashlib.sha256()
        self._closed_ok = False

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:
        if self.closed:
            raise ValueError("write to closed envelope")
        mv = bytes(b)
        self._buf.extend(mv)
        while len(self._buf) > self._chunk:
            self._emit(bytes(self._buf[: self._chunk]), final=False)
            del self._buf[: self._chunk]
        return len(mv)

    def _emit(self, data: bytes, final: bool) -> None:
        ct = self._aes.encrypt(_nonce(self._prefix, self._index, final), data, _aad(self._hh, self._index))
        self._fh.write(ct)
        self._digest.update(ct)
        self._index += 1

    def close(self) -> None:
        if self.closed:
            return
        self._emit(bytes(self._buf), final=True)
        self._buf.clear()
        self._fh.flush()
        os.fsync(self._fh.fileno())
        self._fh.close()
        os.replace(self._tmp, self._path)
        self._closed_ok = True
        super().close()

    def abort(self) -> None:
        if not self.closed:
            self._fh.close()
            self._tmp.unlink(missing_ok=True)
            super().close()

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.abort()
            return False
        self.close()
        return False

    def __del__(self):
        # Never let garbage collection commit a half-written file as if it were complete.
        try:
            self.abort()
        except Exception:  # noqa: BLE001, S110
            pass


class EnvelopeReader(io.RawIOBase):
    """Seekable decrypting reader (random access by chunk), usable by pyarrow via ``pa.PythonFile``."""

    def __init__(self, path: Path, dek: bytes, logical_name: str | None = None):
        super().__init__()
        self._fh = open(path, "rb")  # noqa: SIM115
        magic = self._fh.read(8)
        if magic != MAGIC:
            self._fh.close()
            raise IntegrityError("not a Tripline envelope")
        (hlen,) = struct.unpack(">I", self._fh.read(4))
        if hlen > 65536:
            raise IntegrityError("envelope header too large")
        hb = self._fh.read(hlen)
        header = json.loads(hb)
        if canonical_bytes(header) != hb or header.get("v") != 1 or header.get("alg") != "AES-256-GCM":
            raise IntegrityError("bad envelope header")
        if header.get("dek_id") != key_id(dek):
            raise IntegrityError("envelope belongs to a different case key")
        if logical_name is not None and header.get("name") != logical_name:
            raise IntegrityError("envelope logical name mismatch (file moved or substituted)")
        self.header = header
        self._hh = hashlib.sha256(hb).digest()
        self._prefix = b64d(header["nonce_prefix"])
        self._chunk = int(header["chunk"])
        self._aes = AESGCM(hkdf(dek, b"tripline-file" + b64d(header["file_id"])))
        self._data_start = 12 + hlen
        total = os.fstat(self._fh.fileno()).st_size - self._data_start
        if total < TAG:
            raise IntegrityError("envelope truncated")
        step = self._chunk + TAG
        self._n_chunks = max(1, -(-total // step))
        last_ct = total - (self._n_chunks - 1) * step
        if last_ct < TAG:
            raise IntegrityError("envelope truncated")
        self._size = (self._n_chunks - 1) * self._chunk + (last_ct - TAG)
        self._pos = 0
        self._cache_idx = -1
        self._cache = b""

    @property
    def size(self) -> int:
        return self._size

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._pos

    def seek(self, offset: int, whence: int = 0) -> int:
        if whence == 0:
            pos = offset
        elif whence == 1:
            pos = self._pos + offset
        elif whence == 2:
            pos = self._size + offset
        else:
            raise ValueError("bad whence")
        if pos < 0:
            raise ValueError("negative seek")
        self._pos = pos
        return pos

    def _load(self, idx: int) -> bytes:
        if idx == self._cache_idx:
            return self._cache
        step = self._chunk + TAG
        self._fh.seek(self._data_start + idx * step)
        final = idx == self._n_chunks - 1
        ct = self._fh.read(step)
        try:
            pt = self._aes.decrypt(_nonce(self._prefix, idx, final), ct, _aad(self._hh, idx))
        except InvalidTag:
            raise IntegrityError("envelope authentication failed (tampered, truncated or wrong key)") from None
        self._cache_idx, self._cache = idx, pt
        return pt

    def read(self, n: int = -1) -> bytes:
        if self._pos >= self._size:
            return b""
        if n is None or n < 0:
            n = self._size - self._pos
        n = min(n, self._size - self._pos)
        out = bytearray()
        while n > 0:
            idx, off = divmod(self._pos, self._chunk)
            pt = self._load(idx)
            piece = pt[off: off + n]
            if not piece:
                break
            out.extend(piece)
            self._pos += len(piece)
            n -= len(piece)
        return bytes(out)

    def readinto(self, b) -> int:
        data = self.read(len(b))
        b[: len(data)] = data
        return len(data)

    def readall(self) -> bytes:
        return self.read(-1)

    def verify_all(self) -> None:
        for i in range(self._n_chunks):
            self._load(i)

    def close(self) -> None:
        if not self.closed:
            self._fh.close()
            self._cache = b""
        super().close()


def encrypt_bytes_to(path: Path, dek: bytes, logical_name: str, data: bytes) -> None:
    with EnvelopeWriter(path, dek, logical_name) as w:
        w.write(data)


def decrypt_file(path: Path, dek: bytes, logical_name: str | None = None) -> bytes:
    with EnvelopeReader(path, dek, logical_name) as r:
        return r.readall()
