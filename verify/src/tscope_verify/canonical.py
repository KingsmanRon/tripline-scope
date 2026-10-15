"""RFC 8785 (JSON Canonicalization Scheme) helpers and hashing."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import rfc8785


class NotCanonicalError(ValueError):
    pass


def canonical_bytes(obj: Any) -> bytes:
    """Serialise ``obj`` per RFC 8785. Floats must be finite; ints must fit in IEEE-754 doubles."""
    return rfc8785.dumps(obj)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def load_canonical(data: bytes) -> Any:
    """Parse JSON bytes and require that they are already in RFC 8785 canonical form."""
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NotCanonicalError(f"not valid UTF-8 JSON: {type(exc).__name__}") from None
    if canonical_bytes(obj) != data:
        raise NotCanonicalError("JSON is not in RFC 8785 canonical form")
    return obj
