"""Test-only minimal EVTX writer, written from the published EVTX layout (file header, 64 KiB chunks with
CRC32 checksums, event records holding BinXML with inline element/attribute names and UTF-16 text values).

It writes plain elements (no templates/substitutions), which is enough for a parser to rebuild the XML of
Windows Security events for tests. Never used outside the test suite.
"""

from __future__ import annotations

import datetime as dt
import struct
import zlib

CHUNK = 65536
_EPOCH = dt.datetime(1601, 1, 1, tzinfo=dt.UTC)


def _filetime(t: dt.datetime) -> int:
    return int((t - _EPOCH).total_seconds() * 10_000_000)


def _name_hash(name: str) -> int:
    h = 0
    for ch in name:
        h = (h * 65599 + ord(ch)) & 0xFFFFFFFF
    return h & 0xFFFF


class _BinXml:
    def __init__(self, chunk_offset: int):
        self.buf = bytearray()
        self.base = chunk_offset          # offset of buf[0] within the chunk

    def pos(self) -> int:
        return self.base + len(self.buf)

    def name(self, text: str) -> None:
        """Inline name structure: next offset, hash, length, UTF-16 chars, NUL."""
        self.buf += struct.pack("<IHH", 0, _name_hash(text), len(text)) + text.encode("utf-16-le") + b"\x00\x00"

    def open(self, tag: str, attrs: list[tuple[str, str]], body) -> None:
        self.buf.append(0x41 if attrs else 0x01)
        size_at = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"                    # data size, patched below
        self.buf += struct.pack("<I", self.pos() + 4)      # name offset -> inline name right after this field
        self.name(tag)
        if attrs:
            alist_at = len(self.buf)
            self.buf += b"\x00\x00\x00\x00"
            a0 = len(self.buf)
            for i, (k, v) in enumerate(attrs):
                self.buf.append(0x46 if i < len(attrs) - 1 else 0x06)
                self.buf += struct.pack("<I", self.pos() + 4)
                self.name(k)
                self.value(v)
            struct.pack_into("<I", self.buf, alist_at, len(self.buf) - a0)
        if body is None:
            self.buf.append(0x03)                          # close empty element
        else:
            self.buf.append(0x02)                          # close start element
            if isinstance(body, str):
                self.value(body)
            else:
                for child in body:
                    self.open(*child)
            self.buf.append(0x04)                          # end element
        struct.pack_into("<I", self.buf, size_at, len(self.buf) - (size_at + 4))

    def value(self, text: str) -> None:
        self.buf += b"\x05\x01" + struct.pack("<H", len(text)) + text.encode("utf-16-le")


def _event_tree(ev: dict):
    system = [
        ("Provider", [("Name", "Microsoft-Windows-Security-Auditing")], None),
        ("EventID", [], str(ev["EventID"])),
        ("TimeCreated", [("SystemTime", ev["ts"].strftime("%Y-%m-%dT%H:%M:%S.%fZ"))], None),
        ("EventRecordID", [], str(ev["record_id"])),
        ("Channel", [], "Security"),
        ("Computer", [], ev["computer"]),
    ]
    data = [("Data", [("Name", k)], str(v)) for k, v in ev["data"].items()]
    return ("Event", [("xmlns", "http://schemas.microsoft.com/win/2004/08/events/event")],
            [("System", [], system), ("EventData", [], data)])


def _record(ev: dict, rec_off: int) -> bytes:
    bx = _BinXml(rec_off + 24)
    bx.buf += b"\x0f\x01\x01\x00"                          # fragment header
    bx.open(*_event_tree(ev))
    bx.buf.append(0x00)                                    # end of stream
    size = 24 + len(bx.buf) + 4
    return struct.pack("<IIQQ", 0x00002A2A, size, ev["record_id"], _filetime(ev["ts"])) + bytes(bx.buf) + \
        struct.pack("<I", size)


def _chunk(records: list[bytes], offsets: list[int], first: int, last: int) -> bytes:
    data = b"".join(records)
    chunk = bytearray(CHUNK)
    chunk[512:512 + len(data)] = data
    hdr = bytearray(512)
    struct.pack_into("<8sQQQQIII", hdr, 0, b"ElfChnk\x00", first, last, first, last, 128, offsets[-1], 512 + len(data))
    struct.pack_into("<I", hdr, 52, zlib.crc32(data) & 0xFFFFFFFF)
    struct.pack_into("<I", hdr, 124, zlib.crc32(bytes(hdr[:120]) + bytes(hdr[128:512])) & 0xFFFFFFFF)
    chunk[:512] = hdr
    return bytes(chunk)


def write_evtx(path, events: list[dict]) -> None:
    """events: [{ts, EventID, computer, data{}}]; record ids 1..n, as many 64 KiB chunks as needed."""
    chunks, recs, offs, first = [], [], [], 1
    pos = 512
    for i, ev in enumerate(events, 1):
        ev = dict(ev, record_id=i)
        rec = _record(ev, pos)
        if pos + len(rec) > CHUNK:
            chunks.append(_chunk(recs, offs, first, i - 1))
            recs, offs, first, pos = [], [], i, 512
            rec = _record(ev, pos)
        recs.append(rec)
        offs.append(pos)
        pos += len(rec)
    if recs:
        chunks.append(_chunk(recs, offs, first, len(events)))
    fh = bytearray(4096)
    struct.pack_into("<8sQQQIHHHH", fh, 0, b"ElfFile\x00", 0, len(chunks) - 1, len(events) + 1, 128, 2, 3, 4096,
                     len(chunks))
    struct.pack_into("<I", fh, 124, zlib.crc32(bytes(fh[:120])) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(bytes(fh) + b"".join(chunks))
