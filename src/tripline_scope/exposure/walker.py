"""Confined, budgeted, read-only traversal of declared snapshot roots, with bounded archive expansion.

Guarantees:

* only paths inside a declared root are listed or opened; symlinks are never followed (a symlink whose target
  lies outside the root is recorded as a rejected escape, one inside the root as "not followed");
* files are opened ``O_RDONLY | O_NOFOLLOW`` and checked with ``fstat`` against the directory entry (a file
  swapped for a link or FIFO between listing and opening is refused); special files are never opened;
* per-file size, file count, total bytes and wall-clock budgets are enforced; a file over the per-file budget is
  not read (only a 4 KiB header for format recognition) and is reported ``unavailable``;
* archives (zip, tar, gzip, bzip2, xz) are expanded in memory only, bounded by depth, member count, per-member
  size, compression ratio and total decompressed bytes; nothing is ever extracted to disk.
"""

from __future__ import annotations

import bz2
import datetime as dt
import io
import lzma
import os
import posixpath
import re
import stat
import tarfile
import time
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass

from tripline_scope.core.redact import scrub_text

from .coverage import Recorder
from .filetypes import sniff
from .manifest import Manifest, Root

HEADER_BYTES = 4096
FILE_CONTROLS = ("A1", "A3")


class BudgetExhausted(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class Item:
    root: Root
    rel: str                 # posix path relative to the root; archive members as "outer.zip!inner/file.csv"
    data: bytes | None       # whole content when ``complete``; None when only the header was read
    header: bytes
    size: int
    mtime: float | None
    depth: int = 0           # archive nesting depth (0 = a file on disk)

    @property
    def complete(self) -> bool:
        return self.data is not None

    @property
    def unit(self) -> str:
        return f"root:{self.root.id}"

    @property
    def display(self) -> str:
        return display_location(self.root.id, self.rel)


def display_location(root_id: str, rel: str) -> str:
    """Operator/report display of a location: identifier-like content in names is redacted."""
    return scrub_text(f"{root_id}:{rel}")[:400]


def scrub_rel(rel: str) -> str:
    return scrub_text(rel)[:400]


def _glob_re(pattern: str) -> re.Pattern:
    out, i = [], 0
    p = pattern.strip().lstrip("/")
    while i < len(p):
        if p.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif p.startswith("**", i):
            out.append(".*")
            i += 2
        elif p[i] == "*":
            out.append("[^/]*")
            i += 1
        elif p[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(p[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


class Budget:
    def __init__(self, b: dict, clock=time.monotonic):
        self.b = b
        self.clock = clock
        self.start = clock()
        self.files = 0
        self.bytes = 0

    def check_time(self) -> None:
        if self.clock() - self.start > self.b["max_seconds"]:
            raise BudgetExhausted("time budget exhausted")

    def charge_file(self) -> None:
        self.check_time()
        if self.files >= self.b["max_files"]:
            raise BudgetExhausted("file-count budget exhausted")
        self.files += 1

    def charge_bytes(self, n: int) -> None:
        if self.bytes + n > self.b["max_total_bytes"]:
            raise BudgetExhausted("total-bytes budget exhausted")
        self.bytes += n


class Walker:
    def __init__(self, manifest: Manifest, budget: Budget, rec: Recorder):
        self.m = manifest
        self.budget = budget
        self.rec = rec
        self.global_excl = [(p, _glob_re(p)) for p in manifest.exclusions]

    # ------------------------------------------------------------------ filesystem
    def _excluded(self, root: Root, rel: str, is_dir: bool) -> str | None:
        target = rel + "/" if is_dir else rel
        for pat, rx in self.global_excl + [(p, _glob_re(p)) for p in root.exclusions]:
            if rx.match(target) or (is_dir and rx.match(rel)):
                return pat
        return None

    def walk(self, root: Root) -> Iterator[Item]:
        """Yield files under ``root`` in deterministic (sorted, depth-first) order."""
        base = os.fspath(root.path)
        unit = f"root:{root.id}"
        stack = [""]
        while stack:
            reldir = stack.pop()
            absdir = os.path.join(base, reldir) if reldir else base
            try:
                with os.scandir(absdir) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except OSError as exc:
                self.rec.unavail(FILE_CONTROLS, unit, f"directory not readable ({type(exc).__name__})",
                                 display_location(root.id, reldir or "."))
                continue
            subdirs = []
            for e in entries:
                rel = f"{reldir}/{e.name}" if reldir else e.name
                try:
                    if e.is_symlink():
                        self._symlink(root, base, e.path, rel)
                        continue
                    st = e.stat(follow_symlinks=False)
                except OSError as exc:
                    self.rec.unavail(FILE_CONTROLS, unit, f"entry not readable ({type(exc).__name__})",
                                     display_location(root.id, rel))
                    continue
                is_dir = stat.S_ISDIR(st.st_mode)
                pat = self._excluded(root, rel, is_dir)
                if pat:
                    self.rec.exclude("declared-exclusion", unit, display_location(root.id, rel),
                                     f"matches exclusion pattern {pat}")
                    continue
                if is_dir:
                    subdirs.append(rel)
                elif stat.S_ISREG(st.st_mode):
                    item = self._file(root, e.path, rel, st)
                    if item is not None:
                        yield item
                else:
                    self.rec.exclude("special-file", unit, display_location(root.id, rel),
                                     "not a regular file (device, FIFO or socket): never opened")
            stack.extend(reversed(subdirs))

    def _symlink(self, root: Root, base: str, path: str, rel: str) -> None:
        unit = f"root:{root.id}"
        try:
            target = os.readlink(path)
        except OSError:
            target = None
        lexical = os.path.normpath(os.path.join(os.path.dirname(path), target)) if target is not None else None
        inside = lexical is not None and (lexical == base or lexical.startswith(base + os.sep))
        if inside:
            self.rec.exclude("symlink-not-followed", unit, display_location(root.id, rel),
                             "symbolic link inside the root: not followed (its target is scanned in place)")
        else:
            self.rec.exclude("symlink-escape-rejected", unit, display_location(root.id, rel),
                             "symbolic link pointing outside the approved root: rejected, target never opened")
            self.rec.count("A1", "symlink_escapes_rejected")

    def _file(self, root: Root, path: str, rel: str, st: os.stat_result) -> Item | None:
        unit = f"root:{root.id}"
        self.budget.charge_file()
        maxb = self.m.budget["max_file_bytes"]
        too_large = st.st_size > maxb
        want = HEADER_BYTES if too_large else st.st_size
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        except OSError as exc:
            self.rec.unavail(FILE_CONTROLS, unit, f"file not readable ({type(exc).__name__})",
                             display_location(root.id, rel))
            return None
        try:
            fst = os.fstat(fd)
            if not stat.S_ISREG(fst.st_mode) or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                self.rec.unavail(FILE_CONTROLS, unit, "file changed between listing and opening: refused",
                                 display_location(root.id, rel))
                return None
            chunks, got = [], 0
            while got < want + (0 if too_large else 1):
                b = os.read(fd, min(1 << 20, want + 1 - got))
                if not b:
                    break
                chunks.append(b)
                got += len(b)
            data = b"".join(chunks)
        except OSError as exc:
            self.rec.unavail(FILE_CONTROLS, unit, f"file not readable ({type(exc).__name__})",
                             display_location(root.id, rel))
            return None
        finally:
            os.close(fd)
        if too_large:
            self.budget.charge_bytes(len(data))
            self.rec.unavail(FILE_CONTROLS, unit, "exceeds the per-file size budget: content not inspected "
                             "(format recognised from the header only)", display_location(root.id, rel))
            self.rec.count("A1", "files_over_size_budget")
            return Item(root, rel, None, data[:HEADER_BYTES], st.st_size, st.st_mtime)
        if len(data) > maxb:
            self.rec.unavail(FILE_CONTROLS, unit, "file grew past the per-file size budget while reading",
                             display_location(root.id, rel))
            return None
        self.budget.charge_bytes(len(data))
        return Item(root, rel, data, data[:HEADER_BYTES], len(data), st.st_mtime)

    # ------------------------------------------------------------------ archives
    def expand(self, item: Item, kind: str) -> Iterator[Item]:
        """Members of an archive item (recursion is the caller's job: it calls expand again on nested archives)."""
        unit = item.unit
        b = self.m.budget
        if item.depth >= b["archive_max_depth"]:
            self.rec.unavail(FILE_CONTROLS, unit, "archive nesting exceeds the depth budget: not expanded", item.display)
            self.rec.count("A3", "archives_depth_limited")
            return
        try:
            if kind == "zip":
                yield from self._zip(item)
            elif kind == "tar":
                yield from self._tar(item, item.data)
            elif kind in ("gzip", "bzip2", "xz"):
                yield from self._stream(item, kind)
        except BudgetExhausted:
            raise
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError, zlib.error, lzma.LZMAError, ValueError,
                NotImplementedError, RuntimeError) as exc:
            self.rec.parser_failure(kind, unit, item.display, type(exc).__name__)

    def _member(self, item: Item, name: str, data: bytes, mtime: float | None) -> Item:
        self.budget.charge_bytes(len(data))
        clean = posixpath.normpath("/" + name.replace("\\", "/")).lstrip("/") or "member"
        return Item(item.root, f"{item.rel}!{clean}", data, data[:HEADER_BYTES], len(data),
                    mtime if mtime is not None else item.mtime, item.depth + 1)

    def _limits(self):
        b = self.m.budget
        return b["archive_max_members"], b["max_file_bytes"], b["archive_max_ratio"], b["archive_max_total_bytes"]

    def _zip(self, item: Item) -> Iterator[Item]:
        max_members, max_file, max_ratio, max_total = self._limits()
        unit = item.unit
        zf = zipfile.ZipFile(io.BytesIO(item.data))
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > max_members:
            self.rec.unavail(FILE_CONTROLS, unit, f"archive has more members than the budget ({max_members}); "
                             "the rest were not inspected", item.display)
        total = 0
        for info in infos[:max_members]:
            self.budget.check_time()
            loc = f"{item.display}!{scrub_rel(info.filename)}"
            if info.flag_bits & 0x1:
                self.rec.unavail(FILE_CONTROLS, unit, "encrypted archive member: not inspected", loc)
                continue
            if info.file_size > max_file:
                self.rec.unavail(FILE_CONTROLS, unit, "archive member exceeds the per-file size budget", loc)
                continue
            if info.file_size / max(info.compress_size, 1) > max_ratio:
                self.rec.unavail(FILE_CONTROLS, unit, "compression ratio exceeds the budget (possible archive "
                                 "bomb): not decompressed", loc)
                self.rec.count("A3", "archive_bombs_refused")
                continue
            if total + info.file_size > max_total:
                self.rec.unavail(FILE_CONTROLS, unit, "archive decompressed-size budget exhausted; remaining "
                                 "members not inspected", loc)
                break
            with zf.open(info) as fh:
                data = fh.read(min(info.file_size, max_file) + 1)
            if len(data) > info.file_size or len(data) > max_file:
                self.rec.unavail(FILE_CONTROLS, unit, "archive member larger than declared: refused", loc)
                continue
            total += len(data)
            try:
                mt = dt.datetime(*info.date_time, tzinfo=dt.UTC).timestamp()
            except (ValueError, OverflowError):
                mt = None
            yield self._member(item, info.filename, data, mt)

    def _tar(self, item: Item, data: bytes) -> Iterator[Item]:
        max_members, max_file, max_ratio, max_total = self._limits()
        unit = item.unit
        total, n = 0, 0
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tf:
            for m in tf:
                self.budget.check_time()
                n += 1
                if n > max_members:
                    self.rec.unavail(FILE_CONTROLS, unit, f"archive has more members than the budget ({max_members}); "
                                     "the rest were not inspected", item.display)
                    break
                loc = f"{item.display}!{scrub_rel(m.name)}"
                if m.issym() or m.islnk():
                    self.rec.exclude("archive-link", unit, loc, "link inside an archive: not followed")
                    continue
                if not m.isreg():
                    continue
                if m.size > max_file:
                    self.rec.unavail(FILE_CONTROLS, unit, "archive member exceeds the per-file size budget", loc)
                    continue
                if total + m.size > max_total:
                    self.rec.unavail(FILE_CONTROLS, unit, "archive decompressed-size budget exhausted; remaining "
                                     "members not inspected", loc)
                    break
                fh = tf.extractfile(m)
                if fh is None:
                    continue
                content = fh.read(m.size + 1)
                total += len(content)
                yield self._member(item, m.name, content[: m.size], float(m.mtime) if m.mtime else None)

    def _stream(self, item: Item, kind: str) -> Iterator[Item]:
        _, max_file, max_ratio, max_total = self._limits()
        cap = min(max_file, max_total, max(len(item.data), 1) * max_ratio)
        if kind == "gzip":
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = d.decompress(item.data, cap + 1)
        elif kind == "bzip2":
            out = bz2.BZ2Decompressor().decompress(item.data, max_length=cap + 1)
        else:
            out = lzma.LZMADecompressor().decompress(item.data, max_length=cap + 1)
        if len(out) > cap:
            self.rec.unavail(FILE_CONTROLS, item.unit, "decompressed size exceeds the ratio/size budget (possible "
                             "archive bomb): not inspected", item.display)
            self.rec.count("A3", "archive_bombs_refused")
            return
        name = posixpath.basename(item.rel.split("!")[-1])
        for suf in (".gz", ".tgz", ".bz2", ".xz"):
            if name.lower().endswith(suf):
                name = name[: -len(suf)] + (".tar" if suf == ".tgz" else "")
                break
        else:
            name = name + ".decompressed"
        member = self._member(item, name, out, None)
        if sniff(member.rel, member.header) == "tar":
            member.depth = item.depth  # a .tar.gz is one archive level, not two
            yield from self._tar(member, out)
        else:
            yield member
