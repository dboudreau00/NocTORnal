"""The archive-expansion child process: one bounded walk over one archive
sample's bytes (roadmap phase 8 "archive expansion", 2026-10-02).

Run as `python -m noctornal_api.lab_archive_child` by `lab_archive`
through the same runner static triage uses (`lab_triage.run_child`),
never imported for its walk by anything that holds a database
connection, a key or a request. Pure in the sense `lab_static` is: no
database, no environment reads beyond what the parent hands it, no files.

## Why a child, and why nothing touches a disk

An archive is the oldest delivery wrapper there is, and its container
format is parsed by code that was written for well-formed input: a zip
bomb, a tar whose size field lies, a name that walks out of its
directory. So the walk happens in a process that bounds itself BEFORE it
reads a payload byte (`lab_static.apply_limits`: no file writes, a CPU
limit, an address space limit where the platform enforces one), under the
parent's wall clock and output cap, and every member is read INTO MEMORY
through a reader that stops one byte past its cap. Nothing here ever
calls `extract`, `extractall` or opens a path: a member's name is used
for exactly two things, the refusal rules below and the path recorded on
the child sample.

## What crosses, and how

stdin carries one header line (UTF-8 JSON, at most `HEADER_CAP` bytes)
naming the caps and the archive-password convention, then the archive.
stdout carries one frame: an 8-byte big-endian length, the JSON report,
then every accepted member's bytes back to back in the report's order
(`frame`). The parent recomputes every digest and believes nothing but
the shape (`lab_archive`): a member whose bytes do not hash to what the
report says is dropped with the whole answer.

Every refusal is reported as a CODE from `REFUSALS`, never a sentence,
and a member's name reaches the report only once `safe_path` has found
it printable; an unprintable one is reported in its escaped form. A
parser's own message can quote hostile bytes, so an exception is reported
by its class alone, as `lab_static` reports one.

## The rules, in the order they are applied to a member

1. A directory entry is recorded and holds nothing.
2. A symbolic link, a hard link or a device file is refused: each is an
   instruction to a filesystem, and nothing here has one.
3. The name: NUL or an unprintable character, over `MAX_PATH_CHARS`, an
   absolute path (a leading slash, a drive letter, a UNC prefix) or a
   `..` component is refused. The normalised path (forward slashes, no
   `.` components) is what the child sample records.
4. A second member with the same normalised path is a duplicate, and one
   that differs only by case or Unicode normalisation (NFKC, casefolded)
   collides with the first: both are refused, the first stands.
5. An encrypted zip member is opened with the archive-password
   convention (docs/16 C6, `infected`, handed in by the parent) and
   refused when that does not open it; an encryption or compression
   method the standard library cannot read is refused by name.
6. The declared size is checked against the per-member cap before a byte
   is read, then the bytes are read under the cap anyway (a size field
   can lie); an empty member is refused (an empty submission is not a
   sample); a zip member's compression ratio is checked against the cap,
   and the whole walk's ratio against the archive's own size.
7. The running total of uncompressed bytes is checked against its cap
   after every member; past it the whole expansion is refused, because a
   partial answer to "what is in this archive" is the kind that gets
   trusted.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import re
import struct
import sys
import tarfile
import time
import unicodedata
import zipfile
import zlib

from noctornal_api.lab_static import HEADER_CAP, PROTOCOL, _read_exact, apply_limits

#: What the child accepts as the archive's family, by the magic the parent
#: typed it with (`samples.file_type_of`) and what the child sees.
FAMILIES = ("zip", "tar")
MODE = "archive"
#: The longest member path recorded; a longer one is refused by name.
MAX_PATH_CHARS = 512
#: Members are read this much at a time, never more than their cap plus
#: one byte, so a lying size field costs one extra chunk at most.
CHUNK = 1 << 20

#: Whole-archive refusals, by code. The parent holds the sentences.
ARCHIVE_REFUSALS = (
    "corrupt", "truncated", "not_tar", "multipart", "member_count",
    "total_bytes", "ratio", "unknown_format",
)
#: Per-member refusals, by code.
MEMBER_REFUSALS = (
    "directory", "symlink", "hardlink", "device", "unprintable_name",
    "name_too_long", "absolute_path", "parent_traversal", "duplicate_name",
    "case_collision", "encrypted_no_password", "encryption_unsupported",
    "compression_unsupported", "member_bytes", "ratio", "empty",
    "corrupt_member", "truncated_member", "size_mismatch",
)
REFUSALS = ARCHIVE_REFUSALS + MEMBER_REFUSALS
#: The per-member refusals behind which there is no content to compare: a
#: directory, a link, a device and an empty entry hold no bytes, so a
#: refusal of one leaves nothing unscreened. Every other member refusal
#: left bytes that no screening saw, which the derived "members were not
#: compared" gap says (2026-10-03).
CONTENT_FREE_REFUSALS = ("directory", "symlink", "hardlink", "device", "empty")

_DRIVE = re.compile(r"^[A-Za-z]:")
_EOCD_SEARCH = 22 + 65535


class Refused(Exception):
    """The whole walk stops: `code` is one of ARCHIVE_REFUSALS."""

    def __init__(self, code: str, **detail):
        super().__init__(code)
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

def escaped(name: str) -> str:
    """A name a reader can look at whatever it holds: every character
    outside printable ASCII becomes its `\\uXXXX` or `\\xXX` escape, and
    the result is capped so an escape of a long name stays short."""
    out = name.encode("unicode_escape").decode("ascii")
    return out[:MAX_PATH_CHARS] + ("..." if len(out) > MAX_PATH_CHARS else "")


def safe_path(raw: str) -> tuple[str | None, str | None]:
    """`(normalised path, None)` or `(None, refusal code)`. The path is
    forward-slashed with no empty or `.` components; a trailing slash is
    dropped (the caller decides directories by the entry's own kind)."""
    if not isinstance(raw, str) or not raw:
        return None, "unprintable_name"
    if "\x00" in raw or not raw.isprintable():
        return None, "unprintable_name"
    if len(raw) > MAX_PATH_CHARS:
        return None, "name_too_long"
    name = raw.replace("\\", "/")
    if name.startswith("/") or _DRIVE.match(name) or name.startswith("//"):
        return None, "absolute_path"
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None, "parent_traversal"
    if not parts:
        return None, "unprintable_name"
    return "/".join(parts), None


def folded(path: str) -> str:
    """The key two names collide on: NFKC, then casefolded."""
    return unicodedata.normalize("NFKC", path).casefold()


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------

class _Walk:
    """One walk's state: the caps, the names seen, the members kept, the
    refusals recorded and the running totals."""

    def __init__(self, caps: dict, archive_len: int, password: bytes):
        self.max_members = int(caps["members"])
        self.max_total = int(caps["total_bytes"])
        self.max_member = int(caps["member_bytes"])
        self.max_ratio = int(caps["ratio"])
        self.archive_len = max(archive_len, 1)
        self.password = password
        self.members: list[dict] = []
        self.payloads: list[bytes] = []
        self.refused: list[dict] = []
        self.entries = 0
        self.total = 0
        #: Bytes decompressed to get past members refused over the
        #: per-member cap in a STREAMING tar (2026-10-03): the reader must still decompress
        #: them, so they
        #: count against the total and the ratio like any other byte.
        self.skipped = 0
        self.seen_exact: dict[str, int] = {}
        self.seen_folded: dict[str, str] = {}

    def refuse(self, shown: str, code: str, **detail) -> None:
        entry = {"path": shown, "code": code}
        if detail:
            entry["detail"] = detail
        self.refused.append(entry)

    def count(self) -> None:
        self.entries += 1
        if self.entries > self.max_members:
            raise Refused("member_count", entries=self.entries,
                          cap=self.max_members)

    def name(self, raw: str) -> str | None:
        """The path to record, or None after a refusal was recorded."""
        path, code = safe_path(raw)
        if path is None:
            self.refuse(escaped(raw), code)
            return None
        if path in self.seen_exact:
            self.refuse(path, "duplicate_name", first=self.seen_exact[path])
            return None
        key = folded(path)
        if key in self.seen_folded:
            self.refuse(path, "case_collision",
                        collides_with=self.seen_folded[key])
            return None
        self.seen_exact[path] = len(self.members)
        self.seen_folded[key] = path
        return path

    def read_bounded(self, stream, declared: int, path: str) -> bytes | None:
        """The member's bytes, never more than the cap plus one byte
        whatever the header says; None after a refusal was recorded."""
        parts: list[bytes] = []
        got = 0
        while True:
            want = min(CHUNK, self.max_member + 1 - got)
            if want <= 0:
                self.refuse(path, "member_bytes", declared=declared,
                            cap=self.max_member)
                return None
            chunk = stream.read(want)
            if not chunk:
                break
            parts.append(chunk)
            got += len(chunk)
        data = b"".join(parts)
        if len(data) > self.max_member:
            self.refuse(path, "member_bytes", declared=declared,
                        cap=self.max_member)
            return None
        if len(data) != declared:
            self.refuse(path, "size_mismatch", declared=declared, actual=len(data))
            return None
        if not data:
            self.refuse(path, "empty")
            return None
        return data

    def skip_over_cap(self, stream, declared: int) -> None:
        """A tar member over the per-member cap is refused, but a streaming
        read still has to decompress it to reach the next header, and
        tarfile's own stream skip (`seek`) is quadratic in the compression
        ratio: a 171 byte tar.bz2 declaring one 96 MiB member burned the
        whole wall clock and ended as a generic timeout, and a 48 MiB member
        at 85 to 1 took 14 seconds where reading it in pieces takes half a
        second. So: the declared size is held to the archive's own ratio
        BEFORE a byte is decompressed, and what is decompressed is read in
        `CHUNK` pieces and counted against the total and the ratio as it
        goes. The cost of a skip is thereby bounded by the caps, not by what
        a header claims, and a bomb is a named refusal of the whole archive."""
        if (self.total + self.skipped + declared) / self.archive_len > self.max_ratio:
            raise Refused("ratio", ratio=round(
                (self.total + self.skipped + declared) / self.archive_len, 1),
                cap=self.max_ratio)
        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                return
            self.skipped += len(chunk)
            held = self.total + self.skipped
            if held > self.max_total:
                raise Refused("total_bytes", total=held, cap=self.max_total)
            if held / self.archive_len > self.max_ratio:
                raise Refused("ratio", ratio=round(held / self.archive_len, 1),
                              cap=self.max_ratio)

    def keep(self, path: str, data: bytes, *, compressed: int | None) -> None:
        self.total += len(data)
        if self.total > self.max_total:
            raise Refused("total_bytes", total=self.total, cap=self.max_total)
        ratio = None
        if compressed is not None:
            ratio = len(data) / max(compressed, 1)
            if ratio > self.max_ratio:
                self.total -= len(data)
                self.refuse(path, "ratio", ratio=round(ratio, 1),
                            cap=self.max_ratio)
                return
        if (self.total + self.skipped) / self.archive_len > self.max_ratio:
            raise Refused("ratio", ratio=round(
                (self.total + self.skipped) / self.archive_len, 1),
                cap=self.max_ratio)
        self.members.append({"index": len(self.members), "path": path,
                             "size": len(data),
                             "sha256": hashlib.sha256(data).hexdigest(),
                             "compressed_size": compressed,
                             "ratio": round(ratio, 2) if ratio is not None else None})
        self.payloads.append(data)


# -- zip ---------------------------------------------------------------------

def _end_record_at(data: bytes) -> int:
    if (len(data) >= 22 and data[-22:-18] == b"PK\x05\x06"
            and data[-2:] == b"\x00\x00"):
        return len(data) - 22
    return data.rfind(b"PK\x05\x06", max(0, len(data) - _EOCD_SEARCH))


#: A central directory file header: its signature, its fixed length, and where
#: its three variable lengths (name, extra field, comment) sit in it.
_CD_SIGNATURE = b"PK\x01\x02"
_CD_FIXED = 46


def _count_directory(data: bytes, start: int, cd_size: int, max_members: int) -> int:
    """How many entries the central directory really holds, counted by
    walking its records from `start` and refusing at the first one past
    `max_members`. The claimed count is not believed: zipfile reads records
    until `cd_size` bytes are used and never looks at the count, so a
    directory of millions of 46-byte records behind an end record that
    claims one entry was parsed whole, up to the size of the archive, before
    the count refusal (docs/17). The walk only counts: a record that is not
    one ends it, and zipfile, which reads the same bytes from the same place,
    refuses that as corrupt in its own words."""
    if start < 0:
        raise Refused("corrupt")
    end = min(start + cd_size, len(data))
    count = 0
    at = start
    while at + _CD_FIXED <= end and data[at:at + 4] == _CD_SIGNATURE:
        count += 1
        if count > max_members:
            raise Refused("member_count", entries=count, cap=max_members)
        name, extra, comment = struct.unpack("<HHH", data[at + 28:at + 34])
        at += _CD_FIXED + name + extra + comment
    return count


def zip_preflight(data: bytes, max_members: int) -> int:
    """The entry count of the archive, refused by count or by a multi-part
    layout BEFORE zipfile builds one object per entry (the discipline
    `yara_rules` uses for a rule bundle). The end record (or a zip64 record a
    locator points at) is read for its claim, and the central directory is
    then counted by walking it (`_count_directory`), at most `max_members`
    records. Returns the larger of the claim and the count."""
    at = _end_record_at(data)
    if at < 0 or at + 22 > len(data):
        raise Refused("corrupt")
    (_sig, disk, cd_disk, _here, total, cd_size, cd_offset,
     _comment) = struct.unpack("<4sHHHHIIH", data[at:at + 22])
    # Where zipfile reads the directory from: it ends where the end record
    # begins, and a zip64 end record and its locator (76 bytes) come first.
    cd_end = at
    loc = at - 20
    if loc >= 0 and data[loc:loc + 4] == b"PK\x06\x07":
        (_s, z_disk, z64_at, disks) = struct.unpack("<4sIQI", data[loc:loc + 20])
        if z_disk or disks > 1:
            raise Refused("multipart")
        if z64_at + 56 > len(data) or data[z64_at:z64_at + 4] != b"PK\x06\x06":
            z64_at = loc - 56
            if z64_at < 0 or data[z64_at:z64_at + 4] != b"PK\x06\x06":
                raise Refused("corrupt")
        (_s, _size, _made, _need, disk64, cd_disk64, _here64, total64,
         cd_size64, _cd_offset64) = struct.unpack(
            "<4sQHHIIQQQQ", data[z64_at:z64_at + 56])
        disk, cd_disk = disk or disk64, cd_disk or cd_disk64
        total = max(total, total64)
        cd_size = max(cd_size, cd_size64)
        cd_end = at - 76
    if disk or cd_disk:
        raise Refused("multipart")
    if total > max_members:
        raise Refused("member_count", entries=total, cap=max_members)
    if cd_size > len(data):
        raise Refused("corrupt")
    return max(total, _count_directory(data, cd_end - cd_size, cd_size, max_members))


#: The most a zip entry marked as a symbolic link may hold and still be one:
#: its bytes are the link's target, a path.
MAX_LINK_TARGET = 1024


def _zip_kind(info: zipfile.ZipInfo) -> str | None:
    """A refusal code for a zip entry that is not a plain file, read from
    the Unix mode in the external attributes, else None.

    In a zip that mode is a bit beside an entry that carries bytes, which
    Windows and most extractors write out as an ordinary file. So an entry
    marked as a device that holds any bytes, or as a link that holds more
    than a link target, is read as the file it is: refused as content-free,
    it hid a payload from expansion and screening (2026-10-07)."""
    if info.is_dir():
        return "directory"
    mode = (info.external_attr >> 16) & 0xF000
    if mode == 0xA000 and info.file_size <= MAX_LINK_TARGET:
        return "symlink"
    if mode in (0x2000, 0x6000, 0x1000, 0xC000) and info.file_size == 0:
        return "device"
    return None


def walk_zip(data: bytes, walk: _Walk) -> None:
    zip_preflight(data, walk.max_members)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, EOFError, OSError, ValueError, OverflowError):
        raise Refused("corrupt") from None
    with zf:
        infos = zf.infolist()
        if len(infos) > walk.max_members:
            raise Refused("member_count", entries=len(infos), cap=walk.max_members)
        # The bytes open with a local header (`family_of`), so the first
        # member the central directory names must start there. zipfile reads
        # the LAST end record and shifts every offset past whatever precedes
        # it, so a zip appended to another one listed only the second, and
        # the first one's members went unexpanded and unscreened with nothing
        # refused (2026-10-07).
        if infos and min(i.header_offset for i in infos) != 0:
            raise Refused("corrupt", error="bytes_before_first_member")
        for info in infos:
            walk.count()
            kind = _zip_kind(info)
            if kind is not None:
                path, _code = safe_path(info.filename)
                walk.refuse(path or escaped(info.filename), kind)
                continue
            path = walk.name(info.filename)
            if path is None:
                continue
            if info.file_size > walk.max_member:
                walk.refuse(path, "member_bytes", declared=info.file_size,
                            cap=walk.max_member)
                continue
            encrypted = bool(info.flag_bits & 0x1)
            try:
                stream = zf.open(info, pwd=walk.password if encrypted else None)
            except RuntimeError as exc:
                # zipfile says "Bad password for file" as a RuntimeError;
                # anything else of that class is the parser refusing.
                code = ("encrypted_no_password" if encrypted
                        and "password" in str(exc).lower() else "corrupt_member")
                walk.refuse(path, code, error=type(exc).__name__)
                continue
            except NotImplementedError as exc:
                walk.refuse(path, "encryption_unsupported" if encrypted
                            else "compression_unsupported",
                            error=type(exc).__name__)
                continue
            except (zipfile.BadZipFile, EOFError, OSError, ValueError,
                    OverflowError, LookupError, zlib.error) as exc:
                walk.refuse(path, "corrupt_member", error=type(exc).__name__)
                continue
            try:
                with stream:
                    body = walk.read_bounded(stream, info.file_size, path)
            except EOFError as exc:
                walk.refuse(path, "truncated_member", error=type(exc).__name__)
                continue
            except RuntimeError as exc:
                # A wrong password is found at the first bytes, a bad CRC
                # at the last: both are the member not being what its
                # header says.
                code = ("encrypted_no_password" if encrypted
                        and "password" in str(exc).lower() else "corrupt_member")
                walk.refuse(path, code, error=type(exc).__name__)
                continue
            except (zipfile.BadZipFile, OSError, ValueError, OverflowError,
                    LookupError, MemoryError, zlib.error) as exc:
                # ZipCrypto's check is ONE byte, so a wrong password gets
                # past it once in 256 and then decrypts to garbage that
                # fails here (zlib.error, a CRC): for an encrypted member
                # that is the password not opening it, not a corrupt
                # archive (and an uncaught zlib.error used to refuse the
                # WHOLE archive as corrupt; 2026-10-03).
                walk.refuse(path, "encrypted_no_password" if encrypted
                            else "corrupt_member", error=type(exc).__name__)
                continue
            if body is None:
                continue
            walk.keep(path, body, compressed=info.compress_size)


# -- tar ---------------------------------------------------------------------

def _tar_kind(member: tarfile.TarInfo) -> str | None:
    if member.isdir():
        return "directory"
    if member.issym():
        return "symlink"
    if member.islnk():
        return "hardlink"
    if member.isdev():
        return "device"
    if not member.isreg():
        return "corrupt_member"
    return None


def _tar_stream(data: bytes):
    """The tar's bytes as a stream, decompressed by the library's own file
    readers, which read EVERY stream of a multi-stream gzip, bzip2 or xz file
    as `tar xzf` does. tarfile's own `r|*` decompressor stops at the end of
    the first stream, so a second stream's members were neither expanded nor
    refused (2026-10-07)."""
    raw = io.BytesIO(data)
    if data[:2] == b"\x1f\x8b":
        return gzip.GzipFile(fileobj=raw, mode="rb")
    if data[:3] == b"BZh":
        return bz2.BZ2File(raw, mode="rb")
    if data[:6] == b"\xfd7zXZ\x00":
        return lzma.LZMAFile(raw, mode="rb")
    return raw


#: Trailing NULs after a tar's last member that cost nothing against the
#: caps: a writer's record padding (GNU tar's largest blocking factor is a
#: little under 64 KiB).
PADDING_FREE = 1 << 20

#: What a decompressing stream raises on bytes that are not what they claim.
_STREAM_ERRORS = (EOFError, OSError, ValueError, OverflowError, zlib.error,
                  lzma.LZMAError)


def _rest_is_padding(tf: tarfile.TarFile, walk: _Walk) -> bool:
    """Whether everything after the walk's last member is NUL padding. The
    walk ends at the end-of-archive blocks, and also, silently, at a header
    after the first that does not parse; members behind either were read by
    nothing (GNU tar skips the bad header and reads on). Read in pieces; the
    first PADDING_FREE bytes are a writer's record padding (a 32 KiB record
    of NULs compresses to almost nothing, so counting it would refuse a tiny
    honest archive by ratio), and past them every byte counts against the
    total and the ratio, as a skip does."""
    seen = 0
    while True:
        chunk = tf.fileobj.read(CHUNK)
        if not chunk:
            return True
        if chunk.count(0) != len(chunk):
            return False
        counted = max(0, seen + len(chunk) - PADDING_FREE) - max(0, seen - PADDING_FREE)
        seen += len(chunk)
        if not counted:
            continue
        walk.skipped += counted
        held = walk.total + walk.skipped
        if held > walk.max_total:
            raise Refused("total_bytes", total=held, cap=walk.max_total)
        if held / walk.archive_len > walk.max_ratio:
            raise Refused("ratio", ratio=round(held / walk.archive_len, 1),
                          cap=walk.max_ratio)


def walk_tar(data: bytes, walk: _Walk) -> None:
    """A streaming read (`r|`) over `_tar_stream`: gzip, bzip2 and xz are
    decompressed as the members are read, never into one buffer first, so a
    compressed bomb is stopped by the total cap having cost that much and no
    more. A member over the per-member cap is refused by name and drained in
    pieces that count against the total and the ratio
    (`_Walk.skip_over_cap`): the skip is a decompression too. Anything but
    padding after the last member read refuses the whole archive."""
    try:
        tf = tarfile.open(fileobj=_tar_stream(data), mode="r|")
    except tarfile.ReadError:
        raise Refused("not_tar" if data[:2] in (b"\x1f\x8b", b"BZ", b"\xfd7")
                      else "corrupt") from None
    except _STREAM_ERRORS:
        raise Refused("corrupt") from None
    with tf:
        try:
            for member in tf:
                walk.count()
                kind = _tar_kind(member)
                if kind is not None:
                    path, _code = safe_path(member.name)
                    walk.refuse(path or escaped(member.name), kind)
                    stream = (tf.extractfile(member)
                              if kind == "corrupt_member" and member.size > 0 else None)
                    if stream is not None:
                        # A member of a type nothing reads still has its
                        # declared bytes before the next header, and tarfile's
                        # own skip decompresses them uncounted.
                        with stream:
                            walk.skip_over_cap(stream, member.size)
                    continue
                path = walk.name(member.name)
                if path is None:
                    continue
                if member.size > walk.max_member:
                    walk.refuse(path, "member_bytes", declared=member.size,
                                cap=walk.max_member)
                    stream = tf.extractfile(member)
                    if stream is not None:
                        with stream:
                            walk.skip_over_cap(stream, member.size)
                    continue
                stream = tf.extractfile(member)
                if stream is None:
                    walk.refuse(path, "corrupt_member")
                    continue
                with stream:
                    body = walk.read_bounded(stream, member.size, path)
                if body is None:
                    continue
                walk.keep(path, body, compressed=None)
            if not _rest_is_padding(tf, walk):
                raise Refused("corrupt", error="data_after_last_member")
        except tarfile.ReadError as exc:
            raise Refused("truncated", error=type(exc).__name__) from None
        except _STREAM_ERRORS as exc:
            raise Refused("corrupt", error=type(exc).__name__) from None


def family_of(data: bytes) -> str | None:
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06":
        return "zip"
    if data[:2] == b"\x1f\x8b" or data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00":
        return "tar"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    return None


def expand(data: bytes, caps: dict, password: bytes) -> tuple[dict, list[bytes]]:
    """The walk, in process, for the child's main and for the tests that
    drive the rules directly: `(report, payloads)`."""
    walk = _Walk(caps, len(data), password)
    family = family_of(data)
    report: dict = {"family": family, "refusal": None}
    try:
        if family == "zip":
            walk_zip(data, walk)
        elif family == "tar":
            walk_tar(data, walk)
        else:
            raise Refused("unknown_format")
    except Refused as exc:
        report["refusal"] = {"code": exc.code, "detail": exc.detail}
        walk.members, walk.payloads = [], []
    except MemoryError:
        report["refusal"] = {"code": "total_bytes", "detail": {"error": "MemoryError"}}
        walk.members, walk.payloads = [], []
    report.update({"members": walk.members, "refused": walk.refused,
                   "counts": {"entries": walk.entries,
                              "accepted": len(walk.members),
                              "refused": len(walk.refused)},
                   "total_bytes": sum(len(p) for p in walk.payloads)})
    return report, walk.payloads


def frame(report: dict, payloads: list[bytes]) -> bytes:
    body = json.dumps(report, separators=(",", ":")).encode()
    return struct.pack(">Q", len(body)) + body + b"".join(payloads)


# ---------------------------------------------------------------------------
# The child's main
# ---------------------------------------------------------------------------

def main() -> int:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    line = stdin.readline(HEADER_CAP + 1)
    if len(line) > HEADER_CAP or not line.endswith(b"\n"):
        stdout.write(b'{"ok":false,"error":"bad_header"}')
        return 2
    header = json.loads(line)
    if header.get("protocol") != PROTOCOL or header.get("mode") != MODE:
        stdout.write(b'{"ok":false,"error":"bad_header"}')
        return 2
    limits = header.get("limits") or {}
    applied = apply_limits(int(limits.get("memory_bytes", 2 << 30)),
                           int(limits.get("cpu_s", 300)))
    started = time.monotonic()
    data = _read_exact(stdin, int(header.get("sample_len", 0)))
    password = str(header.get("password") or "").encode("utf-8")
    try:
        report, payloads = expand(data, header["caps"], password)
    except (Exception, MemoryError, RecursionError) as exc:  # noqa: BLE001
        report, payloads = {"family": None, "members": [], "refused": [],
                            "refusal": {"code": "corrupt",
                                        "detail": {"error": type(exc).__name__}},
                            "counts": {"entries": 0, "accepted": 0,
                                       "refused": 0},
                            "total_bytes": 0}, []
    report.update({"ok": True, "mode": MODE, "limits": applied,
                   "timing_ms": int((time.monotonic() - started) * 1000)})
    stdout.write(frame(report, payloads))
    stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
