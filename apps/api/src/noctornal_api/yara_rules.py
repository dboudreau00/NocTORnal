"""YARA rule sets: intake, storage, labels, activation and the compiled
build cache (F12, 2026-09-24).

A rule set is a unit's statement of what it hunts, so it is LABELLED
(classification and compartments, only ever raised) and every read of it
checks both beside each other (docs/05, Binding a compartment column,
rule 7). A version is an immutable upload: its licence is recorded, and a
set becomes live only when
a DIFFERENT person activates a version (a Security Officer, holding
`sample.yara.activate`, which no role may hold with `sample.yara.manage`),
writing down the licence clearance when the source asks for review. The
software records a clearance; it cannot give one (docs/18 C14).

Findings are machine analyses (`samples.record_machine_analysis`), gated by
the set's labels as well as the sample's, and never write the graph: a
family reaches a case only as a person's assessment with a confidence.

## Hostile input in the API process

An upload is a .yar/.yara file or a .zip of them, parsed here with the
standard library only, in a worker thread rather than on the event loop.
The zip's end-of-central-directory record and any zip64 record a locator
points at are read FIRST and the entry count and directory size refused
before `zipfile.ZipFile` builds one object per entry (2026-09-24), and
zipfile reads the upload through a guard that counts the directory it is
actually handed before it parses it, so no
bound rests on a record the uploader wrote; each entry is read through a
bounded reader that never trusts header sizes, with a ratio and a total
cap; encrypted and
nested archives are refused, and so is any path that is absolute, climbs,
carries a control character, is too long or collides with another by case,
each named with its escapes visible.

## Storage

The canonical source (JSON, files sorted by path) is what the SHA-256 and
the duplicate check are over; it is STORED as one gzip member per file,
with each file's offset and length recorded, so viewing one file
decompresses one file and rule text (which carries malicious byte patterns)
is never plain at rest (docs/18 D3).

## Compiled builds carry native code

yara-x serialises rules with wasmtime-precompiled machine code, so a build
read back from the database is code a child will run. Builds are a
history, insert-only, and each carries an HMAC keyed from the KEK ring over
its version, engine, platform, host fingerprint and blob digest. The parent
verifies it before a blob reaches a child; a build that fails it, or that
the child cannot load (another CPU), is recorded in
`lab.yara_compiled_rejected` and a newer build is compiled and chosen. An
attacker who can write rows but not read the KEK cannot get code into a
child this way; the child's own residual exposure is `lab_static`'s
docstring.
"""
from __future__ import annotations

import gzip
import hashlib
import hmac
import io
import json
import os
import platform
import re
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass, field
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.config import parse_size
from noctornal_api.security import envelope
from noctornal_api.security.access import AccessResolutionError, tlp_from_name


# ---------------------------------------------------------------------------
# Settings and caps
# ---------------------------------------------------------------------------

SCAN_TIMEOUT_ENV = "NOCTORNAL_YARA_SCAN_TIMEOUT_S"
MAX_UPLOAD_ENV = "NOCTORNAL_YARA_MAX_UPLOAD_BYTES"

MIB = 1 << 20
#: The largest canonical source a version may hold.
MAX_SOURCE_BYTES = 64 * MIB
#: The most the parent reads back from a compile child.
MAX_COMPILED_BYTES = 256 * MIB
MAX_ENTRIES = 5000
MAX_ENTRY_BYTES = 8 * MIB
#: Uncompressed to compressed, per entry, above RATIO_FLOOR bytes.
MAX_RATIO = 100
RATIO_FLOOR = 64 * 1024
#: The central directory of 5000 entries with 255-character names is
#: under 1.5 MiB; anything larger is not a rule bundle.
MAX_CENTRAL_DIRECTORY = 4 * MIB
MAX_PATH = 255
#: What a file view returns at most.
FILE_VIEW_BYTES = 1 * MIB

RULE_SUFFIXES = (".yar", ".yara")
_ARCHIVE_SUFFIXES = (".zip", ".gz", ".tgz", ".tar", ".7z", ".rar", ".bz2",
                     ".xz", ".jar", ".apk", ".cab")
_ARCHIVE_MAGIC = (b"PK\x03\x04", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c",
                  b"Rar!\x1a\x07", b"BZh", b"\xfd7zXZ\x00", b"MSCF")

#: A rule set key: lower case, digits and hyphens.
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")

#: The engine's package, as pip names it.
ENGINE_DIST = "yara-x"
#: What the card and the refusals call the optional extra.
EXTRA = "noctornal-api[yara]"


@dataclass(frozen=True)
class YaraSettings:
    scan_timeout_s: int
    max_upload_bytes: int


def yara_settings(env=None) -> tuple[YaraSettings | None, str | None]:
    """The one reader of the YARA settings. `(settings, None)` or `(None,
    problem)`; the problem names the variable and never its value."""
    env = os.environ if env is None else env
    raw = (env.get(SCAN_TIMEOUT_ENV) or "").strip()
    timeout = 60
    if raw:
        if not raw.isdigit() or not 5 <= int(raw) <= 600:
            return None, (f"{SCAN_TIMEOUT_ENV} must be a whole number of "
                          f"seconds from 5 to 600")
        timeout = int(raw)
    raw = (env.get(MAX_UPLOAD_ENV) or "").strip()
    upload = 32 * MIB
    if raw:
        try:
            upload = parse_size(raw)
        except ValueError:
            return None, (f"{MAX_UPLOAD_ENV} is not a size (bytes, or a whole "
                          f"number with a binary K, M or G, such as 32MiB)")
        if not MIB <= upload <= 256 * MIB:
            return None, f"{MAX_UPLOAD_ENV} must be between 1 MiB and 256 MiB"
    return YaraSettings(timeout, upload), None


def upload_cap() -> int:
    """For the route's body cap: the setting, or its default when the
    setting is unusable (the boot refusal and readiness say why)."""
    settings, _problem = yara_settings()
    return settings.max_upload_bytes if settings else 32 * MIB


# ---------------------------------------------------------------------------
# The engine and the build key
# ---------------------------------------------------------------------------

def engine_version() -> str | None:
    """The installed yara-x, read from its metadata: the parent never
    imports the engine (it runs in the child)."""
    try:
        import importlib.metadata
        return importlib.metadata.version(ENGINE_DIST)
    except Exception:  # noqa: BLE001 - absent is an answer
        return None


def engine_id() -> str | None:
    v = engine_version()
    return f"yara-x {v}" if v else None


def host_platform() -> str:
    return f"{sys.platform}-{platform.machine().lower()}"


@dataclass(frozen=True)
class BuildKey:
    """What a compiled build is only valid for."""
    engine: str
    platform: str
    fingerprint: str


def build_key() -> BuildKey | None:
    """This host's key, or None without the engine."""
    from noctornal_api.lab_static import host_fingerprint
    engine = engine_id()
    if engine is None:
        return None
    return BuildKey(engine, host_platform(), host_fingerprint())


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

class BundleError(ValueError):
    """An upload refused before anything was stored, in a sentence."""


@dataclass
class BundleFile:
    path: str
    status: str                  # accepted | ignored
    reason: str | None = None
    sha256: str | None = None
    bytes: int | None = None
    text: str | None = field(default=None, repr=False)

    def meta(self) -> dict:
        return {"path": self.path, "status": self.status,
                "reason": self.reason, "sha256": self.sha256,
                "bytes": self.bytes}


@dataclass
class RuleBundle:
    files: list[BundleFile]

    @property
    def accepted(self) -> list[BundleFile]:
        return sorted((f for f in self.files if f.status == "accepted"),
                      key=lambda f: f.path)

    def canonical(self) -> bytes:
        """The canonical source: JSON of the accepted files sorted by path.
        Order-independent by construction."""
        return canonical_json([(f.path, f.text) for f in self.accepted])

    def pack(self) -> tuple[bytes, list[dict]]:
        """One gzip member per accepted file, in path order (mtime 0, so a
        re-upload packs byte for byte the same), and every file's metadata
        with, for an accepted one, where its member lies."""
        members: list[bytes] = []
        at = 0
        placed: dict[str, tuple[int, int]] = {}
        for f in self.accepted:
            member = gzip.compress(f.text.encode("utf-8"), mtime=0)
            placed[f.path] = (at, len(member))
            members.append(member)
            at += len(member)
        meta = []
        for f in sorted(self.files, key=lambda f: f.path):
            m = f.meta()
            if f.path in placed and f.status == "accepted":
                m["offset"], m["length"] = placed[f.path]
            meta.append(m)
        return b"".join(members), meta


def canonical_json(files: list[tuple[str, str]]) -> bytes:
    body = {"files": [{"path": p, "text": t} for p, t in sorted(files)]}
    return json.dumps(body, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def escaped(name: str) -> str:
    """A path as a reader may be shown it: every control character, bidi
    override and backslash spelt as an escape."""
    return name.encode("unicode_escape").decode("ascii")


def _check_path(raw: str) -> str:
    path = raw.replace("\\", "/")
    shown = escaped(raw)
    if any(ord(ch) < 32 or ord(ch) == 0x7F or 0x202A <= ord(ch) <= 0x202E
           or 0x2066 <= ord(ch) <= 0x2069 or ord(ch) in (0x200B, 0x200C,
                                                         0x200D, 0xFEFF)
           for ch in path):
        raise BundleError(f"the entry {shown} carries a control or invisible "
                          f"character; nothing was stored")
    if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
        raise BundleError(f"the entry {shown} is an absolute path; nothing "
                          f"was stored")
    if any(part == ".." for part in path.split("/")):
        raise BundleError(f"the entry {shown} climbs out of the bundle with "
                          f"'..'; nothing was stored")
    if len(path) > MAX_PATH:
        raise BundleError(f"an entry's path is longer than {MAX_PATH} "
                          f"characters; nothing was stored")
    return path


def _nested(path: str, head: bytes) -> bool:
    return (path.lower().endswith(_ARCHIVE_SUFFIXES)
            or head.startswith(_ARCHIVE_MAGIC))


def _decode(path: str, data: bytes) -> BundleFile:
    digest = hashlib.sha256(data).hexdigest()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return BundleFile(path, "ignored", "not UTF-8 text", digest, len(data))
    if text.startswith("\ufeff"):
        text = text[1:]
    return BundleFile(path, "accepted", None, digest, len(data), text)


#: The longest read zipfile makes while it looks for the end record: the
#: record itself and the largest comment a zip can carry.
_EOCD_SEARCH = 22 + 65535


def _end_record_at(data: bytes) -> int:
    """Where zipfile finds the end of the central directory: at the very
    end when there is no comment, else the last signature in the tail."""
    if (len(data) >= 22 and data[-22:-18] == b"PK\x05\x06"
            and data[-2:] == b"\x00\x00"):
        return len(data) - 22
    return data.rfind(b"PK\x05\x06", max(0, len(data) - _EOCD_SEARCH))


def _zip_preflight(data: bytes) -> None:
    """Refuse on the entry count and the directory size, read from the
    end-of-central-directory record AND from any zip64 record a locator
    points at, BEFORE `zipfile` parses the whole directory into objects.

    CPython's zipfile honours a zip64 locator whenever one sits just
    before the end record, whatever the plain record says; on 2026-09-24
    a 600,000-entry directory hidden behind a plain record claiming one
    entry got past the old preflight (reading zip64 only on
    0xFFFF markers). The larger of the two claims is checked.
    `_DirectoryGuard` then bounds what zipfile actually parses, whatever
    record it trusts."""
    at = _end_record_at(data)
    if at < 0 or at + 22 > len(data):
        raise BundleError("the upload is not a readable zip (no end of "
                          "central directory); nothing was stored")
    (_sig, disk, cd_disk, _here, total, cd_size, cd_offset,
     _comment) = struct.unpack("<4sHHHHIIH", data[at:at + 22])
    loc = at - 20
    if loc >= 0 and data[loc:loc + 4] == b"PK\x06\x07":
        (_s, z_disk, z64_at, disks) = struct.unpack("<4sIQI",
                                                    data[loc:loc + 20])
        if z_disk or disks > 1:
            raise BundleError("multi-part zip archives are refused; nothing "
                              "was stored")
        if z64_at + 56 > len(data) or data[z64_at:z64_at + 4] != b"PK\x06\x06":
            # zipfile also looks just before the locator, for an archive
            # with bytes prepended.
            z64_at = loc - 56
            if z64_at < 0 or data[z64_at:z64_at + 4] != b"PK\x06\x06":
                raise BundleError("the upload's zip64 record is unreadable; "
                                  "nothing was stored")
        (_s, _size, _made, _need, disk64, cd_disk64, _here64, total64,
         cd_size64, cd_offset64) = struct.unpack(
            "<4sQHHIIQQQQ", data[z64_at:z64_at + 56])
        disk, cd_disk = disk or disk64, cd_disk or cd_disk64
        total = max(total, total64)
        cd_size = max(cd_size, cd_size64)
        cd_offset = cd_offset64
    elif 0xFFFF == total or 0xFFFFFFFF in (cd_size, cd_offset):
        raise BundleError("the upload's zip64 record is missing; nothing "
                          "was stored")
    if disk or cd_disk:
        raise BundleError("multi-part zip archives are refused; nothing was "
                          "stored")
    if total > MAX_ENTRIES:
        raise BundleError(f"the upload has {total} entries; a bundle may have "
                          f"at most {MAX_ENTRIES}. Nothing was stored.")
    if cd_size > MAX_CENTRAL_DIRECTORY or cd_offset + cd_size > len(data):
        raise BundleError("the upload's central directory is larger than a "
                          "rule bundle's could be; nothing was stored")


def _count_directory(data: bytes) -> int:
    """The records in a central directory, walked the way zipfile walks it
    (a 46-byte header, then the name, extra field and comment), stopping
    one past MAX_ENTRIES."""
    n = at = 0
    while at + 46 <= len(data) and data[at:at + 4] == b"PK\x01\x02":
        name, extra, comment = struct.unpack("<HHH", data[at + 28:at + 34])
        at += 46 + name + extra + comment
        n += 1
        if n > MAX_ENTRIES:
            break
    return n


class _DirectoryGuard(io.BytesIO):
    """The upload as zipfile reads it. Every read is checked BEFORE zipfile
    parses what it returns: none may be longer than a rule bundle's
    central directory could be, and one that holds a central directory
    has its records counted. So the objects zipfile builds are bounded by
    what it is actually handed, whichever end record it chose to trust
    and whatever count that record claimed (on 2026-09-24 a plain record
    understating the count by ~90,000 entries was still parsed in full
    under the old directory-size cap alone)."""

    def read(self, n: int | None = -1) -> bytes:
        if n is None or n < 0:
            n = self._size - self.tell()
        if n > MAX_CENTRAL_DIRECTORY:
            raise BundleError("the upload's central directory is larger than "
                              "a rule bundle's could be; nothing was stored")
        chunk = super().read(n)
        if (chunk[:4] == b"PK\x01\x02"
                and _count_directory(chunk) > MAX_ENTRIES):
            raise BundleError(f"the upload has more than {MAX_ENTRIES} "
                              f"entries; nothing was stored")
        return chunk

    def __init__(self, data: bytes):
        super().__init__(data)
        self._size = len(data)


def _read_bounded(zf: zipfile.ZipFile, info: zipfile.ZipInfo,
                  shown: str) -> bytes:
    """An entry's bytes, never more than MAX_ENTRY_BYTES whatever its
    header says, refused past the ratio cap."""
    parts: list[bytes] = []
    total = 0
    try:
        with zf.open(info) as f:
            while True:
                chunk = f.read(min(1 << 16, MAX_ENTRY_BYTES + 1 - total))
                if not chunk:
                    break
                parts.append(chunk)
                total += len(chunk)
                if total > MAX_ENTRY_BYTES:
                    raise BundleError(
                        f"the entry {shown} is larger than "
                        f"{MAX_ENTRY_BYTES // MIB} MiB uncompressed; nothing "
                        f"was stored")
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError,
            RuntimeError) as exc:
        raise BundleError(f"the entry {shown} could not be read "
                          f"({type(exc).__name__}); nothing was stored") from None
    if total > RATIO_FLOOR and total > MAX_RATIO * max(info.compress_size, 1):
        raise BundleError(f"the entry {shown} expands more than {MAX_RATIO} "
                          f"times; a rule file does not. Nothing was stored.")
    return b"".join(parts)


def parse_bundle(filename: str | None, data: bytes) -> RuleBundle:
    """A .yar/.yara file or a .zip of them, as a bundle, or a BundleError.
    Standard library only, in the API process, under the caps above."""
    name = (filename or "").strip()
    if not data:
        raise BundleError("the upload is empty; nothing was stored")
    is_zip = data.startswith((b"PK\x03\x04", b"PK\x05\x06"))
    if not is_zip:
        if not name.lower().endswith(RULE_SUFFIXES):
            raise BundleError("upload one .yar or .yara file, or a .zip of "
                              "them; nothing was stored")
        if len(data) > MAX_ENTRY_BYTES:
            raise BundleError(f"a rule file may be at most "
                              f"{MAX_ENTRY_BYTES // MIB} MiB; nothing was "
                              f"stored")
        path = _check_path(os.path.basename(name.replace("\\", "/")) or name)
        if data.startswith(_ARCHIVE_MAGIC):
            raise BundleError("the file is an archive named as a rule file; "
                              "nothing was stored")
        bundle = RuleBundle([_decode(path, data)])
    else:
        _zip_preflight(data)
        try:
            zf = zipfile.ZipFile(_DirectoryGuard(data))
            infos = zf.infolist()
        except BundleError:
            raise
        except (zipfile.BadZipFile, zlib.error, EOFError, ValueError,
                struct.error, OSError) as exc:
            raise BundleError(f"the upload is not a readable zip "
                              f"({type(exc).__name__}); nothing was stored") from None
        if len(infos) > MAX_ENTRIES:
            raise BundleError(f"the upload has {len(infos)} entries; a bundle "
                              f"may have at most {MAX_ENTRIES}. Nothing was "
                              f"stored.")
        files: list[BundleFile] = []
        seen: dict[str, str] = {}
        total = 0
        for info in infos:
            if info.is_dir():
                continue
            path = _check_path(info.filename)
            shown = escaped(info.filename)
            folded = path.casefold()
            if folded in seen:
                raise BundleError(f"the entries {escaped(seen[folded])} and "
                                  f"{shown} differ only by case; nothing was "
                                  f"stored")
            seen[folded] = info.filename
            if info.flag_bits & 0x1:
                raise BundleError(f"the entry {shown} is encrypted; nothing "
                                  f"was stored")
            if path.lower().endswith(_ARCHIVE_SUFFIXES):
                raise BundleError(f"the entry {shown} is itself an archive; "
                                  f"nested archives are refused and nothing "
                                  f"was stored")
            if not path.lower().endswith(RULE_SUFFIXES):
                files.append(BundleFile(path, "ignored",
                                        "not a .yar or .yara file"))
                continue
            content = _read_bounded(zf, info, shown)
            if _nested(path, content[:8]):
                raise BundleError(f"the entry {shown} is an archive named as a "
                                  f"rule file; nothing was stored")
            total += len(content)
            if total > MAX_SOURCE_BYTES:
                raise BundleError(f"the rule files add up to more than "
                                  f"{MAX_SOURCE_BYTES // MIB} MiB; nothing was "
                                  f"stored")
            files.append(_decode(path, content))
        bundle = RuleBundle(files)
    if not bundle.accepted:
        raise BundleError("the upload holds no .yar or .yara file that reads "
                          "as UTF-8 text; nothing was stored")
    if len(bundle.canonical()) > MAX_SOURCE_BYTES:
        raise BundleError(f"the rule source is larger than "
                          f"{MAX_SOURCE_BYTES // MIB} MiB; nothing was stored")
    return bundle


def member_text(source_gz: bytes, meta: dict, *,
                limit: int = FILE_VIEW_BYTES) -> tuple[str, bool]:
    """One stored file's text, decompressed on its own and bounded:
    `(text, truncated)`."""
    start, length = int(meta["offset"]), int(meta["length"])
    member = bytes(source_gz[start:start + length])
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(member, limit + 1)
    truncated = len(out) > limit
    return out[:limit].decode("utf-8", "replace"), truncated


def stored_canonical(source_gz: bytes, files: list[dict]) -> bytes:
    """The canonical source rebuilt from the stored members, for a compile:
    every accepted file in full."""
    pairs = []
    for meta in files:
        if meta.get("status") != "accepted":
            continue
        text, truncated = member_text(source_gz, meta, limit=MAX_ENTRY_BYTES)
        if truncated:
            raise ValueError("a stored member is larger than a rule file may be")
        pairs.append((meta["path"], text))
    return canonical_json(pairs)


# ---------------------------------------------------------------------------
# The build MAC
# ---------------------------------------------------------------------------

_MAC_LABEL = b"noctornal yara-compiled v1"


def _mac_key(key_id: str) -> bytes | None:
    raw = envelope.ring().get(key_id)
    if raw is None:
        return None
    return hmac.new(raw, _MAC_LABEL, hashlib.sha256).digest()


def _mac_message(version_id, key: BuildKey, blob_sha256: bytes) -> bytes:
    return b"|".join([str(version_id).encode(), key.engine.encode(),
                      key.platform.encode(), key.fingerprint.encode(),
                      bytes(blob_sha256)])


def seal_build(version_id, key: BuildKey, blob: bytes
               ) -> tuple[bytes, str, bytes]:
    """`(blob_sha256, mac_key_id, mac)` for a build this process made,
    under the ring's ACTIVE key."""
    digest = hashlib.sha256(blob).digest()
    key_id = envelope.active_key_id()
    mac = hmac.new(_mac_key(key_id), _mac_message(version_id, key, digest),
                   hashlib.sha256).digest()
    return digest, key_id, mac


def verify_build(version_id, key: BuildKey, blob: bytes, blob_sha256: bytes,
                 key_id: str, mac: bytes) -> bool | None:
    """True when the blob is what a process holding the KEK built for this
    version and key; False on any mismatch; None when the ring no longer
    holds the key it was sealed under (a retired key dropped: recompile,
    nothing to alarm about)."""
    sealed = verify_seal(version_id, key, blob_sha256, key_id, mac)
    if sealed is not True:
        return sealed
    return hashlib.sha256(blob).digest() == bytes(blob_sha256)


def verify_seal(version_id, key: BuildKey, blob_sha256: bytes, key_id: str,
                mac: bytes) -> bool | None:
    """The MAC over a build's recorded digest, without reading its blob:
    what a listing may afford on every request. It proves the row was
    sealed by a process holding the KEK; `verify_build` also proves the
    blob is the one sealed, and only a build that passes that reaches a
    child. None when the ring no longer holds the key."""
    k = _mac_key(key_id)
    if k is None:
        return None
    want = hmac.new(k, _mac_message(version_id, key, bytes(blob_sha256)),
                    hashlib.sha256).digest()
    return hmac.compare_digest(want, bytes(mac))


# ---------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------

class RulesetError(Exception):
    """A refusal, with the status the router answers."""

    status = 409

    def __init__(self, message: str, *, code: str = "refused"):
        super().__init__(message)
        self.code = code


class RulesetNotFound(RulesetError):
    status = 404


class RulesetInvalid(RulesetError):
    status = 400


def ruleset_gate(r: str = "r") -> str:
    """The set's labels against the reader's, compartments beside
    classification (docs/05, Binding a compartment column, rule 7)."""
    return (f"{r}.classification <= %(rs_clearance)s::core.tlp "
            f"AND {r}.compartments <@ %(rs_compartments)s::text[]")


def ruleset_params(clearance: str | None, compartments) -> dict:
    if clearance is None:
        raise RulesetError("a rule set read needs the reader's clearance")
    return {"rs_clearance": clearance,
            "rs_compartments": sorted(compartments or ())}


def _audit(conn, action: str, *, ruleset_id, actor_id, detail: dict,
           outcome: str = "SUCCESS") -> None:
    conn.execute(
        """INSERT INTO audit.event (actor_id, actor_kind, action, object_type,
                                    object_id, outcome, detail)
           VALUES (%s, %s, %s, 'yara_ruleset', %s, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, ruleset_id,
         outcome, Json(detail)))


#: A version's metadata row, as `_version_out` reads it. Never the source.
_VERSION_ROW_SQL = """SELECT v.id, v.version, v.file_count, v.licence,
                          v.licence_review_required, v.provenance, v.note,
                          v.uploaded_at, v.adopted_at,
                          up.display_name, up.email, ad.display_name, ad.email,
                          v.files, v.source_bytes
                     FROM lab.yara_ruleset_version v
                     LEFT JOIN iam.app_user up ON up.id = v.uploaded_by
                     LEFT JOIN iam.app_user ad ON ad.id = v.adopted_by"""


class RulesetService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- reads ---------------------------------------------------------------

    def visible_ruleset(self, ruleset_id: UUID, *, clearance: str,
                        compartments) -> dict | None:
        row = self._c.execute(
            f"""SELECT r.id, r.key, r.display_name, r.classification,
                       r.compartments
                  FROM lab.yara_ruleset r
                 WHERE r.id = %(id)s AND {ruleset_gate()}""",
            {"id": ruleset_id, **ruleset_params(clearance, compartments)}
        ).fetchone()
        if row is None:
            return None
        return {"id": str(row[0]), "key": row[1], "display_name": row[2],
                "classification": row[3], "compartments": sorted(row[4] or [])}

    def visible_version(self, version_id: UUID, *, clearance: str,
                        compartments) -> dict | None:
        row = self._c.execute(
            f"""SELECT v.id, v.ruleset_id, v.version, r.key, v.uploaded_by,
                       v.adopted_by, v.licence, v.licence_review_required,
                       v.files, r.classification, r.compartments,
                       r.display_name
                  FROM lab.yara_ruleset_version v
                  JOIN lab.yara_ruleset r ON r.id = v.ruleset_id
                 WHERE v.id = %(id)s AND {ruleset_gate()}""",
            {"id": version_id, **ruleset_params(clearance, compartments)}
        ).fetchone()
        if row is None:
            return None
        return {"id": str(row[0]), "ruleset_id": str(row[1]),
                "version": row[2], "key": row[3],
                "uploaded_by": str(row[4]) if row[4] else None,
                "adopted_by": str(row[5]) if row[5] else None,
                "licence": row[6], "licence_review_required": row[7],
                "files": row[8], "classification": row[9],
                "compartments": sorted(row[10] or []),
                "display_name": row[11]}

    def open_activation(self, ruleset_id) -> dict | None:
        row = self._c.execute(
            """SELECT a.id, a.version_id, v.version, a.activated_by,
                      a.activated_at, u.display_name, u.email
                 FROM lab.yara_activation a
                 JOIN lab.yara_ruleset_version v ON v.id = a.version_id
                 LEFT JOIN iam.app_user u ON u.id = a.activated_by
                WHERE a.ruleset_id = %s AND a.deactivated_at IS NULL""",
            (ruleset_id,)).fetchone()
        if row is None:
            return None
        return {"id": str(row[0]), "version_id": str(row[1]),
                "version": row[2], "activated_by": str(row[3]),
                "activated_at": row[4].isoformat(),
                "activated_by_name": row[5], "activated_by_email": row[6]}

    def build_status(self, version_id, key: BuildKey | None) -> dict:
        """The newest build of this version for this host, as a listing
        shows it: `{status, rule_count, warning_count, report,
        compiled_at}`, or `{status: 'compiling' | 'compile_failed' |
        'rebuild_needed' | 'engine_absent'}`.

        READ ONLY AND CHEAP, because every listing, version view and the
        officer's pending list calls it for every version on every request
        (until 2026-09-24 each call loaded and hashed the whole compiled
        blob, up to 256 MiB, and could write rejections and compile jobs
        from a GET). It never reads the blob: it checks the
        MAC over the recorded digest, and a build whose seal does not
        verify is shown as needing a rebuild, which happens when the
        version is next activated or scans (`usable_build`, which writers
        call, rejects it and queues the compile)."""
        if key is None:
            return {"status": "engine_absent"}
        row = self._c.execute(
            """SELECT c.id, c.status, c.rule_count, c.warning_count,
                      c.report, c.blob_sha256, c.mac_key_id, c.mac,
                      c.compiled_at
                 FROM lab.yara_compiled c
                WHERE c.version_id = %s AND c.engine = %s AND c.platform = %s
                  AND c.fingerprint = %s
                  AND NOT EXISTS (SELECT 1 FROM lab.yara_compiled_rejected x
                                   WHERE x.compiled_id = c.id)
                ORDER BY c.compiled_at DESC, c.id DESC LIMIT 1""",
            (version_id, key.engine, key.platform, key.fingerprint)).fetchone()
        found = None
        if row is not None:
            (cid, status, rules, warnings, report, digest, key_id, mac,
             at) = row
            found = {"id": str(cid), "status": status, "rule_count": rules,
                     "warning_count": warnings, "report": report,
                     "compiled_at": at.isoformat()}
            if status != "FAILED" and verify_seal(
                    version_id, key, bytes(digest), key_id,
                    bytes(mac)) is not True:
                return {"status": "rebuild_needed"}
        if found is None:
            job = self._c.execute(
                """SELECT status, attempts FROM lab.yara_compile_job
                    WHERE version_id = %s AND engine = %s AND platform = %s
                      AND fingerprint = %s""",
                (version_id, key.engine, key.platform, key.fingerprint)
            ).fetchone()
            if job and job[0] == "FAILED":
                return {"status": "compile_failed", "attempts": job[1]}
            return {"status": "compiling"}
        return found

    def usable_build(self, version_id, key: BuildKey, *,
                     with_blob: bool = True) -> dict | None:
        """The newest build of this version for this key that has not been
        rejected: FAILED as recorded, or a COMPILED/PARTIAL one whose MAC
        verifies. A MAC mismatch under a key the ring still holds is
        rejected, audited and queued for a recompile, and the next older
        build is not used either (it was superseded); an unknown key
        queues a recompile without an alarm."""
        rows = self._c.execute(
            """SELECT c.id, c.status, c.rule_count, c.warning_count, c.report,
                      c.compiled, c.blob_sha256, c.mac_key_id, c.mac,
                      c.compiled_at
                 FROM lab.yara_compiled c
                WHERE c.version_id = %s AND c.engine = %s AND c.platform = %s
                  AND c.fingerprint = %s
                  AND NOT EXISTS (SELECT 1 FROM lab.yara_compiled_rejected x
                                   WHERE x.compiled_id = c.id)
                ORDER BY c.compiled_at DESC, c.id DESC LIMIT 1""",
            (version_id, key.engine, key.platform, key.fingerprint)).fetchone()
        if rows is None:
            return None
        (cid, status, rules, warnings, report, blob, digest, key_id, mac,
         at) = rows
        out = {"id": str(cid), "status": status, "rule_count": rules,
               "warning_count": warnings, "report": report,
               "compiled_at": at.isoformat()}
        if status == "FAILED":
            return out
        verdict = verify_build(version_id, key, bytes(blob), bytes(digest),
                               key_id, bytes(mac))
        if verdict is None:
            self.queue_compile(version_id, key)
            return None
        if not verdict:
            self.reject_build(cid, version_id, "mac_mismatch")
            return None
        if with_blob:
            out["blob"] = bytes(blob)
        return out

    def reject_build(self, compiled_id, version_id, reason: str) -> None:
        """Record that a build must not be used, queue a recompile, and
        say so in the audit chain when it was a MAC mismatch."""
        with self._c.transaction():
            self._c.execute(
                "INSERT INTO lab.yara_compiled_rejected (compiled_id, reason) "
                "VALUES (%s, %s) ON CONFLICT (compiled_id) DO NOTHING",
                (compiled_id, reason))
            row = self._c.execute(
                """SELECT c.engine, c.platform, c.fingerprint, v.ruleset_id,
                          v.version
                     FROM lab.yara_compiled c
                     JOIN lab.yara_ruleset_version v ON v.id = c.version_id
                    WHERE c.id = %s""", (compiled_id,)).fetchone()
            self._queue(version_id, BuildKey(row[0], row[1], row[2]))
            if reason == "mac_mismatch":
                _audit(self._c, "YARA_COMPILED_REJECTED", ruleset_id=row[3],
                       actor_id=None, outcome="DENIED",
                       detail={"version": row[4], "compiled_id": str(compiled_id),
                               "engine": row[0], "platform": row[1],
                               "reason": reason})

    def queue_compile(self, version_id, key: BuildKey) -> None:
        with self._c.transaction():
            self._queue(version_id, key)

    def _queue(self, version_id, key: BuildKey) -> None:
        self._c.execute(
            """INSERT INTO lab.yara_compile_job
                   (version_id, engine, platform, fingerprint)
               VALUES (%s, %s, %s, %s)
               ON CONFLICT (version_id, engine, platform, fingerprint)
               DO UPDATE SET status = CASE WHEN lab.yara_compile_job.status
                                               = 'RUNNING'
                                          THEN 'RUNNING' ELSE 'QUEUED' END,
                             attempts = CASE WHEN lab.yara_compile_job.status
                                                 = 'FAILED'
                                            THEN 0
                                            ELSE lab.yara_compile_job.attempts
                                       END,
                             updated_at = now()""",
            (version_id, key.engine, key.platform, key.fingerprint))

    def listing(self, *, clearance: str, compartments,
                key: BuildKey | None) -> list[dict]:
        """Every set the reader may see, with its versions' metadata (never
        source), this host's build status, the open activation, licence
        and provenance."""
        sets = self._c.execute(
            f"""SELECT r.id, r.key, r.display_name, r.description,
                       r.classification, r.compartments, r.created_via,
                       r.created_at, u.display_name, u.email
                  FROM lab.yara_ruleset r
                  LEFT JOIN iam.app_user u ON u.id = r.created_by
                 WHERE {ruleset_gate()}
                 ORDER BY r.display_name, r.key""",
            ruleset_params(clearance, compartments)).fetchall()
        out = []
        for s in sets:
            versions = self._c.execute(
                _VERSION_ROW_SQL + " WHERE v.ruleset_id = %s "
                "ORDER BY v.version DESC", (s[0],)).fetchall()
            out.append({
                "id": str(s[0]), "key": s[1], "display_name": s[2],
                "description": s[3], "classification": s[4],
                "compartments": sorted(s[5] or []), "created_via": s[6],
                "created_at": s[7].isoformat(), "created_by_name": s[8],
                "created_by_email": s[9],
                "open": self.open_activation(s[0]),
                "versions": [self._version_out(v, key) for v in versions]})
        return out

    def version_out(self, version_id: UUID, key: BuildKey | None) -> dict | None:
        """One version as the listing shows it, and its set's open
        activation, without building the whole listing (the version view
        used to). The caller has already checked the set's labels."""
        v = self._c.execute(_VERSION_ROW_SQL + " WHERE v.id = %s",
                            (version_id,)).fetchone()
        if v is None:
            return None
        ruleset_id = self._c.execute(
            "SELECT ruleset_id FROM lab.yara_ruleset_version WHERE id = %s",
            (version_id,)).fetchone()[0]
        return {**self._version_out(v, key),
                "open": self.open_activation(ruleset_id)}

    def _version_out(self, v, key: BuildKey | None) -> dict:
        files = v[13] or []
        prov = dict(v[5] or {})
        return {"id": str(v[0]), "version": v[1], "file_count": v[2],
                "licence": v[3], "licence_review_required": v[4],
                "provenance": prov, "note": v[6],
                "uploaded_at": v[7].isoformat(),
                "adopted_at": v[8].isoformat() if v[8] else None,
                "uploaded_by_name": v[9], "uploaded_by_email": v[10],
                "adopted_by_name": v[11], "adopted_by_email": v[12],
                "imported": prov.get("via") == "yara_db.py",
                "needs_adoption": prov.get("via") == "yara_db.py" and not v[8],
                "files": [{"index": i, "path": f.get("path"),
                           "status": f.get("status"), "reason": f.get("reason"),
                           "bytes": f.get("bytes")}
                          for i, f in enumerate(files)],
                "source_bytes": v[14],
                "build": self.build_status(v[0], key)}

    # -- writes --------------------------------------------------------------

    def create(self, *, key: str, display_name: str, description: str | None,
               classification: str, compartments, actor_id: UUID | None,
               via: str = "console", host_user: str | None = None) -> dict:
        """A new, empty set. Its key is unique among the sets carrying the
        same labels only (migration 0080's index): the caller may read every
        set at the labels it writes, so the refusal below never confirms a
        set it cannot see (until 2026-09-24 a 409 named a RED set's key to
        an AMBER caller). A script's creation records the
        host user, as its version's does."""
        key = (key or "").strip()
        if not KEY_RE.match(key):
            raise RulesetInvalid(
                "a rule set key is 2 to 63 characters of lower-case letters, "
                "digits and hyphens, starting with a letter or digit")
        if not (display_name or "").strip():
            raise RulesetInvalid("a rule set needs a name")
        try:
            tlp_from_name(classification)
        except AccessResolutionError as exc:
            raise RulesetInvalid(str(exc)) from exc
        try:
            with self._c.transaction():
                row = self._c.execute(
                    """INSERT INTO lab.yara_ruleset
                           (key, display_name, description, classification,
                            compartments, created_by, created_via)
                       VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                    (key, display_name.strip(), (description or "").strip()
                     or None, classification, sorted(compartments or ()),
                     actor_id, via)).fetchone()
                detail = {"key": key, "classification": classification,
                          "compartments": sorted(compartments or ()),
                          "via": via}
                if host_user:
                    detail["host_user"] = host_user
                _audit(self._c, "YARA_RULESET_CREATED", ruleset_id=row[0],
                       actor_id=actor_id, detail=detail)
        except psycopg.errors.UniqueViolation:
            raise RulesetError(f"a rule set with the key {key} exists already "
                               f"at these labels") from None
        except psycopg.errors.RaiseException as exc:
            raise RulesetInvalid(str(exc).splitlines()[0]) from None
        return {"id": str(row[0]), "key": key}

    def add_version(self, ruleset_id: UUID, bundle: RuleBundle, *,
                    licence: str, licence_review_required: bool,
                    provenance: dict, note: str | None,
                    uploaded_by: UUID | None, host_user: str | None = None,
                    key: BuildKey | None = None) -> dict:
        """Store one immutable version, numbered under a lock on its set,
        refused when an identical bundle is already a version of it, and
        queue its compile for this host (never compiled inline)."""
        if not (licence or "").strip():
            raise RulesetInvalid("a version needs its licence, as the source "
                                 "states it")
        canonical = bundle.canonical()
        digest = hashlib.sha256(canonical).digest()
        source_gz, files = bundle.pack()
        via = provenance.get("via") or "upload"
        if uploaded_by is None and via != "yara_db.py":
            raise RulesetInvalid("a version names the person who uploaded it")
        with self._c.transaction():
            head = self._c.execute(
                "SELECT key FROM lab.yara_ruleset WHERE id = %s FOR UPDATE",
                (ruleset_id,)).fetchone()
            if head is None:
                raise RulesetNotFound("no such rule set")
            twin = self._c.execute(
                "SELECT version FROM lab.yara_ruleset_version "
                "WHERE ruleset_id = %s AND source_sha256 = %s",
                (ruleset_id, digest)).fetchone()
            if twin is not None:
                raise RulesetError(
                    f"this bundle is identical to version {twin[0]} of "
                    f"{head[0]}; nothing was stored", code="duplicate")
            number = self._c.execute(
                "SELECT coalesce(max(version), 0) + 1 FROM "
                "lab.yara_ruleset_version WHERE ruleset_id = %s",
                (ruleset_id,)).fetchone()[0]
            row = self._c.execute(
                """INSERT INTO lab.yara_ruleset_version
                       (ruleset_id, version, source_sha256, source_gz,
                        source_bytes, files, file_count, licence,
                        licence_review_required, provenance, note,
                        uploaded_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (ruleset_id, number, digest, source_gz, len(canonical),
                 Json(files), len(bundle.accepted), licence.strip(),
                 bool(licence_review_required), Json(provenance),
                 (note or "").strip() or None, uploaded_by)).fetchone()
            if key is not None:
                self._queue(row[0], key)
            detail = {"version": number, "source_sha256": digest.hex(),
                      "file_count": len(bundle.accepted),
                      "ignored": sum(1 for f in bundle.files
                                     if f.status == "ignored"),
                      "licence": licence.strip(),
                      "review": bool(licence_review_required), "via": via}
            if host_user:
                detail["host_user"] = host_user
            _audit(self._c, "YARA_RULESET_VERSION_ADDED",
                   ruleset_id=ruleset_id, actor_id=uploaded_by, detail=detail)
        return {"id": str(row[0]), "version": number,
                "files": [{"path": f["path"], "status": f["status"],
                           "reason": f["reason"]} for f in files],
                "compile": "queued" if key is not None else "engine_absent"}

    def adopt(self, version_id: UUID, *, actor_id: UUID) -> dict:
        with self._c.transaction():
            row = self._c.execute(
                """UPDATE lab.yara_ruleset_version
                      SET adopted_by = %s, adopted_at = now()
                    WHERE id = %s AND uploaded_by IS NULL AND adopted_by IS NULL
                RETURNING ruleset_id, version""",
                (actor_id, version_id)).fetchone()
            if row is None:
                raise RulesetError(
                    "only a version imported by scripts/yara_db.py, and not "
                    "yet adopted, can be adopted")
            _audit(self._c, "YARA_RULESET_VERSION_ADOPTED", ruleset_id=row[0],
                   actor_id=actor_id, detail={"version": row[1]})
        return {"version": row[1], "adopted": True}

    def activate(self, version_id: UUID, *, actor_id: UUID,
                 licence_acknowledgement: str | None, replace_open: bool,
                 key: BuildKey | None) -> dict:
        """Activate a version somebody else sponsored. Each refusal is a
        sentence, is audited, and changes nothing."""
        ack = (licence_acknowledgement or "").strip() or None
        v = self._c.execute(
            """SELECT v.ruleset_id, v.version, v.uploaded_by, v.adopted_by,
                      v.licence_review_required, v.provenance->>'via'
                 FROM lab.yara_ruleset_version v WHERE v.id = %s""",
            (version_id,)).fetchone()
        if v is None:
            raise RulesetNotFound("no such version")
        ruleset_id, number, uploader, adopter, review, via = v

        def refuse(code: str, message: str, cls=RulesetError):
            _audit(self._c, "YARA_RULESET_ACTIVATION_REFUSED",
                   ruleset_id=ruleset_id, actor_id=actor_id, outcome="DENIED",
                   detail={"version": number, "reason": code})
            raise cls(message, code=code)

        if key is None:
            refuse("engine_absent",
                   f"the YARA engine (yara-x) is not installed in this "
                   f"deployment: install {EXTRA}")
        if uploader is None and adopter is None:
            refuse("not_adopted",
                   "this version was imported by scripts/yara_db.py and no lab "
                   "member has adopted it yet; a lab member must adopt it in "
                   "the Lab's Rules tab first")
        if actor_id in (uploader, adopter):
            refuse("self_sponsored",
                   "You uploaded or adopted this version; somebody else has "
                   "to activate it.")
        if review and (not ack or len(ack) <= 20):
            refuse("acknowledgement_missing",
                   "this version's licence is flagged for review: write down "
                   "the clearance (more than 20 characters) before activating "
                   "it", RulesetInvalid)
        build = self.usable_build(version_id, key, with_blob=False)
        if build is None or build["status"] == "FAILED":
            if build is None:
                self.queue_compile(version_id, key)
                refuse("not_compiled",
                       "this version is still compiling for this engine; try "
                       "again after the next static triage pass")
            refuse("compile_failed",
                   "no rule in this version compiled for this engine, so "
                   "activating it would scan with nothing; upload a version "
                   "that compiles")
        open_now = self.open_activation(ruleset_id)
        replaced = None
        try:
            with self._c.transaction():
                if open_now is not None:
                    if open_now["version_id"] == str(version_id):
                        raise RulesetError(
                            f"version {number} is already the active one",
                            code="already_active")
                    if not replace_open:
                        raise RulesetError(
                            f"version {open_now['version']} of this set is "
                            f"active; deactivate it, or activate this one in "
                            f"its place", code="another_open")
                    self._c.execute(
                        """UPDATE lab.yara_activation
                              SET deactivated_by = %s, deactivated_at = now(),
                                  deactivation_reason = %s
                            WHERE id = %s AND deactivated_at IS NULL""",
                        (actor_id, f"replaced by version {number}",
                         open_now["id"]))
                    replaced = open_now["version"]
                row = self._c.execute(
                    """INSERT INTO lab.yara_activation
                           (ruleset_id, version_id, activated_by,
                            licence_acknowledgement)
                       VALUES (%s, %s, %s, %s) RETURNING id""",
                    # A note on a version that needs no review is kept when
                    # it says something, and dropped when it is too short
                    # to be a clearance (the CHECK's floor).
                    (ruleset_id, version_id, actor_id,
                     ack if ack and len(ack) > 20 else None)).fetchone()
                _audit(self._c, "YARA_RULESET_ACTIVATED",
                       ruleset_id=ruleset_id, actor_id=actor_id,
                       detail={"activation_id": str(row[0]), "version": number,
                               "licence_acknowledgement": ack,
                               "replaced": replaced, "via": via or "upload"})
        except RulesetError as exc:
            _audit(self._c, "YARA_RULESET_ACTIVATION_REFUSED",
                   ruleset_id=ruleset_id, actor_id=actor_id, outcome="DENIED",
                   detail={"version": number, "reason": exc.code})
            raise
        except psycopg.errors.RaiseException as exc:
            # The activation trigger: the same rules, as the database holds
            # them, for a writer that is not this service.
            raise RulesetError(str(exc).splitlines()[0]) from None
        return {"activation_id": str(row[0]), "version": number,
                "replaced": replaced}

    def deactivate(self, version_id: UUID, *, actor_id: UUID,
                   reason: str) -> dict:
        reason = (reason or "").strip()
        if len(reason) < 10:
            raise RulesetInvalid("say why the rule set is being switched off "
                                 "(at least 10 characters)")
        with self._c.transaction():
            row = self._c.execute(
                """UPDATE lab.yara_activation a
                      SET deactivated_by = %s, deactivated_at = now(),
                          deactivation_reason = %s
                    WHERE a.version_id = %s AND a.deactivated_at IS NULL
                RETURNING a.id, a.ruleset_id""",
                (actor_id, reason, version_id)).fetchone()
            if row is None:
                raise RulesetError("that version is not the active one")
            number = self._c.execute(
                "SELECT version FROM lab.yara_ruleset_version WHERE id = %s",
                (version_id,)).fetchone()[0]
            _audit(self._c, "YARA_RULESET_DEACTIVATED", ruleset_id=row[1],
                   actor_id=actor_id,
                   detail={"activation_id": str(row[0]), "version": number,
                           "reason": reason})
        return {"deactivated": True, "version": number}

    def pending(self, *, clearance: str, compartments,
                key: BuildKey | None) -> dict:
        """The officer's list: versions that are not active, and the open
        activations, metadata only, filtered by the officer's ceiling."""
        rows = self._c.execute(
            f"""SELECT v.id, v.version, r.id, r.key, r.display_name,
                       r.classification, r.compartments, v.licence,
                       v.licence_review_required, v.uploaded_at,
                       coalesce(up.display_name, ad.display_name),
                       coalesce(up.email, ad.email),
                       v.uploaded_by IS NULL AND v.adopted_by IS NULL,
                       v.uploaded_by, v.adopted_by, v.file_count
                  FROM lab.yara_ruleset_version v
                  JOIN lab.yara_ruleset r ON r.id = v.ruleset_id
                  LEFT JOIN iam.app_user up ON up.id = v.uploaded_by
                  LEFT JOIN iam.app_user ad ON ad.id = v.adopted_by
                 WHERE {ruleset_gate()}
                   AND NOT EXISTS (SELECT 1 FROM lab.yara_activation a
                                    WHERE a.version_id = v.id
                                      AND a.deactivated_at IS NULL)
                   AND NOT EXISTS (SELECT 1 FROM lab.yara_ruleset_version n
                                    WHERE n.ruleset_id = v.ruleset_id
                                      AND n.version > v.version)
                 ORDER BY v.uploaded_at DESC""",
            ruleset_params(clearance, compartments)).fetchall()
        waiting = [{
            "version_id": str(r[0]), "version": r[1], "ruleset_id": str(r[2]),
            "key": r[3], "display_name": r[4], "classification": r[5],
            "compartments": sorted(r[6] or []), "licence": r[7],
            "licence_review_required": r[8], "uploaded_at": r[9].isoformat(),
            "sponsor_name": r[10], "sponsor_email": r[11],
            "needs_adoption": r[12],
            "sponsor_id": str(r[13] or r[14]) if (r[13] or r[14]) else None,
            "file_count": r[15], "build": self.build_status(r[0], key)}
            for r in rows]
        opened = self._c.execute(
            f"""SELECT a.id, v.id, v.version, r.id, r.key, r.display_name,
                       r.classification, r.compartments, a.activated_at,
                       u.display_name, u.email
                  FROM lab.yara_activation a
                  JOIN lab.yara_ruleset_version v ON v.id = a.version_id
                  JOIN lab.yara_ruleset r ON r.id = a.ruleset_id
                  LEFT JOIN iam.app_user u ON u.id = a.activated_by
                 WHERE a.deactivated_at IS NULL AND {ruleset_gate()}
                 ORDER BY a.activated_at DESC""",
            ruleset_params(clearance, compartments)).fetchall()
        active = [{"activation_id": str(r[0]), "version_id": str(r[1]),
                   "version": r[2], "ruleset_id": str(r[3]), "key": r[4],
                   "display_name": r[5], "classification": r[6],
                   "compartments": sorted(r[7] or []),
                   "activated_at": r[8].isoformat(),
                   "activated_by_name": r[9], "activated_by_email": r[10]}
                  for r in opened]
        return {"waiting": waiting, "active": active}

    def file_text(self, version_id: UUID, index: int) -> dict:
        row = self._c.execute(
            "SELECT source_gz, files FROM lab.yara_ruleset_version "
            "WHERE id = %s", (version_id,)).fetchone()
        if row is None:
            raise RulesetNotFound("no such version")
        files = row[1] or []
        if not 0 <= index < len(files):
            raise RulesetNotFound("that version has no file at that position")
        meta = files[index]
        if meta.get("status") != "accepted":
            return {"path": meta.get("path"), "text": None, "truncated": False,
                    "reason": meta.get("reason")}
        text, truncated = member_text(bytes(row[0]), meta)
        return {"path": meta.get("path"), "text": text,
                "truncated": truncated}


__all__ = [
    "BuildKey", "BundleError", "EXTRA", "MAX_COMPILED_BYTES",
    "MAX_SOURCE_BYTES", "RuleBundle", "RulesetError", "RulesetInvalid",
    "RulesetNotFound", "RulesetService", "YaraSettings", "build_key",
    "canonical_json", "engine_id", "engine_version", "member_text",
    "parse_bundle", "ruleset_gate", "ruleset_params", "seal_build",
    "stored_canonical", "upload_cap", "verify_build", "verify_seal",
    "yara_settings",
]
