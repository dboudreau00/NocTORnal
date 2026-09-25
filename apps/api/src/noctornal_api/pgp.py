"""Phase 7 -- PGP signature verification (docs/10).

docs/10, on why this is worth building at all:

    PGP signed messages are the strong case. A message signed by a key
    whose fingerprint appears in the contact block is real cryptographic
    evidence of control, not a claim. Verify signatures where you can and
    record the verification as its own assertion.

Everything else in Phase 7 produces CLAIMS. This is the one path that
produces a CONFIRMATION, which is why it is also the one place where
getting it wrong is worst: a CONFIRMED binding is what docs/10 says may
carry weight in automatic identity resolution.

## No cryptography is implemented here

Verification is delegated to the `gpg` binary. This module parses its
machine-readable `--status-fd` output and nothing else -- never the
human-readable text, which is localised, reformatted between versions,
and has historically been spoofable by crafted user IDs.

The packet walker below (`_pgp_packets`, F10a, 2026-09-24) reads OpenPGP
FRAMING before gpg is run: packet tags and lengths, and a signature's one
type byte. It decides what gpg may be shown, never what gpg concluded.

If `gpg` is absent or unusable, the outcome is `NO_VERIFIER` and the
binding stays CLAIMED. A missing verifier is a failure to LOOK, and it is
recorded as distinct from a failure of the evidence so that "nobody has
checked these" is a query rather than a guess. There is no code path in
which an absent verifier produces a confirmation. A gpg below the version
floor is treated as absent (F10a): a build with a known forgery or
parser defect is not a verifier whose word is evidence (docs/16 C11).

## The two traps, and why the schema holds them rather than this file

**Trap 1 -- the wrong key.** A signature that verifies proves control of
whatever key signed it. That is only interesting if it is the key the
actor CLAIMED. Verifying against "some key in our keyring" and reporting
success is evidence about a stranger. Since F10a the claimed fingerprint
may be the signing subkey itself or the primary that subkey is bound
under (gpg's VALIDSIG names both): vendors publish the primary and sign
with a subkey, and reading only the first field recorded every such
genuine signature as KEY_MISMATCH.

**Trap 2 -- the replayed message.** A valid signature over some other
text says nothing about an identifier appended afterwards. Any signed
message a vendor ever published can be reposted with an attacker's Tox ID
pasted below it, and a naive `value in message` check passes -- because
the value IS in the message, just not in the part that was signed.

So the payload compared against is **gpg's own output of the verified
region**, obtained with `--output`, never the text we were handed. In a
clearsigned message everything after `-----END PGP SIGNATURE-----` is
unsigned and gpg does not emit it. For a DETACHED signature the payload
is the data supplied beside it, which gpg checked whole.

Both traps are ALSO CHECK constraints on `comms.pgp_verification`. That is
deliberate duplication: these are exactly the checks that survive review
and then get refactored away, and a constraint does not get refactored
away by accident.

## A third trap: the escrow error, cryptographically (F10b)

A guarantor's signed vouch "vendor X's Tox is ABC", checked with the
GUARANTOR's key and naming X's binding, is a good signature by the
claimed key over text naming the identifier, and used to upgrade X's
binding. Nothing tied the key to the binding's holder. A binding is now
confirmed only when a cited contact block lists the fingerprint as its
publisher's own and ties that publisher to the binding (the same block
lists the identifier as its own, or the block's publisher IS the
binding's identity), with no identity conflict; otherwise the check is
UNATTRIBUTED and the binding stays CLAIMED. A trigger holds the same rule.

## There is no TRUSTED outcome

GnuPG's web of trust answers "do I trust this key's owner", which is a
different question from "did this key sign this text". Only the second is
evidence here, so `--trust-model always` is passed and trust is never
consulted or reported. An investigator's keyring trust has no bearing on
whether a vendor controls a key.

## Expired and revoked keys

Both still prove the key signed the text, so both are recorded with their
own outcome rather than as failures. Neither is `VERIFIED`, so neither
upgrades a binding to CONFIRMED: a signature from a key revoked before
the message was published is a fact that needs a person to interpret, not
one a parser should convert into an attribution.
"""
from __future__ import annotations

import base64
import binascii
import functools
import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, replace
from uuid import UUID

import psycopg
from psycopg.types.json import Json

VERIFIED = "VERIFIED"
BAD_SIGNATURE = "BAD_SIGNATURE"
KEY_MISMATCH = "KEY_MISMATCH"
VALUE_NOT_IN_PAYLOAD = "VALUE_NOT_IN_PAYLOAD"
KEY_UNAVAILABLE = "KEY_UNAVAILABLE"
EXPIRED_KEY = "EXPIRED_KEY"
REVOKED_KEY = "REVOKED_KEY"
EXPIRED_SIGNATURE = "EXPIRED_SIGNATURE"
MALFORMED = "MALFORMED"
NO_VERIFIER = "NO_VERIFIER"
#: A good signature by the claimed key over text naming the identifier,
#: with nothing on record tying that key to the binding's holder (F10b,
#: 2026-09-24). Its own outcome, because KEY_MISMATCH means a DIFFERENT
#: key signed, and this is the right key with a missing link.
UNATTRIBUTED = "UNATTRIBUTED"

#: The two forms a check takes (F10a, 2026-09-24).
CLEARSIGNED = "CLEARSIGNED"
DETACHED = "DETACHED"
FORMS = (CLEARSIGNED, DETACHED)

#: How the claimed fingerprint was arrived at (F10b): typed or pasted at
#: the check, or a registry key somebody confirmed against a publication.
BASIS_STATED = "STATED"
BASIS_CONFIRMED_KEY = "CONFIRMED_KEY"

#: How a contact block ties the key to the binding's holder (F10b).
SAME_BLOCK = "SAME_BLOCK"
SAME_IDENTITY = "SAME_IDENTITY"

#: Outcomes for which gpg reported a good signature over the payload, so
#: the payload really is "the exact bytes that were signed". For anything
#: else the file gpg produced is attacker plaintext nobody signed, and
#: digesting it under that column's name would be a false record.
#: UNATTRIBUTED is here (F10b, 2026-09-24): it is a good
#: signature by the claimed key over the payload, and the schema requires
#: its digest, so leaving it out turned the console's default path into a
#: CheckViolation with no row and no audit.
_SIGNED_PAYLOAD_OUTCOMES = frozenset({
    "VERIFIED", "KEY_MISMATCH", "VALUE_NOT_IN_PAYLOAD",
    "EXPIRED_KEY", "REVOKED_KEY", EXPIRED_SIGNATURE, UNATTRIBUTED,
})

_FPR = re.compile(r"^[0-9A-F]{40}$|^[0-9A-F]{64}$")
_WS = re.compile(r"\s+")
#: How long gpg gets, for EVERYTHING one call does (F10a): one budget per
#: ephemeral keyring however many runs it makes, so reading a key file of
#: eight keys cannot hold a worker for eleven times this.
GPG_TIMEOUT_SECONDS = 20
#: Refuse absurd input before handing it to a subprocess.
MAX_MESSAGE_BYTES = 1_000_000
MAX_KEY_BYTES = 1_000_000
#: A detached signature is one signature packet: a few hundred bytes, a
#: few kilobytes with a large RSA key. Anything near this is not one.
MAX_SIGNATURE_BYTES = 65_536
#: A loop bound for the packet walker. A 1 MB key cannot hold more.
MAX_PACKETS = 20_000
#: Cap on what gpg may PRODUCE, not just what it is given. An armored
#: compressed message a few hundred KB long expands to hundreds of MB --
#: measured at 760x from a naive zeros bomb at half the input limit -- and
#: the result was previously read into memory whole. Bounded in two places
#: because either alone is insufficient: `--max-output` stops gpg writing
#: it, and the capped read stops US reading a file some other path created.
MAX_PAYLOAD_BYTES = 4_000_000
#: How much of the status stream to retain on the row. Kept from the FRONT:
#: the verdict is decided by the first VALIDSIG, and keeping the tail would
#: let a long user ID push the line that produced the verdict out of the
#: record that exists to justify it.
MAX_STATUS_CHARS = 8_000

#: A value shorter than this is never confirmed by containment. Short
#: strings appear inside longer numbers by coincidence, and a coincidence
#: that reads as cryptographic proof is worse than no answer.
MIN_CONFIRMABLE_LENGTH = 4
#: A value at least this long may match as a PREFIX of a longer token --
#: which is the normal Tox case, where the actor prints the full 76-hex ID
#: and the durable value is its 64-hex head. Below it, both ends must be
#: delimited.
PREFIX_MATCH_LENGTH = 32

#: The signature classes a document signature carries: 00 over binary
#: bytes, 01 over canonical text (a clearsigned message is always 01).
#: Anything else (a certification, a key binding, a timestamp) is not a
#: signature over the text, whatever gpg says of its validity (F10a,
#: 2026-09-24).
DOCUMENT_SIGNATURE_CLASSES = frozenset({"00", "01"})


class PgpError(Exception):
    """A request this module refuses. HTTP 400 unless a subclass says
    otherwise (routers/comms.py `_pgp_problem`)."""


class PgpNotFound(PgpError):
    """404: the object is unknown, in another case, or above the caller's
    labels. One class and one wording for all three, because a status that
    tells them apart is an existence oracle (F10-fix, 2026-09-24)."""


class PgpConflict(PgpError):
    """409: the request is well formed and the record refuses it (a label
    that would cross, a key not yet confirmed, a lapsed lookup)."""


class PgpUnavailable(PgpError):
    """503: no usable gpg, so nothing can be read (F10a)."""


class PgpShapeError(PgpError):
    """The OpenPGP framing is not what this path accepts. Raised by the
    packet walker BEFORE any subprocess (F10a)."""


def normalise_fingerprint(value: str) -> str:
    """Uppercase hex, no spaces. Not cryptography -- formatting.

    Fingerprints circulate printed in groups of four. A comparison between
    the spaced and unspaced forms fails, and the failure looks like a key
    mismatch, which is the one outcome that must never be produced by a
    formatting difference.
    """
    cleaned = _WS.sub("", value or "").upper()
    # "0x" prefixes appear in profile fields and mail headers.
    if cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    if not _FPR.match(cleaned):
        raise PgpError(
            f"{value!r} is not a PGP fingerprint: expected 40 hex characters "
            f"(v4) or 64 (v5), with or without spacing")
    return cleaned


@dataclass(frozen=True)
class VerificationResult:
    """What a verifier concluded, and the raw evidence for it."""

    outcome: str
    #: The fingerprint that ACTUALLY signed, per VALIDSIG. None when
    #: nothing verified. A subkey whenever the signer used one.
    signing_fingerprint: str | None = None
    #: gpg's own output of the SIGNED region -- never the input text.
    signed_payload: bytes | None = None
    value_in_payload: bool = False
    #: The --status-fd lines, verbatim. A disputed verification should be
    #: re-readable rather than re-arguable.
    status_output: str = ""
    verifier: str = "GPG"
    verifier_version: str | None = None
    detail: str = ""
    #: F10a: CLEARSIGNED or DETACHED; the primary key the signing key is
    #: bound under (VALIDSIG's last field); the signature class, 00 or 01.
    form: str = CLEARSIGNED
    signing_primary_fingerprint: str | None = None
    signature_class: str | None = None

    @property
    def confirms(self) -> bool:
        return self.outcome == VERIFIED

    def signed_payload_present(self) -> bool:
        """Whether gpg emitted any verified plaintext.

        A method rather than exposing the bytes to callers who only want
        to know it exists: the payload is attacker-supplied content and
        should be read deliberately, not incidentally.
        """
        return bool(self.signed_payload)


# ---------------------------------------------------------------------------
# The verifier: where it is, which version, and whether that version counts
# ---------------------------------------------------------------------------

#: F10a, 2026-09-24: the first release in
#: each series that carries the fixes for CVE-2022-34903 (a status-line
#: injection that can forge VALIDSIG, 2.2.36 and 2.3.7) AND CVE-2025-68973
#: (an out-of-bounds write in the armour parser that crafted armour reaches,
#: 2.4.9 and 2.5.14; 2.2.51 is the extended-support fix). Every path here
#: hands gpg armour an attacker chose. The 2.3 series ended without the
#: second fix and is refused; anything before 2.2 is refused; a series
#: after 2.5 postdates both fixes.
MIN_GPG_VERSIONS: dict[tuple[int, int], tuple[int, int, int]] = {
    (2, 2): (2, 2, 51),
    (2, 4): (2, 4, 9),
    (2, 5): (2, 5, 14),
}
#: An operator's attestation that a distribution build carries the fixes
#: of an upstream release although its version string is older (Debian
#: 13's 2.4.7-21+deb13u1 and Ubuntu 24.04's 2.4.4-2ubuntu17.4 both do).
#: The value is that upstream release, for example "2.4.9". It is
#: recorded on every verification row and shown in the readiness row as
#: the operator's word, because the build cannot tell a patched 2.4.4 from
#: an unpatched one (2026-09-24).
PATCHED_AS_ENV = "NOCTORNAL_GPG_PATCHED_AS"
_VERSION = re.compile(r"\(GnuPG[^)]*\)\s+(\d+)\.(\d+)\.(\d+)")
_ATTESTED = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def gpg_path() -> str | None:
    """The gpg binary, or None. `NOCTORNAL_GPG` overrides discovery."""
    override = os.environ.get("NOCTORNAL_GPG", "").strip()
    if override:
        return override if os.path.isfile(override) else None
    return shutil.which("gpg")


@functools.lru_cache(maxsize=4)
def _version_line(path: str) -> str | None:
    """The first line of `gpg --version`, once per binary per process.
    Tests call `_version_line.cache_clear()` after stubbing a binary."""
    try:
        out = subprocess.run(
            [path, "--version"], capture_output=True, text=True,
            timeout=GPG_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    first = (out.stdout or "").splitlines()
    return first[0].strip() if first else None


def gpg_version_tuple(path: str) -> tuple[int, int, int] | None:
    """(major, minor, patch) read from `gpg --version`, or None."""
    line = _version_line(path)
    match = _VERSION.search(line or "")
    return tuple(int(g) for g in match.groups()) if match else None


def _meets_floor(version: tuple[int, int, int]) -> bool:
    major, minor, _patch = version
    if major != 2:
        return major > 2
    if minor >= 6:
        return True
    floor = MIN_GPG_VERSIONS.get((major, minor))
    return floor is not None and version >= floor


def _floor_text(version: tuple[int, int, int]) -> str:
    floor = MIN_GPG_VERSIONS.get(version[:2])
    return ".".join(map(str, floor)) if floor else "2.4.9"


def _shown(version: tuple[int, int, int]) -> str:
    return ".".join(map(str, version))


def _attestation(installed: tuple[int, int, int]
                 ) -> tuple[tuple[int, int, int] | None, str | None]:
    """(the attested release, None), (None, why it cannot count), or
    (None, None) when nothing is attested. An attestation counts only for
    the installed series, at or above the installed version, and at the
    floor: one left over from another gpg must not vouch for this one."""
    raw = os.environ.get(PATCHED_AS_ENV, "").strip()
    if not raw:
        return None, None
    match = _ATTESTED.match(raw)
    if not match:
        return None, (f"{PATCHED_AS_ENV} must name an upstream release as "
                      f"three numbers, for example 2.4.9.")
    attested = tuple(int(g) for g in match.groups())
    if attested[:2] != installed[:2] or attested < installed:
        return None, (f"{PATCHED_AS_ENV} names {_shown(attested)}, which is not "
                      f"a release of the installed {installed[0]}.{installed[1]} "
                      f"series at or above {_shown(installed)}, so it cannot vouch "
                      f"for this gpg.")
    if not _meets_floor(attested):
        return None, (f"{PATCHED_AS_ENV} names {_shown(attested)}, which is itself "
                      f"below {_floor_text(attested)}.")
    return attested, None


def _floor_problem(path: str) -> str | None:
    """None when gpg at `path` meets the floor (by version, or by the
    operator's attestation); otherwise the sentence a check records."""
    version = gpg_version_tuple(path)
    if version is None:
        return ("the gpg version could not be read, so its output cannot be "
                "trusted as evidence.")
    if _meets_floor(version):
        return None
    attested, problem = _attestation(version)
    if attested is not None:
        return None
    if problem is not None:
        return problem
    if version[:2] == (2, 3):
        return (f"gpg {_shown(version)} is refused: the 2.3 series ended without "
                f"the fix for an armour parser memory error (CVE-2025-68973). "
                f"Install GnuPG 2.4.9 or later.")
    return (f"gpg {_shown(version)} is below {_floor_text(version)}, the first "
            f"release in its series with the fixes for a status-line forgery "
            f"(CVE-2022-34903) and an armour parser memory error "
            f"(CVE-2025-68973). Install a current gpg, or set {PATCHED_AS_ENV} "
            f"to the upstream release a distribution build's fixes match.")


def verifier_version() -> str | None:
    """The version line recorded on every row, with the operator's
    attestation when one is what lets this gpg count."""
    path = gpg_path()
    if not path:
        return None
    line = _version_line(path)
    version = gpg_version_tuple(path)
    if line and version and not _meets_floor(version):
        attested, _problem = _attestation(version)
        if attested is not None:
            return (f"{line} (attested by the operator as carrying the fixes "
                    f"of {_shown(attested)}, {PATCHED_AS_ENV})")
    return line


def verifier_status() -> tuple[bool, str]:
    """(usable, a sentence) for the readiness row: whether a check made now
    could produce a verdict, and why not."""
    path = gpg_path()
    if not path:
        override = os.environ.get("NOCTORNAL_GPG", "").strip()
        where = (" NOCTORNAL_GPG names a file that does not exist."
                 if override else "")
        return False, ("no gpg binary, so every signature check records "
                       "NO_VERIFIER and no binding can be confirmed." + where)
    problem = _floor_problem(path)
    if problem:
        return False, problem
    version = gpg_version_tuple(path)
    attested = None
    if not _meets_floor(version):
        attested, _problem = _attestation(version)
    shown = f"GnuPG {_shown(version)} at {path}"
    if attested is not None:
        shown += (f", attested by the operator as carrying the fixes of "
                  f"{_shown(attested)} ({PATCHED_AS_ENV})")
    return True, shown + "; the version is recorded on every verification row."


def _unavailable(detail: str) -> VerificationResult:
    return VerificationResult(
        outcome=NO_VERIFIER, verifier="NONE",
        detail=(f"{detail} No signature was checked. This is a failure to "
                f"LOOK, not a finding about the evidence, and the binding "
                f"stays CLAIMED."))


# ---------------------------------------------------------------------------
# One ephemeral keyring, one budget, no agent
# ---------------------------------------------------------------------------

#: Read through the module so a test can drive the budget with a fake clock.
_monotonic = time.monotonic

#: Every gpg run's fixed arguments, all RELATIVE (see `_EphemeralGpg`).
_BASE_ARGS: tuple[str, ...] = (
    "--homedir", "home", "--batch", "--no-tty", "--yes", "--quiet",
    # No agent is ever started (F10a, 2026-09-24). gpg 2.4.9 imported a
    # SECRET key armoured as a public key block and autostarted a
    # gpg-agent in the ephemeral home that outlived the deleted directory.
    # With this flag secret material cannot be imported at all (measured:
    # return code 2, nothing imported, no socket), and nothing outlives
    # the temporary home.
    "--no-autostart",
    # Trust answers a different question (see the module docstring) and
    # consulting it here would make the result depend on the
    # investigator's keyring.
    "--trust-model", "always",
    # No network. A key fetched mid-verification is a key the attacker
    # chose, and an outbound connection from an evidence check is an
    # operational leak.
    "--keyserver-options", "no-auto-key-retrieve",
    "--no-auto-key-locate", "--auto-key-locate", "nodefault",
    # Bound what gpg may PRODUCE. An armored compressed message well
    # inside MAX_MESSAGE_BYTES expands to hundreds of megabytes; the input
    # cap says nothing about the output.
    "--max-output", str(MAX_PAYLOAD_BYTES),
)


class _EphemeralGpg:
    """A throwaway keyring for one call, and one time budget for it.

    Runs in an EPHEMERAL keyring so the host's own keys are never
    consulted and nothing is imported anywhere durable -- a verification
    must not depend on what somebody imported last week, and a keyring
    that accumulates attacker-supplied keys is a liability of its own.

    RELATIVE paths, with cwd set to the work directory.

    Not a style choice. The common Windows gpg is the MSYS build shipped
    with Git, which expects POSIX paths: handed `C:\\Users\\...\\home` it
    resolves it against its own cwd and produces a nonsense path, then
    reports "the supplied public key could not be read" -- a MALFORMED
    outcome for a perfectly good key. Relative paths sidestep drive-letter
    translation entirely and work identically under a native Windows gpg
    and a POSIX one. `put` returns a relative name for that reason.
    """

    def __init__(self, binary: str):
        self._binary = binary
        self._tmp: tempfile.TemporaryDirectory | None = None
        self.work = ""
        self._ends = 0.0

    def __enter__(self) -> _EphemeralGpg:
        self._tmp = tempfile.TemporaryDirectory(prefix="noctornal-pgp-")
        self.work = self._tmp.name
        os.makedirs(os.path.join(self.work, "home"), mode=0o700, exist_ok=True)
        self._ends = _monotonic() + GPG_TIMEOUT_SECONDS
        return self

    def __exit__(self, *exc) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None

    def put(self, name: str, data: bytes) -> str:
        """Write bytes under a fixed literal name; the relative name back."""
        if os.sep in name or "/" in name or name.startswith("."):
            raise ValueError("a work file has a plain literal name")
        with open(os.path.join(self.work, name), "wb") as fh:
            fh.write(data)
        return name

    def run(self, *args: str) -> subprocess.CompletedProcess:
        """One gpg run inside what is left of the budget. text=False
        everywhere: the status stream carries attacker-controlled user-ID
        bytes, and decoding it to str both enables the line-injection in
        `_status_lines` and can raise UnicodeDecodeError from inside
        subprocess (see `_show`). Bytes in, decisions on ASCII tokens."""
        remaining = self._ends - _monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired([self._binary], GPG_TIMEOUT_SECONDS)
        return subprocess.run(
            [self._binary, *_BASE_ARGS, *args], cwd=self.work,
            capture_output=True, text=False, timeout=remaining, check=False)

    def read(self, name: str, cap: int) -> bytes:
        """At most `cap + 1` bytes of a file gpg wrote, or b"". Capped
        independently of --max-output: this read must be bounded by OUR
        limit, not by whatever produced the file."""
        path = os.path.join(self.work, name)
        if not os.path.isfile(path):
            return b""
        with open(path, "rb") as fh:
            return fh.read(cap + 1)


# ---------------------------------------------------------------------------
# The packet walker: framing only, before gpg sees anything (F10a)
# ---------------------------------------------------------------------------

#: The armour kinds this reader can place. Anything else that looks like
#: an armour line is refused rather than skipped: a block the walker
#: cannot see is a block its rules do not apply to.
_ARMOUR_KINDS = frozenset({
    "PUBLIC KEY BLOCK", "PRIVATE KEY BLOCK", "SECRET KEY BLOCK",
    "SIGNATURE", "SIGNED MESSAGE", "MESSAGE", "ARMORED FILE",
})
_SECRET_KINDS = frozenset({"PRIVATE KEY BLOCK", "SECRET KEY BLOCK"})
_SECRET_TAGS = frozenset({5, 7})
_SECRET_SENTENCE = ("this is a SECRET key. It is not stored or read here; "
                    "lodge it as an exhibit if it is evidence.")
#: Public key material: public key, public subkey, user id, user
#: attribute, signature. Trust packets (12) are refused: they exist only
#: in local keyrings, and a forged signature cache in one is how a subkey
#: is attached to somebody else's key (2026-09-24).
_PUBLIC_KEY_TAGS = frozenset({6, 14, 13, 17, 2})
_ARMOUR_LINE = re.compile(rb"^-----(BEGIN|END) PGP ([A-Z ]+)-----$")
_HEADER_LINE = re.compile(rb"^[A-Za-z][A-Za-z0-9-]*: ")
_B64_LINE = re.compile(rb"^[A-Za-z0-9+/=]+$")
_CHECKSUM_LINE = re.compile(rb"^=[A-Za-z0-9+/]{4}$")


def _dearmour(data: bytes, armour_kinds: frozenset[str]) -> bytes:
    """The packet streams of every armour block in `data`, concatenated.

    Mirrors gpg: header and body lines are read with trailing space, tab
    and CR stripped (gpg reads a header ending in a tab, and a CRLF file);
    every block is read, not the first (gpg imports a second block after
    forum text); text outside blocks is ignored, UTF-8 included (a key
    pasted from a forum post). Any line that starts like an armour line
    and is not exactly one this reader recognises is refused."""
    blocks: list[bytes] = []
    lines = [line.rstrip(b" \t\r") for line in data.split(b"\n")]
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip(b" \t")
        if not (stripped.startswith(b"-----BEGIN") or stripped.startswith(b"-----END")):
            i += 1
            continue
        match = _ARMOUR_LINE.match(line)
        kind = match.group(2).decode("ascii") if match else None
        if match is None or kind not in _ARMOUR_KINDS:
            raise PgpShapeError(
                "an armour line here is not one this reader can place, so the "
                "material is refused rather than read around it.")
        if match.group(1) == b"END":
            raise PgpShapeError("an armour END line has no BEGIN before it.")
        if kind not in armour_kinds:
            if kind in _SECRET_KINDS:
                raise PgpShapeError(_SECRET_SENTENCE)
            raise PgpShapeError(
                f"this is armoured as PGP {kind}, which is not what this field "
                f"takes.")
        i += 1
        while i < len(lines) and _HEADER_LINE.match(lines[i]):
            i += 1
        body: list[bytes] = []
        ended = False
        while i < len(lines):
            line = lines[i]
            end = _ARMOUR_LINE.match(line)
            if end is not None:
                if end.group(1) != b"END" or end.group(2).decode("ascii") != kind:
                    raise PgpShapeError(
                        f"the PGP {kind} block ends with a different armour "
                        f"line, so it is refused.")
                ended = True
                i += 1
                break
            if line.lstrip(b" \t").startswith((b"-----BEGIN", b"-----END")):
                raise PgpShapeError(
                    "an armour line here is not one this reader can place, so "
                    "the material is refused rather than read around it.")
            if line and not _CHECKSUM_LINE.match(line):
                if not _B64_LINE.match(line):
                    raise PgpShapeError(
                        f"the PGP {kind} block carries a line that is not "
                        f"base64.")
                body.append(line)
            i += 1
        if not ended:
            raise PgpShapeError(f"the PGP {kind} block has no END line.")
        try:
            blocks.append(base64.b64decode(b"".join(body), validate=True))
        except (ValueError, binascii.Error):
            raise PgpShapeError(
                f"the PGP {kind} block is not valid base64.") from None
    if not blocks:
        raise PgpShapeError("no OpenPGP armour was found.")
    return b"".join(blocks)


def _walk(stream: bytes) -> list[tuple[int, bytes]]:
    """(tag, body) for every packet, or PgpShapeError. Partial and
    indeterminate lengths are refused: only data packets may use them, and
    none belongs in a key or a detached signature."""
    packets: list[tuple[int, bytes]] = []
    pos, size = 0, len(stream)
    if size == 0:
        raise PgpShapeError("there are no OpenPGP packets here.")
    while pos < size:
        head = stream[pos]
        if not head & 0x80:
            raise PgpShapeError("this is not an OpenPGP packet stream.")
        pos += 1
        if head & 0x40:
            tag = head & 0x3F
            if pos >= size:
                raise PgpShapeError("an OpenPGP packet header is cut short.")
            first = stream[pos]
            if first < 192:
                length, pos = first, pos + 1
            elif first < 224:
                if pos + 2 > size:
                    raise PgpShapeError("an OpenPGP packet header is cut short.")
                length = ((first - 192) << 8) + stream[pos + 1] + 192
                pos += 2
            elif first == 255:
                if pos + 5 > size:
                    raise PgpShapeError("an OpenPGP packet header is cut short.")
                length = int.from_bytes(stream[pos + 1:pos + 5], "big")
                pos += 5
            else:
                raise PgpShapeError(
                    "a packet uses a partial length, which only data packets "
                    "may use; none belongs here.")
        else:
            tag = (head >> 2) & 0x0F
            kind = head & 0x03
            if kind == 3:
                raise PgpShapeError(
                    "a packet has an indeterminate length, which only data "
                    "packets may use; none belongs here.")
            octets = (1, 2, 4)[kind]
            if pos + octets > size:
                raise PgpShapeError("an OpenPGP packet header is cut short.")
            length = int.from_bytes(stream[pos:pos + octets], "big")
            pos += octets
        if pos + length > size:
            raise PgpShapeError("an OpenPGP packet runs past the end of the data.")
        packets.append((tag, stream[pos:pos + length]))
        pos += length
        if len(packets) > MAX_PACKETS:
            raise PgpShapeError("there are more OpenPGP packets here than any "
                                "key or signature holds.")
    return packets


def _pgp_packets(data: bytes, *, armour_kinds: frozenset[str]
                 ) -> list[tuple[int, bytes]]:
    """The packets in `data`, armoured or binary. gpg decides whether
    input is armoured from its first byte, so this does: below 0x80 is
    text (armour), anything else is a binary packet stream."""
    if not data:
        raise PgpShapeError("there is nothing here.")
    stream = _dearmour(data, armour_kinds) if data[0] < 0x80 else data
    return _walk(stream)


def _public_key_shape(data: bytes) -> list[tuple[int, bytes]]:
    """Public key material and nothing else, refused before gpg if not."""
    packets = _pgp_packets(data, armour_kinds=frozenset({"PUBLIC KEY BLOCK"}))
    for tag, _body in packets:
        if tag in _SECRET_TAGS:
            raise PgpShapeError(_SECRET_SENTENCE)
    if packets[0][0] != 6:
        raise PgpShapeError("this is not an OpenPGP public key: it does not "
                            "begin with a public key packet.")
    for tag, _body in packets:
        if tag not in _PUBLIC_KEY_TAGS:
            raise PgpShapeError(
                f"this is not public key material: it carries an OpenPGP "
                f"packet of type {tag}.")
    return packets


def _signature_type(body: bytes) -> int | None:
    """A signature packet's type byte: v3 keeps it after the hashed-length
    octet, v4, v5 and v6 right after the version."""
    if not body:
        return None
    if body[0] == 3 and len(body) > 2:
        return body[2]
    if body[0] in (4, 5, 6) and len(body) > 1:
        return body[1]
    return None


def _detached_shape(signature: bytes) -> None:
    """Exactly one signature packet, over a document (class 00 or 01).
    Refuses before gpg the shape of a signature followed by a literal
    packet (gpg would check the literal, not the data supplied), and a
    one-pass signed message offered in the detached slot."""
    packets = _pgp_packets(signature, armour_kinds=frozenset({"SIGNATURE"}))
    if len(packets) != 1 or packets[0][0] != 2:
        raise PgpShapeError("a detached signature is one signature packet and "
                            "nothing else.")
    kind = _signature_type(packets[0][1])
    if kind not in (0x00, 0x01):
        raise PgpShapeError("that signature is not over a document (its class "
                            "is neither 00 nor 01).")


# ---------------------------------------------------------------------------
# The two checks
# ---------------------------------------------------------------------------

def _key_bytes(public_key: str | bytes | None) -> bytes:
    if public_key is None:
        return b""
    return public_key if isinstance(public_key, bytes) else public_key.encode("utf-8")


def verify_clearsigned(signed_message: str, public_key: str | bytes, *,
                       claimed_fingerprint: str,
                       confirms_value: str | None = None
                       ) -> VerificationResult:
    """Check a clearsigned message against a supplied public key."""
    claimed = normalise_fingerprint(claimed_fingerprint)
    if not signed_message or not signed_message.strip():
        return VerificationResult(MALFORMED, detail="no signed message given")
    key = _key_bytes(public_key)
    if not key.strip():
        return VerificationResult(
            KEY_UNAVAILABLE,
            detail="no public key supplied, so there is nothing to check the "
                   "signature against")
    if len(signed_message.encode()) > MAX_MESSAGE_BYTES:
        return VerificationResult(MALFORMED, detail="signed message too large")
    if len(key) > MAX_KEY_BYTES:
        return VerificationResult(MALFORMED, detail="public key too large")
    if "-----BEGIN PGP SIGNED MESSAGE-----" not in signed_message:
        return VerificationResult(
            MALFORMED,
            detail="not a clearsigned message: no PGP SIGNED MESSAGE header")
    try:
        _public_key_shape(key)
    except PgpShapeError as exc:
        return VerificationResult(MALFORMED, detail=f"the public key: {exc}")

    binary = gpg_path()
    if not binary:
        return _unavailable("No gpg binary is available on this host.")
    problem = _floor_problem(binary)
    if problem:
        return _unavailable(problem[:1].upper() + problem[1:])
    version = verifier_version()
    try:
        with _EphemeralGpg(binary) as gpg:
            gpg.put("key.in", key)
            gpg.put("message.asc", signed_message.encode("utf-8"))
            imported = gpg.run("--import", "key.in")
            if imported.returncode != 0:
                return VerificationResult(
                    MALFORMED, status_output=_show(imported.stderr),
                    verifier_version=version,
                    detail="the supplied public key could not be read")
            proc = gpg.run("--status-fd", "1", "--output", "verified.txt",
                           "--decrypt", "message.asc")
            payload = gpg.read("verified.txt", MAX_PAYLOAD_BYTES)
    except subprocess.TimeoutExpired:
        return _unavailable(f"gpg did not return within {GPG_TIMEOUT_SECONDS}s.")
    except OSError as exc:
        return _unavailable(f"gpg could not be run ({exc}).")

    status = proc.stdout or b""
    if len(payload) > MAX_PAYLOAD_BYTES:
        return VerificationResult(
            MALFORMED, status_output=_show(status), verifier_version=version,
            detail=(f"the signed payload exceeds {MAX_PAYLOAD_BYTES} bytes, "
                    f"which a contact block never does"))
    return _read_status(status, payload, claimed=claimed,
                        confirms_value=confirms_value, version=version,
                        form=CLEARSIGNED)


def verify_detached(signature: bytes, data: bytes, public_key: str | bytes, *,
                    claimed_fingerprint: str, confirms_value: str | None = None,
                    data_was_pasted: bool = False) -> VerificationResult:
    """Check a detached signature over `data` against a public key (F10a).

    The payload compared against the identifier, and digested on the row,
    is `data` itself: gpg verified those bytes whole. For a text-mode
    (class 01) signature they are the bytes BEFORE gpg's line-ending
    canonicalisation, which is what was supplied."""
    claimed = normalise_fingerprint(claimed_fingerprint)
    if not signature:
        return VerificationResult(MALFORMED, form=DETACHED,
                                  detail="no detached signature given")
    if len(signature) > MAX_SIGNATURE_BYTES:
        return VerificationResult(
            MALFORMED, form=DETACHED,
            detail=f"the signature is larger than {MAX_SIGNATURE_BYTES} bytes, "
                   f"which no single signature is")
    if not data:
        return VerificationResult(MALFORMED, form=DETACHED,
                                  detail="no signed data given")
    if len(data) > MAX_MESSAGE_BYTES:
        return VerificationResult(MALFORMED, form=DETACHED,
                                  detail="signed data too large")
    key = _key_bytes(public_key)
    if not key.strip():
        return VerificationResult(
            KEY_UNAVAILABLE, form=DETACHED,
            detail="no public key supplied, so there is nothing to check the "
                   "signature against")
    if len(key) > MAX_KEY_BYTES:
        return VerificationResult(MALFORMED, form=DETACHED,
                                  detail="public key too large")
    try:
        _detached_shape(signature)
    except PgpShapeError as exc:
        return VerificationResult(MALFORMED, form=DETACHED,
                                  detail=f"the signature: {exc}")
    try:
        _public_key_shape(key)
    except PgpShapeError as exc:
        return VerificationResult(MALFORMED, form=DETACHED,
                                  detail=f"the public key: {exc}")

    binary = gpg_path()
    if not binary:
        return replace(_unavailable("No gpg binary is available on this host."),
                       form=DETACHED)
    problem = _floor_problem(binary)
    if problem:
        return replace(_unavailable(problem[:1].upper() + problem[1:]),
                       form=DETACHED)
    version = verifier_version()
    try:
        with _EphemeralGpg(binary) as gpg:
            gpg.put("key.in", key)
            gpg.put("sig", signature)
            gpg.put("data", data)
            imported = gpg.run("--import", "key.in")
            if imported.returncode != 0:
                return VerificationResult(
                    MALFORMED, form=DETACHED, status_output=_show(imported.stderr),
                    verifier_version=version,
                    detail="the supplied public key could not be read")
            proc = gpg.run("--status-fd", "1", "--verify", "sig", "data")
    except subprocess.TimeoutExpired:
        return replace(_unavailable(
            f"gpg did not return within {GPG_TIMEOUT_SECONDS}s."), form=DETACHED)
    except OSError as exc:
        return replace(_unavailable(f"gpg could not be run ({exc})."),
                       form=DETACHED)
    return _read_status(proc.stdout or b"", data, claimed=claimed,
                        confirms_value=confirms_value, version=version,
                        form=DETACHED, data_was_pasted=data_was_pasted)


def _show(raw: bytes | None, limit: int = MAX_STATUS_CHARS) -> str:
    """Attacker bytes, rendered for the record and never for a decision.

    `errors="replace"` because an OpenPGP user ID is arbitrary bytes and
    gpg re-emits it unvalidated. Decoding it strictly threw
    `UnicodeDecodeError` from inside `subprocess`, which on Windows killed
    the reader thread and silently produced an empty stream -- reported as
    BAD_SIGNATURE for a signature that verified perfectly -- and on POSIX
    propagated out uncaught, so no row was recorded at all.
    """
    if not raw:
        return ""
    text = raw.decode("utf-8", errors="replace")
    if len(text) > limit:
        return text[:limit] + f"\n... [truncated at {limit} characters]"
    return text


def _status_lines(status: bytes) -> list[list[str]]:
    """Parse gpg's --status-fd stream. BYTES, split on b"\\n" ONLY.

    This is the whole defence against a forged verdict, so it is worth
    stating what goes wrong otherwise.

    gpg delimits status lines with `\\n` and percent-escapes `%` and every
    byte below 0x20 in the attacker-controlled user-ID field. It does NOT
    escape bytes at or above 0x80. Python's `str.splitlines()` splits on
    far more than `\\n`: it also breaks on U+0085, U+2028 and U+2029, none
    of which gpg escapes.

    So an attacker generated a key whose user ID was:

        Attacker Persona<U+0085>[GNUPG:] VALIDSIG <victim fingerprint> ...

    gpg emitted that verbatim inside GOODSIG -- which it emits BEFORE the
    real VALIDSIG -- `splitlines()` cut it into two lines, and the parser
    read the forged one first. Outcome VERIFIED, `signing_fingerprint` the
    victim's, binding upgraded to CONFIRMED, for a key the attacker did
    not hold. Reproduced end to end.

    The CHECK constraints could not catch it: they compare
    `signing_fingerprint` to `claimed_fingerprint`, and both came from the
    same lied-to parse, so they agreed. A constraint defends against the
    application forgetting to check; it cannot defend against the
    application checking a forged input.

    It was invisible on the Windows dev host because cp1252 does not map
    those bytes to line terminators. The deployment target is Linux under
    UTF-8, where it works.
    """
    out: list[list[str]] = []
    for line in (status or b"").split(b"\n"):
        if not line.startswith(b"[GNUPG:] "):
            continue
        # Fields are ASCII tokens; anything else in them is not something
        # a decision may rest on.
        out.append(line[9:].decode("ascii", errors="replace").split())
    return out


_TOKEN_CHAR = re.compile(r"[0-9A-Za-z]")


def _payload_contains(payload_text: str, value: str) -> tuple[bool, str]:
    """Is `value` genuinely NAMED in the signed text? (present, reason)

    A bare substring test is not enough, and the failure is not
    hypothetical. Telegram durable values are bare digits, so a vendor who
    signed an ordinary sentence containing an order number could confirm a
    stranger's account:

        signed: "Escrow order 3877451900 shipped 2026-07-25."
        value : "77451"      -> substring: True

    That drove a binding to CONFIRMED and recorded it as "cryptographic
    evidence ... of the key's holder publishing that identifier", which is
    false. The same collision happens by accident, which is worse, because
    nothing about it looks like an attack.

    The rule: the match must START at a token boundary, and must also END
    at one unless the value is long enough to be unambiguous on its own.
    The exception is load-bearing rather than a loophole -- an actor
    normally prints the full 76-hex Tox ID while the durable value is its
    64-hex head, so demanding a boundary at both ends would refuse the
    commonest legitimate case.
    """
    needle = (value or "").strip()
    if len(needle) < MIN_CONFIRMABLE_LENGTH:
        return False, (
            f"{needle!r} is too short ({len(needle)} characters) to be "
            f"confirmed by appearing in a text. Short strings occur inside "
            f"longer numbers by coincidence, and a coincidence that reads "
            f"as cryptographic proof is worse than no answer.")

    hay, low = payload_text.lower(), needle.lower()
    start = hay.find(low)
    while start != -1:
        left_ok = start == 0 or not _TOKEN_CHAR.match(hay[start - 1])
        end = start + len(low)
        right_ok = end == len(hay) or not _TOKEN_CHAR.match(hay[end])
        if left_ok and (right_ok or len(needle) >= PREFIX_MATCH_LENGTH):
            return True, ""
        start = hay.find(low, start + 1)
    return False, (
        f"{needle!r} does not appear in the signed text as an identifier. "
        f"It may occur inside a longer run of characters (an order "
        f"number, another account), which is not the same as the signer "
        f"naming it.")


@dataclass(frozen=True)
class _ValidSig:
    fingerprint: str
    primary: str | None
    sig_class: str | None


_CLASS = re.compile(r"^[0-9a-f]{2}$")


def _validsig(parts: list[str]) -> _ValidSig:
    """VALIDSIG <fpr> <date> <ts> <expire> <version> <reserved> <pk-algo>
    <hash-algo> <class> [<primary-fpr>]. The FIRST field is the key that
    made the signature, a subkey whenever the vendor signs with one; the
    primary it is bound under is the LAST (F10a, measured on 2.4.9)."""
    primary = parts[10].upper() if len(parts) > 10 and _FPR.match(
        parts[10].upper()) else None
    sig_class = parts[9].lower() if len(parts) > 9 and _CLASS.match(
        parts[9].lower()) else None
    return _ValidSig(parts[1].upper(), primary, sig_class)


def _read_status(status: bytes, payload: bytes, *, claimed: str,
                 confirms_value: str | None, version: str | None,
                 form: str = CLEARSIGNED,
                 data_was_pasted: bool = False) -> VerificationResult:
    """Decide the outcome from the machine-readable lines ONLY.

    Order matters. gpg emits VALIDSIG for an expired or revoked key as
    well as a good one, so checking VALIDSIG first would report a revoked
    key as a clean confirmation.
    """
    lines = _status_lines(status)
    codes = {parts[0] for parts in lines if parts}
    validsigs = [_validsig(parts) for parts in lines
                 if len(parts) > 1 and parts[0] == "VALIDSIG"]
    sig = validsigs[0] if validsigs else None
    signing = sig.fingerprint if sig else None

    common = {"status_output": _show(status), "verifier_version": version,
              "signing_fingerprint": signing, "signed_payload": payload,
              "form": form,
              "signing_primary_fingerprint": sig.primary if sig else None,
              "signature_class": sig.sig_class if sig else None}

    # Taking the FIRST of several is what made line injection profitable,
    # and it is also wrong on its own terms: a message carrying two
    # signatures has two answers, and picking one silently is a guess
    # about which the analyst meant. Both fixed by refusing. LINES are
    # counted (F10a): this counted a set of one identical string, which
    # was never more than one.
    goodsigs = sum(1 for parts in lines if parts and parts[0] == "GOODSIG")
    newsigs = sum(1 for parts in lines if parts and parts[0] == "NEWSIG")
    if len(validsigs) > 1 or goodsigs > 1 or newsigs > 1:
        return VerificationResult(
            MALFORMED, **common,
            detail=(f"the status stream reported {len(validsigs)} valid "
                    f"signatures. This system verifies ONE signature over "
                    f"ONE message; several means either a multiply-signed "
                    f"message or an attempt to smuggle a status line "
                    f"through a crafted user ID, and neither is something "
                    f"to resolve by picking the first."))

    # A detached check whose signature file carried signed data of its
    # own: gpg checked THAT, not the data supplied beside it. The walker
    # refuses the shape before gpg runs; this refuses it again from gpg's
    # own report, so an older gpg's leniency cannot slip it through.
    if form == DETACHED and "PLAINTEXT" in codes:
        return VerificationResult(
            MALFORMED, **common,
            detail=("the signature file carried signed data of its own, so "
                    "the data supplied beside it is not what gpg checked. A "
                    "detached signature is a signature and nothing else."))

    if "NODATA" in codes and not signing:
        return VerificationResult(
            MALFORMED, **common,
            detail="gpg found no OpenPGP data in the message")
    if "REVKEYSIG" in codes:
        return VerificationResult(
            REVOKED_KEY, **common,
            detail="the signature is good but the key is REVOKED. That is a "
                   "fact for a person to interpret (a signature from a key "
                   "revoked before the message was published is not the same "
                   "as one from a live key), so it does not confirm a "
                   "binding on its own.")
    if "EXPKEYSIG" in codes:
        return VerificationResult(
            EXPIRED_KEY, **common,
            detail="the signature is good but the key had EXPIRED. It still "
                   "proves the key signed the text; it does not confirm a "
                   "binding without a person deciding the expiry is "
                   "immaterial.")
    if "EXPSIG" in codes:
        # The SIGNATURE expired, which is not the same as the KEY expiring.
        # gpg emits EXPSIG in place of GOODSIG, so without this branch it
        # fell through to "gpg did not report a good signature" -- failing
        # closed, but mislabelling the evidence as forged when it is
        # merely stale. The module gives expired KEYS their own outcome
        # for exactly this reason.
        return VerificationResult(
            EXPIRED_SIGNATURE, **common,
            detail="the signature is good but has EXPIRED. It still shows "
                   "the key signed the text; whether an expired signature "
                   "confirms anything now is a judgement for a person.")
    if "BADSIG" in codes:
        detail = "the signature did not verify against this key"
        if form == DETACHED and data_was_pasted:
            detail += (". The data was pasted as text. A signature over a "
                       "file's exact bytes fails on a copy that lost the "
                       "file's Windows line endings, so upload the file "
                       "itself before reading this as forged.")
        return VerificationResult(BAD_SIGNATURE, **common, detail=detail)
    if "NO_PUBKEY" in codes:
        return VerificationResult(
            KEY_UNAVAILABLE, **common,
            detail="the message was signed by a key that was not supplied")
    if "ERRSIG" in codes and "GOODSIG" not in codes:
        return VerificationResult(
            KEY_UNAVAILABLE, **common,
            detail="gpg could not check the signature (unsupported algorithm "
                   "or missing key)")
    if "GOODSIG" not in codes or not signing:
        return VerificationResult(
            BAD_SIGNATURE, **common,
            detail="gpg did not report a good signature")

    # A good signature that is not over a document (a certification, a
    # key binding) says nothing about any text (F10a).
    if sig.sig_class not in DOCUMENT_SIGNATURE_CLASSES:
        return VerificationResult(
            MALFORMED, **common,
            detail=("gpg reported a signature of a class that is not a "
                    "signature over a document, so it confirms nothing about "
                    "the text."))

    # TRAP 1. A good signature by a key nobody claimed is evidence about a
    # stranger. The claim may name the signing key or the primary it is
    # bound under; gpg read the binding, so either is the same holder.
    if claimed not in {sig.fingerprint, sig.primary}:
        made_by = (f"{signing} (a subkey of {sig.primary})"
                   if sig.primary and sig.primary != signing else signing)
        return VerificationResult(
            KEY_MISMATCH, **common,
            detail=(f"the signature is VALID but it was made by {made_by}, "
                    f"not by the claimed key {claimed}. A signature proves "
                    f"control of whatever key signed it; if that is not the "
                    f"key the actor published, it says nothing about them."))

    if confirms_value is None:
        return VerificationResult(
            VALUE_NOT_IN_PAYLOAD, **common, value_in_payload=False,
            detail="the signature is valid and by the claimed key, but no "
                   "identifier was named for it to confirm. A valid signature "
                   "over unspecified text confirms control of the key and "
                   "nothing about any selector.")

    # TRAP 2. Compared against gpg's OUTPUT of the signed region, never
    # against the text we were handed: everything after the signature
    # block in a clearsigned message is unsigned, and a naive substring
    # check over the raw input passes for an identifier pasted there.
    text = payload.decode("utf-8", errors="replace")
    present, why_not = _payload_contains(text, confirms_value)
    if not present:
        return VerificationResult(
            VALUE_NOT_IN_PAYLOAD, **common, value_in_payload=False,
            detail=(f"the signature is valid and by the claimed key, but "
                    f"{why_not} Any message this vendor ever signed can be "
                    f"reposted with somebody else's identifier appended "
                    f"below the signature block, and that is what this "
                    f"refuses. The match is deliberately strict, so a "
                    f"genuine signature can land here when the actor "
                    f"printed the identifier in a different form (spaced "
                    f"hex, for instance). Check the signed text before "
                    f"reading this as an attack: a false confirmation is "
                    f"far more expensive than a second look."))

    signer = (f"subkey {signing} of key {sig.primary}"
              if sig.primary and sig.primary != signing else signing)
    return VerificationResult(
        VERIFIED, **common, value_in_payload=True,
        detail=(f"signed by {signer}, and {confirms_value!r} appears within "
                f"the signed text. This is cryptographic evidence of control "
                f"of the key, and of the key's holder publishing that "
                f"identifier."))


# ---------------------------------------------------------------------------
# Recording, and who may see a record
# ---------------------------------------------------------------------------

#: ONE visibility predicate for verification rows, over alias `v`, with
#: named parameters %(clearance)s and %(held)s (F10-fix, 2026-09-24). A
#: verification carries no labels of its own but cites a binding, a block
#: and (F10b) a registry key, each of which may sit above its case; a row
#: is shown only when everything it cites is. The ledger, the queue's
#: "attempted" flag and last outcome, and pgp_keys.py's reads all use this
#: constant: the queue once had its own unfiltered EXISTS, which would
#: have been an existence and outcome oracle for checks the reader may not
#: see the moment the console displayed it.
_VISIBLE_VERIFICATION = """
    (v.channel_binding_id IS NULL OR EXISTS (
        SELECT 1 FROM comms.channel_binding vb
         WHERE vb.id = v.channel_binding_id
           AND vb.classification <= %(clearance)s::core.tlp
           AND vb.compartments <@ %(held)s::text[]))
    AND (v.contact_block_id IS NULL OR EXISTS (
        SELECT 1 FROM comms.contact_block vk
         WHERE vk.id = v.contact_block_id
           AND vk.classification <= %(clearance)s::core.tlp
           AND vk.compartments <@ %(held)s::text[]))
    AND (v.pgp_key_id IS NULL OR EXISTS (
        SELECT 1 FROM comms.pgp_key vpk
          JOIN comms.pgp_key_acquisition vpa ON vpa.id = vpk.acquisition_id
         WHERE vpk.id = v.pgp_key_id
           AND vpa.classification <= %(clearance)s::core.tlp
           AND vpa.compartments <@ %(held)s::text[]))
"""

#: The sentences a check that names a binding but lacks the link records.
_NO_BLOCK = "no contact block was cited"
_NO_KEY_LINK = ("the cited contact block does not list this fingerprint as its "
                "publisher's own")
_IDENTITY_CONFLICT = ("the cited block's publisher and the binding's identity "
                      "are different entities")
_NO_HOLDER_LINK = ("the cited block does not list this identifier as its "
                   "publisher's own, and the binding is not tied to the "
                   "block's publisher")


def _tlp_above(a: str, b: str) -> bool:
    from noctornal_api.security.access import tlp_from_name
    return tlp_from_name(a) > tlp_from_name(b)


def _labels_within(inner: tuple[str, list], outer: tuple[str, list]) -> bool:
    """Whether labels `inner` (classification, compartments) sit within
    `outer`: no higher classification, no compartment `outer` lacks."""
    return (not _tlp_above(inner[0], outer[0])
            and set(inner[1] or ()) <= set(outer[1] or ()))


class PgpService:
    """Records verifications, and upgrades a binding when one earns it."""

    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- loading under the caller's labels --------------------------------

    def _binding(self, case_id: UUID, binding_id: UUID, *, clearance: str,
                 held: frozenset[str]) -> dict:
        row = self._c.execute(
            """SELECT id, platform_key, observed_value, durable_value,
                      identity_node_id, classification::text, compartments
                 FROM comms.channel_binding
                WHERE id = %s AND case_id = %s
                  AND classification <= %s::core.tlp
                  AND compartments <@ %s::text[]""",
            (binding_id, case_id, clearance, sorted(held))).fetchone()
        if row is None:
            raise PgpNotFound("no such channel binding in this case")
        return {"id": row[0], "platform_key": row[1], "observed_value": row[2],
                "durable_value": row[3], "identity_node_id": row[4],
                "classification": row[5], "compartments": list(row[6] or [])}

    def _block(self, case_id: UUID, block_id: UUID, *, clearance: str,
               held: frozenset[str]) -> dict:
        row = self._c.execute(
            """SELECT id, publisher_identity_node_id, classification::text,
                      compartments
                 FROM comms.contact_block
                WHERE id = %s AND case_id = %s
                  AND classification <= %s::core.tlp
                  AND compartments <@ %s::text[]""",
            (block_id, case_id, clearance, sorted(held))).fetchone()
        if row is None:
            raise PgpNotFound("no such contact block in this case")
        return {"id": row[0], "publisher_identity_node_id": row[1],
                "classification": row[2], "compartments": list(row[3] or [])}

    def _registry_key(self, case_id: UUID, key_id: UUID, *, clearance: str,
                      held: frozenset[str]) -> dict:
        """A registry key for a check (F10b): visible, confirmed and not
        retired, with its material and the block its confirmation cites."""
        row = self._c.execute(
            """SELECT k.id, k.material, k.confirmed_fingerprint, k.retired_at,
                      a.classification::text, a.compartments,
                      e.block_id
                 FROM comms.pgp_key k
                 JOIN comms.pgp_key_acquisition a ON a.id = k.acquisition_id
                 LEFT JOIN comms.contact_block_entry e
                        ON e.id = k.confirmed_contact_block_entry_id
                WHERE k.id = %s AND k.case_id = %s
                  AND a.classification <= %s::core.tlp
                  AND a.compartments <@ %s::text[]""",
            (key_id, case_id, clearance, sorted(held))).fetchone()
        if row is None:
            raise PgpNotFound("no such key in this case")
        if row[3] is not None:
            raise PgpConflict("that key is retired, so no check is made with it")
        if row[2] is None:
            raise PgpConflict(
                "that key's fingerprint has not been confirmed against what "
                "the actor published, so it cannot stand behind a check yet")
        return {"id": row[0], "material": row[1], "fingerprint": row[2],
                "classification": row[4], "compartments": list(row[5] or []),
                "confirmation_block_id": row[6]}

    def _attribution(self, *, binding: dict, block: dict | None, claimed: str,
                     primary: str | None) -> tuple[str | None, str | None]:
        """(SAME_BLOCK or SAME_IDENTITY, None), or (None, the reason the
        key is not tied to the binding's holder). The same three links the
        trigger `comms.pgp_verification_is_attributed` requires."""
        if block is None:
            return None, _NO_BLOCK
        fingerprints = sorted({claimed} | ({primary} if primary else set()))
        linked = self._c.execute(
            """SELECT EXISTS (
                 SELECT 1 FROM comms.contact_block_entry e
                  WHERE e.block_id = %s AND e.role = 'SELF'
                    AND e.selector_type = 'PGP_FPR'
                    AND comms.pgp_fingerprint_norm(e.durable_value) = ANY(%s::text[]))""",
            (block["id"], fingerprints)).fetchone()[0]
        if not linked:
            return None, _NO_KEY_LINK
        publisher = block["publisher_identity_node_id"]
        identity = binding["identity_node_id"]
        if publisher is not None and identity is not None:
            if publisher != identity:
                return None, _IDENTITY_CONFLICT
            return SAME_IDENTITY, None
        same_block = self._c.execute(
            """SELECT EXISTS (
                 SELECT 1 FROM comms.contact_block_entry e
                  WHERE e.block_id = %s AND e.role = 'SELF'
                    AND e.platform_key = %s
                    AND lower(e.durable_value) = lower(%s))""",
            (block["id"], binding["platform_key"],
             binding["durable_value"])).fetchone()[0]
        if same_block:
            return SAME_BLOCK, None
        return None, _NO_HOLDER_LINK

    # -- the check ----------------------------------------------------------

    def verify_and_record(self, *, case_id: UUID, created_by: UUID,
                          clearance: str, compartments: frozenset[str],
                          form: str = CLEARSIGNED,
                          signed_message: str | None = None,
                          signature: bytes | None = None,
                          signed_data: bytes | None = None,
                          data_was_pasted: bool = False,
                          public_key: str | None = None,
                          claimed_fingerprint: str | None = None,
                          claimed_fingerprint_source_ref: str | None = None,
                          pgp_key_id: UUID | None = None,
                          confirms_value: str | None = None,
                          channel_binding_id: UUID | None = None,
                          contact_block_id: UUID | None = None,
                          note: str | None = None) -> dict:
        """Verify, record the outcome, and upgrade the binding IF earned.

        Every outcome is recorded, including the ones that failed and the
        one that means nobody looked. A verification queue you can only
        see the successes of is a queue that hides its own gaps.

        `clearance` and `compartments` are REQUIRED keyword arguments with
        no default (F10-fix, 2026-09-24): the binding, the block and the
        key are loaded under them, and a forgotten argument must fail
        loudly rather than read at the wrong level (collection.py gives
        the same reason for its own). Everything that could refuse runs
        before gpg is forked, and before any message names a value: an
        object the caller may not see is one 404 whatever the reason.
        """
        held = frozenset(compartments)
        if form not in FORMS:
            raise PgpError("a check is CLEARSIGNED or DETACHED")
        claimed = (normalise_fingerprint(claimed_fingerprint)
                   if claimed_fingerprint else None)

        binding = None
        binding_value = None
        if channel_binding_id is not None:
            binding = self._binding(case_id, channel_binding_id,
                                    clearance=clearance, held=held)
            binding_value = binding["durable_value"]
            # The 0037 trigger refuses to confirm a binding with no durable
            # value, and reaching it cost a gpg run and answered an
            # unaudited 500 (2026-09-24). Refused here, first.
            if binding_value is None:
                raise PgpConflict(
                    "No durable form was recorded for this identifier, so a "
                    "signature cannot confirm it.")

        block = None
        if contact_block_id is not None:
            block = self._block(case_id, contact_block_id,
                                clearance=clearance, held=held)

        key = None
        basis = BASIS_STATED
        if pgp_key_id is not None:
            if public_key:
                raise PgpError("name a registry key or paste a key, not both")
            if claimed_fingerprint_source_ref:
                raise PgpError("a registry key carries its own provenance, so "
                               "no source is named for its fingerprint")
            key = self._registry_key(case_id, pgp_key_id, clearance=clearance,
                                     held=held)
            if claimed is not None and claimed != key["fingerprint"]:
                raise PgpError("the fingerprint named is not the chosen key's")
            claimed = key["fingerprint"]
            basis = BASIS_CONFIRMED_KEY
            # A key confirmed against a contact block line brings that
            # block as the attribution block when the body cites none, and
            # the row cites it (the trigger requires it).
            if (block is None and binding is not None
                    and key["confirmation_block_id"] is not None):
                try:
                    block = self._block(case_id, key["confirmation_block_id"],
                                        clearance=clearance, held=held)
                except PgpNotFound:
                    block = None
        elif claimed is None:
            raise PgpError("name the fingerprint the signature should be made by")

        if binding is not None:
            # Labels run block <= key <= binding (F10b): a binding is never
            # confirmed on material its readers may not see.
            labels = (binding["classification"], binding["compartments"])
            if key is not None and not _labels_within(
                    (key["classification"], key["compartments"]), labels):
                raise PgpConflict(
                    f"this key is filed at TLP:{key['classification']}, above "
                    f"the binding it would confirm; a binding is never "
                    f"confirmed on material its readers may not see.")
            if block is not None and not _labels_within(
                    (block["classification"], block["compartments"]), labels):
                raise PgpConflict(
                    f"this contact block is filed at TLP:{block['classification']}, "
                    f"above the binding it would confirm; a binding is never "
                    f"confirmed on material its readers may not see.")
            # Confirming a binding means confirming ITS identifier. Letting
            # the caller name a different one would let a valid signature
            # over selector A upgrade a binding holding selector B. Only
            # now may a message name the value: the caller can see it.
            if confirms_value is None:
                confirms_value = binding_value
            elif confirms_value.strip().lower() != binding_value.lower():
                raise PgpError(
                    f"this verification is offered for {confirms_value!r} but "
                    f"the binding holds {binding_value!r}; a signature over "
                    f"one identifier cannot confirm another")

        material = key["material"] if key is not None else public_key
        if form == CLEARSIGNED:
            if not signed_message:
                raise PgpError("a clearsigned check needs the signed message")
            result = verify_clearsigned(
                signed_message, material or "", claimed_fingerprint=claimed,
                confirms_value=confirms_value)
        else:
            if signature is None or signed_data is None:
                raise PgpError("a detached check needs the signature and the "
                               "data it signs")
            result = verify_detached(
                signature, signed_data, material or "",
                claimed_fingerprint=claimed, confirms_value=confirms_value,
                data_was_pasted=data_was_pasted)

        attribution = None
        if result.outcome == VERIFIED and binding is not None:
            attribution, missing = self._attribution(
                binding=binding, block=block, claimed=claimed,
                primary=result.signing_primary_fingerprint)
            if attribution is None:
                result = replace(
                    result, outcome=UNATTRIBUTED,
                    detail=("The signature is valid, made by the claimed key "
                            "over text naming the identifier. What is missing "
                            "is the link between that key and whoever holds "
                            f"this binding: {missing}. The binding stays "
                            "CLAIMED."))
        cited_block = block["id"] if block is not None else contact_block_id

        # Only digest bytes a signature actually covered. The column is
        # documented as "the exact bytes that were signed", and gpg writes
        # its --output file even when the signature FAILS -- so digesting
        # it unconditionally recorded attacker plaintext under that name.
        digest = (hashlib.sha256(result.signed_payload).digest()
                  if result.signed_payload
                  and result.outcome in _SIGNED_PAYLOAD_OUTCOMES else None)
        with self._c.transaction():
            row = self._c.execute(
                """INSERT INTO comms.pgp_verification
                       (case_id, channel_binding_id, contact_block_id,
                        claimed_fingerprint, signing_fingerprint,
                        confirms_value, signed_payload_sha256,
                        value_in_payload, outcome, verifier, verifier_version,
                        status_output, note, created_by, signature_form,
                        signing_primary_fingerprint, signature_class,
                        pgp_key_id, claimed_fingerprint_basis,
                        claimed_fingerprint_source_ref, attribution)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id, verified_at""",
                (case_id, channel_binding_id, cited_block, claimed,
                 result.signing_fingerprint, confirms_value, digest,
                 result.value_in_payload, result.outcome, result.verifier,
                 result.verifier_version, result.status_output, note,
                 created_by, result.form, result.signing_primary_fingerprint,
                 result.signature_class, pgp_key_id, basis,
                 claimed_fingerprint_source_ref if key is None else None,
                 attribution)).fetchone()
            verification_id, verified_at = row

            upgraded = False
            if result.confirms and channel_binding_id is not None:
                # Only a VERIFIED outcome reaches here, and the schema
                # would refuse the row above if VERIFIED were claimed
                # without a matching fingerprint, an in-payload value and
                # an attributing contact block.
                self._c.execute(
                    """UPDATE comms.channel_binding
                          SET verification = 'CONFIRMED',
                              verification_note = %s
                        WHERE id = %s""",
                    (f"PGP signature by {result.signing_fingerprint} over "
                     f"the identifier, verified "
                     f"{verified_at.isoformat()} (verification "
                     f"{verification_id})", channel_binding_id))
                upgraded = True

            self._audit(case_id, created_by, "PGP_VERIFICATION",
                        verification_id, {
                            "outcome": result.outcome,
                            "form": result.form,
                            "claimed_fingerprint": claimed,
                            "signing_fingerprint": result.signing_fingerprint,
                            "signing_primary_fingerprint":
                                result.signing_primary_fingerprint,
                            "basis": basis,
                            "pgp_key_id": str(pgp_key_id) if pgp_key_id else None,
                            "attribution": attribution,
                            "value_in_payload": result.value_in_payload,
                            "binding_upgraded": upgraded,
                            "verifier": result.verifier,
                        })

        return {
            "id": str(verification_id),
            "outcome": result.outcome,
            "confirms": result.confirms,
            "binding_upgraded": upgraded,
            "form": result.form,
            "claimed_fingerprint": claimed,
            "claimed_fingerprint_basis": basis,
            "pgp_key_id": str(pgp_key_id) if pgp_key_id else None,
            "signing_fingerprint": result.signing_fingerprint,
            "signing_primary_fingerprint": result.signing_primary_fingerprint,
            "signature_class": result.signature_class,
            "contact_block_id": str(cited_block) if cited_block else None,
            "attribution": attribution,
            "value_in_payload": result.value_in_payload,
            "verifier": result.verifier,
            "verifier_version": result.verifier_version,
            "detail": result.detail,
            "verified_at": verified_at.isoformat(),
        }

    # -- reads --------------------------------------------------------------

    def verifications(self, case_id: UUID, *, clearance: str,
                      compartments: frozenset[str] = frozenset()
                      ) -> list[dict]:
        """The verification ledger for a case.

        `comms.pgp_verification` carries no labels of its own -- but it
        carries `confirms_value`, which IS the identifier held by the
        binding it cites, and a binding can be classified above its case.
        So a listing filtered only by case handed an under-cleared reader
        the durable value of a RED binding through a table that looked
        label-free. A row is shown when everything it cites is visible
        (`_VISIBLE_VERIFICATION`).
        """
        rows = self._c.execute(
            f"""SELECT v.id, v.channel_binding_id, v.contact_block_id,
                       v.claimed_fingerprint, v.signing_fingerprint,
                       v.confirms_value, v.value_in_payload, v.outcome,
                       v.verifier, v.verifier_version, v.note, v.verified_at,
                       v.signature_form, v.signing_primary_fingerprint,
                       v.signature_class, v.pgp_key_id,
                       v.claimed_fingerprint_basis,
                       v.claimed_fingerprint_source_ref, v.attribution
                  FROM comms.pgp_verification v
                 WHERE v.case_id = %(case)s
                   AND {_VISIBLE_VERIFICATION}
                 ORDER BY v.verified_at DESC, v.id DESC""",
            {"case": case_id, "clearance": clearance,
             "held": sorted(compartments)}).fetchall()
        return [{"id": str(r[0]),
                 "channel_binding_id": str(r[1]) if r[1] else None,
                 "contact_block_id": str(r[2]) if r[2] else None,
                 "claimed_fingerprint": r[3], "signing_fingerprint": r[4],
                 "confirms_value": r[5], "value_in_payload": r[6],
                 "outcome": r[7], "verifier": r[8], "verifier_version": r[9],
                 "note": r[10], "verified_at": r[11].isoformat(),
                 "form": r[12], "signing_primary_fingerprint": r[13],
                 "signature_class": r[14],
                 "pgp_key_id": str(r[15]) if r[15] else None,
                 "claimed_fingerprint_basis": r[16],
                 "claimed_fingerprint_source_ref": r[17],
                 "attribution": r[18]}
                for r in rows]

    def unverified_claims(self, case_id: UUID, *, clearance: str,
                          compartments: frozenset[str] = frozenset()
                          ) -> list[dict]:
        """CLAIMED bindings, and what the reader may see of their checks.

        The queue that exists because `NO_VERIFIER` is a distinct outcome:
        without it, "not confirmed" and "not checked" look identical, and
        an analyst reads an unchecked claim as a checked-and-failed one.

        `verification_attempted` and the last outcome come from checks
        the READER may see (`_VISIBLE_VERIFICATION`, F10-fix 2026-09-24): a
        check citing a block above them reads to them as no check, which
        is the truth about what they can see and no oracle.
        """
        rows = self._c.execute(
            f"""SELECT cb.id, cb.platform_key, cb.observed_value,
                       cb.durable_value, cb.verification,
                       last.outcome, last.verified_at
                  FROM comms.channel_binding cb
                  LEFT JOIN LATERAL (
                       SELECT v.outcome, v.verified_at
                         FROM comms.pgp_verification v
                        WHERE v.channel_binding_id = cb.id
                          AND {_VISIBLE_VERIFICATION}
                        ORDER BY v.verified_at DESC, v.id DESC
                        LIMIT 1) last ON true
                 WHERE cb.case_id = %(case)s AND cb.verification = 'CLAIMED'
                   -- This returns observed AND durable values, so it is a
                   -- read of the binding's content and not merely of its
                   -- existence: the binding's own labels apply.
                   AND cb.classification <= %(clearance)s::core.tlp
                   AND cb.compartments <@ %(held)s::text[]
                 ORDER BY cb.created_at DESC""",
            {"case": case_id, "clearance": clearance,
             "held": sorted(compartments)}).fetchall()
        return [{"channel_binding_id": str(r[0]), "platform_key": r[1],
                 "observed_value": r[2], "durable_value": r[3],
                 "verification": r[4],
                 "verification_attempted": r[5] is not None,
                 "last_outcome": r[5],
                 "last_verified_at": r[6].isoformat() if r[6] else None,
                 "confirmable": r[3] is not None,
                 "note": ("a CLAIM nobody has attempted to confirm"
                          if r[5] is None else
                          "a CLAIM that has been checked and not confirmed")}
                for r in rows]

    def _audit(self, case_id: UUID, actor_id: UUID, action: str,
               object_id: UUID, detail: dict, *,
               object_type: str = "pgp_verification",
               outcome: str = "SUCCESS") -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, outcome, detail)
               VALUES (%s, 'USER', %s, %s, %s, %s, %s, %s)""",
            (actor_id, action, object_type, object_id, case_id, outcome,
             Json(detail)))
