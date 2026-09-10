"""Phase 8 -- malware sample handling (docs/11, invariant 10).

=====================================================================
COUNSEL MUST REVIEW A DEPLOYMENT OF THIS BEFORE IT IS USED IN ANY
ABSOLUTE SENSE.

Built on an operator directive of 2026-07-25 which supersedes decision
36's block. That block was never about the code. It was about the fact
that a store of attacker-supplied binaries WILL eventually receive
material whose possession alone is an offence; that the handling rules
differ between the two jurisdictions this platform targets (decision 13:
US and Canada); and that discovering that after the first ingest is a
legal problem rather than a technical one.

This module cannot fix that and does not pretend to. What it does is
refuse to accept anything until an operator has declared, in the
environment, that a prohibited-content policy exists and names a
designated person -- see `policy_declared()`. The declaration is a
statement by the operator, not a verification by the software. A false
declaration produces a working system and an unlawful deployment.
=====================================================================

## Invariant 10, enforced rather than documented

    Samples never render, never execute. The binary is only ever an
    encrypted archive download from a SEPARATE ORIGIN.

The origin split is usually written down and then forgotten at deploy
time, so it is a runtime check here, and the check is CONFIGURATION,
never a request header. Three origins decide it (`origin_split()`):

- `NOCTORNAL_SAMPLE_ORIGIN` -- the origin sample bytes are served from;
- `NOCTORNAL_BASE_URL` -- the application origin, the one the console is
  served from and email links point at (`transports.base_url()`);
- `NOCTORNAL_PUBLIC_ORIGIN` -- the origin THIS process is served at. It
  defaults to the application origin, so a process that says nothing is
  the application and refuses.

`download()` serves bytes only on a process configured as the sample
origin, and only when that origin is a real second origin rather than a
second name for the application's. Everywhere else it refuses and names
the origin to fetch from. Serving hostile bytes from the same origin as
the case file means an escape -- a crafted filename, an SVG preview, a
PDF renderer bug -- runs with the analyst's session on the case data.
docs/11: "you would have built a drive-by vector into your own
highest-trust system, seeded with hostile files by design."

**Until 2026-09-09 the check compared `NOCTORNAL_SAMPLE_ORIGIN` against
`request.url`, which Starlette builds from the Host header -- a value the
client sends.** A caller who set `Host: samples.example` on a request to
the application origin passed it, and behind a proxy that rewrote Host
nobody passed it. It was also unsatisfiable from the console: the UI's
CSP was `connect-src 'self'`, so the Lab pane could only ever fetch the
application origin, which meant the variable was either equal to the
application origin (the check a no-op, bytes served from the origin the
invariant forbids, "invariant 10 holds" in every document) or the Lab
pane could not download at all. The two halves were internally
consistent and wrong together. Now the UI CSP names the sample origin,
the sample process answers the console's cross-origin request, and the
verdict comes from the three variables above.

**What crosses to that origin is a TICKET, not a session** (0061). The
cookie pair is `__Host-` prefixed and `SameSite=strict`, so none of it
can reach the sample origin -- that is the point of the split -- and the
console therefore forced the login-body token there as a Bearer: a
standing session credential, held in page memory, posted to a second
origin, on the one path that puts working malware on somebody's disk.
`issue_download_ticket` replaces it. The ticket is minted on the
APPLICATION origin under the ordinary cookie session (so the
`x-csrf-token` double-submit applies), is good for one sample and one
redemption within `DOWNLOAD_TICKET_TTL_SECONDS`, and carries no standing
authority: what it buys is the archive the analyst was already
downloading. Nor does it outlive the authority it was minted under -- the
redemption re-reads the holder's ACCOUNT (active, still holding
`sample.download`) and their live clearance before a byte moves, so a
revocation inside the window bites. The session behind the mint is the
one thing not re-derived there, and 0061 says exactly that. The Bearer
path still works; removing it is a later step.

**When `NOCTORNAL_SAMPLE_ORIGIN` is unset the control is OFF**, and the
readiness register, the router docstring and `GET /samples/policy` all
say so in those words: every download refuses, on every process, and no
document may claim the invariant holds for such a deployment.

Three more rules the code holds:

- **The object key is the SHA-256, never the filename.** Original
  filenames are attacker-controlled and are themselves a payload vector
  (`../../etc/cron.d/x`, a right-to-left override, a 4KB name). The
  original is kept in a column for the record and never used as a path.
- **Nothing is stored as an executable.** Every sample is encrypted at
  rest under a per-sample key. Besides containment, this is what stops
  your own EDR quarantining the evidence -- docs/11 calls that a routine
  and embarrassing failure in labs that skip it.
- **Quarantine is the landing state.** Nothing reaches the RE queue
  before triage has run.

## What the archive password does and does not do

The convention is a ZIP with the password `infected`. It DOES prevent
accidental double-click execution and stop mail gateways and EDR from
silently eating the sample in transit. It provides NO confidentiality --
the password is public and ZipCrypto is broken. Confidentiality comes
from access control, transport and audit. The password must never be
allowed to create a false sense of protection, so `archive()` says so in
the archive comment itself.

## What is NOT built, and is not pretended

- **No YARA, no ssdeep, no imphash, no Rich header.** Each needs a
  dependency (`yara-python`, `ssdeep`, `pefile`) and ssdeep needs a C
  toolchain. What IS computed is recorded; what is not is recorded as a
  GAP on the row, because a NULL imphash that reads as "this sample has
  no imports" is worse than an absent one that says why.
- **No detonation.** The record exists and the authorisation constraint
  is real; nothing submits to a sandbox. docs/11 is emphatic that you
  integrate rather than build one.
- **No prohibited-content hash screening.** The hook and the REJECTED
  path exist. The hash sets do not, and in most jurisdictions holding
  them requires authorisation this deployment does not have.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import logging
import math
import os
import secrets
import struct
import threading
import time
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlsplit
from uuid import UUID

import psycopg
from psycopg.types.json import Json

# The one existing spelling of "does this ACTIVE account hold this global
# permission", used at redemption. See `_still_authorised`.
from noctornal_api.iam_admin import IamAdminService
from noctornal_api.security import envelope
from noctornal_api.security.access import AccessResolutionError, tlp_from_name
# The one spelling of "hash an opaque token" in this codebase. A download
# ticket is the same kind of secret as a session token -- high-entropy,
# presented once, stored only as its digest -- and giving it a second
# hashing function would mean two places to get the encoding wrong.
from noctornal_api.security.tokens import hash_token

log = logging.getLogger("noctornal.samples")

SUBMITTED = "SUBMITTED"
QUARANTINED = "QUARANTINED"
TRIAGED = "TRIAGED"
ASSIGNED = "ASSIGNED"
IN_ANALYSIS = "IN_ANALYSIS"
REPORTED = "REPORTED"
REJECTED = "REJECTED"

#: The industry convention (MalwareBazaar, VirusShare, malware-traffic).
#: It is a safety interlock, not a secret.
ARCHIVE_PASSWORD = b"infected"

#: 256 MB. A sample larger than this is a disk image or a mistake, and
#: either way it does not belong in a quarantine queue behind an HTTP
#: request.
MAX_SAMPLE_BYTES = 256 * 1024 * 1024

#: How long a download ticket is good for (0061).
#:
#: Sixty seconds, and the number is chosen against what the ticket
#: actually spans: the gap between two requests ONE browser makes back to
#: back -- mint on the application origin, then redeem on the sample
#: origin -- with a preflight and a click's worth of latency between them.
#: It is not a session and must not be sized like one. The generous
#: reading of that gap is a slow link and a busy laptop, which is seconds;
#: sixty leaves an order of magnitude of headroom and still means a ticket
#: copied out of a proxy log or a crash dump is inert by the time anybody
#: reads it. The other half of the bound is that the ticket is single-use,
#: so the window is not "how long is it valid" but "how long may it sit
#: unused before the analyst has to click again".
DOWNLOAD_TICKET_TTL_SECONDS = 60

#: The verb both doors into a sample's bytes state, in ONE place because
#: two of them now read it: `routers/samples.py` gates the download and
#: the mint on it through `require_global`, and the redemption re-reads it
#: on the sample origin (`_still_authorised`). Two spellings of the key
#: would mean a permission renamed in the seed silently ungating one door
#: while the other kept refusing.
DOWNLOAD_PERMISSION = "sample.download"

#: The refusal reason, from `_ticket_refusal`, that names nobody: a
#: presented string that matched no row at all. It is the one refusal an
#: unauthenticated caller can produce on demand, and it is therefore the
#: one that is counted rather than written down. Named rather than
#: repeated so the producer and the consumer cannot drift.
_UNKNOWN_TICKET = "unknown_ticket"

#: What EVERY refused redemption says, whatever the reason. One string,
#: used by every raise on that path, because the whole point is that a
#: caller cannot tell the four ticket-state refusals from each other or
#: from the account one: "already redeemed" would tell the holder of a
#: stolen ticket that it was real and that somebody else got there first.
#: It enumerates the possibilities instead, so a legitimate analyst is not
#: sent looking at the wrong one, and the audit records which it was.
_TICKET_REFUSED = (
    "this download ticket is not valid: it has been used, it has expired, "
    "it was not issued for this sample, or the account it was issued to "
    "may no longer download samples. Tickets are good for one download "
    f"within {DOWNLOAD_TICKET_TTL_SECONDS} seconds -- ask the console for "
    "another."
)

#: How often the unknown-ticket warning may be written, in seconds. The
#: peer chooses how often that event happens, so a line per event lets the
#: peer choose how fast the log grows -- the same reasoning, and the same
#: mechanism, as the pre-accept refusal sampler in `routers/live.py`.
_UNKNOWN_TICKET_LOG_SECONDS = 30.0


class _SampledWarning:
    """At most one log line per window, carrying the count of everything
    the window swallowed, so an operator reads "412 since the last line"
    rather than 412 lines.

    A deliberate second, smaller copy of the class in
    `http/routers/live.py`. A service module must not import a router --
    the dependency runs the other way and closing that loop for a
    twelve-line helper would be the wrong trade -- and the shared home for
    it is a new module, which is a change to make on purpose rather than
    inside a security fix. `threading.Lock` because the ASGI threadpool
    runs these handlers on more than one thread.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: float | None = None
        self._since = 0

    def note(self) -> int | None:
        """Count one event. Returns how many the due line stands for -- on
        the first ever, and on the first after each window -- and None when
        this one is to be swallowed into the next line's count."""
        now = time.monotonic()
        with self._lock:
            self._since += 1
            if (self._last is not None
                    and now - self._last < _UNKNOWN_TICKET_LOG_SECONDS):
                return None
            self._last = now
            n, self._since = self._since, 0
            return n


_unknown_tickets = _SampledWarning()


class SampleError(Exception):
    pass


class PolicyNotDeclared(SampleError):
    """Raised when nothing has been ingested because nobody has said the
    prohibited-content policy exists."""


def policy_declared() -> tuple[bool, str]:
    """Has an operator declared a prohibited-content policy?

    Two environment variables, both required:

    - `NOCTORNAL_PROHIBITED_CONTENT_POLICY` -- a reference an auditor can
      follow. A document id, a ticket, a URL. Not a boolean, because
      "true" is what somebody types to make an error go away and a
      reference is what somebody has to actually possess.
    - `NOCTORNAL_DESIGNATED_PERSON` -- who material is escalated to.
      docs/11 is specific that the response to prohibited material is a
      documented procedure with a named person, not a product feature.

    This is a DECLARATION, not a verification. The software cannot check
    that the referenced policy exists, is correct, or has been read by
    anyone. What it can do is refuse to make ingesting a one-click
    accident, and put the operator's own reference in the audit trail so
    that "nobody knew" is not available afterwards.
    """
    reference = os.environ.get("NOCTORNAL_PROHIBITED_CONTENT_POLICY", "").strip()
    person = os.environ.get("NOCTORNAL_DESIGNATED_PERSON", "").strip()
    if not reference or not person:
        return False, (
            "sample ingest is refused until an operator declares a "
            "prohibited-content policy: set "
            "NOCTORNAL_PROHIBITED_CONTENT_POLICY to a reference an auditor "
            "can follow, and NOCTORNAL_DESIGNATED_PERSON to whoever material "
            "is escalated to. Counsel must have written that policy first "
            "(docs/11); this check records the declaration, it cannot verify "
            "it.")
    return True, reference


def sample_origin() -> str:
    """The separate origin sample bytes may be served from, as configured.

    Empty means "not configured", and `download()` then refuses. That is
    invariant 10 as a runtime check rather than a deployment note: an
    origin split that is only ever written down is an origin split that
    does not survive the first hurried deploy.

    This is the raw setting, trailing slash stripped. Whether it is an
    origin at all, and how it stands against the application origin and
    this process's own, is `origin_split()`'s verdict; readers that need a
    decision call that, and this exists so the register can quote what the
    operator actually typed.
    """
    return os.environ.get("NOCTORNAL_SAMPLE_ORIGIN", "").strip().rstrip("/")


#: What `transports.base_url()` falls back to. Restated here rather than
#: imported so this module -- which the HTTP layer imports at startup --
#: does not pull the mail transports in with it; a test reads both and
#: insists they are the same string.
_DEFAULT_APP_ORIGIN = "http://127.0.0.1:8000"


def app_origin() -> str:
    """The application origin, as configured: `NOCTORNAL_BASE_URL`, the
    variable email links are already built from. A deployment has exactly
    one console origin and that variable is where it is written down."""
    return os.environ.get("NOCTORNAL_BASE_URL", _DEFAULT_APP_ORIGIN).strip().rstrip("/")


def public_origin() -> str:
    """The origin THIS process is served at: `NOCTORNAL_PUBLIC_ORIGIN`,
    defaulting to the application origin.

    The default is the safe direction. A process that does not say which
    origin it is serving is taken to be the application, and the
    application refuses to hand over sample bytes -- so forgetting the
    variable on the sample process produces a refusal that names what to
    set, and forgetting it on the application changes nothing.
    """
    return (os.environ.get("NOCTORNAL_PUBLIC_ORIGIN", "").strip().rstrip("/")
            or app_origin())


def normalise_origin(value: str, *, allow_path: bool = False) -> str | None:
    """`scheme://host[:port]`, lower-cased, default port dropped -- or
    None when the value is not an http(s) origin.

    One normaliser, because the split is decided by string EQUALITY and
    three readers (the download, the UI's CSP and the cross-origin
    answer) must agree on what "the same origin" means. `allow_path`
    exists for the application origin: `NOCTORNAL_BASE_URL` may carry a
    path prefix for a deployment mounted under one, and its ORIGIN is
    what the split compares. The sample origin may not: a path there
    would make the console's download URL and the CSP source both
    path-specific, and "an origin with a path" is exactly the
    `app.internal/samples` shape docs/11 says is not a separate origin.
    """
    parts = urlsplit(value.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if not allow_path and (parts.path not in ("", "/") or parts.query
                           or parts.fragment):
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if not host:
        return None
    if ":" in host:              # IPv6 literal: hostname strips the brackets
        host = f"[{host}]"
    default = 443 if parts.scheme == "https" else 80
    suffix = f":{port}" if port and port != default else ""
    return f"{parts.scheme}://{host}{suffix}"


@dataclass(frozen=True)
class OriginSplit:
    """The three origins invariant 10 turns on, normalised, and the
    verdict they give for THIS process.

    `role` is one of:

    - `unconfigured` -- `NOCTORNAL_SAMPLE_ORIGIN` is unset: the control is
      OFF and every download refuses everywhere;
    - `invalid` -- it is set but is not an origin;
    - `same_origin` -- it names the application origin: two names for one
      origin is not a split, and the download refuses rather than serve
      hostile bytes from the origin the invariant forbids;
    - `app` -- this process is the application: it refuses and names the
      sample origin to fetch from;
    - `sample` -- this process is the sample origin: it serves.

    `refusal` is why `download()` refuses on this process, or None when it
    serves. `split_problem` is the subset of refusals that are about the
    DEPLOYMENT rather than about which process this is -- what the
    register and the policy endpoint report, and what the console shows
    instead of a download button.
    """

    role: str
    sample: str | None
    app: str | None
    this: str | None
    refusal: str | None

    @property
    def serves_here(self) -> bool:
        return self.refusal is None

    @property
    def split_problem(self) -> str | None:
        if self.role in ("unconfigured", "invalid", "same_origin"):
            return self.refusal
        return None


def origin_split(*, this: str | None = None) -> OriginSplit:
    """Decide the origin split from configuration alone.

    `this` overrides `public_origin()`; the service tests use it to stand
    a call on one process or the other without an environment. Nothing in
    the HTTP layer passes it -- the router used to pass the Host header
    here, which is the defect this function replaced.
    """
    raw_sample = sample_origin()
    raw_app = app_origin()
    raw_this = this if this is not None else public_origin()
    app = normalise_origin(raw_app, allow_path=True)
    this_origin = normalise_origin(raw_this, allow_path=True)

    if not raw_sample:
        return OriginSplit(
            "unconfigured", None, app, this_origin,
            "sample downloads are refused: NOCTORNAL_SAMPLE_ORIGIN is not "
            "configured, so there is no separate origin to serve hostile "
            "bytes from and the origin split is OFF. Invariant 10 is not a "
            "deployment suggestion.")
    sample = normalise_origin(raw_sample)
    if sample is None:
        return OriginSplit(
            "invalid", None, app, this_origin,
            f"sample downloads are refused: NOCTORNAL_SAMPLE_ORIGIN="
            f"{raw_sample!r} is not an origin. It must be scheme://host[:port] "
            f"with no path, query or credentials -- a path is a location on "
            f"an origin, not an origin, and docs/11 is explicit that "
            f"app.internal/samples is not separate from app.internal.")
    if app is not None and sample == app:
        return OriginSplit(
            "same_origin", sample, app, this_origin,
            f"sample downloads are refused: NOCTORNAL_SAMPLE_ORIGIN equals "
            f"the application origin ({app}, from NOCTORNAL_BASE_URL). Two "
            f"names for one origin is not a split, and serving hostile bytes "
            f"there is the drive-by vector invariant 10 exists to prevent. "
            f"Give samples their own host.")
    if this_origin != sample:
        return OriginSplit(
            "app", sample, app, this_origin,
            f"sample bytes are served only from the configured sample origin, "
            f"never from the application origin: fetch this download from "
            f"{sample}. This process is configured as "
            f"{this_origin or raw_this!r} (NOCTORNAL_PUBLIC_ORIGIN, or "
            f"NOCTORNAL_BASE_URL when that is unset).")
    return OriginSplit("sample", sample, app, this_origin, None)


def download_cors_headers(origin_header: str | None) -> dict[str, str]:
    """The headers that let the console on the APPLICATION origin read a
    download from THIS process -- when this process is the sample origin
    and the request's `Origin` is the application's. Empty otherwise.

    The allowed origin is the CONFIGURED application origin, never an echo
    of the header: a page on any other origin gets no
    `Access-Control-Allow-Origin` and the browser withholds the response.
    No `Access-Control-Allow-Credentials`, so no cookie ever crosses --
    which is why the console proves itself there with something that is
    neither: a one-shot download ticket in the FORM BODY (0061), minted
    on the application origin under the cookie session. It carried a
    Bearer until 2026-09-10, and that is the credential this comment used
    to name. The redemption sends no header of its own at all, because
    one outside the CORS safelist would make it a preflighted request and
    `app._preflight` admits `authorization` alone.

    Exists at all because a CSP that names the sample origin is only half
    of letting the Lab pane download: without this answer the browser
    performs the request and then refuses to show the page the bytes, and
    the pane reports "the request did not complete" for a download the
    server served. The two halves live in one module so they cannot drift.
    """
    split = origin_split()
    if not split.serves_here or split.app is None:
        return {}
    if normalise_origin(origin_header or "") != split.app:
        return {}
    return {
        "Access-Control-Allow-Origin": split.app,
        "Access-Control-Expose-Headers":
            "Content-Disposition, X-Sample-Archive-Password",
        "Vary": "Origin",
    }


# ---------------------------------------------------------------------------
# Static triage -- pure, no I/O, no execution
# ---------------------------------------------------------------------------

#: Magic bytes, longest first so a prefix cannot shadow a longer match.
#: Typed by STRUCTURE, never by extension: the extension is part of the
#: attacker's message, and `invoice.pdf.exe` is the oldest trick there is.
_MAGIC: list[tuple[bytes, str]] = [
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/MZ"),
    (b"\xca\xfe\xba\xbe", "Mach-O universal"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32"),
    (b"PK\x03\x04", "ZIP or OOXML"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"\x1f\x8b", "gzip"),
    (b"%PDF-", "PDF"),
    (b"\xd0\xcf\x11\xe0", "OLE compound (legacy Office)"),
    (b"#!", "script with shebang"),
]


@dataclass(frozen=True)
class Triage:
    """What static triage established, and what it could not.

    `gaps` is not decoration. A NULL imphash reads as "this sample has no
    imports"; a recorded gap reads as "nobody looked". Invariant 12 is
    about ingest, but the principle is the same -- an absence with no
    reason is indistinguishable from a finding.
    """

    sha256: bytes
    sha1: bytes
    md5: bytes
    byte_size: int
    file_type: str
    entropy: float
    gaps: list[dict] = field(default_factory=list)


def shannon_entropy(data: bytes) -> float:
    """Bits per byte. Above ~7.2 means packed, encrypted or compressed --
    which is a triage signal, not a verdict."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return -sum((c / size) * math.log2(c / size) for c in counts if c)


def file_type_of(data: bytes) -> str:
    for magic, label in _MAGIC:
        if data.startswith(magic):
            return label
    return "unknown"


def triage(data: bytes) -> Triage:
    """Static only. Nothing here executes, parses a container, or
    expands an archive.

    Archive expansion is deliberately absent: docs/11 asks for it with
    depth and expansion-ratio caps, and an uncapped expander is a zip
    bomb waiting for someone to send one. Building the capped version is
    real work and the honest thing is to record its absence rather than
    ship the uncapped one.
    """
    gaps = [
        {"step": "imphash", "reason": "pefile is not a dependency"},
        {"step": "rich_header_hash", "reason": "pefile is not a dependency"},
        {"step": "ssdeep", "reason": "ssdeep needs a C toolchain"},
        {"step": "tlsh", "reason": "py-tlsh is not a dependency"},
        {"step": "yara", "reason": "no rule corpus and no yara-python"},
        {"step": "archive_expansion",
         "reason": "not built: an expander without depth and ratio caps is a "
                   "zip bomb waiting to be sent one"},
        {"step": "prohibited_content_screening",
         "reason": "no authorised hash set; the REJECTED path is manual"},
    ]
    return Triage(
        sha256=hashlib.sha256(data).digest(),
        sha1=hashlib.sha1(data).digest(),
        md5=hashlib.md5(data).digest(),
        byte_size=len(data),
        file_type=file_type_of(data),
        entropy=round(shannon_entropy(data), 4),
        gaps=gaps,
    )


#: Traditional PKWARE ("ZipCrypto") key schedule. Not a security
#: primitive here and not treated as one -- see `archive()`.
_ZC_KEYS = (0x12345678, 0x23456789, 0x34567890)


#: The standard CRC-32 table, derived rather than pasted so it cannot be
#: subtly wrong in a way nobody reads.
_ZC_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _ZC_TABLE.append(_c)


def _zc_crc32(byte: int, crc: int) -> int:
    return (crc >> 8) ^ _ZC_TABLE[(crc ^ byte) & 0xFF]


class _ZipCrypto:
    """The traditional ZIP cipher, for the `infected` convention.

    **This is not confidentiality and is not used as any part of a
    security control.** ZipCrypto is broken by a known-plaintext attack
    older than most of the people who will read this, and the password is
    printed in the archive comment and in a response header. Its two jobs,
    which are the two docs/11 asks for, are mechanical:

      1. an interlock, so a live binary cannot be double-clicked out of a
         file manager without an explicit step;
      2. an opaque container, so the lab's OWN endpoint protection and mail
         gateway do not quarantine the sample in transit -- the "routine
         and embarrassing failure" this module's docstring names.

    Confidentiality of a sample comes from the access gate and the
    envelope encryption at rest, neither of which this touches.

    Written out because Python's `zipfile` **cannot write encrypted
    entries at all** -- `setpassword()` is decrypt-only. The previous
    version of `archive()` believed otherwise, produced a plain DEFLATE
    entry with the encryption bit clear, and shipped an archive comment
    telling the analyst a password protected it. Round-tripped in the
    tests through Python's own decryptor, which is the strongest available
    check that this is the real format and not a plausible-looking one.
    """

    def __init__(self, password: bytes):
        self.k = list(_ZC_KEYS)
        for byte in password:
            self._update(byte)

    def _update(self, byte: int) -> None:
        k0, k1, k2 = self.k
        k0 = _zc_crc32(byte, k0)
        k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
        k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
        k2 = _zc_crc32(k1 >> 24, k2)
        self.k = [k0, k1, k2]

    def _stream_byte(self) -> int:
        temp = (self.k[2] | 2) & 0xFFFF
        return ((temp * (temp ^ 1)) >> 8) & 0xFF

    def encrypt(self, plain: bytes) -> bytes:
        out = bytearray(len(plain))
        for i, byte in enumerate(plain):
            out[i] = byte ^ self._stream_byte()
            self._update(byte)
        return bytes(out)


def archive(data: bytes, sha256_hex: str,
            password: bytes = ARCHIVE_PASSWORD) -> bytes:
    """Wrap the sample so it cannot be double-clicked into running.

    Named for its hash, not its original filename -- the name is
    attacker-controlled and the archive is the last place it should
    reappear. The comment states plainly what the password is worth,
    because the single commonest mistake with this convention is treating
    it as confidentiality.

    **This produced a PLAIN ZIP until 2026-07-26.** The old docstring
    said "Python's zipfile writes ZipCrypto", which is false in the
    direction that matters: `zipfile` reads encrypted entries and cannot
    write them. `ARCHIVE_PASSWORD` was defined, exported in `__all__`, and
    referenced by nothing. The entry carried flag bits 0x0000 and opened
    with no prompt in Explorer, 7-Zip, a mail gateway or an EDR agent --
    while the archive comment and the `X-Sample-Archive-Password` header
    both told the analyst a password protected it. Invariant 10 says the
    binary is only ever an *encrypted* archive download; it was not one.

    The ZIP is built by hand because there is no stdlib API for this. The
    fields that matter and are easy to get wrong:

    - flag bit 0 set (encrypted), and **bit 3 NOT set**: with a data
      descriptor the check byte comes from the mod-time instead of the
      CRC, and readers disagree about which;
    - the 12-byte encryption header's LAST byte must equal the high byte
      of the entry's CRC-32, which is how a reader recognises a wrong
      password;
    - the CRC is over the PLAINTEXT, the sizes are of the ENCRYPTED
      stream, and compression happens before encryption.
    """
    name = f"{sha256_hex}.bin".encode("ascii")
    crc = zlib.crc32(data) & 0xFFFFFFFF
    deflated = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = deflated.compress(data) + deflated.flush()

    cipher = _ZipCrypto(password)
    # Eleven random bytes and the CRC check byte. `secrets` rather than
    # `random`: the header is not a secret, but a predictable one makes a
    # known-plaintext attack on a weak cipher completely free, and there is
    # no reason to hand that over.
    header = bytearray(secrets.token_bytes(11))
    header.append((crc >> 24) & 0xFF)
    payload = cipher.encrypt(bytes(header)) + cipher.encrypt(body)

    # Fixed timestamp: the archive is content-addressed, and a wall-clock
    # mod-time would make two archives of identical bytes differ.
    dos_time, dos_date = 0, 0x21          # 1980-01-01, the DOS epoch
    flags = 0x0001                        # bit 0: encrypted. NOT bit 3.
    local = struct.pack(
        "<IHHHHHIIIHH", 0x04034B50, 20, flags, 8, dos_time, dos_date,
        crc, len(payload), len(data), len(name), 0) + name
    central = struct.pack(
        "<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, 8, dos_time,
        dos_date, crc, len(payload), len(data), len(name), 0, 0, 0, 0,
        0, 0) + name
    comment = (
        b"NocTORnal sample. Password: infected. This password prevents "
        b"accidental execution and stops scanners eating the file. It is "
        b"PUBLIC and provides NO confidentiality. Handle under the "
        b"classification this was released at."
    )
    offset = len(local) + len(payload)
    end = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central),
                      offset, len(comment))
    return local + payload + central + end + comment


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

class SampleStorage:
    """The sample bucket. docs/11: "Bucket separate from evidence, WORM, no
    public access, no CDN, own credentials."

    Its OWN credentials, deliberately. Reusing the evidence keys would mean
    a compromise of the evidence path reaches the malware store and vice
    versa, and the whole point of a separate bucket is that the two do not
    share a blast radius. `SAMPLE_ACCESS_KEY` falls back to the MinIO ones
    ONLY for a single-node development stack, and says so.
    """

    def __init__(self) -> None:
        from minio import Minio

        endpoint = os.environ.get("SAMPLE_ENDPOINT") or os.environ.get(
            "MINIO_ENDPOINT")
        access = os.environ.get("SAMPLE_ACCESS_KEY") or os.environ.get(
            "MINIO_ACCESS_KEY")
        secret = os.environ.get("SAMPLE_SECRET_KEY") or os.environ.get(
            "MINIO_SECRET_KEY")
        if not (endpoint and access and secret):
            raise SampleError(
                "sample storage is not configured: set SAMPLE_ENDPOINT / "
                "SAMPLE_ACCESS_KEY / SAMPLE_SECRET_KEY (a deployment should "
                "give the sample bucket its own credentials, not the evidence "
                "bucket's)")
        secure = os.environ.get("SAMPLE_SECURE", "false").lower() == "true"
        self._bucket = os.environ.get("SAMPLE_BUCKET", "noctornal-samples")
        self._client = Minio(endpoint, access_key=access, secret_key=secret,
                             secure=secure)

    def put(self, key: str, data: bytes) -> None:
        self._client.put_object(
            self._bucket, key, io.BytesIO(data), length=len(data),
            # Never the real type. Nothing about a sample is ever parsed by
            # anything, and a Content-Type is a hint to parse.
            content_type="application/octet-stream")

    def get(self, key: str) -> bytes:
        response = self._client.get_object(self._bucket, key)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def delete(self, key: str) -> None:
        self._client.remove_object(self._bucket, key)


@dataclass(frozen=True)
class Sample:
    id: UUID
    case_id: UUID | None
    sha256: str
    sha1: str | None
    md5: str | None
    original_filename: str | None
    byte_size: int
    state: str
    reject_reason: str | None
    file_type: str | None
    entropy: float | None
    triage_gaps: list
    submitted_by: UUID
    submitted_at: datetime
    source_note: str | None
    assigned_to: UUID | None
    classification: str
    compartments: frozenset[str]


@dataclass(frozen=True)
class DownloadTicket:
    """What a mint hands back. `raw` exists in this object and in the
    response that carries it, and nowhere else: the row holds
    `hash_token(raw)`, and no audit detail, log line or URL ever repeats
    it (0061).

    `expires_at` comes back from the INSERT rather than being computed
    here, because the expiry is set by the DATABASE clock and compared
    against the database clock at redemption. A Python `datetime.now()`
    would introduce a second clock into a sixty-second window, which is
    how a control ends up refusing valid tickets on one host and
    accepting expired ones on another.
    """

    id: UUID
    raw: str
    sample_id: UUID
    user_id: UUID
    expires_at: datetime


def new_download_ticket() -> str:
    """256 bits, URL-safe, from the CSPRNG -- the same construction as a
    session token, because a ticket is guessed the same way one is."""
    return secrets.token_urlsafe(32)


class SampleService:
    """Storage is injected so the tests exercise the state machine, the
    encryption and the custody ledger without MinIO -- and so the
    quarantine path is provable without a bucket full of live malware."""

    def __init__(self, conn: psycopg.Connection, storage=None):
        self._c = conn
        self._storage = storage

    # -- ingest ------------------------------------------------------------

    def submit(self, data: bytes, *, submitted_by: UUID,
               case_id: UUID | None = None,
               original_filename: str | None = None,
               source_note: str | None = None,
               classification: str = "AMBER",
               compartments: frozenset[str] = frozenset(),
               visible_to_clearance: str | None = None,
               visible_to_compartments: frozenset[str] = frozenset(),
               ) -> Sample:
        """Land a sample in QUARANTINE, run static triage, encrypt at rest.

        Refuses outright unless a prohibited-content policy has been
        declared. That refusal is the whole reason this phase was blocked,
        and it stays enforced rather than becoming a comment.

        `visible_to_*` are the SUBMITTER's labels, and they are used for
        exactly one thing: deciding how much the duplicate refusal is
        allowed to say. They default to None, which means "say nothing" —
        the conservative direction, so a caller that omits them leaks
        nothing rather than everything. That is the opposite of how
        `queue()` and `download()` treated their clearance argument before
        F19, and deliberately so.
        """
        declared, detail = policy_declared()
        if not declared:
            raise PolicyNotDeclared(detail)
        if not data:
            raise SampleError("an empty submission is not a sample")
        if len(data) > MAX_SAMPLE_BYTES:
            raise SampleError(
                f"sample exceeds {MAX_SAMPLE_BYTES} bytes; a submission that "
                f"large is a disk image or a mistake")
        # Validated HERE, before anything is written anywhere. The router
        # takes `classification` as an unconstrained `Form(...)` string and
        # it lands in a `core.tlp` column, so a typo used to surface as a
        # psycopg DataError from inside the INSERT -- which, under the old
        # ordering, was AFTER the bytes had already gone to the object
        # store. A label the system cannot parse is a bad request, not a
        # database error.
        try:
            tlp_from_name(classification)
        except AccessResolutionError as exc:
            raise SampleError(str(exc)) from exc

        # THE CASE'S FLOOR, APPLIED (F19, 2026-07-26).
        #
        # `lab.sample` is the one labelled table with no `enforce_tlp_floor`
        # trigger -- core.node, core.edge and core.evidence all have one --
        # and the router's `classification` is a `Form(...)` defaulting to
        # AMBER. So an analyst attaching the dropper from a RED,
        # compartmented case and touching nothing else produced a row at
        # AMBER with no compartments, and every read that consulted the
        # sample's own labels handed it to anybody with AMBER clearance.
        #
        # RAISED rather than refused. Refusing would mean an analyst who
        # left a form field alone gets an error instead of a safe default,
        # and the safe direction here is unambiguous. Migration 0043
        # attaches the floor trigger as the backstop for anything that does
        # not come through this method.
        if case_id is not None:
            case = self._c.execute(
                'SELECT classification, compartments FROM core."case" '
                "WHERE id = %s", (case_id,)).fetchone()
            if case is None:
                raise SampleError("no such case")
            classification = max(tlp_from_name(classification),
                                 tlp_from_name(case[0])).name
            compartments = frozenset(compartments) | frozenset(case[1] or [])

        result = triage(data)
        digest_hex = result.sha256.hex()

        existing = self._c.execute(
            """SELECT s.id, greatest(s.classification,
                                     coalesce(c.classification,
                                              s.classification)),
                      s.compartments || coalesce(c.compartments, '{}')
                 FROM lab.sample s
                 LEFT JOIN core."case" c ON c.id = s.case_id
                WHERE s.sha256 = %s""", (result.sha256,)).fetchone()
        if existing is not None:
            # Deduplication on content, exactly like evidence. Two analysts
            # finding the same binary is a finding about the actors, not a
            # reason for two copies of live malware.
            #
            # But the refusal is an EXISTENCE ORACLE, and it was answering
            # for everybody (F19). The submitter obviously knows the hash —
            # they hold the file. What the message discloses is that THIS
            # DEPLOYMENT already holds it, which in a compartmented case is
            # the fact that somebody else is working the same intrusion.
            # Uploading a hash you suspect and reading the error is a cheap
            # probe.
            #
            # So the useful message goes only to a caller who could have
            # seen the existing row anyway, and everybody else gets a
            # refusal that says no more than "not accepted". The caller who
            # may not see it still cannot store a duplicate, which is the
            # behaviour that matters.
            if _may_see(existing[1], existing[2], visible_to_clearance,
                        visible_to_compartments):
                raise SampleError(
                    f"this sample is already held (sha256 "
                    f"{digest_hex[:16]}...); link the existing record rather "
                    f"than storing it twice")
            raise SampleError(
                "this submission was not accepted. If you believe it is new, "
                "raise it with the lab — a duplicate of something you may "
                "not see is refused without saying so, because the refusal "
                "would otherwise answer a question the access gate does not.")

        # Per-sample data key, envelope-encrypted with the same scheme
        # persona credentials and TOTP secrets use.
        data_key = os.urandom(32)
        key_blob, key_id = envelope.encrypt(data_key.hex())
        ciphertext = _xor_stream(data, data_key)

        storage_key = f"samples/{digest_hex[:2]}/{digest_hex}"
        bucket = os.environ.get("SAMPLE_BUCKET", "noctornal-samples")

        # ROW FIRST, THEN BYTES. The order matters more here than anywhere
        # else in the system (F19, 2026-07-26).
        #
        # The old order put the ciphertext in the bucket and then inserted.
        # Any failure in between -- a constraint violation, a bad label, a
        # dropped connection -- left a copy of LIVE MALWARE in an
        # object-locked bucket with no row naming it, no submitter attached
        # to it and no state machine covering it. Object lock means it
        # cannot then be deleted, by anyone, including root. That is the
        # single worst durable outcome this module can produce.
        #
        # Reversed, the failure modes swap for strictly better ones: a
        # storage failure rolls the row back and nothing is retained
        # anywhere, and every validation error now fires before a single
        # byte leaves the process. The residual window -- put succeeds, then
        # COMMIT fails -- is far narrower than "put succeeds, then INSERT
        # rejects the row", and it is the one an operator can actually
        # detect, because a bucket object whose digest matches no row is a
        # query rather than an archaeology exercise.
        with self._c.transaction():
            row = self._c.execute(
                """INSERT INTO lab.sample
                       (case_id, sha256, sha1, md5, original_filename,
                        byte_size, storage_key, storage_bucket,
                        data_key_ciphertext, data_key_id, state, file_type,
                        entropy, triage_gaps, submitted_by, source_note,
                        classification, compartments)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           'QUARANTINED', %s, %s, %s, %s, %s, %s, %s)
                   RETURNING """ + _COLUMNS,
                (case_id, result.sha256, result.sha1, result.md5,
                 original_filename, result.byte_size, storage_key, bucket,
                 key_blob, key_id, result.file_type, result.entropy,
                 Json(result.gaps), submitted_by, source_note, classification,
                 sorted(compartments)),
            ).fetchone()
            sample = _record(row)
            if self._storage is not None:
                self._storage.put(storage_key, ciphertext)
            self._access(sample.id, submitted_by, "VIEWED_META",
                         {"event": "submitted", "policy_reference": detail})
        return sample

    def reject(self, sample_id: UUID, *, actor_id: UUID, reason: str,
               purge_bytes: bool = True) -> Sample:
        """The REJECTED path docs/11 requires: record THAT something was
        rejected and why, **without retaining the content**.

        The bytes go; the row stays. That asymmetry is the point -- an
        auditor asking "did anything prohibited ever come through here"
        needs an answer, and the answer cannot be the material itself.

        ## Legal hold beats this, and the collision is not ours to resolve

        docs/08 states it without qualification: **"legal_hold overrides all
        deletion, everywhere."** `lab.sample.legal_hold` has existed since
        migration 0031 and, until F19 (2026-07-26), was read by nothing --
        so one non-step-up call irreversibly destroyed material under a
        court hold, and did it through the code path most likely to be
        reached in a hurry.

        What makes this worse than an ordinary missing check is that the two
        rules genuinely conflict. A prohibited-content policy may require
        destruction; a preservation order requires retention; and in some
        jurisdictions doing either is an offence against the other. Software
        cannot pick. So the destruction is REFUSED and the conflict is put
        in front of a person, with `purge_bytes=False` available to record
        the rejection and the reason while the bytes stay put. That is
        docs/18 L1's open question arriving as a runtime refusal rather than
        as a silent irreversible act.

        The case's hold counts too. docs/08 puts `legal_hold` on the case
        precisely so a hold can be applied to everything in it at once
        without enumerating the contents.
        """
        if not reason or not reason.strip():
            raise SampleError("a rejection has to say why; that record is the "
                              "only thing that survives the content")
        current = self.get(sample_id)
        if current is None:
            raise SampleError("no such sample")
        if current.state == REJECTED:
            raise SampleError("already rejected")

        held = self._c.execute(
            """SELECT s.legal_hold, coalesce(c.legal_hold, false)
                 FROM lab.sample s
                 LEFT JOIN core."case" c ON c.id = s.case_id
                WHERE s.id = %s""", (sample_id,)).fetchone()
        if purge_bytes and held and (held[0] or held[1]):
            raise SampleError(
                "this sample is under a legal hold, and docs/08 is "
                "unqualified: a hold overrides all deletion, everywhere. "
                "Rejecting it would destroy material somebody has been "
                "ordered to preserve. If a prohibited-content policy also "
                "requires destruction, that conflict is a decision for "
                "counsel and the designated person, not for this endpoint "
                "-- lift the hold deliberately, or call this with "
                "purge_bytes=False to record the rejection and keep the "
                "bytes.")

        if purge_bytes:
            # Refusing rather than proceeding, for the same reason
            # `retention._purge_evidence` and `ingest._with_raw` do: the
            # row about to be written says `bytes_purged: true` in an
            # APPEND-ONLY ledger. Writing that without a store is not a
            # missing side effect, it is a false record of a destruction
            # -- and the one an auditor asking "was this destroyed" will
            # be shown. The state machine is still testable with a fake;
            # what is refused is claiming a destruction with nothing at
            # all behind it.
            if self._storage is None:
                raise SampleError(
                    "the sample store is not configured, so the bytes "
                    "cannot be destroyed and recording this rejection "
                    "would claim a destruction that did not happen. Fix "
                    "the store, or call this with purge_bytes=False to "
                    "record the rejection while the material stays put.")
            self._storage.delete(
                self._c.execute(
                    "SELECT storage_key FROM lab.sample WHERE id = %s",
                    (sample_id,)).fetchone()[0])

        row = self._c.execute(
            """UPDATE lab.sample
                  SET state = 'REJECTED', reject_reason = %s,
                      data_key_ciphertext = CASE WHEN %s THEN %s
                                                 ELSE data_key_ciphertext END
                WHERE id = %s RETURNING """ + _COLUMNS,
            # The data key is destroyed WITH the bytes, so that even if the
            # object survives a bucket-lifecycle race nothing can decrypt
            # it. Only with them, though: destroying the key while keeping
            # the ciphertext preserves a file nobody can ever read, which
            # satisfies a preservation order in form and defeats it in
            # substance.
            (reason.strip(), purge_bytes, b"", sample_id)).fetchone()
        self._access(sample_id, actor_id, "REJECTED",
                     {"reason": reason.strip(), "bytes_purged": purge_bytes})
        return _record(row)

    # -- queue -------------------------------------------------------------

    def assign(self, sample_id: UUID, *, analyst_id: UUID,
               actor_id: UUID) -> Sample:
        row = self._c.execute(
            """UPDATE lab.sample
                  SET assigned_to = %s, assigned_at = now(), state = 'ASSIGNED'
                WHERE id = %s AND state IN ('QUARANTINED','TRIAGED')
            RETURNING """ + _COLUMNS,
            (analyst_id, sample_id)).fetchone()
        if row is None:
            raise SampleError(
                "only a quarantined or triaged sample can be assigned")
        self._access(sample_id, actor_id, "ASSIGNED",
                     {"analyst_id": str(analyst_id)})
        return _record(row)

    def record_analysis(self, sample_id: UUID, *, analyst_id: UUID, kind: str,
                        findings: dict | None = None,
                        extracted_selectors: list | None = None,
                        yara_hits: list[str] | None = None,
                        family_assessment: str | None = None,
                        confidence: str | None = None,
                        narrative: str | None = None,
                        tool: str | None = None,
                        tool_version: str | None = None) -> UUID:
        """Findings are machine-readable by construction.

        `family_assessment` without a `confidence` is refused by a CHECK
        constraint, because a family attribution is an ASSESSMENT and one
        without a confidence is a fact wearing an assessment's clothes.
        Reaching the graph is a separate, deliberate step: it becomes a
        `core.assertion` like everything else (invariant 1), never a column
        stamped on an actor.
        """
        if kind not in {"STATIC", "YARA", "MANUAL_RE", "SANDBOX", "VENDOR"}:
            raise SampleError(f"unknown analysis kind {kind!r}")
        if family_assessment and not confidence:
            raise SampleError(
                "a family attribution is an assessment, not a fact: give it a "
                "confidence or do not record it")
        row = self._c.execute(
            """INSERT INTO lab.sample_analysis
                   (sample_id, kind, analyst_id, tool, tool_version, findings,
                    extracted_selectors, yara_hits, family_assessment,
                    confidence, narrative)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (sample_id, kind, analyst_id, tool, tool_version,
             Json(findings or {}), Json(extracted_selectors or []),
             yara_hits, family_assessment, confidence, narrative)).fetchone()
        self._c.execute(
            "UPDATE lab.sample SET state = 'IN_ANALYSIS' "
            "WHERE id = %s AND state = 'ASSIGNED'", (sample_id,))
        self._access(sample_id, analyst_id, "ANALYSED", {"kind": kind})
        return row[0]

    # -- egress ------------------------------------------------------------

    def download(self, sample_id: UUID, *, actor_id: UUID,
                 request_origin: str | None = None,
                 clearance: str | None = None,
                 compartments: frozenset[str] = frozenset(),
                 ticket_id: UUID | None = None
                 ) -> tuple[bytes, str]:
        """The encrypted archive, and only from the separate origin.

        Which origin this process is serving comes from CONFIGURATION --
        `origin_split()`, read here so a second caller cannot skip it.
        `request_origin` is kept under its old name for the service tests,
        which stand a call on one process or the other by passing the
        origin that process would be configured as; it is NOT where a
        request arrived, and nothing in the HTTP layer passes it. Until
        2026-09-09 the router passed `request.url`'s origin here, and that
        is the Host header: a client-supplied value the check then granted
        on. Serving hostile bytes from the app origin means an escape runs
        with the analyst's session on the case file -- a drive-by vector
        built into the highest-trust system in the estate, seeded with
        hostile files by design (docs/11).

        **The caller's clearance is REQUIRED, and it was missing entirely.**
        This method used to select `storage_key, data_key_ciphertext,
        data_key_id, sha256, state` and nothing else: no classification, no
        compartments, no case. The router gated it on
        `require_global("sample.download")` plus step-up, and
        `require_global` knows nothing about a case OR an element.

        The inconsistency was inside one file. `queue()` filters on
        `classification <= caller AND compartments <@ caller`, and
        `detail()` 404s an over-classified sample -- so the same caller was
        told the sample did not exist and handed its bytes one request
        later. On the one path in the entire system that puts working
        malware on somebody's disk.

        The case's labels are composed in as well: a sample can be
        classified ABOVE its case (queue's docstring says so), and a sample
        submitted with the router's `AMBER` default sits BELOW a RED case
        with nothing to catch it -- `lab.sample` has no `enforce_tlp_floor`
        trigger, unlike node, edge and evidence. Both directions are
        handled here because neither is handled anywhere else.

        `ticket_id` names the one-shot ticket that authorised this copy,
        when one did (0061). It is recorded in the custody row and
        nowhere else: "who took a copy of a live binary" is the question
        `lab.sample_access` exists to answer, and HOW they proved they
        could is part of that answer. The clearance handed in is always
        the live one -- for a ticket that means the ticket-holder's
        ceiling read at redemption, not the one that was true when the
        ticket was minted a minute ago.
        """
        # Ahead of the origin split, and it has to stay ahead of it: a
        # caller who forgot the argument must be told THAT, not handed a
        # deployment refusal about origins that sends them to the
        # environment. `_downloadable` asks again -- the guard belongs to
        # the decision, and the mint reaches the decision by another door.
        _require_clearance(clearance)
        split = origin_split(this=request_origin)
        if not split.serves_here:
            raise SampleError(split.refusal)
        configured = split.sample

        row = self._downloadable(sample_id, clearance=clearance,
                                 compartments=compartments)
        if self._storage is None:
            raise SampleError("sample storage is not configured")

        data_key = bytes.fromhex(envelope.decrypt(row[1], key_id=row[2]))
        ciphertext = self._storage.get(row[0])
        data = _xor_stream(ciphertext, data_key)

        digest = hashlib.sha256(data).digest()
        if digest != bytes(row[3]):
            # Same discipline as the evidence read path: re-verify on EVERY
            # read and fail closed. A sample whose bytes changed is either a
            # storage fault or a tamper, and neither is a thing to hand to
            # an analyst.
            #
            # RECORDED, not merely raised (F19). This used to raise into the
            # router, which mapped it to a 409 and moved on — so the one
            # signal that the malware store had been altered produced an
            # error message for one analyst and nothing anybody would ever
            # find. `core.evidence` has done this properly since Phase 1:
            # a failed HASH_VERIFIED custody row, then the refusal.
            #
            # Written in its own transaction so it survives the raise. An
            # audit row rolled back with the failure it records is not an
            # audit row.
            with self._c.transaction():
                self._access(
                    sample_id, actor_id, "VIEWED_META",
                    {"event": "integrity_check_failed",
                     "recorded_sha256": bytes(row[3]).hex(),
                     "computed_sha256": digest.hex(),
                     "storage_key": row[0]})
                self._c.execute(
                    """INSERT INTO audit.event
                           (actor_id, actor_kind, action, object_type,
                            object_id, outcome, detail)
                       VALUES (%s, 'USER', 'SAMPLE_INTEGRITY_ALARM', 'sample',
                               %s, 'DENIED', %s)""",
                    (actor_id, sample_id,
                     Json({"recorded_sha256": bytes(row[3]).hex(),
                           "computed_sha256": digest.hex()})))
            raise SampleError(
                "sample integrity check failed: stored bytes do not match the "
                "recorded sha256. This is a tamper alarm, not a transient "
                "error — it has been written to the custody ledger and the "
                "audit log, and the bytes have NOT been served.")

        # `via` is derived rather than passed: a ticket id present means
        # the authority was a ticket, and two parameters that can disagree
        # about one fact is how a custody row comes to say something that
        # is not so.
        custody = {"origin": configured}
        if ticket_id is not None:
            custody["via"] = "ticket"
            custody["ticket_id"] = str(ticket_id)
        self._access(sample_id, actor_id, "DOWNLOADED", custody,
                     archive_format="ZIP_INFECTED")
        return archive(data, digest.hex()), digest.hex()

    def _downloadable(self, sample_id: UUID, *, clearance: str | None,
                      compartments: frozenset[str] = frozenset()) -> tuple:
        """The decision that stands between a caller and a live binary, in
        ONE place because two endpoints now make it.

        Returns `(storage_key, data_key_ciphertext, data_key_id, sha256,
        state)` for a sample this caller may take a copy of, and raises
        otherwise. `issue_download_ticket` calls it and throws the row
        away: what it needs is the refusal, so that a ticket can never be
        minted for a sample its holder could not have downloaded directly.
        Restating the predicate there would have been the same defect this
        method's own history is made of -- `download()` had no label check
        at all while `detail()` twenty lines away 404'd the same sample.

        Five parts, and each one has been wrong here at some point:

        1. the caller's clearance is stated rather than assumed;
        2. the sample exists, and is readable at that clearance -- with
           its CASE's labels composed in, stricter classification and
           union of compartments, exactly as `deps.effective_labels` does
           for a node. Applied IN the query, so a caller who may not read
           it gets "no such sample", the same answer a nonexistent id
           gets: a status code must not be an existence oracle;
        3. its compartments are ones the caller is read into;
        4. it was not REJECTED, whose bytes are destroyed by definition;
        5. it still has a data key, without which there is nothing to
           decrypt.
        """
        _require_clearance(clearance)
        row = self._c.execute(
            """SELECT s.storage_key, s.data_key_ciphertext, s.data_key_id,
                      s.sha256, s.state
                 FROM lab.sample s
                 LEFT JOIN core."case" c ON c.id = s.case_id
                WHERE s.id = %s
                  AND greatest(s.classification,
                               coalesce(c.classification, s.classification))
                      <= %s::core.tlp
                  AND (s.compartments
                       || coalesce(c.compartments, '{}')) <@ %s""",
            (sample_id, clearance, list(compartments))).fetchone()
        if row is None:
            raise SampleError("no such sample")
        if row[4] == REJECTED:
            raise SampleError("this sample was rejected and its bytes destroyed")
        if not row[1]:
            raise SampleError("this sample has no data key; it cannot be read")
        return row

    # -- the hand-off between the two origins (0061) -----------------------

    def issue_download_ticket(self, sample_id: UUID, *, actor_id: UUID,
                              clearance: str | None = None,
                              compartments: frozenset[str] = frozenset(),
                              session_id: UUID | None = None,
                              ip_hash: bytes | None = None,
                              request_origin: str | None = None
                              ) -> DownloadTicket:
        """Mint a one-shot, sixty-second authority to download ONE sample.

        Minted on the APPLICATION origin, under the caller's ordinary
        session, and redeemed on the sample origin -- which is the whole
        point. A `__Host-` cookie cannot travel to the sample origin, so
        until now the console forced the login-body token there as a
        Bearer: a standing session credential, held in page memory,
        presented to a second origin. The ticket confers authority over
        this sample and nothing else, once, and expires whether it is used
        or not.

        Refuses on two configuration grounds before it looks at anything:

        - `split_problem` -- the control is off, or the configured value
          is not an origin, or it is a second name for the application's.
          A ticket whose `download_url` points at an origin that refuses
          every download is a worse answer than a refusal here, because
          the failure would surface as the console's "did not complete";
        - this process IS the sample origin. The sample origin exists so
          that no analyst session runs there; minting on it would put the
          session it is minted under exactly where the split says none may
          be. `app.py`'s `_allowed_on_sample_origin` already 404s this
          path on that process -- the ticket path is not the download path
          and is not in its allow-list -- and this is the check that does
          not depend on a regular expression in another file agreeing.

        Then the SAME decision `download()` makes, through
        `_downloadable`, so the mint cannot authorise what the download
        would refuse.
        """
        split = origin_split(this=request_origin)
        if split.split_problem is not None:
            raise SampleError(split.split_problem)
        if split.serves_here:
            raise SampleError(
                "download tickets are minted on the application origin and "
                "redeemed here. This process is configured as the sample "
                f"origin ({split.sample}), which serves sample bytes and "
                f"nothing else; ask {split.app} for a ticket.")
        self._downloadable(sample_id, clearance=clearance,
                           compartments=compartments)

        raw = new_download_ticket()
        # The expiry is set BY THE DATABASE and compared against the
        # database clock at redemption. Computing it here would put a
        # second clock inside a sixty-second window -- the API host's --
        # and two clocks a few seconds apart mean a ticket that is expired
        # on arrival or one that outlives its own audit row.
        # The TTL crosses as a `timedelta`, which psycopg adapts to
        # `interval` -- so the addition is `timestamptz + interval` with
        # nothing for the planner to guess at. `make_interval(secs => %s)`
        # would have left an integer parameter to be resolved against an
        # overloaded function's `double precision` argument.
        row = self._c.execute(
            """INSERT INTO lab.download_ticket
                   (token_hash, sample_id, user_id, session_id, expires_at,
                    ip_hash)
               VALUES (%s, %s, %s, %s, now() + %s, %s)
               RETURNING id, expires_at""",
            (hash_token(raw), sample_id, actor_id, session_id,
             timedelta(seconds=DOWNLOAD_TICKET_TTL_SECONDS),
             ip_hash)).fetchone()
        # Audited as an ISSUE, not as custody. `lab.sample_access` is the
        # record of who took a copy, its action set is closed, and a
        # ticket is not a copy -- the custody row is written when the
        # bytes are actually served, and it names this ticket.
        self._audit("SAMPLE_DOWNLOAD_TICKET_ISSUED", actor_id=actor_id,
                    sample_id=sample_id, session_id=session_id,
                    ip_hash=ip_hash,
                    detail={"ticket_id": str(row[0]),
                            "expires_at": row[1].isoformat(),
                            "ttl_seconds": DOWNLOAD_TICKET_TTL_SECONDS,
                            "sample_origin": split.sample})
        return DownloadTicket(id=row[0], raw=raw, sample_id=sample_id,
                              user_id=actor_id, expires_at=row[1])

    def redeem_download_ticket(self, presented: str, *, sample_id: UUID,
                               ip_hash: bytes | None = None
                               ) -> tuple[UUID, UUID]:
        """Spend a ticket. Returns `(user_id, ticket_id)`; raises on
        anything else.

        ONE statement decides it. The predicate and the write are the same
        `UPDATE ... RETURNING`, so two simultaneous presentations of the
        same ticket cannot both find `redeemed_at IS NULL` -- the row lock
        the UPDATE takes serialises them and exactly one gets a row back.
        A `SELECT` then an `UPDATE` would have been the readable version
        and would have handed the archive to both halves of a race, which
        is precisely what "one-shot" must not mean.

        `sample_id` is part of the predicate, not a check afterwards: a
        ticket presented on the path of a DIFFERENT sample matches no row
        at all, so it is refused and -- deliberately -- not spent. Burning
        it would let anyone who could reach this endpoint invalidate a
        ticket they cannot use by guessing the wrong sample.

        Expiry is `expires_at > now()`, the database's clock on both
        sides of the hand-off, and the row is not deleted: an exhausted
        ticket is evidence for as long as the retention pass leaves it.

        ## The ACCOUNT is re-read here; the session is not

        A live ticket is not an authority on its own, and treating it as
        one meant that inside the sixty-second window an account which had
        just been DEACTIVATED, or had `sample.download` revoked, still
        received the archive. Sixty seconds is short and that is still the
        wrong answer on the one path that puts working malware on a disk,
        so `_still_authorised` re-asks the question the mint asked --
        active account, verb held through a global role -- on this
        process, before the bytes move. The other half of the mint's
        decision, the sample's labels against the holder's LIVE ceiling,
        has always been re-read: `routers/samples.download` calls
        `user_ceiling` and `_downloadable` runs again.

        What is deliberately NOT re-derived is the SESSION -- whether it
        still exists, has been revoked, has expired, or would satisfy
        step-up freshness now. That is the residual 0061 states, and it is
        a different question from this one: the session is a credential
        this origin cannot resolve without a third copy of a check
        `http/deps.py` keeps in exactly two places, whereas the account is
        one row and one join away from the ticket the caller just
        presented.
        """
        digest = hash_token(presented or "")
        row = self._c.execute(
            """UPDATE lab.download_ticket
                  SET redeemed_at = now()
                WHERE token_hash = %s
                  AND sample_id = %s
                  AND redeemed_at IS NULL
                  AND expires_at > now()
            RETURNING id, user_id, session_id, token_hash""",
            (digest, sample_id)).fetchone()
        if row is None:
            # WHY it failed goes in the audit and never in the answer. The
            # caller learns only that the ticket is not usable: "already
            # redeemed" tells a holder of a stolen ticket that it was real
            # and that someone else got there first, which is exactly the
            # oracle `deps.current_user` refuses to be about sessions.
            reason, holder = self._ticket_refusal(digest, sample_id)
            if reason == _UNKNOWN_TICKET:
                # ...and one of the five reasons is not audited at all.
                #
                # An unknown ticket names nobody and evidences nothing: a
                # string that matched no row. It is also the ONE refusal a
                # caller with no credential of any kind can produce on
                # demand, by posting `ticket=x` at this origin -- so
                # writing a row for it made `audit.event`, which is
                # append-only by design, hash-chained and serialised by an
                # advisory lock, appendable by anyone who could reach the
                # sample process, with nothing able to remove what they
                # wrote. That is the shape `RateLimiter.should_audit`
                # already refuses on its own denials, for the same reason.
                #
                # The honest record of "somebody sent a string" is a
                # counted log line, the way `routers/live.py` records a
                # pre-accept refusal, and the `sample.download` limit
                # bounds how many strings one source may send. The other
                # four reasons each name a REAL minted ticket and a real
                # user; those still write a row, because those are events
                # a security officer must be able to find years later.
                counted = _unknown_tickets.note()
                if counted is not None:
                    log.warning(
                        "download ticket presented that matches no row (%d "
                        "since the last line). Unaudited by design: this "
                        "refusal needs no credential, so a row per attempt "
                        "would let the caller append to the audit chain at "
                        "will.", counted)
            else:
                self._audit("SAMPLE_DOWNLOAD_TICKET_REFUSED", actor_id=holder,
                            sample_id=sample_id, outcome="DENIED",
                            ip_hash=ip_hash, detail={"reason": reason})
            raise SampleError(_TICKET_REFUSED)
        if not hmac.compare_digest(bytes(row[3]), digest):
            # Cannot fire against the predicate above, and that is the
            # point of writing it: the equality that granted this row was
            # the database's, inside an index, and this is the comparison
            # THIS process makes on the bytes it got back before it serves
            # a live binary. The day somebody loosens that WHERE clause --
            # a prefix lookup, a join, a LIKE -- a partial match stops
            # here instead of becoming a download.
            self._audit("SAMPLE_DOWNLOAD_TICKET_REFUSED", actor_id=row[1],
                        sample_id=sample_id, outcome="DENIED", ip_hash=ip_hash,
                        detail={"reason": "hash_mismatch_after_lookup"})
            raise SampleError(_TICKET_REFUSED)
        # The ticket is already SPENT at this point, and the account check
        # below can still refuse. That ordering is deliberate in both
        # directions. Spending first is what makes the one-shot property a
        # single statement, which is the only way two simultaneous
        # presentations cannot both succeed; and a ticket presented by a
        # holder who has just lost their authority is a ticket that should
        # not survive to be presented again if the deactivation is
        # reversed. Nothing is lost by burning it: unlike a wrong-sample
        # guess, this presentation could only be made by somebody actually
        # holding the string.
        holder = row[1]
        if not self._still_authorised(holder):
            self._audit("SAMPLE_DOWNLOAD_TICKET_REFUSED", actor_id=holder,
                        sample_id=sample_id, session_id=row[2],
                        outcome="DENIED", ip_hash=ip_hash,
                        detail={"reason": self._authority_refusal(holder),
                                # The row was spent by the UPDATE above, so
                                # the ledger and the audit agree about a
                                # ticket that reads as redeemed and served
                                # nothing.
                                "ticket_id": str(row[0]), "spent": True})
            raise SampleError(_TICKET_REFUSED)
        self._audit("SAMPLE_DOWNLOAD_TICKET_REDEEMED", actor_id=holder,
                    sample_id=sample_id, session_id=row[2], ip_hash=ip_hash,
                    detail={"ticket_id": str(row[0])})
        return holder, row[0]

    def _still_authorised(self, user_id: UUID) -> bool:
        """Is the ticket's holder still an ACTIVE account holding
        `sample.download` through a global role?

        `IamAdminService.holds_global_permission` is that question already
        written down -- its own docstring calls it "the same question
        `deps.require_global` asks, WITHOUT the step-up freshness clause".
        Reused rather than restated: a second copy of the join would be the
        defect this whole path is made of, where `download()` had no label
        check while `detail()` twenty lines away had one.

        Its docstring also says it must not authorise a WRITE, because a
        write is what step-up exists to re-challenge. This is not a write
        and the step-up it omits was not skipped: `require_global` and
        `require_step_up` both ran at the mint, less than
        `DOWNLOAD_TICKET_TTL_SECONDS` ago, and sixty seconds is a tighter
        assurance bound than the fifteen minutes `STEP_UP_FRESHNESS`
        would have allowed. What could not be re-asked here is whether the
        SESSION that satisfied it is still live, and that -- not the
        account -- is the residual 0061 states.
        """
        return IamAdminService(self._c).holds_global_permission(
            user_id, DOWNLOAD_PERMISSION)

    def _authority_refusal(self, user_id: UUID) -> str:
        """Which half of `_still_authorised` said no, for the audit only.

        A second read on the refusal path alone, for `_ticket_refusal`'s
        reason: "the account was disabled and a download was attempted
        thirty seconds later" and "this analyst's download permission was
        revoked" are two different things to go and ask somebody about,
        and a single reason string would send a security officer to the
        wrong one.
        """
        row = self._c.execute(
            "SELECT is_active FROM iam.app_user WHERE id = %s",
            (user_id,)).fetchone()
        if row is None or not row[0]:
            return "account_deactivated"
        return "download_permission_revoked"

    def _ticket_refusal(self, digest: bytes,
                        sample_id: UUID) -> tuple[str, UUID | None]:
        """Why a redemption matched nothing, for the audit row only.

        A second read, on the refusal path alone, because "a ticket was
        refused" is not a useful thing for a security officer to find:
        replay, a stale tab and a ticket aimed at the wrong sample are
        three different events and only one of them is an attack. The
        holder comes back too, so the audit row names a user when there is
        one to name.
        """
        row = self._c.execute(
            """SELECT user_id, sample_id, redeemed_at, expires_at <= now()
                 FROM lab.download_ticket WHERE token_hash = %s""",
            (digest,)).fetchone()
        if row is None:
            # The one reason with no user behind it, and the one the
            # caller reaches with no credential -- so it is counted rather
            # than audited. Named, because its consumer branches on it.
            return _UNKNOWN_TICKET, None
        if row[2] is not None:
            return "already_redeemed", row[0]
        if row[3]:
            return "expired", row[0]
        if row[1] != sample_id:
            return "issued_for_another_sample", row[0]
        # Live, unspent, for this sample, and the UPDATE still matched
        # nothing: another request redeemed it between the two statements.
        return "redeemed_concurrently", row[0]

    def request_detonation(self, sample_id: UUID, *, requested_by: UUID,
                           target: str, exposure_level: str,
                           authorised_by: UUID | None = None,
                           note: str | None = None) -> UUID:
        """Record a detonation request. **Nothing is submitted anywhere.**

        docs/11: do not build a sandbox, integrate with one. What is built
        is the authorisation record, because detonation is an overt act --
        operators watch public sandboxes for their own samples and treat a
        submission as a signal they have been noticed, which can end an
        operation that took months.
        """
        if exposure_level not in {"NONE", "VENDOR", "PUBLIC"}:
            raise SampleError(f"unknown exposure level {exposure_level!r}")
        if exposure_level != "NONE" and (authorised_by is None or not note):
            raise SampleError(
                "anything that leaves the building needs a named authoriser "
                "and a note: submitting to a vendor or public sandbox exposes "
                "the sample AND your interest in it")
        row = self._c.execute(
            """INSERT INTO lab.detonation
                   (sample_id, target, exposure_level, authorised_by,
                    authorisation_note, requested_by, status)
               VALUES (%s, %s, %s, %s, %s, %s,
                       CASE WHEN %s = 'NONE' THEN 'PENDING' ELSE 'AUTHORISED' END)
               RETURNING id""",
            (sample_id, target, exposure_level, authorised_by, note,
             requested_by, exposure_level)).fetchone()
        self._access(sample_id, requested_by, "DETONATED",
                     {"target": target, "exposure_level": exposure_level})
        return row[0]

    # -- reads -------------------------------------------------------------

    def get(self, sample_id: UUID) -> Sample | None:
        row = self._c.execute(
            f"SELECT {_COLUMNS} FROM lab.sample WHERE id = %s",
            (sample_id,)).fetchone()
        return _record(row) if row else None

    def queue(self, *, states: tuple[str, ...] = (QUARANTINED, TRIAGED, ASSIGNED),
              clearance: str | None = None,
              compartments: frozenset[str] = frozenset(),
              limit: int = 100) -> list[Sample]:
        """The RE queue, filtered by the caller's own labels COMPOSED with
        each sample's case.

        Both halves are needed and the file used to have neither reliably.
        A sample can be classified ABOVE its case, so the case gate alone is
        not enough; and it can sit BELOW its case, because the router's
        `classification` defaults to AMBER and `lab.sample` has no
        `enforce_tlp_floor` trigger — so the sample's own labels alone are
        not enough either. `submit()` now raises the row to the case's floor
        and this composes at read time as well, because a case whose
        classification is raised after the fact must take its samples with
        it.

        `clearance` is REQUIRED. It used to default to `"RED"`, which meant
        a caller who forgot the argument was silently handed everything —
        the same fail-open shape that left `download()` with no gate at all,
        sitting in the same file.
        """
        if clearance is None:
            raise SampleError(
                "queue() needs the caller's clearance. It used to default to "
                "RED, so a caller that forgot became maximally privileged in "
                "silence — which is exactly how download() came to have no "
                "label check at all.")
        rows = self._c.execute(
            f"""SELECT {_SAMPLE_COLUMNS} FROM lab.sample s
                 LEFT JOIN core."case" c ON c.id = s.case_id
                WHERE s.state = ANY(%s)
                  AND greatest(s.classification,
                               coalesce(c.classification, s.classification))
                      <= %s::core.tlp
                  AND (s.compartments
                       || coalesce(c.compartments, '{{}}')) <@ %s
                ORDER BY s.submitted_at DESC LIMIT %s""",
            (list(states), clearance, list(compartments), limit)).fetchall()
        return [_record(r) for r in rows]

    def visible(self, sample_id: UUID, *, clearance: str,
                compartments: frozenset[str] = frozenset()) -> Sample | None:
        """One sample, or None if the caller may not know it exists.

        The composition is written once here and once in `download()`
        rather than in the router, so a second caller cannot skip it —
        which is what happened to `download()`. Returning None rather than
        raising keeps the router's answer identical to "no such sample": a
        status code must not be an existence oracle for a compartmented
        case.
        """
        row = self._c.execute(
            f"""SELECT {_SAMPLE_COLUMNS} FROM lab.sample s
                 LEFT JOIN core."case" c ON c.id = s.case_id
                WHERE s.id = %s
                  AND greatest(s.classification,
                               coalesce(c.classification, s.classification))
                      <= %s::core.tlp
                  AND (s.compartments
                       || coalesce(c.compartments, '{{}}')) <@ %s""",
            (sample_id, clearance, list(compartments))).fetchone()
        return _record(row) if row else None

    def analyses(self, sample_id: UUID) -> list[dict]:
        rows = self._c.execute(
            """SELECT id, kind, analyst_id, tool, findings,
                      extracted_selectors, yara_hits, family_assessment,
                      confidence, narrative, created_at
                 FROM lab.sample_analysis WHERE sample_id = %s
                ORDER BY created_at DESC""", (sample_id,)).fetchall()
        return [{"id": str(r[0]), "kind": r[1],
                 "analyst_id": str(r[2]) if r[2] else None, "tool": r[3],
                 "findings": r[4], "extracted_selectors": r[5],
                 "yara_hits": r[6] or [], "family_assessment": r[7],
                 "confidence": r[8], "narrative": r[9],
                 "created_at": r[10].isoformat()} for r in rows]

    def detonations(self, sample_id: UUID) -> list[dict]:
        """Every detonation REQUEST against this sample.

        Requests, not results: nothing in this build submits to a sandbox.
        The record exists because detonation is an overt act — operators
        watch public sandboxes for their own samples and treat a
        submission as a signal they have been noticed, which can end an
        operation that took months. So the authorisation is captured
        before anything could be sent, and it stays captured whether or
        not an integration ever appears.

        `authorised_by` is joined to an email rather than left as a uuid:
        the whole point of the column is that a NAMED human agreed, and a
        name a reviewer has to look up separately is one they will not.
        """
        rows = self._c.execute(
            """SELECT d.id, d.target, d.exposure_level, d.status,
                      d.requested_at, d.submitted_at, d.external_ref,
                      d.authorisation_note, r.email, a.email
                 FROM lab.detonation d
                 JOIN iam.app_user r ON r.id = d.requested_by
                 LEFT JOIN iam.app_user a ON a.id = d.authorised_by
                WHERE d.sample_id = %s
                ORDER BY d.requested_at DESC""", (sample_id,)).fetchall()
        return [{"id": str(r[0]), "target": r[1], "exposure_level": r[2],
                 "status": r[3],
                 "requested_at": r[4].isoformat() if r[4] else None,
                 "submitted_at": r[5].isoformat() if r[5] else None,
                 "external_ref": r[6], "authorisation_note": r[7],
                 "requested_by": r[8], "authorised_by": r[9],
                 # Stated on every row rather than once on the page: a
                 # reader scanning a list of "AUTHORISED" rows should not
                 # have to remember that none of them went anywhere.
                 "submitted": False} for r in rows]

    def custody(self, sample_id: UUID) -> list[dict]:
        rows = self._c.execute(
            """SELECT actor_id, action, occurred_at, archive_format, detail
                 FROM lab.sample_access WHERE sample_id = %s
                ORDER BY occurred_at DESC""", (sample_id,)).fetchall()
        return [{"actor_id": str(r[0]), "action": r[1],
                 "occurred_at": r[2].isoformat(), "archive_format": r[3],
                 "detail": r[4]} for r in rows]

    # -- internals ---------------------------------------------------------

    def _access(self, sample_id: UUID, actor_id: UUID, action: str,
                detail: dict, archive_format: str | None = None) -> None:
        self._c.execute(
            """INSERT INTO lab.sample_access
                   (sample_id, actor_id, action, archive_format, detail)
               VALUES (%s, %s, %s, %s, %s)""",
            (sample_id, actor_id, action, archive_format, Json(detail)))

    def _audit(self, action: str, *, sample_id: UUID, detail: dict,
               actor_id: UUID | None = None, outcome: str = "SUCCESS",
               session_id: UUID | None = None,
               ip_hash: bytes | None = None) -> None:
        """The hash-chained audit log, for the ticket events.

        Distinct from `_access`: `lab.sample_access` is the CUSTODY
        ledger and its `action` set is closed by a CHECK constraint to
        the seven things that can happen to a sample, of which minting a
        ticket is not one. A ticket is an authorisation; the custody row
        is written when bytes are served, and names the ticket that
        authorised them.

        `actor_kind` follows `deps.audit_auth_event`: a refusal with no
        identifiable holder is SYSTEM, not a USER row with a null actor.
        """
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    outcome, detail, ip_hash, session_id)
               VALUES (%s, %s, %s, 'sample', %s, %s, %s, %s, %s)""",
            (actor_id, "USER" if actor_id else "SYSTEM", action, sample_id,
             outcome, Json(detail), ip_hash, session_id))


def _xor_stream(data: bytes, key: bytes) -> bytes:
    """Encrypt the sample at rest under its per-sample key.

    A keystream XOR, and the honest note about it: this is CONTAINMENT, not
    confidentiality. Its jobs are that the bytes on disk are not
    recognisable as malware -- so your own EDR does not quarantine the
    evidence, which docs/11 calls a routine and embarrassing failure -- and
    that nothing in the pipeline is a runnable file. Confidentiality comes
    from the bucket's own access control, the origin split and the audit
    trail.

    A production deployment should replace this with AES-256-GCM streamed
    through the object store, which also gives integrity. It is not that
    here because the sample bytes are re-verified against their recorded
    sha256 on every read (see `download`), so tampering is detected on the
    path that matters, and a half-streamed AES implementation would be a
    worse thing to ship than a clearly-labelled simple one.
    """
    stream = bytearray()
    counter = 0
    while len(stream) < len(data):
        stream.extend(hashlib.sha256(key + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(b ^ s for b, s in zip(data, stream[:len(data)], strict=True))


_COLUMNS = ("id, case_id, sha256, sha1, md5, original_filename, byte_size, "
            "state, reject_reason, file_type, entropy, triage_gaps, "
            "submitted_by, submitted_at, source_note, assigned_to, "
            "classification, compartments")
#: The same list, table-qualified, for the reads that JOIN `core."case"` to
#: compose its labels. Derived from the one string rather than restated, so
#: the two cannot fall out of step and unpack into the wrong fields — the
#: same discipline `notifications._N_COLUMNS` uses for the same reason.
_SAMPLE_COLUMNS = ", ".join("s." + c.strip() for c in _COLUMNS.split(","))


def _require_clearance(clearance: str | None) -> None:
    """Refuse a caller who did not say what they are cleared for.

    One message for the two doors into a sample's bytes -- the download
    and the ticket that authorises one -- because a defaulted clearance
    is how this path came to have no label check at all, and a second
    spelling of the refusal is a second chance to get the default wrong.
    """
    if clearance is None:
        raise SampleError(
            "download() hands over live malware and needs the caller's "
            "clearance. Defaulting would make every caller that forgets "
            "silently maximally privileged, which is how this path came "
            "to have no label check at all.")


def _may_see(classification: str, compartments, clearance: str | None,
             held: frozenset[str]) -> bool:
    """Would this caller have been shown a row with these labels?

    `clearance is None` means the caller did not say, and the answer is no.
    A helper whose unknown case is "yes" is the shape that left `queue()`
    defaulting to RED and `download()` with no check at all.
    """
    if clearance is None:
        return False
    try:
        if tlp_from_name(classification) > tlp_from_name(clearance):
            return False
    except AccessResolutionError:
        return False
    return frozenset(compartments or []) <= held


def _record(r) -> Sample:
    return Sample(
        id=r[0], case_id=r[1], sha256=bytes(r[2]).hex(),
        sha1=bytes(r[3]).hex() if r[3] else None,
        md5=bytes(r[4]).hex() if r[4] else None,
        original_filename=r[5], byte_size=r[6], state=r[7], reject_reason=r[8],
        file_type=r[9], entropy=float(r[10]) if r[10] is not None else None,
        triage_gaps=r[11] or [], submitted_by=r[12], submitted_at=r[13],
        source_note=r[14], assigned_to=r[15], classification=r[16],
        compartments=frozenset(r[17] or []),
    )


__all__ = [
    "ARCHIVE_PASSWORD", "ASSIGNED", "DOWNLOAD_PERMISSION",
    "DOWNLOAD_TICKET_TTL_SECONDS",
    "IN_ANALYSIS", "MAX_SAMPLE_BYTES",
    "QUARANTINED", "REJECTED", "REPORTED", "SUBMITTED", "TRIAGED",
    "DownloadTicket", "OriginSplit", "PolicyNotDeclared", "Sample",
    "SampleError", "SampleService", "Triage", "app_origin", "archive",
    "download_cors_headers", "file_type_of", "new_download_ticket",
    "normalise_origin",
    "origin_split", "policy_declared", "public_origin", "sample_origin",
    "SampleStorage", "shannon_entropy", "triage",
]
