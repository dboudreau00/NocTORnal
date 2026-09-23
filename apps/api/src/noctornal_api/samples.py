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

## A rejected sample is preserved, not destroyed (F2, 2026-09-22)

The owner's decision after the review of that day. `reject()` moves the
ciphertext into a separate object-locked store under a legal hold and
keeps the data key, unless `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION` says
`destroy`. Getting a preserved sample back out takes two people: a
Security Officer's time-boxed authorisation naming one case owner, and
that case owner, through the same encrypted archive and the same sample
origin a download uses. `PreservationStorage` has no method that deletes
or lifts a hold. See `reject` and `retrieve_preserved`, and docs/11.

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
from typing import NamedTuple
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
from noctornal_api.config import SAMPLE_CAP_ENV, declared_cap
from noctornal_api.security.tokens import hash_token

log = logging.getLogger("noctornal.samples")

SUBMITTED = "SUBMITTED"
QUARANTINED = "QUARANTINED"
TRIAGED = "TRIAGED"
ASSIGNED = "ASSIGNED"
IN_ANALYSIS = "IN_ANALYSIS"
REPORTED = "REPORTED"
REJECTED = "REJECTED"

#: What the queue can be filtered by, in queue order. SUBMITTED is in the
#: enum and never landed in (a submission lands in QUARANTINED), so it is
#: not offered. Until 2026-09-22 the route took no state at all and the
#: console filtered the working set client-side, so choosing Rejected, In
#: analysis or Reported always showed "Nothing in the queue."
#: (ux13-lab:rejected-filter-always-empty).
QUEUE_STATES = (QUARANTINED, TRIAGED, ASSIGNED, IN_ANALYSIS, REPORTED,
                REJECTED)

#: What the queue shows when no state is asked for: work still waiting.
WORKING_SET = (QUARANTINED, TRIAGED, ASSIGNED)

#: F2, decided by the owner on 2026-09-22: what `reject()` does with the
#: bytes. `preserve` (the default) moves the ciphertext into the
#: preservation store under a legal hold and keeps the data key; `destroy`
#: is the behaviour this module had until that day. Anything else refuses,
#: naming this variable, because a typo that silently picked either one
#: would be a disposition nobody chose.
DISPOSITION_ENV = "NOCTORNAL_REJECTED_SAMPLE_DISPOSITION"
PRESERVE = "preserve"
DESTROY = "destroy"
DISPOSITIONS = (PRESERVE, DESTROY)

#: The two verbs around a preserved sample (migration 0063). The
#: authoriser and the retriever hold different roles on purpose, and the
#: table refuses an authorisation whose two people are one person.
AUTHORISE_PERMISSION = "sample.preserved.authorise"
RETRIEVE_PERMISSION = "sample.preserved.retrieve"

#: What a download ticket may be spent on (0063). The redemption re-reads
#: the permission that belongs to the purpose, and the route reads the
#: store that belongs to it, so one purpose can never be spent as the
#: other.
TICKET_DOWNLOAD = "download"
TICKET_RETRIEVAL = "preserved_retrieval"

#: How long an authorisation to retrieve a preserved sample may last. The
#: table's CHECK holds the same bound, so the number here is the
#: friendlier refusal and not the control.
MAX_AUTHORISATION_DAYS = 30

#: How long a preserving rejection waits for the sample's row lock before
#: giving up. The lock is taken BEFORE anything is copied, so a second
#: rejection of the same sample waits for the first and then sees
#: REJECTED, instead of copying too and leaving a held version behind that
#: no row names and this product can never delete (verifier on F2,
#: 2026-09-22). A module constant so a test can shorten it.
REJECT_LOCK_TIMEOUT = "5s"


def _row_busy() -> SampleError:
    """The refusal when a rejection could not get the sample's row lock
    within `REJECT_LOCK_TIMEOUT`. Read at call time, so a test that
    shortens the timeout sees its own value named.

    Raise it `from None`, never from the LockNotAvailable: the router's
    `safe_detail` replaces the whole message of an error chained to a
    psycopg one, so the analyst was shown "the request could not be
    completed" instead of this (final review verifier on U5, 2026-09-23).
    The lock timeout's own text adds nothing this does not say."""
    return SampleError(
        f"another change to this sample is still in progress (most likely "
        f"somebody else rejecting it), and this rejection stopped after "
        f"waiting {REJECT_LOCK_TIMEOUT} for it. Nothing has changed and "
        f"nothing was copied. Reopen the sample and try again.")


def _db_error_in(exc: BaseException) -> psycopg.Error | None:
    """The psycopg error anywhere in `exc`'s chain, as cause or context.

    For a refusal whose authored text has to reach the analyst.
    `http.errors.safe_detail` throws away the WHOLE message of an error
    whose cause chain holds a psycopg error, which is right, since a
    psycopg error's text is raw PQ output. So such a refusal is raised
    `from None`, names the database error by its class only, and logs it
    against a ref the message carries (final review verifier on U4,
    2026-09-23). Bounded and cycle-guarded, like `safe_detail`'s walk.
    """
    seen: set[int] = set()
    todo: list[BaseException | None] = [exc]
    while todo and len(seen) < 16:
        cur = todo.pop()
        if cur is None or id(cur) in seen:
            continue
        if isinstance(cur, psycopg.Error):
            return cur
        seen.add(id(cur))
        todo.extend((cur.__cause__, cur.__context__))
    return None


#: Why a `destroy` rejection of a held sample is refused. Said twice, once
#: before any lock and once under it (a hold placed in between counts).
_HOLD_REFUSES_DESTROY = (
    "this sample is under a legal hold, and docs/08 is "
    "unqualified: a hold overrides all deletion, everywhere. "
    "This deployment destroys rejected samples "
    f"({DISPOSITION_ENV}=destroy), so rejecting it would destroy "
    "material somebody has been ordered to preserve. If a "
    "prohibited-content policy also requires destruction, that "
    "conflict is a decision for counsel and the designated "
    "person, not for this endpoint. Lift the hold deliberately, "
    "or record the rejection without disposing of the bytes "
    "(purge_bytes=False).")

#: One VIEWED_META row per person per sample within this window. The
#: console reopens a sample after every action it takes, and a ledger
#: with a "viewed" row between every real event is one nobody reads.
VIEW_DEDUPE_SECONDS = 300

#: The industry convention (MalwareBazaar, VirusShare, malware-traffic).
#: It is a safety interlock, not a secret.
ARCHIVE_PASSWORD = b"infected"

#: Declared by NOCTORNAL_MAX_SAMPLE_BYTES, 256 MiB when unset (the same
#: reader as the evidence cap, `config.declared_cap`). A sample larger
#: than this is a disk image or a mistake, and either way it does not
#: belong in a quarantine queue behind an HTTP request. The sample bucket
#: is deliberately NOT object-locked (docs/11), so unlike the evidence cap
#: this one is about memory and the queue rather than permanent storage,
#: and a production boot does not insist on the declaration.
MAX_SAMPLE_BYTES = declared_cap(SAMPLE_CAP_ENV)

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

#: Which permission a ticket's redemption re-reads, by the ticket's
#: purpose (0063). Keyed on the column's CHECK vocabulary, so a purpose
#: this build does not know raises a KeyError rather than falling back to
#: either permission.
_PURPOSE_PERMISSION = {
    TICKET_DOWNLOAD: DOWNLOAD_PERMISSION,
    TICKET_RETRIEVAL: RETRIEVE_PERMISSION,
}

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
    f"within {DOWNLOAD_TICKET_TTL_SECONDS} seconds. Ask the console for "
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


class AuthorisationRequired(SampleError):
    """A preserved sample was asked for by somebody with no live
    authorisation for it. The router answers 451, as victim PII does: the
    refusal is the two-person control working, not a fault."""


class PreservationUnverified(SampleError):
    """The held PUT returned, so a held version EXISTS, and then the store
    could not be made to confirm what it holds (the read-back failed, or
    disagreed). Carries `copy`, the version the PUT reported, so the
    rejection can name it.

    Final review C8, 2026-09-23: only a size or hold MISMATCH was a
    SampleError, and it was reported as "Nothing has changed"; an S3 or
    transport error from the read-back was not a SampleError at all, reached
    the router raw, and answered 500. Either way the held version was named
    nowhere, and each retry wrote another one."""

    def __init__(self, message: str, copy: PreservedObject) -> None:
        super().__init__(message)
        self.copy = copy


class PreservationUnconfirmed(SampleError):
    """The held PUT was sent and no answer came back (a timeout, a dropped
    connection), so a held version may or may not exist at `bucket`/`key`,
    and if it does, its version id is not known here. Distinct from a
    refusal, where the store answered and nothing was written (C8)."""

    def __init__(self, message: str, bucket: str, key: str) -> None:
        super().__init__(message)
        self.bucket = bucket
        self.key = key


def disposition_setting() -> tuple[str | None, str | None]:
    """`(disposition, problem)` for `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION`.

    Unset or blank means `preserve`, the owner's default and the direction
    that loses nothing. A value that is neither `preserve` nor `destroy`
    comes back as a problem naming the variable, never as a guess: a typo
    that silently became either one would be a disposition nobody chose,
    and one of the two cannot be undone.
    """
    raw = os.environ.get(DISPOSITION_ENV, "").strip().lower()
    if not raw:
        return PRESERVE, None
    if raw in DISPOSITIONS:
        return raw, None
    return None, (
        f"{DISPOSITION_ENV}={raw!r} is not a disposition this build knows. "
        f"Set it to 'preserve' (the default: a rejected sample's ciphertext "
        f"moves into the preservation store under a legal hold and its "
        f"data key is kept) or 'destroy' (the bytes and the data key are "
        f"deleted). Rejections that dispose of the bytes are refused until "
        f"it is one of the two.")


def rejected_sample_disposition() -> str:
    """The configured disposition, or a refusal naming the variable."""
    value, problem = disposition_setting()
    if value is None:
        raise SampleError(problem)
    return value


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
            f"with no path, query or credentials. A path is a location on "
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

#: Seconds to wait for a TCP connection to the sample or preservation store.
STORE_CONNECT_TIMEOUT_S = 10.0
#: Seconds to wait on any one read from the socket. Per read, not per
#: transfer: a 256 MiB sample streams in many reads, each well inside this.
STORE_READ_TIMEOUT_S = 60.0


def _bounded_http(*, resend_writes: bool = True):
    """The HTTP pool both sample stores use, which gives up in seconds.

    minio-py's own pool waits five minutes on a connect or a read and
    retries five times, so one stalled call could hold a request for about
    half an hour. The preserving rejection makes calls to these stores
    inside a transaction that holds the sample's row lock, and until final
    review C7 (2026-09-23) the working-copy delete ran while the audit
    chain's advisory lock was held too, which stalled every audited write
    in the deployment behind one hung DELETE. The same bound as
    `readiness._object_store_client`, loosened for real transfers.

    Retries: a connection that never opened is retried (nothing was sent).
    A READ that timed out is NOT: the request went out, and retrying a held
    PUT whose answer was lost writes a second held version that nothing
    can delete. A 5xx answer is retried only where a resend is harmless.
    For the samples store it is (a resent PUT overwrites the same
    unversioned object, a resent DELETE deletes nothing twice). For the
    preservation store (`resend_writes=False`) only reads are resent: a 502
    or 504 can come from a proxy after the store took the held PUT, so a 5xx
    does not prove nothing was written, and `preserve()` reports the
    refusal instead (final review verifier on C7, 2026-09-23, which found
    this docstring claiming it did). Certificate handling is minio-py's
    own default, restated because passing a pool replaces it.
    """
    import certifi
    import urllib3

    retry = {"total": 2, "connect": 2, "read": 0, "status": 2,
             "backoff_factor": 0.2, "status_forcelist": [500, 502, 503, 504]}
    if not resend_writes:
        retry["allowed_methods"] = frozenset({"GET", "HEAD"})
    return urllib3.PoolManager(
        timeout=urllib3.Timeout(connect=STORE_CONNECT_TIMEOUT_S,
                                read=STORE_READ_TIMEOUT_S),
        maxsize=10,
        cert_reqs="CERT_REQUIRED",
        ca_certs=os.environ.get("SSL_CERT_FILE") or certifi.where(),
        retries=urllib3.Retry(**retry),
    )


def _missing(exc: BaseException) -> bool:
    """Whether a failed working-store read means the object is not there,
    as opposed to the store not answering. KeyError is the test doubles'
    spelling of NoSuchKey."""
    if isinstance(exc, KeyError):
        return True
    return getattr(exc, "code", None) in ("NoSuchKey", "NoSuchObject")


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
                             secure=secure, http_client=_bounded_http())

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
class PreservedObject:
    """Where a rejected sample's ciphertext now lives, as the store
    reported it after the write, not as it was asked for."""

    bucket: str
    key: str
    version_id: str | None
    size: int


class PreservationStorage:
    """The preservation bucket (F2, 2026-09-22): where a rejected sample's
    ciphertext goes instead of being destroyed.

    Modelled on `SampleStorage`, and separate from it for the same reason
    that store is separate from evidence: its own bucket
    (`PRESERVE_BUCKET`, default `noctornal-preserved`) and its own
    credentials (`PRESERVE_ENDPOINT` / `PRESERVE_ACCESS_KEY` /
    `PRESERVE_SECRET_KEY`). Those fall back to the `SAMPLE_*` variables and
    then to `MINIO_*` ONLY so a single-node development stack works with
    nothing added; a deployment gives this bucket its own account, and
    infra/production/compose.yml mints one when the variables are set.

    The bucket is created WITH object lock and no default retention. The
    protection is a per-object LEGAL HOLD, placed on the one version this
    process wrote, which holds until somebody deliberately lifts it and has
    no expiry for a clock to run out.

    Two things are deliberately absent. There is no `delete`, and no method
    that lifts a hold: retrieval reads a held object and leaves the hold
    exactly where it was, and nothing in this codebase may release one.
    Lifting a hold is an operator's act under counsel's instruction,
    outside the product, and it should be.
    """

    def __init__(self) -> None:
        from minio import Minio

        def pick(*names: str) -> str | None:
            for name in names:
                value = os.environ.get(name)
                if value:
                    return value
            return None

        endpoint = pick("PRESERVE_ENDPOINT", "SAMPLE_ENDPOINT", "MINIO_ENDPOINT")
        access = pick("PRESERVE_ACCESS_KEY", "SAMPLE_ACCESS_KEY",
                      "MINIO_ACCESS_KEY")
        secret = pick("PRESERVE_SECRET_KEY", "SAMPLE_SECRET_KEY",
                      "MINIO_SECRET_KEY")
        if not (endpoint and access and secret):
            raise SampleError(
                "the preservation store is not configured: set "
                "PRESERVE_ENDPOINT / PRESERVE_ACCESS_KEY / PRESERVE_SECRET_KEY "
                "(a deployment should give the preservation bucket its own "
                "credentials), or set NOCTORNAL_REJECTED_SAMPLE_DISPOSITION "
                "deliberately")
        secure = (pick("PRESERVE_SECURE", "SAMPLE_SECURE") or "false"
                  ).lower() == "true"
        self.bucket = os.environ.get("PRESERVE_BUCKET") or "noctornal-preserved"
        self._client = Minio(endpoint, access_key=access, secret_key=secret,
                             secure=secure,
                             http_client=_bounded_http(resend_writes=False))

    def preserve(self, key: str, data: bytes) -> PreservedObject:
        """Write, hold, and prove both, or raise saying what now exists.

        The hold is set IN the write (`legal_hold=True` on the PUT), so no
        window exists in which the object is in the bucket unheld. Then the
        store is asked, about the exact version it returned, what it now
        holds: the size must be the size written and the hold must read
        back as ON. A bucket created without object lock refuses the held
        PUT outright, and that refusal is translated into a sentence that
        says which bucket and what to do, rather than an S3 error code.

        Three ways to fail, and the caller must be able to tell them apart
        (final review C8, 2026-09-23): the store REFUSED the PUT, so nothing
        was written (`SampleError`); the PUT got no answer, so a held
        version may exist (`PreservationUnconfirmed`); or the PUT returned
        and the read-back failed or disagreed, so a held version DOES exist
        (`PreservationUnverified`, naming it). The read-back messages say
        "hold", never the two words the console reads as "record the
        rejection only", because once a held copy exists that is the one
        way out that strands it.
        """
        from minio.error import S3Error

        try:
            written = self._client.put_object(
                self.bucket, key, io.BytesIO(data), length=len(data),
                content_type="application/octet-stream", legal_hold=True)
        except S3Error as exc:
            if "lock" in (exc.message or "").lower() or exc.code in (
                    "InvalidRequest", "ObjectLockConfigurationNotFoundError"):
                raise SampleError(
                    f"the preservation bucket {self.bucket!r} would not take a "
                    f"legal hold ({exc.code}: {exc.message}). It must be "
                    f"created with object lock (mc mb --with-lock); object "
                    f"lock cannot be switched on afterwards, so an unlocked "
                    f"bucket has to be replaced.") from exc
            raise SampleError(
                f"the preservation store refused the copy ({exc.code}: "
                f"{exc.message})") from exc
        except Exception as exc:
            raise PreservationUnconfirmed(
                f"the preservation store did not answer the held copy "
                f"({type(exc).__name__}: {exc}), so a held version may or "
                f"may not now exist at {self.bucket}/{key}",
                self.bucket, key) from exc
        version = written.version_id
        made = PreservedObject(self.bucket, key, version, len(data))
        try:
            stat = self._client.stat_object(self.bucket, key,
                                            version_id=version)
            if stat.size != len(data):
                raise SampleError(
                    f"the preservation store reports {stat.size} bytes at "
                    f"{self.bucket}/{key} after {len(data)} were written")
            if not self._client.is_object_legal_hold_enabled(
                    self.bucket, key, version_id=version):
                raise SampleError(
                    f"the preservation store accepted {self.bucket}/{key} but "
                    f"does not report the hold as on")
        except SampleError as exc:
            raise PreservationUnverified(str(exc), made) from exc
        except Exception as exc:
            raise PreservationUnverified(
                f"the held copy was written to {self.bucket}/{key} but could "
                f"not be read back ({type(exc).__name__}: {exc})",
                made) from exc
        return PreservedObject(self.bucket, key, version, stat.size)

    def latest_held(self, key: str) -> PreservedObject | None:
        """The newest version at `key`, if the store holds one under a hold.

        For a rejection whose working copy is already gone because an
        earlier attempt deleted it and then failed to record (final review
        U4, 2026-09-23): the retry adopts the held copy instead of steering
        the analyst to a record-only rejection that would leave it named by
        no row. A plain HEAD and a hold read, which the preservation
        account's policy already allows; listing versions it may not do.
        The caller still proves the bytes are this sample's before
        recording anything."""
        from minio.error import S3Error

        try:
            stat = self._client.stat_object(self.bucket, key)
        except S3Error as exc:
            if exc.code in ("NoSuchKey", "NoSuchVersion", "NoSuchObject"):
                return None
            raise
        if not self._client.is_object_legal_hold_enabled(
                self.bucket, key, version_id=stat.version_id):
            return None
        return PreservedObject(self.bucket, key, stat.version_id, stat.size)

    def get(self, key: str, *, version_id: str | None = None,
            bucket: str | None = None) -> bytes:
        """The held ciphertext, read in place. `bucket` is the one the
        sample's row names, which outlives a later change of
        `PRESERVE_BUCKET`."""
        response = self._client.get_object(bucket or self.bucket, key,
                                           version_id=version_id)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def is_held(self, key: str, *, version_id: str | None = None,
                bucket: str | None = None) -> bool:
        return self._client.is_object_legal_hold_enabled(
            bucket or self.bucket, key, version_id=version_id)


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
    #: F2 (0063): where a rejected sample's ciphertext went, if it was
    #: preserved rather than destroyed or left in place.
    preserved_bucket: str | None = None
    preserved_key: str | None = None
    preserved_at: datetime | None = None
    #: The sample's OWN hold. The case's is composed in where a decision
    #: turns on it (`reject`), not carried here.
    legal_hold: bool = False
    #: True once the data key has been zeroed (a destroy). Read as a
    #: boolean in SQL so the sealed key itself never enters this object.
    key_destroyed: bool = False

    @property
    def bytes_disposition(self) -> str:
        """Where the bytes are, in one word the console can show.

        `in_sample_store` for a live sample; for a rejected one,
        `preserved`, `destroyed`, or `kept` (the rejection was recorded
        without disposing of anything, which is what a hold or a missing
        object leaves)."""
        if self.preserved_key:
            return "preserved"
        if self.state != REJECTED:
            return "in_sample_store"
        return "destroyed" if self.key_destroyed else "kept"


class Redemption(NamedTuple):
    """What a spent ticket proves: who, which ticket, and for what."""

    user_id: UUID
    ticket_id: UUID
    purpose: str


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

    def __init__(self, conn: psycopg.Connection, storage=None,
                 preservation=None):
        self._c = conn
        self._storage = storage
        #: The preservation store (F2). Injected like `storage`, and None
        #: unless the caller is about to preserve or retrieve: building
        #: one needs credentials that a queue read has no use for.
        self._preservation = preservation

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
                "raise it with the lab. A duplicate of something you may "
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
                   RETURNING """ + _RETURNING,
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
        rejected and why, and take the material out of the working store.

        ## What happens to the bytes (F2, owner decision, 2026-09-22)

        `purge_bytes=True` means "dispose of the bytes the way this
        deployment has decided", read from
        `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION`:

        - `preserve`, the default. The CIPHERTEXT is copied into the
          preservation store at `preserved/<sha256[:2]>/<sha256>`, under a
          legal hold set in the same PUT, and the store is asked what it
          now holds (size, and that the hold reads back ON) before
          anything else moves. Only then is the row marked REJECTED with
          where the copy went, then the working copy is deleted from the
          samples bucket, and the audit row is appended LAST (C7, below).
          The data key is KEPT: ciphertext with no key is a file nobody
          can ever read, which would satisfy a preservation order in form
          and defeat it in substance (0063 makes that a CHECK). What moves
          is exactly what was stored; the only decryption on this path is
          the in-memory proof a retry makes before adopting a held copy
          (U4, below), the same check a retrieval makes.
        - `destroy`, the behaviour until that day: the object is deleted
          and the data key zeroed.

        `purge_bytes=False` keeps its old meaning: record the rejection and
        the reason, dispose of nothing, leave the bytes where they are.

        Until 2026-09-22 a rejection DESTROYED by default, on the first
        click, from a card that did not name the sample
        (ux13-lab:reject-one-click-destroy). The console now asks for a
        confirmation that names the sample and states which of these will
        happen, and the default no longer loses anything.

        ## Failure leaves nothing half done

        If the copy fails, nothing changes: the sample is still where it
        was, in the state it was in, and the refusal says why. Once a held
        copy exists (the held PUT returned, or was sent and never answered)
        nothing in this product can delete it, so every failure from then
        on names it, says truthfully whether the working copy was already
        deleted, and is written to the audit log in its own statement
        (`SAMPLE_PRESERVATION_INCOMPLETE`) so the record does not live only
        in one analyst's error box (final review C8, 2026-09-23).

        A retry whose working copy is gone does not steer to a record-only
        rejection: if the preservation store holds a held copy at this
        sample's key and the kept data key opens it to this sample's
        SHA-256, the retry records THAT copy (final review U4, 2026-09-23).
        Until then a failure between the working-copy delete and COMMIT
        told the analyst the working copy was still in place, the retry
        answered "nothing to preserve", and the record-only rejection it
        suggested left the held copy linked to no row, for good.

        The audit append takes the chain's global advisory lock and holds
        it to COMMIT, so nothing slow may run after it: the working-copy
        delete, a network call, used to (final review C7, 2026-09-23), and
        a stalled object store then stalled every audited write in the
        deployment, logins included.

        The sample's row is locked before anything is copied, so two
        rejections of one sample cannot both copy: the second waits for
        the first (up to `REJECT_LOCK_TIMEOUT`), reads REJECTED and
        refuses having copied nothing. The record-only and destroy paths
        take the same lock (final review U5, 2026-09-23): without it a
        record-only rejection that started during a preserving one waited
        on the row, then overwrote its reason and appended a second,
        contradictory REJECTED custody row.

        ## Legal hold still beats DESTROY, and does not block PRESERVE

        docs/08 states it without qualification: **"legal_hold overrides
        all deletion, everywhere."** A prohibited-content policy may
        require destruction and a preservation order requires retention,
        and in some jurisdictions each is an offence against the other.
        Software cannot pick, so destruction under a hold (the sample's or
        its case's) is REFUSED and the conflict goes to a person.

        Preservation is not a deletion of the material. It moves the same
        ciphertext, key intact, into a store where it sits under a legal
        hold of its own; a sample under a hold is, if anything, better
        preserved afterwards. So it proceeds, and the custody row records
        that a hold was in force when it did.
        """
        if not reason or not reason.strip():
            raise SampleError("a rejection has to say why; that record is the "
                              "only thing that survives the content")
        current = self.get(sample_id)
        if current is None:
            raise SampleError("no such sample")
        if current.state == REJECTED:
            raise SampleError("already rejected")

        held, storage_key = self._hold_and_key(sample_id)

        if not purge_bytes:
            return self._reject_keeping(sample_id, actor_id=actor_id,
                                        reason=reason.strip())

        disposition = rejected_sample_disposition()
        if disposition == PRESERVE:
            return self._reject_preserving(
                current, actor_id=actor_id, reason=reason.strip(),
                storage_key=storage_key, held=held)

        if held:
            raise SampleError(_HOLD_REFUSES_DESTROY)

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
        return self._reject_destroying(sample_id, actor_id=actor_id,
                                       reason=reason.strip())

    def _hold_and_key(self, sample_id: UUID) -> tuple[bool, str]:
        """Whether a legal hold covers the sample (its own or its case's),
        and its working-store key."""
        row = self._c.execute(
            """SELECT s.legal_hold, coalesce(c.legal_hold, false), s.storage_key
                 FROM lab.sample s
                 LEFT JOIN core."case" c ON c.id = s.case_id
                WHERE s.id = %s""", (sample_id,)).fetchone()
        if row is None:
            raise SampleError("no such sample")
        return bool(row[0] or row[1]), row[2]

    def _lock_unrejected(self, sample_id: UUID, *, nothing: str) -> None:
        """Inside the caller's transaction: lock the sample's row, and
        refuse if it is already REJECTED.

        Every rejection path takes this lock before it changes anything
        (final review U5, 2026-09-23). The preserving path took it alone,
        so a record-only rejection that started while a preserving one was
        copying passed the unlocked pre-check in `reject`, waited on its
        UPDATE, and then, READ COMMITTED re-reading a row that still
        matched `WHERE id = %s`, overwrote the reason and appended a second
        REJECTED custody row saying the bytes were kept where they had in
        fact been moved. Now the second rejection waits here, reads
        REJECTED, and changes nothing.

        NO KEY UPDATE rather than UPDATE so that inserts elsewhere that only
        reference this row (a custody row written by somebody opening it,
        whose foreign key takes KEY SHARE) are not held up. The short wait
        is for THIS lock only; the audit append a caller may make later
        waits on the chain's advisory lock at the default timeout.
        """
        self._c.execute("SELECT set_config('lock_timeout', %s, true)",
                        (REJECT_LOCK_TIMEOUT,))
        locked = self._c.execute(
            """SELECT state FROM lab.sample WHERE id = %s
               FOR NO KEY UPDATE""", (sample_id,)).fetchone()
        self._c.execute("SET LOCAL lock_timeout TO DEFAULT")
        if locked is None:
            raise SampleError("no such sample")
        if locked[0] == REJECTED:
            raise SampleError(
                "already rejected (somebody else finished rejecting it while "
                f"this rejection was waiting). {nothing}")

    def _reject_destroying(self, sample_id: UUID, *, actor_id: UUID,
                           reason: str) -> Sample:
        """The `destroy` disposition: the object deleted, the key zeroed.

        Under the row lock, with the hold read again under it, so neither a
        concurrent rejection nor a hold placed since `reject` looked can be
        destroyed through (U5). There is no audit append here, so the
        delete holding the row lock holds up only this sample."""
        try:
            with self._c.transaction():
                self._lock_unrejected(sample_id, nothing="Nothing was "
                                      "destroyed.")
                held, storage_key = self._hold_and_key(sample_id)
                if held:
                    raise SampleError(_HOLD_REFUSES_DESTROY)
                self._storage.delete(storage_key)
                row = self._c.execute(
                    """UPDATE lab.sample
                          SET state = 'REJECTED', reject_reason = %s,
                              data_key_ciphertext = %s
                        WHERE id = %s AND state <> 'REJECTED'
                    RETURNING """ + _RETURNING,
                    # The data key is destroyed WITH the bytes, so that even
                    # if the object survives a bucket-lifecycle race nothing
                    # can decrypt it. Only with them, though: destroying the
                    # key while keeping the ciphertext preserves a file
                    # nobody can ever read, which satisfies a preservation
                    # order in form and defeats it in substance.
                    (reason, b"", sample_id)).fetchone()
                if row is None:
                    raise SampleError("already rejected")
                self._access(sample_id, actor_id, "REJECTED",
                             {"reason": reason, "bytes_purged": True,
                              "disposition": "destroyed"})
        except psycopg.errors.LockNotAvailable:
            raise _row_busy() from None
        return _record(row)

    def _reject_keeping(self, sample_id: UUID, *, actor_id: UUID,
                        reason: str) -> Sample:
        """`purge_bytes=False`: the rejection and its reason, recorded, and
        nothing disposed of. The bytes and the key stay where they were.
        Under the row lock, like every rejection (U5)."""
        try:
            with self._c.transaction():
                self._lock_unrejected(sample_id, nothing="Nothing was "
                                      "recorded.")
                held, _key = self._hold_and_key(sample_id)
                # `state <> 'REJECTED'` cannot fail under the lock; it is
                # the belt, as on the other two paths.
                row = self._c.execute(
                    """UPDATE lab.sample SET state = 'REJECTED',
                              reject_reason = %s
                        WHERE id = %s AND state <> 'REJECTED'
                    RETURNING """ + _RETURNING,
                    (reason, sample_id)).fetchone()
                if row is None:
                    raise SampleError("already rejected")
                detail = {"reason": reason, "bytes_purged": False,
                          "disposition": "kept"}
                if held:
                    detail["legal_hold"] = True
                self._access(sample_id, actor_id, "REJECTED", detail)
        except psycopg.errors.LockNotAvailable:
            raise _row_busy() from None
        return _record(row)

    def _reject_preserving(self, current: Sample, *, actor_id: UUID,
                           reason: str, storage_key: str,
                           held: bool) -> Sample:
        """The `preserve` disposition. See `reject` for the order and why."""
        if self._storage is None:
            raise SampleError(
                "the sample store is not configured, so there is nothing to "
                "copy into the preservation store and the rejection is "
                "refused rather than recorded as a preservation that did not "
                "happen. Fix the store, or record the rejection without "
                "disposing of the bytes (purge_bytes=False).")
        if self._preservation is None:
            raise SampleError(
                "the preservation store is not configured, so this rejection "
                "cannot preserve the sample and is refused rather than "
                "destroying it by default. Configure PRESERVE_BUCKET and its "
                f"credentials, set {DISPOSITION_ENV}=destroy deliberately, or "
                "record the rejection without disposing of the bytes "
                "(purge_bytes=False).")

        preserved_key = f"preserved/{current.sha256[:2]}/{current.sha256}"
        # Set once a held copy exists (the held PUT returned). From that
        # moment any failure must NAME the copy, because nothing in this
        # product can delete it.
        copy: PreservedObject | None = None
        # Set when the held PUT was sent and never answered: a held copy
        # may exist and its version is not known (C8).
        unconfirmed: PreservationUnconfirmed | None = None
        # Whether the working copy is gone: deleted by this attempt, or
        # already missing when a retry adopted the held copy (U4).
        working_gone = False
        # Set as the delete is sent: a delete that raised may still have
        # removed the object, and the refusal must not say otherwise.
        deleting = False
        adopted = False
        try:
            with self._c.transaction():
                # The row is locked BEFORE anything is copied (verifier on
                # F2, 2026-09-22). Two rejections of one sample used to
                # both copy into the preservation bucket; the loser's
                # guarded UPDATE then matched nothing and it raised a bare
                # "already rejected", leaving a held version that no row
                # named. Now the second waits here, reads REJECTED and
                # copies nothing.
                self._lock_unrejected(current.id, nothing="Nothing was "
                                      "copied.")
                try:
                    ciphertext = self._storage.get(storage_key)
                except Exception as exc:
                    copy = self._adopt_held_copy(current, preserved_key,
                                                 storage_key, exc)
                    adopted = working_gone = True
                if not adopted:
                    try:
                        copy = self._preservation.preserve(preserved_key,
                                                           ciphertext)
                    except PreservationUnverified as exc:
                        copy = exc.copy
                        raise
                    except PreservationUnconfirmed as exc:
                        unconfirmed = exc
                        raise
                    except SampleError as exc:
                        raise SampleError(
                            f"{exc} Nothing has changed: the sample is still "
                            f"in the working store and is not rejected."
                        ) from exc

                detail = {"reason": reason, "bytes_purged": False,
                          "disposition": "preserved",
                          "preserved_bucket": copy.bucket,
                          "preserved_key": copy.key,
                          "preserved_version_id": copy.version_id,
                          "preserved_bytes": copy.size}
                if adopted:
                    # Said in the ledger, because this rejection did not
                    # itself move the bytes: an earlier attempt did, and
                    # failed before it could record the move.
                    detail["adopted_held_copy"] = True
                if held:
                    detail["legal_hold"] = True
                # `state <> 'REJECTED'` cannot fail under the lock above; it
                # stays as the belt, and if it ever does fail the handler
                # below names the copy rather than losing it.
                row = self._c.execute(
                    """UPDATE lab.sample
                          SET state = 'REJECTED', reject_reason = %s,
                              preserved_bucket = %s, preserved_key = %s,
                              preserved_version_id = %s, preserved_at = now()
                        WHERE id = %s AND state <> 'REJECTED'
                    RETURNING """ + _RETURNING,
                    (reason, copy.bucket, copy.key, copy.version_id,
                     current.id)).fetchone()
                if row is None:
                    raise SampleError("the sample was rejected by somebody "
                                      "else while it was being copied")
                # The custody ledger takes no chain lock, so it goes before
                # the delete with the row it describes.
                self._access(current.id, actor_id, "REJECTED", detail)
                # Inside the transaction, so a working copy that will not
                # delete leaves the row unclaimed. BEFORE the audit append,
                # never after it (final review C7, 2026-09-23): the append
                # takes the audit chain's global advisory lock and holds it
                # to COMMIT, and this is a network call. Behind it, a
                # stalled store stalled every audited write in the
                # deployment, logins included, for as long as minio-py
                # kept retrying.
                if not adopted:
                    deleting = True
                    self._storage.delete(storage_key)
                    working_gone = True
                # LAST: nothing slow may run between this and COMMIT.
                self._audit("SAMPLE_REJECTED_PRESERVED", actor_id=actor_id,
                            sample_id=current.id,
                            detail={k: v for k, v in detail.items()
                                    if k != "reason"})
        except Exception as exc:
            if copy is None and unconfirmed is None:
                if isinstance(exc, psycopg.errors.LockNotAvailable):
                    # The row lock above timed out: before any copy.
                    raise _row_busy() from None
                raise
            refusal = self._preservation_incomplete(
                current.id, actor_id=actor_id, copy=copy,
                unconfirmed=unconfirmed, working_gone=working_gone,
                delete_unconfirmed=deleting and not working_gone,
                cause=exc)
            # Unchained when the cause is a database error, which after the
            # delete it most likely is: the audit append and COMMIT are all
            # that follow it. Chained, `safe_detail` threw the whole message
            # away and the analyst read "the request could not be completed
            # (ref ...)" instead of where the only copy of the sample now is
            # (final review verifier on U4, 2026-09-23). The database error
            # is logged against the ref the message carries.
            raise refusal from (None if _db_error_in(exc) else exc)
        return _record(row)

    def _adopt_held_copy(self, current: Sample, preserved_key: str,
                         storage_key: str, exc: BaseException
                         ) -> PreservedObject:
        """A retry whose working copy is gone: the held copy an earlier
        attempt left, proven to be this sample's, or a refusal that says
        which of four things is true.

        Final review U4, 2026-09-23. An attempt that deleted the working
        copy and then failed before COMMIT used to leave the next attempt
        here with nothing to read, answering "nothing to preserve" and
        pointing at a record-only rejection, which recorded the sample as
        kept in place, named no held copy, and could never be undone (a
        second rejection is refused, and retrieval needs `preserved_key`).

        Adopted only when the working store says the object is ABSENT (a
        store that did not answer proves nothing), when the newest version
        at the content-addressed key is under a hold, and when the kept data
        key opens it to this sample's SHA-256: the same proof a retrieval
        makes before it serves a byte, so a stray or foreign object at the
        key is never recorded as this sample. The plaintext exists only in
        this process's memory, for the length of the hash.
        """
        kind = type(exc).__name__
        if not _missing(exc):
            raise SampleError(
                f"the sample store could not be read at {storage_key} "
                f"({kind}), so nothing was copied. Nothing has changed. Try "
                f"again when the sample store answers.") from exc
        try:
            found = self._preservation.latest_held(preserved_key)
        except Exception as lookup:
            raise SampleError(
                f"the sample store has no object at {storage_key}, and the "
                f"preservation store could not be asked whether an earlier "
                f"attempt left a held copy of it at {preserved_key} "
                f"({type(lookup).__name__}). Nothing has changed. Try again "
                f"when the preservation store answers: recording the "
                f"rejection without the bytes now could leave such a copy "
                f"named by no row.") from lookup
        if found is None:
            # KeyError from a test double, S3Error NoSuchKey from MinIO,
            # and no held copy either: a row whose object is not in the
            # store (the demo seed writes none) has nothing to preserve,
            # and saying "preserved" for it would be the false record
            # `destroy` refuses to write too.
            raise SampleError(
                f"the sample store has no readable object at {storage_key} "
                f"({kind}) and the preservation store holds no copy of it, "
                f"so there is nothing to preserve. Nothing has changed. "
                f"Record the rejection without disposing of the bytes "
                f"(purge_bytes=False) if the object is known to be "
                f"gone.") from exc
        why = None
        if found.size != current.byte_size:
            why = (f"it is {found.size} bytes and this sample is "
                   f"{current.byte_size}")
        else:
            held_at = (f"the held copy at {found.bucket}/{found.key} (version "
                       f"{found.version_id})")
            key_row = self._c.execute(
                "SELECT data_key_ciphertext, data_key_id FROM lab.sample "
                "WHERE id = %s", (current.id,)).fetchone()
            # Both refused as a SampleError naming what was found, so a key
            # ring or a store that fails here answers the router's 409 and
            # not a bare 500 (final review verifier on U4, 2026-09-23: a
            # missing working object had always been a 409 before adoption
            # added these two calls).
            try:
                data_key = bytes.fromhex(envelope.decrypt(
                    bytes(key_row[0]), key_id=key_row[1]))
            except Exception as err:
                raise SampleError(
                    f"the sample store has no object at {storage_key}, and "
                    f"{held_at} could not be checked against this sample "
                    f"because its data key could not be opened "
                    f"({type(err).__name__}). It was not recorded as this "
                    f"sample's copy and nothing has changed. Raise it with "
                    f"whoever administers the key ring before rejecting "
                    f"this sample.") from err
            try:
                held_bytes = self._preservation.get(
                    found.key, version_id=found.version_id,
                    bucket=found.bucket)
            except Exception as err:
                raise SampleError(
                    f"the sample store has no object at {storage_key}, and "
                    f"{held_at} could not be read to check that it is this "
                    f"sample ({type(err).__name__}). It was not recorded as "
                    f"this sample's copy and nothing has changed. Try again "
                    f"when the preservation store answers.") from err
            digest = hashlib.sha256(_xor_stream(held_bytes, data_key))
            if digest.hexdigest() != current.sha256:
                why = "this sample's data key does not open it to its SHA-256"
        if why is not None:
            raise SampleError(
                f"the sample store has no object at {storage_key}, and the "
                f"held copy at {found.bucket}/{found.key} (version "
                f"{found.version_id}) is not this sample: {why}. It was not "
                f"recorded as this sample's copy and nothing has changed. "
                f"Raise it with whoever administers the preservation "
                f"store before rejecting this sample.") from exc
        return found

    def _preservation_incomplete(self, sample_id: UUID, *, actor_id: UUID,
                                 copy: PreservedObject | None,
                                 unconfirmed: PreservationUnconfirmed | None,
                                 working_gone: bool,
                                 delete_unconfirmed: bool,
                                 cause: BaseException) -> SampleError:
        """The refusal for a preserving rejection that failed once a held
        copy existed (or may have), and a record of it that outlives the
        rolled-back transaction.

        Final review C8 and U4, 2026-09-23. The message names the copy,
        says truthfully whether the working copy is gone, and says what a
        retry will do. It never says "legal hold" or `purge_bytes`: the
        console reads either as "offer the record-only rejection", which
        is the one way out that strands a held copy. The audit row is its
        own statement on the autocommit connection, after the rollback;
        when the connection itself is what failed, the message says the
        row could not be written rather than implying it was.

        A database error is named by its class only, never its text (raw PQ
        output, which the HTTP layer must not return), and logged in full
        against a ref the message and the audit row both carry. The caller
        raises the result unchained in that case, so the message survives
        `safe_detail` (final review verifier on U4, 2026-09-23).
        """
        db = _db_error_in(cause)
        ref = None
        if db is None:
            failure = f"{type(cause).__name__}: {cause}"
        else:
            ref = secrets.token_hex(6)
            failure = (f"{type(db).__name__}, a database error; the server "
                       f"log has it under ref {ref}")
        if copy is not None:
            where = (f"{copy.bucket}/{copy.key}, version {copy.version_id}")
            said = f"A held copy of this sample exists at {where}."
        else:
            where = f"{unconfirmed.bucket}/{unconfirmed.key}"
            said = (f"A held copy of this sample may exist at {where}; the "
                    f"store did not say, and its version is not known here.")
        if working_gone:
            state = ("The working copy is no longer in the samples store, so "
                     "the held copy is now the only copy of this sample. "
                     "Reopen the sample: if it is not shown as rejected, "
                     "reject it again, and the retry records the held copy "
                     "rather than copying again.")
        elif delete_unconfirmed:
            state = ("Nothing was recorded, and the samples store did not "
                     "confirm deleting the working copy, so it may or may "
                     "not still be there. Rejecting it again copies it "
                     "again (a new held version) if it is, and records the "
                     "held copy if it is not.")
        else:
            state = ("Nothing was recorded and the working copy was not "
                     "deleted. Rejecting it again copies it again (a new "
                     "held version), or, if the working copy turns out to "
                     "be gone, records the held copy.")
        detail = {"preserved_bucket": copy.bucket if copy else
                  unconfirmed.bucket,
                  "preserved_key": copy.key if copy else unconfirmed.key,
                  "preserved_version_id": copy.version_id if copy else None,
                  "copy_confirmed": copy is not None,
                  "working_copy_gone": working_gone,
                  "working_delete_unconfirmed": delete_unconfirmed,
                  "failure": type(cause).__name__}
        if ref is not None:
            detail["log_ref"] = ref
            log.warning(
                "a preserving rejection of sample %s failed on a database "
                "error after the held copy (%s), ref %s", sample_id, where,
                ref, exc_info=cause)
        try:
            self._audit("SAMPLE_PRESERVATION_INCOMPLETE", actor_id=actor_id,
                        sample_id=sample_id, outcome="FAILED", detail=detail)
            logged = "This has been written to the audit log."
        except Exception:
            log.warning(
                "a preserving rejection of sample %s failed after the held "
                "copy (%s) and the audit row recording that failed too",
                sample_id, where, exc_info=True)
            logged = ("It could not be written to the audit log either, so "
                      "keep this message.")
        return SampleError(
            f"the rejection could not be completed ({failure}). {said} "
            f"{state} {logged}")

    # -- queue -------------------------------------------------------------

    def assign(self, sample_id: UUID, *, analyst_id: UUID,
               actor_id: UUID) -> Sample:
        row = self._c.execute(
            """UPDATE lab.sample
                  SET assigned_to = %s, assigned_at = now(), state = 'ASSIGNED'
                WHERE id = %s AND state IN ('QUARANTINED','TRIAGED')
            RETURNING """ + _RETURNING,
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
                "error. It has been written to the custody ledger and the "
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
                      s.sha256, s.state, s.preserved_key
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
            # Three different answers since 0063, because "its bytes
            # destroyed" was the only sentence this had and it became false
            # for two of the three dispositions.
            if row[5]:
                raise SampleError(
                    "this sample was rejected and preserved: its bytes are in "
                    "the preservation store under a legal hold, and they are "
                    "released only as a preserved-sample retrieval, which "
                    "needs a live authorisation from a Security Officer "
                    "naming you.")
            if not row[1]:
                raise SampleError(
                    "this sample was rejected and its bytes destroyed")
            raise SampleError(
                "this sample was rejected. Its bytes were left where they "
                "were when the rejection was recorded, and a rejected sample "
                "is not released through the download.")
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
        split = _mint_split(request_origin)
        self._downloadable(sample_id, clearance=clearance,
                           compartments=compartments)
        return self._mint_ticket(sample_id, actor_id=actor_id,
                                 session_id=session_id, ip_hash=ip_hash,
                                 purpose=TICKET_DOWNLOAD,
                                 audit_action="SAMPLE_DOWNLOAD_TICKET_ISSUED",
                                 sample_origin=split.sample)

    def _mint_ticket(self, sample_id: UUID, *, actor_id: UUID,
                     session_id: UUID | None, ip_hash: bytes | None,
                     purpose: str, audit_action: str,
                     sample_origin: str | None,
                     extra: dict | None = None) -> DownloadTicket:
        """The one INSERT both mints share (0063 split it out of
        `issue_download_ticket` when the retrieval ticket arrived), so the
        hash, the database-clock expiry and the issue audit cannot drift
        between a download and a retrieval."""
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
                    ip_hash, purpose)
               VALUES (%s, %s, %s, %s, now() + %s, %s, %s)
               RETURNING id, expires_at""",
            (hash_token(raw), sample_id, actor_id, session_id,
             timedelta(seconds=DOWNLOAD_TICKET_TTL_SECONDS),
             ip_hash, purpose)).fetchone()
        # Audited as an ISSUE, not as custody. `lab.sample_access` is the
        # record of who took a copy, its action set is closed, and a
        # ticket is not a copy -- the custody row is written when the
        # bytes are actually served, and it names this ticket.
        detail = {"ticket_id": str(row[0]),
                  "expires_at": row[1].isoformat(),
                  "ttl_seconds": DOWNLOAD_TICKET_TTL_SECONDS,
                  "sample_origin": sample_origin}
        if purpose != TICKET_DOWNLOAD:
            detail["purpose"] = purpose
        detail.update(extra or {})
        self._audit(audit_action, actor_id=actor_id,
                    sample_id=sample_id, session_id=session_id,
                    ip_hash=ip_hash, detail=detail)
        return DownloadTicket(id=row[0], raw=raw, sample_id=sample_id,
                              user_id=actor_id, expires_at=row[1])

    def redeem_download_ticket(self, presented: str, *, sample_id: UUID,
                               ip_hash: bytes | None = None
                               ) -> Redemption:
        """Spend a ticket. Returns `(user_id, ticket_id, purpose)`; raises
        on anything else. The purpose (0063) says whether the bytes come
        from the working store or, for a preserved sample, the
        preservation store; it is read from the row, never from the
        request.

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
            RETURNING id, user_id, session_id, token_hash, purpose""",
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
        # The permission re-read belongs to the ticket's PURPOSE (0063): a
        # retrieval ticket was minted under `sample.preserved.retrieve`,
        # which the retriever's role holds and `sample.download` is not.
        permission = _PURPOSE_PERMISSION[row[4]]
        if not self._still_authorised(holder, permission):
            self._audit("SAMPLE_DOWNLOAD_TICKET_REFUSED", actor_id=holder,
                        sample_id=sample_id, session_id=row[2],
                        outcome="DENIED", ip_hash=ip_hash,
                        detail={"reason": self._authority_refusal(
                                    holder, permission),
                                # The row was spent by the UPDATE above, so
                                # the ledger and the audit agree about a
                                # ticket that reads as redeemed and served
                                # nothing.
                                "ticket_id": str(row[0]), "spent": True})
            raise SampleError(_TICKET_REFUSED)
        redeemed = {"ticket_id": str(row[0])}
        if row[4] != TICKET_DOWNLOAD:
            redeemed["purpose"] = row[4]
        self._audit("SAMPLE_DOWNLOAD_TICKET_REDEEMED", actor_id=holder,
                    sample_id=sample_id, session_id=row[2], ip_hash=ip_hash,
                    detail=redeemed)
        return Redemption(holder, row[0], row[4])

    def _still_authorised(self, user_id: UUID,
                          permission: str = DOWNLOAD_PERMISSION) -> bool:
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
            user_id, permission)

    def _authority_refusal(self, user_id: UUID,
                           permission: str = DOWNLOAD_PERMISSION) -> str:
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
        if permission == RETRIEVE_PERMISSION:
            return "retrieve_permission_revoked"
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

    # -- preserved samples: two people to get one back out (F2, 0063) -----

    def resolve_account(self, value: str) -> UUID:
        """An account named by id or by email, for the authorisation form.

        The Security Officer granting a retrieval knows the person, not
        their uuid, and the detonation form's "user id of the person"
        field is the example of what that costs. Active accounts only: an
        authorisation for a disabled account authorises nobody and would
        read, later, as though it had."""
        text = (value or "").strip()
        if not text:
            raise SampleError("name the person being authorised")
        try:
            row = self._c.execute(
                "SELECT id FROM iam.app_user WHERE id = %s AND is_active",
                (UUID(text),)).fetchone()
        except ValueError:
            row = self._c.execute(
                "SELECT id FROM iam.app_user "
                "WHERE lower(email) = lower(%s) AND is_active",
                (text,)).fetchone()
        if row is None:
            raise SampleError(f"no active account is {text!r}")
        return row[0]

    def grant_preservation_authorisation(
            self, sample_id: UUID, *, granted_to: UUID, granted_by: UUID,
            scope_note: str, legal_basis: str,
            duration: timedelta = timedelta(days=7)) -> UUID:
        """Authorise ONE named person to retrieve ONE preserved sample.

        Modelled on `IngestService.grant_pii_authorisation`: time-boxed,
        justified, two humans. The person granting and the person granted
        cannot be one person (a CHECK in 0063 as well as this refusal),
        the scope has a length floor because a blanket authorisation is
        not one, the legal basis is mandatory, and the window is capped at
        thirty days.

        The grantee must hold `sample.preserved.retrieve` now. An
        authorisation for somebody whose role cannot use it authorises
        nothing, and a Security Officer told so at the time can pick the
        right person instead of finding out from a refusal later.
        """
        if granted_to == granted_by:
            raise SampleError(
                "a retrieval authorisation needs two people: authorising "
                "yourself is not an authorisation, it is the control removed")
        if len((scope_note or "").strip()) <= 20:
            raise SampleError(
                "say what may be retrieved and why. A blanket authorisation "
                "is not one, and this is the text somebody defends later.")
        if not (legal_basis or "").strip():
            raise SampleError("a legal basis is mandatory")
        if duration <= timedelta(0) or duration > timedelta(
                days=MAX_AUTHORISATION_DAYS):
            raise SampleError(
                f"an authorisation lasts between a moment and "
                f"{MAX_AUTHORISATION_DAYS} days")
        sample = self.get(sample_id)
        if sample is None:
            raise SampleError("no such sample")
        if not sample.preserved_key:
            raise SampleError(
                "only a preserved sample can be authorised for retrieval; "
                "this one is not in the preservation store")
        if not IamAdminService(self._c).holds_global_permission(
                granted_to, RETRIEVE_PERMISSION):
            raise SampleError(
                f"that account does not hold {RETRIEVE_PERMISSION} (the case "
                f"owner role carries it), so an authorisation would authorise "
                f"nothing")
        row = self._c.execute(
            """INSERT INTO lab.preservation_authorisation
                   (sample_id, granted_to, granted_by, scope_note, legal_basis,
                    expires_at)
               VALUES (%s, %s, %s, %s, %s, now() + %s)
               RETURNING id, expires_at""",
            (sample_id, granted_to, granted_by, scope_note.strip(),
             legal_basis.strip(), duration)).fetchone()
        self._audit("SAMPLE_PRESERVED_AUTHORISATION_GRANTED",
                    actor_id=granted_by, sample_id=sample_id,
                    detail={"authorisation_id": str(row[0]),
                            "granted_to": str(granted_to),
                            "scope": scope_note.strip(),
                            "legal_basis": legal_basis.strip(),
                            "expires_at": row[1].isoformat()})
        return row[0]

    def revoke_preservation_authorisation(self, authorisation_id: UUID, *,
                                          sample_id: UUID,
                                          actor_id: UUID) -> None:
        """End an authorisation early. A column, never a DELETE: 0063's
        trigger refuses both a delete and an un-revoke."""
        row = self._c.execute(
            """UPDATE lab.preservation_authorisation
                  SET revoked_at = now(), revoked_by = %s
                WHERE id = %s AND sample_id = %s AND revoked_at IS NULL
            RETURNING id""", (actor_id, authorisation_id, sample_id)).fetchone()
        if row is None:
            raise SampleError(
                "no unrevoked authorisation with that id on this sample")
        self._audit("SAMPLE_PRESERVED_AUTHORISATION_REVOKED",
                    actor_id=actor_id, sample_id=sample_id,
                    detail={"authorisation_id": str(authorisation_id)})

    def preservation_authorisations(self, sample_id: UUID) -> list[dict]:
        """Every authorisation ever granted on this sample, newest first,
        with names rather than uuids: the point of the record is that a
        NAMED person allowed a NAMED person, and a reviewer who has to look
        the ids up separately will not."""
        rows = self._c.execute(
            """SELECT a.id, a.granted_to, gt.display_name, gt.email,
                      gb.display_name, gb.email, a.scope_note, a.legal_basis,
                      a.created_at, a.expires_at, a.revoked_at, rb.email,
                      a.retrieval_count,
                      a.revoked_at IS NULL AND a.expires_at > now()
                 FROM lab.preservation_authorisation a
                 JOIN iam.app_user gt ON gt.id = a.granted_to
                 JOIN iam.app_user gb ON gb.id = a.granted_by
                 LEFT JOIN iam.app_user rb ON rb.id = a.revoked_by
                WHERE a.sample_id = %s
                ORDER BY a.created_at DESC""", (sample_id,)).fetchall()
        return [{"id": str(r[0]), "granted_to": str(r[1]),
                 "granted_to_name": r[2], "granted_to_email": r[3],
                 "granted_by_name": r[4], "granted_by_email": r[5],
                 "scope_note": r[6], "legal_basis": r[7],
                 "created_at": r[8].isoformat(),
                 "expires_at": r[9].isoformat(),
                 "revoked_at": r[10].isoformat() if r[10] else None,
                 "revoked_by_email": r[11], "retrieval_count": r[12],
                 "live": bool(r[13])} for r in rows]

    def preserved_for_authorisation(self, *, clearance: str | None,
                                    compartments: frozenset[str] = frozenset(),
                                    limit: int = 100) -> list[dict]:
        """The Security Officer's list: every preserved sample the officer's
        labels reach, with its authorisations, and NOTHING of its content.

        Final review U3, 2026-09-23. The officer's half of the two-person
        retrieval lived only in the Lab's sample card, which needs
        `sample.read`, and SECURITY_OFFICER holds no `sample.read` (nor may
        it: Security Officers read no case content). So the one role that
        may authorise a retrieval could not reach the form, and the case
        owner was told to ask for something nobody could give.

        What is returned is what an authorisation is ABOUT and nothing
        more: which sample (hash, size, labels), where it is held and since
        when, whether a legal hold covers it, the case's code (the label
        the break-glass review queue already shows the same officer), and
        who has been authorised. No filename, source note, rejection
        reason, analysis or custody: those are the case's content, and the
        officer decides on the request and its legal basis, not on the
        material. The label composition is `queue()`'s, and it is the same
        gate the authorise route applies, so a sample listed here is one
        the officer can act on.
        """
        if clearance is None:
            raise SampleError(
                "the preserved-sample list needs the caller's clearance; a "
                "default would list every compartment to whoever forgot it")
        rows = self._c.execute(
            """SELECT s.id, s.sha256, s.byte_size, s.preserved_bucket,
                      s.preserved_key, s.preserved_at,
                      s.legal_hold OR coalesce(c.legal_hold, false), c.code,
                      greatest(s.classification,
                               coalesce(c.classification, s.classification))
                 FROM lab.sample s
                 LEFT JOIN core."case" c ON c.id = s.case_id
                WHERE s.preserved_key IS NOT NULL
                  AND greatest(s.classification,
                               coalesce(c.classification, s.classification))
                      <= %s::core.tlp
                  AND (s.compartments
                       || coalesce(c.compartments, '{}')) <@ %s
                ORDER BY s.preserved_at DESC LIMIT %s""",
            (clearance, list(compartments), limit)).fetchall()
        return [{"id": str(r[0]), "sha256": bytes(r[1]).hex(),
                 "byte_size": r[2], "preserved_bucket": r[3],
                 "preserved_key": r[4], "preserved_at": r[5].isoformat(),
                 "legal_hold": bool(r[6]), "case_code": r[7],
                 "classification": r[8],
                 "authorisations": self.preservation_authorisations(r[0])}
                for r in rows]

    def live_preservation_authorisation(self, user_id: UUID,
                                        sample_id: UUID) -> UUID | None:
        row = self._c.execute(
            """SELECT id FROM lab.preservation_authorisation
                WHERE granted_to = %s AND sample_id = %s
                  AND revoked_at IS NULL AND expires_at > now()
                ORDER BY expires_at DESC LIMIT 1""",
            (user_id, sample_id)).fetchone()
        return row[0] if row else None

    def _refuse_retrieval(self, sample_id: UUID, actor_id: UUID, reason: str,
                          message: str, *, stage: str,
                          error: type[SampleError] = SampleError,
                          session_id: UUID | None = None,
                          ip_hash: bytes | None = None) -> None:
        """Audit a refused retrieval, then raise.

        Every refusal is written, not only the missing authorisation: a
        preserved sample is material somebody decided to hold under a
        legal hold, and "who tried to get it out, and why were they
        stopped" is a question a Security Officer must be able to answer
        years later. The caller here is always an authenticated account,
        so unlike an unknown download ticket this cannot be used to append
        to the audit chain anonymously. Autocommit, so the row survives
        the raise.
        """
        self._audit("SAMPLE_PRESERVED_RETRIEVAL_REFUSED", actor_id=actor_id,
                    sample_id=sample_id, outcome="DENIED",
                    session_id=session_id, ip_hash=ip_hash,
                    detail={"reason": reason, "stage": stage})
        raise error(message)

    def _retrievable(self, sample_id: UUID, *, actor_id: UUID,
                     clearance: str | None, compartments: frozenset[str],
                     stage: str, session_id: UUID | None = None,
                     ip_hash: bytes | None = None) -> tuple:
        """The label and state half of a retrieval: the same composition
        `_downloadable` makes, then "is it preserved". Returns
        `(sha256, data_key_ciphertext, data_key_id, preserved_bucket,
        preserved_key, preserved_version_id)`."""
        _require_clearance(clearance)
        row = self._c.execute(
            """SELECT s.sha256, s.data_key_ciphertext, s.data_key_id,
                      s.preserved_bucket, s.preserved_key,
                      s.preserved_version_id
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
            self._refuse_retrieval(sample_id, actor_id, "not_visible",
                                   "no such sample", stage=stage,
                                   session_id=session_id, ip_hash=ip_hash)
        if not row[4]:
            self._refuse_retrieval(
                sample_id, actor_id, "not_preserved",
                "this sample is not in the preservation store, so there is "
                "nothing to retrieve. Only a sample rejected under the "
                "'preserve' disposition is held there.", stage=stage,
                session_id=session_id, ip_hash=ip_hash)
        return row

    def _require_live_authorisation(self, sample_id: UUID, actor_id: UUID, *,
                                    stage: str, session_id: UUID | None = None,
                                    ip_hash: bytes | None = None) -> UUID:
        authorisation = self.live_preservation_authorisation(actor_id,
                                                             sample_id)
        if authorisation is None:
            self._refuse_retrieval(
                sample_id, actor_id, "no_live_authorisation",
                "retrieving a preserved sample needs a live authorisation "
                "naming you, granted by a Security Officer, and you hold none "
                "for this sample. Ask one to authorise you: nobody may grant "
                "that to themselves, which is the point of it.",
                stage=stage, error=AuthorisationRequired,
                session_id=session_id, ip_hash=ip_hash)
        return authorisation

    def issue_retrieval_ticket(self, sample_id: UUID, *, actor_id: UUID,
                               clearance: str | None = None,
                               compartments: frozenset[str] = frozenset(),
                               session_id: UUID | None = None,
                               ip_hash: bytes | None = None,
                               request_origin: str | None = None
                               ) -> DownloadTicket:
        """The retrieval's half of the 0061 hand-off: a one-shot,
        sixty-second ticket, minted on the APPLICATION origin, spent at
        the sample origin's download path.

        A retrieval is sample bytes, so invariant 10 applies to it exactly
        as to a download: they come from the separate origin or not at
        all, and the sample process serves the download path and nothing
        else. Reusing that path, and the ticket that crosses to it, is what
        keeps a second door from being opened on the one process the split
        exists to keep narrow. The ticket carries `purpose =
        'preserved_retrieval'`, so it cannot be spent as a download.

        Refuses (and audits the refusal) unless the caller holds a LIVE
        authorisation for this sample. The redemption checks it again,
        because an authorisation revoked inside the sixty seconds must
        bite before a byte moves.
        """
        split = _mint_split(request_origin)
        self._retrievable(sample_id, actor_id=actor_id, clearance=clearance,
                          compartments=compartments, stage="mint",
                          session_id=session_id, ip_hash=ip_hash)
        authorisation = self._require_live_authorisation(
            sample_id, actor_id, stage="mint", session_id=session_id,
            ip_hash=ip_hash)
        return self._mint_ticket(
            sample_id, actor_id=actor_id, session_id=session_id,
            ip_hash=ip_hash, purpose=TICKET_RETRIEVAL,
            audit_action="SAMPLE_RETRIEVAL_TICKET_ISSUED",
            sample_origin=split.sample,
            extra={"authorisation_id": str(authorisation)})

    def retrieve_preserved(self, sample_id: UUID, *, actor_id: UUID,
                           request_origin: str | None = None,
                           clearance: str | None = None,
                           compartments: frozenset[str] = frozenset(),
                           ticket_id: UUID | None = None
                           ) -> tuple[bytes, str]:
        """A preserved sample, in the SAME encrypted archive a download
        produces, under a live authorisation somebody else granted.

        Never plaintext: the held ciphertext is opened with the kept data
        key, re-verified against the recorded SHA-256 (a mismatch is the
        same recorded tamper alarm a download raises), and wrapped by
        `archive()`, whose password is an interlock and not
        confidentiality. The legal hold is not touched: nothing in
        `PreservationStorage` can lift one, and this reads the held
        version in place.

        Written down on both outcomes. Every refusal is an audit row
        (`SAMPLE_PRESERVED_RETRIEVAL_REFUSED`, with the reason); a success
        is a custody row naming the authorisation and the store, an audit
        row, and one more on the authorisation's retrieval count.
        """
        _require_clearance(clearance)
        split = origin_split(this=request_origin)
        if not split.serves_here:
            self._refuse_retrieval(sample_id, actor_id, "origin_split",
                                   split.refusal, stage="retrieve")
        row = self._retrievable(sample_id, actor_id=actor_id,
                                clearance=clearance,
                                compartments=compartments, stage="retrieve")
        authorisation = self._require_live_authorisation(
            sample_id, actor_id, stage="retrieve")
        if self._preservation is None:
            raise SampleError("the preservation store is not configured")
        if not row[1]:
            raise SampleError("this sample has no data key; it cannot be read")

        sha256, key_blob, key_id, bucket, key, version = row
        data_key = bytes.fromhex(envelope.decrypt(key_blob, key_id=key_id))
        ciphertext = self._preservation.get(key, version_id=version,
                                            bucket=bucket)
        data = _xor_stream(ciphertext, data_key)
        digest = hashlib.sha256(data).digest()
        if digest != bytes(sha256):
            # The download's tamper discipline, word for word: recorded in
            # its own transaction so the alarm survives the raise.
            with self._c.transaction():
                self._access(
                    sample_id, actor_id, "VIEWED_META",
                    {"event": "integrity_check_failed",
                     "recorded_sha256": bytes(sha256).hex(),
                     "computed_sha256": digest.hex(),
                     "store": "preservation", "preserved_key": key})
                self._c.execute(
                    """INSERT INTO audit.event
                           (actor_id, actor_kind, action, object_type,
                            object_id, outcome, detail)
                       VALUES (%s, 'USER', 'SAMPLE_INTEGRITY_ALARM', 'sample',
                               %s, 'DENIED', %s)""",
                    (actor_id, sample_id,
                     Json({"recorded_sha256": bytes(sha256).hex(),
                           "computed_sha256": digest.hex(),
                           "store": "preservation"})))
            raise SampleError(
                "preserved sample integrity check failed: the held bytes do "
                "not match the recorded sha256. This is a tamper alarm, not "
                "a transient error. It has been written to the custody "
                "ledger and the audit log, and nothing has been served.")

        custody = {"source": "preservation_store", "origin": split.sample,
                   "preserved_bucket": bucket, "preserved_key": key,
                   "preserved_version_id": version,
                   "authorisation_id": str(authorisation)}
        if ticket_id is not None:
            custody["via"] = "ticket"
            custody["ticket_id"] = str(ticket_id)
        with self._c.transaction():
            self._c.execute(
                "UPDATE lab.preservation_authorisation "
                "SET retrieval_count = retrieval_count + 1 WHERE id = %s",
                (authorisation,))
            self._access(sample_id, actor_id, "DOWNLOADED", custody,
                         archive_format="ZIP_INFECTED")
            self._audit("SAMPLE_PRESERVED_RETRIEVED", actor_id=actor_id,
                        sample_id=sample_id,
                        detail={k: v for k, v in custody.items()
                                if k != "origin"})
        return archive(data, digest.hex()), digest.hex()

    # -- the ledger and the names in it ------------------------------------

    def record_view(self, sample_id: UUID, *, actor_id: UUID) -> bool:
        """Write that somebody opened this sample's record.

        The console's ledger promised "every look is a row" and opening a
        sample wrote nothing, so an analyst relying on it to show who had
        seen a sample was misled (ux13-lab:custody-ledger-hides-who-and-
        what, 2026-09-22). Once per person per `VIEW_DEDUPE_SECONDS`: the
        console reopens the record after each action it takes, and those
        reopenings are not separate looks. Returns whether a row was
        written."""
        recent = self._c.execute(
            """SELECT 1 FROM lab.sample_access
                WHERE sample_id = %s AND actor_id = %s
                  AND action = 'VIEWED_META' AND detail->>'event' = 'viewed'
                  AND occurred_at > now() - %s
                LIMIT 1""",
            (sample_id, actor_id,
             timedelta(seconds=VIEW_DEDUPE_SECONDS))).fetchone()
        if recent:
            return False
        self._access(sample_id, actor_id, "VIEWED_META", {"event": "viewed"})
        return True

    def people(self, ids) -> dict[str, dict]:
        """`{uuid: {"name", "email"}}` for the accounts a record names.

        Submitter and assignee were returned as bare uuids and the console
        read neither (ux13-lab:provenance-never-shown). Names, because
        provenance nobody can read is not provenance."""
        wanted = sorted({str(i) for i in ids if i})
        if not wanted:
            return {}
        rows = self._c.execute(
            "SELECT id, display_name, email FROM iam.app_user "
            "WHERE id = ANY(%s::uuid[])", (wanted,)).fetchall()
        return {str(r[0]): {"name": r[1], "email": r[2]} for r in rows}

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
            f"SELECT {_RETURNING} FROM lab.sample WHERE id = %s",
            (sample_id,)).fetchone()
        return _record(row) if row else None

    def queue(self, *, states: tuple[str, ...] = WORKING_SET,
              clearance: str | None = None,
              compartments: frozenset[str] = frozenset(),
              case_id: UUID | None = None,
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

        `states` is honoured, and `case_id` narrows to one case (2026-09-22).
        The route used to take neither, so the console filtered the working
        set client-side: Rejected, In analysis and Reported were always
        empty, and a Lab opened inside one case listed every case's
        samples (ux13-lab:rejected-filter-always-empty,
        ux13-lab:lab-not-case-scoped). Narrowing by case discloses nothing
        the unfiltered queue does not: the label predicate below is the
        gate either way.
        """
        unknown = [s for s in states if s not in QUEUE_STATES + (SUBMITTED,)]
        if unknown:
            raise SampleError(
                f"unknown sample state {unknown[0]!r}: the states are "
                f"{', '.join(QUEUE_STATES)}")
        if clearance is None:
            raise SampleError(
                "queue() needs the caller's clearance. It used to default to "
                "RED, so a caller that forgot became maximally privileged in "
                "silence, which is exactly how download() came to have no "
                "label check at all.")
        rows = self._c.execute(
            f"""SELECT {_SELECT} FROM lab.sample s
                 LEFT JOIN core."case" c ON c.id = s.case_id
                WHERE s.state = ANY(%s::lab.sample_state[])
                  AND (%s::uuid IS NULL OR s.case_id = %s::uuid)
                  AND greatest(s.classification,
                               coalesce(c.classification, s.classification))
                      <= %s::core.tlp
                  AND (s.compartments
                       || coalesce(c.compartments, '{{}}')) <@ %s
                ORDER BY s.submitted_at DESC LIMIT %s""",
            (list(states), case_id, case_id, clearance, list(compartments),
             limit)).fetchall()
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
            f"""SELECT {_SELECT} FROM lab.sample s
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
        """The ledger, with WHO in it.

        `actor_id`, `archive_format` and `detail` were always returned and
        the console dropped all three, so the chain of custody for
        attacker-supplied binaries named nobody, and a submission and a
        failed integrity check both read "VIEWED_META"
        (ux13-lab:custody-ledger-hides-who-and-what, 2026-09-22). The
        actor's name and email come back now, and for an assignment the
        assignee's too; `detail.event` is what tells the console which
        VIEWED_META row it is looking at.
        """
        rows = self._c.execute(
            """SELECT a.actor_id, a.action, a.occurred_at, a.archive_format,
                      a.detail, u.display_name, u.email,
                      an.display_name, an.email
                 FROM lab.sample_access a
                 LEFT JOIN iam.app_user u ON u.id = a.actor_id
                 LEFT JOIN iam.app_user an
                        ON a.action = 'ASSIGNED'
                       AND an.id::text = a.detail->>'analyst_id'
                WHERE a.sample_id = %s
                ORDER BY a.occurred_at DESC, a.id DESC""",
            (sample_id,)).fetchall()
        return [{"actor_id": str(r[0]), "action": r[1],
                 "occurred_at": r[2].isoformat(), "archive_format": r[3],
                 "detail": r[4], "actor_name": r[5], "actor_email": r[6],
                 "event": (r[4] or {}).get("event"),
                 "analyst_name": r[7], "analyst_email": r[8]}
                for r in rows]

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
            "classification, compartments, preserved_bucket, preserved_key, "
            "preserved_at, legal_hold")
#: The same list, table-qualified, for the reads that JOIN `core."case"` to
#: compose its labels. Derived from the one string rather than restated, so
#: the two cannot fall out of step and unpack into the wrong fields — the
#: same discipline `notifications._N_COLUMNS` uses for the same reason.
_SAMPLE_COLUMNS = ", ".join("s." + c.strip() for c in _COLUMNS.split(","))
#: Whether the data key has been destroyed, read as a BOOLEAN (0063). The
#: console needs to say "destroyed" or "kept" for a rejected sample, and
#: selecting the sealed key itself to decide that would carry key material
#: through every queue read for the sake of one word.
_RETURNING = _COLUMNS + ", octet_length(data_key_ciphertext) = 0"
_SELECT = _SAMPLE_COLUMNS + ", octet_length(s.data_key_ciphertext) = 0"


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


def _mint_split(request_origin: str | None) -> OriginSplit:
    """The two configuration refusals every ticket mint makes before it
    looks at anything, hoisted out of `issue_download_ticket` (0063) so the
    retrieval mint states the same ones rather than a copy of them.

    - `split_problem`: the control is off, the value is not an origin, or
      it is a second name for the application's. A ticket whose
      `download_url` points at an origin that refuses every download is a
      worse answer than a refusal here;
    - this process IS the sample origin, which serves sample bytes and
      nothing else, and on which no analyst session may run.
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
    return split


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
        preserved_bucket=r[18], preserved_key=r[19], preserved_at=r[20],
        legal_hold=bool(r[21]), key_destroyed=bool(r[22]),
    )


__all__ = [
    "ARCHIVE_PASSWORD", "ASSIGNED", "AUTHORISE_PERMISSION",
    "AuthorisationRequired", "DESTROY", "DISPOSITION_ENV", "DISPOSITIONS",
    "DOWNLOAD_PERMISSION", "DOWNLOAD_TICKET_TTL_SECONDS",
    "PRESERVE", "PreservationStorage", "PreservedObject", "QUEUE_STATES",
    "RETRIEVE_PERMISSION", "Redemption", "TICKET_DOWNLOAD",
    "TICKET_RETRIEVAL", "WORKING_SET", "disposition_setting",
    "rejected_sample_disposition",
    "IN_ANALYSIS", "MAX_SAMPLE_BYTES",
    "QUARANTINED", "REJECTED", "REPORTED", "SUBMITTED", "TRIAGED",
    "DownloadTicket", "OriginSplit", "PolicyNotDeclared", "Sample",
    "SampleError", "SampleService", "Triage", "app_origin", "archive",
    "download_cors_headers", "file_type_of", "new_download_ticket",
    "normalise_origin",
    "origin_split", "policy_declared", "public_origin", "sample_origin",
    "SampleStorage", "shannon_entropy", "triage",
]
