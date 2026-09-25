"""Phase 4 -- collection: the adapter interface, the scheduler, the persona
vault and watch matching (docs/04).

The `collect.*` schema has existed since Phase 0. This is the code, and it
arrives LAST among the buildable phases on purpose. docs/09:

    The graph and assertion layer must work end to end before collection
    is switched on. Pointing a firehose at a half-built model produces a
    landfill you then have to clean by hand.

## Invariant 7 is the shape of this module

    Credentials never leave the vault. `collection_account.secret_*`
    is decrypted only inside the collection worker, never in the API
    process, never serialised to a response, never logged.

So `PersonaVault.use()` is a CONTEXT MANAGER that hands a secret to a
callback and drops it, and there is no `get_secret()` anywhere. That is not
politeness -- a function returning a plaintext credential is a function
somebody will call from a request handler, and then the secret is in a
traceback, a log line and an error response. A shape that cannot be misused
is worth more than a rule that must be remembered.

`redact()` exists for the same reason and is applied to every adapter error
before it is stored: a persona's password lands in an HTTP error body far
more often than anybody expects.

## The scheduler is polite by construction

docs/04 asks for jitter and per-source `max_rps`, and the reason is
operational security rather than courtesy. A collector that polls exactly
every 300 seconds is a collector that a competent forum admin can pick out
of an access log in an afternoon -- and a burnt persona is expensive and
slow to replace.

So `next_due_at` adds jitter as a PERCENTAGE of the interval, and
`RateLimiter` spaces requests per source. Both are deliberately visible in
the run record, because "why did this poll at 04:12" should be answerable.

## Operational separation is enforced, not advised

docs/04: "One persona ↔ one egress profile. Enforced with a constraint, not
a convention. Two personas sharing an exit IP can be correlated by any
competent forum admin, and you lose both at once."

`check_egress_separation()` is that check. It is not a database constraint
because an egress profile legitimately serves many personas across DIFFERENT
sources over time -- what must not happen is two personas on the same
profile being live simultaneously against the same source. That is a
temporal condition, and stating it honestly as a check with a reason beats
a constraint that is either wrong or unenforceable.

## What is NOT built, and why

- **No live adapters except RSS in this module.** The adapter contract and
  every gate a forum or Telegram adapter passes through are here (docs/00
  decision 69, 2026-09-24): one frozen `Adapter` contract and its
  `RunContext`, per-item savepoints, raw markup per item, the persona gate
  and lease, a two-person collection authority and a declared
  classification ceiling (collection_authority.py) that every forum and
  Telegram source needs, public boards included. The XenForo, MyBB and
  Telegram adapters themselves live in forum_adapters.py and telegram.py,
  and `default_adapters()` registers them. Whether a unit may read a forum
  at all remains docs/16 L3's question: this code records who said it may.
- **No scheduler PROCESS.** `due_sources()` still only reports and
  `run_once()` still only acts; nothing in this module loops, and nothing
  here runs itself. Same reasoning as decisions 30 and 46 -- a collector
  that runs itself on a timer nobody watches is how a persona gets burnt
  at 3am. What exists as of 2026-09-10 is `scripts/collection_poll.py`, a
  cron ENTRY in the shape of `notify_drain.py`: one process, one
  connection, one pass, an exit code. It asks `due_sources()` what is
  ready and polls that, so the operator chooses how often to LOOK and each
  source's own jittered `next_due_at` still decides when it is polled. A
  runner that imposed its own cadence would be the timer this bullet
  refuses.
- **The egress proxy is not in this module** (2026-09-24). Watch
  targets are user-supplied URLs, which is exactly the SSRF surface docs/09
  names, and `fetch()` closes it at the connect: each hop's name is
  resolved ONCE, every answer is classified by what the address is, and the
  socket is opened to the address that was checked, so a resolver
  answering public for the check and private for the connect (DNS
  rebinding) has nothing left to rebind (sec-ssrf-rebinding, 2026-09-23).
  Persona and passive traffic take a route from `egress.route_for`. In
  development with no proxy the route is DIRECT and the pinned client
  (pinned_http.py) applies egress_policy.py itself; with a proxy, the proxy
  is the only resolver and the only exit, and it enforces the same policy
  with the same functions (docs/00 decision 68, docs/17).
"""
from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import math
import random
import re
import ssl
import time
import types
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json, Jsonb

from noctornal_api import egress, pinned_http
from noctornal_api.wording import agree, count_of
from noctornal_api.egress_policy import (
    DECISION_REF,
    PASSIVE_PROFILE,
    PUBLIC_POLICY,
    EgressRoute,
)

# The collector's old names for what moved to egress_policy.py and
# pinned_http.py (docs/20 section 5, 2026-09-24), kept as the SAME
# objects: the suites patch `collection._is_blocked` and read `_Deadline`,
# `_Hop`, `_dial` and `_cut` through this module, and PersonaVault.use
# shares the one `_LIVE_SECRETS` ContextVar through `secret_in_scope`.
from noctornal_api.egress_policy import (  # noqa: F401
    BLOCKED_NETWORKS as _BLOCKED_NETWORKS,
)
from noctornal_api.egress_policy import (  # noqa: F401
    METADATA_HOSTS as _METADATA_HOSTS,
)
from noctornal_api.egress_policy import (  # noqa: F401
    is_blocked as _is_blocked,
)
from noctornal_api.pinned_http import (  # noqa: F401
    _LIVE_SECRETS,
    _SECRET_PATTERNS,
    COLLECTOR_USER_AGENT,
    LOOKUP_MAX_SECONDS,
    LOOKUP_USER_AGENT,
    MAX_FETCH_SECONDS,
    MAX_REDIRECTS,
    MAX_RESPONSE_BYTES,
    MIN_REDACTABLE_LENGTH,
    REDIRECT_CODES,
    CollectionError,
    DeadlineExceeded,
    DestinationRefused,
    Fetched,
    HttpStatusError,
    RedirectRefused,
    RequestUncertain,
    RouteUnavailable,
    Unreachable,
    UnresolvableHost,
    _cut,
    _dial,
    _PinnedConnection,
    _refuse_unverifying,
    _secret_forms,
    redact,
    secret_in_scope,
)
from noctornal_api.pinned_http import Deadline as _Deadline  # noqa: F401
from noctornal_api.pinned_http import Hop as _Hop  # noqa: F401
from noctornal_api.pinned_http import REDIRECT_CODES as _REDIRECT_CODES  # noqa: F401
from noctornal_api.security import envelope

#: docs/04's persona lifecycle. A burnt persona never returns to HEALTHY:
#: reusing one that a forum admin has already flagged is how you burn the
#: next one too.
HEALTHY, COOLDOWN, LOCKED, BURNED = "HEALTHY", "COOLDOWN", "LOCKED", "BURNED"
_TERMINAL = frozenset({BURNED})

#: `collect.document.triage_state`, as 0011 declared it in a column comment
#: and the Collected pane's filter offers it. A `text` column with no CHECK,
#: so this tuple is the only thing standing between the dropdown and a
#: fifth state the filter cannot select -- a document in one would have
#: disappeared from every view without being deleted.
TRIAGE_STATES = ("NEW", "TRIAGED", "LINKED", "DISCARDED")

#: A suppression is a hit removed from the queue on somebody's say-so, and
#: the reason is the only record of whose and why. Same floor the persona
#: status route applies, for the same reason.
MIN_SUPPRESS_REASON_LENGTH = 5

# ---------------------------------------------------------------------------
# The HTTP core (docs/20 section 5, 2026-09-24)
# ---------------------------------------------------------------------------
#
# The address classifier moved to egress_policy.py, and the pinned client,
# its deadline and its primitives to pinned_http.py, the one outbound HTTP
# client every process uses (docs/00 decision 72). The old names imported
# above are the SAME objects (`collection._Deadline is pinned_http.Deadline`),
# so the suites that read them through this module, and PersonaVault.use,
# are unchanged. What stays here is the collector's test seam and the two
# thin wrappers every collector call goes through.


def _live_is_blocked(address) -> bool:
    """The classifier as the collector's suites see it: this module's
    `_is_blocked`, read at CALL time. test_collection_hardening,
    test_collection_ssrf_rebinding and test_collection_fetch_deadline patch
    `collection._is_blocked` to stand a loopback address in for a public
    one, and the patch still reaches the connect through here. Passed to
    pinned_http's private `_fetch_response` only: no public signature
    carries a switch that changes the classifier."""
    return _is_blocked(address)


def _legacy_route() -> EgressRoute:
    """The route for a call that named none.

    Once a proxy is configured it is refused (no_route): every outbound
    connection takes its route from egress.route_for, and a forgotten one
    must not go direct past the proxy. So is a production call once a route
    provider exists (proxy_required). Otherwise it is the direct public
    route fetch has always used, so nothing changes where there is no
    proxy. RouteUnavailable rather than DestinationRefused, because the code
    decides the class."""
    if egress.proxy_settings() is not None:
        raise RouteUnavailable(
            "a proxy is configured, and this call named no route: every "
            "outbound connection takes its route from egress.route_for "
            f"({DECISION_REF})", code="no_route")
    if egress._production() and egress._route_provider() is not None:
        raise RouteUnavailable(
            "in production every outbound connection leaves through the egress "
            f"proxy, and this call named no route ({DECISION_REF})",
            code="proxy_required")
    return EgressRoute.direct(
        "persona", PASSIVE_PROFILE, PUBLIC_POLICY,
        note="no route given: the direct public route fetch has always used")


def _resolve_and_check(url: str) -> _Hop:
    """Validate ONE hop on the legacy route and pin it, for the callers and
    the suites that used this name. The work is pinned_http.resolve's: one
    lookup, every answer admitted, the answers the only addresses a
    connection may use (docs/17 F15(f), sec-ssrf-rebinding)."""
    return pinned_http._resolve(url, route=_legacy_route(),
                                _blocked_override=_live_is_blocked)


class PersonaUnavailable(CollectionError):
    """The persona cannot be used right now -- cooling down, locked or
    burnt. A distinct type because the caller's response differs: a
    cooldown is a wait, a burn is a replacement."""


class CollectionNotFound(CollectionError):
    """The row does not exist, is not on the case named, or sits above
    the caller's clearance -- and the caller is told none of which. A
    distinct type because the router's answer differs: this is a 404,
    where a bad argument (a triage state that is not one, a reason too
    short to be one) is a 400. Before 2026-09-02 every `CollectionError`
    from a hit route was a 404, so a refused ARGUMENT would have reported
    as a missing ROW."""


class CollectionBusy(CollectionError):
    """Another poll of this same source is in flight, so this call did
    nothing at all -- no fetch, no rows, not even a `collection_run`.

    A distinct type because "nothing was done" is not "something went
    wrong": a FAILED run recorded here would libel a source that is being
    collected from perfectly well at this very moment, and
    `consecutive_failures` drives the health rollup the Feeds pane shows.
    The caller decides what to do with it -- `scripts/collection_poll.py`
    counts it as `skipped` and still exits 0."""


# Redaction -- `redact`, `secret_in_scope` and their patterns live in
# pinned_http.py since 2026-09-24 (docs/20 section 5.8): the transport has
# to redact what it reports. Re-exported above as the SAME objects, so
# `PersonaVault.use` and every caller here share the one ContextVar.


# ---------------------------------------------------------------------------
# The persona vault (invariant 7)
# ---------------------------------------------------------------------------

#: Persona holds (2026-09-24): the machine's own columns. Only
#: `PersonaVault.signal` writes them and the human `set_status` never does,
#: so a platform's wait cannot be undone by hand in any number of steps
#: (guard_persona_holds, migration 0082, holds it against every writer).
HOLD_RATE_LIMITED, HOLD_ABANDONED = "RATE_LIMITED", "ABANDONED"
MACHINE_HOLD_REASONS = (HOLD_RATE_LIMITED, HOLD_ABANDONED)
MACHINE_LOCK_CODES = ("CREDENTIAL_REVOKED", "CREDENTIAL_DUPLICATED",
                      "ACCOUNT_BANNED", "WRONG_ACCOUNT", "PLATFORM_REFUSED")

#: The source kinds a persona can be an account on (the CHECK in 0082).
PERSONA_PLATFORMS = ("XENFORO", "MYBB", "PHPBB", "TELEGRAM", "DISCORD")

#: ONE reading of "this persona may be used now", as SQL over the alias `a`
#: (2026-09-24): PersonaGate.check, the due list's persona
#: hold and the egress proxy's `persona_unavailable` all evaluate this, so
#: the gate and the proxy cannot disagree about a COOLDOWN with no end or a
#: HEALTHY persona with a future cooldown. HEALTHY with no cooldown still
#: running, or COOLDOWN whose end has passed, and no live machine hold or
#: machine lock. BURNED, LOCKED and anything else are unusable.
PERSONA_USABLE_SQL = (
    "(a.status IN ('HEALTHY', 'COOLDOWN')"
    " AND coalesce(a.cooldown_until <= clock_timestamp(), a.status = 'HEALTHY')"
    " AND (a.machine_hold_until IS NULL"
    " OR a.machine_hold_until <= clock_timestamp())"
    " AND a.machine_lock_code IS NULL)")

#: A persona is VISIBLE to a caller when no source it is registered on or
#: bound to sits above the caller's ceiling (2026-09-24). The old
#: predicate looked at the venue only, so an AMBER holder could burn, lock
#: or unlock a persona whose chats or boards are RED. Placeholders are
#: named: `%(clearance)s`.
PERSONA_VISIBLE_SQL = (
    "(%(clearance)s::core.tlp IS NULL OR NOT EXISTS ("
    "SELECT 1 FROM collect.source vs"
    " WHERE (vs.id = a.source_id OR vs.collection_account_id = a.id)"
    " AND vs.classification > %(clearance)s::core.tlp))")

#: What a persona the caller may not see reads as, wherever a visible row
#: would otherwise name it (2026-09-24). No id, no handle:
#: the listing of personas omits it, so a name here would be a chip that
#: leads nowhere and a PRESENCE signal per persona.
HIDDEN_PERSONA = {"hidden": True, "label": "a persona you cannot see"}

_ACTIVE_WINDOW = re.compile(r"^([01][0-9]|2[0-3]):([0-5][0-9])-([01][0-9]|2[0-3]):([0-5][0-9])$")
#: A header value a persona may present: printable ASCII only, so a
#: careless or hostile fingerprint never reaches the HTTP client as the
#: "programming error" it treats a CR, LF or NUL as.
_HEADER_TEXT = re.compile(r"^[\x20-\x7e]+$")


@dataclass(frozen=True)
class Persona:
    id: UUID
    source_id: UUID
    handle: str
    status: str
    cooldown_until: datetime | None
    egress_profile_id: UUID | None
    last_used_at: datetime | None
    burn_reason: str | None

    def is_usable(self, now: datetime | None = None) -> bool:
        """PERSONA_USABLE_SQL's reading of the fields this row carries
        (2026-09-25: it read a COOLDOWN with no end as usable, a second
        rule beside the one the gate asks). It carries no machine
        hold or lock, so the SQL, never this, decides a use."""
        now = now or datetime.now(timezone.utc)
        if self.status not in (HEALTHY, COOLDOWN):
            return False
        if self.cooldown_until is None:
            return self.status == HEALTHY
        return self.cooldown_until <= now


def header_text_problem(label: str, value, *, low: int, high: int) -> str | None:
    """Why `value` cannot be presented as a request header (a persona's
    user agent or language), or None. One rule for the create route and
    for the poll, which refuses a stored value that bypassed the route."""
    if not isinstance(value, str) or not low <= len(value) <= high:
        return f"The {label} is between {low} and {high} characters."
    if not _HEADER_TEXT.match(value):
        return (f"The {label} is printable ASCII on one line: no control "
                f"characters and no line breaks.")
    return None


def active_window(text) -> tuple[int, int] | None:
    """'HH:MM-HH:MM' as (start minute, end minute) of the UTC day, or None
    when the persona has no window. The window may wrap midnight."""
    if not text:
        return None
    match = _ACTIVE_WINDOW.match(str(text).strip())
    if match is None:
        raise ValueError("an active window is HH:MM-HH:MM in UTC")
    h1, m1, h2, m2 = (int(g) for g in match.groups())
    return h1 * 60 + m1, h2 * 60 + m2


def window_opening(window: tuple[int, int], now: datetime) -> datetime | None:
    """None when `now` is inside `window`, else the next UTC time it opens."""
    start, end = window
    minute = now.hour * 60 + now.minute
    inside = (start <= minute < end) if start < end else (
        minute >= start or minute < end)
    if start == end or inside:
        return None
    today = now.replace(hour=start // 60, minute=start % 60, second=0,
                        microsecond=0)
    return today if today > now else today + timedelta(days=1)


def _secret_leaves(secret: str) -> tuple[str, ...]:
    """Every string leaf of a JSON credential, so `redact` removes a
    session string or an API hash exactly and not only the whole blob. A
    credential that is not JSON has no leaves: the whole value is
    registered anyway."""
    import json

    try:
        parsed = json.loads(secret)
    except (TypeError, ValueError):
        return ()
    found: list[str] = []

    def walk(node, depth=0):
        if depth > 16:
            return
        if isinstance(node, str):
            if len(node) >= MIN_REDACTABLE_LENGTH:
                found.append(node)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value, depth + 1)
        elif isinstance(node, list):
            for value in node:
                walk(value, depth + 1)

    walk(parsed)
    return tuple(found)


class Lease:
    """The plaintext of one persona credential for the life of one block.

    `reseal(new)` asks for a credential the platform moved (a session that
    rotated) to be sealed back on exit, by compare-and-set, so a credential
    somebody stored meanwhile wins. `resealed` is None until the block
    ends, then True or False. The value never appears in a repr."""

    __slots__ = ("_value", "_new", "resealed")

    def __init__(self, value: str):
        self._value = value
        self._new: str | None = None
        self.resealed: bool | None = None

    @property
    def value(self) -> str:
        return self._value

    def reseal(self, new_value: str) -> None:
        if not isinstance(new_value, str) or not new_value:
            raise CollectionError("a resealed credential is a non-empty string")
        self._new = new_value

    def __repr__(self) -> str:
        return "Lease(value=[REDACTED])"


class PersonaVault:
    """Envelope-encrypted persona credentials.

    **There is deliberately no `get_secret()`.** `lease()` is a context
    manager that hands the plaintext to a block and drops it, and `use()`
    is a thin wrapper over it. A function that RETURNS a credential is a
    function somebody calls from a request handler, and then the secret is
    in a traceback, a log line and an error response. Invariant 7 is easier
    to hold with a shape that cannot be misused than with a rule that must
    be remembered.

    Since 2026-09-24 a persona is one account on one platform, created
    here with no credential (an operator enrols it on the server); the
    machine's holds and locks are written by `signal` alone; a credential
    the platform moved is resealed by compare-and-set; `destroy_secret`
    stops a persona for good; and every write names its actor, the system
    when there is none.
    """

    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- creating and enrolling -------------------------------------------

    def create(self, *, handle: str, platform: str,
               egress_profile_id: UUID, fingerprint: dict | None = None,
               notes: str | None = None, venue_source_id: UUID | None = None,
               owner_user_id: UUID | None = None,
               actor_id: UUID | None) -> dict:
        """A persona with NO credential. docs/04 one persona, one egress
        profile: a profile any other persona holds, in any status, is
        refused, because two personas seen from one exit are linked by any
        competent site and a burnt persona's exit is the one a site has
        already noticed. That is why a burnt persona keeps its exit for
        good rather than freeing it (2026-09-24): there is no status that
        hands an exit on."""
        handle = (handle or "").strip()
        if not 2 <= len(handle) <= 64:
            raise CollectionError("A handle is between 2 and 64 characters.")
        if platform not in PERSONA_PLATFORMS:
            raise CollectionError(
                f"No persona can be an account on {platform!r}.")
        profile = self._c.execute(
            "SELECT is_active FROM collect.egress_profile WHERE id = %s",
            (egress_profile_id,)).fetchone()
        if profile is None or not profile[0]:
            raise CollectionNotFound(
                "no such egress profile, or it is retired")
        taken = self._c.execute(
            "SELECT 1 FROM collect.collection_account "
            "WHERE egress_profile_id = %s LIMIT 1",
            (egress_profile_id,)).fetchone()
        if taken is not None:
            raise CollectionError(
                "This egress profile already carries a persona. Two personas "
                "sharing an exit can be linked by any competent site, so one "
                "persona, one egress profile.")
        from psycopg.types.json import Jsonb
        row = self._c.execute(
            """INSERT INTO collect.collection_account
                   (source_id, handle, persona_notes, egress_profile_id,
                    fingerprint_profile, status, owner_user_id, platform,
                    status_changed_at)
               VALUES (%s, %s, %s, %s, %s, 'HEALTHY', %s, %s, now())
               RETURNING id""",
            (venue_source_id, handle, (notes or "").strip() or None,
             egress_profile_id, Jsonb(fingerprint or {}), owner_user_id,
             platform)).fetchone()
        self._audit(actor_id, "PERSONA_CREATED", row[0],
                    {"platform": platform,
                     "egress_profile_id": str(egress_profile_id)})
        return {"id": str(row[0]), "handle": handle, "platform": platform,
                "egress_profile_id": str(egress_profile_id),
                "status": HEALTHY, "credential_stored": False}

    def store(self, persona_id: UUID, secret: str, *,
              actor_id: UUID | None, detail: dict | None = None) -> None:
        """Seal a credential. A machine lock (the platform refused the old
        credential) clears in the same UPDATE, because a new credential
        enrolled after the lock is the one thing that lifts it. The clock is
        `clock_timestamp()`, never the transaction's, so the rotation time
        is always after a lock signalled earlier in the same session."""
        ciphertext, key_id = envelope.encrypt(secret)
        updated = self._c.execute(
            """UPDATE collect.collection_account
                  SET secret_ciphertext = %s, secret_key_id = %s,
                      secret_rotated_at = clock_timestamp(),
                      machine_lock_code = NULL, machine_lock_at = NULL
                WHERE id = %s""", (ciphertext, key_id, persona_id)).rowcount
        if updated != 1:
            raise CollectionNotFound("no such persona")
        self._audit(actor_id, "PERSONA_SECRET_STORED", persona_id,
                    dict(detail or {}))

    def destroy_secret(self, persona_id: UUID, *, actor_id: UUID | None,
                       reason: str, detail: dict | None = None) -> None:
        """Destroy a persona's credential. Zero bytes rather than NULL,
        which security/sealed.py already reads as absent. The account id is
        kept: it is who the persona was. Stopping is always allowed, so no
        authority is asked."""
        if not (reason or "").strip():
            raise CollectionError("Destroying a credential has to say why.")
        updated = self._c.execute(
            """UPDATE collect.collection_account
                  SET secret_ciphertext = ''::bytea, secret_key_id = NULL
                WHERE id = %s""", (persona_id,)).rowcount
        if updated != 1:
            raise CollectionNotFound("no such persona")
        self._audit(actor_id, "PERSONA_SECRET_DESTROYED", persona_id,
                    {"reason": reason.strip(), **dict(detail or {})})

    # -- using -------------------------------------------------------------

    def _refusal(self, row, *, stopping: bool) -> str | None:
        """Why the credential may not be opened, or None. Sentences never
        name a source.

        WHETHER is PERSONA_USABLE_SQL's answer (row[6]) and nothing else,
        so the lease cannot open a persona the gate and the due list refuse
        (2026-09-25: a COOLDOWN with no end was refused by
        the gate and opened by use()). The branches below only choose the
        sentence."""
        _secret, _kid, status, cooldown, hold_until, lock_code, usable = row
        if stopping or usable:
            return None
        now = datetime.now(timezone.utc)
        if status in _TERMINAL:
            return (f"this persona is {status} and must not be used "
                    f"again: re-using one a forum admin has already "
                    f"flagged is how you burn the next one too")
        if cooldown and cooldown > now:
            return (f"this persona is cooling down until "
                    f"{cooldown.isoformat()}; a persona active 24/7 is a "
                    f"bot and reads as one")
        sentence, _until = _persona_hold_sentence(
            {"status": status, "cooldown_until": cooldown,
             "hold_until": hold_until, "lock_code": lock_code}, now)
        return sentence

    @contextmanager
    def lease(self, persona_id: UUID, *, actor_id: UUID | None, purpose: str,
              run_id: UUID | None = None, stopping: bool = False):
        """Yield a Lease for the duration of a block, then drop it.

        Refuses as `use()` always did, and on a live machine hold or lock.
        A STOPPING lease (a logout of a duplicated session) opens whatever
        the status or the machine holds and refuses only a missing
        credential: logging a session out is the one use a locked or burnt
        persona still needs.

        For exactly as long as the block runs, `redact` knows the whole
        credential AND every string leaf of a JSON credential, verbatim and
        in its wire forms. On exit, whether or not the block raised, a
        credential the block resealed is written back by compare-and-set
        against the bytes read at entry (sealed.rewrap_table's rule): one
        row changed is PERSONA_SECRET_RESEALED, none is
        PERSONA_SECRET_RESEAL_SKIPPED and the newer credential wins.
        `secret_rotated_at` is not touched: a platform moving a session is
        not a rotation."""
        row = self._c.execute(
            f"""SELECT a.secret_ciphertext, a.secret_key_id, a.status,
                       a.cooldown_until, a.machine_hold_until,
                       a.machine_lock_code, {PERSONA_USABLE_SQL}
                  FROM collect.collection_account a WHERE a.id = %s""",
            (persona_id,)).fetchone()
        if row is None:
            raise CollectionError("no such persona")
        refusal = self._refusal(row, stopping=stopping)
        if refusal:
            raise PersonaUnavailable(refusal)
        if not row[0]:
            raise CollectionError("this persona has no stored credential")
        read_at_entry = bytes(row[0])
        self._audit(actor_id, "PERSONA_USED", persona_id,
                    {"purpose": purpose,
                     "run_id": str(run_id) if run_id else None,
                     "stopping": stopping})
        secret = envelope.decrypt(read_at_entry, key_id=row[1])
        lease = Lease(secret)
        try:
            with secret_in_scope(secret, *_secret_leaves(secret)):
                yield lease
        finally:
            new = lease._new
            lease._new = None
            try:
                if new is not None and new != secret:
                    self._reseal(persona_id, new, read_at_entry, lease,
                                 purpose=purpose, run_id=run_id)
            finally:
                # Python cannot guarantee the string is gone, and pretending
                # otherwise would be worse than saying so: the real control
                # is that it never left this frame.
                del secret
                lease._value = ""
                self._c.execute(
                    "UPDATE collect.collection_account SET last_used_at = now() "
                    "WHERE id = %s", (persona_id,))

    def _reseal(self, persona_id: UUID, new: str, read_at_entry: bytes,
                lease: Lease, *, purpose: str, run_id: UUID | None) -> None:
        ciphertext, key_id = envelope.encrypt(new)
        changed = self._c.execute(
            """UPDATE collect.collection_account
                  SET secret_ciphertext = %s, secret_key_id = %s
                WHERE id = %s AND secret_ciphertext = %s""",
            (ciphertext, key_id, persona_id, read_at_entry)).rowcount
        lease.resealed = changed == 1
        self._audit(None, "PERSONA_SECRET_RESEALED" if changed == 1
                    else "PERSONA_SECRET_RESEAL_SKIPPED", persona_id,
                    {"purpose": purpose,
                     "run_id": str(run_id) if run_id else None})

    @contextmanager
    def use(self, persona_id: UUID, *, actor_id: UUID | None, purpose: str):
        """Yield the plaintext for the duration of a block, then drop it.

        Every use is audited with a purpose, because docs/05 requires
        "every persona use" to be logged and a use with no stated purpose
        is not reviewable. One code path since 2026-09-24: this is `lease()`.
        """
        with self.lease(persona_id, actor_id=actor_id, purpose=purpose) as held:
            yield held.value

    # -- the machine's transitions -----------------------------------------

    def signal(self, persona_id: UUID, *, reason: str,
               hold_until: datetime | None = None,
               hold_reason: str | None = None,
               lock_code: str | None = None,
               run_id: UUID | None = None) -> bool:
        """A transition the PLATFORM imposed, never a person's decision.

        Writes the machine columns only and never `status`: a hold extends
        (greatest of the two) and lapses by time; a lock replaces an
        earlier lock's code and clears only through `store()` of a new
        credential. BURNED stays a human decision with a reason. Audited as
        the system. Returns whether anything changed."""
        if hold_until is None and lock_code is None:
            raise CollectionError("a signal carries a hold or a lock")
        if hold_until is not None and hold_reason not in MACHINE_HOLD_REASONS:
            raise CollectionError(f"unknown hold reason {hold_reason!r}")
        if lock_code is not None and lock_code not in MACHINE_LOCK_CODES:
            raise CollectionError(f"unknown lock code {lock_code!r}")
        changed = False
        if hold_until is not None:
            changed |= self._c.execute(
                """UPDATE collect.collection_account
                      SET machine_hold_until = greatest(
                              coalesce(machine_hold_until, %s), %s),
                          machine_hold_reason = %s
                    WHERE id = %s
                      AND (machine_hold_until IS NULL
                           OR machine_hold_until < %s
                           OR machine_hold_reason IS DISTINCT FROM %s)""",
                (hold_until, hold_until, hold_reason, persona_id, hold_until,
                 hold_reason)).rowcount == 1
        if lock_code is not None:
            changed |= self._c.execute(
                """UPDATE collect.collection_account
                      SET machine_lock_code = %s,
                          machine_lock_at = clock_timestamp()
                    WHERE id = %s""", (lock_code, persona_id)).rowcount == 1
        self._audit(None, "PERSONA_MACHINE_LOCK" if lock_code
                    else "PERSONA_MACHINE_HOLD", persona_id,
                    {"reason": reason,
                     "hold_until": hold_until.isoformat() if hold_until else None,
                     "hold_reason": hold_reason, "lock_code": lock_code,
                     "run_id": str(run_id) if run_id else None,
                     "by": "adapter"})
        return changed

    # -- the human's transitions -------------------------------------------

    def set_status(self, persona_id: UUID, status: str, *, actor_id: UUID,
                   reason: str | None = None,
                   cooldown: timedelta | None = None,
                   clearance: str | None = None) -> dict:
        """Move a persona through the lifecycle.

        BURNED is terminal and requires a reason: the reason is what stops
        the next analyst quietly reusing it, and "burnt" with no explanation
        reads as "somebody was being careful once".

        Gated on the caller's ceiling against EVERY source the persona is
        registered on or bound to (2026-09-24), exactly as
        `personas()` lists them: the venue alone was the old rule, and it
        let an AMBER holder burn, lock or unlock a persona whose chats or
        boards are RED. `clearance=None` is the worker path and applies no
        filter.

        Refuses with `CollectionNotFound` when the row does not exist OR is
        hidden, and the two are indistinguishable. The UPDATE's row count is
        checked as well as the SELECT before it, so a row that vanished or
        was relabelled between the two is refused rather than
        half-recorded.

        This writes `status`, `status_changed_at` and `cooldown_until` and
        NEVER a machine column. BURNED and LOCKED are reachable at any
        moment whatever the platform holds (stopping is always allowed);
        HEALTHY under a live machine hold or lock changes the human status
        only, and the answer says the persona stays paused. A COOLDOWN with
        no end is a person's open rest: it read as usable to the old gate
        and as resting to the proxy (2026-09-24), and it now
        reads unusable to every reader through PERSONA_USABLE_SQL until a
        person lifts it.
        """
        if status not in {HEALTHY, COOLDOWN, LOCKED, BURNED}:
            raise CollectionError(f"unknown persona status {status!r}")
        if status == BURNED and not (reason or "").strip():
            raise CollectionError(
                "a burn has to say what burnt it: without a reason the next "
                "analyst has nothing to avoid repeating")
        params = {"id": persona_id, "clearance": clearance}
        current = self._c.execute(
            f"""SELECT a.status, a.machine_hold_until, a.machine_lock_code
                  FROM collect.collection_account a
                 WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}""",
            params).fetchone()
        if current is None:
            raise CollectionNotFound(
                "no such persona, or it is above your clearance")
        if current[0] == BURNED and status != BURNED:
            raise CollectionError(
                "a burnt persona does not come back: reusing one a forum "
                "admin has already flagged burns the next one too")
        until = (datetime.now(timezone.utc) + cooldown) if cooldown else None
        updated = self._c.execute(
            f"""UPDATE collect.collection_account a
                   SET status = %(status)s, cooldown_until = %(until)s,
                       burn_reason = %(reason)s, status_changed_at = now()
                 WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}""",
            {**params, "status": status, "until": until,
             "reason": (reason or "").strip() or None}).rowcount
        if updated != 1:
            raise CollectionNotFound(
                "no such persona, or it is above your clearance")
        self._audit(actor_id, f"PERSONA_{status}", persona_id,
                    {"reason": reason, "cooldown_until":
                     until.isoformat() if until else None})
        notice = None
        if status == HEALTHY:
            now = datetime.now(timezone.utc)
            if current[2]:
                notice = ("This persona stays locked until a new credential "
                          "is enrolled: its platform refused the old one.")
            elif current[1] and current[1] > now:
                notice = (f"The platform asked this persona to wait until "
                          f"{_utc(current[1])}: it stays paused until then, "
                          f"whatever its status.")
        return {"persona_id": str(persona_id), "status": status,
                "notice": notice}

    # -- reading -----------------------------------------------------------

    def visible(self, persona_id: UUID, *, clearance: str | None) -> bool:
        """Whether `clearance` may see this persona (the set_status rule)."""
        return self._c.execute(
            f"""SELECT 1 FROM collect.collection_account a
                 WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}""",
            {"id": persona_id, "clearance": clearance}).fetchone() is not None

    def personas(self, *, clearance: str | None = None) -> list[dict]:
        """Persona HEALTH, never a secret, under the set_status predicate.

        Every column named explicitly rather than selected with `*` so that
        adding a secret-bearing column later cannot quietly start returning
        it; `credential_stored` says whether one is sealed and nothing
        about it. Each row still names its venue source, and the predicate
        now also hides a persona bound to any source above the caller
        (2026-09-24). `clearance=None` applies NO filter (the worker).

        The authority state is taken among authorities within the caller's
        clearance only, the LIVE one first: a RED
        authority over an AMBER persona says nothing to an AMBER caller.
        """
        params = {"clearance": clearance}
        rows = self._c.execute(
            f"""SELECT a.id, a.handle, s.name, s.base_url, a.status,
                       a.last_used_at, a.burn_reason, a.cooldown_until,
                       a.approved_by, a.secret_rotated_at, a.platform,
                       a.platform_uid, a.egress_profile_id, e.name,
                       a.machine_hold_until, a.machine_hold_reason,
                       a.machine_lock_code,
                       a.fingerprint_profile->>'active_window_utc',
                       coalesce(a.fingerprint_profile ? 'user_agent', false),
                       coalesce(octet_length(a.secret_ciphertext), 0) > 0,
                       (SELECT count(*) FROM collect.source b
                         WHERE b.collection_account_id = a.id AND b.is_active
                           AND (%(clearance)s::core.tlp IS NULL
                                OR b.classification <= %(clearance)s::core.tlp))
                  FROM collect.collection_account a
                  LEFT JOIN collect.source s ON s.id = a.source_id
                  LEFT JOIN collect.egress_profile e ON e.id = a.egress_profile_id
                 WHERE {PERSONA_VISIBLE_SQL}
                 ORDER BY a.status, a.handle""",
            params).fetchall()
        from noctornal_api.collection_authority import CollectionAuthorityService
        states = CollectionAuthorityService(self._c).states_for_personas(
            [r[0] for r in rows], clearance=clearance)
        return [
            {"id": str(r[0]), "handle": r[1], "source_name": r[2],
             "source_url": r[3], "status": r[4],
             "last_used_at": r[5].isoformat() if r[5] else None,
             "burn_reason": r[6],
             "cooldown_until": r[7].isoformat() if r[7] else None,
             "approved": r[8] is not None,
             "secret_rotated_at": r[9].isoformat() if r[9] else None,
             "platform": r[10], "platform_uid": r[11],
             "egress_profile_id": str(r[12]) if r[12] else None,
             "egress_profile_name": r[13],
             "machine_hold_until": r[14].isoformat() if r[14] else None,
             "machine_hold_reason": r[15], "machine_lock_code": r[16],
             "active_window_utc": r[17], "has_browser_identity": bool(r[18]),
             "credential_stored": bool(r[19]), "sources_bound": r[20],
             "authority": states.get(r[0])}
            for r in rows]

    def egress_profiles(self, *, clearance: str | None) -> list[dict]:
        """THE listing persona and source forms pick an exit from.

        Counts only what the caller may see, and one boolean for the rest
        rather than a hidden count, which would be a count oracle.
        `available` is false when any persona holds the profile, with no
        reason given when that persona is hidden: that one bit of presence
        is the deployment's accepted PRESENCE disclosure (docs/16 D2,
        docs/05). Never the sealed endpoint or its key id."""
        params = {"clearance": clearance}
        rows = self._c.execute(
            f"""SELECT e.id, e.name, e.kind, e.region, e.is_active,
                       EXISTS (SELECT 1 FROM collect.collection_account h
                                WHERE h.egress_profile_id = e.id),
                       (SELECT count(*) FROM collect.collection_account a
                         WHERE a.egress_profile_id = e.id
                           AND {PERSONA_VISIBLE_SQL}),
                       (SELECT count(*) FROM collect.source s
                         WHERE s.egress_profile_id = e.id
                           AND (%(clearance)s::core.tlp IS NULL
                                OR s.classification <= %(clearance)s::core.tlp)),
                       (SELECT coalesce(array_agg(DISTINCT a.platform::text), '{{}}')
                          FROM collect.collection_account a
                         WHERE a.egress_profile_id = e.id
                           AND a.platform IS NOT NULL
                           AND {PERSONA_VISIBLE_SQL}),
                       EXISTS (SELECT 1 FROM collect.collection_account a
                                WHERE a.egress_profile_id = e.id
                                  AND NOT {PERSONA_VISIBLE_SQL})
                       OR EXISTS (SELECT 1 FROM collect.source s
                                   WHERE s.egress_profile_id = e.id
                                     AND %(clearance)s::core.tlp IS NOT NULL
                                     AND s.classification > %(clearance)s::core.tlp)
                  FROM collect.egress_profile e
                 ORDER BY e.is_active DESC, e.name""", params).fetchall()
        return [{"id": str(r[0]), "name": r[1], "kind": r[2], "region": r[3],
                 "is_active": r[4], "available": bool(r[4]) and not r[5],
                 "personas": r[6], "sources": r[7],
                 "persona_platforms": sorted(r[8] or []),
                 "some_above_clearance": bool(r[9])}
                for r in rows]

    def check_egress_separation(self, source_id: UUID, *,
                                clearance: str | None = None) -> list[dict]:
        """docs/04: one persona, one egress profile.

        "Two personas sharing an exit IP can be correlated by any competent
        forum admin, and you lose both at once."

        NOT a database constraint over existing rows, which may already
        share: `create()` refuses a taken exit for every new persona, and
        the egress proxy refuses a shared profile. This reports what is
        left: two live personas on one profile against the same source,
        and (2026-09-24) a PERSONA-LESS binding of the source that
        uses the exit of a live persona registered on or bound to it, which
        links the public read to the persona just as surely.

        With a `clearance`, a source above it (or one that does not exist)
        is REFUSED rather than answered with an empty list: the route's
        notice says an empty result means no shared egress was found.

        A persona the caller may not see (PERSONA_VISIBLE_SQL: one bound
        to a source above the caller) is never NAMED here, as it is not in
        personas() or set_status (2026-09-25: the widened
        predicate made this route the one place its handle still showed).
        `handles` lists the visible ones, `persona_count` counts them, and
        `some_hidden` is one bit, never a count: the correlation risk to
        the visible persona is real, and the bit is the PRESENCE the exit
        listing already discloses. A finding in which the caller can see
        nobody is left out, because nothing in it is theirs to act on.
        """
        if clearance is not None:
            visible = self._c.execute(
                """SELECT 1 FROM collect.source
                    WHERE id = %s AND classification <= %s::core.tlp""",
                (source_id, clearance)).fetchone()
            if visible is None:
                raise CollectionNotFound(
                    "no such source, or it is above your clearance")
        params = {"source": source_id, "clearance": clearance}
        rows = self._c.execute(
            f"""SELECT a.egress_profile_id,
                       array_agg(a.handle ORDER BY a.handle)
                           FILTER (WHERE {PERSONA_VISIBLE_SQL}),
                       bool_or(NOT {PERSONA_VISIBLE_SQL})
                  FROM collect.collection_account a
                 WHERE a.source_id = %(source)s
                   AND a.egress_profile_id IS NOT NULL
                   AND a.status NOT IN ('BURNED', 'LOCKED')
                 GROUP BY a.egress_profile_id HAVING count(*) > 1""",
            params).fetchall()
        findings = [self._separation_finding(
                        r[0], r[1], r[2],
                        "two live personas share an exit against one source; "
                        "a forum admin correlating them loses you both")
                    for r in rows if r[1]]
        # Registered on the source (its venue). A persona BOUND to it cannot
        # be here as well: a source carries a persona or an exit, never
        # both (source_one_egress_binding). The source's own public read is
        # a party the caller can see, so a finding whose persona is hidden
        # is kept, without the handle.
        shared = self._c.execute(
            f"""SELECT s.egress_profile_id,
                       array_agg(a.handle ORDER BY a.handle)
                           FILTER (WHERE {PERSONA_VISIBLE_SQL}),
                       bool_or(NOT {PERSONA_VISIBLE_SQL})
                  FROM collect.source s
                  JOIN collect.collection_account a
                    ON a.egress_profile_id = s.egress_profile_id
                   AND a.source_id = s.id
                 WHERE s.id = %(source)s AND s.egress_profile_id IS NOT NULL
                   AND a.status NOT IN ('BURNED', 'LOCKED')
                 GROUP BY s.egress_profile_id""", params).fetchall()
        findings.extend(
            self._separation_finding(
                r[0], r[1], r[2],
                "a public read and a persona share an exit against one "
                "source; the site can link them")
            for r in shared)
        return findings

    @staticmethod
    def _separation_finding(profile_id, handles, some_hidden: bool,
                            risk: str) -> dict:
        handles = list(handles or [])
        return {"egress_profile_id": str(profile_id),
                "persona_count": len(handles), "handles": handles,
                "some_hidden": bool(some_hidden), "risk": risk}

    def _audit(self, actor_id: UUID | None, action: str, persona_id: UUID,
               detail: dict) -> None:
        """actor_kind SYSTEM with a NULL actor when there is no person
        behind the write (the cron, an adapter's signal), the evidence.py
        pattern: a nil UUID recorded as a USER would be a person who does
        not exist (2026-09-24)."""
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id, detail)
               VALUES (%s, %s, %s, 'collection_account', %s, %s)""",
            (actor_id, "USER" if actor_id else "SYSTEM", action, persona_id,
             Json(detail)))


def _utc(moment: datetime) -> str:
    """'2026-09-24 17:05 UTC': every time a sentence carries is UTC and
    says so, as the console's are."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")




# ---------------------------------------------------------------------------
# The adapter interface (docs/00 decision 69, 2026-09-24: one frozen contract)
# ---------------------------------------------------------------------------
#
# Built once, in the collection foundation, so the forum and Telegram
# adapters only IMPLEMENT and REGISTER one: two separate readings of this
# layer would disagree. test_collection_contract.py pins every name here,
# so a change to the contract fails where it is made, not in an adapter
# later.

class SourceRefused(CollectionError):
    """The source is configured so that it is not read: no ceiling
    declared, a label above it, no exit, a binding that does not fit, a
    parser that does not read its kind. Refused before the lock, before a
    run row and before any network, so nothing is recorded as a failure and
    nothing touches the site. The routes answer 409."""


class SourceBlocked(CollectionError):
    """A poll that started and could not read: the run is BLOCKED, the
    source carries the sentence as `blocked_reason`, and no failure is
    counted, because this is configuration, not parser health."""


class RateLimited(CollectionError):
    """The site asked for a wait (HTTP 429, a 503 with Retry-After, a
    platform's flood wait). The run is RATE_LIMITED, the next poll waits
    the asked time and more, and no failure is counted."""

    def __init__(self, retry_after_s: float, sentence: str | None = None):
        self.retry_after_s = max(0.0, float(retry_after_s or 0))
        super().__init__(sentence or (
            f"The site asked for a wait of "
            f"{count_of(int(round(self.retry_after_s)), 'second', 'seconds')}, "
            f"and the next poll waits at least that long."))


class LoginWall(CollectionError):
    """The page the adapter asked for is behind a sign-in. The run FAILED
    with its own class, and nothing is stored."""


class BudgetSpent(CollectionError):
    """The poll's wall clock, its page budget or its byte budget is spent.
    Raised by RunContext.fetch before anything is sent; an adapter catches
    it and returns what it has, and the run carries a note, not a fault."""


class CursorTooLarge(CollectionError):
    """The resume cursor an adapter returned is over 16 KiB serialised: an
    adapter defect, surfaced as a FAILED run."""


class PersonaResting(CollectionError):
    """The persona is outside its active hours. Not a failure, and nothing
    was done."""

    def __init__(self, sentence: str, *, until: datetime | None = None):
        super().__init__(sentence)
        self.until = until


class PersonaSuspended(CollectionError):
    """The platform refused the persona's credential: revoked, banned, the
    wrong account, or (alert_officers) the same session in use from two
    places at once. The persona is locked by the machine until a new
    credential is enrolled; the run is BLOCKED."""

    def __init__(self, sentence: str, *, lock_code: str = "PLATFORM_REFUSED",
                 alert_officers: bool = False):
        super().__init__(sentence)
        self.lock_code = lock_code
        self.alert_officers = alert_officers


class WorkAbandoned(CollectionError):
    """A session outlived its budget and may still be open. The persona
    rests (a machine hold) so no second session starts beside it; the run
    FAILED."""


class EgressUnavailable(CollectionError):
    """No route may be taken: no egress profile, a retired one, or the
    route layer refused (no proxy where one is required, a destination the
    policy refuses). BLOCKED, never FAILED: configuration, not parser
    health (docs/20 section 9)."""


@dataclass(frozen=True)
class RunWarning:
    """Something a run wants known. `kind` is a key of WARNING_KINDS; the
    text is a sentence under the console copy rules that never names the
    source."""

    kind: str
    text: str


PARSER_DRIFT = "PARSER_DRIFT"
ITEM_SKIPPED = "ITEM_SKIPPED"
RAW_NOT_KEPT = "RAW_NOT_KEPT"
WATCH_PATTERN = "WATCH_PATTERN"
BUDGET_SPENT = "BUDGET_SPENT"
RETENTION_UNCLOCKED = "RETENTION_UNCLOCKED"
TIME_WITHOUT_ZONE = "TIME_WITHOUT_ZONE"
EGRESS_DIRECT = "EGRESS_DIRECT"

#: kind -> (error_class, makes_partial, holds_cursor). A kind that does not
#: make a run PARTIAL is a NOTE: stored in collection_run.notes and never a
#: fault. A drift holds the cursor, so the next poll starts where this one
#: started and nothing the parser missed is skipped for ever.
WARNING_KINDS: dict[str, tuple[str | None, bool, bool]] = {
    PARSER_DRIFT: ("ParserDrift", True, True),
    ITEM_SKIPPED: ("ItemSkipped", True, False),
    RAW_NOT_KEPT: ("RawNotKept", True, False),
    WATCH_PATTERN: ("WatchPatternError", True, False),
    BUDGET_SPENT: (None, False, False),
    RETENTION_UNCLOCKED: (None, False, False),
    TIME_WITHOUT_ZONE: (None, False, False),
    EGRESS_DIRECT: (None, False, False),
}

#: When several partial kinds occur, the run's error_class is the first of
#: these that is present.
_PARTIAL_ORDER = ("ParserDrift", "ItemSkipped", "RawNotKept",
                  "WatchPatternError")

EGRESS_DIRECT_NOTE = (
    "This poll was read directly from this host under the in-process egress "
    "policy: no egress proxy is configured.")

#: A resume cursor, serialised, is at most this (collection_run's CHECK).
MAX_CURSOR_BYTES = 16384
#: An item's own markup fragment is at most this.
MAX_ITEM_RAW_BYTES = 1024 * 1024
#: A request log keeps this many entries; the rest are counted in a note.
MAX_REQUEST_LOG = 100
#: A run keeps at most this many notes (collection_run's CHECK).
MAX_NOTES = 20

#: Namespaced external ids for every authority adapter ('post:123',
#: 'member:u:9', 'c:55/1024'), so a member id can never become version 2
#: of a post with the same number.
_NAMESPACED_ID = re.compile(r"^[a-z][a-z0-9_]{0,15}:\S+$")


@dataclass
class Item:
    """One thing a collector found. Deliberately flat and small: an adapter
    that has to construct a graph element is an adapter that can write the
    graph, and invariant 3 says it cannot.

    The adapter contract (2026-09-24) adds the identity fields a forum or a
    chat needs: `author_uid` (the platform's durable account id, typed), `parent_ref`
    (what this replies to), `category` (None is the adapter's default),
    `meta` (adapter data handed to commit hooks and to identity watches,
    never hashed or stored by the framework) and `raw_html` (the item's
    OWN fragment, never the page, navigation and form tokens removed).
    The digest is unchanged, so a meta-only change is never a new version.
    """

    external_id: str
    url: str | None = None
    title: str | None = None
    body: str = ""
    author_handle: str | None = None
    posted_at: datetime | None = None
    thread_ref: str | None = None
    raw: dict = field(default_factory=dict)
    author_uid: str | None = None
    parent_ref: str | None = None
    category: str | None = None
    meta: dict = field(default_factory=dict)
    raw_html: bytes | None = field(default=None, repr=False)

    @property
    def content_sha256(self) -> bytes:
        return hashlib.sha256(
            f"{self.external_id}\x1f{self.title or ''}\x1f{self.body}".encode()
        ).digest()


@dataclass
class FetchResult:
    """What an adapter returns. `cursor` {} means UNCHANGED (the input
    cursor carries forward). An adapter may subclass this to carry data to
    its own commit(); run_once never reads extra fields."""

    items: list[Item] = field(default_factory=list)
    etag: str | None = None
    last_modified: str | None = None
    http_status: int | None = None
    cursor: dict = field(default_factory=dict)
    warnings: list[RunWarning] = field(default_factory=list)
    deleted_external_ids: list[str] = field(default_factory=list)
    secret_update: str | None = field(default=None, repr=False)
    requests: list[dict] = field(default_factory=list)


@dataclass(frozen=True)
class SourceRow:
    """One source as run_once and the adapters see it, read by the one
    function `_source_row` under the caller's ceiling."""

    id: UUID
    kind: str
    name: str
    base_url: str | None
    parser_key: str | None
    classification: str
    default_reliability: str
    max_rps: float
    is_active: bool
    collection_account_id: UUID | None
    egress_profile_id: UUID | None
    parser_config: dict
    blocked_reason: str | None
    cursor_reset_at: datetime | None


class Adapter:
    """What a collector must implement.

    `fetch` returns ITEMS, never graph elements. An adapter that could
    construct a node would be an extractor writing the graph, and invariant
    3 says extractors propose.

    Where an item actually goes -- corrected 2026-09-02. This docstring
    used to say everything an adapter produces "reaches the graph only
    through the proposal queue a human works". It does not reach the
    graph at all. `CollectionService.run_once` stores each item as a
    `collect.document` (versioned, deduplicated on content hash) and, when
    a watch matches, a `collect.watch_hit`; it never calls `ProposalStore`
    and no extractor runs over the document afterwards. The only path from
    a source into `collect.proposal` is a MANUAL capture through
    `CaptureService`, which is an analyst pasting a page, not a poll.

    Wiring the collector into the proposal queue is a design decision
    deliberately NOT made here. It would put a machine's suggestions into
    an analyst's triage at the collector's rate rather than the analyst's,
    which is the "landfill" docs/09 warns about, and it belongs with the
    extractor work rather than with a docstring correction. What this
    class promises is the narrower and true thing: an adapter cannot write
    `core.node` or `core.edge`, because it never holds anything that could.

    ## The frozen contract (docs/00 decision 69, 2026-09-24)

    Class attributes, with the defaults RSS keeps. `source_kinds` empty
    means any kind, which only RSS may use; `requires_authority` is True
    for every forum and Telegram adapter (docs/00 decision 69);
    `persona_platform` None means persona-less only; `run_seconds` is the
    whole poll's wall clock, shared by every request in it. Every hook
    below has the base behaviour shown, and run_once reads each through
    `_attr`, so a duck-typed adapter that defines only `fetch` still polls.
    """

    key: str = "abstract"
    version: str = "0"
    source_kinds: frozenset[str] = frozenset()
    requires_authority: bool = False
    persona_platform: str | None = None
    persona_http: bool = False
    retention_clock: bool = False
    default_category: str = "FORUM_POST"
    keeps_raw: bool = False
    run_seconds: float = MAX_FETCH_SECONDS
    max_pages: int = 1
    max_page_bytes: int = MAX_RESPONSE_BYTES
    max_run_bytes: int = MAX_RESPONSE_BYTES
    min_interval_s: int = 60
    max_rps_cap: float = 1.0
    persona_min_gap_s: float = 0.0
    abandon_cooldown_s: float = 600.0

    def refusal(self, conn: psycopg.Connection, source: SourceRow) -> str | None:
        """An adapter-specific reason not to read this source (a missing
        library, an invalid parser_config). No network, no lock, no
        write."""
        return None

    def validate_source(self, base_url: str | None,
                        parser_config: dict) -> list[str]:
        """Sentences refusing a source at creation."""
        return []

    def validate_config(self, parser_config: dict) -> list[str]:
        """Sentences refusing a parser_config."""
        return []

    def validate_persona(self, fingerprint: dict) -> list[str]:
        """Sentences refusing a persona's recorded identity at creation."""
        return []

    def authority_need(self, source: SourceRow) -> str:
        """The scope run_once asks the authority for."""
        return "PUBLIC_READ"

    def plan(self, conn: psycopg.Connection, source: SourceRow, persona):
        """Runs before any network; may raise SourceBlocked."""
        return None

    def fetch(self, *, base_url: str, cursor: dict | None = None,
              etag: str | None = None, secret: str | None = None,
              context=None, route: EgressRoute | None = None) -> FetchResult:
        """`secret` is always None and stays for RSS only: a persona
        adapter reads context.persona.lease.value, which is registered for
        redaction. `route` is the route run_once resolved for this poll;
        an authority adapter reads the same object as context.route."""
        raise NotImplementedError

    def commit(self, conn: psycopg.Connection, *, source_id: UUID,
               run_id: UUID, persona_id: UUID | None,
               stored: dict[str, UUID], existing: dict[str, UUID],
               fetched: FetchResult) -> None:
        """Per-run side effects, inside the persist transaction. `stored`
        maps external_id to each document this run inserted; `existing`
        to the latest version the content-hash dedupe matched."""
        return None

    def commit_item(self, conn: psycopg.Connection, *, source_id: UUID,
                    run_id: UUID, persona_id: UUID | None, item: Item,
                    document_id: UUID, inserted: bool) -> None:
        """Per-item side effects, INSIDE the item's savepoint right after
        its document row: a side-table row the database refuses rolls back
        with its document and becomes ITEM_SKIPPED."""
        return None

    def settle(self, conn: psycopg.Connection, *, source_id: UUID,
               persona_id: UUID | None, run_id: UUID, status: str,
               error: str | None) -> None:
        """Called once for every outcome that wrote a run row, after the
        run is final and the source rescheduled, in its own transaction, so
        an adjustment to next_due_at wins. Its exception never changes the
        run."""
        return None


_MISSING = object()


def _attr(adapter, name: str):
    """A contract attribute of `adapter`, or the base value. A callable
    hook the adapter lacks is the BASE implementation bound to the adapter,
    so a duck-typed stub's missing commit, settle, plan or refusal runs the
    no-op with the right self instead of a TypeError inside the persist
    transaction."""
    value = getattr(adapter, name, _MISSING)
    if value is not _MISSING:
        return value
    base = getattr(Adapter, name)
    if callable(base):
        return types.MethodType(base, adapter)
    return base


class RssAdapter(Adapter):
    """The simplest adapter, and the one that proves the pipeline.

    docs/09 puts RSS first for exactly that reason: it needs no persona, no
    authorisation and no target that can notice it, so the plumbing can be
    proved before any of the risk arrives.

    Parsed with the stdlib XML parser and **entity resolution disabled**:
    an XXE in a feed you did not write is a file-read primitive, and a feed
    is by definition attacker-adjacent.

    Reads RSS and WEB sources only (2026-09-24): a XENFORO or TELEGRAM
    source with parser_key 'rss' would otherwise be read with no authority
    at all, bypassing docs/00 decision 69.
    """

    key = "rss"
    version = "1"
    source_kinds = frozenset({"RSS", "WEB"})

    def fetch(self, *, base_url: str, cursor: dict | None = None,
              etag: str | None = None, secret: str | None = None,
              context=None, route: EgressRoute | None = None) -> FetchResult:
        body, status, new_etag, last_modified = fetch(base_url, etag=etag,
                                                      route=route)
        if status == 304 or not body:
            return FetchResult(items=[], etag=etag, http_status=status)
        return FetchResult(items=parse_rss(body), etag=new_etag,
                           last_modified=last_modified, http_status=status)


#: The append point for a category only collection produces.
COLLECT_ONLY_CATEGORIES: tuple[str, ...] = (
    "FORUM_MEMBER",  # F3 and F4 (2026-09-24), a forum member's profile
)


def document_categories() -> tuple[str, ...]:
    """ingest.CATEGORIES plus the collect-only ones. Imported here rather
    than at the top, to keep this module's import graph as it is."""
    from noctornal_api.ingest import CATEGORIES
    return tuple(CATEGORIES) + COLLECT_ONLY_CATEGORIES


def __getattr__(name: str):
    """`collection.DOCUMENT_CATEGORIES`, computed on first read (PEP 562),
    so the name the contract gives exists without the import above
    running at module load."""
    if name == "DOCUMENT_CATEGORIES":
        return document_categories()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def default_adapters() -> dict[str, Adapter]:
    """THE registry: CollectionService with no adapters argument uses it,
    the routes obtain it through get_adapters() in routers/collection.py,
    and the readiness rows read it. An adapter is registered by one line
    here and nowhere else."""
    from noctornal_api.forum_adapters import forum_registry  # F3 and F4 (2026-09-24)
    from noctornal_api.telegram import TelegramAdapter  # F5.3

    return {
        "rss": RssAdapter(),
        **forum_registry(),  # xenforo and mybb, public boards (2026-09-24)
        "telegram": TelegramAdapter(),  # F5.3, 2026-09-24
    }


#: Every reader of a source that a caller may see: the ceiling on the
#: source's own label. One fragment, so a later compartments column on
#: collect.source is one edit.
_SOURCE_VISIBLE = ("(%(clearance)s::core.tlp IS NULL "
                   "OR s.classification <= %(clearance)s::core.tlp)")

_SOURCE_COLUMNS = (
    "s.id, s.kind::text, s.name, s.base_url, s.parser_key, "
    "s.classification::text, s.default_reliability::text, s.max_rps, "
    "s.is_active, s.collection_account_id, s.egress_profile_id, "
    "s.parser_config, s.blocked_reason, s.cursor_reset_at")


def _row_to_source(row) -> SourceRow:
    return SourceRow(
        id=row[0], kind=row[1], name=row[2], base_url=row[3],
        parser_key=row[4], classification=row[5],
        default_reliability=row[6], max_rps=float(row[7] or 1),
        is_active=bool(row[8]), collection_account_id=row[9],
        egress_profile_id=row[10], parser_config=dict(row[11] or {}),
        blocked_reason=row[12], cursor_reset_at=row[13])


def _source_row(conn: psycopg.Connection, source_id: UUID,
                clearance: str | None) -> SourceRow:
    """The source, or CollectionNotFound when it does not exist OR sits
    above the caller's ceiling, indistinguishably."""
    row = conn.execute(
        f"SELECT {_SOURCE_COLUMNS} FROM collect.source s "
        f"WHERE s.id = %(id)s AND {_SOURCE_VISIBLE}",
        {"id": source_id, "clearance": clearance}).fetchone()
    if row is None:
        raise CollectionNotFound(
            "no such source, or it is above your clearance")
    return _row_to_source(row)




#: Anything that could introduce an entity. A feed is attacker-adjacent by
#: definition -- it is a document written by the people under investigation.
_DOCTYPE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.I)


#: The XML prolog ends at the first element start-tag. Anything before it
#: is a declaration, comment or processing instruction — the only region
#: where a DTD may legally appear (CP1).
_ROOT_START = re.compile(rb"<[A-Za-z_]")


def _root_element_offset(body: bytes, cap: int = 1 << 20) -> int:
    """Where the prolog ends, capped so a body with no root element does
    not turn the DOCTYPE scan into a full pass over 16 MiB."""
    match = _ROOT_START.search(body[:cap])
    return match.start() if match else min(len(body), cap)


def parse_rss(body: bytes) -> list[Item]:
    """Minimal RSS/Atom parsing that REFUSES a DOCTYPE.

    `defusedxml` would be the right dependency and is not one. Without it,
    the honest defence is to refuse the construct rather than to try to
    neuter it: a feed has no legitimate need for a DOCTYPE or an internal
    entity, and refusing both closes XXE and billion-laughs outright
    instead of relying on a parser flag whose name and effect have changed
    between Python versions.

    An XXE in a feed you did not write is a file-read primitive on the
    collector, which is the host holding every persona credential.
    """
    from xml.etree import ElementTree

    # CP1 (2026-07-26): scan up to the ROOT ELEMENT, not a fixed 8 KiB.
    #
    # The window was `body[:8192]` while bodies up to 16 MiB are accepted,
    # so an 8 KiB XML comment ahead of the DTD walked straight past the
    # regex. ElementTree resolves no external entities and modern libexpat
    # caps entity amplification, so the demonstrated harm is limited — but
    # this is the check that is supposed to make those two facts
    # irrelevant, and a defence with a documented bypass is not one.
    #
    # The prolog is everything before the first element start-tag that is
    # not a comment, PI or declaration. Scanning to the first `<` that
    # begins a name character bounds the work without bounding the
    # coverage: a DTD cannot legally appear after the root element starts,
    # so anything past that point is not a prolog DTD.
    prolog_end = _root_element_offset(body)
    if _DOCTYPE.search(body[:prolog_end]):
        raise CollectionError(
            "refusing a feed containing a DOCTYPE or ENTITY declaration: a "
            "feed has no legitimate need for one, and an XXE here is a "
            "file-read primitive on the host holding every persona "
            "credential")

    try:
        root = ElementTree.fromstring(body)
    except Exception as exc:  # noqa: BLE001 - a broken feed is not a crash
        raise CollectionError(f"feed did not parse: {type(exc).__name__}") from exc

    items: list[Item] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].lower()
        if tag not in {"item", "entry"}:
            continue
        fields: dict[str, str] = {}
        for child in element:
            name = child.tag.rsplit("}", 1)[-1].lower()
            if name == "link" and not (child.text or "").strip():
                fields["link"] = child.attrib.get("href", "")
            else:
                fields[name] = (child.text or "").strip()
        external = (fields.get("guid") or fields.get("id")
                    or fields.get("link") or fields.get("title") or "")
        if not external:
            continue
        items.append(Item(
            external_id=external,
            url=fields.get("link"),
            title=fields.get("title"),
            body=fields.get("description") or fields.get("summary")
            or fields.get("content") or "",
            author_handle=fields.get("author") or fields.get("creator"),
            raw=fields,
        ))
    return items


def fetch(url: str, *, etag: str | None = None,
          timeout: float = 15.0,
          max_redirects: int = MAX_REDIRECTS,
          max_bytes: int = MAX_RESPONSE_BYTES,
          tls_context: ssl.SSLContext | None = None,
          max_seconds: float = MAX_FETCH_SECONDS,
          route: EgressRoute | None = None,
          ) -> tuple[bytes, int, str | None, str | None]:
    """An outbound HTTP GET that connects only to addresses it has checked.

    Refuses non-HTTP schemes, credentials in the URL and any name that
    resolves into private space, and does it on **every redirect hop**
    rather than the first URL only. `tls_context` is for a private CA; it
    must still verify certificates against the name, and None means the
    platform trust store, as before.

    `timeout` bounds each socket operation and `max_seconds` bounds the
    whole call, every hop included (c2, 2026-09-24). The second is the one
    a hostile source cannot stretch: it is enforced by a watchdog that
    shuts the socket down under a read still going when it runs out, so a
    body or a header drip-fed one byte at a time ends on time instead of
    when the far end chooses. See `pinned_http.Deadline`.

    `route` is the route from egress.route_for; None is the direct public
    route this function has always used, refused once a proxy is
    configured (2026-09-24). A thin wrapper since then: the work is
    pinned_http's, the one outbound client, and this keeps the collector's
    signature, its return tuple and every message its suites read.

    ## The check and the connect are one lookup (sec-ssrf-rebinding)

    Until 2026-09-23 this docstring called itself a floor and said why: the
    name was resolved once by the check and again by the socket layer
    inside `urlopen`, and nothing stopped the two answers differing. That
    is DNS rebinding, and it needs no more than a zone with a zero TTL
    answering a public address first and an internal one second.

    Now each hop's name is resolved ONCE and the answers that were judged
    are the addresses the pinned connection dials, by number. The name
    still goes everywhere a name belongs: the `Host` header, TLS SNI and
    the certificate check, so a pinned address serves only the host the
    URL names.

    No proxy is consulted from the environment. urlopen read HTTP_PROXY,
    HTTPS_PROXY and, on Windows, the system proxy setting, and a forward
    proxy resolves the name itself, so a check made here would say nothing
    about where it connected. A proxy is used only when the caller passes a
    route from egress.route_for whose mode is PROXY; the egress proxy is
    then the single resolver at the boundary and applies egress_policy.py
    itself, and this process resolves nothing but the proxy's own address
    (docs/00 decision 68).

    Redirects (docs/17 F15(f)) are followed hop by hop, never inside the
    HTTP library: `urlopen` used to follow them internally, so hops 2..N
    were reached with no check at all and a public host answering
    `302 -> http://127.0.0.1/` fetched the internal page.
    """
    fetched = pinned_http._fetch_response(
        url, route=route if route is not None else _legacy_route(), etag=etag,
        timeout=timeout, max_redirects=max_redirects, max_bytes=max_bytes,
        tls_context=tls_context, max_seconds=max_seconds,
        accept_status=frozenset({304}), user_agent=COLLECTOR_USER_AGENT,
        _blocked_override=_live_is_blocked)
    if fetched.status == 304:
        return b"", 304, etag, None
    return fetched.body, fetched.status, fetched.etag, fetched.last_modified


def fetch_response(url: str, *, route: EgressRoute | None = None, **kwargs) -> Fetched:
    """pinned_http.fetch_response with the collector's test seam: the call
    a collection adapter's RunContext makes (docs/20 section 9), so a
    suite that patches `collection._is_blocked` reaches the connect through
    this path as it does through `fetch`. `route` None is the legacy route
    `fetch` uses (2026-09-24)."""
    return pinned_http._fetch_response(
        url, route=route if route is not None else _legacy_route(),
        _blocked_override=_live_is_blocked, **kwargs)


# ---------------------------------------------------------------------------
# The scheduler
# ---------------------------------------------------------------------------

def next_due_at(last_ok: datetime | None, interval_s: int, jitter_pct: int,
                *, now: datetime | None = None,
                rng: random.Random | None = None) -> datetime:
    """When to poll next, with jitter as a PERCENTAGE of the interval.

    docs/04 asks for jitter and the reason is operational security, not
    courtesy: a collector that polls exactly every 300 seconds is one a
    competent forum admin picks out of an access log in an afternoon, and a
    burnt persona is expensive and slow to replace.

    Jitter is symmetric around the interval rather than added to it -- only
    ever adding makes the MINIMUM gap the interval, which is still a
    signature.
    """
    now = now or datetime.now(timezone.utc)
    if last_ok is None:
        # A source that has NEVER been polled is due now, not one interval
        # from now. Waiting the interval first means a newly-added source
        # sits idle for its whole period and somebody concludes the
        # collector is broken -- which is how a working system gets
        # "fixed".
        return now
    base = last_ok + timedelta(seconds=interval_s)
    if jitter_pct <= 0:
        return base
    generator = rng or random.Random()
    spread = interval_s * (jitter_pct / 100.0)
    return base + timedelta(seconds=generator.uniform(-spread, spread))


class RateLimiter:
    """Per-source `max_rps`, spaced rather than bursted.

    docs/04 asks for it globally through Redis; this is the durable half
    and it is honest about being that. A burst that respects an average is
    still a burst, and a burst is what gets noticed.

    docs/17 F15(i): the state used to live on the INSTANCE, and
    `CollectionService` is constructed per request, so the dict was always
    empty and this never spaced anything. It now reads and writes
    `collect.source.last_request_at`, which survives the process and is
    shared between workers -- the property that actually matters. A Redis
    token bucket remains the right optimisation; it is no longer the fix
    for a correctness bug.
    """

    def __init__(self, conn: psycopg.Connection | None = None, *,
                 sleep=time.sleep, clock=time.monotonic):
        self._c = conn
        self._last: dict[UUID, float] = {}
        self._sleep = sleep
        self._clock = clock

    def wait(self, source_id: UUID, max_rps: float) -> float:
        if max_rps <= 0:
            return 0.0
        gap = 1.0 / max_rps
        delay = 0.0
        if self._c is not None:
            # `now()` is the TRANSACTION timestamp in Postgres and would
            # be identical for two calls in one transaction; clock_timestamp
            # is the wall clock, which is what a gap between requests means.
            row = self._c.execute(
                """SELECT extract(epoch FROM
                              clock_timestamp() - last_request_at)
                     FROM collect.source WHERE id = %s""",
                (source_id,)).fetchone()
            elapsed = float(row[0]) if row and row[0] is not None else None
            if elapsed is not None and elapsed < gap:
                # A stamp ahead of the clock (it stepped back) waits the
                # whole gap, never none (2026-09-25).
                delay = gap - max(elapsed, 0.0)
                self._sleep(delay)
            self._c.execute(
                "UPDATE collect.source SET last_request_at = clock_timestamp() "
                "WHERE id = %s", (source_id,))
            return delay

        # No connection: in-process only, which is what the unit tests use
        # and what a caller gets if they construct this by hand. Kept so
        # the class is still testable without a database, and NOT the
        # default anywhere real.
        now = self._clock()
        previous = self._last.get(source_id)
        if previous is not None and now - previous < gap:
            delay = gap - (now - previous)
            self._sleep(delay)
        self._last[source_id] = self._clock()
        return delay

    def wait_persona(self, persona_id: UUID, min_gap_s: float) -> float:
        """The gap between two requests made AS one persona, whatever source
        they read (2026-09-24): the platform sees one account, so the
        gap is the account's. Measured on collection_account.last_request_at
        with clock_timestamp(), exactly as `wait` measures a source, so it
        survives the process and is shared between workers. Zero or less
        does nothing."""
        if min_gap_s <= 0:
            return 0.0
        delay = 0.0
        if self._c is None:
            key = ("persona", persona_id)
            now = self._clock()
            previous = self._last.get(key)
            if previous is not None and now - previous < min_gap_s:
                delay = min_gap_s - (now - previous)
                self._sleep(delay)
            self._last[key] = self._clock()
            return delay
        row = self._c.execute(
            """SELECT extract(epoch FROM clock_timestamp() - last_request_at)
                 FROM collect.collection_account WHERE id = %s""",
            (persona_id,)).fetchone()
        elapsed = float(row[0]) if row and row[0] is not None else None
        if elapsed is not None and elapsed < min_gap_s:
            # As `wait`: a stamp ahead of the clock waits the whole gap.
            delay = min_gap_s - max(elapsed, 0.0)
            self._sleep(delay)
        self._c.execute(
            "UPDATE collect.collection_account "
            "SET last_request_at = clock_timestamp() WHERE id = %s",
            (persona_id,))
        return delay


@dataclass
class RunResult:
    run_id: UUID
    items_seen: int = 0
    items_new: int = 0
    items_deleted: int = 0
    watch_hits: int = 0
    error: str | None = None
    #: Things the run could not do while otherwise succeeding -- the same
    #: idea as `lab.sample.triage_gaps`. A watch whose regex will not
    #: compile is the case this exists for: it matches nothing, for ever,
    #: and without this the run is indistinguishable from one where the
    #: pattern simply did not fire. `default_factory`, because a mutable
    #: default on a dataclass is shared by every instance.
    warnings: list[str] = field(default_factory=list)
    #: What the run wants known that is not a fault: a walk that
    #: stopped at its budget, documents with no retention clock.
    notes: list[str] = field(default_factory=list)
    #: One of collect.run_status: OK, PARTIAL, FAILED, BLOCKED or
    #: RATE_LIMITED.
    status: str = "OK"
    #: The sentence a BLOCKED run stores on its source.
    blocked_reason: str | None = None


#: Serialises the poll of ONE source across processes -- see `run_once`.
#:
#: Keyed on the SOURCE rather than one lock for the whole collector,
#: because two different sources SHOULD poll at the same time: they are
#: different sites, politeness is already per source (`max_rps` and
#: `collect.source.last_request_at`), and a single global lock would make
#: the runner's throughput the slowest feed's fetch timeout -- which is the
#: shape of failure where a cron entry starts overlapping ITSELF.
#:
#: Session-scoped (`pg_try_advisory_lock`), not transaction-scoped, for the
#: reason `transports._DRAIN_LOCK` states: `db.connect()` is autocommit, so
#: a `pg_advisory_xact_lock` would be released by the very statement that
#: took it and would guard nothing. The name is hashed with
#: `hashtextextended(..., 0)`, the idiom the drain lock and migrations 0013
#: and 0024 already use, so the lock space is addressed one way across the
#: codebase.
_POLL_LOCK = "collect.run_once"


def _poll_lock_key(source_id: UUID) -> str:
    """The lock name for one source.

    The id goes INSIDE the name rather than into a second key argument:
    `hashtextextended` takes text and returns the single bigint the
    one-argument form of `pg_try_advisory_lock` wants, and mixing the two
    forms would split the lock space in two -- the two-argument form has a
    keyspace of its own, and a lock taken in one is invisible to the other.
    """
    return f"{_POLL_LOCK}:{source_id}"


#: The kinds of `collect.source_kind`, as create_source validates them.
SOURCE_KINDS = ("RSS", "XENFORO", "MYBB", "PHPBB", "TELEGRAM", "DISCORD",
                "PASTE", "WEB", "MANUAL", "VENDOR_API")

#: What a source with no exit is told, at creation, in the held list and at
#: the route: a direct read would show the investigating host.
EGRESS_NONE_SENTENCE = ("This source has no egress profile, so it is not "
                        "read: a direct read would show the investigating "
                        "host.")
EGRESS_RETIRED_SENTENCE = ("The egress profile this source is read through "
                           "is missing or retired.")
#: The collection authority's refusal about a PERSON, answered 409 before
#: any run row and with no change to the source.
CONFIRMER_SENTENCE = ("The person who confirmed this authority does not run "
                      "the collection it covers. Somebody else runs it.")
SUSPENDED_SOURCE_SENTENCE = ("The persona that reads this source was "
                             "suspended by its platform.")

#: The labels a watch may match an item's `meta['match_ids']` under.
_MATCH_LABEL = re.compile(r"^[a-z_]{1,24}$")

_DEFAULT_STORE = object()


class _ItemInvalid(Exception):
    """An item the framework will not store; becomes ITEM_SKIPPED."""


def _clean_text(value):
    """NUL is replaced with U+FFFD and a lone surrogate with '?': Postgres
    stores neither, and one poison post must not fail a whole poll."""
    if value is None:
        return None
    text = str(value).replace("\x00", "�")
    return text.encode("utf-8", "replace").decode("utf-8")


def _capped(value, limit: int):
    return None if value is None else value[:limit]


class CollectionService:
    """The scheduler's reporting half, one poll, and the read path.

    Where a poll's output goes, stated exactly because the `Adapter`
    docstring used to overstate it: `run_once` stores what it fetched as
    `collect.document` and `collect.watch_hit` rows, and records the poll
    itself on `collect.collection_run`, on the source (health, failure
    count, next due time) and on `collect.watch.last_hit_at`. That is the
    whole list, plus (2026-09-24) the raw markup an adapter keeps,
    in its own bucket, and whatever an adapter's own commit hooks write
    inside the same persist transaction. No proposal, no extraction, no
    graph element.

    Two kinds of caller share this class, and `clearance` is how they are
    told apart. The listing methods take `clearance=None` for the
    worker/scheduler, which has no user and must see every source or it
    silently polls nothing, and a TLP name for an HTTP caller, whose own
    ceiling then hides any source labelled above it.

    `fetcher` replaces `collection.fetch_response` inside RunContext (the
    tests inject one; nothing in production passes it) and `raw_store` the
    raw markup store (default: MinIO when configured, else none).
    """

    def __init__(self, conn: psycopg.Connection,
                 adapters: dict[str, Adapter] | None = None,
                 limiter: RateLimiter | None = None, *,
                 fetcher=None, raw_store=_DEFAULT_STORE, sleep=time.sleep):
        self._c = conn
        self._adapters = adapters or default_adapters()
        self._limiter = limiter or RateLimiter(conn, sleep=sleep)
        self._fetcher = fetcher
        self._raw_store = raw_store
        self._sleep = sleep

    @property
    def adapters(self) -> dict[str, Adapter]:
        return self._adapters

    @property
    def raw_store(self):
        """The raw markup store, built on first use: most callers of this
        class never touch it, and a MinIO client per request is waste."""
        if self._raw_store is _DEFAULT_STORE:
            from noctornal_api.rawstore import default_document_raw_store
            self._raw_store = default_document_raw_store()
        return self._raw_store

    # -- what may be polled -------------------------------------------------

    #: The causes `refusal_cause` names, for the readiness row's counts.
    CAUSE_KIND = "kind"
    CAUSE_BINDING = "binding"
    CAUSE_INACTIVE = "inactive"
    CAUSE_NO_CEILING = "no_ceiling"
    CAUSE_ABOVE_CEILING = "above_ceiling"
    CAUSE_NO_EGRESS = "no_egress"
    CAUSE_PERSONA = "persona"
    CAUSE_ADAPTER = "adapter"

    def _refusal(self, source: SourceRow, adapter) -> str | None:
        """Why this source is not read at all, before any lock, run row or
        network (step 3 of run_once's order), or None. The same answer
        creates the held list's REFUSED rows, so the schedule and the poll
        cannot disagree. Never about the caller: the confirmer's refusal is
        run_once's."""
        found = self.refusal_cause(source, adapter)
        return found[1] if found else None

    def refusal_cause(self, source: SourceRow, adapter
                      ) -> tuple[str, str] | None:
        """(cause, sentence) for `_refusal`, or None. The cause is one of
        the CAUSE_ names, so the readiness row counts causes rather than
        parsing sentences."""
        from noctornal_api.collection_authority import (
            AUTHORITY_KINDS,
            ceiling_refusal,
            source_ceiling,
        )

        requires = bool(_attr(adapter, "requires_authority"))
        kinds = frozenset(_attr(adapter, "source_kinds") or ())
        if source.kind in AUTHORITY_KINDS and not requires:
            return self.CAUSE_KIND, (
                "This source is a forum or Telegram source and its parser "
                "does not enforce collection authority, so it is not read.")
        if kinds and source.kind not in kinds:
            return self.CAUSE_KIND, (
                f"This source is a {source.kind} source, and the "
                f"{source.parser_key} parser does not read that kind.")
        platform = _attr(adapter, "persona_platform")
        if platform is None and source.collection_account_id is not None:
            return self.CAUSE_BINDING, (
                "This source is bound to a persona, and its parser reads "
                "without one.")
        if platform is not None and source.collection_account_id is None:
            return self.CAUSE_BINDING, (
                "This source is read by a persona, and none is bound to it.")
        if not requires:
            return None
        if not source.is_active:
            return self.CAUSE_INACTIVE, "This source is deactivated."
        refusal = ceiling_refusal(source)
        if refusal:
            declared, _sentence = source_ceiling(source.kind)
            return (self.CAUSE_NO_CEILING if declared is None
                    else self.CAUSE_ABOVE_CEILING), refusal
        if source.collection_account_id is None:
            profile = source.egress_profile_id
            if profile is None:
                return self.CAUSE_NO_EGRESS, EGRESS_NONE_SENTENCE
        else:
            persona = self._c.execute(
                "SELECT platform::text, egress_profile_id "
                "FROM collect.collection_account WHERE id = %s",
                (source.collection_account_id,)).fetchone()
            if persona is None:
                return self.CAUSE_PERSONA, (
                    "The persona this source is read as no longer exists.")
            if persona[0] != platform:
                return self.CAUSE_PERSONA, (
                    f"This persona is a {persona[0]} account and this source "
                    f"is read by a {platform} adapter."
                    if persona[0] else
                    f"This persona is not placed on any platform, and this "
                    f"source is read by a {platform} adapter.")
            profile = persona[1]
            if profile is None:
                return self.CAUSE_NO_EGRESS, (
                    "This persona has no egress profile, so it cannot reach "
                    "anything.")
        active = self._c.execute(
            "SELECT is_active FROM collect.egress_profile WHERE id = %s",
            (profile,)).fetchone()
        if active is None or not active[0]:
            return self.CAUSE_NO_EGRESS, EGRESS_RETIRED_SENTENCE
        own = _attr(adapter, "refusal")(self._c, source)
        return (self.CAUSE_ADAPTER, own) if own else None

    def _schedule(self, *, now: datetime, rng: random.Random | None,
                  clearance: str | None) -> tuple[list[dict], list[dict]]:
        """(due, held) in `next_due_at` order. One read of the sources, the
        persona rows of the bound ones and the authority coverage, so the
        cron's pass is three queries however many sources there are."""
        from noctornal_api.collection_authority import CollectionAuthorityService

        rows = self._c.execute(
            f"""SELECT {_SOURCE_COLUMNS}, s.poll_interval_s, s.jitter_pct,
                       s.last_ok_at, s.consecutive_failures, s.health,
                       s.next_due_at
                  FROM collect.source s
                 WHERE s.is_active AND {_SOURCE_VISIBLE}
                 ORDER BY s.next_due_at NULLS FIRST""",
            {"clearance": clearance}).fetchall()
        candidates: list[tuple[SourceRow, tuple, datetime]] = []
        for row in rows:
            source = _row_to_source(row)
            interval, jitter, last_ok, failures, health, when = row[14:20]
            if when is None:
                # A source added before 0042, or one whose schedule was
                # never set. Roll it ONCE and persist, rather than treating
                # a missing schedule as "not due" and never polling it.
                when = next_due_at(last_ok, interval, jitter, now=now, rng=rng)
                self._c.execute(
                    "UPDATE collect.source SET next_due_at = %s WHERE id = %s",
                    (when, source.id))
            if when <= now:
                candidates.append((source, (interval, jitter, failures,
                                            health), when))
        personas = self._persona_rows(
            [s.collection_account_id for s, _r, _w in candidates
             if s.collection_account_id is not None], clearance=clearance)
        authority_sources = [
            s for s, _r, _w in candidates
            if (a := self._adapters.get(s.parser_key)) is not None
            and _attr(a, "requires_authority")]
        uncovered = (CollectionAuthorityService(self._c, self._adapters)
                     .uncovered_map(authority_sources, clearance=clearance)
                     if authority_sources else {})
        due: list[dict] = []
        held: list[dict] = []
        for source, (interval, jitter, failures, health), when in candidates:
            adapter = self._adapters.get(source.parser_key)
            persona = personas.get(source.collection_account_id)
            entry = {
                "id": source.id, "kind": source.kind, "name": source.name,
                "base_url": source.base_url, "max_rps": source.max_rps,
                "parser_key": source.parser_key, "due_at": when.isoformat(),
                "consecutive_failures": failures, "health": health,
                "requires_authority": bool(
                    adapter is not None and _attr(adapter, "requires_authority")),
                "run_seconds": (float(_attr(adapter, "run_seconds"))
                                if adapter is not None else None),
                "persona": _persona_ref(persona),
                "egress_profile_id": (str(source.egress_profile_id)
                                      if source.egress_profile_id else None),
            }
            if adapter is None:
                # Kept on the due list, as it always was: the poll refuses
                # it by name and the cron's exit code says so every pass.
                due.append(entry)
                continue
            hold = self._hold(source, adapter, persona, uncovered, now=now,
                              interval=interval, jitter=jitter, when=when,
                              rng=rng)
            if hold is None:
                due.append(entry)
            else:
                held.append({"id": source.id, "name": source.name,
                             "kind": source.kind, **hold,
                             "persona": _persona_ref(persona)})
        return due, held

    def _hold(self, source: SourceRow, adapter, persona: dict | None,
              uncovered: dict, *, now: datetime, interval: int, jitter: int,
              when: datetime, rng) -> dict | None:
        """Why a due source waits on a person, or None when it may be
        polled. A held source is not polled and not rescheduled, so it
        cannot fill a pass's --limit slots, and it is due the moment the
        person acts; the one exception is a persona resting outside its
        active hours (below)."""
        refusal = self._refusal(source, adapter)
        if refusal:
            return {"reason": "REFUSED", "sentence": refusal, "until": None}
        if not _attr(adapter, "requires_authority"):
            return None
        if persona is not None:
            if not persona["usable"]:
                sentence, until = _persona_hold_sentence(persona, now)
                return {"reason": "PERSONA", "sentence": sentence,
                        "until": until.isoformat() if until else None}
            try:
                window = active_window(persona["window"])
            except ValueError:
                window = None
            opening = window_opening(window, now) if window else None
            if opening is not None:
                # A night's rest must not end in every source firing on the
                # first cron pass after the opening, at the same time every
                # day (the regular signature docs/04 forbids): the next due
                # time moves to the opening plus a jitter of its own. The
                # second write due_sources makes, beside rolling a missing
                # schedule.
                spread = min(interval * max(jitter, 0) / 100.0, 3600.0)
                generator = rng or random.Random()
                moved = opening + timedelta(
                    seconds=generator.uniform(0, spread) if spread > 0 else 0)
                if when < opening:
                    self._c.execute(
                        "UPDATE collect.source SET next_due_at = %s "
                        "WHERE id = %s", (moved, source.id))
                return {"reason": "PERSONA",
                        "sentence": (f"This persona is outside its active "
                                     f"hours until "
                                     f"{opening.strftime('%H:%M')} UTC."),
                        "until": opening.isoformat()}
        sentence = uncovered.get(source.id)
        if sentence:
            return {"reason": "AUTHORITY", "sentence": sentence, "until": None}
        return None

    def _persona_rows(self, ids: list[UUID], *,
                      clearance: str | None) -> dict[UUID, dict]:
        if not ids:
            return {}
        rows = self._c.execute(
            f"""SELECT a.id, a.handle, a.status, a.cooldown_until,
                       a.machine_hold_until, a.machine_lock_code,
                       a.fingerprint_profile->>'active_window_utc',
                       {PERSONA_USABLE_SQL},
                       {PERSONA_VISIBLE_SQL}, a.egress_profile_id
                  FROM collect.collection_account a
                 WHERE a.id = ANY(%(ids)s)""",
            {"ids": list(ids), "clearance": clearance}).fetchall()
        return {r[0]: {"id": r[0], "handle": r[1], "status": r[2],
                       "cooldown_until": r[3], "hold_until": r[4],
                       "lock_code": r[5], "window": r[6], "usable": r[7],
                       "visible": r[8], "egress_profile_id": r[9]}
                for r in rows}

    def due_sources(self, *, now: datetime | None = None,
                    rng: random.Random | None = None,
                    clearance: str | None = None) -> list[dict]:
        """What is ready to poll. Reports; does not act.

        Nothing loops here. A collector that runs itself on a timer nobody
        watches is how a persona gets burnt at 3am, and the same reasoning
        (decisions 30, 46) applies: the seam is deliberate.

        It also does not ROLL here. docs/17 F15(i): this used to compute
        `next_due_at` freshly on every call, so the schedule was re-rolled
        every time anybody looked and the realised interval depended on how
        often the scheduler polls. Frequent polling collapsed the variance
        toward the floor -- a regular cadence, which is the signature
        jitter exists to avoid. The schedule is now stored, rolled once
        when a run finishes, and read as-is.

        Since 2026-09-24, only what may be polled. A source that would be
        refused before any request, whose persona cannot be used now, or
        that no confirmed authority covers is left out and reported by
        `held_sources` instead, so it cannot fill a pass or be recorded as
        a failure.

        `clearance=None` -- the default, and the scheduler's reading --
        applies NO classification filter. An HTTP caller passes its own
        ceiling, and a source labelled above it is not reported as due: its
        name and URL are what the label protects.
        """
        due, _held = self._schedule(now=now or datetime.now(timezone.utc),
                                    rng=rng, clearance=clearance)
        return due

    def held_sources(self, *, clearance: str | None = None,
                     now: datetime | None = None) -> list[dict]:
        """The due sources that wait on a person: REFUSED (a ceiling to
        declare, an exit to bind), PERSONA (a persona to rest or replace)
        or AUTHORITY (an authority to confirm), each with its sentence. An
        AUTHORITY sentence is generic whenever the nearest authority is
        above the caller's ceiling, and a persona the caller may not
        see is 'a persona you cannot see'."""
        _due, held = self._schedule(now=now or datetime.now(timezone.utc),
                                    rng=None, clearance=clearance)
        return held

    def due_and_held(self, *, clearance: str | None = None,
                     now: datetime | None = None,
                     rng: random.Random | None = None
                     ) -> tuple[list[dict], list[dict]]:
        """Both answers from ONE reading of the schedule: the cron's pass
        (2026-09-25). Asking due_sources and then
        held_sources reads it twice, and the first reading moves a source
        whose persona is outside its active hours to the window's opening,
        so the second no longer saw it as due and the pass under-counted
        `held`."""
        return self._schedule(now=now or datetime.now(timezone.utc),
                              rng=rng, clearance=clearance)

    def held_count(self) -> int:
        """A count of held sources from a reading of its own. The cron
        uses due_and_held instead, for the reason given there."""
        return len(self.held_sources())

    def poll_seconds(self, source_id: UUID) -> float:
        """The wall clock a poll of this source may take: the adapter's
        run_seconds for an authority adapter, 0 for any other, so the cron
        reserves a long poll's budget without changing how RSS passes are
        clocked."""
        row = self._c.execute(
            "SELECT parser_key FROM collect.source WHERE id = %s",
            (source_id,)).fetchone()
        adapter = self._adapters.get(row[0]) if row else None
        if adapter is None or not _attr(adapter, "requires_authority"):
            return 0.0
        return float(_attr(adapter, "run_seconds"))

    def _reschedule(self, source_id: UUID, *,
                    rng: random.Random | None = None) -> datetime:
        """Roll the next due time ONCE, after a poll, and store it."""
        row = self._c.execute(
            "SELECT poll_interval_s, jitter_pct FROM collect.source "
            "WHERE id = %s", (source_id,)).fetchone()
        when = next_due_at(datetime.now(timezone.utc), row[0], row[1], rng=rng)
        self._c.execute(
            "UPDATE collect.source SET next_due_at = %s WHERE id = %s",
            (when, source_id))
        return when

    # -- one poll -----------------------------------------------------------

    def run_once(self, source_id: UUID, *, actor_id: UUID | None,
                 persona_id: UUID | None = None,
                 watch_id: UUID | None = None,
                 clearance: str | None = None) -> RunResult:
        """One poll. Every outcome that got as far as the lock is a
        `collection_run` row, including the failures -- parser health is
        only knowable if the failures are recorded as carefully as the
        successes.

        `clearance` is the caller's own ceiling, and a source above it is
        refused as `CollectionNotFound` -- indistinguishably from a source
        that does not exist. Added 2026-09-02, because a failing poll
        returned the SSRF guard's messages, which quote the host. `None` is
        the worker's reading and applies NO filter.

        `actor_id` is who pressed Poll now, recorded on the run; None is
        the system (the cron), and persona use it causes is audited as the
        system, never as a nil UUID (2026-09-24).

        ## One poll of one source at a time (2026-09-10)

        A per-source advisory lock (`pg_try_advisory_lock`, session scoped,
        because this connection is autocommit), taken AFTER the clearance
        check so "busy" is not an existence oracle. The loser returns
        immediately with `CollectionBusy` and writes nothing.

        ## The order (2026-09-24)

        1. the source under the ceiling, and its adapter;
        2. the persona argument: a persona-less parser takes none, and a
           persona parser reads as the bound persona only;
        3. every refusal that is about configuration (`_refusal`) and the
           confirmer's (a person who confirmed the covering authority does
           not run it), before any lock, run row or network;
        4. the source lock; 5. the persona gate's check, lock and hours;
        6. the resume cursor, read AFTER the lock; 7. the run row, with its
           start time, persona, exit and requester, COMMITTED before the
           route is resolved (autocommit; a caller inside a transaction is
           refused), because the egress proxy reads it from its own
           connection;
        8. the authority (missing: BLOCKED); 9. the adapter's plan;
        10. the egress route, RSS included (the passive default, so RSS
           keeps working once a proxy is configured); 11. RSS's one wait;
        12. the persona lease and the fetch; 13. the outcome;
        14. ONE persist transaction with a savepoint per item;
        15. a persist failure is FAILED and re-raised; 16. the lease, the
           persona lock and the source lock are released; 17. the adapter
           settles every outcome that wrote a run row.
        """
        from noctornal_api.collection_authority import (
            AuthorityError,
            CollectionAuthorityService,
        )

        if self._c.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
            raise CollectionError(
                "a poll runs on a connection with no transaction open: its "
                "run row is committed before the route is resolved, so the "
                "egress proxy can read it")
        source = _source_row(self._c, source_id, clearance)
        adapter = self._adapters.get(source.parser_key)
        if adapter is None:
            raise CollectionError(
                f"no adapter registered for parser_key {source.parser_key!r}")
        platform = _attr(adapter, "persona_platform")
        requires = bool(_attr(adapter, "requires_authority"))
        if platform is None:
            if persona_id is not None:
                raise CollectionError("This source is read without a persona.")
        elif persona_id is not None and persona_id != source.collection_account_id:
            raise CollectionError("This source is read by another persona.")
        persona_id = source.collection_account_id if platform is not None else None

        refusal = self._refusal(source, adapter)
        if refusal:
            raise SourceRefused(refusal)
        authority = (CollectionAuthorityService(self._c, self._adapters)
                     if requires else None)
        need = _attr(adapter, "authority_need")(source) if requires else None
        if (requires and actor_id is not None
                and authority.confirmer_runs(persona_id, source.id, actor_id,
                                             need=need)):
            raise AuthorityError(CONFIRMER_SENTENCE)

        # Taken AFTER the clearance check above, and it must stay there: if
        # a caller who is not cleared for this source could tell "busy"
        # from "no such source", the lock would be the existence oracle
        # that check closed.
        held = self._c.execute(
            "SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
            (_poll_lock_key(source_id),)).fetchone()[0]
        if not held:
            raise CollectionBusy(
                "this source is already being polled by another runner; "
                "nothing was done")
        try:
            gate = None
            persona_row = None
            if persona_id is not None:
                gate = PersonaGate(
                    self._c, persona_id, actor_id=actor_id,
                    clearance=clearance, purpose="poll", source_id=source.id,
                    need=need, platform=platform, needs_secret=True,
                    needs_browser_identity=bool(_attr(adapter, "persona_http")),
                    min_gap_s=float(_attr(adapter, "persona_min_gap_s") or 0),
                    sleep=self._sleep, adapter=adapter)
                persona_row = gate.check()
                gate.lock()
            try:
                if gate is not None:
                    gate.window()
                return self._poll(source, adapter, actor_id=actor_id,
                                  watch_id=watch_id, persona_row=persona_row,
                                  gate=gate, need=need, authority=authority)
            finally:
                if gate is not None:
                    gate.release()
        finally:
            # A session lock outlives the statement that took it, so an
            # exception escaping the poll -- the persist handler re-raises
            # one on purpose -- would otherwise strand the lock for the life
            # of the connection, and this source would be unpollable until
            # the process that held it exited.
            #
            # Guarded because this is SQL in a bare `finally`. When the
            # CONNECTION is what failed, this statement raises too, and an
            # exception from a `finally` REPLACES the one unwinding through
            # it: the caller would read an OperationalError from
            # pg_advisory_unlock and never see the defect that actually
            # ended the poll. Swallowing is right here: a session lock
            # lives and dies with its session, so a connection too broken
            # to run this has already released the lock by dying. Logged
            # rather than silent, because a healthy connection that refuses
            # the unlock would mean the lock really is stranded.
            try:
                self._c.execute(
                    "SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                    (_poll_lock_key(source_id),))
            except Exception:  # noqa: BLE001 - must not mask the real failure
                import logging

                logging.getLogger(__name__).warning(
                    "advisory unlock failed for source %s; if the connection "
                    "is still usable the poll lock is stranded until this "
                    "process exits", source_id, exc_info=True)

    def _resume_point(self, source: SourceRow) -> tuple[dict, str | None]:
        """The input cursor and etag: the latest FINISHED run's, never a
        run started before `cursor_reset_at`. Every finished run stores the
        cursor to resume from, so the latest one always holds the resume
        point. Read after the lock, so two polls never read the same one."""
        row = self._c.execute(
            """SELECT cursor, etag FROM collect.collection_run
                WHERE source_id = %s AND status <> 'RUNNING'
                  AND (%s::timestamptz IS NULL OR started_at > %s)
                ORDER BY started_at DESC NULLS LAST, id DESC LIMIT 1""",
            (source.id, source.cursor_reset_at,
             source.cursor_reset_at)).fetchone()
        if row is None:
            return {}, None
        return dict(row[0] or {}), row[1]

    def _poll(self, source: SourceRow, adapter, *, actor_id: UUID | None,
              watch_id: UUID | None, persona_row: dict | None,
              gate, need: str | None, authority) -> RunResult:
        """Steps 6 to 17 of run_once, with the source (and persona) locked."""
        from noctornal_api.collection_authority import AuthorityMissing
        from noctornal_api.collection_context import PersonaContext, RunContext

        requires = bool(_attr(adapter, "requires_authority"))
        persona_id = persona_row["id"] if persona_row else None
        input_cursor, previous_etag = self._resume_point(source)
        if persona_row is not None:
            exit_profile = persona_row["egress_profile_id"]
        elif requires:
            exit_profile = source.egress_profile_id
        else:
            # The passive default: its id is the egress proxy's to know, and
            # a passive run records NULL, which is what the proxy's run
            # check requires of one (2026-09-24).
            exit_profile = None
        run_id = self._c.execute(
            """INSERT INTO collect.collection_run
                   (source_id, watch_id, collection_account_id,
                    egress_profile_id, status, parser_version, started_at,
                    cursor, requested_by)
               VALUES (%s, %s, %s, %s, 'RUNNING', %s, clock_timestamp(), %s,
                       %s) RETURNING id""",
            (source.id, watch_id, persona_id, exit_profile,
             str(_attr(adapter, "version")), Jsonb(input_cursor),
             actor_id)).fetchone()[0]
        result = RunResult(run_id=run_id)
        notes: list[str] = []
        state = {"requests": [], "raw_keys": []}

        try:
            with contextlib.ExitStack() as stack:
                live = None
                try:
                    if requires:
                        live = authority.require(persona_id=persona_id,
                                                 source_id=source.id, need=need)
                        self._c.execute(
                            """UPDATE collect.collection_run
                                  SET authority_id = %s, authority_target_id = %s
                                WHERE id = %s""",
                            (live.authority_id, live.target_id, run_id))
                    _attr(adapter, "plan")(self._c, source, persona_row)
                    route = _route_for_source(self._c, source, persona_row,
                                              adapter=adapter, run_id=run_id)
                except AuthorityMissing as exc:
                    return self._blocked(result, source, "AuthorityMissing",
                                         str(exc), state, notes, adapter,
                                         persona_id)
                except SourceBlocked as exc:
                    return self._blocked(result, source, "SourceBlocked",
                                         str(exc), state, notes, adapter,
                                         persona_id)
                except EgressUnavailable as exc:
                    return self._blocked(result, source, "EgressUnavailable",
                                         str(exc), state, notes, adapter,
                                         persona_id)
                stack.enter_context(_route_secret(route))
                if requires and not route.proxied:
                    notes.append(EGRESS_DIRECT_NOTE)
                if not requires:
                    self._limiter.wait(source.id, source.max_rps)
                lease = None
                if gate is not None:
                    try:
                        lease = stack.enter_context(gate.lease(run_id=run_id))
                    except PersonaUnavailable as exc:
                        return self._blocked(result, source,
                                             "PersonaUnavailable", str(exc),
                                             state, notes, adapter, persona_id)
                context = None
                if requires:
                    persona_ctx = None
                    if persona_row is not None:
                        persona_ctx = PersonaContext(
                            persona_id=persona_id,
                            handle=persona_row["handle"],
                            platform=persona_row["platform"],
                            platform_uid=persona_row["platform_uid"],
                            fingerprint=dict(persona_row["fingerprint"] or {}),
                            authority=live, route=route, lease=lease)
                    context = RunContext(
                        source=source, run_id=run_id, adapter=adapter,
                        route=route, persona=persona_ctx,
                        fetcher=self._fetcher, limiter=self._limiter)
                try:
                    fetched = self._fetch(adapter, source, context, route,
                                          input_cursor, previous_etag)
                except RateLimited as exc:
                    until = record_outcome(self._c, persona_id=persona_id,
                                           source_id=source.id, run_id=run_id,
                                           exc=exc, adapter=adapter)
                    self._capture(context, state, notes)
                    floor = datetime.now(timezone.utc) + timedelta(
                        seconds=exc.retry_after_s * 1.1 + random.uniform(5, 30))
                    self._finish(result, source, status="RATE_LIMITED",
                                 error_class="RateLimited", detail=str(exc),
                                 state=state, notes=notes, count_failure=False,
                                 next_due_floor=max(floor, until or floor))
                    return self._settled(adapter, source, persona_id, result)
                except PersonaSuspended as exc:
                    record_outcome(self._c, persona_id=persona_id,
                                   source_id=source.id, run_id=run_id,
                                   exc=exc, adapter=adapter)
                    self._capture(context, state, notes)
                    return self._blocked(result, source, "PersonaSuspended",
                                         str(exc), state, notes, adapter,
                                         persona_id,
                                         blocked=SUSPENDED_SOURCE_SENTENCE)
                except (SourceBlocked, EgressUnavailable) as exc:
                    self._capture(context, state, notes)
                    return self._blocked(result, source, type(exc).__name__,
                                         str(exc), state, notes, adapter,
                                         persona_id)
                except (RouteUnavailable, DestinationRefused) as exc:
                    # docs/20 section 9: a route refusal on any poll, RSS
                    # included, is BLOCKED, never a failure counted against
                    # a feed's health (2026-09-24).
                    self._capture(context, state, notes)
                    return self._blocked(result, source, "EgressUnavailable",
                                         redact(str(exc)), state, notes,
                                         adapter, persona_id)
                except WorkAbandoned as exc:
                    record_outcome(self._c, persona_id=persona_id,
                                   source_id=source.id, run_id=run_id,
                                   exc=exc, adapter=adapter)
                    self._capture(context, state, notes)
                    self._finish(result, source, status="FAILED",
                                 error_class="WorkAbandoned", detail=str(exc),
                                 state=state, notes=notes, count_failure=True)
                    return self._settled(adapter, source, persona_id, result)
                except Exception as exc:  # noqa: BLE001 - every failure is a row
                    self._capture(context, state, notes)
                    self._finish(result, source, status="FAILED",
                                 error_class=type(exc).__name__,
                                 detail=self._failure_text(exc, requires),
                                 state=state, notes=notes, count_failure=True)
                    return self._settled(adapter, source, persona_id, result)
                self._capture(context, state, notes)
                if fetched.secret_update and lease is not None:
                    # As soon as fetch returns, so a credential the platform
                    # moved is kept even when the persist then fails.
                    lease.reseal(fetched.secret_update)
                return self._persist_or_fail(source, adapter, fetched, result,
                                             state, notes, input_cursor,
                                             persona_id, watch_id)
        except BaseException as exc:
            # Anything that escaped the outcome handling above (the persist
            # failure re-raises on purpose) has already finished its row;
            # a failure before the fetch that did not is finished here, so
            # no run is stranded at RUNNING. Guarded, because a connection
            # that failed would raise again here and replace the real error.
            try:
                still = self._c.execute(
                    "SELECT status FROM collect.collection_run WHERE id = %s",
                    (run_id,)).fetchone()
                if still is not None and still[0] == "RUNNING":
                    self._finish(result, source, status="FAILED",
                                 error_class=type(exc).__name__,
                                 detail=self._failure_text(exc, requires),
                                 state=state, notes=notes, count_failure=True)
                    self._settled(adapter, source, persona_id, result)
            except Exception:  # noqa: BLE001 - must not mask the real failure
                import logging

                logging.getLogger(__name__).warning(
                    "could not finish run %s after a failure", run_id,
                    exc_info=True)
            raise

    def _fetch(self, adapter, source: SourceRow, context, route,
               input_cursor: dict, previous_etag: str | None) -> FetchResult:
        """The adapter's fetch. An authority adapter gets its RunContext
        (and the previous run's etag); RSS is called as it always was, with
        its route. The context's shared deadline is entered for the fetch
        and exited when it ends."""
        fetch_fn = _attr(adapter, "fetch")
        if context is None:
            fetched = fetch_fn(base_url=source.base_url,
                               cursor=dict(input_cursor), etag=None,
                               context=None, route=route)
        else:
            with context:
                fetched = fetch_fn(base_url=source.base_url,
                                   cursor=dict(input_cursor),
                                   etag=previous_etag, context=context,
                                   route=route)
        if not isinstance(fetched, FetchResult):
            raise CollectionError("the adapter returned no FetchResult")
        return fetched

    @staticmethod
    def _failure_text(exc: BaseException, requires: bool) -> str:
        """What a FAILED run stores. For an authority adapter only this
        codebase's own sentences are stored: a library's text never reaches
        a row (it can carry a session or an exit's address). Redacted
        either way, because a persona's password lands in an HTTP error
        body far more often than anybody expects."""
        if requires and not isinstance(exc, CollectionError):
            return f"The adapter failed with {type(exc).__name__}."
        return redact(str(exc))[:2000]

    @staticmethod
    def _capture(context, state: dict, notes: list[str]) -> None:
        """The RunContext's request log and budget notes onto the run."""
        if context is None:
            return
        state["requests"] = context.logged()
        for note in context.notes():
            if note not in notes:
                notes.append(note)

    def _finish(self, result: RunResult, source: SourceRow, *, status: str,
                error_class: str | None, detail: str | None, state: dict,
                notes: list[str], count_failure: bool,
                blocked_reason: str | None = None,
                next_due_floor: datetime | None = None) -> None:
        """Finalise a run that did not persist: the row (with its request
        log, once), the source, the schedule. The request log is written on
        EVERY outcome, so the custody record never depends on success."""
        detail = redact(detail or "")[:2000] or None
        self._c.execute(
            """UPDATE collect.collection_run
                  SET status = %s, finished_at = now(), error_class = %s,
                      error_detail = %s, requests = %s, notes = %s
                WHERE id = %s""",
            (status, error_class, detail,
             Jsonb(state["requests"][:MAX_REQUEST_LOG]), notes[:MAX_NOTES],
             result.run_id))
        if blocked_reason is not None:
            self._c.execute(
                """UPDATE collect.source SET blocked_reason = %s,
                          blocked_at = now() WHERE id = %s""",
                (redact(blocked_reason)[:2000], source.id))
        if count_failure:
            self._record_failure(source.id, error_class or "Error")
        # Rescheduled on failure too. A source that only reschedules on
        # success is one that retries as fast as the scheduler runs the
        # moment it breaks -- which is a hammering pattern aimed at a site
        # that has just started refusing us.
        when = self._reschedule(source.id)
        if next_due_floor is not None and next_due_floor > when:
            self._c.execute(
                "UPDATE collect.source SET next_due_at = %s WHERE id = %s",
                (next_due_floor, source.id))
        result.status = status
        result.error = detail
        result.notes = list(notes[:MAX_NOTES])
        result.blocked_reason = (redact(blocked_reason)[:2000]
                                 if blocked_reason else None)

    def _blocked(self, result: RunResult, source: SourceRow, error_class: str,
                 sentence: str, state: dict, notes: list[str], adapter,
                 persona_id, *, blocked: str | None = None) -> RunResult:
        """A BLOCKED run: the attempt happened and could not read. The
        source carries the reason, no failure is counted, and the run keeps
        the input cursor (it stores none of its own)."""
        self._finish(result, source, status="BLOCKED", error_class=error_class,
                     detail=sentence, state=state, notes=notes,
                     count_failure=False, blocked_reason=blocked or sentence)
        return self._settled(adapter, source, persona_id, result)

    def _settled(self, adapter, source: SourceRow, persona_id,
                 result: RunResult) -> RunResult:
        """adapter.settle, once per outcome that wrote a run row, after the
        run is final and the source rescheduled, in its own transaction.
        Its exception is logged by class name and never changes the run."""
        try:
            with self._c.transaction():
                _attr(adapter, "settle")(
                    self._c, source_id=source.id, persona_id=persona_id,
                    run_id=result.run_id, status=result.status,
                    error=result.error)
        except Exception as exc:  # noqa: BLE001 - never changes the run
            import logging

            logging.getLogger(__name__).warning(
                "adapter %s settle raised %s", _attr(adapter, "key"),
                type(exc).__name__)
        return result

    def _persist_or_fail(self, source: SourceRow, adapter,
                         fetched: FetchResult, result: RunResult, state: dict,
                         notes: list[str], input_cursor: dict,
                         persona_id, watch_id) -> RunResult:
        """Step 14, and its failure. Everything after the fetch is inside
        a handler for the same reason `analytics_runs` CR9 is: the run row
        was INSERTed 'RUNNING' on an autocommit connection, so it is
        already committed and survives whatever unwinds above it.

        Re-raised, not swallowed: a fetch failure is an expected outcome
        (the site is down) and returns a result; a failure to persist what
        was fetched is a defect, and the caller must not be told the poll
        succeeded. A cursor over its cap is the adapter's defect and is
        recorded, not raised."""
        try:
            self._persist(source, adapter, fetched, result, state, notes,
                          input_cursor, persona_id, watch_id)
        except Exception as exc:
            for key in list(state["raw_keys"]):
                self._delete_unused_raw(key)
            result.items_new = 0
            result.items_deleted = 0
            result.watch_hits = 0
            if isinstance(exc, CursorTooLarge):
                self._finish(result, source, status="FAILED",
                             error_class="CursorTooLarge", detail=str(exc),
                             state=state, notes=notes, count_failure=True)
                return self._settled(adapter, source, persona_id, result)
            self._finish(result, source, status="FAILED",
                         error_class=type(exc).__name__,
                         detail=f"persist: {redact(str(exc))[:1990]}",
                         state=state, notes=notes, count_failure=True)
            self._settled(adapter, source, persona_id, result)
            raise
        return self._settled(adapter, source, persona_id, result)

    def _persist(self, source: SourceRow, adapter, fetched: FetchResult,
                 result: RunResult, state: dict, notes: list[str],
                 input_cursor: dict, persona_id, watch_id) -> None:
        """ONE transaction: a savepoint per item (validate, store, raw
        markup, commit_item, watch matching), then deletions, the adapter's
        per-run commit, the run row, the source and the schedule. A
        database refusal inside one item rolls back only that item and
        becomes ITEM_SKIPPED naming its id, so no single post, side-table
        CHECK or repeated watch hit can wedge a source."""
        from noctornal_api.retention import RetentionService

        items = list(fetched.items or [])
        result.items_seen = len(items)
        warnings = [w for w in (fetched.warnings or [])
                    if isinstance(w, RunWarning) and w.kind in WARNING_KINDS]
        clocked = bool(_attr(adapter, "retention_clock"))
        default_category = _attr(adapter, "default_category") or "FORUM_POST"
        keeps_raw = bool(_attr(adapter, "keeps_raw"))
        commit_item = _attr(adapter, "commit_item")
        rules = RetentionService(self._c).rules() if clocked else {}
        categories = document_categories()
        stored: dict[str, UUID] = {}
        existing: dict[str, UUID] = {}
        naive = 0
        unclocked: set[str] = set()
        raw_gaps = {"unconfigured": 0, "refused": 0}
        broken: dict[tuple[UUID, str], str] = {}
        with self._c.transaction():
            watches = self._watches(source.id)
            for item in items:
                put_key = None
                gap = None
                try:
                    with self._c.transaction():
                        clean, naive_time = self._validate_item(
                            item, adapter=adapter, categories=categories)
                        category = clean.category or default_category
                        retain_days = None
                        if clocked:
                            rule = rules.get(category)
                            if rule is not None:
                                retain_days = rule.retain_days
                        document_id, inserted = self._store_document(
                            source.id, result.run_id, watch_id, clean,
                            classification=source.classification,
                            category=category, retain_days=retain_days)
                        if inserted and keeps_raw and clean.raw_html:
                            put_key, gap = self._attach_raw(
                                source.id, document_id, clean.raw_html)
                            if put_key is not None:
                                # Listed at once, so a failure that ends the
                                # whole persist deletes this object too.
                                state["raw_keys"].append(put_key)
                        commit_item(self._c, source_id=source.id,
                                    run_id=result.run_id,
                                    persona_id=persona_id, item=clean,
                                    document_id=document_id,
                                    inserted=inserted)
                        hits = self._match_watches(
                            source.id, result.run_id, clean, watches, broken)
                except _ItemInvalid as exc:
                    warnings.append(RunWarning(ITEM_SKIPPED, (
                        f"Item {_item_label(item)} was skipped: {exc}")))
                    continue
                except (psycopg.DataError, psycopg.IntegrityError) as exc:
                    if put_key is not None:
                        state["raw_keys"].remove(put_key)
                        self._delete_unused_raw(put_key)
                    warnings.append(RunWarning(ITEM_SKIPPED, (
                        f"Item {_item_label(item)} was skipped: the database "
                        f"refused it ({type(exc).__name__}).")))
                    continue
                # Counted only once the item's savepoint is released: an item
                # that rolled back contributes nothing to the run's numbers.
                if inserted:
                    stored[clean.external_id] = document_id
                    result.items_new += 1
                else:
                    existing[clean.external_id] = document_id
                if gap:
                    raw_gaps[gap] += 1
                if clocked and retain_days is None:
                    unclocked.add(category)
                result.watch_hits += hits
                if naive_time:
                    naive += 1
            result.items_deleted = self._mark_deleted(
                source.id, fetched.deleted_external_ids or [])
            _attr(adapter, "commit")(
                self._c, source_id=source.id, run_id=result.run_id,
                persona_id=persona_id, stored=stored, existing=existing,
                fetched=fetched)
            if result.watch_hits:
                self._c.execute(
                    "UPDATE collect.watch SET last_hit_at = now() "
                    "WHERE source_id = %s", (source.id,))
            warnings.extend(RunWarning(WATCH_PATTERN, (
                f"watch {wid} has a regex that will not compile and therefore "
                f"matches nothing: {reason} (pattern {redact(pat)[:120]!r})"))
                for (wid, pat), reason in broken.items())
            if raw_gaps["unconfigured"]:
                n = raw_gaps["unconfigured"]
                warnings.append(RunWarning(RAW_NOT_KEPT, (
                    f"Raw markup was not kept for "
                    f"{count_of(n, 'document', 'documents')}: object storage "
                    f"for collected pages is not configured, so "
                    f"{agree(n, 'it', 'they')} cannot be re-parsed.")))
            if raw_gaps["refused"]:
                n = raw_gaps["refused"]
                warnings.append(RunWarning(RAW_NOT_KEPT, (
                    f"Raw markup was not kept for "
                    f"{count_of(n, 'document', 'documents')}: the object "
                    f"store refused it, so {agree(n, 'it', 'they')} cannot "
                    f"be re-parsed.")))
            for category in sorted(unclocked):
                notes.append(f"No retention rule covers {category}, so these "
                             f"documents have no retention clock.")
            if naive:
                notes.append(
                    f"{count_of(naive, 'item', 'items')} carried a time with "
                    f"no zone, so {agree(naive, 'its', 'their')} posting time "
                    f"was not stored.")
            partial = [w for w in warnings if WARNING_KINDS[w.kind][1]]
            notes.extend(w.text for w in warnings
                         if not WARNING_KINDS[w.kind][1] and w.text not in notes)
            holds = any(WARNING_KINDS[w.kind][2] for w in warnings)
            cursor = fetched.cursor if isinstance(fetched.cursor, dict) else {}
            resume = input_cursor if (not cursor or holds) else cursor
            if len(json.dumps(resume, ensure_ascii=False, default=str)
                   .encode("utf-8")) > MAX_CURSOR_BYTES:
                raise CursorTooLarge(
                    "The adapter returned a reading position over 16 KiB, so "
                    "it was not stored and the next poll starts from the "
                    "previous one.")
            classes = {WARNING_KINDS[w.kind][0] for w in partial}
            error_class = next((c for c in _PARTIAL_ORDER if c in classes), None)
            result.warnings = [w.text for w in partial]
            result.notes = list(notes[:MAX_NOTES])
            result.status = "PARTIAL" if partial else "OK"
            self._c.execute(
                """UPDATE collect.collection_run
                      SET status = %s, finished_at = now(), items_seen = %s,
                          items_new = %s, items_deleted = %s, http_status = %s,
                          etag = %s, last_modified = %s, error_class = %s,
                          error_detail = %s, notes = %s, requests = %s,
                          cursor = %s
                    WHERE id = %s""",
                (result.status, result.items_seen, result.items_new,
                 result.items_deleted, fetched.http_status,
                 _capped(fetched.etag, 1000),
                 _capped(fetched.last_modified, 200), error_class,
                 "; ".join(result.warnings)[:2000] or None, result.notes,
                 Jsonb(state["requests"][:MAX_REQUEST_LOG]), Jsonb(resume),
                 result.run_id))
            drift = "ParserDrift" in classes
            self._c.execute(
                """UPDATE collect.source
                      SET last_ok_at = now(), blocked_reason = NULL,
                          blocked_at = NULL
                    WHERE id = %s""", (source.id,))
            if drift:
                # Two drifting polls read DEGRADED and put the source on the
                # unhealthy list: a parser that stopped matching is usually
                # the site changing its markup.
                self._record_failure(source.id, "ParserDrift")
            else:
                self._c.execute(
                    """UPDATE collect.source
                          SET consecutive_failures = 0, health = 'OK'
                        WHERE id = %s""", (source.id,))
            self._reschedule(source.id)

    def _validate_item(self, item: Item, *, adapter,
                       categories: tuple[str, ...]) -> tuple[Item, bool]:
        """The cleaned item, and whether its time had no zone. Anything
        the framework will not store is _ItemInvalid (ITEM_SKIPPED)."""
        external = item.external_id
        if not isinstance(external, str) or not external.strip():
            raise _ItemInvalid("it carries no id.")
        if "\x00" in external:
            raise _ItemInvalid("its id carries a NUL character.")
        if len(external) > 512:
            raise _ItemInvalid("its id is longer than 512 characters.")
        if _attr(adapter, "requires_authority") and not _NAMESPACED_ID.match(external):
            raise _ItemInvalid(
                "its id is not namespaced (for example post:123), so it "
                "could be taken for another kind of item.")
        if item.category is not None and item.category not in categories:
            raise _ItemInvalid("its category is not a document category.")
        if not isinstance(item.body, str):
            raise _ItemInvalid("its body is not text.")
        for name in ("title", "author_handle", "thread_ref", "parent_ref",
                     "author_uid", "url"):
            value = getattr(item, name)
            if value is not None and not isinstance(value, str):
                raise _ItemInvalid(f"its {name.replace('_', ' ')} is not text.")
        if item.raw_html is not None:
            if not isinstance(item.raw_html, (bytes, bytearray)):
                raise _ItemInvalid("its markup is not bytes.")
            if len(item.raw_html) > MAX_ITEM_RAW_BYTES:
                raise _ItemInvalid("its markup is larger than 1 MiB.")
        posted = item.posted_at
        naive = False
        if posted is not None:
            if not isinstance(posted, datetime):
                raise _ItemInvalid("its posting time is not a time.")
            if posted.tzinfo is None or posted.tzinfo.utcoffset(posted) is None:
                posted, naive = None, True
        clean = dataclasses.replace(
            item,
            external_id=_clean_text(external),
            url=_capped(_clean_text(item.url), 2048),
            title=_capped(_clean_text(item.title), 1000),
            body=_clean_text(item.body),
            author_handle=_capped(_clean_text(item.author_handle), 256),
            thread_ref=_capped(_clean_text(item.thread_ref), 512),
            parent_ref=_capped(_clean_text(item.parent_ref), 512),
            author_uid=_capped(_clean_text(item.author_uid), 512),
            posted_at=posted,
            raw_html=bytes(item.raw_html) if item.raw_html is not None else None)
        return clean, naive

    def _store_document(self, source_id: UUID, run_id: UUID,
                        watch_id: UUID | None, item: Item, *,
                        classification: str, category: str = "FORUM_POST",
                        retain_days: int | None = None) -> tuple[UUID, bool]:
        """Deduped on content hash, versioned rather than overwritten.

        An edited forum post is a NEW version, not a correction: what the
        actor said and what they later said instead are both facts, and
        overwriting loses the more interesting one.

        Since 2026-09-24 it returns (document id, inserted). The dedupe
        reads UNPURGED rows only, so a re-fetch of a purged post is a new
        capture with a new clock (the purge replaces the digest with one not
        derived from the content, docs/00 decision 74). A hit returns the
        latest version of that item and clears its deleted-upstream flag:
        the item is back.
        `retain_until` is set only from a retention rule's days.
        """
        digest = item.content_sha256
        hit = self._c.execute(
            """SELECT id FROM collect.document
                WHERE source_id = %s AND content_sha256 = %s
                  AND purged_at IS NULL LIMIT 1""",
            (source_id, digest)).fetchone()
        if hit:
            latest = self._c.execute(
                """SELECT id, is_deleted_upstream FROM collect.document
                    WHERE source_id = %s AND external_id = %s
                      AND purged_at IS NULL
                    ORDER BY version DESC LIMIT 1""",
                (source_id, item.external_id)).fetchone()
            document_id = latest[0] if latest else hit[0]
            if latest and latest[1]:
                self._c.execute(
                    "UPDATE collect.document SET is_deleted_upstream = false "
                    "WHERE id = %s", (document_id,))
            return document_id, False
        previous = self._c.execute(
            """SELECT id, version FROM collect.document
                WHERE source_id = %s AND external_id = %s
                ORDER BY version DESC LIMIT 1""",
            (source_id, item.external_id)).fetchone()
        row = self._c.execute(
            """INSERT INTO collect.document
                   (source_id, collection_run_id, watch_id, external_id,
                    external_url, thread_ref, parent_ref, author_handle,
                    author_uid, posted_at, title, body_text, content_sha256,
                    version, supersedes_id, classification, category,
                    retain_until)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                       %s, %s, %s, %s,
                       CASE WHEN %s::integer IS NULL THEN NULL
                            ELSE now() + make_interval(days => %s::integer) END)
               RETURNING id""",
            (source_id, run_id, watch_id, item.external_id, item.url,
             item.thread_ref, item.parent_ref, item.author_handle,
             item.author_uid, item.posted_at, item.title, item.body, digest,
             (previous[1] + 1) if previous else 1,
             previous[0] if previous else None, classification, category,
             retain_days, retain_days)).fetchone()
        return row[0], True

    def _attach_raw(self, source_id: UUID, document_id: UUID,
                    fragment: bytes) -> tuple[str | None, str | None]:
        """Put an item's scrubbed markup and point its new document at it:
        (key, None), or (None, 'unconfigured' | 'refused'). ONE order:
        the row was inserted with the key NULL, the
        object is put, then the key is written, all inside the item's
        savepoint, so a rollback leaves no row naming a missing object."""
        from noctornal_api.collection_context import _scrub_raw
        from noctornal_api.rawstore import document_raw_key

        store = self.raw_store
        if store is None:
            return None, "unconfigured"
        data = _scrub_raw(fragment)
        key = document_raw_key(source_id, data)
        try:
            store.put(key, data)
        except Exception:  # noqa: BLE001 - a refused put is a named gap
            import logging

            logging.getLogger(__name__).warning(
                "raw markup put refused for one document", exc_info=True)
            return None, "refused"
        self._c.execute(
            "UPDATE collect.document SET body_html_key = %s WHERE id = %s",
            (key, document_id))
        return key, None

    def _delete_unused_raw(self, key: str) -> None:
        """Best effort: delete a raw object this run put, unless a committed
        document still names it (identical fragments share a key within one
        source). A failed delete is one log line naming the key: an
        unreferenced object is the recorded residual (docs/17)."""
        used = self._c.execute(
            """SELECT 1 FROM collect.document
                WHERE body_html_key = %s AND purged_at IS NULL LIMIT 1""",
            (key,)).fetchone()
        if used is not None or self.raw_store is None:
            return
        try:
            self.raw_store.delete(key)
        except Exception:  # noqa: BLE001 - best effort, logged
            import logging

            logging.getLogger(__name__).warning(
                "could not delete unreferenced raw object %s", key)

    def _mark_deleted(self, source_id: UUID, ids: list[str]) -> int:
        """Flag the LATEST version of each item the site no longer shows.
        The body stays: deletions are intelligence (docs/04). A flag rather
        than a new version, because a copy of an unchanged body would
        collide with the content-hash dedupe."""
        wanted = sorted({_clean_text(i) for i in ids
                         if isinstance(i, str) and i.strip() and len(i) <= 512})
        if not wanted:
            return 0
        return self._c.execute(
            """UPDATE collect.document d
                  SET is_deleted_upstream = true
                WHERE d.id IN (
                        SELECT DISTINCT ON (x.external_id) x.id
                          FROM collect.document x
                         WHERE x.source_id = %s AND x.external_id = ANY(%s)
                         ORDER BY x.external_id, x.version DESC)
                  AND d.purged_at IS NULL AND NOT d.is_deleted_upstream""",
            (source_id, wanted[:5000])).rowcount

    def _watches(self, source_id: UUID) -> list[tuple]:
        return self._c.execute(
            """SELECT id, case_id, keywords, selector_watch, regexes,
                      priority, suppress_window_s
                 FROM collect.watch
                WHERE source_id = %s AND is_active""", (source_id,)).fetchall()

    def _match_watches(self, source_id: UUID, run_id: UUID, item: Item,
                       watches: list[tuple],
                       broken: dict[tuple[UUID, str], str]) -> int:
        """Keyword, selector and regex matching into `watch_hit`, for ONE
        item, inside its savepoint (2026-09-24).

        Suppression is applied HERE rather than at notification time,
        because docs/04 wants repeated hits on the same thread collapsed
        into one with a running count -- and a suppression that happens
        after the row is written is a suppression that still filled the
        table.

        Added: a selector equal to the item's author_uid records
        'author:<uid>', and each `meta['match_ids']` entry equal to a
        selector records '<label>:<id>'. The hit is written with ON
        CONFLICT DO NOTHING and counted only when a row went in, so a post
        re-fetched after its suppression window never raises a unique
        violation and never wedges the source. Purged documents are never
        matched. A broken pattern is reported once per run in `broken`.
        """
        haystack = f"{item.title or ''}\n{item.body}".lower()
        uid = (item.author_uid or "").strip()
        match_ids = item.meta.get("match_ids") if isinstance(item.meta, dict) else None
        typed = []
        if isinstance(match_ids, dict):
            typed = [(label, value.strip()) for label, value in match_ids.items()
                     if isinstance(label, str) and _MATCH_LABEL.match(label)
                     and isinstance(value, str) and value.strip()]
        hits = 0
        document = None
        for watch in watches:
            (watch_id, _case_id, keywords, selectors, regexes, priority,
             suppress) = watch
            matched: list[str] = []
            for needle in (keywords or []):
                if needle and needle.lower() in haystack:
                    matched.append(f"keyword:{needle}")
            for needle in (selectors or []):
                if needle and needle.lower() in haystack:
                    matched.append(f"selector:{needle}")
                exact = (needle or "").strip()
                if exact and uid and exact == uid:
                    matched.append(f"author:{uid}")
                for label, value in typed:
                    if exact and exact == value:
                        matched.append(f"{label}:{value}")
            for pattern in (regexes or []):
                try:
                    if pattern and re.search(pattern, haystack, re.I):
                        matched.append(f"regex:{pattern}")
                except re.error as exc:
                    # A watch with a broken pattern must not stop the other
                    # watches from matching, and must not be SILENT: a watch
                    # is a standing tasking, and swallowed it reads exactly
                    # like a quiet one. `redact` because an operator
                    # watching for a leaked credential puts that credential
                    # in the pattern, and this string is stored.
                    broken[(watch_id, pattern)] = redact(str(exc))[:200]
                    continue
            if not matched:
                continue
            if document is None:
                document = self._c.execute(
                    """SELECT id FROM collect.document
                        WHERE source_id = %s AND external_id = %s
                          AND purged_at IS NULL
                        ORDER BY version DESC LIMIT 1""",
                    (source_id, item.external_id)).fetchone()
                if document is None:
                    return hits
            if self._suppressed(watch_id, item.thread_ref
                                or item.external_id, suppress):
                continue
            inserted = self._c.execute(
                """INSERT INTO collect.watch_hit
                       (watch_id, document_id, matched_on, score)
                   VALUES (%s, %s, %s, %s)
                   ON CONFLICT (watch_id, document_id) DO NOTHING
                   RETURNING id""",
                # `score` is inverted from `priority`: docs/04 numbers
                # priority 1 as the most urgent, and a score wants the
                # opposite sense so ORDER BY score DESC is the queue.
                (watch_id, document[0], Json(matched),
                 10 - (priority or 3))).fetchone()
            if inserted is not None:
                hits += 1
        return hits

    def _suppressed(self, watch_id: UUID, thread: str | None,
                    window_s: int | None) -> bool:
        if not window_s or not thread:
            return False
        row = self._c.execute(
            """SELECT 1 FROM collect.watch_hit wh
                 JOIN collect.document d ON d.id = wh.document_id
                WHERE wh.watch_id = %s
                  AND coalesce(d.thread_ref, d.external_id) = %s
                  AND wh.created_at > now() - (%s || ' seconds')::interval
                LIMIT 1""", (watch_id, thread, window_s)).fetchone()
        return row is not None

    def _record_failure(self, source_id: UUID, error_class: str) -> None:
        """Parser health. docs/04 asks for drift alerting, and the signal is
        consecutive failures rather than a rate: a parser that broke this
        morning fails every time, and a rate over a week hides that."""
        self._c.execute(
            """UPDATE collect.source
                  SET consecutive_failures = consecutive_failures + 1,
                      health = CASE
                        WHEN consecutive_failures + 1 >= 5 THEN 'BROKEN'
                        WHEN consecutive_failures + 1 >= 2 THEN 'DEGRADED'
                        ELSE 'OK' END
                WHERE id = %s""", (source_id,))

    # -- sources ------------------------------------------------------------

    def sources(self, *, clearance: str | None) -> list[dict]:
        """Every source the caller may see, with who reads it, through which
        exit, its authority state and the refusal it would meet. A persona
        the caller may not see is not named."""
        from noctornal_api.collection_authority import CollectionAuthorityService

        rows = self._c.execute(
            f"""SELECT {_SOURCE_COLUMNS}, s.health, e.name
                  FROM collect.source s
                  LEFT JOIN collect.egress_profile e ON e.id = s.egress_profile_id
                 WHERE {_SOURCE_VISIBLE}
                 ORDER BY s.is_active DESC, s.name""",
            {"clearance": clearance}).fetchall()
        sources = [(_row_to_source(r), r[14], r[15]) for r in rows]
        personas = self._persona_rows(
            [s.collection_account_id for s, _h, _e in sources
             if s.collection_account_id], clearance=clearance)
        states = CollectionAuthorityService(self._c, self._adapters) \
            .states_for_sources([s.id for s, _h, _e in sources],
                                clearance=clearance)
        out = []
        for source, health, egress_name in sources:
            adapter = self._adapters.get(source.parser_key)
            requires = bool(adapter is not None
                            and _attr(adapter, "requires_authority"))
            out.append({
                "id": str(source.id), "kind": source.kind, "name": source.name,
                "base_url": source.base_url, "parser_key": source.parser_key,
                "classification": source.classification,
                "is_active": source.is_active, "health": health,
                "persona": _persona_ref(personas.get(source.collection_account_id)),
                "egress_profile": ({"id": str(source.egress_profile_id),
                                    "name": egress_name}
                                   if source.egress_profile_id else None),
                "requires_authority": requires,
                "authority": states.get(source.id) if requires else None,
                "blocked_reason": source.blocked_reason,
                "refusal": (self._refusal(source, adapter)
                            if adapter is not None else
                            "This source has no parser, so nothing polls it."
                            if not source.parser_key else
                            f"No parser in this build is called "
                            f"{source.parser_key}."),
            })
        return out

    def create_source(self, *, kind: str, name: str, base_url: str | None,
                      parser_key: str, classification: str,
                      default_reliability: str = "F",
                      poll_interval_s: int = 900, jitter_pct: int = 25,
                      max_rps: float = 0.2, parser_config: dict | None = None,
                      collection_account_id: UUID | None = None,
                      egress_profile_id: UUID | None = None,
                      actor_id: UUID, clearance: str,
                      ceiling_env=None) -> dict:
        """A new source. Every refusal is a sentence
        (CollectionError, a 400), except a persona or exit the caller may
        not see (CollectionNotFound, a 404). A source is created with no
        schedule, so it is due at once; a forum or Telegram source then
        waits on its authority before anything is read."""
        from noctornal_api.collection_authority import (
            AUTHORITY_KINDS,
            source_ceiling,
        )
        from noctornal_api.security.access import (
            AccessResolutionError,
            tlp_from_name,
        )

        adapter = self._adapters.get(parser_key)
        if adapter is None:
            raise CollectionError(f"No parser in this build is called {parser_key}.")
        if kind not in SOURCE_KINDS:
            raise CollectionError(f"{kind} is not a source kind.")
        name = (name or "").strip()
        if not 3 <= len(name) <= 200:
            raise CollectionError("A source's name is between 3 and 200 characters.")
        config = dict(parser_config or {})
        if base_url is not None:
            problem = _address_problem(base_url)
            if problem:
                raise CollectionError(problem)
        problems = (list(_attr(adapter, "validate_source")(base_url, config))
                    + list(_attr(adapter, "validate_config")(config)))
        if problems:
            raise CollectionError(" ".join(problems))
        import json as _json
        if len(_json.dumps(config).encode("utf-8")) > 16000:
            raise CollectionError("The parser settings are larger than 16 KiB.")
        requires = bool(_attr(adapter, "requires_authority"))
        kinds = frozenset(_attr(adapter, "source_kinds") or ())
        if kinds and kind not in kinds:
            raise CollectionError(
                f"The {parser_key} parser does not read {kind} sources.")
        if kind in AUTHORITY_KINDS and not requires:
            raise CollectionError(
                "A forum or Telegram source needs a parser that enforces "
                "collection authority.")
        minimum = int(_attr(adapter, "min_interval_s") or 0)
        if poll_interval_s < minimum:
            raise CollectionError(
                f"This parser polls a source at most once every "
                f"{count_of(minimum, 'second', 'seconds')}.")
        cap = float(_attr(adapter, "max_rps_cap") or 1.0)
        if not 0 < max_rps <= cap:
            raise CollectionError(
                f"This parser sends at most {cap:g} requests per second.")
        if not 0 <= jitter_pct <= 90:
            raise CollectionError("The jitter is between 0 and 90 percent.")
        try:
            label = tlp_from_name(classification)
            ceiling_self = tlp_from_name(clearance)
        except AccessResolutionError as exc:
            raise CollectionError(f"{classification} is not a TLP name.") from exc
        if label > ceiling_self:
            raise CollectionError(
                f"You cannot label a source above your own TLP:{clearance} "
                f"clearance.")
        if requires:
            declared, _sentence = source_ceiling(kind, ceiling_env)
            if declared is not None and label > tlp_from_name(declared):
                raise CollectionError(
                    f"This source would be labelled TLP:{classification}, "
                    f"above the TLP:{declared} ceiling declared for {kind} "
                    f"sources, so it would never be read by the collector. "
                    f"Collect it by hand into its case instead.")
        self._check_binding(adapter, collection_account_id, egress_profile_id,
                            clearance=clearance)
        row = self._c.execute(
            """INSERT INTO collect.source
                   (kind, name, base_url, default_reliability, classification,
                    poll_interval_s, jitter_pct, max_rps, parser_key,
                    parser_config, collection_account_id, egress_profile_id)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (kind, name, base_url, default_reliability, classification,
             poll_interval_s, jitter_pct, max_rps, parser_key, Jsonb(config),
             collection_account_id, egress_profile_id)).fetchone()
        self._audit(actor_id, "SOURCE_CREATED", "source", row[0],
                    {"kind": kind, "parser_key": parser_key,
                     "classification": classification})
        return {"id": str(row[0]), "kind": kind, "name": name,
                "parser_key": parser_key, "classification": classification,
                "requires_authority": requires}

    def _check_binding(self, adapter, persona_id: UUID | None,
                       egress_profile_id: UUID | None, *,
                       clearance: str | None) -> None:
        """The binding rules create_source and bind_source share: a
        persona of the adapter's platform, visible, not burnt, with no exit
        beside it; or, for a persona-less authority
        adapter, an active exit no persona holds; and no binding at all for
        a parser that needs no authority (RSS reads through the passive
        default)."""
        platform = _attr(adapter, "persona_platform")
        requires = bool(_attr(adapter, "requires_authority"))
        if persona_id is not None:
            if platform is None:
                raise CollectionError("This source is read without a persona.")
            if egress_profile_id is not None:
                raise CollectionError(
                    "A persona reads through its own egress profile.")
            row = self._c.execute(
                f"""SELECT a.platform::text, a.status
                      FROM collect.collection_account a
                     WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}""",
                {"id": persona_id, "clearance": clearance}).fetchone()
            if row is None:
                raise CollectionNotFound(
                    "no such persona, or it is above your clearance")
            if row[0] != platform:
                raise CollectionError(
                    f"This source is read by a {_attr(adapter, 'key')} "
                    f"adapter, which needs a {platform} persona.")
            if row[1] == BURNED:
                raise CollectionError(
                    "This persona is burnt and must not be used again.")
            return
        if platform is not None:
            raise CollectionError("This source is read by a persona.")
        if egress_profile_id is None:
            return
        if not requires:
            raise CollectionError(
                "RSS sources read through the passive default egress profile.")
        profile = self._c.execute(
            "SELECT is_active FROM collect.egress_profile WHERE id = %s",
            (egress_profile_id,)).fetchone()
        if profile is None or not profile[0]:
            raise CollectionNotFound("no such egress profile, or it is retired")
        carried = self._c.execute(
            "SELECT 1 FROM collect.collection_account "
            "WHERE egress_profile_id = %s LIMIT 1",
            (egress_profile_id,)).fetchone()
        if carried is not None:
            raise CollectionError(
                "This egress profile carries a persona. A public read and a "
                "persona must not share an exit.")

    def bind_source(self, source_id: UUID, *, persona_id: UUID | None,
                    egress_profile_id: UUID | None, reason: str,
                    reset_cursor: bool, actor_id: UUID,
                    clearance: str | None) -> dict:
        """Who reads a source and through which exit.
        Authority targets recorded for the old binding stop covering the
        source at once (require() reads the current binding), and the
        answer says so."""
        reason = (reason or "").strip()
        if not 5 <= len(reason) <= 500:
            raise CollectionError(
                "A binding change has to say why, in 5 to 500 characters.")
        source = _source_row(self._c, source_id, clearance)
        adapter = self._adapters.get(source.parser_key)
        if adapter is None:
            raise CollectionError(
                f"No parser in this build is called {source.parser_key}.")
        self._check_binding(adapter, persona_id, egress_profile_id,
                            clearance=clearance)
        self._c.execute(
            """UPDATE collect.source
                  SET collection_account_id = %s, egress_profile_id = %s,
                      cursor_reset_at = CASE WHEN %s THEN clock_timestamp()
                                             ELSE cursor_reset_at END
                WHERE id = %s""",
            (persona_id, egress_profile_id, bool(reset_cursor), source_id))
        self._audit(actor_id, "SOURCE_BINDING_CHANGED", "source", source_id,
                    {"from_persona": _str(source.collection_account_id),
                     "to_persona": _str(persona_id),
                     "from_egress": _str(source.egress_profile_id),
                     "to_egress": _str(egress_profile_id),
                     "reason": reason, "reset_cursor": bool(reset_cursor)})
        requires = bool(_attr(adapter, "requires_authority"))
        return {"source_id": str(source_id),
                "persona_id": _str(persona_id),
                "egress_profile_id": _str(egress_profile_id),
                "reset_cursor": bool(reset_cursor),
                "notice": ("The new binding needs its own confirmed authority "
                           "for this source before the next poll."
                           if requires else None)}

    def set_source_active(self, source_id: UUID, *, active: bool, reason: str,
                          actor_id: UUID, clearance: str | None) -> dict:
        """Deactivate or activate a source, with a reason, audited. There is
        no route that edits a source's address, kind or parser."""
        reason = (reason or "").strip()
        if not 5 <= len(reason) <= 500:
            raise CollectionError(
                "A source's activation has to say why, in 5 to 500 characters.")
        _source_row(self._c, source_id, clearance)
        self._c.execute(
            "UPDATE collect.source SET is_active = %s WHERE id = %s",
            (bool(active), source_id))
        self._audit(actor_id,
                    "SOURCE_ACTIVATED" if active else "SOURCE_DEACTIVATED",
                    "source", source_id, {"reason": reason})
        return {"source_id": str(source_id), "is_active": bool(active)}

    # -- health and history -------------------------------------------------

    def unhealthy_sources(self, *, clearance: str | None = None) -> list[dict]:
        """Sources that have actually FAILED, not sources nobody has polled.

        `WHERE health <> 'OK'` looked right and was not: a source that has
        never run carries the default health with zero failures, so every
        newly added source appeared on the alert list next to a parser that
        genuinely broke. Never-polled sources are reported separately.

        Since 2026-09-24 a source whose last poll was BLOCKED is listed
        too, with its reason: nothing is being read from it, and the reason
        is what somebody has to act on.

        `clearance` as in `due_sources`: None is the worker and filters
        nothing; a TLP name hides sources labelled above it.
        """
        rows = self._c.execute(
            """SELECT id, name, health, consecutive_failures, last_ok_at,
                      blocked_reason
                 FROM collect.source
                WHERE is_active
                  AND (consecutive_failures > 0
                       OR (health <> 'OK' AND last_ok_at IS NOT NULL)
                       OR blocked_reason IS NOT NULL)
                  AND (%s::core.tlp IS NULL OR classification <= %s::core.tlp)
                ORDER BY consecutive_failures DESC""",
            (clearance, clearance)).fetchall()
        return [{"id": str(r[0]), "name": r[1], "health": r[2],
                 "consecutive_failures": r[3],
                 "last_ok_at": r[4].isoformat() if r[4] else None,
                 "blocked_reason": r[5],
                 "note": "a parser that stopped matching is usually the site "
                         "changing its markup, and it fails silently unless "
                         "somebody is watching this"}
                for r in rows]

    def never_polled_sources(self, *,
                             clearance: str | None = None) -> list[dict]:
        """Active, configured, and never successfully collected from.

        Not an error and not healthy either. A source somebody added and
        nobody ever ran is the quiet way a collection plan turns out to
        have been aspirational.

        `clearance` as in `due_sources`: None filters nothing, a TLP name
        hides sources labelled above it.
        """
        rows = self._c.execute(
            """SELECT id, name, kind, created_at, consecutive_failures
                 FROM collect.source
                WHERE is_active AND last_ok_at IS NULL
                  AND consecutive_failures = 0
                  AND (%s::core.tlp IS NULL OR classification <= %s::core.tlp)
                ORDER BY created_at""",
            (clearance, clearance)).fetchall()
        return [{"id": str(r[0]), "name": r[1], "kind": r[2],
                 "created_at": r[3].isoformat() if r[3] else None,
                 "consecutive_failures": r[4],
                 "note": "configured but never collected from"}
                for r in rows]

    _RUN_COLUMNS = (
        "r.id, r.source_id, r.started_at, r.finished_at, r.status::text, "
        "r.items_seen, r.items_new, r.http_status, r.error_class, "
        "r.error_detail, s.name, r.collection_account_id, r.egress_profile_id, "
        "CASE WHEN %(clearance)s::core.tlp IS NULL "
        "OR ca.classification <= %(clearance)s::core.tlp "
        "THEN r.authority_id END, "
        "r.requested_by, u.display_name, r.items_deleted, r.notes, "
        "jsonb_array_length(r.requests)")

    _RUN_FROM = (
        "FROM collect.collection_run r "
        "JOIN collect.source s ON s.id = r.source_id "
        "LEFT JOIN collect.collection_authority ca ON ca.id = r.authority_id "
        "LEFT JOIN iam.app_user u ON u.id = r.requested_by")

    def _run_dict(self, r, personas: dict) -> dict:
        return {"id": str(r[0]), "source_id": str(r[1]),
                "started_at": r[2].isoformat() if r[2] else None,
                "finished_at": r[3].isoformat() if r[3] else None,
                "status": r[4], "items_seen": r[5], "items_new": r[6],
                "http_status": r[7], "error_class": r[8], "error_detail": r[9],
                "source_name": r[10],
                "persona": _persona_ref(personas.get(r[11])),
                "egress_profile_id": _str(r[12]),
                "authority_id": _str(r[13]),
                "requested_by": _str(r[14]),
                "requested_by_name": r[15] if r[14] else "the system",
                "items_deleted": r[16], "notes": list(r[17] or []),
                "request_count": r[18]}

    def runs(self, *, source_id: UUID | None = None, limit: int = 50,
             clearance: str | None = None) -> list[dict]:
        """Recent polls, successes and failures alike, newest first.

        Joined to the source and filtered by the caller's ceiling on its
        label (2026-09-02): a run names its source, and a failed run's
        error quotes the fetch. An explicit `source_id` above the ceiling
        is answered with an empty list, NOT refused, because an empty run
        history means "no polls matched" whether the source was never
        polled, is above the ceiling or is not a source at all, and the
        three are identical to the caller.

        Since 2026-09-24, ordered by the start time with runs whose start
        was never recorded last (the index collection_run_started_idx),
        and each row says who asked for it (the system for the cron), the
        persona (unnamed when the caller may not see it), the exit, the
        authority (only when that authority is within the caller's
        clearance, so a RED authority over an AMBER source leaks no id) and
        how many requests its custody log holds.
        """
        rows = self._c.execute(
            f"""SELECT {self._RUN_COLUMNS} {self._RUN_FROM}
                 WHERE (%(source)s::uuid IS NULL OR r.source_id = %(source)s)
                   AND {_SOURCE_VISIBLE}
                 ORDER BY r.started_at DESC NULLS LAST, r.id DESC
                 LIMIT %(limit)s""",
            {"source": source_id, "clearance": clearance,
             "limit": limit}).fetchall()
        personas = self._persona_rows([r[11] for r in rows if r[11]],
                                      clearance=clearance)
        return [self._run_dict(r, personas) for r in rows]

    def run_detail(self, run_id: UUID, *, clearance: str | None) -> dict:
        """One run with its request log, read under the SOURCE's label:
        CollectionNotFound above it, indistinguishable from a missing id."""
        row = self._c.execute(
            f"""SELECT {self._RUN_COLUMNS}, r.requests, r.cursor
                  {self._RUN_FROM}
                 WHERE r.id = %(run)s AND {_SOURCE_VISIBLE}""",
            {"run": run_id, "clearance": clearance}).fetchone()
        if row is None:
            raise CollectionNotFound("no such run, or it is above your clearance")
        personas = self._persona_rows([row[11]] if row[11] else [],
                                      clearance=clearance)
        detail = self._run_dict(row, personas)
        detail["requests"] = list(row[19] or [])
        return detail


    # ── the read path ──────────────────────────────────────────────────
    #
    # Everything above WRITES `collect.document` and `collect.watch_hit`.
    # Until 2026-08-10 nothing read them back. No endpoint, no UI, and no
    # search reach -- `SearchService` covered `core.node` and
    # `core.evidence` only, and `document.search_tsv`'s GIN index was used
    # by no query in the tree until `SearchService.search` joined the
    # document table on 2026-09-02. A watch could fire four hundred times
    # and the analyst saw the integer 400 on a run card and could not open
    # one of them.
    #
    # That is the tags/node-sets defect one layer up: not a service with
    # no caller, an entire PHASE with no caller. The lifecycle columns
    # show the intent was never finished rather than decided against --
    # `watch_hit` carries `notified_at`, `suppressed`, `acknowledged_by`,
    # `acknowledged_at` and a partial index for the unnotified set, none
    # of them written or read by anything. The read path made three of
    # them visible; `suppress_hit`, `unsuppress_hit` and
    # `set_document_triage` below (2026-09-02) are the writers the pane
    # had been describing. `notified_at` still has no writer: there is no
    # notification kind for a watch hit, and inventing one belongs with
    # the notification registry, not here.
    #
    # Clearance is a PARAMETER here rather than constructor state, unlike
    # CommsService, because this same class does the collecting and the
    # collector has no user. A read method that inherited a NULL clearance
    # from a worker would be a read method that returns everything.
    #
    # L1 (2026-09-24): so are the reader's `compartments`, checked as
    # `d.compartments <@` them in every read and reader's verb below. Unlike
    # a missing clearance, a missing set FAILS CLOSED: the default is the
    # empty set, which sees only documents that carry no compartment, so a
    # caller that forgets to pass it hides captures rather than exposing
    # them, and existing callers keep working.

    def documents(self, *, clearance: str,
                  compartments: frozenset[str] = frozenset(),
                  source_id: UUID | None = None,
                  triage_state: str | None = None,
                  since: datetime | None = None,
                  limit: int = 100,
                  with_hold_reason: bool = False) -> list[dict]:
        """Collected documents, newest first.

        `legal_hold_reason` is free text a person wrote, which can name
        the matter the hold serves, so it is returned only when
        `with_hold_reason` says the caller is one who places and lifts
        document holds (retention.manage); every other reader sees
        `legal_hold` and None (2026-09-25).

        NOT case-scoped, because `collect.document` has no `case_id`: a
        document hangs off a SOURCE, and the same forum post is evidence
        in however many cases cite it. So this is gated on the global
        `collection.read` and filtered by classification, which defaults
        to AMBER and can be higher.

        `body_text` is excerpted. The full text of a forum thread is not a
        list-view concern, and an endpoint that returns every body pulls
        megabytes to render twenty titles.

        Purged documents are excluded outright. `retention` EMPTIES
        `body_text` and stamps `purged_at`; a row whose text is gone
        renders as an EMPTY document rather than as a deletion, which is
        the reported-as-the-wrong-thing shape this codebase keeps
        finding. (Until 2026-09-02 this said retention "NULLs" the
        column. It cannot: `collect.document.body_text` is NOT NULL, so
        the purge writes `''` and `purged_at` is what says the empty
        string means destroyed rather than blank -- which is exactly why
        `purged_at`, not the text, is the predicate below.)

        BOTH labels are checked -- the document's and its source's -- and
        the second was added on 2026-09-02. Every row here carries
        `s.name` and `d.external_url`, which is the source's identity, and
        `_store_document` copies the source's label onto the document only
        at INSERT. So a source collected while it was AMBER and later
        reclassified RED left its already-collected documents at AMBER,
        and the reclassification that was supposed to hide the forum's
        name went on publishing it on every one of them. The two labels
        answer different questions -- the document's says how sensitive
        the post is, the source's says how sensitive it is that we are
        reading that forum at all -- and a row that discloses both has to
        satisfy both.
        """
        rows = self._c.execute(
            """SELECT d.id, d.source_id, s.name, d.external_url, d.title,
                      left(d.body_text, 400), d.author_handle, d.posted_at,
                      d.captured_at, d.lang, d.version, d.triage_state,
                      d.classification::text, d.is_deleted_upstream,
                      length(d.body_text), d.compartments, s.kind::text,
                      d.author_uid, d.parent_ref, d.category, d.legal_hold,
                      d.legal_hold_reason
                 FROM collect.document d
                 JOIN collect.source s ON s.id = d.source_id
                WHERE d.purged_at IS NULL
                  AND d.classification <= %s::core.tlp
                  AND s.classification <= %s::core.tlp
                  AND d.compartments <@ %s::text[]
                  AND (%s::uuid IS NULL OR d.source_id = %s)
                  AND (%s::text IS NULL OR d.triage_state = %s)
                  AND (%s::timestamptz IS NULL OR d.captured_at >= %s)
                ORDER BY coalesce(d.posted_at, d.captured_at) DESC
                LIMIT %s""",
            (clearance, clearance, sorted(compartments), source_id,
             source_id, triage_state, triage_state, since, since,
             limit)).fetchall()
        return [{"id": str(r[0]), "source_id": str(r[1]), "source_name": r[2],
                 "external_url": r[3], "title": r[4], "excerpt": r[5],
                 "author_handle": r[6],
                 "posted_at": r[7].isoformat() if r[7] else None,
                 "captured_at": r[8].isoformat() if r[8] else None,
                 "lang": r[9], "version": r[10], "triage_state": r[11],
                 "classification": r[12], "is_deleted_upstream": r[13],
                 # So a reader can tell a short post from a truncated one.
                 "body_length": r[14],
                 "truncated": (r[14] or 0) > 400,
                 "compartments": sorted(r[15] or []),
                 # The identity fields a forum or a chat carries, and the
                 # document-level hold (2026-09-24).
                 "source_kind": r[16], "author_uid": r[17],
                 "parent_ref": r[18], "category": r[19],
                 "legal_hold": bool(r[20]),
                 "legal_hold_reason": r[21] if with_hold_reason else None}
                for r in rows]

    def watch_hits(self, case_id: UUID, *, clearance: str,
                   compartments: frozenset[str] = frozenset(),
                   unacknowledged_only: bool = False,
                   limit: int = 100) -> list[dict]:
        """What the watches on this case matched.

        Case-scoped, because `collect.watch` carries `case_id` even though
        the document it matched does not.

        Unacknowledged first, then by score: a hit nobody has looked at
        outranks a higher-scoring one somebody has already dealt with.

        A suppressed hit is RETURNED, carrying its reason. Suppression is
        alert hygiene -- the same thread matching hourly -- and hiding it
        outright would make a watch that is drowning look like a watch
        that is quiet, which is exactly the difference an analyst needs.

        Filtered on the DOCUMENT's label only, unlike `documents()` and
        `SearchService.search`, which were given the source's label as
        well on 2026-09-02. The difference is deliberate and is the case
        scope: a row is here because a watch somebody put on THIS case
        matched, the route is gated on `collection.read` against that
        case rather than globally, and the analyst who configured the
        watch is already entitled to know it fired. `external_url` does
        carry the source's host, so a source reclassified RED after
        collection is still reachable this way by the people on the case
        its watch belongs to -- recorded here rather than silently
        assumed covered, because whether a watch may be placed on a
        source above its owner's ceiling is a question about watch
        creation and belongs with that, not here.
        """
        rows = self._c.execute(
            """SELECT h.id, h.watch_id, w.name, h.document_id, d.title,
                      left(d.body_text, 240), d.external_url,
                      d.author_handle, d.posted_at, h.matched_on, h.score,
                      h.created_at, h.notified_at, h.suppressed,
                      h.suppress_reason, h.acknowledged_by,
                      h.acknowledged_at, d.classification::text
                 FROM collect.watch_hit h
                 JOIN collect.watch w ON w.id = h.watch_id
                 JOIN collect.document d ON d.id = h.document_id
                WHERE w.case_id = %s
                  AND d.purged_at IS NULL
                  AND d.classification <= %s::core.tlp
                  AND d.compartments <@ %s::text[]
                  AND (NOT %s OR h.acknowledged_at IS NULL)
                ORDER BY (h.acknowledged_at IS NULL) DESC,
                         h.score DESC NULLS LAST, h.created_at DESC
                LIMIT %s""",
            (case_id, clearance, sorted(compartments), unacknowledged_only,
             limit)).fetchall()
        return [{"id": str(r[0]), "watch_id": str(r[1]), "watch_name": r[2],
                 "document_id": str(r[3]), "title": r[4], "excerpt": r[5],
                 "external_url": r[6], "author_handle": r[7],
                 "posted_at": r[8].isoformat() if r[8] else None,
                 "matched_on": r[9],
                 "score": float(r[10]) if r[10] is not None else None,
                 "created_at": r[11].isoformat() if r[11] else None,
                 "notified_at": r[12].isoformat() if r[12] else None,
                 "suppressed": r[13], "suppress_reason": r[14],
                 "acknowledged_by": str(r[15]) if r[15] else None,
                 "acknowledged_at": r[16].isoformat() if r[16] else None,
                 "classification": r[17]}
                for r in rows]

    def acknowledge_hit(self, hit_id: UUID, *, user_id: UUID,
                        clearance: str,
                        compartments: frozenset[str] = frozenset()) -> dict:
        """Mark a hit as looked at. Idempotent, and it does not re-stamp.

        `acknowledged_at` is set once. Re-acknowledging would rewrite when
        somebody FIRST saw it, and that timestamp is the only evidence of
        how long a hit sat unread.

        The clearance check is inside the UPDATE rather than in a prior
        SELECT, so there is no window between deciding and writing, and a
        hit on a document above the caller's clearance is not merely
        hidden from the list but unacknowledgeable.

        `d.purged_at IS NULL` is the same predicate on the other axis, and
        it was missing until 2026-09-02: `watch_hits` has always dropped
        hits on purged documents, so acknowledging one stamped
        `acknowledged_by` on a row no list will ever show again -- a
        write reported as a success that no reader can observe.
        """
        row = self._c.execute(
            """UPDATE collect.watch_hit h
                  SET acknowledged_by = coalesce(h.acknowledged_by, %s),
                      acknowledged_at = coalesce(h.acknowledged_at, now())
                 FROM collect.document d
                WHERE h.id = %s AND d.id = h.document_id
                  AND d.purged_at IS NULL
                  AND d.classification <= %s::core.tlp
                  AND d.compartments <@ %s::text[]
            RETURNING h.id, h.acknowledged_by, h.acknowledged_at""",
            (user_id, hit_id, clearance, sorted(compartments))).fetchone()
        if row is None:
            raise CollectionError(
                "no such watch hit, or it is above your clearance")
        return {"id": str(row[0]), "acknowledged_by": str(row[1]),
                "acknowledged_at": row[2].isoformat() if row[2] else None}

    # ── the writers the Collected pane was describing ─────────────────
    #
    # `watch_hits` returns `suppressed` and `suppress_reason`, `documents`
    # returns and filters on `triage_state`, and the pane offers both. Until
    # 2026-09-02 no production path set any of them: `_match_watches`
    # drops a suppressed match BEFORE the row is written (so a stored
    # `suppressed = true` could only come from a test), and nothing touched
    # `triage_state` after the INSERT default. The UI was internally
    # consistent with a service that showed the columns, and both were
    # describing rows that did not exist.
    #
    # Every write is inside one UPDATE whose WHERE carries the case (for
    # hits), the clearance, and `d.purged_at IS NULL`, exactly as the
    # matching read does: no window between deciding and writing, and a row
    # the caller may not see is not merely hidden but unwritable. Every
    # write is audited, because these columns record nothing about who
    # changed them.
    #
    # The purge half of that sentence was untrue when it was written. The
    # writers carried the clearance predicate and not the purge one, while
    # `watch_hits` and `set_document_triage` carried both -- so a hit on a
    # purged document was invisible to every reader and still suppressible,
    # unsuppressible and acknowledgeable, and each of those returned a 200
    # describing a change no list would ever show. Corrected 2026-09-02, on
    # all three writers rather than the two that were reported: the claim is
    # about the read/write pair, and fixing one of a matched set is how the
    # next reader concludes the odd one out was deliberate.

    def suppress_hit(self, case_id: UUID, hit_id: UUID, *, actor_id: UUID,
                     reason: str, clearance: str,
                     compartments: frozenset[str] = frozenset()) -> dict:
        """Take a hit out of the queue on somebody's say-so, with a reason.

        The reason is the whole point. A hit that vanished from the queue
        for no stated cause is exactly what the pane's "suppressed hits
        are shown with their reason" exists to prevent, so a blank or a
        three-letter one is refused here, for every caller, rather than by
        a validator on one route.

        Re-suppressing an already-suppressed hit replaces the reason. The
        latest reason is the one the next analyst needs, and the audit
        trail keeps the earlier ones.

        `case_id` is the case in the ROUTE, and it must be the case the
        watch belongs to. The route gate authorised the caller against
        that case, not against whatever case the hit is actually on.
        """
        reason = (reason or "").strip()
        if len(reason) < MIN_SUPPRESS_REASON_LENGTH:
            raise CollectionError(
                f"a suppression has to say why, in at least "
                f"{MIN_SUPPRESS_REASON_LENGTH} characters: without a reason "
                f"the next analyst cannot tell noise from something somebody "
                f"wanted gone")
        row = self._c.execute(
            """UPDATE collect.watch_hit h
                  SET suppressed = true, suppress_reason = %s
                 FROM collect.watch w, collect.document d
                WHERE h.id = %s AND w.id = h.watch_id AND w.case_id = %s
                  AND d.id = h.document_id
                  AND d.purged_at IS NULL
                  AND d.classification <= %s::core.tlp
                  AND d.compartments <@ %s::text[]
            RETURNING h.id, h.suppressed, h.suppress_reason""",
            (reason, hit_id, case_id, clearance,
             sorted(compartments))).fetchone()
        if row is None:
            raise CollectionNotFound(
                "no such watch hit on this case, or it is above your clearance")
        self._audit(actor_id, "WATCH_HIT_SUPPRESSED", "watch_hit", hit_id,
                    {"reason": reason}, case_id=case_id)
        return {"id": str(row[0]), "suppressed": row[1],
                "suppress_reason": row[2]}

    def unsuppress_hit(self, case_id: UUID, hit_id: UUID, *, actor_id: UUID,
                       clearance: str,
                       compartments: frozenset[str] = frozenset()) -> dict:
        """Put a hit back. Clears the reason too: a hit that is not
        suppressed but still carries a reason would render as both.

        Carries `d.purged_at IS NULL` for the same reason `suppress_hit`
        does: unsuppressing a hit the list will never show is a write
        reported as a success that changes nothing an analyst can see.
        """
        row = self._c.execute(
            """UPDATE collect.watch_hit h
                  SET suppressed = false, suppress_reason = NULL
                 FROM collect.watch w, collect.document d
                WHERE h.id = %s AND w.id = h.watch_id AND w.case_id = %s
                  AND d.id = h.document_id
                  AND d.purged_at IS NULL
                  AND d.classification <= %s::core.tlp
                  AND d.compartments <@ %s::text[]
            RETURNING h.id, h.suppressed, h.suppress_reason""",
            (hit_id, case_id, clearance, sorted(compartments))).fetchone()
        if row is None:
            raise CollectionNotFound(
                "no such watch hit on this case, or it is above your clearance")
        self._audit(actor_id, "WATCH_HIT_UNSUPPRESSED", "watch_hit", hit_id,
                    {}, case_id=case_id)
        return {"id": str(row[0]), "suppressed": row[1],
                "suppress_reason": row[2]}

    def set_document_triage(self, document_id: UUID, state: str, *,
                            actor_id: UUID, clearance: str,
                            compartments: frozenset[str] = frozenset()
                            ) -> dict:
        """Move a document between 0011's four triage states.

        Validated against `TRIAGE_STATES` because the column is bare
        `text`: a fifth value would be stored, would match no option in
        the pane's filter, and the document would have left every view
        without being deleted. LINKED is settable by hand deliberately --
        nothing automated links a document to the graph (see the
        `Adapter` docstring), so an analyst who has done it by hand is the
        only one who can say so.

        NOT case-scoped, like `documents`: a document hangs off a source,
        not a case. Gated on clearance inside the UPDATE -- on the
        DOCUMENT's label and on its SOURCE's, because triage is the
        reader's verb and has to be gated on exactly what the read is
        gated on. `documents()` gained the source join on 2026-09-02 and
        this writer was left behind for the length of one commit, which
        made a document hidden from the list still triageable and turned
        the 200-vs-404 split into an existence oracle of the same shape
        `/sources/{id}/run` had just lost. Purged
        documents are untouchable -- triaging a destroyed exhibit would
        resurrect it in the filtered list with an empty body.
        """
        if state not in TRIAGE_STATES:
            raise CollectionError(
                f"unknown triage state {state!r}: one of "
                f"{', '.join(TRIAGE_STATES)}")
        row = self._c.execute(
            """UPDATE collect.document d
                  SET triage_state = %s
                 FROM (SELECT id, triage_state FROM collect.document
                        WHERE id = %s) old,
                      collect.source s
                WHERE d.id = old.id AND s.id = d.source_id
                  AND d.purged_at IS NULL
                  AND d.classification <= %s::core.tlp
                  AND s.classification <= %s::core.tlp
                  AND d.compartments <@ %s::text[]
            RETURNING d.id, old.triage_state, d.triage_state""",
            (state, document_id, clearance, clearance,
             sorted(compartments))).fetchone()
        if row is None:
            raise CollectionNotFound(
                "no such document, or it is above your clearance")
        self._audit(actor_id, "DOCUMENT_TRIAGED", "document", document_id,
                    {"from": row[1], "to": row[2]})
        return {"id": str(row[0]), "previous_state": row[1],
                "triage_state": row[2]}

    def _audit(self, actor_id: UUID | None, action: str, object_type: str,
               object_id: UUID, detail: dict, *,
               case_id: UUID | None = None) -> None:
        """actor_kind SYSTEM with a NULL actor when no person is behind the
        write (2026-09-24), as evidence.py records it."""
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (actor_id, "USER" if actor_id else "SYSTEM", action, object_type,
             object_id, case_id, Json(detail)))


# ---------------------------------------------------------------------------
# Helpers the service and the gate share (2026-09-24)
# ---------------------------------------------------------------------------

def _str(value) -> str | None:
    return str(value) if value is not None else None


def _item_label(item) -> str:
    """An item's id for a warning: redacted and short, because the id is
    the site's text and the warning is stored."""
    external = getattr(item, "external_id", None)
    if not isinstance(external, str) or not external:
        return "with no id"
    return repr(redact(external.replace("\x00", "�"))[:120])


def _persona_ref(persona: dict | None) -> dict | None:
    """A persona as a row that names it may show it: {id, handle} when the
    caller may see it, else HIDDEN_PERSONA, never its id or handle."""
    if persona is None:
        return None
    if not persona.get("visible", True):
        return dict(HIDDEN_PERSONA)
    return {"id": str(persona["id"]), "handle": persona["handle"]}


def _persona_hold_sentence(persona: dict, now: datetime
                           ) -> tuple[str, datetime | None]:
    """Why a persona cannot be used now, for the held list. Never names a
    source."""
    status = persona.get("status")
    if status == BURNED:
        return "This persona is burnt and must not be used again.", None
    if status == LOCKED:
        return "This persona is locked.", None
    if persona.get("lock_code"):
        return ("This persona is locked because its platform refused its "
                "credential. It comes back only with a new credential "
                "enrolled after the lock."), None
    hold = persona.get("hold_until")
    if hold and hold > now:
        return (f"This persona is resting until {_utc(hold)}: its platform "
                f"asked it to wait."), hold
    cooldown = persona.get("cooldown_until")
    if cooldown and cooldown > now:
        return f"This persona is resting until {_utc(cooldown)}.", cooldown
    if status == COOLDOWN and not cooldown:
        return ("This persona is resting until a person lifts its "
                "cooldown."), None
    return "This persona cannot be used now.", None


def _address_problem(url) -> str | None:
    """Why a source address is not one this collector reads, or None."""
    import urllib.parse

    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        return "A source's address is an http or https URL of at most 2048 characters."
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url):
        return "A source's address carries no spaces or control characters."
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "A source's address is an http or https URL with a host."
    if parts.username is not None or parts.password is not None:
        return "A source's address carries no user name or password."
    return None


@contextmanager
def _route_secret(route: EgressRoute):
    """The route's proxy token is registered for redaction for the life of
    the route (2026-09-24): a library holding it as a plain
    password (Telethon's proxy dict) could otherwise echo it into an error
    this codebase stores. A DIRECT route carries none."""
    token = getattr(route, "token", None) if route is not None else None
    if route is not None and route.proxied and token:
        with secret_in_scope(token):
            yield
    else:
        yield


def _route_for_source(conn: psycopg.Connection, source: SourceRow,
                      persona: dict | None, *, adapter,
                      run_id: UUID) -> EgressRoute:
    """The egress route of one poll (docs/00 decision 68, docs/20
    sections 6 and 9).

    An adapter that needs no authority (RSS) ALWAYS takes the passive
    default, so an RSS poll keeps working once a proxy is configured; an
    authority adapter takes the persona's egress profile, or the source's
    own for a persona-less read. The context is the run, whose row is
    committed already. A route the layer refuses is EgressUnavailable,
    carrying its sentence through redact(): a BLOCKED run, configuration
    rather than parser health. route_for refuses a production persona
    route that is not the passive default when no proxy is configured, so
    no forum or Telegram source is ever read directly in production."""
    if not _attr(adapter, "requires_authority"):
        name = PASSIVE_PROFILE
    else:
        profile = (persona["egress_profile_id"] if persona is not None
                   else source.egress_profile_id)
        name = _checked_profile(conn, profile)
    try:
        return egress.route_for("persona", name, conn=conn,
                                context=f"run:{run_id}")
    except RouteUnavailable as exc:
        raise EgressUnavailable(redact(str(exc))) from None


def _route_for_persona(conn: psycopg.Connection, persona: dict, *,
                       context: str) -> EgressRoute:
    """The egress route of a persona's attended act: its own egress
    profile, with an act, stop or run context (the source form could not
    carry an act, which has no source)."""
    name = _checked_profile(conn, persona.get("egress_profile_id"))
    try:
        return egress.route_for("persona", name, conn=conn, context=context)
    except RouteUnavailable as exc:
        raise EgressUnavailable(redact(str(exc))) from None


def _checked_profile(conn: psycopg.Connection, profile) -> str:
    if profile is None:
        raise EgressUnavailable(EGRESS_NONE_SENTENCE)
    row = conn.execute(
        "SELECT is_active FROM collect.egress_profile WHERE id = %s",
        (profile,)).fetchone()
    if row is None or not row[0]:
        raise EgressUnavailable(EGRESS_RETIRED_SENTENCE)
    return str(profile)


# ---------------------------------------------------------------------------
# The persona gate (2026-09-24)
# ---------------------------------------------------------------------------

@dataclass
class PersonaContext:
    """What an attended act or a persona poll holds while the persona is in
    use: who it is, the authority that allows the act, the route and the
    lease (None when the act needs no credential)."""

    persona_id: UUID
    handle: str
    platform: str | None
    platform_uid: str | None
    fingerprint: dict
    authority: object | None
    route: EgressRoute | None
    lease: Lease | None


#: The persona lock's name space, the idiom `_POLL_LOCK` uses.
_PERSONA_LOCK = "collect.persona"


class PersonaGate:
    """The six steps between a request to use a persona and the credential.

    (1) check: the row exists and the caller may see it (set_status's
    predicate; a hidden persona is CollectionNotFound before the lock and
    before any audit row), it is an account on the adapter's platform, and
    it may be used now (PERSONA_USABLE_SQL, with a sentence for why not);
    (2) lock: one runner per persona, because one credential used by two
    connections at once is what a platform reads as a stolen one;
    (3) window: its active hours in UTC; (4) authority: a live confirmed
    authority and the confirmer check; (5) pace: the per-persona gap;
    (6) the route and the lease. STOPPING (a logout, a destroy) checks only
    existence, visibility, platform and the exit: stopping is always
    allowed. `clearance` None is the worker's (the cron) and nobody
    else's: an authenticated host script passes its operator's ceiling
    (2026-09-24).
    """

    def __init__(self, conn: psycopg.Connection, persona_id: UUID, *,
                 actor_id: UUID | None, clearance: str | None, purpose: str,
                 source_id: UUID | None, need: str | None,
                 platform: str | None, run_id: UUID | None = None,
                 stopping: bool = False, needs_secret: bool = True,
                 needs_browser_identity: bool = False, min_gap_s: float = 0.0,
                 sleep=time.sleep, adapter=None):
        # Enforced, not only said (2026-09-25): no ceiling
        # is the worker's reading and sees every persona, so a PERSON
        # reaching the gate without their ceiling is a caller that forgot
        # it, and is refused before anything is read.
        if clearance is None and actor_id is not None:
            raise CollectionError(
                "A person's use of a persona is checked against that "
                "person's clearance, and none was given.")
        self._c = conn
        self.persona_id = persona_id
        self.actor_id = actor_id
        self.clearance = clearance
        self.purpose = purpose
        self.source_id = source_id
        self.need = need
        self.platform = platform
        self.run_id = run_id
        self.stopping = stopping
        self.needs_secret = needs_secret
        self.needs_browser_identity = needs_browser_identity
        self.min_gap_s = min_gap_s
        self._sleep = sleep
        self.adapter = adapter
        self.row: dict | None = None
        self._locked = False

    def check(self) -> dict:
        row = self._c.execute(
            f"""SELECT a.id, a.handle, a.platform::text, a.platform_uid,
                       a.status, a.cooldown_until, a.machine_hold_until,
                       a.machine_lock_code, a.egress_profile_id,
                       coalesce(octet_length(a.secret_ciphertext), 0) > 0,
                       a.fingerprint_profile, {PERSONA_USABLE_SQL}
                  FROM collect.collection_account a
                 WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}""",
            {"id": self.persona_id, "clearance": self.clearance}).fetchone()
        if row is None:
            raise CollectionNotFound(
                "no such persona, or it is above your clearance")
        persona = {"id": row[0], "handle": row[1], "platform": row[2],
                   "platform_uid": row[3], "status": row[4],
                   "cooldown_until": row[5], "hold_until": row[6],
                   "lock_code": row[7], "egress_profile_id": row[8],
                   "credential": row[9], "fingerprint": dict(row[10] or {}),
                   "usable": row[11], "visible": True}
        if self.platform is not None and persona["platform"] != self.platform:
            raise PersonaUnavailable(
                f"This persona is a {persona['platform']} account and this "
                f"source is read by a {self.platform} adapter."
                if persona["platform"] else
                f"This persona is not placed on any platform, and this is "
                f"done by a {self.platform} adapter.")
        if persona["egress_profile_id"] is None:
            raise PersonaUnavailable(
                "This persona has no egress profile, so it cannot reach anything.")
        if self.stopping:
            self.row = persona
            return persona
        if not persona["usable"]:
            now = datetime.now(timezone.utc)
            sentence, until = _persona_hold_sentence(persona, now)
            refused = PersonaUnavailable(sentence)
            # A wait the PLATFORM imposed is answered to an attended act as
            # the platform's wait, with its end in UTC (2026-09-25);
            # attended_answer reads this.
            if (until is not None and until == persona["hold_until"]):
                refused.platform_wait_until = until
            raise refused
        if self.needs_secret and not persona["credential"]:
            raise PersonaUnavailable("This persona has no credential enrolled.")
        if self.needs_browser_identity and header_text_problem(
                "browser identity", persona["fingerprint"].get("user_agent"),
                low=1, high=400):
            raise PersonaUnavailable(
                "This persona has no browser identity recorded, so it cannot "
                "read over the web.")
        self.row = persona
        return persona

    def lock(self) -> None:
        held = self._c.execute(
            "SELECT pg_try_advisory_lock(hashtextextended(%s, 0))",
            (f"{_PERSONA_LOCK}:{self.persona_id}",)).fetchone()[0]
        if not held:
            raise CollectionBusy(
                "this persona is already in use by another runner; nothing "
                "was done")
        self._locked = True

    def window(self, now: datetime | None = None) -> None:
        if self.stopping or self.row is None:
            return
        now = now or datetime.now(timezone.utc)
        try:
            window = active_window(self.row["fingerprint"].get("active_window_utc"))
        except ValueError:
            window = None
        opening = window_opening(window, now) if window else None
        if opening is not None:
            raise PersonaResting(
                f"This persona is outside its active hours until "
                f"{opening.strftime('%H:%M')} UTC.", until=opening)

    def authority(self):
        """The live authority for the act, and the confirmer check: a
        person who confirmed it does not use it. Skipped when stopping."""
        if self.stopping:
            return None
        from noctornal_api.collection_authority import (
            AuthorityError,
            CollectionAuthorityService,
        )

        service = CollectionAuthorityService(self._c)
        live = service.require(persona_id=self.persona_id,
                               source_id=self.source_id,
                               need=self.need or "PUBLIC_READ",
                               actor_id=self.actor_id,
                               clearance=self.clearance)
        if self.actor_id is not None and self.actor_id in (
                live.confirmed_by, live.target_confirmed_by):
            raise AuthorityError(CONFIRMER_SENTENCE)
        return live

    def pace(self) -> None:
        RateLimiter(self._c, sleep=self._sleep).wait_persona(
            self.persona_id, self.min_gap_s)

    def route(self) -> EgressRoute:
        if self.run_id is not None:
            context = f"run:{self.run_id}"
        elif self.stopping:
            context = f"stop:{self.persona_id}"
        else:
            context = f"act:{self.persona_id}"
        return _route_for_persona(self._c, self.row, context=context)

    def lease(self, *, run_id: UUID | None = None):
        if not self.needs_secret:
            return contextlib.nullcontext(None)
        return PersonaVault(self._c).lease(
            self.persona_id, actor_id=self.actor_id, purpose=self.purpose,
            run_id=run_id or self.run_id, stopping=self.stopping)

    def release(self) -> None:
        """Release the persona lock, guarded exactly as run_once's source
        lock is: an exception from here must not replace the real one."""
        if not self._locked:
            return
        self._locked = False
        try:
            self._c.execute(
                "SELECT pg_advisory_unlock(hashtextextended(%s, 0))",
                (f"{_PERSONA_LOCK}:{self.persona_id}",))
        except Exception:  # noqa: BLE001 - must not mask the real failure
            import logging

            logging.getLogger(__name__).warning(
                "persona unlock failed for %s", self.persona_id, exc_info=True)


def record_outcome(conn: psycopg.Connection, *, persona_id: UUID | None,
                   source_id: UUID | None, run_id: UUID | None,
                   exc: BaseException, adapter=None) -> datetime | None:
    """The persona's side of a platform's answer, for runs and attended
    acts alike, always while the persona lock is held (so a wait the
    platform imposed is on the persona before anything else can use it).
    Returns the end of a hold it placed.

    RateLimited: a RATE_LIMITED machine hold of the asked wait plus 10
    percent and 5 to 30 seconds. PersonaSuspended: a machine lock with its
    code, a notification to the collection managers who may see the
    persona, and for a credential in use from two places an alert to the
    security officers. WorkAbandoned: an ABANDONED hold of the adapter's
    abandon_cooldown_s, so no second session starts while the first may
    still be open."""
    if persona_id is None:
        return None
    vault = PersonaVault(conn)
    now = datetime.now(timezone.utc)
    if isinstance(exc, RateLimited):
        until = now + timedelta(seconds=exc.retry_after_s * 1.1
                                + random.uniform(5, 30))
        vault.signal(persona_id, reason=str(exc), hold_until=until,
                     hold_reason=HOLD_RATE_LIMITED, run_id=run_id)
        return until
    if isinstance(exc, PersonaSuspended):
        from noctornal_api import notify_events

        vault.signal(persona_id, reason=str(exc), lock_code=exc.lock_code,
                     run_id=run_id)
        notify_events.persona_suspended(conn, persona_id=persona_id,
                                        reason=str(exc))
        if exc.alert_officers:
            vault._audit(None, "PERSONA_CREDENTIAL_ALERT", persona_id,
                         {"lock_code": exc.lock_code,
                          "run_id": str(run_id) if run_id else None})
            notify_events.persona_credential_alert(conn, persona_id=persona_id)
        return None
    if isinstance(exc, WorkAbandoned):
        seconds = float(_attr(adapter, "abandon_cooldown_s")
                        if adapter is not None else Adapter.abandon_cooldown_s)
        until = now + timedelta(seconds=seconds)
        vault.signal(persona_id, reason=str(exc), hold_until=until,
                     hold_reason=HOLD_ABANDONED, run_id=run_id)
        return until
    return None


def _platform_wait_answer(until: datetime | None) -> str:
    if until is None:
        return "The platform asked this persona to wait. Nothing was done."
    return (f"The platform asked this persona to wait until {_utc(until)}. "
            f"Nothing was done.")


def attended_answer(exc: BaseException) -> tuple[int, str] | None:
    """The fixed status and sentence an attended act's route answers with,
    never a library's text; None for an exception that is not a persona or
    authority outcome (the route's own handling applies).

    The sentences carry the wait's end in UTC and the rest in minutes
    (2026-09-25): persona_session
    puts the hold record_outcome placed on the exception as `hold_until`,
    and the gate puts a live platform hold on its refusal as
    `platform_wait_until`. Either missing, the sentence says less rather
    than guess."""
    from noctornal_api.collection_authority import AuthorityError, AuthorityMissing

    if isinstance(exc, RateLimited):
        return 409, _platform_wait_answer(getattr(exc, "hold_until", None))
    if isinstance(exc, PersonaSuspended):
        return 409, ("The platform refused this persona's credential. Nothing "
                     "was done, and the persona is locked until a new "
                     "credential is enrolled.")
    if isinstance(exc, WorkAbandoned):
        until = getattr(exc, "hold_until", None)
        if until is None:
            return 504, ("The platform did not answer in time. The persona "
                         "rests so no second session starts while the first "
                         "may still be open.")
        seconds = (until - datetime.now(timezone.utc)).total_seconds()
        minutes = max(1, math.ceil(seconds / 60))
        return 504, (f"The platform did not answer in time. The persona rests "
                     f"for {count_of(minutes, 'minute', 'minutes')} so no "
                     f"second session starts while the first may still be "
                     f"open.")
    if isinstance(exc, PersonaUnavailable) and getattr(
            exc, "platform_wait_until", None) is not None:
        return 409, _platform_wait_answer(exc.platform_wait_until)
    if isinstance(exc, (PersonaResting, PersonaUnavailable, CollectionBusy,
                        AuthorityMissing, AuthorityError, EgressUnavailable)):
        return 409, str(exc)
    if isinstance(exc, CollectionNotFound):
        return 404, "no such persona, or it is above your clearance"
    return None


@contextmanager
def persona_session(conn: psycopg.Connection, persona_id: UUID, *,
                    actor_id: UUID | None, clearance: str | None, purpose: str,
                    source_id: UUID | None, need: str, platform: str | None,
                    run_id: UUID | None = None, stopping: bool = False,
                    needs_secret: bool = True,
                    needs_browser_identity: bool = False,
                    min_gap_s: float = 0.0, adapter=None, sleep=time.sleep):
    """An attended persona act (a chat lookup, a join, an enrolment, a
    logout): the six steps of PersonaGate in order, yielding a
    PersonaContext. A platform's answer raised inside the block goes
    through record_outcome BEFORE the persona is unlocked, and is then
    re-raised for the route to answer with `attended_answer`."""
    gate = PersonaGate(conn, persona_id, actor_id=actor_id,
                       clearance=clearance, purpose=purpose,
                       source_id=source_id, need=need, platform=platform,
                       run_id=run_id, stopping=stopping,
                       needs_secret=needs_secret,
                       needs_browser_identity=needs_browser_identity,
                       min_gap_s=min_gap_s, sleep=sleep, adapter=adapter)
    row = gate.check()
    gate.lock()
    try:
        gate.window()
        live = gate.authority()
        gate.pace()
        route = gate.route()
        with _route_secret(route), gate.lease() as lease:
            context = PersonaContext(
                persona_id=persona_id, handle=row["handle"],
                platform=row["platform"], platform_uid=row["platform_uid"],
                fingerprint=dict(row["fingerprint"] or {}), authority=live,
                route=route, lease=lease)
            try:
                yield context
            except (RateLimited, PersonaSuspended, WorkAbandoned) as exc:
                # The end of the hold rides on the exception so the route's
                # attended_answer can say it in UTC (2026-09-25).
                exc.hold_until = record_outcome(
                    conn, persona_id=persona_id, source_id=source_id,
                    run_id=run_id, exc=exc, adapter=adapter)
                raise
    finally:
        gate.release()
