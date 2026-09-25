"""The two-person collection authority and the classification ceilings
(the collection foundation, 2026-09-24; docs/00 decision 69).

An authority is a written authorisation that exists outside this system: a
warrant, a directed-surveillance or covert-source authorisation, an internal
covert online authorisation. The software records it, records who declared
it (a collection manager) and who confirmed it (a security officer, never
the same person), and refuses every forum and Telegram read it does not
cover, public boards included. RSS is unchanged. It cannot verify the
document, exactly as samples.policy_declared records the L1 declaration,
and every screen that shows an authority says so.

## Scopes

PUBLIC_READ: read what the platform shows to anyone, without joining and
without signing in to a members' area. MEMBER_READ: read as a member; it
covers PUBLIC_READ too, needs a persona, and needs `member_authority_ref`,
the reference of the authority to read as a member (docs/16 L3 and L4).
That is stricter than comms' exemption for PERSONA_PARTY, on purpose. There
is deliberately NO active scope: nothing in the product posts, messages or
purchases, and a scope for it would imply something does.

## Who it covers

One persona, or no persona (public reading with nothing signed in). Its
sources are targets, each confirmed by a second person, because adding a
source is the moment the reading set grows. A target covers its source
only while the source is read through the binding the target was added
for, at the address the confirmer was shown: a
rebinding, a re-pointed exit or a changed address needs a new confirmed
target. A persona's authority with no targets at all
allows the persona's own acts (enrolling, looking up a chat) and no read.

## Labels

An authority carries its own classification, at least every target's, and
it only rises. Every listing and every write filters whole rows by it, and
says only that something was withheld, never how much. A sentence that
carries an authority's date or scope is given only to a reader cleared for
that authority; anyone else gets the generic sentence, so a higher-labelled
authority is never an existence or content oracle.

## Ceilings

Every forum and Telegram source also needs a declared classification
ceiling for its kind (NOCTORNAL_FORUM_SOURCE_CEILING,
NOCTORNAL_TELEGRAM_SOURCE_CEILING), capped at AMBER by invariant 8 through
egress Destination.COLLECTION_TARGET: the fact that an exit reads a source
leaves the platform with every request, so a RED or AMBER_STRICT source is
never read by an adapter, whatever a variable says. That work is collected
by hand into its case.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.collection import (
    HIDDEN_PERSONA,
    PERSONA_VISIBLE_SQL,
    CollectionError,
    CollectionNotFound,
    _attr,
    _utc,
    default_adapters,
)
from noctornal_api.wording import agree, count_of

PUBLIC_READ = "PUBLIC_READ"
MEMBER_READ = "MEMBER_READ"
SCOPES = (PUBLIC_READ, MEMBER_READ)

SCOPE_WORDS = {
    PUBLIC_READ: ("Read what the platform shows to anyone, without joining or "
                  "signing in to a members' area"),
    MEMBER_READ: "Read as a member, including what only members see",
}

#: What confirming a persona's authority allows by itself.
PERSONA_ACTS_WORDS = (
    "Confirming it also allows the persona's own acts: enrolling it, looking "
    "up what it will read and, once a source read as a member is confirmed "
    "under it, joining. It allows no read of any source by itself.")

MAX_AUTHORITY_DAYS = 366
PROPOSED_DAYS = 90
EXPIRY_WARNING = timedelta(days=14)

#: Kind -> the variable that declares its ceiling. A later platform appends
#: its kind here, on a line of its own.
SOURCE_CEILING_ENV: dict[str, str] = {
    "XENFORO": "NOCTORNAL_FORUM_SOURCE_CEILING",
    "MYBB": "NOCTORNAL_FORUM_SOURCE_CEILING",
    "PHPBB": "NOCTORNAL_FORUM_SOURCE_CEILING",
    "TELEGRAM": "NOCTORNAL_TELEGRAM_SOURCE_CEILING",
}
ALLOWED_CEILINGS = ("CLEAR", "GREEN", "AMBER")
#: The kinds whose sources are read only by an adapter that enforces
#: collection authority (docs/00 decision 69): the forum and Telegram kinds, and
#: DISCORD, which nothing in this build reads.
AUTHORITY_KINDS = frozenset(SOURCE_CEILING_ENV) | {"DISCORD"}

AUTHORITY_NOTICE_LEAD = (
    "An authority is a written authorisation that exists outside this system. "
    "This record says who declared it and who confirmed it; the software "
    "cannot verify it. ")

_GENERIC = ("No confirmed authority covers reading this source. A collection "
            "manager records one and a security officer confirms it.")
_GENERIC_PERSONA = ("No confirmed authority covers this persona reading this "
                    "source. A collection manager records one and a security "
                    "officer confirms it.")
_NO_PERSONA_AUTHORITY = ("This persona has no confirmed authority at all, so "
                         "it may not sign in to anything.")

#: Why a candidate target does not cover its source, in the order they are
#: tested; the sentence of the first that applies is the one given.
_BINDING, _ADDRESS, _PENDING, _NOT_YET, _EXPIRED, _SCOPE = range(6)


class AuthorityMissing(CollectionError):
    """No live confirmed authority covers the read or the act. A poll that
    meets this is BLOCKED; an attended act is answered 409."""


class AuthorityError(CollectionError):
    """A two-person rule or a binding rule refused the request: the same
    person on both sides, a revoked or expired authority, a source read
    through a different binding. Answered 409."""


@dataclass(frozen=True)
class LiveAuthority:
    authority_id: UUID
    target_id: UUID | None
    scope: str
    valid_until: datetime
    confirmed_by: UUID
    target_confirmed_by: UUID | None


# ---------------------------------------------------------------------------
# Ceilings
# ---------------------------------------------------------------------------

def source_ceiling(kind: str, env=None) -> tuple[str | None, str]:
    """(ceiling, sentence). None when the kind may not be collected at all,
    with the sentence saying why."""
    env = os.environ if env is None else env
    var = SOURCE_CEILING_ENV.get(kind)
    if var is None:
        return None, f"No ceiling can be declared for {kind} sources in this build."
    family = "Telegram" if kind == "TELEGRAM" else "Forum"
    raw = (env.get(var) or "").strip()
    if not raw:
        return None, f"{family} collection is off: {var} is not declared."
    value = raw.upper().replace("+", "_")
    if value in ("AMBER_STRICT", "RED"):
        # Invariant 8: AMBER_STRICT and RED never leave the platform, so a
        # ceiling above AMBER is refused; the sentence says so in words.
        return None, (f"{var} names a label that never leaves this platform, "
                      f"so this collection stays off until it is CLEAR, "
                      f"GREEN or AMBER.")
    if value not in ALLOWED_CEILINGS:
        return None, f"{var} is not a TLP name. It takes CLEAR, GREEN or AMBER."
    return value, f"{var} is {value}."


def ceiling_refusal(source, env=None) -> str | None:
    """Why this source is not read by an adapter at its label, or None.
    Invariant 8's floor through Destination.COLLECTION_TARGET first, then
    the declared ceiling for its kind."""
    from noctornal_api.egress import (
        DENY_ABOVE_DESTINATION_CEILING,
        DENY_ABOVE_PLATFORM_FLOOR,
        Destination,
        can_egress,
    )

    ceiling, sentence = source_ceiling(source.kind, env)
    if ceiling is None:
        return sentence
    decision = can_egress(source.classification, Destination.COLLECTION_TARGET,
                          destination_ceiling=ceiling)
    if decision.allowed:
        return None
    if decision.reason == DENY_ABOVE_DESTINATION_CEILING:
        return (f"This source is labelled TLP:{source.classification}, above "
                f"the ceiling declared for its kind, so it is collected by "
                f"hand, not by the collector.")
    if decision.reason == DENY_ABOVE_PLATFORM_FLOOR:
        # Invariant 8's floor, said in words: this sentence reaches the
        # console, which cites no rule numbers (2026-09-24).
        return (f"This source is labelled TLP:{source.classification}, which "
                f"never leaves this platform, so it is collected by hand, not "
                f"by the collector.")
    return decision.explain()


def ceiling_problems(env) -> list[str]:
    """The production refusals config.verify_environment appends: a
    ceiling variable SET to anything the collector may not read at. Unset
    is valid (that collection is off). No value is quoted."""
    problems = []
    for var in sorted(set(SOURCE_CEILING_ENV.values())):
        raw = (env.get(var) or "").strip()
        if raw and raw.upper().replace("+", "_") not in ALLOWED_CEILINGS:
            problems.append(
                f"{var} is set to a label the collector may not read at: it "
                f"takes CLEAR, GREEN or AMBER, and AMBER_STRICT and RED never "
                f"leave this platform.")
    return problems


def _rank(name: str | None):
    from noctornal_api.security.access import tlp_from_name
    return tlp_from_name(name) if name else None


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _Candidate:
    target_id: UUID
    source_id: UUID
    target_confirmed_at: datetime | None
    target_confirmed_by: UUID | None
    target_revoked_at: datetime | None
    target_base_url: str | None
    target_egress_profile_id: UUID | None
    authority_id: UUID
    persona_id: UUID | None
    scope: str
    classification: str
    valid_from: datetime
    valid_until: datetime
    confirmed_at: datetime | None
    confirmed_by: UUID | None
    revoked_at: datetime | None


def _covers(need: str, scope: str) -> bool:
    return scope == need or (need == PUBLIC_READ and scope == MEMBER_READ)


def _failure(candidate: _Candidate, source: dict, persona_id, need: str,
             at: datetime) -> int | None:
    """The first reason `candidate` does not cover the read, or None."""
    if (candidate.persona_id != persona_id
            or source["persona_id"] != persona_id):
        return _BINDING
    if (candidate.persona_id is None
            and source["egress_profile_id"] != candidate.target_egress_profile_id):
        return _BINDING
    if source["base_url"] != candidate.target_base_url:
        return _ADDRESS
    if candidate.confirmed_at is None or candidate.target_confirmed_at is None:
        return _PENDING
    if at < candidate.valid_from:
        return _NOT_YET
    if at >= candidate.valid_until:
        return _EXPIRED
    if not _covers(need, candidate.scope):
        return _SCOPE
    return None


def _sentence(reason: int, candidate: _Candidate) -> str:
    return {
        _BINDING: ("This source is now read through a different binding, so "
                   "the authority recorded for the old one does not cover it."),
        _ADDRESS: ("This source's address changed after its authority was "
                   "recorded, so the authority does not cover it."),
        _PENDING: "The authority for this source waits for a second person.",
        _NOT_YET: (f"The authority for this source comes into force on "
                   f"{_utc(candidate.valid_from)}."),
        _EXPIRED: (f"The authority for this source expired on "
                   f"{_utc(candidate.valid_until)}."),
        _SCOPE: ("This source is read as a member, and the authority covers "
                 "reading what is public only."),
    }[reason]


def _evaluate(source: dict, candidates: list[_Candidate], *, persona_id,
              need: str, at: datetime, ceiling: str | None
              ) -> tuple[LiveAuthority | None, str]:
    """(covering authority, or None and the sentence to give). Candidates
    above `ceiling` may cover, and never shape the sentence."""
    live = []
    failing = []
    for c in candidates:
        if c.revoked_at is not None or c.target_revoked_at is not None:
            continue
        reason = _failure(c, source, persona_id, need, at)
        if reason is None:
            live.append(c)
        else:
            failing.append((reason, c))

    def order(c: _Candidate):
        return (c.scope == need, c.valid_until)

    if live:
        best = max(live, key=order)
        return LiveAuthority(best.authority_id, best.target_id, best.scope,
                             best.valid_until, best.confirmed_by,
                             best.target_confirmed_by), ""
    limit = _rank(ceiling)
    shown = [(r, c) for r, c in failing
             if limit is None or _rank(c.classification) <= limit]
    if shown:
        reason, c = max(shown, key=lambda rc: order(rc[1]))
        return None, _sentence(reason, c)
    return None, _GENERIC_PERSONA if persona_id is not None else _GENERIC


def _state(confirmed_at, revoked_at, valid_from, valid_until,
           now: datetime) -> str:
    """PENDING, NOT_YET_VALID, LIVE, EXPIRED or REVOKED, computed at read
    and never stored or swept."""
    if revoked_at is not None:
        return "REVOKED"
    if confirmed_at is None:
        return "PENDING"
    if now < valid_from:
        return "NOT_YET_VALID"
    if now >= valid_until:
        return "EXPIRED"
    return "LIVE"


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


_CANDIDATE_SQL = """
SELECT t.id, t.source_id, t.confirmed_at, t.confirmed_by, t.revoked_at,
       t.target_base_url, t.target_egress_profile_id,
       a.id, a.collection_account_id, a.scope, a.classification::text,
       a.valid_from, a.valid_until, a.confirmed_at, a.confirmed_by,
       a.revoked_at
  FROM collect.collection_authority_target t
  JOIN collect.collection_authority a ON a.id = t.authority_id
 WHERE t.source_id = ANY(%s)"""


class CollectionAuthorityService:
    """Record, extend, confirm, revoke and list collection authorities, and
    decide whether one covers a read (`require`). `adapters` decides which
    sources need an authority at all; the routes pass get_adapters(), so a
    test can register a stub authority adapter."""

    def __init__(self, conn: psycopg.Connection, adapters=None):
        self._c = conn
        self._adapters = adapters if adapters is not None else default_adapters()

    # -- coverage ----------------------------------------------------------

    def _candidates(self, source_ids: list[UUID]) -> dict[UUID, list[_Candidate]]:
        out: dict[UUID, list[_Candidate]] = {}
        if not source_ids:
            return out
        for row in self._c.execute(_CANDIDATE_SQL, (list(source_ids),)).fetchall():
            candidate = _Candidate(*row)
            out.setdefault(candidate.source_id, []).append(candidate)
        return out

    def _source(self, source_id: UUID) -> dict:
        row = self._c.execute(
            """SELECT collection_account_id, egress_profile_id, base_url,
                      classification::text
                 FROM collect.source WHERE id = %s""", (source_id,)).fetchone()
        if row is None:
            raise CollectionNotFound("no such source, or it is above your clearance")
        return {"persona_id": row[0], "egress_profile_id": row[1],
                "base_url": row[2], "classification": row[3]}

    def require(self, *, persona_id: UUID | None, source_id: UUID | None,
                need: str, at: datetime | None = None,
                actor_id: UUID | None = None,
                clearance: str | None = None) -> LiveAuthority:
        """The one coverage rule (docs/00 decision 69).

        With a source: a confirmed, unrevoked target of a LIVE authority
        (confirmed, unrevoked, valid_from <= at < valid_until) for that
        source, whose authority names `persona_id` (or no persona, for a
        persona-less read), whose source is still bound that way, at the
        address the target was added for and, persona-less, through the
        same exit; its scope `need`, or MEMBER_READ when the need is public.
        Without a source (a persona act that reads nothing): any LIVE
        authority for the persona with a covering scope. Otherwise
        AuthorityMissing with a sentence that never names the source.

        `clearance` bounds what the sentence may say: the caller's for a
        route or an attended act; None means the text will be stored on a
        run or listed as held, and is bounded by the SOURCE's label.
        `actor_id` is accepted for the attended acts' signature; the
        confirmer rule is `confirmer_runs`, asked before any run row.
        """
        if need not in SCOPES:
            raise ValueError(f"unknown scope {need!r}")
        at = at or datetime.now(timezone.utc)
        if source_id is None:
            if persona_id is None:
                raise AuthorityMissing(_NO_PERSONA_AUTHORITY)
            row = self._c.execute(
                """SELECT id, scope, valid_until, confirmed_by
                     FROM collect.collection_authority
                    WHERE collection_account_id = %s
                      AND confirmed_at IS NOT NULL AND revoked_at IS NULL
                      AND valid_from <= %s AND valid_until > %s
                      AND (scope = %s OR (%s = 'PUBLIC_READ'
                                          AND scope = 'MEMBER_READ'))
                    ORDER BY (scope = %s) DESC, valid_until DESC LIMIT 1""",
                (persona_id, at, at, need, need, need)).fetchone()
            if row is None:
                raise AuthorityMissing(_NO_PERSONA_AUTHORITY)
            return LiveAuthority(row[0], None, row[1], row[2], row[3], None)
        source = self._source(source_id)
        candidates = self._candidates([source_id]).get(source_id, [])
        live, sentence = _evaluate(
            source, candidates, persona_id=persona_id, need=need, at=at,
            ceiling=clearance or source["classification"])
        if live is None:
            raise AuthorityMissing(sentence)
        return live

    def confirmer_runs(self, persona_id: UUID | None, source_id: UUID,
                       actor_id: UUID | None, *, need: str = PUBLIC_READ) -> bool:
        """True when `actor_id` confirmed the authority, or the target, that
        would cover this read. Asked before any run row: the refusal
        is about the person, so it never marks the source blocked. The cron
        (no actor) is never refused."""
        if actor_id is None:
            return False
        try:
            live = self.require(persona_id=persona_id, source_id=source_id,
                                need=need)
        except AuthorityMissing:
            return False
        return actor_id in (live.confirmed_by, live.target_confirmed_by)

    def uncovered_map(self, sources, *, clearance: str | None = None
                      ) -> dict[UUID, str]:
        """{source id: sentence} for each source (SourceRow) no live target
        covers under its current binding. The sentence is bounded by the
        source's own label: it is listed as held."""
        by_source = self._candidates([s.id for s in sources])
        now = datetime.now(timezone.utc)
        out = {}
        for s in sources:
            adapter = self._adapters.get(s.parser_key)
            need = (_attr(adapter, "authority_need")(s) if adapter is not None
                    else PUBLIC_READ)
            source = {"persona_id": s.collection_account_id,
                      "egress_profile_id": s.egress_profile_id,
                      "base_url": s.base_url}
            live, sentence = _evaluate(
                source, by_source.get(s.id, []),
                persona_id=s.collection_account_id, need=need, at=now,
                ceiling=s.classification)
            if live is None:
                out[s.id] = sentence
        return out

    def uncovered_sources(self, *, clearance: str | None = None) -> list[dict]:
        """Active sources whose adapter requires an authority and that no
        live confirmed target covers: [{id, name, sentence}]."""
        from noctornal_api.collection import _SOURCE_COLUMNS, _SOURCE_VISIBLE, _row_to_source

        rows = self._c.execute(
            f"SELECT {_SOURCE_COLUMNS} FROM collect.source s "
            f"WHERE s.is_active AND {_SOURCE_VISIBLE}",
            {"clearance": clearance}).fetchall()
        sources = [_row_to_source(r) for r in rows]
        sources = [s for s in sources
                   if (a := self._adapters.get(s.parser_key)) is not None
                   and _attr(a, "requires_authority")]
        missing = self.uncovered_map(sources)
        return [{"id": str(s.id), "name": s.name, "sentence": missing[s.id]}
                for s in sources if s.id in missing]

    def expiring_count(self, *, within: timedelta = EXPIRY_WARNING) -> int:
        """LIVE authorities that end within `within`."""
        now = datetime.now(timezone.utc)
        return self._c.execute(
            """SELECT count(*) FROM collect.collection_authority
                WHERE confirmed_at IS NOT NULL AND revoked_at IS NULL
                  AND valid_from <= %s AND valid_until > %s
                  AND valid_until <= %s""",
            (now, now, now + within)).fetchone()[0]

    def states_for_sources(self, ids: list[UUID], *, clearance: str | None
                           ) -> dict[UUID, dict]:
        """{source id: {state, scope, valid_until}} for the chips, among
        authorities within `clearance` only."""
        if not ids:
            return {}
        rows = self._c.execute(
            """SELECT id, collection_account_id, egress_profile_id, base_url
                 FROM collect.source WHERE id = ANY(%s)""",
            (list(ids),)).fetchall()
        by_source = self._candidates(list(ids))
        limit = _rank(clearance)
        now = datetime.now(timezone.utc)
        out = {}
        for sid, persona, profile, base_url in rows:
            candidates = [c for c in by_source.get(sid, [])
                          if limit is None or _rank(c.classification) <= limit]
            source = {"persona_id": persona, "egress_profile_id": profile,
                      "base_url": base_url}
            live, _sentence_text = _evaluate(source, candidates, persona_id=persona,
                                             need=PUBLIC_READ, at=now,
                                             ceiling=clearance)
            if live is not None:
                out[sid] = {"state": "LIVE", "scope": live.scope,
                            "valid_until": _iso(live.valid_until)}
                continue
            current = [c for c in candidates
                       if c.revoked_at is None and c.target_revoked_at is None]
            if not current:
                out[sid] = {"state": "REVOKED" if candidates else "NONE",
                            "scope": None, "valid_until": None}
                continue
            best = max(current, key=lambda c: c.valid_until)
            reason = _failure(best, source, persona, PUBLIC_READ, now)
            state = {_PENDING: "PENDING", _NOT_YET: "NOT_YET_VALID",
                     _EXPIRED: "EXPIRED"}.get(reason, "NONE")
            out[sid] = {"state": state, "scope": best.scope if state != "NONE" else None,
                        "valid_until": _iso(best.valid_until) if state != "NONE" else None}
        return out

    def states_for_personas(self, ids: list[UUID], *, clearance: str | None
                            ) -> dict[UUID, dict]:
        """{persona id: {state, scope, valid_until}}: the LIVE authority
        first, else the latest recorded, among those within `clearance`."""
        if not ids:
            return {}
        rows = self._c.execute(
            """SELECT collection_account_id, scope, valid_from, valid_until,
                      confirmed_at, revoked_at, recorded_at
                 FROM collect.collection_authority
                WHERE collection_account_id = ANY(%s)
                  AND (%s::core.tlp IS NULL OR classification <= %s::core.tlp)""",
            (list(ids), clearance, clearance)).fetchall()
        now = datetime.now(timezone.utc)
        best: dict[UUID, tuple] = {}
        for pid, scope, vfrom, vuntil, confirmed, revoked, recorded in rows:
            state = _state(confirmed, revoked, vfrom, vuntil, now)
            key = (state == "LIVE", recorded)
            if pid not in best or key > best[pid][0]:
                best[pid] = (key, {"state": state, "scope": scope,
                                   "valid_until": _iso(vuntil)})
        return {pid: value for pid, (_k, value) in best.items()}

    # -- recording ---------------------------------------------------------

    def _visible_persona(self, persona_id: UUID, clearance: str | None) -> None:
        row = self._c.execute(
            f"SELECT 1 FROM collect.collection_account a "
            f"WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}",
            {"id": persona_id, "clearance": clearance}).fetchone()
        if row is None:
            raise CollectionNotFound("no such persona, or it is above your clearance")

    def _target_sources(self, source_ids: list[UUID], *, persona_id,
                        classification: str, clearance: str | None) -> list[tuple]:
        """Each source, visible to the caller, read by an authority adapter,
        labelled no higher than the authority, and bound as the authority
        covers."""
        from noctornal_api.security.access import tlp_from_name

        rows = []
        label = tlp_from_name(classification)
        limit = _rank(clearance)
        for sid in source_ids:
            row = self._c.execute(
                """SELECT id, classification::text, parser_key,
                          collection_account_id
                     FROM collect.source WHERE id = %s""", (sid,)).fetchone()
            if row is None or (limit is not None and _rank(row[1]) > limit):
                raise CollectionNotFound(
                    "no such source, or it is above your clearance")
            adapter = self._adapters.get(row[2])
            if adapter is None or not _attr(adapter, "requires_authority"):
                raise CollectionError(
                    "This source is not read by a forum or Telegram adapter, "
                    "so it needs no authority.")
            if tlp_from_name(row[1]) > label:
                raise CollectionError(
                    f"An authority is never labelled below a source it "
                    f"covers: choose at least TLP:{row[1]}.")
            if persona_id is not None and row[3] != persona_id:
                raise AuthorityError(
                    "This source is read by a different persona."
                    if row[3] is not None else
                    "This source is read without a persona.")
            if persona_id is None and row[3] is not None:
                raise AuthorityError("This source is read by a persona.")
            rows.append(row)
        return rows

    def record(self, *, persona_id: UUID | None, scope: str,
               classification: str, authority_ref: str, issued_by: str,
               jurisdiction: str, legal_basis: str,
               member_authority_ref: str | None, target_description: str,
               valid_from: datetime, valid_until: datetime,
               source_ids: list[UUID], recorded_by: UUID,
               clearance: str | None) -> dict:
        """Record an authority and its first sources, as the first person.
        Checked before the database's own CHECKs, so a refusal is a
        sentence rather than a constraint name."""
        from noctornal_api.security.access import (
            AccessResolutionError,
            tlp_from_name,
        )

        if scope not in SCOPES:
            raise CollectionError(f"{scope} is not a scope. It is PUBLIC_READ or MEMBER_READ.")
        member_ref = (member_authority_ref or "").strip() or None
        if scope == MEMBER_READ and persona_id is None:
            raise CollectionError("Reading as a member needs a persona.")
        if scope == MEMBER_READ and member_ref is None:
            raise CollectionError(
                "Reading as a member needs its own authority reference.")
        for moment in (valid_from, valid_until):
            if moment.tzinfo is None or moment.tzinfo.utcoffset(moment) is None:
                raise CollectionError("Times are UTC: send an offset.")
        if valid_until <= valid_from:
            raise CollectionError("An authority ends after it starts.")
        if valid_until > valid_from + timedelta(days=MAX_AUTHORITY_DAYS):
            raise CollectionError(
                f"An authority runs for at most {MAX_AUTHORITY_DAYS} days.")
        try:
            label = tlp_from_name(classification)
        except AccessResolutionError as exc:
            raise CollectionError(f"{classification} is not a TLP name.") from exc
        if clearance is not None and label > tlp_from_name(clearance):
            raise CollectionError(
                f"You cannot label an authority above your own TLP:{clearance} "
                f"clearance.")
        ids = list(dict.fromkeys(source_ids or []))
        if persona_id is None and not ids:
            raise CollectionError(
                "An authority with no persona covers sources: name at least one.")
        if len(ids) > 100:
            raise CollectionError("An authority lists at most 100 sources at once.")
        texts = {"authority_ref": (authority_ref or "").strip(),
                 "issued_by": (issued_by or "").strip(),
                 "jurisdiction": (jurisdiction or "").strip(),
                 "legal_basis": (legal_basis or "").strip(),
                 "target_description": (target_description or "").strip()}
        if (len(texts["authority_ref"]) < 3 or not texts["issued_by"]
                or len(texts["jurisdiction"]) < 2 or not texts["legal_basis"]
                or len(texts["target_description"]) <= 20):
            raise CollectionError(
                "An authority records its reference, who issued it, the "
                "jurisdiction, the legal basis and what it covers, in more "
                "than 20 characters.")
        if persona_id is not None:
            self._visible_persona(persona_id, clearance)
        with self._c.transaction():
            self._target_sources(ids, persona_id=persona_id,
                                 classification=label.name, clearance=clearance)
            authority_id = self._c.execute(
                """INSERT INTO collect.collection_authority
                       (collection_account_id, scope, classification,
                        authority_ref, issued_by, jurisdiction, legal_basis,
                        member_authority_ref, target_description, valid_from,
                        valid_until, recorded_by)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING id""",
                (persona_id, scope, label.name, texts["authority_ref"],
                 texts["issued_by"], texts["jurisdiction"],
                 texts["legal_basis"], member_ref,
                 texts["target_description"], valid_from, valid_until,
                 recorded_by)).fetchone()[0]
            for sid in ids:
                self._c.execute(
                    """INSERT INTO collect.collection_authority_target
                           (authority_id, source_id, added_by)
                       VALUES (%s, %s, %s)""", (authority_id, sid, recorded_by))
            self._audit(recorded_by, "COLLECTION_AUTHORITY_RECORDED",
                        authority_id,
                        {"persona_id": str(persona_id) if persona_id else None,
                         "scope": scope, "classification": label.name,
                         "authority_ref": texts["authority_ref"],
                         "valid_until": valid_until.isoformat(),
                         "target_count": len(ids)})
            from noctornal_api import notify_events
            notify_events.collection_authority_pending(
                self._c, authority_id=authority_id, actor_id=recorded_by)
        return self.view(authority_id, clearance=clearance)

    def _authority(self, authority_id: UUID, clearance: str | None) -> tuple:
        row = self._c.execute(
            """SELECT id, collection_account_id, recorded_by, confirmed_at,
                      revoked_at, valid_until, classification::text, scope
                 FROM collect.collection_authority
                WHERE id = %s
                  AND (%s::core.tlp IS NULL OR classification <= %s::core.tlp)""",
            (authority_id, clearance, clearance)).fetchone()
        if row is None:
            raise CollectionNotFound(
                "no such authority, or it is above your clearance")
        return row

    def add_targets(self, authority_id: UUID, *, source_ids: list[UUID],
                    added_by: UUID, clearance: str | None) -> dict:
        """More sources under an authority. Each waits for a second person,
        and the officers are told, so a new target never waits
        silently."""
        row = self._authority(authority_id, clearance)
        if row[4] is not None:
            raise AuthorityError("This authority is revoked.")
        if row[5] <= datetime.now(timezone.utc):
            raise AuthorityError("This authority has expired.")
        ids = list(dict.fromkeys(source_ids or []))
        if not 1 <= len(ids) <= 100:
            raise CollectionError("Add between 1 and 100 sources at once.")
        with self._c.transaction():
            self._target_sources(ids, persona_id=row[1],
                                 classification=row[6], clearance=clearance)
            for sid in ids:
                taken = self._c.execute(
                    """SELECT 1 FROM collect.collection_authority_target
                        WHERE authority_id = %s AND source_id = %s
                          AND revoked_at IS NULL""",
                    (authority_id, sid)).fetchone()
                if taken is not None:
                    raise CollectionError("This source is already under this authority.")
                self._c.execute(
                    """INSERT INTO collect.collection_authority_target
                           (authority_id, source_id, added_by)
                       VALUES (%s, %s, %s)""", (authority_id, sid, added_by))
                self._audit(added_by, "COLLECTION_AUTHORITY_TARGET_ADDED",
                            authority_id, {"source_id": str(sid)})
            from noctornal_api import notify_events
            notify_events.collection_authority_pending(
                self._c, authority_id=authority_id, actor_id=added_by)
        return self.view(authority_id, clearance=clearance)

    def confirm(self, authority_id: UUID, *, confirmed_by: UUID, note: str,
                target_ids: list[UUID], clearance: str | None) -> dict:
        """The second person. The authority (if it is still unconfirmed)
        and each listed target, in one transaction. Nobody confirms what
        they recorded or added, or what they cannot see."""
        note = (note or "").strip()
        if not 5 <= len(note) <= 1000:
            raise CollectionError("A confirmation says what was checked, in 5 to 1000 characters.")
        row = self._authority(authority_id, clearance)
        if row[2] == confirmed_by:
            raise AuthorityError(
                "Two people: you recorded this authority, so somebody else "
                "confirms it.")
        if row[4] is not None:
            raise AuthorityError("This authority is revoked.")
        if row[5] <= datetime.now(timezone.utc):
            raise AuthorityError("This authority has expired.")
        limit = _rank(clearance)
        targets = []
        for tid in dict.fromkeys(target_ids or []):
            target = self._c.execute(
                """SELECT t.id, t.added_by, t.confirmed_at, t.revoked_at,
                          s.classification::text
                     FROM collect.collection_authority_target t
                     JOIN collect.source s ON s.id = t.source_id
                    WHERE t.id = %s AND t.authority_id = %s""",
                (tid, authority_id)).fetchone()
            if target is None or (limit is not None and _rank(target[4]) > limit):
                raise CollectionNotFound(
                    "no such source under this authority, or it is above your "
                    "clearance")
            if target[1] == confirmed_by:
                raise AuthorityError(
                    "Two people: you added this source to the authority, so "
                    "somebody else confirms it.")
            if target[3] is not None:
                raise AuthorityError("That source is no longer under this authority.")
            if target[2] is None:
                targets.append(tid)
        if row[3] is not None and not targets:
            raise AuthorityError(
                "Nothing to confirm: the authority and the sources named are "
                "confirmed already.")
        with self._c.transaction():
            if row[3] is None:
                self._c.execute(
                    """UPDATE collect.collection_authority
                          SET confirmed_by = %s, confirmed_at = now(),
                              confirm_note = %s
                        WHERE id = %s AND confirmed_at IS NULL""",
                    (confirmed_by, note, authority_id))
            for tid in targets:
                self._c.execute(
                    """UPDATE collect.collection_authority_target
                          SET confirmed_by = %s, confirmed_at = now()
                        WHERE id = %s AND confirmed_at IS NULL""",
                    (confirmed_by, tid))
            self._audit(confirmed_by, "COLLECTION_AUTHORITY_CONFIRMED",
                        authority_id,
                        {"target_ids": [str(t) for t in targets], "note": note})
        return self.view(authority_id, clearance=clearance)

    def revoke(self, authority_id: UUID, *, revoked_by: UUID, reason: str,
               by_role: str, clearance: str | None) -> dict:
        """Either side may stop an authority at any time."""
        reason = _reason(reason)
        row = self._authority(authority_id, clearance)
        if row[4] is not None:
            raise AuthorityError("This authority is revoked already.")
        self._c.execute(
            """UPDATE collect.collection_authority
                  SET revoked_by = %s, revoked_at = now(), revoke_reason = %s
                WHERE id = %s AND revoked_at IS NULL""",
            (revoked_by, reason, authority_id))
        self._audit(revoked_by, "COLLECTION_AUTHORITY_REVOKED", authority_id,
                    {"reason": reason, "by_role": by_role})
        return self.view(authority_id, clearance=clearance)

    def revoke_target(self, target_id: UUID, *, revoked_by: UUID, reason: str,
                      by_role: str, clearance: str | None) -> dict:
        """Either side may take one source out from under an authority."""
        reason = _reason(reason)
        row = self._c.execute(
            """SELECT t.authority_id, t.revoked_at, s.classification::text
                 FROM collect.collection_authority_target t
                 JOIN collect.source s ON s.id = t.source_id
                WHERE t.id = %s""", (target_id,)).fetchone()
        limit = _rank(clearance)
        if row is None or (limit is not None and _rank(row[2]) > limit):
            raise CollectionNotFound(
                "no such source under an authority, or it is above your clearance")
        self._authority(row[0], clearance)
        if row[1] is not None:
            raise AuthorityError("That source is no longer under this authority.")
        self._c.execute(
            """UPDATE collect.collection_authority_target
                  SET revoked_by = %s, revoked_at = now(), revoke_reason = %s
                WHERE id = %s AND revoked_at IS NULL""",
            (revoked_by, reason, target_id))
        self._audit(revoked_by, "COLLECTION_AUTHORITY_TARGET_REVOKED", row[0],
                    {"target_id": str(target_id), "reason": reason,
                     "by_role": by_role})
        return self.view(row[0], clearance=clearance)

    # -- reading -----------------------------------------------------------

    _VIEW_SQL = """
SELECT a.id, a.collection_account_id, p.handle, a.scope,
       a.classification::text, a.authority_ref, a.issued_by, a.jurisdiction,
       a.legal_basis, a.member_authority_ref, a.target_description,
       a.valid_from, a.valid_until, a.recorded_by, ru.display_name,
       a.recorded_at, a.confirmed_by, cu.display_name, a.confirmed_at,
       a.confirm_note, a.revoked_at, vu.display_name, a.revoke_reason,
       CASE WHEN a.collection_account_id IS NULL THEN true ELSE EXISTS (
         SELECT 1 FROM collect.collection_account a2
          WHERE a2.id = a.collection_account_id
            AND NOT EXISTS (SELECT 1 FROM collect.source vs
                             WHERE (vs.id = a2.source_id
                                    OR vs.collection_account_id = a2.id)
                               AND %(clearance)s::core.tlp IS NOT NULL
                               AND vs.classification > %(clearance)s::core.tlp))
       END
  FROM collect.collection_authority a
  LEFT JOIN collect.collection_account p ON p.id = a.collection_account_id
  LEFT JOIN iam.app_user ru ON ru.id = a.recorded_by
  LEFT JOIN iam.app_user cu ON cu.id = a.confirmed_by
  LEFT JOIN iam.app_user vu ON vu.id = a.revoked_by
 WHERE (%(clearance)s::core.tlp IS NULL
        OR a.classification <= %(clearance)s::core.tlp)"""

    def _targets(self, authority_ids: list[UUID], clearance: str | None
                 ) -> tuple[dict[UUID, list[dict]], set[UUID]]:
        """Each authority's targets the caller may see, and the ids of the
        authorities with a target above the caller's ceiling."""
        rows = self._c.execute(
            """SELECT t.id, t.authority_id, t.source_id, s.name, s.kind::text,
                      t.target_base_url, s.base_url, t.target_egress_profile_id,
                      e.name, s.collection_account_id, s.egress_profile_id,
                      t.confirmed_at, t.revoked_at, au.display_name,
                      s.classification::text, a.collection_account_id,
                      pa.handle,
                      EXISTS (SELECT 1 FROM collect.source vs
                               WHERE (vs.id = pa.source_id
                                      OR vs.collection_account_id = pa.id)
                                 AND %(clearance)s::core.tlp IS NOT NULL
                                 AND vs.classification > %(clearance)s::core.tlp)
                 FROM collect.collection_authority_target t
                 JOIN collect.collection_authority a ON a.id = t.authority_id
                 JOIN collect.source s ON s.id = t.source_id
                 LEFT JOIN collect.egress_profile e
                        ON e.id = t.target_egress_profile_id
                 LEFT JOIN iam.app_user au ON au.id = t.added_by
                 LEFT JOIN collect.collection_account pa
                        ON pa.id = a.collection_account_id
                WHERE t.authority_id = ANY(%(ids)s)
                ORDER BY t.added_at""",
            {"ids": list(authority_ids), "clearance": clearance}).fetchall()
        import urllib.parse

        limit = _rank(clearance)
        out: dict[UUID, list[dict]] = {}
        hidden: set[UUID] = set()
        for r in rows:
            if limit is not None and _rank(r[14]) > limit:
                hidden.add(r[1])
                continue
            snapshot_host = None
            if r[5]:
                try:
                    snapshot_host = urllib.parse.urlsplit(r[5]).hostname
                except ValueError:
                    snapshot_host = None
            if r[15] is not None:
                binding = {"persona": (dict(HIDDEN_PERSONA) if r[17] else
                                       {"id": str(r[15]), "handle": r[16]})}
                changed = r[9] != r[15]
            else:
                binding = {"egress_profile": ({"id": str(r[7]), "name": r[8]}
                                              if r[7] else None)}
                changed = r[9] is not None or r[10] != r[7]
            state = ("REVOKED" if r[12] is not None
                     else "LIVE" if r[11] is not None else "PENDING")
            out.setdefault(r[1], []).append({
                "id": str(r[0]), "source_id": str(r[2]), "source_name": r[3],
                "source_kind": r[4], "source_host": snapshot_host,
                "address_changed": r[5] != r[6], "binding": binding,
                "binding_changed": changed, "state": state,
                "added_by_name": r[13]})
        return out, hidden

    def _views(self, rows, clearance: str | None) -> list[dict]:
        now = datetime.now(timezone.utc)
        targets, hidden = self._targets([r[0] for r in rows], clearance)
        # F5.3 (2026-09-24). A Telegram target has no address, so the
        # confirmer is shown which chat it is and how it is read.
        from noctornal_api.telegram_service import attach_target_chats
        attach_target_chats(self._c, targets)
        views = []
        for r in rows:
            persona = None
            if r[1] is not None:
                persona = ({"id": str(r[1]), "handle": r[2]} if r[23]
                           else dict(HIDDEN_PERSONA))
            views.append({
                "id": str(r[0]), "persona": persona, "scope": r[3],
                "scope_words": SCOPE_WORDS.get(r[3]),
                "classification": r[4], "authority_ref": r[5],
                "issued_by": r[6], "jurisdiction": r[7], "legal_basis": r[8],
                "member_authority_ref": r[9], "target_description": r[10],
                "valid_from": _iso(r[11]), "valid_until": _iso(r[12]),
                "recorded_by": str(r[13]), "recorded_by_name": r[14],
                "recorded_at": _iso(r[15]),
                "confirmed_by": str(r[16]) if r[16] else None,
                "confirmed_by_name": r[17], "confirmed_at": _iso(r[18]),
                "confirm_note": r[19], "revoked_at": _iso(r[20]),
                "revoked_by_name": r[21], "revoke_reason": r[22],
                "state": _state(r[18], r[20], r[11], r[12], now),
                "targets": targets.get(r[0], []),
                "has_hidden_targets": r[0] in hidden,
                "persona_acts": PERSONA_ACTS_WORDS if r[1] is not None else None,
            })
        return views

    def view(self, authority_id: UUID, *, clearance: str | None) -> dict:
        row = self._c.execute(self._VIEW_SQL + " AND a.id = %(id)s",
                              {"clearance": clearance, "id": authority_id}).fetchone()
        if row is None:
            raise CollectionNotFound(
                "no such authority, or it is above your clearance")
        return self._views([row], clearance)[0]

    def _withheld(self, clearance: str | None, persona_id: UUID | None = None) -> bool:
        if clearance is None:
            return False
        return self._c.execute(
            """SELECT EXISTS (SELECT 1 FROM collect.collection_authority
                               WHERE classification > %s::core.tlp
                                 AND (%s::uuid IS NULL
                                      OR collection_account_id = %s))""",
            (clearance, persona_id, persona_id)).fetchone()[0]

    def listing(self, *, clearance: str | None, persona_id: UUID | None = None,
                state: str | None = None) -> dict:
        """Every authority the caller may see, newest first. Rows above the
        caller's clearance are withheld whole, and `withheld` says only
        that some were, never how many (docs/16 D2, PRESENCE)."""
        rows = self._c.execute(
            self._VIEW_SQL + " AND (%(persona)s::uuid IS NULL "
            "OR a.collection_account_id = %(persona)s) ORDER BY a.recorded_at DESC",
            {"clearance": clearance, "persona": persona_id}).fetchall()
        views = self._views(rows, clearance)
        if state:
            views = [v for v in views if v["state"] == state]
        return {"authorities": views,
                "withheld": self._withheld(clearance, persona_id)}

    def review(self, *, clearance: str | None) -> dict:
        """The confirmer's queue: `pending` (unconfirmed authorities, or live
        ones with sources waiting, not revoked and not expired, oldest
        first) and `live` (so the officer can find what to revoke)."""
        rows = self._c.execute(
            self._VIEW_SQL + " AND a.revoked_at IS NULL AND a.valid_until > now()"
            " ORDER BY a.recorded_at", {"clearance": clearance}).fetchall()
        views = self._views(rows, clearance)
        pending = [v for v in views
                   if v["state"] in ("PENDING", "NOT_YET_VALID", "LIVE")
                   and (v["confirmed_at"] is None
                        or any(t["state"] == "PENDING" for t in v["targets"]))]
        live = [v for v in views if v["state"] == "LIVE"]
        return {"pending": pending, "live": live,
                "withheld": self._withheld(clearance)}

    def _audit(self, actor_id: UUID, action: str, authority_id: UUID,
               detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id, detail)
               VALUES (%s, 'USER', %s, 'collection_authority', %s, %s)""",
            (actor_id, action, authority_id, Json(detail)))


def _reason(reason: str) -> str:
    reason = (reason or "").strip()
    if not 5 <= len(reason) <= 1000:
        raise CollectionError("Stopping an authority says why, in 5 to 1000 characters.")
    return reason


def pending_summary(count: int) -> str:
    """'{n} authorities wait for a second person', agreed."""
    return (f"{count_of(count, 'collection authority', 'collection authorities')} "
            f"{agree(count, 'waits', 'wait')} for a second person")
