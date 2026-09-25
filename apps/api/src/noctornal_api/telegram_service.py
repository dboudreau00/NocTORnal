"""The attended Telegram acts, the enrolment gate and the facts the console
shows (roadmap F5.2 and F5.3, 2026-09-24).

## Acts

Every act that touches Telegram (looking up a chat, joining one, checking
membership, rebinding a chat to another persona, enrolling and logging out
a persona) runs through the collection foundation's persona gate: the
persona must be visible to the caller, usable, not in use elsewhere,
inside its active hours and covered by a live authority confirmed by a
second person; the route is the persona's own with an `act` context (a
`stop` context for a logout); and a platform's answer (a flood wait, a
revoked or duplicated session, an abandoned connection) is recorded on the
persona BEFORE the persona lock is released. The Telegram part then runs
off the calling thread with TELEGRAM_ACT_SECONDS.

## Re-enrolling a persona Telegram locked

The gate refuses a persona under a machine lock, and a lock clears only
when a new credential is stored, so a persona whose session Telegram
revoked could never be enrolled again, and its account and exit would be
lost with it (2026-09-24). The enrolment gate below
admits ONE more persona than the foundation's: one whose only obstacle is
a machine lock AND which holds no credential (the logout destroyed it).
The lock is about a credential that no longer exists; the store() that
ends the enrolment clears it, as 0082's guard allows. The egress proxy's
act rule admits a machine-locked persona for the same reason.

## Labels

A Telegram source is found only when it is visible under the foundation's
one predicate (`collection._SOURCE_VISIBLE`), so every chat route answers a
hidden source exactly like a missing one. A persona is seen only under
PERSONA_VISIBLE_SQL. Counts a caller may read (chats bound, deleted
upstream) count only what the caller's labels reach.
"""
from __future__ import annotations

import contextlib
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api import telegram, telegram_wire
from noctornal_api.collection import (
    _SOURCE_VISIBLE,
    PERSONA_USABLE_SQL,
    PERSONA_VISIBLE_SQL,
    CollectionError,
    CollectionNotFound,
    CollectionService,
    PersonaContext,
    PersonaGate,
    PersonaSuspended,
    PersonaUnavailable,
    RateLimited,
    WorkAbandoned,
    _route_secret,
    _utc,
    active_window,
    persona_session,
    record_outcome,
    secret_in_scope,
)
from noctornal_api.telegram import (
    PERSONA_MIN_GAP_S,
    TELEGRAM_ACT_SECONDS,
    ChatInfo,
    ReferenceRefused,
    TelegramAdapter,
    TelegramChatUnreachable,
    TelegramNameMoved,
    TelegramSecret,
    TelegramWrongAccount,
    run_blocking,
    scope_for,
)

#: The one reading of "usable" with the machine-lock clause taken out: the
#: enrolment gate's. test_telegram_persona_pg holds that it differs from
#: the foundation's by exactly that clause, so a change there fails here.
_LOCK_CLAUSE = " AND a.machine_lock_code IS NULL"
USABLE_IGNORING_LOCK_SQL = PERSONA_USABLE_SQL.replace(_LOCK_CLAUSE, "")

#: The generic refusal for a reference this persona cannot add: an
#: unresolvable reference and a chat that is already a source the caller
#: may not see answer byte-identically, so the answer is no existence
#: oracle.
GENERIC_UNRESOLVED = (
    "This reference could not be added through this persona. Check the name "
    "or id, or ask a collection manager cleared for your unit's Telegram "
    "sources.")

JOIN_NOTICE = (
    "The chat's administrators can now see this persona in the member list "
    "and in the recent actions log, and some groups announce every new "
    "member. Leaving is visible too.")

CREATE_NEXT = ("A security officer confirms this chat under the persona's "
               "authority before it is read.")


class TelegramActError(CollectionError):
    """An act refused with a status and a sentence the route answers as-is."""

    def __init__(self, status: int, sentence: str):
        super().__init__(sentence)
        self.status = status


# ---------------------------------------------------------------------------
# The enrolment gate
# ---------------------------------------------------------------------------

class EnrolmentGate(PersonaGate):
    """PersonaGate's check with one more persona admitted: machine-locked,
    with no credential stored, and usable in every other respect. Every
    other step (the lock, the hours, the authority, the pace, the act
    route) is the foundation's."""

    def check(self) -> dict:
        try:
            return super().check()
        except PersonaUnavailable:
            row = self._c.execute(
                f"""SELECT a.machine_lock_code IS NOT NULL,
                           coalesce(octet_length(a.secret_ciphertext), 0) = 0,
                           {USABLE_IGNORING_LOCK_SQL}
                      FROM collect.collection_account a
                     WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}""",
                {"id": self.persona_id, "clearance": self.clearance}).fetchone()
            if row is None or not (row[0] and row[1] and row[2]):
                raise
        persona = self._c.execute(
            """SELECT a.id, a.handle, a.platform::text, a.platform_uid,
                      a.status, a.cooldown_until, a.machine_hold_until,
                      a.machine_lock_code, a.egress_profile_id,
                      a.fingerprint_profile
                 FROM collect.collection_account a WHERE a.id = %s""",
            (self.persona_id,)).fetchone()
        self.row = {"id": persona[0], "handle": persona[1],
                    "platform": persona[2], "platform_uid": persona[3],
                    "status": persona[4], "cooldown_until": persona[5],
                    "hold_until": persona[6], "lock_code": persona[7],
                    "egress_profile_id": persona[8], "credential": False,
                    "fingerprint": dict(persona[9] or {}), "usable": False,
                    "visible": True}
        return self.row


@contextlib.contextmanager
def enrolment_session(conn: psycopg.Connection, persona_id: UUID, *,
                      actor_id: UUID | None, clearance: str | None,
                      purpose: str, need: str = "PUBLIC_READ",
                      sleep=time.sleep):
    """persona_session for an enrolment or an import, through EnrolmentGate:
    the same six steps in the same order, the same record_outcome before the
    unlock, no credential leased."""
    adapter = TelegramAdapter()
    gate = EnrolmentGate(conn, persona_id, actor_id=actor_id,
                         clearance=clearance, purpose=purpose, source_id=None,
                         need=need, platform="TELEGRAM", needs_secret=False,
                         min_gap_s=PERSONA_MIN_GAP_S, sleep=sleep,
                         adapter=adapter)
    row = gate.check()
    gate.lock()
    try:
        gate.window()
        live = gate.authority()
        gate.pace()
        route = gate.route()
        with _route_secret(route):
            context = PersonaContext(
                persona_id=persona_id, handle=row["handle"],
                platform=row["platform"], platform_uid=row["platform_uid"],
                fingerprint=dict(row["fingerprint"] or {}), authority=live,
                route=route, lease=None)
            try:
                yield context
            except (RateLimited, PersonaSuspended, WorkAbandoned) as exc:
                exc.hold_until = record_outcome(
                    conn, persona_id=persona_id, source_id=None, run_id=None,
                    exc=exc, adapter=adapter)
                raise
    finally:
        gate.release()


# ---------------------------------------------------------------------------
# Running an act
# ---------------------------------------------------------------------------

def _transport(factory, secret: TelegramSecret, route, fingerprint: dict):
    proxy = telegram_wire.proxy_for(route)
    make = factory or telegram_wire.TelethonTransport
    return make(secret, route, dict(fingerprint or {}), proxy=proxy)


def run_act(conn: psycopg.Connection, persona_id: UUID, *, actor_id: UUID,
            clearance: str, purpose: str, source_id: UUID | None, need: str,
            work, transport_factory=None, stopping: bool = False,
            sleep=time.sleep):
    """`await work(transport, context)` as one attended act of the persona,
    through the foundation's persona_session with the caller's clearance.
    Returns what work returned. A session Telegram moved is resealed by the
    lease's compare-and-set."""
    adapter = TelegramAdapter()
    with persona_session(conn, persona_id, actor_id=actor_id,
                         clearance=clearance, purpose=purpose,
                         source_id=source_id, need=need, platform="TELEGRAM",
                         stopping=stopping, needs_secret=True,
                         min_gap_s=PERSONA_MIN_GAP_S, adapter=adapter,
                         sleep=sleep) as ctx:
        secret = TelegramSecret.parse(ctx.lease.value)
        transport = _transport(transport_factory, secret, ctx.route, ctx.fingerprint)

        async def run():
            with secret_in_scope(*secret.secrets()):
                try:
                    return await work(transport, ctx)
                finally:
                    with contextlib.suppress(Exception):
                        await transport.close()

        result = run_blocking(run, TELEGRAM_ACT_SECONDS)
        moved = transport.session_string()
        if moved and moved != secret.session:
            with contextlib.suppress(telegram.TelegramSecretInvalid):
                ctx.lease.reseal(secret.with_session(moved).dump())
        return result


async def _as_persona(transport, ctx) -> None:
    """Open the session and refuse another account than the enrolled one."""
    me = await transport.open()
    if not ctx.platform_uid or me.uid != ctx.platform_uid:
        raise TelegramWrongAccount()


# ---------------------------------------------------------------------------
# Facts for the console
# ---------------------------------------------------------------------------

def hold_facts(row: dict, now: datetime) -> dict | None:
    """A Telegram persona's machine hold or lock in words, from the
    foundation's machine columns."""
    lock = row.get("machine_lock_code")
    if lock:
        words = ("Telegram refused this persona's login: it was used from two "
                 "places at once. Log it out and enrol it again."
                 if lock == "CREDENTIAL_DUPLICATED" else
                 "Telegram refused this persona's login. Log it out and "
                 "enrol it again.")
        return {"kind": lock, "until": None, "words": words}
    until = row.get("machine_hold_until")
    if isinstance(until, str):
        until = datetime.fromisoformat(until)
    if until and until > now:
        words = (f"Telegram asked this persona to pause until {_utc(until)}."
                 if row.get("machine_hold_reason") == "RATE_LIMITED" else
                 f"This persona rests until {_utc(until)} so no second connection "
                 f"starts beside one that may still be open.")
        return {"kind": row.get("machine_hold_reason"), "until": until.isoformat(),
                "words": words}
    return None


def attach_persona_facts(conn: psycopg.Connection, personas: list[dict],
                         clearance: str | None) -> list[dict]:
    """Each Telegram persona row gains a `telegram` object: its account
    id, when its session was enrolled, its egress profile's name, its active
    hours, its hold in words and how many active chats it reads within the
    caller's ceiling. Columns named explicitly, never a secret column."""
    ids = [p["id"] for p in personas if p.get("platform") == "TELEGRAM"]
    if not ids:
        return personas
    rows = {str(r[0]): r for r in conn.execute(
        """SELECT a.id, a.session_enrolled_at,
                  (SELECT count(*) FROM collect.source s
                    WHERE s.collection_account_id = a.id AND s.is_active
                      AND s.kind = 'TELEGRAM'
                      AND (%(clearance)s::core.tlp IS NULL
                           OR s.classification <= %(clearance)s::core.tlp))
             FROM collect.collection_account a
            WHERE a.id = ANY(%(ids)s::uuid[])""",
        {"ids": ids, "clearance": clearance}).fetchall()}
    now = datetime.now(timezone.utc)
    for p in personas:
        row = rows.get(p.get("id"))
        if row is None:
            continue
        p["telegram"] = {
            "platform_uid": p.get("platform_uid"),
            "session_enrolled_at": row[1].isoformat() if row[1] else None,
            "egress_profile_name": p.get("egress_profile_name"),
            "active_window_utc": p.get("active_window_utc"),
            "hold": hold_facts(p, now),
            "chats_bound": int(row[2] or 0),
        }
    return personas


def set_window(conn: psycopg.Connection, persona_id: UUID, window: str | None, *,
               actor_id: UUID, clearance: str) -> dict:
    """A Telegram persona's active hours in UTC, or none. 404 for a persona
    the caller may not see, indistinguishable from a missing one."""
    row = conn.execute(
        f"""SELECT a.platform::text FROM collect.collection_account a
             WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}""",
        {"id": persona_id, "clearance": clearance}).fetchone()
    if row is None:
        raise CollectionNotFound("no such persona, or it is above your clearance")
    if row[0] != "TELEGRAM":
        raise CollectionError("This persona is not a Telegram account.")
    if window is not None:
        try:
            parsed = active_window(window)
        except ValueError:
            parsed = None
        if parsed is None or parsed[0] == parsed[1]:
            raise CollectionError(
                "Active hours are HH:MM-HH:MM in UTC, and not empty.")
        conn.execute(
            """UPDATE collect.collection_account
                  SET fingerprint_profile = fingerprint_profile
                      || jsonb_build_object('active_window_utc', %s::text)
                WHERE id = %s""", (window.strip(), persona_id))
    else:
        conn.execute(
            """UPDATE collect.collection_account
                  SET fingerprint_profile = fingerprint_profile - 'active_window_utc'
                WHERE id = %s""", (persona_id,))
    _audit(conn, actor_id, "PERSONA_WINDOW_SET", "collection_account", persona_id,
           {"active_window_utc": window.strip() if window else None})
    return {"persona_id": str(persona_id),
            "active_window_utc": window.strip() if window else None}


def attach_due_facts(conn: psycopg.Connection, rows: list[dict]) -> list[dict]:
    """Each due Telegram source gains `telegram` {chat, access_mode,
    egress}: the chat's durable id and how it is read, and the reading
    persona's egress profile name when the persona is visible (the row
    already carries the persona, or HIDDEN_PERSONA)."""
    ids = [str(r["id"]) for r in rows if r.get("kind") == "TELEGRAM"]
    if not ids:
        return rows
    found = {str(r[0]): r for r in conn.execute(
        """SELECT c.source_id, c.durable_id, c.access_mode, e.name
             FROM collect.telegram_chat c
             JOIN collect.source s ON s.id = c.source_id
             LEFT JOIN collect.collection_account a ON a.id = s.collection_account_id
             LEFT JOIN collect.egress_profile e ON e.id = a.egress_profile_id
            WHERE c.source_id = ANY(%s::uuid[])""", (ids,)).fetchall()}
    for r in rows:
        row = found.get(str(r.get("id")))
        if row is None:
            continue
        persona = r.get("persona") or {}
        r["telegram"] = {"chat": row[1], "access_mode": row[2],
                         "egress": None if persona.get("hidden") else row[3]}
    return rows


def attach_message_meta(conn: psycopg.Connection, docs: list[dict]) -> list[dict]:
    """Each returned (already label-filtered) Telegram document gains
    `telegram`, its capture record. Reads only the ids given."""
    ids = [d["id"] for d in docs if d.get("source_kind") == "TELEGRAM"]
    if not ids:
        return docs
    found = {str(r[0]): r for r in conn.execute(
        """SELECT document_id, chat_durable_id, message_id, sender_uid,
                  sender_handle_at_capture, post_author, fwd_from_uid,
                  fwd_from_name, reply_to_message_id, topic_id, media_kind,
                  is_service, noforwards, edit_date, deleted_seen_at
             FROM collect.telegram_message
            WHERE document_id = ANY(%s::uuid[])""", (ids,)).fetchall()}
    for d in docs:
        r = found.get(d.get("id"))
        if r is None:
            continue
        d["telegram"] = {
            "chat": r[1], "message_id": r[2], "sender_uid": r[3],
            "sender_handle": r[4], "post_author": r[5], "fwd_from_uid": r[6],
            "fwd_from_name": r[7], "reply_to_message_id": r[8],
            "topic_id": r[9], "media_kind": r[10], "is_service": bool(r[11]),
            "noforwards": bool(r[12]),
            "edit_date": r[13].isoformat() if r[13] else None,
            "deleted_seen_at": r[14].isoformat() if r[14] else None}
    return docs


def attach_target_chats(conn: psycopg.Connection,
                        targets: dict[UUID, list[dict]]) -> None:
    """Each Telegram target an officer is shown gains `chat` {durable
    id, peer type, access mode, name and title at lookup}, read under the
    target's already-filtered source: a Telegram source has no address, so
    without this the confirmer saw only a name the recorder typed
    (2026-09-24)."""
    wanted = [t for rows in targets.values() for t in rows
              if t.get("source_kind") == "TELEGRAM"]
    if not wanted:
        return
    found = {str(r[0]): r for r in conn.execute(
        """SELECT source_id, durable_id, peer_type, access_mode,
                  username_at_resolve, title_at_resolve
             FROM collect.telegram_chat WHERE source_id = ANY(%s::uuid[])""",
        ([t["source_id"] for t in wanted],)).fetchall()}
    for t in wanted:
        r = found.get(t["source_id"])
        if r is not None:
            t["chat"] = {"durable_id": r[1], "peer_type": r[2],
                         "access_mode": r[3], "username_at_resolve": r[4],
                         "title_at_resolve": r[5]}


TELEGRAM_IDLE = "No Telegram source is active, so nothing is sent to Telegram."
TELEGRAM_ACTION = (
    "install the telegram extra, enrol each persona with "
    "scripts/telegram_persona.py, and log out and enrol again each persona "
    "Telegram locked; the ceiling and the egress proxy are reported by the "
    "collection_sources_configured and egress_boundary rows")


def readiness_verdict(conn: psycopg.Connection) -> tuple[bool, str, str]:
    """(ok, evidence, action) for the telegram_collection row: the library,
    the enrolled sessions and the machine locks of the personas that read
    active Telegram sources. Counts, never a chat, a source or a persona
    name: the register is read by user.manage holders who may be below a
    source's label, the same presence disclosure the collection rows make
    (docs/05). The ceiling and the proxy are other rows': one cause, one
    red row."""
    from noctornal_api.wording import agree, count_of

    row = conn.execute(
        """SELECT count(*),
                  count(DISTINCT s.collection_account_id) FILTER (
                    WHERE a.session_enrolled_at IS NULL),
                  count(DISTINCT s.collection_account_id) FILTER (
                    WHERE a.machine_lock_code IS NOT NULL)
             FROM collect.source s
             LEFT JOIN collect.collection_account a ON a.id = s.collection_account_id
            WHERE s.is_active AND s.kind = 'TELEGRAM'
              AND s.parser_key = 'telegram'""").fetchone()
    active, unenrolled, locked = int(row[0]), int(row[1]), int(row[2])
    if not active:
        return True, TELEGRAM_IDLE, ""
    head = (f"{count_of(active, 'Telegram source', 'Telegram sources')} "
            f"{agree(active, 'is', 'are')} active")
    available, library = telegram.client_available()
    problems = []
    if not available:
        problems.append(f"the Telegram client library is not installed, so every "
                        f"poll of {agree(active, 'it', 'them')} is refused")
    if unenrolled:
        problems.append(f"{count_of(unenrolled, 'persona that reads them has', 'personas that read them have')} "
                        f"no enrolled session")
    if locked:
        problems.append(f"{count_of(locked, 'persona that reads them is', 'personas that read them are')} "
                        f"locked by Telegram until enrolled again")
    if problems:
        joined = (problems[0] if len(problems) == 1
                  else ", ".join(problems[:-1]) + " and " + problems[-1])
        return False, f"{head}; {joined}.", TELEGRAM_ACTION
    return True, (f"{head}; {library} Every persona that reads "
                  f"{agree(active, 'it', 'them')} has an enrolled session."), ""


def _audit(conn, actor_id, action: str, object_type: str, object_id,
           detail: dict) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, detail)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, object_type,
         object_id, Json(detail)))


# ---------------------------------------------------------------------------
# Chats
# ---------------------------------------------------------------------------

_CHAT_COLUMNS = (
    "c.source_id, c.peer_type, c.peer_id, c.durable_id, c.access_mode, "
    "c.provenance_class, c.username_at_resolve, c.title_at_resolve, "
    "c.resolved_at, c.access_hash, c.access_hash_account_id, "
    "c.member_since_observed, c.joined_by, c.joined_at, c.is_forum, "
    "c.noforwards, c.migrated_to")


def _chat_row(conn, source_id: UUID, clearance: str) -> dict:
    """A Telegram source and its chat, or CollectionNotFound: a source the
    caller may not see under the foundation's one predicate answers exactly
    like a missing one."""
    row = conn.execute(
        f"""SELECT {_CHAT_COLUMNS}, s.name, s.classification::text,
                   s.collection_account_id, s.is_active, s.parser_config
              FROM collect.telegram_chat c
              JOIN collect.source s ON s.id = c.source_id
             WHERE c.source_id = %(id)s AND {_SOURCE_VISIBLE}""",
        {"id": source_id, "clearance": clearance}).fetchone()
    if row is None:
        raise CollectionNotFound("no such Telegram chat, or it is above your clearance")
    keys = ("source_id", "peer_type", "peer_id", "durable_id", "access_mode",
            "provenance_class", "username_at_resolve", "title_at_resolve",
            "resolved_at", "access_hash", "access_hash_account_id",
            "member_since_observed", "joined_by", "joined_at", "is_forum",
            "noforwards", "migrated_to", "name", "classification",
            "persona_id", "is_active", "parser_config")
    return dict(zip(keys, row, strict=True))


def _chat_info(chat: dict) -> ChatInfo:
    return ChatInfo(peer_type=chat["peer_type"], peer_id=int(chat["peer_id"]),
                    durable_id=chat["durable_id"],
                    access_hash=chat["access_hash"],
                    username=chat["username_at_resolve"],
                    title=chat["title_at_resolve"],
                    is_forum=bool(chat["is_forum"]),
                    noforwards=bool(chat["noforwards"]))


def _refuse_offline_problems(*, classification: str | None) -> None:
    """The refusal-equivalent sentences before any persona act: the library,
    the Telegram ceiling on the requested label (invariant 8 through the
    foundation's COLLECTION_TARGET), and a configured egress proxy."""
    from noctornal_api import egress
    from noctornal_api.collection_authority import ceiling_refusal

    available, sentence = telegram.client_available()
    if not available:
        raise TelegramActError(409, sentence)
    if classification is not None:
        refusal = ceiling_refusal(SimpleNamespace(kind="TELEGRAM",
                                                  classification=classification))
        if refusal:
            raise TelegramActError(409, refusal)
    if not egress.boundary().in_force:
        raise TelegramActError(409, telegram.NO_PROXY_SENTENCE)


async def _reach(transport, chat: dict, persona_id: UUID) -> ChatInfo:
    """The chat as the persona sees it: by its own access hash, by the name
    it was resolved by (a recycled name refused), or from its conversation
    list."""
    info = _chat_info(chat)
    own = (info.access_hash is not None
           and chat["access_hash_account_id"] == persona_id)
    if info.peer_type == "CHAT" or own:
        found = await transport.lookup(info)
    elif info.username:
        found = await transport.resolve_username(info.username)
    else:
        found = await transport.find_dialog(info.durable_id)
        if found is None:
            raise TelegramChatUnreachable()
    if found.durable_id != info.durable_id:
        raise TelegramNameMoved()
    return found


class TelegramChats:
    """The chat routes' service. `transport_factory` replaces the Telethon
    transport (the tests inject a fake; nothing in production passes it)."""

    def __init__(self, conn: psycopg.Connection, *, adapters=None,
                 transport_factory=None, sleep=time.sleep):
        self._c = conn
        self._adapters = adapters
        self._factory = transport_factory
        self._sleep = sleep

    def _service(self) -> CollectionService:
        from noctornal_api.collection import default_adapters

        return CollectionService(self._c, self._adapters or default_adapters())

    # -- create ---------------------------------------------------------------

    def create(self, *, persona_id: UUID, ref: str, name: str,
               classification: str, default_reliability: str,
               access_mode: str, poll_interval_s: int, jitter_pct: int,
               max_rps: float, actor_id: UUID, clearance: str) -> dict:
        """Look the chat up as the persona, then create the source and its
        chat row in one transaction."""
        try:
            parsed = telegram.parse_chat_reference(ref)
        except ReferenceRefused as exc:
            raise TelegramActError(400, str(exc)) from None
        if access_mode not in ("PUBLIC_READ", "MEMBER"):
            raise TelegramActError(400, "The access mode is PUBLIC_READ or MEMBER.")
        if (parsed.durable_id or "").startswith("g:") and access_mode == "PUBLIC_READ":
            raise TelegramActError(400, "Basic groups are never public. Add it "
                                        "as a member chat.")
        _refuse_offline_problems(classification=classification)
        need = "PUBLIC_READ" if parsed.by_username else "MEMBER_READ"

        async def work(transport, ctx):
            await _as_persona(transport, ctx)
            if parsed.by_username:
                return await transport.resolve_username(parsed.username), "username"
            return await transport.find_dialog(parsed.durable_id), "dialog"

        try:
            found, via = run_act(
                self._c, persona_id, actor_id=actor_id, clearance=clearance,
                purpose="resolve a Telegram chat", source_id=None, need=need,
                work=work, transport_factory=self._factory, sleep=self._sleep)
        except (TelegramChatUnreachable, TelegramNameMoved):
            raise TelegramActError(422, GENERIC_UNRESOLVED) from None
        if found is None:
            raise TelegramActError(422, GENERIC_UNRESOLVED)
        existing = self._c.execute(
            f"""SELECT s.id, s.name, ({_SOURCE_VISIBLE})
                  FROM collect.telegram_chat c
                  JOIN collect.source s ON s.id = c.source_id
                 WHERE c.durable_id = %(durable)s""",
            {"durable": found.durable_id, "clearance": clearance}).fetchone()
        if existing is not None and not existing[2]:
            _audit(self._c, actor_id, "TELEGRAM_CHAT_DUPLICATE_HIDDEN", "source",
                   existing[0], {"existing_source_id": str(existing[0])})
            raise TelegramActError(422, GENERIC_UNRESOLVED)
        if existing is not None:
            raise TelegramActError(
                409, f"This chat is already a source: {existing[1]}. Resume it "
                     f"there rather than adding it twice.")
        mode = access_mode
        notice = None
        if found.is_member and mode == "PUBLIC_READ":
            mode = "MEMBER"
            notice = ("The persona is already a member of this chat, so it is "
                      "added as a member chat and needs a member authority.")
        if found.peer_type == "CHAT" and mode == "PUBLIC_READ":
            raise TelegramActError(400, "Basic groups are never public. Add it "
                                        "as a member chat.")
        with self._c.transaction():
            source = self._service().create_source(
                kind="TELEGRAM", name=name, base_url=None, parser_key="telegram",
                classification=classification,
                default_reliability=default_reliability,
                poll_interval_s=poll_interval_s, jitter_pct=jitter_pct,
                max_rps=max_rps, parser_config={"access_mode": mode},
                collection_account_id=persona_id, egress_profile_id=None,
                actor_id=actor_id, clearance=clearance)
            has_hash = found.access_hash is not None and found.peer_type != "CHAT"
            self._c.execute(
                """INSERT INTO collect.telegram_chat
                       (source_id, peer_type, peer_id, durable_id, access_mode,
                        provenance_class, username_at_resolve, title_at_resolve,
                        resolved_by, access_hash, access_hash_account_id,
                        member_since_observed, is_forum, noforwards)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                           CASE WHEN %s THEN now() END, %s, %s)""",
                (source["id"], found.peer_type, found.peer_id, found.durable_id,
                 mode, "PERSONA_PARTY" if mode == "MEMBER" else "OPEN_GROUP",
                 parsed.username if parsed.by_username else None,
                 telegram.clean_name(found.title),
                 actor_id, found.access_hash if has_hash else None,
                 persona_id if has_hash else None,
                 bool(mode == "MEMBER" and found.is_member),
                 bool(found.is_forum), bool(found.noforwards)))
            _audit(self._c, actor_id, "TELEGRAM_CHAT_RESOLVED", "source",
                   source["id"], {"durable_id": found.durable_id, "via": via})
        return {"source": source, "chat": self.view(UUID(source["id"]), clearance),
                "notice": notice, "next": CREATE_NEXT}

    # -- the membership acts --------------------------------------------------

    def join(self, source_id: UUID, *, note: str, actor_id: UUID,
             clearance: str) -> dict:
        chat = _chat_row(self._c, source_id, clearance)
        if chat["access_mode"] != "MEMBER" or chat["peer_type"] == "CHAT" \
                or not chat["username_at_resolve"]:
            raise TelegramActError(
                409, "Only a member chat added by its public name can be joined "
                     "from here. Join any other chat from the persona's own "
                     "device, then use Check membership.")
        if chat["member_since_observed"] is not None:
            raise TelegramActError(409, "The persona is already a member of this chat.")
        _refuse_offline_problems(classification=chat["classification"])
        persona_id = chat["persona_id"]

        async def work(transport, ctx):
            await _as_persona(transport, ctx)
            reached = await _reach(transport, chat, persona_id)
            return await transport.join(reached)

        joined = run_act(self._c, persona_id, actor_id=actor_id,
                         clearance=clearance, purpose="join a Telegram chat",
                         source_id=source_id, need="MEMBER_READ", work=work,
                         transport_factory=self._factory, sleep=self._sleep)
        with self._c.transaction():
            has_hash = joined.access_hash is not None
            self._c.execute(
                """UPDATE collect.telegram_chat
                      SET member_since_observed = now(), joined_by = %s,
                          joined_at = now(),
                          access_hash = coalesce(%s, access_hash),
                          access_hash_account_id = CASE WHEN %s THEN %s
                              ELSE access_hash_account_id END
                    WHERE source_id = %s""",
                (actor_id, joined.access_hash if has_hash else None, has_hash,
                 persona_id, source_id))
            _audit(self._c, actor_id, "TELEGRAM_CHAT_JOINED", "source", source_id,
                   {"durable_id": chat["durable_id"], "note": note.strip()})
        return {"chat": self.view(source_id, clearance), "notice": JOIN_NOTICE}

    def check_membership(self, source_id: UUID, *, actor_id: UUID,
                         clearance: str) -> dict:
        """Reads the persona's own view of a member chat and never joins."""
        chat = _chat_row(self._c, source_id, clearance)
        if chat["access_mode"] != "MEMBER":
            raise TelegramActError(409, "Membership is checked for a member chat.")
        _refuse_offline_problems(classification=chat["classification"])
        persona_id = chat["persona_id"]

        async def work(transport, ctx):
            await _as_persona(transport, ctx)
            return await _reach(transport, chat, persona_id)

        seen = run_act(self._c, persona_id, actor_id=actor_id,
                       clearance=clearance,
                       purpose="check a Telegram chat's membership",
                       source_id=source_id, need="MEMBER_READ", work=work,
                       transport_factory=self._factory, sleep=self._sleep)
        member = bool(seen.is_member)
        with self._c.transaction():
            if member:
                self._c.execute(
                    """UPDATE collect.telegram_chat
                          SET member_since_observed = coalesce(member_since_observed, now())
                        WHERE source_id = %s""", (source_id,))
            else:
                self._c.execute(
                    """UPDATE collect.telegram_chat
                          SET member_since_observed = NULL, joined_by = NULL,
                              joined_at = NULL
                        WHERE source_id = %s""", (source_id,))
            _audit(self._c, actor_id, "TELEGRAM_CHAT_MEMBERSHIP_SEEN", "source",
                   source_id, {"durable_id": chat["durable_id"], "member": member})
        return {"chat": self.view(source_id, clearance), "member": member,
                "notice": ("Telegram reports the persona a member, so the chat is "
                           "read as one once its member authority is confirmed."
                           if member else
                           "Telegram does not report the persona a member. Join "
                           "the chat first; nothing was joined from here.")}

    def mark_member(self, source_id: UUID, *, reason: str, actor_id: UUID,
                    clearance: str) -> dict:
        """PUBLIC_READ to MEMBER, the one identity change the chat's guard
        permits and only in this direction; then the membership check. When
        no member authority covers the chat yet, the mark stands and the
        check's refusal is the answer."""
        chat = _chat_row(self._c, source_id, clearance)
        if chat["access_mode"] != "PUBLIC_READ":
            raise TelegramActError(409, "This chat is already read as a member.")
        with self._c.transaction():
            self._c.execute(
                """UPDATE collect.telegram_chat
                      SET access_mode = 'MEMBER', provenance_class = 'PERSONA_PARTY'
                    WHERE source_id = %s""", (source_id,))
            self._c.execute(
                """UPDATE collect.source
                      SET parser_config = parser_config
                          || '{"access_mode": "MEMBER"}'::jsonb
                    WHERE id = %s""", (source_id,))
            _audit(self._c, actor_id, "SOURCE_ACCESS_MODE_CHANGED", "source",
                   source_id, {"from": "PUBLIC_READ", "to": "MEMBER",
                               "reason": reason.strip()})
        answer = self.check_membership(source_id, actor_id=actor_id,
                                       clearance=clearance)
        answer["marked"] = True
        return answer

    def rebind(self, source_id: UUID, *, persona_id: UUID, reason: str,
               actor_id: UUID, clearance: str) -> dict:
        """Read the chat through another Telegram persona. The resolution
        through the new persona also reads its membership, so a member chat
        the new persona is already in is readable again at once."""
        chat = _chat_row(self._c, source_id, clearance)
        if chat["migrated_to"]:
            raise TelegramActError(409, "This group became a supergroup; add the "
                                        "supergroup as a new chat instead.")
        if persona_id == chat["persona_id"]:
            raise TelegramActError(409, "This chat is read by that persona already.")
        row = self._c.execute(
            f"""SELECT a.platform::text, a.session_enrolled_at, a.status
                  FROM collect.collection_account a
                 WHERE a.id = %(id)s AND {PERSONA_VISIBLE_SQL}""",
            {"id": persona_id, "clearance": clearance}).fetchone()
        if row is None:
            raise CollectionNotFound("no such persona, or it is above your clearance")
        if row[0] != "TELEGRAM" or row[1] is None or row[2] == "BURNED":
            raise TelegramActError(
                409, "The new persona must be a Telegram persona with an enrolled "
                     "session, and not burnt.")
        _refuse_offline_problems(classification=chat["classification"])

        async def work(transport, ctx):
            await _as_persona(transport, ctx)
            info = _chat_info(chat)
            if info.peer_type != "CHAT" and info.username:
                found = await transport.resolve_username(info.username)
            else:
                found = await transport.find_dialog(info.durable_id)
                if found is None:
                    raise TelegramChatUnreachable(
                        "The new persona cannot see this chat. It must be in the "
                        "chat, joined from its own device, before it can read it.")
            if found.durable_id != info.durable_id:
                raise TelegramNameMoved()
            return found

        found = run_act(self._c, persona_id, actor_id=actor_id,
                        clearance=clearance, purpose="rebind a Telegram chat",
                        source_id=None, need=scope_for(chat["access_mode"]),
                        work=work, transport_factory=self._factory,
                        sleep=self._sleep)
        member = bool(chat["access_mode"] == "MEMBER" and found.is_member)
        has_hash = found.access_hash is not None and found.peer_type != "CHAT"
        with self._c.transaction():
            bound = self._service().bind_source(
                source_id, persona_id=persona_id, egress_profile_id=None,
                reason=reason, reset_cursor=chat["peer_type"] == "CHAT",
                actor_id=actor_id, clearance=clearance)
            self._c.execute(
                """UPDATE collect.telegram_chat
                      SET access_hash = %s, access_hash_account_id = %s,
                          joined_by = NULL, joined_at = NULL,
                          member_since_observed = CASE WHEN %s THEN now() END
                    WHERE source_id = %s""",
                (found.access_hash if has_hash else None,
                 persona_id if has_hash else None, member, source_id))
            _audit(self._c, actor_id, "SOURCE_PERSONA_CHANGED", "source", source_id,
                   {"from": str(chat["persona_id"]) if chat["persona_id"] else None,
                    "to": str(persona_id), "reason": reason.strip()})
        notice = ("The new persona needs its own confirmed authority target for "
                  "this chat before the next poll.")
        if chat["access_mode"] == "MEMBER" and not member:
            notice += " It is not a member of this chat: it must join first."
        if chat["peer_type"] == "CHAT":
            notice += (" Message ids in a basic group are per account, so reading "
                       "restarts from the new account's newest messages.")
        return {"chat": self.view(source_id, clearance), "binding": bound,
                "notice": notice}

    # -- stop and resume --------------------------------------------------------

    def set_active(self, source_id: UUID, *, active: bool, reason: str,
                   actor_id: UUID, clearance: str) -> dict:
        chat = _chat_row(self._c, source_id, clearance)
        if active and chat["migrated_to"]:
            raise TelegramActError(409, "This group became a supergroup; add the "
                                        "supergroup as a new chat instead.")
        self._service().set_source_active(source_id, active=active, reason=reason,
                                          actor_id=actor_id, clearance=clearance)
        return {"chat": self.view(source_id, clearance)}

    # -- reading --------------------------------------------------------------

    def view(self, source_id: UUID, clearance: str) -> dict:
        rows = self.listing(clearance=clearance, compartments=None,
                            only=source_id)["chats"]
        if not rows:
            raise CollectionNotFound("no such Telegram chat, or it is above your clearance")
        return rows[0]

    def listing(self, *, clearance: str, compartments: frozenset[str] | None,
                only: UUID | None = None) -> dict:
        """Telegram sources within the caller's labels, with their chat, the
        persona that reads each (hidden when the caller may not see it), the
        egress profile's name, the authority state in a sentence that names
        no source, the last message read and how many messages were seen
        deleted upstream (counted only within the caller's labels)."""
        from noctornal_api.collection import HIDDEN_PERSONA
        from noctornal_api.collection_authority import (
            AuthorityMissing,
            CollectionAuthorityService,
            source_ceiling,
        )

        held = sorted(compartments or [])
        rows = self._c.execute(
            f"""SELECT {_CHAT_COLUMNS}, s.name, s.classification::text,
                       s.collection_account_id, s.is_active, s.blocked_reason,
                       s.parser_config, a.handle, a.status,
                       {PERSONA_VISIBLE_SQL}, e.name,
                       (SELECT r.cursor->>'last_message_id'
                          FROM collect.collection_run r
                         WHERE r.source_id = s.id AND r.status IN ('OK', 'PARTIAL')
                         ORDER BY r.started_at DESC NULLS LAST, r.id DESC LIMIT 1),
                       (SELECT count(*) FROM collect.document d
                         WHERE d.source_id = s.id AND d.is_deleted_upstream
                           AND d.purged_at IS NULL
                           AND d.classification <= %(clearance)s::core.tlp
                           AND d.compartments <@ %(held)s::text[]),
                       s.poll_interval_s, s.max_rps
                  FROM collect.telegram_chat c
                  JOIN collect.source s ON s.id = c.source_id
                  LEFT JOIN collect.collection_account a
                         ON a.id = s.collection_account_id
                  LEFT JOIN collect.egress_profile e ON e.id = a.egress_profile_id
                 WHERE {_SOURCE_VISIBLE}
                   AND (%(only)s::uuid IS NULL OR s.id = %(only)s)
                 ORDER BY s.is_active DESC, s.name""",
            {"clearance": clearance, "held": held, "only": only}).fetchall()
        authority = CollectionAuthorityService(self._c)
        chats = []
        for r in rows:
            (source_id, peer_type, _peer_id, durable_id, access_mode, provenance,
             username, title, resolved_at, _hash, _hash_owner, member_since,
             joined_by, joined_at, is_forum, noforwards, migrated_to, name,
             label, persona_id, is_active, blocked, config, handle, status,
             persona_visible, egress_name, last_id, deleted, interval,
             max_rps) = r
            persona = None
            if persona_id is not None:
                persona = ({"id": str(persona_id), "handle": handle, "status": status}
                           if persona_visible else dict(HIDDEN_PERSONA))
            try:
                live = authority.require(
                    persona_id=persona_id, source_id=source_id,
                    need=scope_for(access_mode), clearance=clearance)
                auth = {"live": True, "scope": live.scope,
                        "sentence": f"An authority is in force until {_utc(live.valid_until)}."}
            except AuthorityMissing as exc:
                auth = {"live": False, "scope": None, "sentence": str(exc)}
            chats.append({
                "source_id": str(source_id), "name": name, "classification": label,
                "is_active": bool(is_active), "blocked_reason": blocked,
                "durable_id": durable_id, "peer_type": peer_type,
                "access_mode": access_mode, "provenance_class": provenance,
                "username_at_resolve": username, "title_at_resolve": title,
                "resolved_at": resolved_at.isoformat() if resolved_at else None,
                "member_since_observed": member_since.isoformat() if member_since else None,
                "joined": joined_at.isoformat() if joined_at else None,
                "is_forum": bool(is_forum), "noforwards": bool(noforwards),
                "migrated_to": migrated_to, "persona": persona,
                "egress_profile_name": None if (persona or {}).get("hidden") else egress_name,
                "authority": auth,
                "last_message_id": int(last_id) if last_id and str(last_id).isdigit() else None,
                "deleted_upstream": int(deleted or 0),
                "poll_interval_s": interval, "max_rps": float(max_rps or 0),
            })
        available, library = telegram.client_available()
        ceiling, sentence = source_ceiling("TELEGRAM")
        from noctornal_api import egress

        in_force = egress.boundary().in_force
        return {"chats": chats, "count": len(chats),
                "telegram": {"available": available, "library": library,
                             "ceiling": ceiling, "ceiling_sentence": sentence,
                             "proxy": in_force,
                             "sentence": (library if not available else
                                          sentence if ceiling is None else
                                          telegram.NO_PROXY_SENTENCE if not in_force
                                          else None)}}

