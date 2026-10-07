"""The persona act queue: what the API asks the collector to do, and the one
runner both of them use (ROADMAP-REMAINING "A collector process",
2026-10-02).

## Why this exists

Until 2026-10-02 every attended persona act ran inside the API process, on
the request thread, with the key that opens every persona credential in the
same process. The owner decided on 2026-10-02 to build the collector that
decision 30 deferred: the API holds no persona key and cannot open a
persona credential, and a separate collector process
(`scripts/collector.py`) does everything that needs one. That reverses the
recorded "no worker process and no queue" for this one purpose, on purpose.

So a route that would make a persona act writes a row in
`collect.persona_act` (0156) instead: the kind, the source, the request's
own parameters, who asked, from which session and when their second factor
was last satisfied, and the label the act is held at. Never a secret. The
collector claims it, runs exactly the code the route used to run, and
writes the answer the route would have given into the row. The route waits
a short bounded time (NOCTORNAL_ACT_WAIT_SECONDS, at most 25 seconds) and
answers with the finished act, or 202 with the act still queued; the
console then follows it on `GET /collection/acts/{id}`.

## What the collector re-checks, at the moment it runs an act

The route checked everything when it was asked. The act may run minutes
later, so before anything else the collector asks again, as the person who
asked: that their session is still live; every global permission the route
demanded, through the gate the route used (`deps.authorize_global`), with
the second factor the request carried, so a step-up older than its
freshness window is refused; the blocking readiness checks
(`refuse_unready`); and their ceiling now, which must still reach the act's
label. Then the act itself runs the persona gate it always ran: the persona
visible, usable and free, inside its hours, a live collection authority
confirmed by a second person (docs/16 L3 holds exactly as before), the
persona's own route on the egress proxy. A persona another runner holds is
not a refusal here: the act goes back in the queue for a few seconds, until
it expires.

## Expiry, and an act whose collector died

An attended act runs while somebody is waiting for it: one not started
within NOCTORNAL_ACT_TTL_SECONDS (15 minutes by default, the step-up
window) is EXPIRED, never run late. One left RUNNING by a collector that
stopped is FAILED with "outcome unknown" and never repeated, because
joining a chat twice, or half of a rebind, is not something to retry
blindly.

## Inline mode, development only

NOCTORNAL_COLLECTOR_INLINE=1 runs the claimed act inside the API process
the moment it is queued, through the same runner, on the request's own
connection. That is the development and Windows shape, where there is no
collector process and the API holds the persona key in .env.local. It is
refused at boot under NOCTORNAL_ENV=production (config.py) and ignored
there at run time.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import psycopg
from psycopg.types.json import Json, Jsonb

from noctornal_api.db import SystemPurpose, system_connection
from noctornal_api.wording import count_of

log = logging.getLogger(__name__)

INLINE_ENV = "NOCTORNAL_COLLECTOR_INLINE"
WAIT_ENV = "NOCTORNAL_ACT_WAIT_SECONDS"
TTL_ENV = "NOCTORNAL_ACT_TTL_SECONDS"
#: What the API notifies and the collector LISTENs on.
NOTIFY_CHANNEL = "noctornal_persona_act"

DEFAULT_WAIT_S = 8.0
MAX_WAIT_S = 25.0
DEFAULT_TTL_S = 900
MIN_TTL_S = 60
MAX_TTL_S = 3600
#: A RUNNING act older than this has lost its collector: the longest act
#: (a forum poll's whole budget, or a Telegram act and its pacing) is well
#: inside it.
STALE_S = 900
#: How long a busy persona puts an act back in the queue for.
BUSY_RETRY_S = 15
_POLL_EVERY_S = 0.25

LIVE = ("PENDING", "RUNNING")
FINISHED = ("DONE", "REFUSED", "FAILED", "EXPIRED", "CANCELLED")


@dataclass(frozen=True)
class ActKind:
    #: What the console calls it.
    what: str
    #: Every global permission the route demands, with whether it forces a
    #: fresh second factor (join does).
    permissions: tuple[tuple[str, bool], ...]


_MANAGE = (("source.manage", False), ("collection.run", False),
           ("collection_account.manage", False))

KINDS: dict[str, ActKind] = {
    "TELEGRAM_RESOLVE": ActKind("Look up a Telegram chat and add it", _MANAGE),
    "TELEGRAM_JOIN": ActKind("Join a Telegram chat", (("collection.run", True),)),
    "TELEGRAM_MEMBERSHIP": ActKind(
        "Check a Telegram chat's membership",
        (("source.manage", False), ("collection.run", False))),
    "TELEGRAM_MARK_MEMBER": ActKind(
        "Mark a Telegram chat as a member chat and check membership", _MANAGE),
    "TELEGRAM_REBIND": ActKind("Read a Telegram chat through another persona",
                               _MANAGE),
    "SOURCE_POLL": ActKind("Poll a source a persona reads",
                           (("collection.run", False),)),
    # A stop, asked by the persona's stop route before it writes the stop:
    # the board's own sign-out needs the sealed session, which only the
    # collector can open, so the API asks and waits a bounded time (merged
    # with the authenticated forum path, 2026-10-03; migration 0165).
    "FORUM_SIGN_OUT": ActKind("Sign a forum persona out of its boards",
                              (("collection_account.manage", False),)),
}

#: The acts that are a stop: never held to the readiness register.
STOP_KINDS = frozenset({"FORUM_SIGN_OUT"})

SESSION_ENDED = ("The session that asked for this act ended before the collector "
                 "ran it, so it was not run. Sign in and ask again.")
LABEL_ABOVE = ("This act is held above your clearance now, so it was not run.")
OUTCOME_UNKNOWN = ("The collector stopped while it ran this act, so whether the "
                   "platform saw it is not known. Nothing repeats it on its own: "
                   "check the chat or the source, and ask again if it is needed.")
FAILED_SENTENCE = ("The collector could not complete this act. Its log names the "
                   "act; nothing was retried.")
CANCELLED_SENTENCE = "You cancelled this act before the collector ran it."
QUEUED_NOTICE = ("The collector runs this act. It is listed under Persona acts, "
                 "with its outcome once it has run.")


def _expired_sentence(ttl: int) -> str:
    minutes = max(1, ttl // 60)
    return (f"The collector did not start this act within "
            f"{count_of(minutes, 'minute', 'minutes')} of the request, so it was "
            f"not run: an attended act runs while somebody is waiting for it. "
            f"Ask again.")


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _production() -> bool:
    return os.environ.get("NOCTORNAL_ENV", "").strip().lower() == "production"


def inline_requested(env=None) -> bool:
    """Whether the inline mode is ASKED for: the one reading of the
    variable, which config.py's boot refusal borrows."""
    return _truthy((env if env is not None else os.environ).get(INLINE_ENV, ""))


def inline_mode() -> bool:
    """Development's inline mode. Never in production, whatever is set:
    the boot refusal comes first, and this is the second line."""
    return inline_requested() and not _production()


def wait_seconds() -> float:
    raw = os.environ.get(WAIT_ENV, "").strip()
    try:
        value = float(raw) if raw else DEFAULT_WAIT_S
    except ValueError:
        value = DEFAULT_WAIT_S
    return max(0.0, min(MAX_WAIT_S, value))


def ttl_seconds() -> int:
    raw = os.environ.get(TTL_ENV, "").strip()
    try:
        value = int(raw) if raw else DEFAULT_TTL_S
    except ValueError:
        value = DEFAULT_TTL_S
    return max(MIN_TTL_S, min(MAX_TTL_S, value))


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------

_COLUMNS = ("id, kind, source_id, classification::text, params, requested_by, "
            "session_id, mfa_satisfied_at, requested_at, not_before, expires_at, "
            "status, attempts, claimed_by, claimed_at, finished_at, result")
_KEYS = ("id", "kind", "source_id", "classification", "params", "requested_by",
         "session_id", "mfa_satisfied_at", "requested_at", "not_before",
         "expires_at", "status", "attempts", "claimed_by", "claimed_at",
         "finished_at", "result")


def _row(r) -> dict | None:
    if r is None:
        return None
    act = dict(zip(_KEYS, r, strict=True))
    act["params"] = dict(act["params"] or {})
    return act


def _jsonable(value):
    """Parameters and bodies as JSON: UUIDs and times as text."""
    return json.loads(json.dumps(value, default=str))


def dedupe_key(kind: str, source_id: UUID | None, params: dict) -> str:
    """What makes two asks the same act: the kind, the SOURCE and the
    parameters. The source is in it because the routes pass it beside the
    parameters, never inside them (verify:g38, 2026-10-03): without it a
    membership check of chat B, a Poll now of source B or a join of B with
    the same note, asked while A's was live, was answered with A's act and
    nothing was queued for B."""
    canonical = json.dumps({"kind": kind,
                            "source_id": str(source_id) if source_id else None,
                            "params": _jsonable(params)},
                           sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _audit(conn, actor_id, action: str, act_id, detail: dict) -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, detail)
           VALUES (%s, %s, %s, 'persona_act', %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, act_id,
         Json(detail)))


#: A PENDING row still before its expiry, or a RUNNING row claimed within
#: STALE_S: the only twins an ask may be answered with (verify:g38,
#: 2026-10-03). An expired PENDING act or a RUNNING act a dead runner left
#: is no act any more, whatever the sweep has not yet written.
_LIVE_SQL = ("((status = 'PENDING' AND expires_at > clock_timestamp()) "
             "OR (status = 'RUNNING' AND claimed_at >= clock_timestamp() "
             "- make_interval(secs => %(stale)s)))")
_DEAD_SQL = ("((status = 'PENDING' AND expires_at <= clock_timestamp()) "
             "OR (status = 'RUNNING' AND claimed_at < clock_timestamp() "
             "- make_interval(secs => %(stale)s)))")


def _twin(conn, user_id: UUID, kind: str, key: str, which: str) -> dict | None:
    return _row(conn.execute(
        f"""SELECT {_COLUMNS} FROM collect.persona_act
             WHERE requested_by = %(me)s AND kind = %(kind)s
               AND dedupe_key = %(key)s AND {which}
             LIMIT 1""",
        {"me": user_id, "kind": kind, "key": key, "stale": STALE_S}).fetchone())


def _live_twin(conn, user_id: UUID, kind: str, key: str) -> dict | None:
    return _twin(conn, user_id, kind, key, _LIVE_SQL)


def submit(conn: psycopg.Connection, *, user_id: UUID, session_id: UUID | None,
           mfa_at: datetime | None, kind: str, params: dict, classification: str,
           source_id: UUID | None) -> dict:
    """Queue one act on the request connection (the request role's INSERT
    policy admits only the caller's own PENDING row within their ceiling).
    The same act asked again while the first is live is the first act: a
    double click is one act.

    A twin that is past its expiry, or RUNNING with a runner that died, is
    swept first, as the system purpose, so the new ask is a new act rather
    than the dead one answered again (verify:g38, 2026-10-03). In
    development's inline mode nothing else ever sweeps; in production the
    collector does too, and this only reaches the caller's own dead twin
    before the unique index would refuse the new row."""
    if kind not in KINDS:
        raise ValueError(f"no persona act is called {kind!r}")
    clean = _jsonable(params)
    key = dedupe_key(kind, source_id, clean)
    act = None
    for attempt in (1, 2):
        twin = _live_twin(conn, user_id, kind, key)
        if twin is not None:
            return twin
        if _twin(conn, user_id, kind, key, _DEAD_SQL) is not None:
            with system_connection(SystemPurpose.PERSONA_ACTS, reuse=conn) as sc:
                sweep(sc)
        try:
            # requested_at and expires_at from ONE clock reading, so the
            # window is exactly the TTL and never a microsecond over the
            # CHECK that caps it at MAX_TTL_S (persona_act_window,
            # 2026-10-03).
            act = _row(conn.execute(
                f"""INSERT INTO collect.persona_act
                       (kind, source_id, classification, params, dedupe_key,
                        requested_by, session_id, mfa_satisfied_at,
                        requested_at, not_before, expires_at)
                    SELECT %s, %s, %s::core.tlp, %s, %s, %s, %s, %s, t, t,
                           t + make_interval(secs => %s)
                      FROM (SELECT clock_timestamp() AS t) AS now_
                    RETURNING {_COLUMNS}""",
                (kind, source_id, classification, Jsonb(clean), key, user_id,
                 session_id, mfa_at, ttl_seconds())).fetchone())
            break
        except psycopg.errors.UniqueViolation:
            # Either a live twin won the race (answered at the top of the
            # next pass), or a twin died between the two reads above and
            # still holds the unique index until it is swept (swept there,
            # then one more try). Twice is a real conflict.
            if attempt == 2:
                raise
    conn.execute("SELECT pg_notify(%s, %s)", (NOTIFY_CHANNEL, str(act["id"])))
    _audit(conn, user_id, "PERSONA_ACT_QUEUED", act["id"], {"kind": kind})
    return act


def read(conn: psycopg.Connection, act_id: UUID, *, user_id: UUID,
         clearance: str | None = None) -> dict | None:
    """One act of the caller's, or None: another person's act and one held
    above the caller answer alike."""
    return _row(conn.execute(
        f"""SELECT {_COLUMNS} FROM collect.persona_act
             WHERE id = %(id)s AND requested_by = %(me)s
               AND (%(clr)s::core.tlp IS NULL OR classification <= %(clr)s::core.tlp)""",
        {"id": act_id, "me": user_id, "clr": clearance}).fetchone())


def wait(conn: psycopg.Connection, act_id: UUID, *, user_id: UUID,
         seconds: float, clock=time.monotonic, sleep=time.sleep) -> dict:
    """The act once finished, or as it stands when `seconds` run out. Reads
    the row on the request connection (autocommit, so each read is fresh);
    never holds a transaction while it waits."""
    deadline = clock() + max(0.0, seconds)
    while True:
        act = read(conn, act_id, user_id=user_id)
        if act is None or act["status"] in FINISHED or clock() >= deadline:
            return act
        sleep(min(_POLL_EVERY_S, max(0.0, deadline - clock())))


def listing(conn: psycopg.Connection, *, user_id: UUID, clearance: str,
            status: str | None = None, limit: int = 50) -> list[dict]:
    rows = conn.execute(
        f"""SELECT {_COLUMNS} FROM collect.persona_act
             WHERE requested_by = %(me)s
               AND classification <= %(clr)s::core.tlp
               AND (%(status)s::text IS NULL OR status = %(status)s)
             ORDER BY requested_at DESC LIMIT %(limit)s""",
        {"me": user_id, "clr": clearance, "status": status,
         "limit": limit}).fetchall()
    return [_row(r) for r in rows]


def public(act: dict) -> dict:
    """What a person is shown of an act: never the parameters (a chat
    reference is the request's own words, and the console has them), never
    the session."""
    result = act.get("result") or {}
    problem = result.get("problem")
    body = result.get("body") or {}
    outcome = None
    if act["status"] == "DONE":
        outcome = body.get("notice") or "Done."
    elif problem:
        outcome = problem.get("detail") or problem.get("title")

    def iso(value):
        return value.isoformat() if isinstance(value, datetime) else value

    return {"id": str(act["id"]), "kind": act["kind"],
            "what": KINDS[act["kind"]].what, "status": act["status"],
            "source_id": str(act["source_id"]) if act["source_id"] else None,
            "classification": act["classification"],
            "requested_at": iso(act["requested_at"]),
            "started_at": iso(act["claimed_at"]),
            "finished_at": iso(act["finished_at"]),
            "expires_at": iso(act["expires_at"]),
            "attempts": act["attempts"], "outcome": outcome,
            "problem": problem}


def cancel(conn: psycopg.Connection, act_id: UUID, *, user_id: UUID,
           clearance: str) -> tuple[dict | None, bool]:
    """Cancel one of the caller's acts while it is still PENDING: (the
    act, whether this call cancelled it). None for an act the caller may
    not see; False when it had already started or finished."""
    act = read(conn, act_id, user_id=user_id, clearance=clearance)
    if act is None or act["status"] != "PENDING":
        return act, False
    with system_connection(SystemPurpose.PERSONA_ACTS, reuse=conn) as sc:
        done = _row(sc.execute(
            f"""UPDATE collect.persona_act
                   SET status = 'CANCELLED', finished_at = clock_timestamp(),
                       result = %s
                 WHERE id = %s AND requested_by = %s AND status = 'PENDING'
                 RETURNING {_COLUMNS}""",
            (Jsonb({"problem": {"status": 409, "title": "Cancelled",
                                "detail": CANCELLED_SENTENCE}}),
             act_id, user_id)).fetchone())
        if done is not None:
            _audit(sc, user_id, "PERSONA_ACT_CANCELLED", act_id,
                   {"kind": act["kind"]})
    if done is not None:
        return done, True
    return read(conn, act_id, user_id=user_id, clearance=clearance), False


# ---------------------------------------------------------------------------
# Running an act
# ---------------------------------------------------------------------------

class _Refusal(Exception):
    def __init__(self, status: int, title: str, detail: str | None):
        super().__init__(detail or title)
        self.problem = {"status": int(status), "title": title,
                        "detail": detail or title}


def instance_name(prefix: str = "collector") -> str:
    """Who claimed an act, for the row and the log: never a secret."""
    return f"{prefix}:{socket.gethostname()[:60]}:{os.getpid()}"


#: What a claim admits, whatever the row says about itself (verify:g38,
#: 2026-10-03). The request role writes the row, so its own expiry and
#: start are capped here by constants: asked no later than now and within
#: MAX_TTL_S of now. persona_act_window (0156) caps expires_at the same
#: way, so a forged far expiry is refused at the door as well.
_CLAIMABLE_SQL = ("status = 'PENDING' AND expires_at > clock_timestamp() "
                  "AND requested_at <= clock_timestamp() "
                  "AND requested_at > clock_timestamp() "
                  "- make_interval(secs => %(max_ttl)s)")


def _claim_next(conn, instance: str) -> dict | None:
    return _row(conn.execute(
        f"""UPDATE collect.persona_act
               SET status = 'RUNNING', claimed_by = %(by)s,
                   claimed_at = clock_timestamp(), attempts = attempts + 1
             WHERE id = (SELECT id FROM collect.persona_act
                          WHERE {_CLAIMABLE_SQL}
                            AND not_before <= clock_timestamp()
                          ORDER BY not_before, requested_at
                          FOR UPDATE SKIP LOCKED LIMIT 1)
             RETURNING {_COLUMNS}""",
        {"by": instance, "max_ttl": MAX_TTL_S}).fetchone())


def _claim(conn, act_id: UUID, instance: str) -> dict | None:
    return _row(conn.execute(
        f"""UPDATE collect.persona_act
               SET status = 'RUNNING', claimed_by = %(by)s,
                   claimed_at = clock_timestamp(), attempts = attempts + 1
             WHERE id = %(id)s AND {_CLAIMABLE_SQL}
             RETURNING {_COLUMNS}""",
        {"by": instance, "id": act_id, "max_ttl": MAX_TTL_S}).fetchone())


def _finish(status_conn, act: dict, status: str, *, body: dict | None = None,
            problem: dict | None = None) -> dict:
    result = {"body": body} if body is not None else {"problem": problem}
    with system_connection(SystemPurpose.PERSONA_ACTS, reuse=status_conn) as sc:
        done = _row(sc.execute(
            f"""UPDATE collect.persona_act
                   SET status = %s, finished_at = clock_timestamp(), result = %s
                 WHERE id = %s AND status = 'RUNNING'
                 RETURNING {_COLUMNS}""",
            (status, Jsonb(_jsonable(result)), act["id"])).fetchone())
        if done is not None:
            _audit(sc, None, "PERSONA_ACT_FINISHED", act["id"],
                   {"kind": act["kind"], "status": status,
                    "http_status": (problem or {}).get("status")})
            return done
        # The sweep already finished it (it ran past STALE_S and was failed
        # as "outcome unknown"), so the row and its FINISHED event say
        # FAILED. Auditing the outcome computed here as well would put two
        # contradicting FINISHED events on one act (verify:g38,
        # 2026-10-03). The act's own events say what it did; the log says
        # it came back late, by id and status only.
        log.warning("persona act %s (%s) came back %s after it was already "
                    "finished", act["id"], act["kind"], status)
        return _row(sc.execute(
            f"SELECT {_COLUMNS} FROM collect.persona_act WHERE id = %s",
            (act["id"],)).fetchone()) or act


def _requeue(status_conn, act: dict, seconds: int) -> dict:
    with system_connection(SystemPurpose.PERSONA_ACTS, reuse=status_conn) as sc:
        again = _row(sc.execute(
            f"""UPDATE collect.persona_act
                   SET status = 'PENDING',
                       not_before = clock_timestamp() + make_interval(secs => %s)
                 WHERE id = %s AND status = 'RUNNING'
                 RETURNING {_COLUMNS}""", (seconds, act["id"])).fetchone())
    return again or act


def _recheck(conn, act: dict) -> tuple[str, frozenset[str]]:
    """The collector's half: the person who asked, now. Returns their
    ceiling's name and the compartments they hold now (F43: a source filed
    under a key they no longer hold is a missing one to the act, as it is to
    the route). Every refusal is the gate's own sentence."""
    from noctornal_api.http.deps import CurrentUser, authorize_global, user_ceiling
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers.collection import refuse_unready
    from noctornal_api.security.access import tlp_from_name
    from noctornal_api.security.sessions import IDLE_TIMEOUT

    # Every expiry SessionService.validate enforces, the idle one included
    # (verify:g38, 2026-10-03): NOCTORNAL_ACT_TTL_SECONDS reaches an hour,
    # and an act must not run for a session the console would already 401.
    # The second factor's time is the SESSION's, which only a sign-in writes
    # (0144), never the act row's copy: the request role writes that row, so
    # a forged copy would have passed the step-up (beta 1 gate 6, 2026-10-07).
    session = act["session_id"] is not None and conn.execute(
        """SELECT mfa_satisfied_at FROM iam.session
            WHERE id = %s AND user_id = %s AND revoked_at IS NULL
              AND expires_at > clock_timestamp()
              AND last_seen_at > clock_timestamp() - %s::interval""",
        (act["session_id"], act["requested_by"], IDLE_TIMEOUT)).fetchone()
    if not session:
        raise _Refusal(403, "Forbidden", SESSION_ENDED)
    user = CurrentUser(act["requested_by"], act["session_id"], session[0])
    try:
        for permission, force in KINDS[act["kind"]].permissions:
            authorize_global(conn, user, permission, force_step_up=force)
        # A stop is always allowed (F38): the stop route asks no readiness,
        # so the sign-out it queues is not held to it either (beta 1 gate 6).
        if act["kind"] not in STOP_KINDS:
            refuse_unready(conn)
        clearance, held = user_ceiling(conn, act["requested_by"])
    except Problem as exc:
        raise _Refusal(exc.status, exc.title, exc.detail) from None
    if tlp_from_name(act["classification"]) > clearance:
        raise _Refusal(403, "Forbidden", LABEL_ABOVE)
    return clearance.name, frozenset(held or ())


def _uuid(value) -> UUID | None:
    return UUID(str(value)) if value else None


def _execute(conn, act: dict, *, clearance: str, compartments=None, adapters,
             transport_factory, sleep) -> dict:
    """Exactly the code the route ran before 2026-10-02, as the person who
    asked, at their ceiling and with their compartments now."""
    p = act["params"]
    kind = act["kind"]
    actor = act["requested_by"]
    if kind == "SOURCE_POLL":
        from noctornal_api.collection import CollectionService
        from noctornal_api.http.routers.collection import run_body

        # As the run route does: a system connection for the poll itself
        # (S1), the caller's ceiling deciding whether it may run at all.
        with system_connection(SystemPurpose.COLLECTION, reuse=conn) as sconn:
            result = CollectionService(sconn, adapters).run_once(
                act["source_id"], actor_id=actor,
                persona_id=_uuid(p.get("persona_id")),
                watch_id=_uuid(p.get("watch_id")), clearance=clearance,
                compartments=compartments)
        return run_body(result)
    if kind == "FORUM_SIGN_OUT":
        from noctornal_api import forum_member

        # A stop, in the collector, the one process that opens the sealed
        # session: through the persona's own route, once per board, then the
        # sessions are cleared whatever the boards answered.
        with system_connection(SystemPurpose.COLLECTION, reuse=conn) as sconn:
            out = forum_member.sign_out_persona(
                sconn, UUID(str(p["persona_id"])), actor_id=actor,
                clearance=clearance, compartments=compartments)
        return {"persona_id": out["persona_id"],
                "signed_out": out["signed_out"], "cleared": out["cleared"],
                "notice": ("The persona was signed out of its forum, and its "
                           "session cleared.")
                if any(s["reached"] for s in out["signed_out"]) else
                ("The forum's own sign-out was not reached; the session this "
                 "product held was cleared.")}
    from noctornal_api.telegram_service import TelegramChats

    chats = TelegramChats(conn, adapters=adapters,
                          transport_factory=transport_factory, sleep=sleep)
    source_id = act["source_id"]
    if kind == "TELEGRAM_RESOLVE":
        return chats.create(
            persona_id=UUID(p["persona_id"]), ref=p["ref"], name=p["name"],
            classification=p["classification"],
            default_reliability=p["default_reliability"],
            access_mode=p["access_mode"], poll_interval_s=int(p["poll_interval_s"]),
            jitter_pct=int(p["jitter_pct"]), max_rps=float(p["max_rps"]),
            actor_id=actor, clearance=clearance,
            compartments=tuple(p.get("compartments") or ()),
            held_compartments=compartments)
    if kind == "TELEGRAM_JOIN":
        return chats.join(source_id, note=p["note"], actor_id=actor,
                          clearance=clearance, compartments=compartments)
    if kind == "TELEGRAM_MEMBERSHIP":
        return chats.check_membership(source_id, actor_id=actor,
                                      clearance=clearance,
                                      compartments=compartments)
    if kind == "TELEGRAM_MARK_MEMBER":
        return chats.mark_member(source_id, reason=p["reason"], actor_id=actor,
                                 clearance=clearance, compartments=compartments)
    if kind == "TELEGRAM_REBIND":
        return chats.rebind(source_id, persona_id=UUID(p["persona_id"]),
                            reason=p["reason"], actor_id=actor,
                            clearance=clearance, compartments=compartments)
    raise ValueError(f"no runner for persona act {kind!r}")


def _problem_for(kind: str, exc: Exception) -> dict:
    """The route's own answer for an outcome, through the route's own
    mapping, so the queue cannot drift from what the route said."""
    if kind in ("SOURCE_POLL", "FORUM_SIGN_OUT"):
        from noctornal_api.http.routers.collection import run_problem
        problem = run_problem(exc)
    else:
        from noctornal_api.http.routers.collection_telegram import act_problem
        problem = act_problem(kind, exc)
    return {"status": int(problem.status), "title": problem.title,
            "detail": problem.detail or problem.title}


def _stored(body: dict) -> dict:
    """The body as the row keeps it: the chat's view is left out and read
    again, at the reader's ceiling, when the act is served."""
    return _jsonable({k: v for k, v in body.items() if k != "chat"})


def _run_claimed(status_conn, work_conn, act: dict, *, adapters,
                 transport_factory, sleep, collector: bool
                 ) -> tuple[dict, dict | None]:
    """Run a claimed act and record its outcome. Returns the finished (or
    requeued) act, and the body as the act returned it when it finished."""
    from noctornal_api.collection import CollectionBusy, CollectionError

    kind = act["kind"]
    try:
        if collector:
            clearance, held = _recheck(work_conn, act)
        else:
            from noctornal_api.http.deps import user_ceiling
            ceiling, keys = user_ceiling(work_conn, act["requested_by"])
            clearance, held = ceiling.name, frozenset(keys or ())
        body = _execute(work_conn, act, clearance=clearance, compartments=held,
                        adapters=adapters, transport_factory=transport_factory,
                        sleep=sleep)
    except _Refusal as refusal:
        state = "REFUSED" if refusal.problem["status"] < 500 else "FAILED"
        return _finish(status_conn, act, state, problem=refusal.problem), None
    except CollectionBusy as exc:
        # Another runner holds the persona or the source. The collector
        # tries again shortly, until the act expires; inline, the person
        # is told now, as before.
        if collector:
            return _requeue(status_conn, act, BUSY_RETRY_S), None
        return _finish(status_conn, act, "REFUSED",
                       problem=_problem_for(kind, exc)), None
    except CollectionError as exc:
        problem = _problem_for(kind, exc)
        state = "REFUSED" if problem["status"] < 500 else "FAILED"
        return _finish(status_conn, act, state, problem=problem), None
    except Exception as exc:  # noqa: BLE001 - recorded, never the text
        # The class name only: an unexpected exception's text is not
        # redacted, and the log is read by people below the act's label.
        log.error("persona act %s (%s) failed: %s", act["id"], kind,
                  type(exc).__name__)
        return _finish(status_conn, act, "FAILED", problem={
            "status": 500, "title": "Internal error",
            "detail": FAILED_SENTENCE}), None
    return _finish(status_conn, act, "DONE", body=_stored(body)), body


def run_inline(conn: psycopg.Connection, act: dict, *, adapters=None,
               transport_factory=None, sleep=time.sleep
               ) -> tuple[dict, dict | None]:
    """Development's inline mode: claim the act just queued and run it here,
    on the request connection. An act already claimed (a double click whose
    first act is running) is waited for instead."""
    with system_connection(SystemPurpose.PERSONA_ACTS, reuse=conn) as sc:
        claimed = _claim(sc, act["id"], instance_name("inline"))
    if claimed is None:
        return wait(conn, act["id"], user_id=act["requested_by"],
                    seconds=wait_seconds()), None
    return _run_claimed(conn, conn, claimed, adapters=adapters,
                        transport_factory=transport_factory, sleep=sleep,
                        collector=False)


def sweep(conn: psycopg.Connection) -> tuple[int, int]:
    """(expired, stale): PENDING acts past their expiry are EXPIRED, never
    run late; RUNNING acts older than STALE_S lost their collector and are
    FAILED with an unknown outcome, never repeated."""
    expired = conn.execute(
        """UPDATE collect.persona_act
               SET status = 'EXPIRED', finished_at = clock_timestamp(),
                   result = jsonb_build_object('problem', jsonb_build_object(
                       'status', 409, 'title', 'Expired', 'detail',
                       %s::text))
             WHERE status = 'PENDING' AND expires_at <= clock_timestamp()
             RETURNING id, kind""", (_expired_sentence(ttl_seconds()),)).fetchall()
    stale = conn.execute(
        """UPDATE collect.persona_act
              SET status = 'FAILED', finished_at = clock_timestamp(),
                  result = jsonb_build_object('problem', jsonb_build_object(
                      'status', 500, 'title', 'Outcome unknown', 'detail',
                      %s::text))
            WHERE status = 'RUNNING'
              AND claimed_at < clock_timestamp() - make_interval(secs => %s)
            RETURNING id, kind""", (OUTCOME_UNKNOWN, STALE_S)).fetchall()
    for act_id, kind in expired:
        _audit(conn, None, "PERSONA_ACT_FINISHED", act_id,
               {"kind": kind, "status": "EXPIRED", "http_status": 409})
    for act_id, kind in stale:
        _audit(conn, None, "PERSONA_ACT_FINISHED", act_id,
               {"kind": kind, "status": "FAILED", "http_status": 500})
    return len(expired), len(stale)


def drain(conn: psycopg.Connection, *, instance: str, limit: int = 20,
          max_seconds: float = 120.0, adapters=None, transport_factory=None,
          sleep=time.sleep, clock=time.monotonic,
          should_stop: Callable[[], bool] | None = None) -> dict:
    """The collector's pass over the queue, on its system connection: the
    sweep, then up to `limit` acts, one at a time, stopping STARTING acts
    after `max_seconds`, or as soon as `should_stop()` says so. Counts by
    outcome; never an act's words.

    `should_stop` is asked before every claim (verify:g38, 2026-10-03): a
    SIGTERM finishes the act in hand and claims no other, so the stop
    grace period covers one act rather than a whole pass of twenty."""
    counters = {"claimed": 0, "done": 0, "refused": 0, "failed": 0,
                "requeued": 0, "expired": 0, "stale": 0}
    counters["expired"], counters["stale"] = sweep(conn)
    began = clock()
    while counters["claimed"] < limit and clock() - began < max_seconds:
        if should_stop is not None and should_stop():
            break
        act = _claim_next(conn, instance)
        if act is None:
            break
        counters["claimed"] += 1
        after, _body = _run_claimed(conn, conn, act, adapters=adapters,
                                    transport_factory=transport_factory,
                                    sleep=sleep, collector=True)
        key = {"DONE": "done", "REFUSED": "refused", "FAILED": "failed",
               "PENDING": "requeued"}.get(after["status"], "failed")
        counters[key] += 1
    return counters


def served_body(conn: psycopg.Connection, act: dict, *, clearance: str,
                adapters=None, compartments=None) -> dict:
    """A finished act's body as the route answers it, its chat read again
    at the reader's ceiling and compartments now; left out when the chat is
    above them or filed under a key they do not hold (F43)."""
    from noctornal_api.collection import CollectionNotFound

    body = dict((act.get("result") or {}).get("body") or {})
    if act["kind"] in ("SOURCE_POLL", "FORUM_SIGN_OUT"):
        return body
    from noctornal_api.telegram_service import TelegramChats

    source = (body.get("source") or {}).get("id") if act["kind"] == \
        "TELEGRAM_RESOLVE" else act["source_id"]
    if source:
        try:
            body["chat"] = TelegramChats(conn, adapters=adapters).view(
                UUID(str(source)), clearance, compartments)
        except CollectionNotFound:
            pass
    return body


#: A PENDING act older than this, outside the inline mode, means no
#: collector is draining the queue.
STUCK_S = 120

COLLECTOR_ACTION_START = (
    "start the collector service (infra/production/compose.yml); it refuses "
    "to start without infra/production/collector.env, and `docker compose "
    "logs collector` names why. On a development machine run python "
    "scripts/collector.py, or set NOCTORNAL_COLLECTOR_INLINE")
COLLECTOR_ACTION_KEY = (
    "give the collector the persona key that sealed them: restore the "
    "infra/production/collector.env they were enrolled under, or name that "
    "key in NOCTORNAL_PERSONA_KEK_RETIRED; or enrol those personas again")

# ---------------------------------------------------------------------------
# The collector's heartbeat (0157, verify:g38, 2026-10-03)
# ---------------------------------------------------------------------------

#: How often the collector moves its heartbeat while it runs.
HEARTBEAT_EVERY_S = 30
#: How old the newest heartbeat may be before the register says no
#: collector runs. Two beats are at most one drain pass apart (120 s of
#: starting acts), plus the act in hand (120 s, a Telegram poll's whole
#: session), plus the wait for a notification: ten minutes covers that
#: twice over.
HEARTBEAT_STALE_S = 600


def heartbeat_start(conn: psycopg.Connection, instance: str, verdict) -> None:
    """The collector's first beat, with its ring verdict at start
    (persona_sealed.RingVerdict: key ids and counts, never key material).
    Rows no collector has moved for a day are deleted first: a heartbeat
    is not a record."""
    conn.execute("DELETE FROM collect.collector_heartbeat "
                 "WHERE seen_at < clock_timestamp() - interval '1 day'")
    problem = verdict.problem[:500] if verdict.problem else None
    conn.execute(
        """INSERT INTO collect.collector_heartbeat
               (instance, started_at, seen_at, key_ids, sampled, unopenable,
                ring_problem)
           VALUES (%s, clock_timestamp(), clock_timestamp(), %s, %s, %s, %s)
           ON CONFLICT (instance) DO UPDATE
              SET started_at = EXCLUDED.started_at, seen_at = EXCLUDED.seen_at,
                  key_ids = EXCLUDED.key_ids, sampled = EXCLUDED.sampled,
                  unopenable = EXCLUDED.unopenable,
                  ring_problem = EXCLUDED.ring_problem""",
        (instance, list(verdict.key_ids), verdict.sampled, verdict.unopenable,
         problem))


def heartbeat(conn: psycopg.Connection, instance: str) -> int:
    """Move this collector's beat. Rows touched: 0 means the row is gone
    (the day-old sweep of another start, or a restored database), and the
    caller writes it again."""
    return conn.execute(
        "UPDATE collect.collector_heartbeat SET seen_at = clock_timestamp() "
        "WHERE instance = %s", (instance,)).rowcount


def collector_seen(conn: psycopg.Connection) -> dict | None:
    """The newest heartbeat, or None when no collector ever started here:
    how long ago, and its ring verdict. Never which host."""
    row = conn.execute(
        """SELECT extract(epoch FROM clock_timestamp() - seen_at), sampled,
                  unopenable, ring_problem
             FROM collect.collector_heartbeat
            ORDER BY seen_at DESC LIMIT 1""").fetchone()
    if row is None:
        return None
    return {"age_s": max(0.0, float(row[0])), "sampled": int(row[1]),
            "unopenable": int(row[2]), "problem": row[3]}


def readiness_verdict(conn: psycopg.Connection) -> tuple[bool, str, str]:
    """(ok, evidence, action) for the collector_split row: whether this API
    process holds the persona key, whether persona acts run in a collector
    and it is draining them, and how many persona credentials are still
    sealed under the TOTP ring. Counts only: the register is read by
    user.manage holders below many labels.

    Outside the inline mode a collector must also have been SEEN lately
    (its heartbeat, 0157), whatever the queue holds, and the persona ring
    it started with must have opened every credential it sampled
    (verify:g38, 2026-10-03). Until then an empty queue read green while
    no collector ran, and in production that is also every scheduled poll
    stopped, feeds no persona reads included."""
    from noctornal_api.security import persona_envelope as pe
    from noctornal_api.security.persona_sealed import sealed_before_split
    from noctornal_api.wording import agree

    held = pe.held()
    inline = inline_mode()
    before = sealed_before_split(conn)
    facts = queue_facts(conn)
    seen = None if inline else collector_seen(conn)
    if inline:
        mode = ("inline mode: persona acts run inside this API process, which "
                "holds the persona key (development only)")
    elif held:
        mode = ("persona acts run in the collector, and this API process holds "
                "the persona key too (development)")
    else:
        mode = ("persona acts run in the collector; this API process holds no "
                "persona key and can open no persona credential")
    evidence = (f"{mode}; {facts['pending']} pending, {facts['running']} "
                f"running, {facts['failed_last_day']} failed in the last day")
    fresh = seen is not None and seen["age_s"] <= HEARTBEAT_STALE_S
    if fresh:
        evidence += (f"; a collector was seen "
                     f"{count_of(int(seen['age_s']), 'second', 'seconds')} ago")
    problems: list[str] = []
    actions: list[str] = []
    if not inline and not fresh:
        if seen is None:
            problems.append(
                "no collector has ever started against this database, so "
                "persona acts wait and, in production, no scheduled poll runs "
                "at all, feeds no persona reads included")
        else:
            minutes = max(1, int(seen["age_s"] // 60))
            problems.append(
                f"no collector has been seen for "
                f"{count_of(minutes, 'minute', 'minutes')}, so persona acts "
                f"wait and, in production, no scheduled poll runs at all, "
                f"feeds no persona reads included")
        actions.append(COLLECTOR_ACTION_START)
    if fresh and seen["unopenable"]:
        problems.append(
            f"the collector's persona key ring did not open "
            f"{seen['unopenable']} of the "
            f"{count_of(seen['sampled'], 'persona credential', 'persona credentials')} "
            f"it sampled when it started: {seen['problem']}")
        actions.append(COLLECTOR_ACTION_KEY)
    if _production() and held:
        problems.append(f"this API process holds {' and '.join(held)}, which in "
                        f"production only the collector holds")
        actions.append("remove the persona key from every file the api service "
                       "reads (it belongs in infra/production/collector.env "
                       "alone) and restart the API")
    if before:
        problems.append(
            f"{count_of(before, 'persona credential is', 'persona credentials are')} "
            f"still sealed under the TOTP key ring, from before the persona key "
            f"existed, and the collector refuses {agree(before, 'it', 'them')}")
        actions.append(f"run {pe.MOVE_COMMAND} in the collector")
    stuck = facts["oldest_pending_s"]
    if not inline and stuck is not None and stuck > STUCK_S:
        minutes = max(1, int(stuck // 60))
        problems.append(
            f"the oldest pending act has waited "
            f"{count_of(minutes, 'minute', 'minutes')}: no collector is draining "
            f"the queue")
        actions.append(COLLECTOR_ACTION_START)
    if problems:
        # One action named once, however many problems it answers.
        return (False, f"{evidence}; " + "; ".join(problems) + ".",
                "; ".join(dict.fromkeys(actions)))
    return True, evidence + ".", ""


def queue_facts(conn: psycopg.Connection) -> dict:
    """Counts for the readiness row, across every requester: no act's
    words, no source, no person."""
    row = conn.execute(
        """SELECT count(*) FILTER (WHERE status = 'PENDING'),
                  count(*) FILTER (WHERE status = 'RUNNING'),
                  extract(epoch FROM clock_timestamp()
                          - min(requested_at) FILTER (WHERE status = 'PENDING')),
                  count(*) FILTER (WHERE status = 'FAILED'
                                   AND finished_at > now() - interval '1 day'),
                  max(finished_at) FILTER (WHERE status = 'DONE')
             FROM collect.persona_act""").fetchone()
    return {"pending": int(row[0]), "running": int(row[1]),
            "oldest_pending_s": float(row[2]) if row[2] is not None else None,
            "failed_last_day": int(row[3]), "last_done_at": row[4]}
