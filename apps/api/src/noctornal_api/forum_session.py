"""A persona's forum session: the cookies a board handed it at sign-in,
sealed in the vault's storage between runs (the authenticated forum path,
2026-10-02).

## Why a session is a credential

A session cookie obtained with a persona's credentials IS a credential: it
opens the member's view of the board exactly as the password does. So it
gets the credential's treatment, invariant 7's shape rather than a rule to
remember: sealed at rest under the same ring as the password
(`collect.collection_account.session_*`, 0161), opened only inside the
member adapter's run and for a sign-out, registered for redaction for
exactly as long as it is in memory (`pinned_http.secret_in_scope`), never
written to a run row, a warning, a document, a log line or a response,
and cleared when the persona signs out or stops.

## Where the key comes from

The persona ring, `security.persona_envelope` (NOCTORNAL_PERSONA_KEK), the
key of its own that only the collector holds in production (the persona
vault split, decision 174, merged 2026-10-03). The two calls below are the
only places this module names it, and nothing here ever falls back to the
TOTP ring: a session cookie opens a member's view of a board as the
password does, so no process that cannot open the password can open it. So
a jar is sealed and opened only inside the collector's process (a run, or
the sign-out act), and what the API does with one is database only: it
clears it (`clear_session` with no origin opens nothing).

## The jar, and whose it is

A jar is `{name: value}` for ONE origin, and what is sealed is one jar PER
ORIGIN (`{"v": 2, "origins": {origin: jar}}`), because a persona may read
more than one board and a cookie is the board's own: the jar was once keyed by persona alone,
so a persona bound to two boards sent the first board's live session to
the second's operator (2026-10-03). A run opens only the jar of the origin of the source it is
reading (`origin_key`), and the run context refuses a request to any other
origin, so a board's cookies reach that board and no other. A blob in the
earlier shape (one flat jar for the persona) cannot be attributed to any
origin and is discarded: the persona signs in again.

Caps bound what a hostile board can make the persona carry:
`MAX_COOKIES` per origin, `MAX_ORIGINS` per persona, `MAX_COOKIE_NAME`,
`MAX_COOKIE_VALUE`. A cookie with `Max-Age=0` or an expiry in the past is a
deletion. Domain and Path attributes are not honoured (one origin, every
path), which is the safe direction: a cookie is sent where a browser would
send it and possibly more widely within the same origin, never to another.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookies import CookieError, SimpleCookie
from uuid import UUID

import psycopg

from noctornal_api.security import persona_envelope

log = logging.getLogger("noctornal.forum_session")

MAX_COOKIES = 20
MAX_COOKIE_NAME = 256
MAX_COOKIE_VALUE = 4096
#: The longest Cookie header a jar may make: under the 8192 characters
#: pinned_http sends as one header value (MAX_HEADER_VALUE).
MAX_COOKIE_HEADER = 8000
#: The boards one persona may hold a live session on at once.
MAX_ORIGINS = 8
#: The sealed blob's shape; an older one is dropped (see the module text).
FORMAT = 2

__all__ = [
    "FORMAT", "MAX_COOKIES", "MAX_COOKIE_NAME", "MAX_COOKIE_VALUE",
    "MAX_ORIGINS", "STOPPED_SQL", "clear_session", "cookie_header",
    "open_session", "open_sessions", "origin_key", "seal_session",
    "session_sealed_at", "take_cookies",
]


def origin_key(url: str | None) -> str | None:
    """The key a jar is filed under: the origin of a source's address
    (scheme, host, effective port) as the run context reads it, so the
    jar a run opens and the origin it may request are one reading. None
    for an address a collector would not read at all."""
    if not url:
        return None
    from noctornal_api.collection_context import origin_text
    return origin_text(url)


def _printable(text: str, cap: int) -> bool:
    return isinstance(text, str) and 0 < len(text) <= cap and text.isprintable() \
        and ";" not in text and "," not in text and " " not in text


def take_cookies(jar: dict[str, str], set_cookie_values, *,
                 now: datetime | None = None) -> dict[str, str]:
    """`jar` updated from a response's Set-Cookie headers, within the caps.
    A deletion (Max-Age=0, or Expires in the past) removes the name; an
    unparseable header is skipped whole."""
    now = now or datetime.now(timezone.utc)
    out = dict(jar)
    for raw in list(set_cookie_values or [])[:MAX_COOKIES * 2]:
        if not isinstance(raw, str) or len(raw) > 2 * MAX_COOKIE_VALUE:
            continue
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except (CookieError, ValueError, TypeError):
            continue
        for name, morsel in cookie.items():
            if not _printable(name, MAX_COOKIE_NAME):
                continue
            gone = False
            max_age = morsel["max-age"]
            if max_age not in ("", None):
                try:
                    gone = int(max_age) <= 0
                except ValueError:
                    gone = True
            expires = morsel["expires"]
            if not gone and expires:
                try:
                    when = parsedate_to_datetime(expires)
                    if when.tzinfo is None:
                        when = when.replace(tzinfo=timezone.utc)
                    gone = when <= now
                except (TypeError, ValueError, IndexError):
                    gone = False
            if gone:
                out.pop(name, None)
                continue
            value = morsel.value
            if not _sendable(name, value):
                continue
            if name not in out and len(out) >= MAX_COOKIES:
                continue
            before = out.get(name)
            out[name] = value
            if len(cookie_header(out) or "") > MAX_COOKIE_HEADER:
                # Kept, it would make every later request of this jar one
                # the client refuses, and the jar is sealed as it stands.
                if before is None:
                    out.pop(name)
                else:
                    out[name] = before
    return out


def _sendable(name, value) -> bool:
    """Whether a cookie can ride in a request: a printable name and an ASCII
    value within the caps (2026-10-07: a value printable but
    not ASCII, or a jar whose header outgrew what the client sends, made
    every later request of the persona's session fail, and the poisoned jar
    was sealed, so every later run failed the same way)."""
    return (_printable(name, MAX_COOKIE_NAME) and isinstance(value, str)
            and len(value) <= MAX_COOKIE_VALUE and value.isascii()
            and value.isprintable() and ";" not in value)


def cookie_header(jar: dict[str, str]) -> str | None:
    """The Cookie header for `jar`, or None when it is empty."""
    parts = [f"{k}={v}" for k, v in jar.items() if _sendable(k, v)]
    return "; ".join(parts) if parts else None


def _clean_jar(jar) -> dict[str, str]:
    if not isinstance(jar, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in jar.items():
        if _sendable(k, v) and len(out) < MAX_COOKIES:
            out[k] = v
            if len(cookie_header(out) or "") > MAX_COOKIE_HEADER:
                out.pop(k)
    return out


def _decode(persona_id: UUID, row) -> dict[str, dict[str, str]]:
    """Every origin's jar from one sealed blob, or none. A blob the
    envelope cannot open, or one in an earlier shape, is no session and a
    log line: a session that cannot be read, or cannot be attributed to a
    board, is signed in again and never guessed at."""
    if row is None or not row[0]:
        return {}
    try:
        value = json.loads(persona_envelope.decrypt(bytes(row[0]), key_id=row[1]))
    except persona_envelope.PersonaKeyError:
        # This process holds no usable persona key: that says nothing about
        # the session, and "no session" would let a caller seal a new blob
        # over a live one. The caller is refused instead.
        raise
    except Exception:  # noqa: BLE001 - an unreadable session is no session
        log.warning("persona %s: the sealed forum session could not be opened "
                    "and is discarded", persona_id)
        return {}
    if not isinstance(value, dict) or value.get("v") != FORMAT \
            or not isinstance(value.get("origins"), dict):
        log.warning("persona %s: a sealed forum session in an earlier shape "
                    "cannot be attributed to one board and is discarded",
                    persona_id)
        return {}
    out: dict[str, dict[str, str]] = {}
    for origin, jar in value["origins"].items():
        clean = _clean_jar(jar)
        if isinstance(origin, str) and origin and clean \
                and len(out) < MAX_ORIGINS:
            out[origin] = clean
    return out


def _store(conn: psycopg.Connection, persona_id: UUID,
           jars: dict[str, dict[str, str]]) -> None:
    if not jars:
        conn.execute(
            """UPDATE collect.collection_account
                  SET session_ciphertext = NULL, session_key_id = NULL,
                      session_sealed_at = NULL
                WHERE id = %s""", (persona_id,))
        return
    ciphertext, key_id = persona_envelope.encrypt(json.dumps(
        {"v": FORMAT, "origins": jars}, separators=(",", ":")))
    conn.execute(
        """UPDATE collect.collection_account
              SET session_ciphertext = %s, session_key_id = %s,
                  session_sealed_at = clock_timestamp()
            WHERE id = %s""", (ciphertext, key_id, persona_id))


#: A persona a person locked or burnt, or its platform locked: it holds no
#: sealed session (collect.collection_account columns).
STOPPED_SQL = ("status::text IN ('LOCKED', 'BURNED') OR machine_lock_code IS NOT NULL")


def seal_session(conn: psycopg.Connection, persona_id: UUID, origin: str,
                 jar: dict[str, str]) -> None:
    """Seal `jar` as the persona's session on `origin`, beside its
    credential and beside any other board's jar. An empty jar removes this
    origin's only. Read, change and write under one row lock, so two runs
    of one persona cannot overwrite each other's board.

    Whether the persona is stopped is read under that same lock, and a
    stopped persona is sealed nothing and has what it held cleared. A stop
    writes the persona's status and then clears its sessions, so a check
    made before the lock could pass, the stop could land between the check
    and this seal, and a burnt persona was left holding a sealed session
    (docs/17, "a stopped persona resealed"). The stop's status write waits
    for the row lock, and a stop that came first is seen here."""
    if not origin:
        return
    with conn.transaction():
        row = conn.execute(
            f"""SELECT session_ciphertext, session_key_id, ({STOPPED_SQL})
                 FROM collect.collection_account WHERE id = %s FOR UPDATE""",
            (persona_id,)).fetchone()
        if row is None:
            return
        if row[2]:
            if row[0]:
                _store(conn, persona_id, {})
            return
        jars = _decode(persona_id, row)
        clean = _clean_jar(jar)
        if clean:
            if origin not in jars and len(jars) >= MAX_ORIGINS:
                log.warning("persona %s holds sessions on %d boards already; "
                            "this one is not kept and is signed in again",
                            persona_id, len(jars))
                return
            jars[origin] = clean
        else:
            jars.pop(origin, None)
        _store(conn, persona_id, jars)


def open_sessions(conn: psycopg.Connection, persona_id: UUID
                  ) -> dict[str, dict[str, str]]:
    """Every sealed jar the persona holds, by origin. For a sign-out, which
    signs out of each board with that board's own cookies and no other."""
    row = conn.execute(
        """SELECT session_ciphertext, session_key_id
             FROM collect.collection_account WHERE id = %s""",
        (persona_id,)).fetchone()
    return _decode(persona_id, row)


def open_session(conn: psycopg.Connection, persona_id: UUID,
                 origin: str | None) -> dict[str, str]:
    """The sealed jar of ONE origin, or an empty one: never another
    origin's."""
    if not origin:
        return {}
    return dict(open_sessions(conn, persona_id).get(origin, {}))


def clear_session(conn: psycopg.Connection, persona_id: UUID,
                  origin: str | None = None) -> bool:
    """No session: the one origin's jar removed, or with no origin every
    jar and the three columns NULL. True when something was held."""
    with conn.transaction():
        row = conn.execute(
            """SELECT session_ciphertext, session_key_id
                 FROM collect.collection_account WHERE id = %s FOR UPDATE""",
            (persona_id,)).fetchone()
        if row is None or not row[0]:
            return False
        if origin is None:
            _store(conn, persona_id, {})
            return True
        jars = _decode(persona_id, row)
        held = origin in jars
        jars.pop(origin, None)
        _store(conn, persona_id, jars)
        return held


def session_sealed_at(conn: psycopg.Connection, persona_id: UUID) -> datetime | None:
    row = conn.execute(
        "SELECT session_sealed_at FROM collect.collection_account WHERE id = %s",
        (persona_id,)).fetchone()
    return row[0] if row else None
