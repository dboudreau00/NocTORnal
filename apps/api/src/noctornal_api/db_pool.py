"""The pool of request connections: the connection `deps.get_conn` hands a route, and no other
(docs/00 decision 233).

Opening a database connection was about 14 ms of every request's fixed 45 to 55 (docs/17, Load and
performance). A pooled connection serves the next request too, so it must not carry this one's
identity into it. The binding row security reads (`iam.rls_bind`, `iam.rls_bind_ticket`) is a
SESSION setting by design, because a request runs on an autocommit connection statement by
statement and never as one transaction; so a connection that comes back is reset, and then proven
clean, before another request can have it, and one that fails either is closed and replaced:

1. a transaction a failure left open is rolled back, behind any statement still running on the
   connection in another thread (psycopg's own lock), so a busy connection is never handed on;
2. `DISCARD ALL` puts every setting back to the session's default, the binding included (the
   startup options, jit off and the statement timeout, ARE those defaults, so they stay), drops a
   SET ROLE, releases every session advisory lock, unlistens, deallocates prepared statements,
   closes cursors and drops temporary tables;
3. in the development and test assume mode the request role is taken again, which DISCARD ALL
   undid, and the remembered exemption verdict is forgotten;
4. one statement reads it all back (`_STATE_SQL`) and compares it with what the same connection
   reported when it was new: bound to nobody, the same user and role, the same settings, and no
   advisory lock, channel, prepared statement or cursor held. Anything else raises, and the pool
   closes the connection.

Steps 2 to 4 run in the pool's own thread (`ConnectionPool(reset=...)`), and the pool hands no
connection out until they have finished. psycopg_pool closes a connection whose reset raises or
leaves it outside the idle state; `test_db_pool_pg.py` holds that rule, so an upgrade that changed
it fails there.

The pool is on when `NOCTORNAL_DB_POOL` says so, by default in production only; otherwise
`request_connection` is `db.connect_request`, closed after the request. Unpooled by design, by
name: `db.connect_request` itself, the live channel's LISTEN connection and its socket helpers,
the side connections of `http/errors.py` and `approvals.py` (a side connection taken from the pool
its request already holds one of can deadlock it, every request holding one and waiting for a
second), and every system connection, job and script. `test_db_pool.py` holds the tree to that.

`db` stays the unpooled helper and imports nothing from here.
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

import psycopg
from psycopg.rows import tuple_row
from psycopg_pool import ConnectionPool

from noctornal_api import db
from noctornal_api.config import is_production

log = logging.getLogger("noctornal.db_pool")

#: `on` or `off`, case and surrounding space aside. Anything else, unset included, is the default:
#: on in production, off everywhere else.
POOL_ENV = "NOCTORNAL_DB_POOL"
#: Connections kept open while idle, per process: a whole number from 0 to 50, else 1.
POOL_MIN_ENV = "NOCTORNAL_DB_POOL_MIN"
#: The most connections the pool holds, per process: a whole number from 1 to 50, else 10.
POOL_MAX_ENV = "NOCTORNAL_DB_POOL_MAX"
#: Seconds a request waits for a free connection before it is answered 503: 1 to 60, else 10.
POOL_TIMEOUT_ENV = "NOCTORNAL_DB_POOL_TIMEOUT"

POOL_MIN_DEFAULT, POOL_MIN_RANGE = 1, (0, 50)
POOL_MAX_DEFAULT, POOL_MAX_RANGE = 10, (1, 50)
POOL_TIMEOUT_DEFAULT, POOL_TIMEOUT_RANGE = 10, (1, 60)

#: A connection is replaced after half an hour whatever its use, which bounds what a long-lived
#: backend grows to and how long a pooled connection outlives a password change, and one above
#: the minimum is closed after five idle minutes.
MAX_LIFETIME_SECONDS = 1800
MAX_IDLE_SECONDS = 300
#: Requests waiting beyond four for each connection are refused at once instead of queued, and
#: never more than the threadpool can spare (`PoolSettings.max_waiting`).
WAITING_PER_CONNECTION = 4
#: The tokens of the threadpool a sync dependency and a sync route run on: anyio's default, 40 for
#: each process, which nothing in this tree changes. `deps.get_conn` waits for its connection on
#: one of them, and the handler of a request that already has a connection needs another to run
#: and give it back; so waiters that held every token would stall the holders for the whole wait
#: (docs/17, "a connection for every request").
THREADPOOL_TOKENS = 40
#: In psycopg_pool's log lines and nowhere else.
POOL_NAME = "noctornal-request"


def pool_enabled() -> bool:
    """Whether request connections come from the pool (`NOCTORNAL_DB_POOL`)."""
    raw = os.environ.get(POOL_ENV, "").strip().lower()
    if raw == "on":
        return True
    if raw == "off":
        return False
    return is_production()


@dataclass(frozen=True)
class PoolSettings:
    min_size: int
    max_size: int
    #: Seconds a request waits for a connection.
    timeout: int

    @property
    def max_waiting(self) -> int:
        """Four for each connection, and never so many that waiters and the connections' own
        handlers can fill the threadpool: a fifth of its tokens stay free of waiters, besides one
        for each connection. Never 0, which psycopg_pool reads as no limit."""
        spare = THREADPOOL_TOKENS - self.max_size - THREADPOOL_TOKENS // 5
        return max(1, min(WAITING_PER_CONNECTION * self.max_size, spare))


def _whole(name: str, default: int, low: int, high: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if low <= value <= high else default


def pool_settings() -> PoolSettings:
    """The pool's size and wait, read as `db.request_statement_timeout` reads its own: a value that
    is not a whole number in its range is the default, so a typo bounds the pool rather than
    freeing it, and nothing makes it unbounded. A minimum above the maximum is held to the
    maximum."""
    largest = _whole(POOL_MAX_ENV, POOL_MAX_DEFAULT, *POOL_MAX_RANGE)
    smallest = min(_whole(POOL_MIN_ENV, POOL_MIN_DEFAULT, *POOL_MIN_RANGE), largest)
    wait = _whole(POOL_TIMEOUT_ENV, POOL_TIMEOUT_DEFAULT, *POOL_TIMEOUT_RANGE)
    return PoolSettings(smallest, largest, wait)


# --- what a clean connection reports ------------------------------------------------------------

#: One statement, run when a connection is new and again on every return, whose answers must be
#: the same both times. The first column is whether the connection is bound to nobody: neither
#: binding setting holds a value (`''` after a reset, NULL before the first binding) and
#: `iam.rls_actor()`, where the schema has it, names nobody. The last is everything a session can
#: hold that DISCARD ALL releases and a pooled connection must not keep: session advisory locks,
#: LISTEN channels, prepared statements and open cursors. Temporary tables are left to DISCARD
#: ALL: counting them is a scan of pg_class on every return, and the test holds the drop.
_STATE_SQL = """
SELECT nullif(pg_catalog.current_setting('noctornal.rls_proof', true), '') IS NULL
       AND nullif(pg_catalog.current_setting('noctornal.rls_ticket', true), '') IS NULL
       AND {actor} IS NULL,
       current_user, session_user,
       pg_catalog.current_setting('role'),
       pg_catalog.current_setting('search_path'),
       pg_catalog.current_setting('statement_timeout'),
       pg_catalog.current_setting('lock_timeout'),
       pg_catalog.current_setting('idle_in_transaction_session_timeout'),
       pg_catalog.current_setting('jit'),
       pg_catalog.current_setting('session_replication_role'),
       pg_catalog.current_setting('default_transaction_read_only'),
       pg_catalog.current_setting('default_transaction_isolation'),
       (SELECT count(*) FROM pg_catalog.pg_locks
         WHERE pid = pg_catalog.pg_backend_pid() AND locktype = 'advisory')
       + (SELECT count(*) FROM pg_catalog.pg_listening_channels())
       + (SELECT count(*) FROM pg_catalog.pg_prepared_statements)
       + (SELECT count(*) FROM pg_catalog.pg_cursors)
"""
_STATE_WITH_ACTOR = _STATE_SQL.format(actor="iam.rls_actor()")
#: A database the migrations have not reached has no `iam.rls_actor()`; the two settings are
#: still read.
_STATE_WITHOUT_ACTOR = _STATE_SQL.format(actor="NULL::uuid")

#: Names for the columns above, for the log: which differed, never what it held.
_STATE_FIELDS = (
    "binding", "current_user", "session_user", "role", "search_path", "statement_timeout",
    "lock_timeout", "idle_in_transaction_session_timeout", "jit", "session_replication_role",
    "default_transaction_read_only", "default_transaction_isolation", "held",
)
_PYTHON_FIELDS = ("autocommit", "read_only", "isolation_level", "deferrable", "row_factory",
                  "prepare_threshold")


@dataclass(frozen=True)
class _Expected:
    sql: str
    state: tuple
    python: tuple


#: What each pooled connection reported when it was new, by connection.
_EXPECTED: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


class UncleanConnection(psycopg.InterfaceError):
    """A returned connection did not read back as it did when new. Raised in the pool's reset, so
    psycopg_pool closes the connection; logged at ERROR, because it means something survived
    DISCARD ALL or the reset did not run."""


def _python_state(conn: psycopg.Connection) -> tuple:
    return (conn.autocommit, conn.read_only, conn.isolation_level, conn.deferrable,
            conn.row_factory, conn.prepare_threshold)


def _clean(state: tuple) -> bool:
    return state[0] is True and state[-1] == 0


def _configure(conn: psycopg.Connection, assume: bool) -> None:
    """Once for each new physical connection, in the pool's own thread: the request role in
    assume mode, then what the connection reports while it is new, which every return is compared
    with. A failure closes it (psycopg_pool would leave it open) and the pool tries again."""
    try:
        if assume:
            conn.execute(f"SET ROLE {db.APP_ROLE}")
        known = conn.execute(
            "SELECT pg_catalog.to_regprocedure('iam.rls_actor()') IS NOT NULL").fetchone()[0]
        sql = _STATE_WITH_ACTOR if known else _STATE_WITHOUT_ACTOR
        state = conn.execute(sql).fetchone()
        python = _python_state(conn)
        if not _clean(state) or python[0] is not True or python[4] is not tuple_row:
            raise UncleanConnection("a new request connection is not clean")
        _EXPECTED[conn] = _Expected(sql, tuple(state), python)
    except BaseException:
        conn.close()
        raise


def _scrub(conn: psycopg.Connection, assume: bool) -> None:
    """Steps 2 and 3 of the module docstring."""
    if not conn.autocommit:
        # A route that turned autocommit off would leave the next request in implicit
        # transactions, and DISCARD ALL cannot run inside one.
        raise UncleanConnection("a request connection came back with autocommit off")
    conn.execute("DISCARD ALL")
    if assume:
        conn.execute(f"SET ROLE {db.APP_ROLE}")
    db._EXEMPT.pop(conn, None)


def _verify(conn: psycopg.Connection) -> None:
    """Step 4: raise unless the connection reads back as it did when new."""
    expected = _EXPECTED.get(conn)
    if expected is None:
        raise UncleanConnection("a request connection has no record of its first state")
    state = tuple(conn.execute(expected.sql).fetchone())
    python = _python_state(conn)
    differ = [name for name, now, then in zip(_STATE_FIELDS, state, expected.state, strict=True)
              if now != then]
    differ += [name for name, now, then in zip(_PYTHON_FIELDS, python, expected.python, strict=True)
               if now != then]
    if not _clean(state):
        differ = sorted(set(differ) | {"binding" if state[0] is not True else "held"})
    if differ:
        log.error("a request connection came back unclean and is closed: %s",
                  ", ".join(differ))
        raise UncleanConnection(f"a request connection came back unclean: {', '.join(differ)}")


def _reset(conn: psycopg.Connection, assume: bool) -> None:
    """On every return, in the pool's own thread, before another request can have the
    connection."""
    _scrub(conn, assume)
    _verify(conn)


# --- the registry -------------------------------------------------------------------------------

#: One pool per (DSN, request options, role mode, connect timeout, settings), as a digest: the
#: DSN carries the password. A distinct key for each is what keeps a test that changes any of them
#: off a pool built for another. Built lazily, never at import or in `create_app`, so building the
#: application needs no database, and uvicorn's workers, fresh interpreters, open their own.
_POOLS: dict[str, ConnectionPool] = {}
_POOLS_LOCK = threading.Lock()


def _key(url: str, options: str, assume: bool, settings: PoolSettings) -> str:
    parts = (url, options, assume, db.connect_timeout_seconds(), settings)
    return hashlib.sha256(repr(parts).encode()).hexdigest()


def _build(url: str, options: str, assume: bool, settings: PoolSettings) -> ConnectionPool:
    """The pool, not yet open. Its connections are opened as `db.connect_request` opens one
    (autocommit, the connect timeout and the request connection's options; the request role in
    assume mode), checked with one empty statement as they go out, so a restarted database costs
    a reconnect and not a 500, and reset and verified as they come back.

    One difference: a pooled connection never prepares a statement (`prepare_threshold=None`).
    psycopg prepares one on the server after five runs and forgets its own record of it on a
    DISCARD ALL only when that is a statement it has not counted before, so from the second reset
    on it would ask the server for a statement the reset had deallocated."""
    return ConnectionPool(
        url,
        kwargs={"autocommit": True, "connect_timeout": db.connect_timeout_seconds(),
                "options": options, "prepare_threshold": None},
        min_size=settings.min_size, max_size=settings.max_size,
        timeout=settings.timeout, max_waiting=settings.max_waiting,
        max_lifetime=MAX_LIFETIME_SECONDS, max_idle=MAX_IDLE_SECONDS,
        open=False, name=POOL_NAME,
        # Looked up when called, so a test can stand another function in.
        configure=lambda conn: _configure(conn, assume),
        check=ConnectionPool.check_connection,
        reset=lambda conn: _reset(conn, assume),
    )


def _request_pool() -> ConnectionPool:
    url = db.dsn()
    options = db.session_options(url, for_request=True)
    assume = db._assume_role()
    settings = pool_settings()
    key = _key(url, options, assume, settings)
    pool = _POOLS.get(key)
    if pool is not None:
        return pool
    with _POOLS_LOCK:
        pool = _POOLS.get(key)
        if pool is None:
            pool = _build(url, options, assume, settings)
            pool.open(wait=False)
            _POOLS[key] = pool
    return pool


def close_pools(timeout: float = 5.0) -> None:
    """Close every pool this process opened: the application's shutdown, and the end of a test
    run. A connection still out is closed when it comes back."""
    with _POOLS_LOCK:
        pools = list(_POOLS.values())
        _POOLS.clear()
    for pool in pools:
        pool.close(timeout=timeout)


# --- the request's connection -------------------------------------------------------------------

def _discard(pool: ConnectionPool, conn: psycopg.Connection) -> None:
    """Closed, then given back, which is how psycopg_pool learns to replace it."""
    conn.close()
    pool.putconn(conn)


def _give_back(pool: ConnectionPool, conn: psycopg.Connection) -> None:
    """Step 1: out of a transaction a failure left open, then back to the pool, whose reset
    (`_reset`) runs before anyone else has the connection. The rollback takes psycopg's own lock,
    so it waits behind a statement still running on the connection in another thread; it sends
    nothing to an idle connection. One that cannot be rolled back is closed and replaced."""
    try:
        conn.rollback()
    except Exception:  # noqa: BLE001 - whatever it was, the connection is not used again
        log.warning("a request connection could not be rolled back and is closed",
                    exc_info=True)
        conn.close()
    pool.putconn(conn)


@contextmanager
def request_connection() -> Iterator[psycopg.Connection]:
    """The connection for one HTTP request: from the pool when `pool_enabled()`, otherwise
    `db.connect_request()`, closed after it.

    A pooled one is the request role in production, as `db.connect_request` gives it, and is
    refused the same way when it is not (`db.refuse_privileged_request_role`, asked once per
    process and DSN). Waiting longer than `NOCTORNAL_DB_POOL_TIMEOUT` for one raises
    psycopg_pool's `PoolTimeout`, too many waiting (`PoolSettings.max_waiting`) `TooManyRequests`, and a pool closed by a
    shutdown `PoolClosed`; `http/errors.py` answers each with a 503."""
    if not pool_enabled():
        conn = db.connect_request()
        try:
            yield conn
        finally:
            conn.close()
        return
    pool = _request_pool()
    conn = pool.getconn()
    try:
        db.refuse_privileged_request_role(conn)
    except BaseException:
        _discard(pool, conn)
        raise
    try:
        yield conn
    finally:
        _give_back(pool, conn)
