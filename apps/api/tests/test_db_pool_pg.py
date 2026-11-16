"""docs/17, "a connection for every request", closed by the request pool (`db_pool`, decision 233).

A pooled connection serves the next request too, and row security binds a connection to its user with a
SESSION setting, so a connection that came back as it left would run the next request as the previous
user. Every test here builds a pool of ONE connection, so the next checkout is provably the same backend
(`backend_pid`), in production's shape (`NOCTORNAL_TEST_ASSUME_ROLE`: the request role), and holds one
piece of what the reset must undo or keep:

- the session binding and the ticket binding are gone, and `iam.rls_actor()` names nobody;
- a session advisory lock, a LISTEN, a temporary table, a prepared statement, a held cursor, a session
  `lock_timeout`, a `search_path` and a SET ROLE are gone too;
- the request connection's own startup settings (jit off, the statement timeout) and the request role
  are kept, and the remembered exemption verdict is forgotten;
- a statement a request repeats is still served after the reset, because a pooled connection never
  prepares one that the reset would deallocate behind psycopg's back;
- a transaction a failure left open is rolled back, and the return waits behind a statement still
  running on the connection in another thread rather than handing a busy connection on;
- a reset that fails, or leaves the connection in a transaction, closes it (psycopg_pool's rule, held
  here so an upgrade that changed it fails), and so does a connection that does not read back as it did
  when new, whatever was left on it;
- without the reset, the next checkout WOULD still be bound to the previous user: the control that shows
  the tests above test something.

Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE (rls_support).
"""
from __future__ import annotations

import logging
import secrets
import threading
import time

import psycopg
import pytest
from psycopg import pq
from psycopg.rows import dict_row

import rls_support as s
from noctornal_api import db, db_pool

pytestmark = s.GATED

PREFIX = "poolt-"


@pytest.fixture
def owner(monkeypatch):
    monkeypatch.setenv(db.ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    s.cleanup(c, PREFIX)
    c.close()


@pytest.fixture(autouse=True)
def one_connection(monkeypatch):
    """A pool of one connection, built fresh for the test and closed after it."""
    monkeypatch.delenv("NOCTORNAL_ENV", raising=False)
    monkeypatch.setenv(db.ASSUME_ROLE_ENV, "1")
    monkeypatch.setenv(db_pool.POOL_ENV, "on")
    monkeypatch.setenv(db_pool.POOL_MIN_ENV, "1")
    monkeypatch.setenv(db_pool.POOL_MAX_ENV, "1")
    monkeypatch.setenv(db_pool.POOL_TIMEOUT_ENV, "10")
    db_pool.close_pools()
    yield
    db_pool.close_pools()


def _session(owner) -> tuple:
    uid = s.user(owner, "AMBER", prefix=PREFIX)
    _, raw = s.session(owner, uid)
    return uid, raw


_STATE = """
SELECT iam.rls_actor(),
       nullif(current_setting('noctornal.rls_proof', true), ''),
       nullif(current_setting('noctornal.rls_ticket', true), ''),
       current_user, current_setting('role'), current_setting('search_path'),
       current_setting('lock_timeout'), current_setting('statement_timeout'),
       current_setting('jit'),
       (SELECT count(*) FROM pg_locks
         WHERE pid = pg_backend_pid() AND locktype = 'advisory'),
       (SELECT count(*) FROM pg_listening_channels()),
       (SELECT count(*) FROM pg_prepared_statements),
       (SELECT count(*) FROM pg_cursors),
       to_regclass('pg_temp.pool_probe')
"""
_NAMES = ("actor", "proof", "ticket", "current_user", "role", "search_path", "lock_timeout",
          "statement_timeout", "jit", "advisory", "listening", "prepared", "cursors", "temp")


def _state(conn) -> dict:
    return dict(zip(_NAMES, conn.execute(_STATE).fetchone(), strict=True))


def _clean(state: dict) -> None:
    assert state["actor"] is None and state["proof"] is None and state["ticket"] is None, state
    assert state["current_user"] == db.APP_ROLE and state["role"] == db.APP_ROLE, state
    assert (state["advisory"], state["listening"], state["prepared"], state["cursors"]) == \
        (0, 0, 0, 0), state
    assert state["temp"] is None, state


def _baseline() -> dict:
    """What a new request connection reports: `db.connect_request`, unpooled."""
    conn = db.connect_request()
    try:
        return _state(conn)
    finally:
        conn.close()


def test_a_pooled_connection_carries_no_session_binding_to_the_next_checkout(owner):
    uid, raw = _session(owner)
    with db_pool.request_connection() as conn:
        pid = conn.info.backend_pid
        db.bind_session(conn, raw)
        assert conn.execute("SELECT iam.rls_actor()").fetchone()[0] == uid
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid == pid, "the pool of one handed out another connection"
        _clean(_state(conn))


def test_a_pooled_connection_carries_no_ticket_binding_to_the_next_checkout(owner):
    with db_pool.request_connection() as conn:
        pid = conn.info.backend_pid
        conn.execute("SELECT actor, exempt FROM iam.rls_bind_ticket(%s)",
                     (secrets.token_urlsafe(32),))
        assert conn.execute("SELECT current_setting('noctornal.rls_ticket', true)").fetchone()[0]
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid == pid
        _clean(_state(conn))


def test_without_the_reset_the_next_checkout_would_run_as_the_previous_user(owner, monkeypatch):
    """The control: with the reset switched off, the same backend comes back still bound to the
    previous request's user. This is the leak every other test here holds shut."""
    monkeypatch.setattr(db_pool, "_reset", lambda conn, assume: None)
    uid, raw = _session(owner)
    with db_pool.request_connection() as conn:
        pid = conn.info.backend_pid
        db.bind_session(conn, raw)
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid == pid
        assert conn.execute("SELECT iam.rls_actor()").fetchone()[0] == uid


def test_a_pooled_connection_releases_its_session_advisory_lock_listen_and_temp_state(owner):
    key = secrets.randbits(62)
    with db_pool.request_connection() as conn:
        pid = conn.info.backend_pid
        conn.execute("SELECT pg_advisory_lock(%s)", (key,))
        conn.execute("LISTEN noctornal_pool_probe")
        conn.execute("CREATE TEMP TABLE pool_probe (v int)")
        conn.execute("PREPARE pool_probe_statement AS SELECT 1")
        conn.execute("DECLARE pool_probe_cursor CURSOR WITH HOLD FOR SELECT 1")
        conn.execute("SELECT set_config('lock_timeout', '7s', false)")
        conn.execute("SET search_path = public")
        # The login is the owner's in assume mode, so the request role can be left for another.
        conn.execute(f"SET ROLE {db.WORKER_ROLE}")
        dirty = _state(conn)
        assert dirty["current_user"] == db.WORKER_ROLE and dirty["lock_timeout"] == "7s"
        assert (dirty["advisory"], dirty["listening"], dirty["prepared"], dirty["cursors"]) == \
            (1, 1, 1, 1) and dirty["temp"] is not None
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid == pid
        state = _state(conn)
        _clean(state)
        baseline = _baseline()
        for name in ("lock_timeout", "search_path", "statement_timeout", "jit"):
            assert state[name] == baseline[name], name
    # And the lock is free for anyone else.
    assert owner.execute("SELECT pg_try_advisory_lock(%s)", (key,)).fetchone()[0]
    owner.execute("SELECT pg_advisory_unlock(%s)", (key,))


def test_a_statement_a_request_repeats_is_still_served_after_the_reset(owner):
    """psycopg prepares a statement on the server once a connection has run it five times, and
    DISCARD ALL deallocates it there; psycopg forgets its own record of it only when the DISCARD
    is a statement it has not seen before. So from the second reset on, a request that repeated a
    statement left the next one asking the server for a prepared statement that no longer exists.
    A pooled connection never prepares: its `prepare_threshold` is None."""
    repeated = "SELECT count(*) FROM pg_catalog.pg_class WHERE relkind = %s"
    pids = set()
    for times in (0, 7, 7, 1):
        with db_pool.request_connection() as conn:
            pids.add(conn.info.backend_pid)
            for _ in range(times):
                conn.execute(repeated, ("r",)).fetchone()
    assert len(pids) == 1
    with db_pool.request_connection() as conn:
        assert conn.prepare_threshold is None
        for _ in range(7):
            conn.execute(repeated, ("r",)).fetchone()
        assert not conn.execute("SELECT count(*) FROM pg_prepared_statements").fetchone()[0]


def test_a_pooled_connection_keeps_the_request_connections_own_settings(owner):
    """The startup options are the session's defaults, so DISCARD ALL returns to them rather than
    to the server's: jit stays off and the statement timeout stays bounded."""
    baseline = _baseline()
    assert baseline["jit"] == "off"
    assert baseline["statement_timeout"] == "2min"
    with db_pool.request_connection() as conn:
        pid = conn.info.backend_pid
        conn.execute("SET jit = on")
        conn.execute("SET statement_timeout = 0")
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid == pid
        state = _state(conn)
        assert (state["jit"], state["statement_timeout"]) == ("off", "2min")


def test_a_pooled_connection_keeps_the_assumed_request_role_after_a_reset(owner):
    with db_pool.request_connection() as conn:
        pid = conn.info.backend_pid
        conn.execute("RESET ROLE")
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid == pid
        assert conn.execute("SELECT current_user").fetchone()[0] == db.APP_ROLE
        assert db.is_exempt(conn) is False


def test_the_exempt_cache_is_rederived_after_a_reset(owner):
    with db_pool.request_connection() as conn:
        first = conn
        db._EXEMPT[conn] = True
    with db_pool.request_connection() as conn:
        assert conn is first, "the pool of one handed out another connection"
        assert conn not in db._EXEMPT
        assert db.is_exempt(conn) is False


def test_a_connection_returned_mid_transaction_is_rolled_back(owner):
    key = secrets.randbits(62)
    with pytest.raises(RuntimeError, match="the route failed"):
        with db_pool.request_connection() as conn:
            pid = conn.info.backend_pid
            conn.execute("BEGIN")
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (key,))
            assert conn.info.transaction_status == pq.TransactionStatus.INTRANS
            raise RuntimeError("the route failed")
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid == pid
        assert conn.info.transaction_status == pq.TransactionStatus.IDLE
        _clean(_state(conn))
    assert owner.execute("SELECT pg_try_advisory_xact_lock(%s)", (key,)).fetchone()[0]


def test_a_return_waits_behind_a_statement_still_running_in_another_thread(owner):
    """A client that goes away mid-request can leave the route's thread running a statement while
    the dependency's exit runs in another. The return takes psycopg's own lock, so it waits for the
    statement, and the connection goes back idle, not busy and not closed."""
    context = db_pool.request_connection()
    conn = context.__enter__()
    pid = conn.info.backend_pid
    errors: list[BaseException] = []

    def route():
        try:
            conn.execute("SELECT pg_sleep(1.5)")
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    worker = threading.Thread(target=route)
    worker.start()
    time.sleep(0.4)
    started = time.monotonic()
    context.__exit__(None, None, None)
    waited = time.monotonic() - started
    worker.join(10)
    assert not errors, errors
    assert waited >= 0.6, f"the return did not wait for the running statement ({waited:.2f} s)"
    with db_pool.request_connection() as again:
        assert again.info.backend_pid == pid, "the connection was closed, not handed back idle"
        assert again.info.transaction_status == pq.TransactionStatus.IDLE
        _clean(_state(again))


def _raise(conn, assume):
    raise psycopg.OperationalError("the reset failed")


def _leave_a_transaction(conn, assume):
    conn.execute("BEGIN")


@pytest.mark.parametrize("scrub", [_raise, _leave_a_transaction],
                         ids=["raises", "leaves-a-transaction"])
def test_a_connection_whose_reset_fails_is_never_handed_out_again(owner, monkeypatch, scrub):
    """psycopg_pool closes a connection whose reset raises or leaves it outside the idle state;
    the pool's safety rests on that rule, so it is held here."""
    monkeypatch.setattr(db_pool, "_scrub", scrub)
    with db_pool.request_connection() as conn:
        pid = conn.info.backend_pid
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid != pid
        _clean(_state(conn))


_LEFT_BEHIND = {
    "binding": "SELECT set_config('noctornal.rls_proof', 'left behind', false)",
    "ticket-binding": "SELECT set_config('noctornal.rls_ticket', 'left behind', false)",
    "advisory-lock": "SELECT pg_advisory_lock(424242)",
    "listen": "LISTEN noctornal_pool_probe",
    "prepared-statement": "PREPARE pool_probe_statement AS SELECT 1",
    "cursor": "DECLARE pool_probe_cursor CURSOR WITH HOLD FOR SELECT 1",
    "role": f"SET ROLE {db.WORKER_ROLE}",
    "lock-timeout": "SET lock_timeout = '7s'",
    "statement-timeout": "SET statement_timeout = 0",
    "search-path": "SET search_path = public",
    "read-only": "SET default_transaction_read_only = on",
    "isolation": "SET default_transaction_isolation = 'serializable'",
}


@pytest.mark.parametrize("left", sorted(_LEFT_BEHIND))
def test_a_connection_that_comes_back_dirty_fails_the_verify_and_is_discarded(
        owner, monkeypatch, caplog, left):
    """With DISCARD ALL switched off, whatever a request leaves on its connection is caught by the
    read-back and the connection is closed, never handed to the next request."""
    monkeypatch.setattr(db_pool, "_scrub", lambda conn, assume: None)
    with caplog.at_level(logging.ERROR, logger="noctornal.db_pool"):
        with db_pool.request_connection() as conn:
            pid = conn.info.backend_pid
            conn.execute(_LEFT_BEHIND[left])
        with db_pool.request_connection() as conn:
            assert conn.info.backend_pid != pid, f"{left} survived into the next checkout"
            _clean(_state(conn))
    assert any("came back unclean" in r.getMessage() for r in caplog.records)
    assert "left behind" not in caplog.text, "the log names what differed, never its value"


def test_a_connection_whose_driver_settings_changed_is_discarded(owner, monkeypatch):
    monkeypatch.setattr(db_pool, "_scrub", lambda conn, assume: None)
    with db_pool.request_connection() as conn:
        pid = conn.info.backend_pid
        conn.row_factory = dict_row
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid != pid


def test_a_connection_with_autocommit_turned_off_is_discarded(owner):
    with db_pool.request_connection() as conn:
        pid = conn.info.backend_pid
        conn.autocommit = False
    with db_pool.request_connection() as conn:
        assert conn.info.backend_pid != pid
        assert conn.autocommit is True


def test_a_pooled_connection_is_refused_in_production_when_its_role_is_privileged(
        owner, monkeypatch):
    """`db.connect_request`'s refusal holds for a pooled connection too: the owner's own login,
    with no SET ROLE, is a superuser and is never handed to a request."""
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.delenv(db.ASSUME_ROLE_ENV)
    monkeypatch.setattr(db, "_REQUEST_ROLE_PROVEN", set())
    with pytest.raises(db.SystemContextUnavailable):
        with db_pool.request_connection():
            pytest.fail("a privileged connection was handed to a request")


def test_the_pool_is_off_and_each_request_has_its_own_connection_when_told(owner, monkeypatch):
    monkeypatch.setenv(db_pool.POOL_ENV, "off")
    with db_pool.request_connection() as conn:
        assert conn.execute("SELECT current_user").fetchone()[0] == db.APP_ROLE
    assert conn.closed
    assert not db_pool._POOLS


def test_close_pools_closes_every_pool_and_a_connection_still_out_on_return(owner):
    context = db_pool.request_connection()
    conn = context.__enter__()
    pool = next(iter(db_pool._POOLS.values()))
    db_pool.close_pools(timeout=1)
    assert pool.closed and not db_pool._POOLS
    context.__exit__(None, None, None)
    assert conn.closed
