"""The two ledgers draw inside the chain lock and name the writer
(F51, 2026-10-03: evidence-audit-chain-forks, evidence-ledger-actor-time-forgeable).

`audit.event` and `core.evidence_custody` hash-chain every row to the
previous one. Until 0153 the sequence (`seq`, `id`) was a column default
drawn BEFORE the chain trigger took its advisory lock, so two writers could
take the lock in the opposite order to their draws and fork the chain in
ordinary traffic; and the request role could insert a row naming another
user, with any time it liked. These tests hold:

- the order of the steps in each trigger (isolation guard, lock, draw and
  clock, tail) by its text, and the draw inside the lock by behaviour: a
  writer that is waiting for the lock has not drawn;
- the tail read is exact only in READ COMMITTED, so a transaction at any
  other level is refused (verify:g37 tail-read-isolation, 2026-10-03), and a
  row is stamped with the clock at its append, not the start of a transaction
  a request can hold open (evidence-ledger-actor-time-forgeable);
- seq order is chain order under real contention, many writers at once;
- a caller can choose neither its place in the chain nor its time;
- the request role cannot append a row naming a user it is not bound to,
  on either ledger, and every legitimate writer that names a user it is not
  bound to (a session refused before the binding, a sign-out, a refusal
  written out of band) still lands;
- the verifier reads the whole chain as one list and counts a fork written
  since the fix as a break.

Gated like the other row-security tests. Account prefix `rlsled-`.
"""
from __future__ import annotations

import os
import threading
import time
from types import SimpleNamespace
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Json

import rls_support as s

pytestmark = s.GATED

os.environ.setdefault("NOCTORNAL_INGEST_PEPPER", "test-pepper-not-a-real-one")

P = "rlsled-"
AUDIT_LOCK = "audit.event.chain"
CUSTODY_LOCK = "core.evidence_custody.chain"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test')"
    c.execute(f"DELETE FROM lab.download_ticket WHERE user_id IN {users}")
    c.execute(f"DELETE FROM lab.sample WHERE submitted_by IN {users}")
    s.cleanup(c, P)
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(owner, clearance: str = "AMBER", *roles: str):
    uid = s.user(owner, clearance, prefix=P)
    for role in roles:
        s.grant_global(owner, uid, role)
    return uid


def _bound(owner, uid):
    _, raw = s.session(owner, uid)
    return s.app_conn(raw)


def _append_sql(**extra) -> str:
    cols = ["actor_id", "actor_kind", "action", "object_type", "object_id", "detail"]
    return ("INSERT INTO audit.event (" + ", ".join([*extra, *cols]) + ") VALUES ("
            + ", ".join([*[f"%({k})s" for k in extra], "%(actor)s", "%(kind)s",
                         "%(action)s", "'test'", "%(object)s", "%(detail)s"]) + ")")


def _append(conn, object_id, *, actor=None, action="RLSLED_TEST", **extra) -> None:
    conn.execute(_append_sql(**extra), {
        "actor": actor, "kind": "USER" if actor else "SYSTEM", "action": action,
        "object": object_id, "detail": Json({}), **extra})


def _function_text(owner, signature: str) -> str:
    return owner.execute("SELECT prosrc FROM pg_proc WHERE oid = %s::regprocedure",
                         (signature,)).fetchone()[0]


# ---------------------------------------------------------------------------
# The order of the three steps
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("signature,lock,draw,tail", [
    ("audit.chain_hash()", AUDIT_LOCK, "NEW.seq :=", "FROM audit.event e ORDER BY e.seq"),
    ("core.custody_chain_hash()", CUSTODY_LOCK, "NEW.id :=",
     "FROM core.evidence_custody c ORDER BY c.id"),
])
def test_the_ledger_triggers_take_the_lock_before_the_draw(owner, signature, lock, draw, tail):
    """Guard, then lock, then draw and clock, then read the tail. The order is
    the whole fix: a draw before the lock is what forked the chain, a tail
    read before the lock is a stale tail, a clock read before it is the time
    of an earlier moment than the append, and the isolation guard comes first
    so a refusal never queues behind the lock. Held by the text of the
    function a catalog reads, so a later revision that reorders them fails
    here by name (and so does a database that applied an earlier draft of
    0153: the live text is what is read)."""
    text = _function_text(owner, signature)
    flat = " ".join(text.split())
    assert lock in flat, signature
    clock = "NEW.occurred_at := pg_catalog.clock_timestamp()"
    at = {name: flat.find(token) for name, token in
          (("guard", "current_setting('transaction_isolation')"),
           ("lock", "pg_advisory_xact_lock"), ("draw", draw), ("clock", clock),
           ("tail", tail))}
    assert all(position >= 0 for position in at.values()), (signature, at)
    assert at["guard"] < at["lock"] < at["draw"] < at["tail"], (signature, at)
    assert at["lock"] < at["clock"] < at["tail"], (signature, at)
    # now() is the START of the caller's transaction: not the time of an append.
    assert "pg_catalog.now()" not in flat and "NEW.occurred_at := now()" not in flat, signature
    definer, config = owner.execute(
        "SELECT prosecdef, proconfig FROM pg_proc WHERE oid = %s::regprocedure",
        (signature,)).fetchone()
    assert definer and any(c.startswith("search_path=pg_catalog,") for c in config), config


def test_neither_ledger_column_has_a_default_that_draws_outside_the_lock(owner):
    for table, column in (("audit.event", "seq"), ("core.evidence_custody", "id")):
        default = owner.execute(
            "SELECT column_default FROM information_schema.columns "
            "WHERE table_schema || '.' || table_name = %s AND column_name = %s",
            (table, column)).fetchone()[0]
        assert default is None, (table, column, default)


# ---------------------------------------------------------------------------
# The draw is inside the lock, by behaviour
# ---------------------------------------------------------------------------

def _waits_without_drawing(owner, *, lock_name, sequence, insert_sql, params) -> None:
    """Hold the chain lock in one transaction, let a writer start an INSERT
    and wait for it to queue on the lock, then read the sequence. If the
    writer had drawn before the lock (0013's column default) the sequence
    has moved while it waits; inside the lock it has not."""
    from noctornal_api.db import dsn

    holder = psycopg.connect(dsn())
    writer = psycopg.connect(dsn())
    pid = writer.execute("SELECT pg_backend_pid()").fetchone()[0]
    failure: list[BaseException] = []
    before = owner.execute(f"SELECT last_value, is_called FROM {sequence}").fetchone()
    holder.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (lock_name,))

    def write() -> None:
        try:
            writer.execute(insert_sql, params)
        except BaseException as exc:  # noqa: BLE001 - reported below
            failure.append(exc)

    thread = threading.Thread(target=write)
    thread.start()
    try:
        deadline = time.monotonic() + 30
        while True:
            state = owner.execute(
                "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
                (pid,)).fetchone()
            if state and state[0] == "Lock":
                break
            assert time.monotonic() < deadline, "the writer never queued on the chain lock"
            time.sleep(0.05)
        during = owner.execute(f"SELECT last_value, is_called FROM {sequence}").fetchone()
    finally:
        holder.rollback()
        holder.close()
        thread.join(timeout=60)
        writer.rollback()
        writer.close()
    assert not failure, failure
    assert during == before, (
        f"{sequence} moved from {before} to {during} while the writer was still "
        f"waiting for the chain lock: it was drawn before the lock")


def test_an_audit_writer_waiting_for_the_chain_lock_has_not_drawn_its_seq(owner):
    _waits_without_drawing(
        owner, lock_name=AUDIT_LOCK, sequence="audit.event_seq_seq",
        insert_sql=_append_sql(), params={
            "actor": None, "kind": "SYSTEM", "action": "RLSLED_WAIT",
            "object": uuid4(), "detail": Json({})})


def test_a_custody_writer_waiting_for_the_chain_lock_has_not_drawn_its_id(owner):
    boss = _user(owner, "RED")
    case_id = s.case(owner, boss)
    exhibit = s.exhibit(owner, case_id, boss)
    _waits_without_drawing(
        owner, lock_name=CUSTODY_LOCK, sequence="core.evidence_custody_id_seq",
        insert_sql=("INSERT INTO core.evidence_custody (evidence_id, action, actor_id) "
                    "VALUES (%s, 'VIEWED', %s)"),
        params=(exhibit, boss))


# ---------------------------------------------------------------------------
# Seq order is chain order under contention
# ---------------------------------------------------------------------------

def test_seq_order_is_chain_order_when_many_writers_append_at_once(owner):
    """Eight connections, fifteen rows each, released together. Against 0013
    this forked the chain in nearly every run; the rows must be one list in
    seq order, each naming the one before it."""
    start = owner.execute("SELECT coalesce(max(seq), 0) FROM audit.event").fetchone()[0]
    tail = owner.execute("SELECT row_hash FROM audit.event WHERE seq = %s",
                         (start,)).fetchone()
    marker = uuid4()
    conns = [s.owner_conn() for _ in range(8)]
    gate = threading.Barrier(len(conns))
    errors: list[BaseException] = []

    def write(conn) -> None:
        try:
            gate.wait(timeout=30)
            for _ in range(15):
                _append(conn, marker)
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=write, args=(c,)) for c in conns]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    for c in conns:
        c.close()
    assert not errors, errors
    rows = owner.execute("SELECT seq, prev_hash, row_hash, object_id FROM audit.event "
                         "WHERE seq > %s ORDER BY seq", (start,)).fetchall()
    assert sum(1 for r in rows if r[3] == marker) == 8 * 15
    assert len(rows) == 8 * 15, "something else wrote to this database during the test"
    if tail is not None:
        assert bytes(rows[0][1]) == bytes(tail[0])
    for before, row in zip(rows, rows[1:], strict=False):
        assert bytes(row[1]) == bytes(before[2]), (before[0], row[0])


def test_custody_id_order_is_chain_order_when_many_writers_append_at_once(owner):
    boss = _user(owner, "RED")
    case_id = s.case(owner, boss)
    exhibit = s.exhibit(owner, case_id, boss)
    # Each writer commits, or there would be no contention to test. Custody
    # rows are append-only and keep their exhibit, case and account alive, as
    # every custody test's do (rls_support.cleanup), so the numbers are small.
    start = owner.execute("SELECT coalesce(max(id), 0) FROM core.evidence_custody").fetchone()[0]
    conns = [s.owner_conn() for _ in range(4)]
    gate = threading.Barrier(len(conns))
    errors: list[BaseException] = []

    def write(conn) -> None:
        try:
            gate.wait(timeout=30)
            for _ in range(4):
                conn.execute("INSERT INTO core.evidence_custody "
                             "(evidence_id, action, actor_id) VALUES (%s, 'VIEWED', %s)",
                             (exhibit, boss))
        except BaseException as exc:  # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=write, args=(c,)) for c in conns]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=120)
    for c in conns:
        c.close()
    assert not errors, errors
    rows = owner.execute("SELECT id, prev_hash, row_hash FROM core.evidence_custody "
                         "WHERE id > %s ORDER BY id", (start,)).fetchall()
    assert len(rows) == 4 * 4
    for before, row in zip(rows, rows[1:], strict=False):
        assert bytes(row[1]) == bytes(before[2]), (before[0], row[0])


# ---------------------------------------------------------------------------
# A caller chooses neither its place in the chain nor its time
# ---------------------------------------------------------------------------

def test_an_audit_row_gets_the_databases_seq_and_time_whatever_the_caller_sends(owner):
    analyst = _user(owner)
    app = _bound(owner, analyst)
    marker = uuid4()
    try:
        before = owner.execute("SELECT max(seq) FROM audit.event").fetchone()[0]
        _append(app, marker, actor=analyst, seq=1, occurred_at="2020-01-01T00:00:00Z")
    finally:
        app.close()
    seq, occurred_at, age = owner.execute(
        "SELECT seq, occurred_at, now() - occurred_at FROM audit.event "
        "WHERE object_id = %s", (marker,)).fetchone()
    assert seq > before, "the caller chose its own seq"
    assert age.total_seconds() < 300, f"the caller chose its own time: {occurred_at}"


def test_a_custody_row_gets_the_databases_id_and_time_whatever_the_caller_sends(owner):
    analyst = _user(owner, "AMBER", "ANALYST")
    boss = _user(owner, "RED")
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, analyst)
    exhibit = s.exhibit(owner, case_id, boss, "AMBER")
    app = _bound(owner, analyst)
    try:
        before = owner.execute("SELECT coalesce(max(id), 0) FROM core.evidence_custody"
                               ).fetchone()[0]
        with app.transaction(force_rollback=True):
            row = app.execute(
                "INSERT INTO core.evidence_custody (id, evidence_id, action, actor_id, "
                "occurred_at) VALUES (1, %s, 'VIEWED', %s, '2020-01-01T00:00:00Z') "
                "RETURNING id, now() - occurred_at", (exhibit, analyst)).fetchone()
        assert row[0] > before, "the caller chose its own id"
        assert row[1].total_seconds() < 300, "the caller chose its own time"
    finally:
        app.close()


# ---------------------------------------------------------------------------
# The tail read is exact only in READ COMMITTED (verify:g37 tail-read-isolation)
# ---------------------------------------------------------------------------

def _ledger_writer(owner, ledger: str, who: str):
    """(connection, append, rows): `who` ('owner' or 'request') appends to
    `ledger` ('audit' or 'custody'). `rows()` lists what this writer's rows
    came to, as (seq or id, occurred_at) in chain order."""
    analyst = _user(owner, "AMBER", "ANALYST")
    marker = uuid4()
    conn = s.owner_conn() if who == "owner" else _bound(owner, analyst)
    if ledger == "audit":
        def append(c) -> None:
            _append(c, marker, actor=analyst, action="RLSLED_LEDGER")

        def rows():
            return owner.execute("SELECT seq, occurred_at FROM audit.event "
                                 "WHERE object_id = %s ORDER BY seq", (marker,)).fetchall()
    else:
        boss = _user(owner, "RED")
        case_id = s.case(owner, boss)
        s.assign(owner, case_id, analyst)
        exhibit = s.exhibit(owner, case_id, boss, "AMBER")

        def append(c) -> None:
            c.execute("INSERT INTO core.evidence_custody (evidence_id, action, actor_id) "
                      "VALUES (%s, 'VIEWED', %s)", (exhibit, analyst))

        def rows():
            return owner.execute("SELECT id, occurred_at FROM core.evidence_custody "
                                 "WHERE evidence_id = %s ORDER BY id", (exhibit,)).fetchall()
    return conn, append, rows


@pytest.mark.parametrize("level", ["REPEATABLE READ", "SERIALIZABLE"])
@pytest.mark.parametrize("who", ["owner", "request"])
@pytest.mark.parametrize("ledger", ["audit", "custody"])
def test_the_ledger_triggers_refuse_an_append_outside_read_committed(owner, ledger, who, level):
    """Under REPEATABLE READ or SERIALIZABLE the snapshot predates the wait for
    the chain lock, so the tail the trigger reads is stale and the append
    forks the chain, which the verifier counts as tampering. The request role
    chooses its own level, so the trigger refuses rather than trusting the
    caller: a transaction that began at the level, and a session whose
    default is the level."""
    conn, append, rows = _ledger_writer(owner, ledger, who)
    try:
        conn.execute(f"BEGIN ISOLATION LEVEL {level}")
        conn.execute("SELECT 1")
        with pytest.raises(psycopg.errors.InvalidTransactionState) as refused:
            append(conn)
        assert "READ COMMITTED" in str(refused.value) and level.lower() in str(refused.value)
        conn.execute("ROLLBACK")
        conn.execute(f"SET default_transaction_isolation = '{level.lower()}'")
        with pytest.raises(psycopg.errors.InvalidTransactionState):
            append(conn)
    finally:
        conn.close()
    assert rows() == [], "a refused append left a row"


@pytest.mark.parametrize("level", ["READ COMMITTED", "READ UNCOMMITTED"])
@pytest.mark.parametrize("ledger", ["audit", "custody"])
def test_a_read_committed_append_still_lands(owner, ledger, level):
    """The guard refuses the levels that read a stale tail and nothing else.
    PostgreSQL runs READ UNCOMMITTED as READ COMMITTED, a new snapshot per
    statement, so it is as exact."""
    conn, append, rows = _ledger_writer(owner, ledger, "request")
    try:
        conn.execute(f"BEGIN ISOLATION LEVEL {level}")
        conn.execute("SELECT 1")
        append(conn)
        conn.execute("COMMIT")
    finally:
        conn.close()
    assert len(rows()) == 1


def test_a_request_choosing_repeatable_read_cannot_fork_the_audit_chain(owner):
    """The verifier's reproduction: a bound analyst begins REPEATABLE READ and
    takes its snapshot, an honest writer appends and commits, then the analyst
    appends its own row. It used to chain off the stale tail, fork the log and
    make `verify_chain` report tampering that no later write clears. It is
    refused now, the chain stays one list, and its next READ COMMITTED
    append chains to the honest writer's row."""
    from noctornal_api.audit_verify import verify_chain

    analyst = _user(owner)
    marker = uuid4()
    start = owner.execute("SELECT coalesce(max(seq), 0) FROM audit.event").fetchone()[0]
    app = _bound(owner, analyst)
    honest = s.owner_conn()
    try:
        app.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        app.execute("SELECT 1 FROM audit.event WHERE actor_id = %s LIMIT 1", (analyst,))
        _append(honest, marker, action="RLSLED_ISO_HONEST")
        with pytest.raises(psycopg.errors.InvalidTransactionState):
            _append(app, marker, actor=analyst, action="RLSLED_ISO_STALE")
        app.execute("ROLLBACK")
        _append(app, marker, actor=analyst, action="RLSLED_ISO_AFTER")
    finally:
        app.close()
        honest.close()
    report = verify_chain(owner, since_seq=start)
    assert [(b.seq, b.kind) for b in report.breaks if b.seq > start] == []
    assert [f.seq for f in report.forks if f.seq > start] == []
    rows = owner.execute("SELECT action, prev_hash, row_hash FROM audit.event "
                         "WHERE object_id = %s ORDER BY seq", (marker,)).fetchall()
    assert [r[0] for r in rows] == ["RLSLED_ISO_HONEST", "RLSLED_ISO_AFTER"]
    assert bytes(rows[1][1]) == bytes(rows[0][2])


# ---------------------------------------------------------------------------
# A row is stamped at its append (evidence-ledger-actor-time-forgeable)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ledger", ["audit", "custody"])
def test_a_row_is_stamped_at_its_append_not_at_the_start_of_its_transaction(owner, ledger):
    """`now()` is the start of the transaction, and a request can hold one open
    for as long as it likes: stamping with it let a caller back-date a row by
    the transaction's age (8.1 s measured, unbounded). The clock at the append,
    read inside the chain lock, is no earlier than the moment before the
    INSERT."""
    conn, append, rows = _ledger_writer(owner, ledger, "request")
    try:
        conn.execute("BEGIN")
        conn.execute("SELECT pg_sleep(1)")
        before = conn.execute("SELECT clock_timestamp()").fetchone()[0]
        append(conn)
        conn.execute("COMMIT")
    finally:
        conn.close()
    (_, stamped), = rows()
    assert stamped >= before, (
        f"stamped {(before - stamped).total_seconds():.2f} s before its own append")


@pytest.mark.parametrize("ledger", ["audit", "custody"])
def test_time_order_is_chain_order_when_the_earlier_writer_holds_its_transaction_open(
        owner, ledger):
    """A began first and holds its transaction open; B appends and commits;
    then A appends. A is later in the chain, and its time must not be earlier
    than B's, as it was when the time was the transaction's start."""
    slow, slow_append, slow_rows = _ledger_writer(owner, ledger, "request")
    fast, fast_append, fast_rows = _ledger_writer(owner, ledger, "owner")
    try:
        slow.execute("BEGIN")
        slow.execute("SELECT 1")
        time.sleep(1)
        fast_append(fast)
        slow_append(slow)
        slow.execute("COMMIT")
    finally:
        slow.close()
        fast.close()
    (fast_place, fast_at), = fast_rows()
    (slow_place, slow_at), = slow_rows()
    assert slow_place > fast_place, "the writer that appended last is not last in the chain"
    assert slow_at >= fast_at, (
        f"a later row is stamped {(fast_at - slow_at).total_seconds():.2f} s EARLIER")


# ---------------------------------------------------------------------------
# A request writes history in its own name only
# ---------------------------------------------------------------------------

def test_a_bound_request_cannot_append_an_audit_row_naming_another_user(owner):
    analyst, other = _user(owner), _user(owner)
    marker = uuid4()
    app = _bound(owner, analyst)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _append(app, marker, actor=other, action="LEGAL_HOLD_LIFTED")
        # Its own name, and no name, are what it may write.
        _append(app, marker, actor=analyst, action="RLSLED_OWN")
        _append(app, marker, actor=None, action="RLSLED_NOBODY")
    finally:
        app.close()
    assert {r[0] for r in owner.execute(
        "SELECT action FROM audit.event WHERE object_id = %s", (marker,)).fetchall()} == {
        "RLSLED_OWN", "RLSLED_NOBODY"}


def test_an_unbound_request_cannot_append_an_audit_row_naming_anyone(owner):
    victim = _user(owner)
    marker = uuid4()
    app = s.app_conn()
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _append(app, marker, actor=victim, action="AUTH_SUCCEEDED")
        _append(app, marker, actor=None, action="RLSLED_NOBODY")
    finally:
        app.close()
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s",
                   (marker,)) == 1


def test_a_bound_request_cannot_append_a_custody_row_naming_another_user(owner):
    analyst = _user(owner, "AMBER", "ANALYST")
    other = _user(owner)
    boss = _user(owner, "RED")
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, analyst)
    exhibit = s.exhibit(owner, case_id, boss, "AMBER")
    app = _bound(owner, analyst)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("INSERT INTO core.evidence_custody (evidence_id, action, actor_id, "
                        "hash_verified) VALUES (%s, 'EXPORTED', %s, true)", (exhibit, other))
        with app.transaction(force_rollback=True):
            app.execute("INSERT INTO core.evidence_custody (evidence_id, action, actor_id) "
                        "VALUES (%s, 'VIEWED', %s)", (exhibit, analyst))
    finally:
        app.close()
    assert s.count(owner, "SELECT count(*) FROM core.evidence_custody "
                          "WHERE evidence_id = %s", (exhibit,)) == 0


def test_the_system_role_and_the_owner_still_name_whoever_they_must(owner):
    """The policy binds the request role. A sweep, a script, a migration or
    a system purpose is exempt and writes the user it acts for."""
    from noctornal_api.db import SystemPurpose, connect_system

    someone = _user(owner)
    marker = uuid4()
    _append(owner, marker, actor=someone, action="RLSLED_OWNER")
    sconn = connect_system(SystemPurpose.SCRIPT)
    try:
        _append(sconn, marker, actor=someone, action="RLSLED_SYSTEM")
    finally:
        sconn.close()
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s "
                          "AND actor_id = %s", (marker, someone)) == 2


# ---------------------------------------------------------------------------
# The writers that name a user the connection is not bound to still land
# ---------------------------------------------------------------------------

def test_a_session_refusal_before_the_binding_is_still_audited(owner):
    """`deps.current_user` writes SESSION_BINDING_REFUSED naming the session's
    user BEFORE it binds the connection, and RLS_BINDING_FAILED for a binding
    that did not take. Both go through `audit_auth_event`."""
    from noctornal_api.http.deps import audit_auth_event

    user = _user(owner)
    marker = str(uuid4())
    app = s.app_conn()
    try:
        audit_auth_event(app, "SESSION_BINDING_REFUSED", user, None, {"marker": marker})
        audit_auth_event(app, "RLS_BINDING_FAILED", user, None, {"marker": marker})
    finally:
        app.close()
    rows = owner.execute(
        "SELECT action, actor_id, actor_kind FROM audit.event "
        "WHERE detail ->> 'marker' = %s ORDER BY seq", (marker,)).fetchall()
    assert rows == [("SESSION_BINDING_REFUSED", user, "USER"),
                    ("RLS_BINDING_FAILED", user, "USER")]


def test_a_bound_request_audits_in_its_own_connection(owner):
    """The reroute is for the exceptions only: a row naming the bound user
    stays on the request's connection (so it shares its transaction)."""
    from noctornal_api.http.deps import audit_append_connection

    user, other = _user(owner), _user(owner)
    app = _bound(owner, user)
    try:
        with audit_append_connection(app, user) as same, \
                audit_append_connection(app, None) as nobody, \
                audit_append_connection(app, other) as rerouted:
            assert same is app and nobody is app
            assert rerouted is not app
    finally:
        app.close()


def test_a_refusal_written_out_of_band_names_the_refused_user(owner):
    from noctornal_api.approvals import record_out_of_band

    user = _user(owner)
    marker = uuid4()
    app = _bound(owner, user)
    try:
        record_out_of_band(app, action="RLSLED_REFUSED", actor_id=user,
                           object_type="approval_request", object_id=marker,
                           case_id=None, detail={"why": "test"})
    finally:
        app.close()
    assert owner.execute(
        "SELECT actor_id, outcome FROM audit.event WHERE object_id = %s",
        (marker,)).fetchall() == [(user, "DENIED")]


def test_a_row_security_refusal_is_audited_against_the_refused_user(owner):
    from noctornal_api.http.errors import _audit_rls_refused

    user = _user(owner)
    ref = uuid4().hex[:12]
    request = SimpleNamespace(state=SimpleNamespace(noctornal_user_id=user),
                              url=SimpleNamespace(path="/api/v1/test"), method="POST")
    _audit_rls_refused(request, RuntimeError("new row violates row-level security policy"),
                       ref)
    assert owner.execute(
        "SELECT actor_id, outcome FROM audit.event "
        "WHERE action = 'RLS_REFUSED' AND detail ->> 'ref' = %s", (ref,)).fetchall() == [
        (user, "DENIED")]


def test_a_sign_out_is_audited_by_the_request_that_ends_the_session(owner, client):
    """`AUTH_LOGOUT` names the signing-out user. It used to be written AFTER
    the revocation, when the connection was bound to nobody, and row security
    on the log refuses a named row from an unbound connection: the sign-out
    would have 500ed. The row is written first now, in the revocation's own
    transaction."""
    user = _user(owner)
    _, raw = s.session(owner, user)
    r = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {raw}"})
    assert r.status_code == 204, r.text
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE action = 'AUTH_LOGOUT' "
                          "AND actor_id = %s", (user,)) == 1
    again = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {raw}"})
    assert again.status_code == 401, "the session ended"


# ---------------------------------------------------------------------------
# The endpoint says what it cannot see
# ---------------------------------------------------------------------------

def _officer(owner):
    uid = _user(owner, "AMBER", "SECURITY_OFFICER")
    _, raw = s.session(owner, uid)
    return {"Authorization": f"Bearer {raw}"}


def test_the_verify_endpoint_names_its_tail_and_its_blind_spots_on_every_answer(owner, client):
    from noctornal_api.audit_verify import BLIND_SPOTS

    headers = _officer(owner)
    for params in ({}, {"limit": 5}):
        r = client.get("/api/v1/audit/verify", headers=headers, params=params)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["caveat"].startswith(BLIND_SPOTS), body["caveat"]
        assert "end of the log" in body["caveat"] and "anchor_hash" in body["caveat"]
        newest = owner.execute(
            "SELECT seq, encode(row_hash, 'hex') FROM audit.event "
            "ORDER BY seq DESC LIMIT 1").fetchone()
        # The tail is whole-log even when the walk was windowed; the officer's
        # own request wrote rows since, so it may have moved on.
        assert body["tail_seq"] <= newest[0] and len(body["tail_row_hash"]) == 64
        assert body["rows"] >= body["checked"]
        assert body["anchor"] is None
    assert "Windowed" in client.get("/api/v1/audit/verify", headers=headers,
                                    params={"limit": 5}).json()["caveat"]


def test_the_verify_endpoint_checks_an_anchor_it_is_given(owner, client):
    headers = _officer(owner)
    anchor = owner.execute(
        "SELECT seq, encode(row_hash, 'hex') FROM audit.event "
        "ORDER BY seq DESC LIMIT 1").fetchone()
    held = client.get("/api/v1/audit/verify", headers=headers, params={
        "limit": 1, "anchor_seq": anchor[0], "anchor_hash": anchor[1]}).json()
    assert held["anchor"] == {"seq": anchor[0], "row_hash": anchor[1], "held": True}
    assert not [b for b in held["breaks"] if b["kind"] == "ANCHOR"]

    gone = client.get("/api/v1/audit/verify", headers=headers, params={
        "limit": 1, "anchor_seq": anchor[0], "anchor_hash": "0" * 64}).json()
    assert gone["anchor"]["held"] is False and gone["intact"] is False
    assert [b["kind"] for b in gone["breaks"] if b["kind"] == "ANCHOR"] == ["ANCHOR"]


def test_the_verify_endpoint_refuses_half_an_anchor_and_a_malformed_one(owner, client):
    headers = _officer(owner)
    assert client.get("/api/v1/audit/verify", headers=headers,
                      params={"anchor_seq": 5}).status_code == 422
    assert client.get("/api/v1/audit/verify", headers=headers,
                      params={"anchor_hash": "0" * 64}).status_code == 422
    assert client.get("/api/v1/audit/verify", headers=headers, params={
        "anchor_seq": 5, "anchor_hash": "NOT HEX"}).status_code == 422


# ---------------------------------------------------------------------------
# The ledger sequences stay revoked
# ---------------------------------------------------------------------------

def test_runtime_roles_ensure_replays_the_sequence_revoke(owner):
    """`scripts/runtime_roles.py ensure` replays 0108's grants, which hand
    every sequence to the runtime roles, on a cluster whose roles were made
    after their migration ran. 0153's revoke has to be replayed after it or
    the repair would give the ledger sequences back. (Not run here: `ensure`
    rewrites every grant of both roles to 0108's frozen shape.)"""
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    source = (root / "scripts" / "runtime_roles.py").read_text(encoding="utf-8")
    assert '_migration("0153").REVOKE_SQL' in source
    assert source.index('_migration("0108")') < source.index('_migration("0153").REVOKE_SQL')

    import importlib.util
    path = next((root / "db" / "migrations" / "versions").glob("0153_*.py"))
    spec = importlib.util.spec_from_file_location("m0153", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for role in ("noctornal_app", "noctornal_worker"):
        for sequence in ("audit.event_seq_seq", "core.evidence_custody_id_seq"):
            assert f"REVOKE USAGE, SELECT ON SEQUENCE {sequence} FROM {role}" in module.REVOKE_SQL
            assert f"GRANT USAGE, SELECT ON SEQUENCE {sequence} TO {role}" in module.GRANT_SQL
    # And what the replay says, run: idempotent, on a database that has it.
    owner.execute(module.REVOKE_SQL)
    for role in ("noctornal_app", "noctornal_worker"):
        assert not owner.execute(
            "SELECT has_sequence_privilege(%s, 'audit.event_seq_seq', 'USAGE')",
            (role,)).fetchone()[0]


def test_a_request_cannot_move_the_chains_fork_boundary(owner):
    """The verifier reads the latest `AUDIT_CHAIN_SERIALISED` row as the
    point after which no fork is honest. A request that could append one
    could excuse forks, so the INSERT policy refuses the action."""
    analyst = _user(owner)
    marker = uuid4()
    app = _bound(owner, analyst)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _append(app, marker, actor=analyst, action="AUDIT_CHAIN_SERIALISED")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _append(app, marker, actor=None, action="AUDIT_CHAIN_SERIALISED")
    finally:
        app.close()
    assert s.count(owner, "SELECT count(*) FROM audit.event WHERE object_id = %s",
                   (marker,)) == 0


# ---------------------------------------------------------------------------
# A ticket redemption names its ticket's holder (the sample origin runs no
# session and holds no system connection)
# ---------------------------------------------------------------------------

TICKET_EVENTS = ("SAMPLE_DOWNLOAD_TICKET_REDEEMED", "SAMPLE_DOWNLOAD_TICKET_REFUSED",
                 "EVIDENCE_PRODUCTION_TICKET_REDEEMED", "EVIDENCE_PRODUCTION_TICKET_REFUSED")


def _production_ticket(owner, holder, exhibit, *, expired: bool = True) -> str:
    """A production ticket row for `holder`: expired by default (a refusal
    is about a ticket that cannot be spent, which no session binds)."""
    from noctornal_api.security.tokens import hash_token

    raw = uuid4().hex + uuid4().hex
    owner.execute(
        """INSERT INTO lab.download_ticket
               (token_hash, user_id, issued_at, expires_at, purpose, evidence_id)
           VALUES (%s, %s, now() - interval '3 minutes',
                   now() - interval '2 minutes', 'exhibit_production', %s)""",
        (hash_token(raw), holder, exhibit))
    return raw


def test_a_connection_presenting_a_ticket_may_name_its_holder_in_ticket_events_only(owner):
    from noctornal_api.db import present_ticket

    holder, other = _user(owner), _user(owner)
    boss = _user(owner, "RED")
    exhibit = s.exhibit(owner, s.case(owner, boss), boss)
    raw = _production_ticket(owner, holder, exhibit)
    marker = uuid4()
    app = s.app_conn()
    try:
        # No ticket presented: the unbound connection names nobody.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _append(app, marker, actor=holder, action=TICKET_EVENTS[3])
        present_ticket(app, raw)
        for action in TICKET_EVENTS:
            _append(app, marker, actor=holder, action=action)
        # The ticket attributes ticket events about ITS holder and nothing else.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _append(app, marker, actor=holder, action="LEGAL_HOLD_LIFTED")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _append(app, marker, actor=other, action=TICKET_EVENTS[3])
        present_ticket(app, uuid4().hex)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _append(app, marker, actor=holder, action=TICKET_EVENTS[3])
    finally:
        app.close()
    assert {r[0] for r in owner.execute(
        "SELECT action FROM audit.event WHERE object_id = %s", (marker,)).fetchall()} == set(
        TICKET_EVENTS)


def test_an_expired_production_ticket_is_refused_and_audited_against_its_holder(owner):
    """The sample origin spends the ticket on a connection bound to nobody and
    audits the refusal naming the holder. Row security on the log refuses a
    row naming a user from such a connection unless the connection presents
    the user's ticket: `redeem_production_ticket` declares it first."""
    from noctornal_api.evidence import EvidenceService, ProductionRefused

    holder = _user(owner)
    boss = _user(owner, "RED")
    case_id = s.case(owner, boss)
    exhibit = s.exhibit(owner, case_id, boss)
    raw = _production_ticket(owner, holder, exhibit)
    app = s.app_conn()
    try:
        with pytest.raises(ProductionRefused):
            EvidenceService(app, storage=None).redeem_production_ticket(
                raw, case_id=case_id, evidence_id=exhibit)
    finally:
        app.close()
    assert owner.execute(
        "SELECT actor_id, outcome, detail ->> 'reason' FROM audit.event "
        "WHERE action = 'EVIDENCE_PRODUCTION_TICKET_REFUSED' AND object_id = %s",
        (exhibit,)).fetchall() == [(holder, "DENIED", "expired")]


def test_an_expired_lab_ticket_is_refused_and_audited_against_its_holder(owner):
    """The Lab's download ticket takes the same path as an exhibit's: spent on
    the sample origin on a connection bound to nobody, the refusal audited
    naming the holder. `redeem_download_ticket` presents the ticket first."""
    import os

    from noctornal_api.samples import SampleError, SampleService
    from noctornal_api.security.tokens import hash_token

    holder = _user(owner)
    boss = _user(owner, "RED")
    sample = owner.execute(
        """INSERT INTO lab.sample (case_id, sha256, byte_size, storage_key,
                                   storage_bucket, data_key_ciphertext, data_key_id,
                                   submitted_by, classification)
           VALUES (NULL, %s, 10, %s, 'test', %s, 'test', %s, 'GREEN') RETURNING id""",
        (os.urandom(32), f"test/{uuid4().hex}", bytes([1]), boss)).fetchone()[0]
    raw = uuid4().hex + uuid4().hex
    owner.execute(
        """INSERT INTO lab.download_ticket
               (token_hash, user_id, issued_at, expires_at, purpose, sample_id)
           VALUES (%s, %s, now() - interval '3 minutes', now() - interval '2 minutes',
                   'download', %s)""", (hash_token(raw), holder, sample))
    app = s.app_conn()
    try:
        with pytest.raises(SampleError):
            SampleService(app).redeem_download_ticket(raw, sample_id=sample)
    finally:
        app.close()
    assert owner.execute(
        "SELECT actor_id, outcome, detail ->> 'reason' FROM audit.event "
        "WHERE action = 'SAMPLE_DOWNLOAD_TICKET_REFUSED' AND object_id = %s",
        (sample,)).fetchall() == [(holder, "DENIED", "expired")]
