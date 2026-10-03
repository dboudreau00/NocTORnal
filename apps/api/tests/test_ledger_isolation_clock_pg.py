"""The ledgers refuse a stale tail, stamp the append and keep their sequences
to the trigger (F51, 2026-10-03: verify:g37 tail-read-isolation, the time half
of evidence-ledger-actor-time-forgeable, and the sequence side channel).

`audit.event` and `core.evidence_custody` hash-chain every row to the previous
one. 0149 takes the lock, THEN draws the number and reads the tail; 0150 and
0151 pin who a request may name. What the review of the draw-inside-the-lock
work found and 0149 and 0169 hold on top of that, each failing without it:

- the order of the steps in each trigger (isolation guard, lock, draw and
  clock, tail) by the text of the live function, and the draw inside the lock
  by behaviour: a writer that is waiting for the lock has not drawn;
- the tail read is exact only in READ COMMITTED, so a transaction at any other
  level is refused with `invalid_transaction_state` and the chain does not
  fork, while READ COMMITTED and READ UNCOMMITTED still land;
- a row is stamped with the clock at its append, not the start of a
  transaction a request can hold open, and time order is chain order;
- neither ledger column has a default, and the runtime roles hold no privilege
  on either sequence (`SELECT last_value` read the whole log's volume);
- with `audit.event` under row-level security (0168), a request's append still
  chains, is still pinned to who it may name, and an unbound connection's claim
  to a user is kept as a claim and not lost.

The concurrency and the attribution contract themselves are
`test_ledger_chain_g49_pg.py` and `test_ledger_attribution_g49_pg.py`.

Gated like the other row-security tests. Account prefix `rlsled-`.
"""
from __future__ import annotations

import os
import threading
import time
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


def _user(owner, clearance: str = "AMBER", *roles: str):
    uid = s.user(owner, clearance, prefix=P)
    for role in roles:
        s.grant_global(owner, uid, role)
    return uid


def _bound(owner, uid):
    _, raw = s.session(owner, uid)
    return s.app_conn(raw)


def _append_sql() -> str:
    return ("INSERT INTO audit.event (actor_id, actor_kind, action, object_type, "
            "object_id, detail) VALUES (%(actor)s, %(kind)s, %(action)s, 'test', "
            "%(object)s, %(detail)s)")


def _append(conn, object_id, *, actor=None, action="RLSLED_TEST") -> None:
    conn.execute(_append_sql(), {
        "actor": actor, "kind": "USER" if actor else "SYSTEM", "action": action,
        "object": object_id, "detail": Json({})})


def _function_text(owner, signature: str) -> str:
    return owner.execute("SELECT prosrc FROM pg_proc WHERE oid = %s::regprocedure",
                         (signature,)).fetchone()[0]


# ---------------------------------------------------------------------------
# The order of the steps
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("signature,draw,tail", [
    ("audit.chain_hash()", "NEW.seq :=", "FROM audit.event ORDER BY seq DESC"),
    ("core.custody_chain_hash()", "NEW.id :=",
     "FROM core.evidence_custody ORDER BY id DESC"),
])
def test_the_ledger_triggers_take_the_lock_before_the_draw(owner, signature, draw, tail):
    """Guard, then lock, then draw and clock, then read the tail. The order is
    the whole fix: a draw before the lock is what forked the chain, a tail
    read before the lock is a stale tail, a clock read before it is the time
    of an earlier moment than the append, and the isolation guard comes first
    so a refusal never queues behind the lock. Held by the text of the
    function a catalog reads, so a later revision that reorders them fails
    here by name (and so does a database that applied an earlier draft of
    0149: the live text is what is read)."""
    flat = " ".join(_function_text(owner, signature).split())
    clock = "NEW.occurred_at := pg_catalog.clock_timestamp()"
    at = {name: flat.find(token) for name, token in
          (("guard", "current_setting('transaction_isolation')"),
           ("lock", "pg_advisory_xact_lock"), ("draw", draw), ("clock", clock),
           ("tail", tail))}
    assert all(position >= 0 for position in at.values()), (signature, at)
    assert at["guard"] < at["lock"] < at["draw"] < at["tail"], (signature, at)
    assert at["lock"] < at["clock"] < at["tail"], (signature, at)
    # now() is the START of the caller's transaction: not the time of an append.
    assert "NEW.occurred_at := now()" not in flat, signature
    assert "NEW.occurred_at := pg_catalog.now()" not in flat, signature
    if signature.startswith("audit."):
        # The caller 0150 pins, and nobody else: that trigger marks the row
        # (`infinity`) and the chain replaces the mark with the clock, so an
        # exempt writer keeps its time and the serialised section makes no
        # catalog read of its own (no second exemption test inside the lock).
        mark = flat.find("NEW.occurred_at = 'infinity'")
        assert at["lock"] < mark < at["clock"], at
        assert "rls_caller_exempt" not in flat, "a catalog read inside the chain trigger"
    definer, config = owner.execute(
        "SELECT prosecdef, proconfig FROM pg_proc WHERE oid = %s::regprocedure",
        (signature,)).fetchone()
    assert definer and any(c.startswith("search_path=pg_catalog,") for c in config), config


def test_the_attribution_trigger_marks_the_rows_the_chain_dates(owner):
    """0150 runs before the lock and tests the caller once. For a caller row
    security binds it marks `occurred_at`; for an exempt one it returns first,
    so the mark is never put on a row the chain must leave alone."""
    flat = " ".join(_function_text(owner, "audit.pin_attribution()").split())
    exempt = flat.find("iam.rls_caller_exempt()")
    mark = flat.find("NEW.occurred_at := 'infinity'")
    returns = flat.find("RETURN NEW", exempt)
    assert 0 <= exempt < returns < mark, (exempt, returns, mark)


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
# The tail read is exact only in READ COMMITTED
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
# A row is stamped at its append
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


def test_an_exempt_audit_writer_keeps_the_time_it_supplies(owner):
    """0150's line, unchanged by the clock: the owner and the system role write
    on behalf of people at times they choose (a migration's carried rows, a
    fixture), and only the caller row security binds is dated by the
    database."""
    marker = uuid4()
    owner.execute(
        "INSERT INTO audit.event (occurred_at, actor_kind, action, object_type, "
        "object_id, detail) VALUES ('2020-01-01T00:00:00Z', 'SYSTEM', 'RLSLED_OWN_TIME', "
        "'test', %s, '{}')", (marker,))
    year = owner.execute("SELECT extract(year FROM occurred_at) FROM audit.event "
                         "WHERE object_id = %s", (marker,)).fetchone()[0]
    assert year == 2020


# ---------------------------------------------------------------------------
# The sequences are the trigger's alone (0169)
# ---------------------------------------------------------------------------

def test_runtime_roles_ensure_replays_the_sequence_revoke(owner):
    """`scripts/runtime_roles.py ensure` replays 0108's grants, which hand
    every sequence to the runtime roles, on a cluster whose roles were made
    after their migration ran. 0169's revoke has to be replayed after it or
    the repair would give the ledger sequences back. (Not run here: `ensure`
    rewrites every grant of both roles to 0108's frozen shape.)"""
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[3]
    source = (root / "scripts" / "runtime_roles.py").read_text(encoding="utf-8")
    assert 'sequences.REVOKE_SQL' in source
    assert source.index('_migration("0108")') < source.index("sequences.REVOKE_SQL")

    path = next((root / "db" / "migrations" / "versions").glob("0169_*.py"))
    spec = importlib.util.spec_from_file_location("m0169", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "0169"
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


def test_a_request_cannot_read_or_draw_the_ledger_sequences(owner):
    analyst = _user(owner)
    app = _bound(owner, analyst)
    try:
        for statement in ("SELECT last_value FROM audit.event_seq_seq",
                          "SELECT nextval('audit.event_seq_seq')",
                          "SELECT last_value FROM core.evidence_custody_id_seq",
                          "SELECT nextval('core.evidence_custody_id_seq')"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(statement)
            app.execute("ROLLBACK")
    finally:
        app.close()


# ---------------------------------------------------------------------------
# The pin composes with row-level security on the log (0168)
# ---------------------------------------------------------------------------

def test_the_attribution_pin_holds_with_the_insert_policy_in_place(owner):
    """The log is under row-level security and its INSERT policy admits every
    append. What a request may name is the pin's (0150), and it fires first:
    another user is refused, a claim from a connection bound to nobody lands
    without an actor and keeps the claim, and the row chains to the true tail
    whoever it is written by, a row its writer may not read included."""
    from noctornal_api.audit_verify import verify_chain

    assert owner.execute(
        "SELECT relrowsecurity FROM pg_class WHERE oid = 'audit.event'::regclass"
    ).fetchone()[0] is True
    (check,) = owner.execute(
        "SELECT with_check FROM pg_policies WHERE schemaname = 'audit' "
        "AND tablename = 'event' AND cmd = 'INSERT'").fetchone()
    assert check.strip().lower() == "true", check

    analyst, other, victim = _user(owner), _user(owner), _user(owner)
    marker = uuid4()
    start = owner.execute("SELECT coalesce(max(seq), 0) FROM audit.event").fetchone()[0]
    bound, unbound = _bound(owner, analyst), s.app_conn()
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            _append(bound, marker, actor=other, action="RLSLED_FORGED")
        _append(bound, marker, actor=analyst, action="RLSLED_OWN")
        _append(unbound, marker, actor=victim, action="RLSLED_UNBOUND")
    finally:
        bound.close()
        unbound.close()
    rows = {r[0]: r[1:] for r in owner.execute(
        "SELECT action, actor_id, detail ->> 'unverified_actor_id' FROM audit.event "
        "WHERE object_id = %s", (marker,)).fetchall()}
    assert rows == {"RLSLED_OWN": (analyst, None),
                    "RLSLED_UNBOUND": (None, str(victim))}
    report = verify_chain(owner, since_seq=start)
    assert [b for b in report.breaks if b.seq > start] == []
    assert [f for f in report.forks if f.seq > start] == []


def test_an_expired_production_ticket_is_refused_and_audited_with_its_holder_as_a_claim(owner):
    """The sample origin spends the ticket on a connection bound to nobody and
    audits the refusal naming the holder. The database cannot vouch for the
    holder of a ticket that was never spent, so the row, which the policy
    admits, names nobody and keeps the claim in its detail (0150): the refusal
    of an attempt is never lost to row security on the log."""
    from noctornal_api.evidence import EvidenceService, ProductionRefused
    from noctornal_api.security.tokens import hash_token

    holder = _user(owner)
    boss = _user(owner, "RED")
    case_id = s.case(owner, boss)
    exhibit = s.exhibit(owner, case_id, boss)
    raw = uuid4().hex + uuid4().hex
    owner.execute(
        """INSERT INTO lab.download_ticket
               (token_hash, user_id, issued_at, expires_at, purpose, evidence_id)
           VALUES (%s, %s, now() - interval '3 minutes',
                   now() - interval '2 minutes', 'exhibit_production', %s)""",
        (hash_token(raw), holder, exhibit))
    app = s.app_conn()
    try:
        with pytest.raises(ProductionRefused):
            EvidenceService(app, storage=None).redeem_production_ticket(
                raw, case_id=case_id, evidence_id=exhibit)
    finally:
        app.close()
    assert owner.execute(
        "SELECT actor_id, outcome, detail ->> 'reason', detail ->> 'unverified_actor_id' "
        "FROM audit.event "
        "WHERE action = 'EVIDENCE_PRODUCTION_TICKET_REFUSED' AND object_id = %s",
        (exhibit,)).fetchall() == [(None, "DENIED", "expired", str(holder))]
