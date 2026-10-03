"""One chain, however many writers (evidence-audit-chain-forks, 2026-10-03).

`audit.event.seq` and `core.evidence_custody.id` were serial columns drawn
BEFORE the BEFORE INSERT trigger took the advisory lock that serialises the
chain. Two writers handed 33 and 34 could reach the lock in the opposite
order: 34 chained off the old tail, 33 then chained off 34, and the next
writer, which takes the HIGHEST number as the tail, chained off 34 too. Row
33 became a dead end that nothing names as a predecessor, and a dead end is a
row an owner can delete while the verifier still says intact. 0149 draws the
number inside the lock.

What these tests hold, each against the unfixed trigger as well as the fixed
one (they fail without 0149):

- CONCURRENCY: writers on three roles (the owner, the system role, the
  request role bound to a user) append at once, twenty rounds each, and the
  rows after the watermark form ONE linked list in number order, with no fork;
- THE MECHANISM, deterministically: a caller that supplies a high number and
  then a low one used to chain the low one off the high one; the number is now
  the trigger's, so number order is chain order whatever the caller says;
- THE VERIFIER: a fork written after the boundary 0149 records is a break and
  makes `intact` false; one with a claimant at or below it is legacy and is
  only listed; a database that has no boundary treats every fork as legacy;
- THE FUNCTIONS: both chain functions run as the definer with a pinned path,
  the boundary functions exist, and the attribution trigger fires before the
  chain trigger;
- THE MIGRATIONS: 0149, 0150 and 0151 downgrade and upgrade again, in a
  rolled-back transaction, leaving the database as it was.

Rows these tests commit stay (both ledgers are append-only); they are
recognisable by their `G49_CHAIN_` actions.
"""
from __future__ import annotations

import importlib.util
import os
import threading
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

import rls_support as s

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"), reason="needs a migrated database")

ROUNDS = 20
WRITERS = 6
PER_WRITER = 25
ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"

APP = os.environ.get("NOCTORNAL_APP_DB_ROLE", "").strip()
WORKER = os.environ.get("NOCTORNAL_WORKER_DB_ROLE", "noctornal_worker").strip()


@pytest.fixture()
def tamperable():
    """A non-autocommit connection whose work is always rolled back."""
    from noctornal_api.db import dsn
    conn = psycopg.connect(dsn())
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _run(writers) -> list[str]:
    """Start every writer at once, return what went wrong."""
    gate = threading.Barrier(len(writers))
    problems: list[str] = []

    def work(open_conn, insert):
        try:
            conn = open_conn()
            try:
                gate.wait(timeout=60)
                for i in range(PER_WRITER):
                    insert(conn, i)
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001 - reported by the caller
            problems.append(repr(exc))

    threads = [threading.Thread(target=work, args=pair) for pair in writers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=300)
    return problems


# ---------------------------------------------------------------------------
# Concurrency, on the audit chain
# ---------------------------------------------------------------------------

_BAD_LINKS = """
SELECT count(*) FROM audit.event e
 WHERE e.seq > %s
   AND e.prev_hash IS DISTINCT FROM
       (SELECT p.row_hash FROM audit.event p
         WHERE p.seq < e.seq ORDER BY p.seq DESC LIMIT 1)"""


def _audit_writers(tag: str, analyst=None, raw=None):
    from noctornal_api.db import connect

    def owner():
        return connect()

    def worker():
        c = connect()
        c.execute(f"SET ROLE {WORKER}")
        return c

    def app_bound():
        return s.app_conn(raw)

    def insert(actor):
        def _insert(conn, i):
            conn.execute(
                "INSERT INTO audit.event (actor_id, actor_kind, action, detail) "
                "VALUES (%s, %s, %s, '{}'::jsonb)",
                (actor, "USER" if actor else "SYSTEM", f"G49_CHAIN_{tag}_{i}"))
        return _insert

    pairs = [(owner, insert(None)), (owner, insert(None))]
    if os.environ.get("NOCTORNAL_APP_DB_ROLE"):
        pairs += [(worker, insert(None)), (worker, insert(None)),
                  (app_bound, insert(analyst)), (app_bound, insert(None))]
    else:
        pairs += [(owner, insert(None))] * 4
    return pairs


@pytest.mark.parametrize("round_", range(ROUNDS))
def test_concurrent_appends_by_every_role_form_one_chain(round_):
    from noctornal_api.audit_verify import verify_chain
    from noctornal_api.db import connect

    owner = connect()
    analyst = raw = None
    try:
        if APP:
            analyst = s.user(owner, "AMBER", prefix="g49c-")
            _, raw = s.session(owner, analyst)
        start = owner.execute(
            "SELECT coalesce(max(seq), 0) FROM audit.event").fetchone()[0]
        tag = uuid4().hex[:8]
        problems = _run(_audit_writers(tag, analyst, raw))
        assert not problems, problems

        written = owner.execute(
            "SELECT count(*) FROM audit.event WHERE action LIKE %s",
            (f"G49_CHAIN_{tag}_%",)).fetchone()[0]
        assert written == WRITERS * PER_WRITER, written
        bad = owner.execute(_BAD_LINKS, (start,)).fetchone()[0]
        assert bad == 0, (
            f"{bad} rows chained off a row that was not the one before them: "
            "the chain forked under concurrent writers")
        report = verify_chain(owner, since_seq=start)
        assert report.checked >= written
        assert not report.forks, [f.seq for f in report.forks]
        assert report.intact, [b.kind for b in report.breaks]
    finally:
        s.cleanup(owner, "g49c-")
        owner.close()


# ---------------------------------------------------------------------------
# Concurrency, on the custody chain
# ---------------------------------------------------------------------------

_BAD_CUSTODY_LINKS = """
SELECT count(*) FROM core.evidence_custody e
 WHERE e.id > %s
   AND e.prev_hash IS DISTINCT FROM
       (SELECT p.row_hash FROM core.evidence_custody p
         WHERE p.id < e.id ORDER BY p.id DESC LIMIT 1)"""


@pytest.mark.parametrize("round_", range(ROUNDS))
def test_concurrent_custody_appends_form_one_chain(round_):
    from noctornal_api.custody_verify import verify_custody_chain
    from noctornal_api.db import connect

    owner = connect()
    try:
        boss = s.user(owner, "RED", prefix="g49d-")
        analyst = s.user(owner, "AMBER", prefix="g49d-")
        case = s.case(owner, boss)
        s.assign(owner, case, analyst)
        exhibit = s.exhibit(owner, case, boss)
        _, raw = s.session(owner, analyst)
        start = owner.execute(
            "SELECT coalesce(max(id), 0) FROM core.evidence_custody").fetchone()[0]

        def insert(actor):
            def _insert(conn, i):
                conn.execute(
                    "INSERT INTO core.evidence_custody "
                    "(evidence_id, action, actor_id, detail) "
                    "VALUES (%s, 'VIEWED', %s, %s::jsonb)",
                    (exhibit, actor, '{"g49": %d}' % i))
            return _insert

        def worker():
            c = connect()
            c.execute(f"SET ROLE {WORKER}")
            return c

        writers = [(connect, insert(boss)), (connect, insert(boss))]
        if APP:
            writers += [(worker, insert(boss)), (worker, insert(analyst)),
                        (lambda: s.app_conn(raw), insert(analyst)),
                        (lambda: s.app_conn(raw), insert(analyst))]
        else:
            writers += [(connect, insert(boss))] * 4
        problems = _run(writers)
        assert not problems, problems

        written = owner.execute(
            "SELECT count(*) FROM core.evidence_custody WHERE evidence_id = %s",
            (exhibit,)).fetchone()[0]
        assert written == WRITERS * PER_WRITER, written
        bad = owner.execute(_BAD_CUSTODY_LINKS, (start,)).fetchone()[0]
        assert bad == 0, (
            f"{bad} custody rows chained off a row that was not the one before "
            "them: the ledger forked under concurrent writers")
        report = verify_custody_chain(owner, evidence_id=exhibit)
        assert report.intact, [b.kind for b in report.breaks]
        assert not [f for f in verify_custody_chain(owner).forks if f.id > start]
    finally:
        s.cleanup(owner, "g49d-")
        owner.close()


# ---------------------------------------------------------------------------
# The mechanism, deterministically
# ---------------------------------------------------------------------------

def test_a_caller_cannot_choose_the_audit_number_so_the_chain_follows_it(tamperable):
    """The old trigger honoured a supplied `seq`: a high number first and a
    low one second chained the LOW row off the HIGH one, which is the
    inversion two concurrent writers produced by accident. The number is the
    trigger's now, drawn inside the lock, so the second row is numbered above
    the first and chains off it whatever either asked for."""
    ins = ("INSERT INTO audit.event (seq, actor_kind, action, detail) "
           "VALUES (%s, 'SYSTEM', %s, '{}'::jsonb) "
           "RETURNING seq, encode(prev_hash, 'hex'), encode(row_hash, 'hex')")
    high = 10 ** 15
    first = tamperable.execute(ins, (high, "G49_CHAIN_HIGH")).fetchone()
    second = tamperable.execute(ins, (high - 5000, "G49_CHAIN_LOW")).fetchone()
    assert first[0] != high, "the caller's number was kept"
    assert second[0] > first[0], "the later append has the lower number"
    assert second[1] == first[2], "the later append did not chain off the earlier"


def test_a_caller_cannot_choose_the_custody_id_so_the_chain_follows_it(tamperable):
    uid, ev = _custody_fixture(tamperable)
    ins = ("INSERT INTO core.evidence_custody (id, evidence_id, action, actor_id) "
           "VALUES (%s, %s, 'VIEWED', %s) "
           "RETURNING id, encode(prev_hash, 'hex'), encode(row_hash, 'hex')")
    high = 10 ** 15
    first = tamperable.execute(ins, (high, ev, uid)).fetchone()
    second = tamperable.execute(ins, (high - 5000, ev, uid)).fetchone()
    assert first[0] != high
    assert second[0] > first[0]
    assert second[1] == first[2]


def _custody_fixture(conn):
    """A user and an exhibit row, inside the rolled-back transaction."""
    uid = s.user(conn, "RED", prefix="g49m-")
    case = s.case(conn, uid)
    return uid, s.exhibit(conn, case, uid)


def test_a_chain_is_only_extended_from_a_snapshot_that_can_see_the_tail(tamperable):
    """A REPEATABLE READ transaction would read the tail as of its own
    snapshot, miss a row committed since, and fork the chain. Refused, as
    nothing in the product opens one, with `invalid_transaction_state` (the
    full matrix of levels, roles and ledgers is
    `test_ledger_isolation_clock_pg.py`)."""
    tamperable.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
    tamperable.execute("SELECT 1")
    with pytest.raises(psycopg.errors.InvalidTransactionState, match="READ COMMITTED"):
        tamperable.execute(
            "INSERT INTO audit.event (actor_kind, action, detail) "
            "VALUES ('SYSTEM', 'G49_CHAIN_RR', '{}'::jsonb)")


# ---------------------------------------------------------------------------
# The verifier
# ---------------------------------------------------------------------------

def _seed(conn, n: int = 4) -> int:
    start = conn.execute("SELECT coalesce(max(seq), 0) FROM audit.event").fetchone()[0]
    for i in range(n):
        conn.execute(
            "INSERT INTO audit.event (actor_kind, action, outcome, detail) "
            "VALUES ('USER', %s, 'SUCCESS', '{}'::jsonb)", (f"G49_CHAIN_SEED_{i}",))
    return start


def _twin(conn, seq=None, action="G49_CHAIN_TWIN") -> None:
    """A second row claiming the newest row's predecessor, LINK-clean and
    CONTENT-clean (its hash is computed with the verifier's own expression),
    so the only thing wrong with it is the fork. `seq` None takes the default
    number, which is above the boundary."""
    from noctornal_api.audit_verify import _HASH_EXPR

    conn.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    if seq is None:
        seq = conn.execute("SELECT nextval('audit.event_seq_seq')").fetchone()[0]
    conn.execute(
        """INSERT INTO audit.event (seq, actor_kind, action, outcome, detail,
                                    prev_hash, row_hash)
           SELECT %s, 'USER', %s, 'SUCCESS', '{}'::jsonb, e.prev_hash,
                  decode('00', 'hex')
             FROM audit.event e
            WHERE e.seq = (SELECT max(seq) FROM audit.event WHERE seq > 0)""",
        (seq, action))
    conn.execute(
        f"UPDATE audit.event AS e SET row_hash = {_HASH_EXPR} WHERE e.seq = %s",
        (seq,))


def test_the_boundary_is_recorded_and_every_new_row_is_above_it(tamperable):
    boundary = tamperable.execute("SELECT audit.chain_ordered_after()").fetchone()[0]
    assert boundary >= 0
    start = _seed(tamperable)
    assert start >= boundary, "rows written since 0149 are numbered above it"
    custody = tamperable.execute(
        "SELECT core.custody_chain_ordered_after()").fetchone()[0]
    assert custody >= 0


def test_a_fork_above_the_boundary_is_a_break_and_is_not_intact(tamperable):
    """Before 0149 this was filed as 'not tampering'. A dead end written now
    cannot come from honest traffic, and it is the row an owner can delete
    without orphaning anything."""
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable)
    _twin(tamperable)
    report = verify_chain(tamperable, since_seq=since)
    assert [f.kind for f in report.forks] == ["FORK", "FORK"]
    assert [b.kind for b in report.breaks] == ["FORK", "FORK"], \
        "a fork above the boundary must be a break"
    assert not report.intact
    assert report.fork_boundary is not None


def test_a_fork_with_a_legacy_claimant_is_listed_and_is_not_a_break(tamperable):
    """The forks the old order wrote stay what they were: listed, never an
    accusation, because an append-only table cannot be cleaned of them and
    counting them made the endpoint answer BROKEN on untouched history."""
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable)
    _twin(tamperable, seq=-1)
    report = verify_chain(tamperable, since_seq=since)
    assert report.forks, "the legacy fork was not listed at all"
    assert not report.breaks, [b.kind for b in report.breaks]
    assert report.intact


def test_without_a_boundary_every_fork_is_legacy(tamperable):
    """A database that has not run 0149 has no boundary, and its forks are
    the old order's."""
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable)
    _twin(tamperable)
    tamperable.execute("DROP FUNCTION audit.chain_ordered_after()")
    report = verify_chain(tamperable, since_seq=since)
    assert report.fork_boundary is None
    assert report.forks and not report.breaks
    assert report.intact


def test_a_fork_does_not_mask_real_tampering(tamperable):
    """An edited row that is also forked is still a CONTENT break."""
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable)
    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute(
        "UPDATE audit.event SET action = 'G49_CHAIN_EDITED' "
        "WHERE seq = (SELECT max(seq) FROM audit.event)")
    _twin(tamperable)
    report = verify_chain(tamperable, since_seq=since)
    kinds = [b.kind for b in report.breaks]
    assert "CONTENT" in kinds and "FORK" in kinds, kinds


def test_a_custody_fork_above_the_boundary_is_a_break_too(tamperable):
    from noctornal_api.custody_verify import _HASH_EXPR, verify_custody_chain

    uid, ev = _custody_fixture(tamperable)
    for _ in range(3):
        tamperable.execute(
            "INSERT INTO core.evidence_custody (evidence_id, action, actor_id) "
            "VALUES (%s, 'VIEWED', %s)", (ev, uid))
    tamperable.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
    new_id = tamperable.execute(
        "SELECT nextval('core.evidence_custody_id_seq')").fetchone()[0]
    tamperable.execute(
        """INSERT INTO core.evidence_custody
               (id, evidence_id, action, actor_id, detail, prev_hash, row_hash)
           SELECT %s, c.evidence_id, 'VIEWED', c.actor_id, '{}'::jsonb,
                  c.prev_hash, decode('00', 'hex')
             FROM core.evidence_custody c
            WHERE c.id = (SELECT max(id) FROM core.evidence_custody)""", (new_id,))
    tamperable.execute(
        f"UPDATE core.evidence_custody AS c SET row_hash = {_HASH_EXPR} "
        "WHERE c.id = %s", (new_id,))
    report = verify_custody_chain(tamperable, evidence_id=ev)
    assert report.forks
    assert any(b.kind == "FORK" for b in report.breaks), \
        "a custody fork above the boundary must be a break"
    assert not report.intact


# ---------------------------------------------------------------------------
# The functions and the migrations
# ---------------------------------------------------------------------------

def test_the_chain_functions_run_as_the_definer_and_pin_their_path(tamperable):
    """Both read the tail of a ledger and must read the REAL tail whoever is
    writing: a role that row security filters would read a filtered tail and
    fork the chain."""
    rows = tamperable.execute(
        """SELECT p.oid::regprocedure::text, p.prosecdef, coalesce(p.proconfig, '{}')
             FROM pg_proc p
            WHERE p.oid IN ('audit.chain_hash()'::regprocedure,
                            'core.custody_chain_hash()'::regprocedure,
                            'audit.pin_attribution()'::regprocedure)""").fetchall()
    assert len(rows) == 3, rows
    for fn, definer, config in rows:
        assert definer, f"{fn} must be SECURITY DEFINER"
        paths = [c for c in config if c.startswith("search_path=")]
        assert paths, f"{fn} has no pinned search_path"
        names = [n.strip() for n in paths[0].split("=", 1)[1].split(",")]
        assert names[0] == "pg_catalog" and names[-1] == "pg_temp", (fn, names)


def test_the_attribution_trigger_fires_before_the_chain_trigger(tamperable):
    """BEFORE row triggers run in name order, and the chain hashes the values
    the attribution trigger pins."""
    names = [r[0] for r in tamperable.execute(
        """SELECT tgname FROM pg_trigger
            WHERE tgrelid = 'audit.event'::regclass AND NOT tgisinternal
              AND (tgtype & 2) = 2 AND (tgtype & 4) = 4 AND (tgtype & 1) = 1
            ORDER BY tgname""").fetchall()]
    assert names == ["audit_attribution", "audit_chain"], names


def _migration(prefix: str):
    path = next(VERSIONS.glob(f"{prefix}_*.py"))
    spec = importlib.util.spec_from_file_location(f"g49_{prefix}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _state(conn) -> dict:
    out = {}
    for fn in ("audit.chain_hash()", "core.custody_chain_hash()"):
        out[fn] = conn.execute(
            "SELECT pg_get_functiondef(%s::regprocedure)", (fn,)).fetchone()[0]
    out["triggers"] = [r[0] for r in conn.execute(
        """SELECT tgname FROM pg_trigger
            WHERE tgrelid IN ('audit.event'::regclass, 'core.evidence_custody'::regclass)
              AND NOT tgisinternal ORDER BY tgname""").fetchall()]
    out["policy"] = conn.execute(
        """SELECT with_check FROM pg_policies
            WHERE schemaname = 'core' AND tablename = 'evidence_custody'
              AND policyname = 'rls_append'""").fetchone()[0]
    return out


def test_the_migrations_downgrade_and_upgrade_again(tamperable):
    """0149, 0150 and 0151 each go down and up. In a transaction that is
    rolled back, so nothing persists and no other test sees the old trigger."""
    m0, m1, m2 = _migration("0149"), _migration("0150"), _migration("0151")
    before = _state(tamperable)
    assert "rls_actor" in before["policy"], "0151 is not applied on this database"
    assert "audit_attribution" in before["triggers"], "0150 is not applied"

    tamperable.execute(m2.DOWNGRADE_SQL)
    tamperable.execute(m1.DOWNGRADE_SQL)
    tamperable.execute(m0.DOWNGRADE_SQL)
    down = _state(tamperable)
    assert "audit_attribution" not in down["triggers"]
    assert "SECURITY DEFINER" not in down["audit.chain_hash()"], \
        "0149's downgrade left the audit chain function as the definer"
    assert "nextval" not in down["audit.chain_hash()"]
    assert "rls_actor" not in down["policy"]
    assert tamperable.execute(
        "SELECT to_regprocedure('audit.chain_ordered_after()')").fetchone()[0] is None

    tamperable.execute(m0.UPGRADE_SQL)
    tamperable.execute(m1.UPGRADE_SQL)
    tamperable.execute(m2.UPGRADE_SQL)
    after = _state(tamperable)
    assert after == before, "downgrade then upgrade did not restore the state"
    assert tamperable.execute(
        "SELECT audit.chain_ordered_after()").fetchone()[0] >= 0

    # And once more, so the second upgrade is shown to be repeatable.
    tamperable.execute(m2.DOWNGRADE_SQL)
    tamperable.execute(m1.DOWNGRADE_SQL)
    tamperable.execute(m0.DOWNGRADE_SQL)
    tamperable.execute(m0.UPGRADE_SQL)
    tamperable.execute(m1.UPGRADE_SQL)
    tamperable.execute(m2.UPGRADE_SQL)
    assert _state(tamperable) == before
