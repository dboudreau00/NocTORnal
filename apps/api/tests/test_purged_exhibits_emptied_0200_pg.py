"""Migration 0200: an exhibit purged before a purge emptied it is emptied once, and nothing else changes
(independent review of Beta 1.6, AREA-03, the rows the fix could not reach).

The purge now empties a destroyed exhibit's description, source address, extracted text and full-text
vector in the update that marks it (`test_exhibit_purge_empties_content_pg.py`). An exhibit destroyed
before that still carries all four. 0200 does the same to each of them, once, as the schema owner.

What is held here, on real rows with every guard on `core.evidence` in place and no mock:

- a purged exhibit that says something is emptied in all four places and keeps everything else, its
  title, hashes, ids and `purged_at` included, and the search no longer finds it by a word of its body;
- one that says less (an address alone, a vector built from the title alone) is emptied too, and one that
  is already empty is not written;
- a live exhibit is not touched, not even rewritten;
- a second run changes nothing: no row updated, no audit event;
- the vector needs its own statement, because a single update leaves a title-only vector (the premise
  the revision's order rests on);
- no guard is disabled, and the revision writes one summary audit event with a count and no value;
- the revision runs through Alembic's own `upgrade()` on a connection in a transaction, as the migration
  job calls it, and round-trips: the downgrade changes nothing and restores nothing;
- a role that row security would filter is refused, never silently run over the rows it can see, and a
  purged exhibit that still carries content after the update fails the revision with a count.

Every change runs inside a transaction that is rolled back (the test_notify_ledger_migration_pg.py
pattern), so the shared database never holds a row these tests made and no other exhibit is emptied.
Accounts `k8e-*`. Gated on DATABASE_URL; the row security case also needs the runtime role.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

import rls_support as s

DATABASE_URL = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "k8e-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
ACTION = "PURGED_EXHIBITS_EMPTIED"

TITLE = "k8 harbour notes"
DESCRIPTION = "informant debrief covering the harbour handover"
SOURCE_URL = "https://forum.example.test/threads/4412"
#: A word only the extracted text carries, so a hit on it can only come from the full-text vector.
BODY_WORD = "zebrafinch"
#: The four columns a purge empties, and the only ones the revision writes.
EMPTIED = ("description", "source_url", "extracted_text", "search_tsv")


class _RollBack(Exception):
    pass


@pytest.fixture
def conn():
    c = s.owner_conn()
    yield c
    s.cleanup(c, PREFIX)
    c.close()


def _migration():
    path = next(VERSIONS.glob("0200_*.py"))
    spec = importlib.util.spec_from_file_location("m0200", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _account(conn):
    uid = s.user(conn, "RED", prefix=PREFIX)
    return uid, s.case(conn, uid)


def _exhibit(conn, case_id, actor, *, description=None, source_url=None, text=None,
             purged=False, vector_emptied=False, title=TITLE) -> str:
    """One exhibit as the code before the fix left it: the content in the row, and the vector the
    trigger built from it. `purged` marks it with the one update the old purge ran, which names no other
    column. `vector_emptied` is what the new purge leaves behind it (the vector NULL)."""
    evidence_id = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, description, media_type, byte_size, sha256, storage_key,
                storage_bucket, acquired_at, acquired_by, acquisition_method, source_url,
                extracted_text)
           VALUES (%s, %s, %s, 'text/plain', 12, %s, %s, 'k8e-bucket', now(), %s,
                   'MANUAL_UPLOAD', %s, %s)
           RETURNING id""",
        (case_id, title, description, os.urandom(32), f"k8e/{uuid4().hex}", actor, source_url,
         text)).fetchone()[0]
    if purged:
        conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s", (evidence_id,))
    if vector_emptied:
        conn.execute("UPDATE core.evidence SET search_tsv = NULL WHERE id = %s", (evidence_id,))
    return evidence_id


def _estate(conn, case_id, actor) -> dict[str, str]:
    """The exhibits of one deployment that upgraded: what says everything, what says less, what the new
    purge already emptied, and a live exhibit that says everything."""
    said = dict(description=DESCRIPTION, source_url=SOURCE_URL,
                text=f"the notes mention a {BODY_WORD} twice")
    return {
        "said": _exhibit(conn, case_id, actor, purged=True, **said),
        "address": _exhibit(conn, case_id, actor, purged=True, source_url=SOURCE_URL),
        "bare": _exhibit(conn, case_id, actor, purged=True),
        "already": _exhibit(conn, case_id, actor, purged=True, vector_emptied=True),
        "live": _exhibit(conn, case_id, actor, **said),
    }


def _row(conn, evidence_id) -> dict:
    return conn.execute("SELECT to_jsonb(e) FROM core.evidence e WHERE id = %s",
                        (evidence_id,)).fetchone()[0]


def _kept(conn, evidence_id) -> dict:
    """The row with the four emptied columns taken out: what the revision must not change."""
    row = _row(conn, evidence_id)
    return {k: v for k, v in row.items() if k not in EMPTIED}


def _says(conn, evidence_id) -> dict:
    """Which of the four a row still holds."""
    row = _row(conn, evidence_id)
    return {k: row[k] is not None for k in EMPTIED}


def _found_by(conn, evidence_id, word) -> bool:
    return conn.execute(
        "SELECT count(*) FROM core.evidence WHERE id = %s "
        "AND search_tsv @@ plainto_tsquery('simple', %s)", (evidence_id, word)).fetchone()[0] == 1


def _updates(conn) -> int:
    """Rows of core.evidence updated so far by this transaction."""
    return conn.execute(
        "SELECT coalesce(n_tup_upd, 0) FROM pg_stat_xact_user_tables "
        "WHERE schemaname = 'core' AND relname = 'evidence'").fetchone()[0]


def _events(conn) -> int:
    return conn.execute("SELECT count(*) FROM audit.event WHERE action = %s",
                        (ACTION,)).fetchone()[0]


def _guards(conn) -> list[tuple]:
    """Every trigger of the table that is not an internal one, with its state: 'O' is enabled."""
    return conn.execute(
        "SELECT tgname, tgenabled FROM pg_trigger "
        "WHERE tgrelid = 'core.evidence'::regclass AND NOT tgisinternal ORDER BY tgname").fetchall()


# ---------------------------------------------------------------------------------------------------
# What the revision is
# ---------------------------------------------------------------------------------------------------

def test_the_revision_chains_after_0199_and_every_statement_names_the_purged_rows():
    m = _migration()
    assert (m.revision, m.down_revision) == ("0200", "0199")
    for statement in (m.EMPTY_THE_WORDS, m.EMPTY_THE_VECTOR):
        assert "purged_at IS NOT NULL" in statement
        assert statement.count("UPDATE ") == 1 and "DELETE" not in statement
    assert "title" not in m.EMPTY_THE_WORDS and "title" not in m.EMPTY_THE_VECTOR
    assert "DISABLE TRIGGER" not in Path(m.__file__).read_text(encoding="utf-8"), (
        "no guard is switched off, not even for a statement")


def test_a_single_update_leaves_a_title_only_vector_so_the_revision_needs_two(conn):
    """The premise of the order: `evidence_tsv_update` rebuilds the vector when the description or the
    text changes, over a NULL set in the same statement. If that trigger changes, this fails first and
    says the two statements may become one."""
    uid, case_id = _account(conn)
    with pytest.raises(_RollBack), conn.transaction():
        evidence_id = _exhibit(conn, case_id, uid, description=DESCRIPTION, purged=True)
        conn.execute("UPDATE core.evidence SET description = NULL, search_tsv = NULL "
                     "WHERE id = %s", (evidence_id,))
        assert _says(conn, evidence_id)["search_tsv"], "the trigger put the title back"
        assert _found_by(conn, evidence_id, "harbour")
        assert not _found_by(conn, evidence_id, "informant")
        raise _RollBack


# ---------------------------------------------------------------------------------------------------
# What it empties and what it keeps
# ---------------------------------------------------------------------------------------------------

def test_a_purged_exhibit_is_emptied_in_all_four_places_and_keeps_its_name(conn):
    m = _migration()
    uid, case_id = _account(conn)
    with pytest.raises(_RollBack), conn.transaction():
        ids = _estate(conn, case_id, uid)
        said = ids["said"]

        # The premise: it says all of it, and the search finds the exhibit by a word only its body holds.
        assert _says(conn, said) == dict.fromkeys(EMPTIED, True)
        assert _found_by(conn, said, BODY_WORD) and _found_by(conn, said, "informant")
        kept = {name: _kept(conn, i) for name, i in ids.items()}
        guards = _guards(conn)
        assert guards and all(state == "O" for _, state in guards)

        assert m.empty(conn) >= 3  # said, address, bare; other purged rows of the database may be here

        for name in ("said", "address", "bare"):
            assert _says(conn, ids[name]) == dict.fromkeys(EMPTIED, False), name
        assert not _found_by(conn, said, BODY_WORD)
        assert not _found_by(conn, said, "harbour"), "the vector goes whole, the title's words too"
        # Everything else of every purged row: the title, hashes, size, key, ids and the moment it was
        # purged.
        for name in ("said", "address", "bare", "already"):
            assert _kept(conn, ids[name]) == kept[name], name
        row = _row(conn, said)
        assert row["title"] == TITLE and row["purged_at"] is not None
        # No guard was disabled to do it.
        assert _guards(conn) == guards
        raise _RollBack


def test_a_live_exhibit_is_not_touched_not_even_rewritten(conn):
    m = _migration()
    uid, case_id = _account(conn)
    with pytest.raises(_RollBack), conn.transaction():
        ids = _estate(conn, case_id, uid)
        live = ids["live"]
        before = _row(conn, live)
        ctid = conn.execute("SELECT ctid::text FROM core.evidence WHERE id = %s", (live,)).fetchone()
        assert before["description"] == DESCRIPTION and before["search_tsv"] is not None

        m.empty(conn)

        assert _row(conn, live) == before, "a live exhibit says what it said"
        assert conn.execute("SELECT ctid::text FROM core.evidence WHERE id = %s",
                            (live,)).fetchone() == ctid, "and its tuple was not rewritten"
        assert _found_by(conn, live, BODY_WORD)
        raise _RollBack


def test_an_exhibit_the_new_purge_already_emptied_is_not_written(conn):
    m = _migration()
    uid, case_id = _account(conn)
    with pytest.raises(_RollBack), conn.transaction():
        ids = _estate(conn, case_id, uid)
        already = ids["already"]
        before = _row(conn, already)
        ctid = conn.execute("SELECT ctid::text FROM core.evidence WHERE id = %s",
                            (already,)).fetchone()
        assert all(before[k] is None for k in EMPTIED)

        m.empty(conn)

        assert _row(conn, already) == before
        assert conn.execute("SELECT ctid::text FROM core.evidence WHERE id = %s",
                            (already,)).fetchone() == ctid
        raise _RollBack


# ---------------------------------------------------------------------------------------------------
# Run again, run through Alembic, run back
# ---------------------------------------------------------------------------------------------------

def test_a_second_run_changes_nothing_and_writes_nothing(conn):
    m = _migration()
    uid, case_id = _account(conn)
    with pytest.raises(_RollBack), conn.transaction():
        ids = _estate(conn, case_id, uid)
        assert m.empty(conn) >= 3
        after_first = {name: _row(conn, i) for name, i in ids.items()}
        updates, events = _updates(conn), _events(conn)

        assert m.empty(conn) == 0

        assert _updates(conn) == updates, "the second run updated a row"
        assert _events(conn) == events, "and wrote an audit event"
        assert {name: _row(conn, i) for name, i in ids.items()} == after_first
        raise _RollBack


def test_it_records_one_summary_event_with_a_count_and_no_value(conn):
    m = _migration()
    uid, case_id = _account(conn)
    with pytest.raises(_RollBack), conn.transaction():
        _estate(conn, case_id, uid)
        before = _events(conn)
        changed = m.empty(conn)
        assert _events(conn) == before + 1
        kind, object_type, case, outcome, detail = conn.execute(
            "SELECT actor_kind, object_type, case_id, outcome, detail FROM audit.event "
            "WHERE action = %s ORDER BY seq DESC LIMIT 1", (ACTION,)).fetchone()
        assert (kind, object_type, case, outcome) == ("SYSTEM", "deployment", None, "SUCCESS")
        assert detail == {"exhibits": changed, "by": m.BY}
        text = str(detail)
        assert DESCRIPTION not in text and SOURCE_URL not in text and BODY_WORD not in text
        raise _RollBack


def _through_alembic(connection, fn):
    """Run `fn()` as the migration job runs a revision: inside Alembic's operations context, on a
    SQLAlchemy connection in a transaction of its own, where `op.get_bind()` answers with it."""
    from alembic.migration import MigrationContext
    from alembic.operations import Operations
    with Operations.context(MigrationContext.configure(connection)):
        fn()


def test_alembic_runs_it_in_the_migration_jobs_shape_and_the_downgrade_restores_nothing(conn, capsys):
    """`upgrade()` and `downgrade()` as the job calls them: a driver connection that is not in
    autocommit, inside one transaction that is rolled back here. The downgrade is a no-op and a second
    upgrade changes nothing, so down, up is the same as up."""
    from sqlalchemy import create_engine, pool
    m = _migration()
    uid, case_id = _account(conn)
    engine = create_engine(DATABASE_URL, poolclass=pool.NullPool)
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")  # begin the transaction the job's connection is in
            raw = connection.connection.driver_connection
            assert not raw.autocommit, "the job's connection is not the suite's"
            ids = _estate(raw, case_id, uid)
            before = {name: _row(raw, i) for name, i in ids.items()}
            events = _events(raw)

            _through_alembic(connection, m.upgrade)
            assert capsys.readouterr().out.startswith("[0200] purged exhibits emptied")
            for name in ("said", "address", "bare"):
                assert _says(raw, ids[name]) == dict.fromkeys(EMPTIED, False), name
            for name in ("already", "live"):
                assert _row(raw, ids[name]) == before[name], name
            assert _events(raw) == events + 1
            emptied = {name: _row(raw, i) for name, i in ids.items()}

            updates = _updates(raw)
            _through_alembic(connection, m.downgrade)
            _through_alembic(connection, m.upgrade)
            assert capsys.readouterr().out == "", "nothing left to say the second time"
            assert _updates(raw) == updates, "down, up wrote a row"
            assert _events(raw) == events + 1
            assert {name: _row(raw, i) for name, i in ids.items()} == emptied, (
                "the downgrade restored what a purge destroyed, or the second upgrade changed it")
            connection.rollback()
    finally:
        engine.dispose()
    assert conn.execute("SELECT count(*) FROM core.evidence WHERE title = %s", (TITLE,)
                        ).fetchone()[0] == 0, "the rolled-back transaction left a row behind"


# ---------------------------------------------------------------------------------------------------
# What it refuses
# ---------------------------------------------------------------------------------------------------

@pytest.mark.skipif(not s.APP_ROLE, reason="NOCTORNAL_APP_DB_ROLE not set")
def test_a_role_row_security_would_filter_is_refused_and_not_run_over_the_rows_it_can_see(conn):
    """Row security is enabled on the table and not forced, so the schema owner (the role Alembic runs
    as) sees every row. A role that policies filter would otherwise run both statements over whatever
    it can see and report success; `SET LOCAL row_security = off` turns that into an error."""
    m = _migration()
    uid, case_id = _account(conn)
    with pytest.raises(_RollBack), conn.transaction():
        ids = _estate(conn, case_id, uid)
        before = {name: _row(conn, i) for name, i in ids.items()}
        conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(s.APP_ROLE)))
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as refused:
            m.empty(conn)
        assert "row-level security" in str(refused.value)
        conn.execute("RESET ROLE")
        assert {name: _row(conn, i) for name, i in ids.items()} == before
        raise _RollBack


def test_a_purged_exhibit_that_still_says_something_fails_the_revision_with_a_count(conn):
    """A guard or a trigger that put the content back would leave a destroyed exhibit readable behind a
    revision that reported success. The revision looks again and refuses, naming a count and no value,
    and its own changes go with it."""
    m = _migration()
    uid, case_id = _account(conn)
    with pytest.raises(_RollBack), conn.transaction():
        ids = _estate(conn, case_id, uid)
        # Fires after evidence_tsv, and puts a vector back on any purged row it updates.
        conn.execute("""
            CREATE FUNCTION core.k8_put_the_vector_back() RETURNS trigger LANGUAGE plpgsql AS $f$
            BEGIN
              IF NEW.purged_at IS NOT NULL THEN
                NEW.search_tsv := to_tsvector('simple', 'spoiled');
              END IF;
              RETURN NEW;
            END $f$""")
        conn.execute("CREATE TRIGGER zz_k8_put_the_vector_back BEFORE UPDATE ON core.evidence "
                     "FOR EACH ROW EXECUTE FUNCTION core.k8_put_the_vector_back()")
        before = {name: _row(conn, i) for name, i in ids.items()}
        events = _events(conn)

        with pytest.raises(RuntimeError) as refused:
            m.empty(conn)

        message = str(refused.value)
        assert message.startswith("refusing to finish 0200: ") and "purged exhibits still carry" in message
        assert DESCRIPTION not in message and SOURCE_URL not in message
        assert {name: _row(conn, i) for name, i in ids.items()} == before, (
            "the refused revision left a change behind")
        assert _events(conn) == events
        raise _RollBack
