"""The audit chain verifier — and the proof that it can fail.

A tamper-evidence check that has only ever been run against intact data is
not known to work. These tests deliberately break the chain in each of the
two ways it can break and assert the verifier notices, because the failure
mode that matters is a verifier which returns "intact" unconditionally —
that is strictly worse than having none, since it manufactures assurance.

## How the tampering is done, and why it is safe

`audit.event` carries row-level and statement-level triggers that block
UPDATE, DELETE and TRUNCATE (0013, 0052), so ordinary SQL cannot corrupt
it — which is the point of the table and also the obstacle to testing it.

`ALTER TABLE ... DISABLE TRIGGER USER` is the established idiom in this
suite for exactly this (see `test_evidence_pg.py`), and **DDL in Postgres
is transactional**: the disable, the tamper and the re-read all happen
inside one transaction that is then rolled back. Nothing persists, the
triggers are never left off, and no other test can observe a broken chain.

The connection here is deliberately NOT the autocommit one from
`db.connect()` — with autocommit there is no transaction to roll back and
the tamper would be permanent.
"""
from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="needs a migrated database")


@pytest.fixture()
def tamperable():
    """A non-autocommit connection whose work is always rolled back."""
    import psycopg

    from noctornal_api.db import dsn

    conn = psycopg.connect(dsn())
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()


def _seed(conn, n: int = 6) -> int:
    """Write real audit rows through the trigger; return the seq to verify FROM.

    Hand-inserting `row_hash` would test the verifier against the
    verifier's own idea of the hash, which is circular. These go in as
    plain INSERTs and `audit.chain_hash()` computes the chain.

    THE RETURNED WATERMARK MATTERS. These tests must verify only the rows
    they wrote, never the whole table, because the table is shared with
    every other suite and accumulates real history. The development
    database currently carries 67 pre-existing FORK anomalies (two rows
    claiming one predecessor) from concurrent writes; asserting `intact`
    over all 60,000 rows would fail for reasons that have nothing to do
    with the code under test, and "fix the test by loosening the
    assertion" is how a real finding gets buried.
    """
    start = conn.execute("SELECT COALESCE(MAX(seq), 0) FROM audit.event").fetchone()[0]
    for i in range(n):
        conn.execute(
            """INSERT INTO audit.event
                   (actor_kind, action, outcome, detail)
               VALUES ('USER', %s, 'SUCCESS', %s::jsonb)""",
            (f"TEST_EVENT_{i}", '{"seeded": true, "n": %d}' % i),
        )
    return start


def test_untouched_chain_verifies(tamperable):
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable)
    report = verify_chain(tamperable, since_seq=since)
    assert report.checked > 0, "nothing was checked; the assertion below is vacuous"
    assert report.intact, [b.kind for b in report.breaks]


def test_in_place_edit_is_a_CONTENT_break(tamperable):
    """A row edited in place must be caught by the hash recompute."""
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable)
    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute(
        """UPDATE audit.event SET action = 'NOTHING_HAPPENED'
            WHERE seq = (SELECT max(seq) - 2 FROM audit.event)""")

    report = verify_chain(tamperable, since_seq=since)
    assert not report.intact
    kinds = [b.kind for b in report.breaks]
    # CONTENT only: the row's own hash no longer matches its columns, but
    # its stored prev_hash is still its predecessor's, so the LINK holds.
    # If this ever reports LINK too, the recompute is reading the wrong
    # prev_hash and the two checks are not independent.
    assert kinds == ["CONTENT"], kinds


def test_deleted_row_is_a_LINK_break(tamperable):
    """A row removed from the middle must break the link, not the content."""
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable)
    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute(
        """DELETE FROM audit.event
            WHERE seq = (SELECT max(seq) - 2 FROM audit.event)""")

    report = verify_chain(tamperable, since_seq=since)
    assert not report.intact
    kinds = [b.kind for b in report.breaks]
    # Exactly one: the SUCCESSOR of the deleted row, whose stored prev_hash
    # now points at a hash no longer present. Every other row is untouched.
    assert kinds == ["LINK"], kinds


def test_windowed_run_reports_that_it_is_windowed(tamperable):
    """`limit` must not be able to masquerade as a full verification.

    The oldest row in a window has no loaded predecessor, so its link is
    not asserted — a deletion straddling the boundary is invisible. The
    report has to carry enough for a caller to know that.
    """
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable, n=10)
    full = verify_chain(tamperable, since_seq=since)
    windowed = verify_chain(tamperable, limit=3)

    assert windowed.checked == 3
    assert full.checked > windowed.checked
    assert windowed.last_seq == full.last_seq, "a window must take the NEWEST rows"
    assert windowed.first_seq > full.first_seq


def test_empty_window_is_not_reported_as_a_pass(tamperable):
    """`intact` on zero rows means "nothing to say", never "verified".

    Guarded by a test because the property is a trap: `not self.breaks` is
    True for an empty chain, so any caller that reads `intact` without
    reading `checked` will believe it verified something.
    """
    from noctornal_api.audit_verify import verify_chain

    report = verify_chain(tamperable, since_seq=2**40)
    assert report.checked == 0
    assert report.intact          # documented behaviour...
    assert report.first_seq is None   # ...and the tell that it is vacuous
    assert report.last_seq is None


def _forge_clean_fork(conn, action="FORKED_TWIN") -> None:
    """Add a second row claiming the newest row's predecessor.

    The twin's `row_hash` is computed with the SAME expression the trigger
    uses, imported from the module under test rather than re-typed, so the
    fork is LINK-clean and CONTENT-clean: the only thing wrong with it is
    that two rows now claim one predecessor. A hand-invented hash would be
    flagged CONTENT and the test would prove nothing about forks — which
    is exactly what the first version of this did.
    """
    from noctornal_api.audit_verify import _HASH_EXPR

    conn.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    conn.execute(
        """INSERT INTO audit.event
               (actor_kind, action, outcome, detail, prev_hash, row_hash)
           SELECT 'USER', %s, 'SUCCESS', '{}'::jsonb, e.prev_hash, decode('00','hex')
             FROM audit.event e
            WHERE e.seq = (SELECT max(seq) FROM audit.event)""",
        (action,))
    conn.execute(
        f"""UPDATE audit.event AS e SET row_hash = {_HASH_EXPR}
             WHERE e.seq = (SELECT max(seq) FROM audit.event)""")


def test_a_fork_is_reported_but_is_NOT_tampering(tamperable):
    """Two rows sharing a predecessor must not make the chain "broken".

    This is the case that fires on real history. `seq` is drawn from
    `nextval()` before the chaining trigger takes its advisory lock, so
    concurrent writers can chain off the same tail; the development
    database carries 67 such forks in 60,181 rows, none of them tampering.

    Counting them as breaks made `/audit/verify` answer BROKEN on
    untouched history — the one answer a tamper-evidence tool cannot
    afford, and the SECOND time this module made that mistake (the first
    was assuming `seq` order was chain order). Hence a named test.
    """
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable, n=4)
    _forge_clean_fork(tamperable)

    report = verify_chain(tamperable, since_seq=since)
    assert report.forks, "the fork was not detected at all"
    assert [f.kind for f in report.forks] == ["FORK", "FORK"], \
        "both claimants must be named — which one is the intruder is not " \
        "something the verifier can decide"
    # THE POINT: no tampering was found, so the chain is not "broken".
    assert not report.breaks, [b.kind for b in report.breaks]
    assert report.intact, "a fork must not be reported as tampering"


def test_a_fork_does_not_mask_real_tampering(tamperable):
    """Separating forks out must not create a hiding place.

    Without this, "forks are not breaks" could be implemented by dropping
    any row that forks — and an attacker who forked a row they also edited
    would be invisible.
    """
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable, n=4)
    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute(
        """UPDATE audit.event SET action = 'EDITED_AND_FORKED'
            WHERE seq = (SELECT max(seq) FROM audit.event)""")
    _forge_clean_fork(tamperable, action="FORKED_TWIN_2")

    report = verify_chain(tamperable, since_seq=since)
    assert report.forks, "the fork was lost"
    assert any(b.kind == "CONTENT" for b in report.breaks), \
        "the edited row was masked by its own fork"
    assert not report.intact


# ---------------------------------------------------------------------------
# The anchor: where does the chain START?
# ---------------------------------------------------------------------------

def _forge_second_genesis(conn, action="SECOND_GENESIS") -> None:
    """Insert a row claiming to be the chain's first.

    LINK-clean and CONTENT-clean by construction: the hash input for a
    NULL-predecessor row is the literal string 'GENESIS', so a forgery
    computed with the module's own `_HASH_EXPR` recomputes exactly. Before
    the anchor check existed this row was not merely unreported as
    tampering -- it was dropped from the report entirely, and `intact`
    stayed True.
    """
    from noctornal_api.audit_verify import _HASH_EXPR

    conn.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    conn.execute(
        f"""INSERT INTO audit.event
                (actor_kind, action, outcome, detail, prev_hash, row_hash)
            SELECT 'USER', %s, 'SUCCESS', '{{}}'::jsonb, NULL, {_HASH_EXPR}
              FROM (SELECT NULL::bytea AS prev_hash, now() AS occurred_at,
                           NULL::uuid AS actor_id, 'USER' AS actor_kind,
                           %s AS action, NULL::text AS object_type,
                           NULL::uuid AS object_id, NULL::uuid AS case_id,
                           'SUCCESS' AS outcome, '{{}}'::jsonb AS detail,
                           NULL::bytea AS ip_hash,
                           NULL::uuid AS session_id) e""",
        (action, action))
    conn.execute("ALTER TABLE audit.event ENABLE TRIGGER USER")


def test_a_second_genesis_is_reported_as_tampering(tamperable):
    """A row with `prev_hash NULL` passed every check: LINK exempts it by
    construction, FORK filters `prev_hash IS NOT NULL` (and a NULL never
    equals a NULL in the join anyway), and CONTENT blesses it because the
    hash input for such a row is the literal 'GENESIS'.

    That is the shape of a TRUNCATION -- delete the first k rows,
    re-anchor row k+1 -- and it is the one thing no relative check can
    see, because every surviving row still agrees with its predecessor.

    Unlike a fork this is not reachable by honest traffic: 0013 writes a
    NULL predecessor only into an empty table, under the advisory lock,
    and no application code writes prev_hash. So it counts as tampering.
    """
    from noctornal_api.audit_verify import verify_chain

    before = verify_chain(tamperable)
    assert before.genesis_count == 1, (
        f"this database has {before.genesis_count} genesis rows before the "
        f"test forges one; the assertion below would not mean what it says")
    assert before.intact

    _forge_second_genesis(tamperable)

    after = verify_chain(tamperable)
    assert after.genesis_count == 2
    assert not after.intact, "a second genesis is invisible"
    assert {b.kind for b in after.breaks} == {"GENESIS"}
    assert len(after.breaks) == 2, (
        "both claimants must be named -- which one is the intruder is not "
        "something this can decide")


def test_the_anchor_is_checked_over_the_whole_table_not_the_window(tamperable):
    """The true genesis is almost never inside a `limit` window. Computing
    the anchor from the window would answer "no genesis" on every windowed
    run -- the false accusation this module has already made twice."""
    from noctornal_api.audit_verify import verify_chain

    _seed(tamperable)
    windowed = verify_chain(tamperable, limit=2)
    assert windowed.checked == 2
    assert windowed.genesis_count == 1, (
        "the anchor was computed from the window, so a windowed run "
        "reports a chain with no first row")
    assert windowed.intact


# ---------------------------------------------------------------------------
# The writer: the claims the fork split rests on
# ---------------------------------------------------------------------------

def test_the_chaining_lock_serialises_concurrent_writers(tamperable):
    """`ChainReport.intact` excludes forks, and the reason given for years
    was that ordinary concurrency produces them -- `seq` is drawn before
    the trigger takes its lock, so two writers chain off one tail.

    It does not. With one transaction holding the xact advisory lock
    mid-INSERT, a second connection's INSERT blocks until commit. If this
    ever stops being true, the fork explanation becomes correct again and
    the docstring in `audit_verify.py` must be changed back.
    """
    import psycopg

    from noctornal_api.db import dsn

    ins = ("INSERT INTO audit.event (actor_kind, action, outcome, detail) "
           "VALUES ('SYSTEM','LOCKTEST','SUCCESS','{}'::jsonb)")
    tamperable.execute(ins)          # holds the lock; rolled back by fixture

    other = psycopg.connect(dsn())
    try:
        other.execute("SET statement_timeout = '1200ms'")
        with pytest.raises(psycopg.errors.QueryCanceled):
            other.execute(ins)
    finally:
        other.rollback()
        other.close()


def test_a_multi_row_insert_does_not_fork_the_chain(tamperable):
    """The other half of the same claim. A BEFORE INSERT trigger firing
    once per row could plausibly hand every row of one statement the same
    tail -- it does not, because each row is inserted before the next
    row's trigger runs."""
    tamperable.execute(
        "INSERT INTO audit.event (actor_kind, action, outcome, detail) "
        "SELECT 'SYSTEM', 'MULTIROW_' || g, 'SUCCESS', '{}'::jsonb "
        "FROM generate_series(1,3) g")
    distinct = tamperable.execute(
        "SELECT count(DISTINCT prev_hash) FROM audit.event "
        "WHERE action LIKE 'MULTIROW_%'").fetchone()[0]
    assert distinct == 3, (
        "a multi-row insert chained every row off the same predecessor")
