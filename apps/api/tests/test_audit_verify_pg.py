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

    # `seq` is given: the chain trigger draws it (0153), and with the
    # trigger stood down nothing else does.
    conn.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    conn.execute(
        """INSERT INTO audit.event
               (seq, actor_kind, action, outcome, detail, prev_hash, row_hash)
           SELECT nextval('audit.event_seq_seq'), 'USER', %s, 'SUCCESS',
                  '{}'::jsonb, e.prev_hash, decode('00','hex')
             FROM audit.event e
            WHERE e.seq = (SELECT max(seq) FROM audit.event)""",
        (action,))
    conn.execute(
        f"""UPDATE audit.event AS e SET row_hash = {_HASH_EXPR}
             WHERE e.seq = (SELECT max(seq) FROM audit.event)""")


def test_a_fork_written_since_the_fix_is_tampering(tamperable):
    """Two rows sharing a predecessor, one of them written since 0153, is a
    break.

    A fork used to be reported and not counted, on the ground that honest
    traffic could not make one. It could: `seq` was drawn before the
    chaining trigger took its lock (evidence-audit-chain-forks,
    2026-10-03), and a fork's dead-end row could be deleted with the answer
    still `intact`. 0153 draws the sequence and reads the tail inside the
    lock, so a fork among rows it wrote is not honest traffic any more.
    """
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable, n=4)
    _forge_clean_fork(tamperable)

    report = verify_chain(tamperable, since_seq=since)
    assert report.forks, "the fork was not detected at all"
    assert [f.kind for f in report.forks] == ["FORK", "FORK"], \
        "both claimants must be named: which one is the intruder is not " \
        "something the verifier can decide"
    assert [b.kind for b in report.breaks] == ["FORK", "FORK"], report.breaks
    assert not report.intact, "a fork among rows the fixed trigger wrote went unreported"
    assert report.forks_since_fix == 2
    assert report.fork_boundary_seq > 0, \
        "this database carries the boundary row 0153 appended"


def test_a_fork_older_than_the_boundary_is_history(tamperable):
    """A fork between rows written BEFORE 0153 stays reported and is not
    counted: the table is append-only, an upgraded deployment cannot clean
    it, and counting it would answer BROKEN on a chain nobody tampered
    with, the one answer a tamper-evidence tool cannot afford. The boundary
    is passed in so the test does not depend on how old the database is."""
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable, n=4)
    _forge_clean_fork(tamperable)
    newest = tamperable.execute("SELECT max(seq) FROM audit.event").fetchone()[0]

    report = verify_chain(tamperable, since_seq=since, fork_boundary_seq=newest)
    assert [f.kind for f in report.forks] == ["FORK", "FORK"]
    assert not report.breaks, [b.kind for b in report.breaks]
    assert report.intact, "a fork older than the boundary must not be tampering"
    assert report.forks_since_fix == 0


def test_the_boundary_is_the_row_the_migration_wrote(tamperable):
    """The verifier reads its boundary from the log: the LATEST
    `AUDIT_CHAIN_SERIALISED` row, which 0153 appended where rows already
    existed. The latest, because a downgrade and an upgrade install the
    fixed trigger again and every row between the two was written by the old
    one, which forks. A database with none has boundary zero."""
    from noctornal_api.audit_verify import FORK_MARKER_ACTION, verify_chain

    marker = tamperable.execute(
        "SELECT max(seq) FROM audit.event WHERE action = %s AND object_type = 'audit'",
        (FORK_MARKER_ACTION,)).fetchone()[0]
    assert verify_chain(tamperable, limit=1).fork_boundary_seq == (marker or 0)
    assert verify_chain(tamperable, limit=1, fork_boundary_seq=7).fork_boundary_seq == 7


def test_a_later_marker_moves_the_boundary_and_excuses_the_rows_before_it(tamperable):
    """Re-applying 0153 (a downgrade and an upgrade) appends another marker.
    A fork written between the two, by the older trigger, is history, and one
    written after the new marker is a break."""
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable, n=3)
    _forge_clean_fork(tamperable)
    # The marker the second upgrade would write, through the real trigger.
    tamperable.execute("ALTER TABLE audit.event ENABLE TRIGGER USER")
    tamperable.execute(
        "INSERT INTO audit.event (actor_kind, action, object_type, detail) "
        "VALUES ('SYSTEM', 'AUDIT_CHAIN_SERIALISED', 'audit', '{}'::jsonb)")
    excused = verify_chain(tamperable, since_seq=since)
    assert excused.forks and excused.intact, [b.kind for b in excused.breaks]
    _forge_clean_fork(tamperable, action="FORKED_AFTER")
    assert not verify_chain(tamperable, since_seq=since).intact


def test_a_fork_does_not_mask_real_tampering(tamperable):
    """Separating old forks out must not create a hiding place.

    Without this, "old forks are not breaks" could be implemented by
    dropping any row that forks, and an attacker who forked a row they also
    edited would be invisible. Here the fork is OLD (the boundary is above
    it), and the edit is still caught.
    """
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable, n=4)
    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute(
        """UPDATE audit.event SET action = 'EDITED_AND_FORKED'
            WHERE seq = (SELECT max(seq) FROM audit.event)""")
    _forge_clean_fork(tamperable, action="FORKED_TWIN_2")
    newest = tamperable.execute("SELECT max(seq) FROM audit.event").fetchone()[0]

    report = verify_chain(tamperable, since_seq=since, fork_boundary_seq=newest)
    assert report.forks, "the fork was lost"
    assert any("CONTENT" in b.kind for b in report.breaks), \
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
                (seq, actor_kind, action, outcome, detail, prev_hash, row_hash)
            SELECT nextval('audit.event_seq_seq'), 'USER', %s, 'SUCCESS',
                   '{{}}'::jsonb, NULL, {_HASH_EXPR}
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


# ---------------------------------------------------------------------------
# The tail: what `intact` cannot see, and the anchor that can
# (evidence-chain-no-anchor, 2026-10-03)
# ---------------------------------------------------------------------------

def test_the_report_names_the_whole_logs_tail_window_or_not(tamperable):
    from noctornal_api.audit_verify import verify_chain

    _seed(tamperable, n=3)
    newest = tamperable.execute(
        "SELECT seq, encode(row_hash, 'hex') FROM audit.event "
        "ORDER BY seq DESC LIMIT 1").fetchone()
    total = tamperable.execute("SELECT count(*) FROM audit.event").fetchone()[0]

    for report in (verify_chain(tamperable), verify_chain(tamperable, limit=2)):
        assert (report.tail_seq, report.tail_row_hash) == newest
        assert report.rows == total, "the count is the table's, not the window's"


def test_a_removed_tail_reads_intact_without_an_anchor_and_is_caught_with_one(tamperable):
    """The cheapest delete there is: the newest rows. Nothing names the
    newest row as its predecessor, so removing the last k rows orphans
    nothing and the chain agrees with itself. This pins the blind spot, and
    the anchor that closes it."""
    from noctornal_api.audit_verify import BLIND_SPOTS, verify_chain

    since = _seed(tamperable, n=4)
    before = verify_chain(tamperable, since_seq=since)
    anchor = (before.tail_seq, before.tail_row_hash)

    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute("DELETE FROM audit.event WHERE seq > %s", (since + 2,))

    blind = verify_chain(tamperable, since_seq=since)
    assert blind.intact, "if this fails the blind spot is closed; update BLIND_SPOTS"
    assert blind.tail_seq < anchor[0]
    # The answer says what it cannot see, in words, every time.
    assert "end of the log" in BLIND_SPOTS and "tail_row_hash" in BLIND_SPOTS

    held = verify_chain(tamperable, since_seq=since, anchor=anchor)
    assert not held.intact
    assert [b.kind for b in held.breaks] == ["ANCHOR"], held.breaks
    assert held.anchor is not None and held.anchor.held is False


def test_a_rewritten_tail_reads_intact_without_an_anchor_and_is_caught_with_one(tamperable):
    """The owner's other move: edit the newest row and recompute its hash.
    The hash is unkeyed and its expression is in this repository, so the
    result agrees with itself (CONTENT and LINK both clean)."""
    from noctornal_api.audit_verify import _HASH_EXPR, verify_chain

    since = _seed(tamperable, n=4)
    before = verify_chain(tamperable, since_seq=since)
    anchor = (before.tail_seq, before.tail_row_hash)

    tamperable.execute("ALTER TABLE audit.event DISABLE TRIGGER USER")
    tamperable.execute(
        "UPDATE audit.event SET action = 'REWRITTEN' WHERE seq = %s", (anchor[0],))
    tamperable.execute(
        f"UPDATE audit.event AS e SET row_hash = {_HASH_EXPR} WHERE e.seq = %s",
        (anchor[0],))

    blind = verify_chain(tamperable, since_seq=since)
    assert blind.intact, "a self-consistent rewrite is invisible to a relative check"
    caught = verify_chain(tamperable, since_seq=since, anchor=anchor)
    assert not caught.intact
    assert [b.kind for b in caught.breaks] == ["ANCHOR"], caught.breaks


def test_an_anchor_the_log_still_holds_changes_nothing(tamperable):
    from noctornal_api.audit_verify import verify_chain

    since = _seed(tamperable, n=3)
    tail = verify_chain(tamperable, since_seq=since)
    report = verify_chain(tamperable, since_seq=since,
                          anchor=(tail.tail_seq, tail.tail_row_hash))
    assert report.intact and report.anchor.held
    # An earlier row of the log is as good an anchor as the tail.
    earlier = tamperable.execute(
        "SELECT seq, encode(row_hash, 'hex') FROM audit.event WHERE seq = %s",
        (since + 1,)).fetchone()
    assert verify_chain(tamperable, since_seq=since, anchor=earlier).intact


def test_a_malformed_anchor_is_refused_not_ignored(tamperable):
    """An anchor that does not parse must not silently verify nothing."""
    from noctornal_api.audit_verify import verify_chain

    for bad in ("", "xyz", "AB" * 32, "ab" * 31):
        with pytest.raises(ValueError):
            verify_chain(tamperable, limit=1, anchor=(1, bad))
