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
