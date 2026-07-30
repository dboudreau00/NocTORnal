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
