"""F37 (docs/17, 2026-10-02) against Postgres: what a stored contact block
holds when its fingerprint line was copied from gpg, and what happens to a
block stored before the change.

- a gpg-copied line is stored with all forty hex characters, and that value
  passes the same normalisation and test the key registry applies before it
  lets a block line confirm a key (it used to read NOT_A_FINGERPRINT);
- a block copied under another publisher is found by
  `impersonation_candidates` whichever way the fingerprint was written;
- nothing re-reads a stored block: a block stored under cb-1 keeps its
  truncated reading when its text is parsed again in the same case, which is
  why the decision names the blocks parsed before (`parser_version`) and does
  not claim to have repaired them.

Env-gated on DATABASE_URL; users `cbg-`.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; contact-block tests are gated")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

GPG = "7A5C 1B6E 2D0F 9A3C 4E8B  1F7D 6C2A 9B0E 3D5F 8A1C"
NORM = "7A5C1B6E2D0F9A3C4E8B1F7D6C2A9B0E3D5F8A1C"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'cbg-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM comms.contact_block_entry WHERE block_id IN "
                  f"(SELECT id FROM comms.contact_block WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM comms.contact_block WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'cbg-%@noctornal.test'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"cbg-{uuid4().hex[:8]}@noctornal.test", "Blocks", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (uid,))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-CBG-{uuid4().hex[:6]}", title="Blocks",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


@pytest.fixture
def svc(conn):
    from noctornal_api.contact_blocks import ContactBlockService
    return ContactBlockService(conn)


def _store(svc, case_id, uid, text, handle):
    return svc.parse_and_store(case_id=case_id, raw_text=text, source_ref="https://forum/f37",
                               created_by=uid, publisher_handle=handle)


def test_a_gpg_copied_line_is_stored_whole_and_stamped_cb_2(conn, svc):
    from noctornal_api.pgp_keys import _fpr_verdict

    uid = _user(conn)
    case_id = _case(conn, uid)
    stored = _store(svc, case_id, uid, f"Jabber: v@shop.tld\nPGP: {GPG}", "vendor-a")
    assert stored["parser_version"] == "cb-2"
    line = next(e for e in stored["entries"] if e["selector_type"] == "PGP_FPR")
    assert line["durable_value"] == NORM and line["role"] == "SELF"
    # What the key registry does with a block line before it confirms a key.
    normalised = conn.execute("SELECT comms.pgp_fingerprint_norm(%s)",
                              (line["durable_value"],)).fetchone()[0]
    assert _fpr_verdict(normalised) == (NORM, None)


def test_a_block_copied_under_another_publisher_is_found_whichever_way_it_was_typed(conn, svc):
    uid = _user(conn)
    case_id = _case(conn, uid)
    a = _store(svc, case_id, uid, f"Jabber: v@shop.tld\nPGP: {GPG}", "vendor-a")
    b = _store(svc, case_id, uid, f"Jabber: v@shop.tld\nPGP: {NORM}", "vendor-b")
    assert a["block_fingerprint"] == b["block_fingerprint"]
    found = svc.impersonation_candidates(case_id, clearance="RED")
    assert [f["publishers"] for f in found] == [["vendor-a", "vendor-b"]]
    assert found[0]["basis"].startswith("the normalised selector SET")


def test_a_stored_block_is_never_re_read_so_a_cb_1_block_keeps_its_reading(conn, svc):
    """Nothing in the tree re-parses a stored block: the same text submitted
    to the same case returns the first parse, entries, fingerprint and
    version untouched. A block parsed under cb-1 therefore keeps a truncated
    fingerprint line until it is parsed again somewhere new, and the
    parser_version column is how to find the ones that need it."""
    uid = _user(conn)
    case_id = _case(conn, uid)
    text = f"PGP: {GPG}"
    first = _store(svc, case_id, uid, text, "vendor-a")
    conn.execute("UPDATE comms.contact_block SET parser_version = 'cb-1' WHERE id = %s",
                 (first["id"],))
    conn.execute("""UPDATE comms.contact_block_entry SET durable_value = %s
                     WHERE block_id = %s AND selector_type = 'PGP_FPR'""",
                 (NORM[:20], first["id"]))
    again = _store(svc, case_id, uid, text, "vendor-a")
    assert again["already_parsed"] is True and again["id"] == first["id"]
    assert again["parser_version"] == "cb-1"
    assert [e["durable_value"] for e in again["entries"]] == [NORM[:20]]
    # In a case of its own the same text takes the new reading.
    other_case = _case(conn, uid)
    fresh = _store(svc, other_case, uid, text, "vendor-a")
    assert fresh["parser_version"] == "cb-2"
    assert [e["durable_value"] for e in fresh["entries"]] == [NORM]
