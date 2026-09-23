"""Hosts the sender chose, served defanged (final review U17, 2026-09-23).

The email row and the Received chain drew the HELO name, each hop's `from`
and `by`, and the Message-ID's domain verbatim. None of them is constrained
to a hostname: `_RECEIVED_FROM` and `_domain_of` keep `/`, `?` and `#`, so
EHLO `pay.evil.example/verify` and Message-ID `<a@pay.evil.example/verify>`
reached the pane as working URLs, under help text promising every URL in it
is defanged. This files such a message through the real service and reads
the list row and the detail back.

Its own email prefix, `dch-`, so its teardown touches nothing of
`test_deception_pg.py`'s. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

EMAIL_LIKE = "dch-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    # Custody rows stay, and so does what they point at: the same rule and
    # the same NULL-guarded pins as `test_deception_pg.py`.
    pinned_evidence = "(SELECT evidence_id FROM core.evidence_custody)"
    pinned_cases = "(SELECT case_id FROM core.evidence WHERE case_id IS NOT NULL)"
    pinned_users = (
        "(SELECT actor_id FROM core.evidence_custody WHERE actor_id IS NOT NULL"
        " UNION SELECT acquired_by FROM core.evidence WHERE acquired_by IS NOT NULL"
        ' UNION SELECT owner_user_id FROM core."case" WHERE owner_user_id IS NOT NULL'
        ' UNION SELECT deputy_user_id FROM core."case" WHERE deputy_user_id IS NOT NULL)'
    )
    with c.transaction():
        c.execute(f"DELETE FROM deception.email_hop WHERE message_id IN "
                  f"(SELECT id FROM deception.email_message WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.email_attachment WHERE message_id IN "
                  f"(SELECT id FROM deception.email_message WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.email_message WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN "
                  f"(SELECT id FROM core.evidence WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub} "
                  f"AND id NOT IN {pinned_evidence}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f"AND id NOT IN {pinned_cases}")
        c.execute(f"DELETE FROM iam.app_user WHERE id IN {sub} "
                  f"AND id NOT IN {pinned_users}")
    c.close()


def _owner_and_case(conn):
    from noctornal_api.cases import CaseService
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"dch-{uuid4().hex[:8]}@noctornal.test", "Dch", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    case_id = CaseService(conn).create(
        code=f"OP-DCH-{uuid4().hex[:6]}", title="Deception hosts",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=uid, created_by=uid)
    return uid, case_id


def test_a_helo_name_and_message_id_with_a_path_come_back_defanged(conn):
    from noctornal_api.deception import DeceptionService, parse_eml
    from noctornal_api.evidence import EvidenceService, EvidenceStorage

    owner, case_id = _owner_and_case(conn)
    raw = (
        b"Received: from pay.evil.example/verify ([203.0.113.7]) by"
        b" mx.corp.example with ESMTP; Mon, 20 Jul 2026 09:00:01 +0000\r\n"
        b"Received: from relay.evil.example/hop?x=1 ([198.51.100.20]) by"
        b" out.evil.example/by; Mon, 20 Jul 2026 08:59:00 +0000\r\n"
        b"Message-ID: <" + uuid4().hex.encode() + b"@pay.evil.example/verify>\r\n"
        b"From: \"Jane, CFO\" <jane@acme.example>\r\n"
        b"Subject: Remittance update\r\n\r\nBody.\r\n")
    exhibit = EvidenceService(conn, EvidenceStorage()).ingest(
        case_id=case_id, title="bec.eml", media_type="message/rfc822",
        data=raw, acquired_by=owner, acquisition_method="MANUAL_UPLOAD")
    svc = DeceptionService(conn)
    message_id = svc.record_email(
        case_id=case_id, evidence_id=exhibit.evidence_id,
        parsed=parse_eml(raw, trusted=("corp.example",)), recorded_by=owner)

    # The list row: the sending host and the Message-ID host.
    [row] = svc.emails(case_id, clearance="RED")
    origin = row["sending_host"]
    assert origin["host"] == "pay.evil.example/verify"
    assert origin["host_defanged"] == "pay[.]evil[.]example/verify"
    assert origin["observed_by_defanged"] == "mx.corp.example"
    assert row["message_id_domain_defanged"] == "pay[.]evil[.]example/verify"

    # The detail: the same origin, and every hop's `from` and `by`.
    detail = svc.email(message_id, clearance="RED")
    assert detail["sending_host"] == origin
    assert detail["message_id_domain_defanged"] == (
        row["message_id_domain_defanged"])
    hops = {h["seq"]: h for h in detail["hops"]}
    assert hops[0]["from_host_defanged"] == "pay[.]evil[.]example/verify"
    assert hops[0]["by_host_defanged"] == "mx.corp.example"
    assert hops[1]["from_host_defanged"] == "relay[.]evil[.]example/hop?x=1"
    assert hops[1]["by_host_defanged"] == "out[.]evil[.]example/by"
    # Nothing the console draws for a host still carries a live one.
    for h in detail["hops"]:
        for key in ("from_host_defanged", "by_host_defanged"):
            assert "evil.example" not in (h[key] or ""), (key, h[key])
