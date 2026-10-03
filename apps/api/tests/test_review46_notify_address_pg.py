"""egress-notify-address-list (review of 2026-10-03).

The F19 allowlist for a personal notification address read only the text
after the LAST '@', so 'collector@attacker.example, me@corp.example' was
accepted and smtplib sent one RCPT per address. These tests fail on the code
as it stood (dc28ffa): the list was stored, and the drain sent to whatever
was stored.
"""
from __future__ import annotations

import os
import re
import smtplib
import sys
from pathlib import Path
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pg = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "r46n-"
MIGRATION = (Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
             / "0148_notify_address_single.py")

REFUSED_SHAPES = [
    "collector@attacker.example, me@corp.example",
    "collector@attacker.example; me@corp.example",
    "Collector <collector@attacker.example>, me@corp.example",
    "<collector@attacker.example> me@corp.example",
    "undisclosed:collector@attacker.example;, me@corp.example",
    "me@corp.example\r\nBcc: collector@attacker.example",
    "me@corp.example\nBcc: collector@attacker.example",
    "me@corp.example\n",
    "me @corp.example",
    "\"me\"@corp.example",
    "me@corp.example (comment)",
    "collector@attacker.example@corp.example",
    "",
]

#: A local part an MTA reads as routing: the domain after the last '@' is
#: allowed, and the mail still goes elsewhere (Postfix honours the percent
#: hack by default; '!' is a bang path; the rest are alias and delivery
#: syntax).
ROUTING_LOCAL_PARTS = [
    "collector%attacker.example@corp.example",
    "attacker.example!collector@corp.example",
    "|touch-x@corp.example",
    "a/b@corp.example",
    "a`b@corp.example",
    "a$b@corp.example",
    "a{b}@corp.example",
    "a=b@corp.example",
    "a*b@corp.example",
]


@pytest.fixture
def conn():
    from outbound_support import teardown

    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


@pytest.mark.parametrize("value", REFUSED_SHAPES)
def test_a_list_or_header_text_is_not_one_address(value):
    from noctornal_api.notifications import single_address_domain
    assert single_address_domain(value) is None


@pytest.mark.parametrize("value", ROUTING_LOCAL_PARTS)
def test_a_local_part_that_routes_elsewhere_is_not_a_plain_address(value):
    from noctornal_api.notifications import single_address_domain
    assert single_address_domain(value) is None


@pg
@pytest.mark.parametrize("value", ROUTING_LOCAL_PARTS)
def test_a_routing_local_part_behind_a_permitted_domain_is_refused_by_the_service(
        conn, monkeypatch, value):
    from outbound_support import make_user

    from noctornal_api.notifications import NotificationError, NotificationService

    monkeypatch.setenv("NOCTORNAL_NOTIFY_ADDRESS_DOMAINS", "corp.example")
    uid, _ = make_user(conn, PREFIX)
    with pytest.raises(NotificationError, match="one plain address"):
        NotificationService(conn).set_preference(uid, "SMTP", address=value)


@pytest.mark.parametrize("value,domain", [
    ("me@corp.example", "corp.example"),
    ("a.analyst@Agency.Example", "agency.example"),
    ("o'brien+alerts@corp.example", "corp.example"),
])
def test_one_plain_address_keeps_working(value, domain):
    from noctornal_api.notifications import single_address_domain
    assert single_address_domain(value) == domain


def test_the_database_check_spells_the_service_rule():
    from noctornal_api.notifications import SINGLE_ADDRESS_PATTERN
    text = MIGRATION.read_text(encoding="utf-8")
    found = re.search(r"\$addr\$\^(.*)\$\$addr\$", text)
    assert found, "0148 no longer carries the pattern"
    assert found.group(1) == SINGLE_ADDRESS_PATTERN


@pg
@pytest.mark.parametrize("value", REFUSED_SHAPES[:7])
def test_an_address_list_ending_in_a_permitted_domain_is_refused(conn, monkeypatch, value):
    from outbound_support import make_user

    from noctornal_api.notifications import NotificationError, NotificationService

    monkeypatch.setenv("NOCTORNAL_NOTIFY_ADDRESS_DOMAINS", "corp.example")
    uid, _ = make_user(conn, PREFIX)
    with pytest.raises(NotificationError, match="one plain address"):
        NotificationService(conn).set_preference(uid, "SMTP", address=value)
    stored = conn.execute("SELECT address FROM notify.preference WHERE user_id = %s "
                          "AND channel = 'SMTP'", (uid,)).fetchone()
    assert stored is None or stored[0] is None


@pg
def test_a_permitted_single_address_is_still_accepted(conn, monkeypatch):
    from outbound_support import make_user

    from noctornal_api.notifications import NotificationService

    monkeypatch.setenv("NOCTORNAL_NOTIFY_ADDRESS_DOMAINS", "corp.example")
    uid, _ = make_user(conn, PREFIX)
    pref = NotificationService(conn).set_preference(uid, "SMTP", address="me@corp.example")
    assert pref.address == "me@corp.example"


@pg
def test_the_database_refuses_a_list_from_any_writer(conn):
    import psycopg
    from outbound_support import make_user

    uid, _ = make_user(conn, PREFIX)
    with pytest.raises(psycopg.errors.CheckViolation):
        with conn.transaction():
            conn.execute(
                "INSERT INTO notify.preference (user_id, channel, address) "
                "VALUES (%s, 'SMTP', %s)",
                (uid, "collector@attacker.example, me@corp.example"))


@pg
def test_a_stored_list_is_never_expanded_into_recipients(conn):
    """The drain sends to coalesce(preference, account email). A value that
    is not one plain address is a failed delivery, never one RCPT per name:
    smtplib's own expansion is what turned the list into extra recipients."""
    from outbound_support import assign, make_case, make_user

    from noctornal_api import transports
    from noctornal_api.notifications import NotificationService

    owner, _ = make_user(conn, PREFIX, clearance="RED")
    alice, email = make_user(conn, PREFIX, clearance="RED")
    listed = f"{PREFIX}c{uuid4().hex[:6]}@attacker.example, {email}"
    conn.execute("UPDATE iam.app_user SET email = %s WHERE id = %s", (listed, alice))
    case_id = make_case(conn, owner, PREFIX, classification="GREEN")
    assign(conn, case_id, alice)
    nonce = uuid4().hex[:10]
    n = NotificationService(conn).notify(
        recipient_id=alice, case_id=case_id, kind="EVIDENCE_INTEGRITY_ALARM",
        subject=f"OP-X: integrity [{nonce}]", summary="An exhibit failed.",
        body="Exhibit 4 no longer matches.", classification="GREEN", actor_id=owner)
    assert n is not None

    recipients: list[list[str]] = []

    class Recorder(smtplib.SMTP):
        def ehlo_or_helo_if_needed(self):
            return None

        def has_extn(self, opt):
            return False

        def sendmail(self, from_addr, to_addrs, msg, mail_options=(), rcpt_options=()):
            recipients.append(list(to_addrs))
            return {}

    def send_mail(message):
        if nonce in str(message["Subject"]):
            Recorder().send_message(message)

    transports.dispatch_due(conn, send_mail=send_mail, post_webhook=lambda *a: None)
    assert recipients == [], f"the list was expanded into {recipients}"
    state, sent_to, detail = conn.execute(
        "SELECT state, sent_to, detail FROM notify.delivery WHERE notification_id = %s "
        "AND channel = 'SMTP'", (n.id,)).fetchone()
    assert sent_to is None and state in ("PENDING", "FAILED")
    assert "not one plain address" in detail


@pg
def test_a_list_stored_before_0148_is_not_rewritten_silently(conn):
    """0148's CHECK is NOT VALID, so a list stored before it stays (its
    audit rows say who set it). Rewriting the row for another field would
    trip the CHECK; the service says what to do instead. The constraint is
    dropped only inside a rolled-back transaction, to plant such a row."""
    from outbound_support import make_user

    from noctornal_api.notifications import NotificationError, NotificationService

    uid, _ = make_user(conn, PREFIX)
    with conn.transaction(force_rollback=True):
        conn.execute("ALTER TABLE notify.preference DROP CONSTRAINT preference_address_single")
        conn.execute("INSERT INTO notify.preference (user_id, channel, address) "
                     "VALUES (%s, 'SMTP', 'collector@attacker.example, me@corp.example')",
                     (uid,))
        svc = NotificationService(conn)
        with pytest.raises(NotificationError, match="no longer used"):
            svc.set_preference(uid, "SMTP", min_priority=1)
        cleared = svc.set_preference(uid, "SMTP", address=None)
        assert cleared.address is None
