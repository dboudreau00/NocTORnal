"""N4 (2026-09-02): `transports.send_smtp` has a real message pass through
it.

Until now the SMTP transport had zero test coverage: every drain test
injected `send_mail=lambda m: ...`, which proves the gate, the redaction
and the ledger and proves nothing about the function that opens the
socket. The dev stack ships Mailpit (SMTP on 1025, HTTP API on 8025)
precisely so this can be exercised without a real relay.

Gated on SMTP_HOST as well as DATABASE_URL: an operator's `.env.local` that
points SMTP_HOST at a real relay would make this test send real mail, so it
also requires the Mailpit API to answer -- a relay that is not Mailpit has
no /api/v1 and the test skips rather than sends blind.

**The email prefix is `nsmtp-` and must stay unique.**
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
MAILPIT_API = os.environ.get("MAILPIT_API", f"http://{SMTP_HOST or 'localhost'}:8025")
pytestmark = pytest.mark.skipif(
    not (DATABASE_URL and SMTP_HOST),
    reason="DATABASE_URL and SMTP_HOST required; the SMTP test is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "nsmtp-%@noctornal.test"


def _mailpit(path: str) -> dict:
    with urllib.request.urlopen(f"{MAILPIT_API}{path}", timeout=5) as r:
        return json.loads(r.read().decode("utf-8"))


@pytest.fixture
def mailpit():
    try:
        _mailpit("/api/v1/messages?limit=1")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        pytest.skip(f"Mailpit API not reachable at {MAILPIT_API}: {exc}")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification "
                  f"  WHERE recipient_id IN {sub} OR actor_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


def _user(conn):
    from noctornal_api.stores import PgUserStore
    email = f"nsmtp-{uuid4().hex[:8]}@noctornal.test"
    uid = PgUserStore(conn).create_user(email, "Smtp", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s", (uid,))
    return uid, email


def test_a_notification_drains_through_real_smtp_and_lands_in_mailpit(conn, mailpit):
    from noctornal_api.notifications import URGENT, NotificationService
    from noctornal_api.transports import dispatch_due

    recipient, email = _user(conn)
    actor, _ = _user(conn)
    marker = uuid4().hex[:10]
    n = NotificationService(conn).notify(
        recipient_id=recipient, actor_id=actor, kind="MERGE_PERFORMED",
        # URGENT so it sorts to the FRONT of `due()` (priority, then age):
        # a NORMAL row raised behind a backlog is not reached in one capped
        # pass, and the first version of this test stalled for minutes
        # pushing 200 rows a killed run had left through real SMTP before
        # failing on a row it never got to.
        priority=URGENT,
        subject=f"OP-{marker}: two entities were merged",
        summary=f"A merge in OP-{marker} re-pointed 3 relationship(s).",
        body="shadowbroker was merged into A. Petrov.", classification="AMBER")
    assert n is not None

    # One real notification, not the whole outbox. The cap is the due rows
    # that sort ahead of ours -- other URGENT ones, none in a clean
    # database -- plus ours, so exactly the rows the drain must reach to
    # reach ours go through the socket. The predicate mirrors `due()`,
    # which has no channel filter, so neither does this: an undercount
    # would starve our row, an overcount only drains a few more.
    ahead = conn.execute(
        """SELECT count(*) FROM notify.delivery d
             JOIN notify.notification n ON n.id = d.notification_id
            WHERE d.state = 'PENDING' AND d.deliver_after <= now()
              AND n.priority = %s AND d.notification_id <> %s""",
        (URGENT, n.id)).fetchone()[0]

    # No injected transport: this is the real `send_smtp`.
    counters = dispatch_due(conn, limit=ahead + 1)
    assert counters["sent"] >= 1, counters

    row = conn.execute(
        """SELECT state, sent_to, detail FROM notify.delivery
            WHERE notification_id = %s AND channel = 'SMTP'""", (n.id,)).fetchone()
    assert row[0] == "SENT", row
    assert row[1] == email, "the ledger records where it went"

    found = _mailpit(f"/api/v1/search?query=to:{email}")
    assert found["messages"], f"nothing addressed to {email} reached Mailpit"
    msg = found["messages"][0]
    assert [t["Address"] for t in msg["To"]] == [email]
    assert msg["Subject"] == f"[NocTORnal] OP-{marker}: two entities were merged"
    # The body rule (docs/07): the summary travels, the body never does.
    detail = _mailpit(f"/api/v1/message/{msg['ID']}")
    assert "re-pointed 3 relationship(s)" in detail["Text"]
    assert "shadowbroker" not in detail["Text"]
    assert "A. Petrov" not in detail["Text"]
