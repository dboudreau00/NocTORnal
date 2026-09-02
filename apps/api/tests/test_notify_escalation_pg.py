"""N3 (2026-09-02): an unacknowledged priority-1 escalates, and the drain
can be run without a step-up session.

Before this there was no escalation anywhere (`grep escalat` found
nothing). docs/07 makes acknowledgement the signal that stops a thing
nagging -- but nothing nagged. A break-glass alert or an integrity alarm
that its recipient never acknowledged simply sat there, which is the
"one alert that mattered" being muted by absence rather than by choice.

The only drain trigger was POST /notifications/dispatch behind
`integration.manage`, a STEP-UP permission a cron entry cannot satisfy.
`scripts/notify_drain.py` is the honest worker for this release: one
process, one connection, one drain, an exit code.

**The email prefix is `nesc-` and must stay unique.**

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
from datetime import date, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; escalation tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "nesc-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification "
                  f"  WHERE recipient_id IN {sub} OR actor_id IN {sub} "
                  f"     OR case_id IN {csub})")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub} "
                  f"    OR case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


def _user(conn, clearance="AMBER", *roles):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"nesc-{uuid4().hex[:8]}@noctornal.test", "Esc", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-NESC-{uuid4().hex[:6]}", title="Escalation",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _assign(conn, case_id, user_id, granted_by, role="ANALYST"):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, user_id, role, granted_by))


def _urgent(conn, recipient, case_id, actor, *, age=timedelta(hours=2)):
    """An URGENT notification that has been sitting unacknowledged for
    `age`. `created_at` is backdated in SQL because the escalation rule
    compares against the database clock, not this process's."""
    from noctornal_api.notifications import URGENT, NotificationService
    n = NotificationService(conn).notify(
        recipient_id=recipient, case_id=case_id, kind="EVIDENCE_INTEGRITY_ALARM",
        priority=URGENT, subject="OP-X: an exhibit failed its integrity check",
        summary="An exhibit on OP-X failed verification.", body="Exhibit 1.",
        classification="AMBER", actor_id=actor)
    assert n is not None
    conn.execute("UPDATE notify.notification SET created_at = now() - %s WHERE id = %s",
                 (age, n.id))
    return n


def _escalations(conn, recipient, original_id):
    return conn.execute(
        """SELECT id, case_id, classification FROM notify.notification
            WHERE recipient_id = %s AND kind = 'ESCALATION'
              AND object_type = 'notification' AND object_id = %s""",
        (recipient, original_id)).fetchall()


# ---------------------------------------------------------------------------
# escalate_unacknowledged
# ---------------------------------------------------------------------------

def test_an_unacknowledged_urgent_escalates_to_the_case_owner_once(conn):
    """The sweep returns how many ORIGINALS it escalated: 1 here in a clean
    database. It is asserted as `>= 1` because the sweep is global, and a
    backlog another suite's killed run left behind is escalated -- and
    counted -- in the same pass, which is the right behaviour and not this
    test's business. The precise claim is on OUR original: exactly one
    ESCALATION row, to the owner, and a second sweep adds nothing."""
    from noctornal_api.notifications import escalate_unacknowledged

    owner, analyst, actor = _user(conn), _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, analyst, owner)
    _assign(conn, case_id, actor, owner)
    n = _urgent(conn, analyst, case_id, actor)

    assert escalate_unacknowledged(conn, after=timedelta(hours=1)) >= 1
    rows = _escalations(conn, owner, n.id)
    assert len(rows) == 1 and rows[0][1] == case_id
    # Idempotent: the row it wrote is the row it looks for.
    assert escalate_unacknowledged(conn, after=timedelta(hours=1)) == 0
    assert len(_escalations(conn, owner, n.id)) == 1


def test_an_acknowledged_urgent_does_not_escalate(conn):
    from noctornal_api.notifications import NotificationService, escalate_unacknowledged

    owner, analyst, actor = _user(conn), _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, analyst, owner)
    _assign(conn, case_id, actor, owner)
    n = _urgent(conn, analyst, case_id, actor)
    assert NotificationService(conn).acknowledge(n.id, analyst)

    assert escalate_unacknowledged(conn, after=timedelta(hours=1)) == 0
    assert _escalations(conn, owner, n.id) == []


def test_a_young_urgent_is_left_alone(conn):
    from noctornal_api.notifications import escalate_unacknowledged

    owner, analyst, actor = _user(conn), _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, analyst, owner)
    _assign(conn, case_id, actor, owner)
    n = _urgent(conn, analyst, case_id, actor, age=timedelta(minutes=5))
    escalate_unacknowledged(conn, after=timedelta(hours=1))
    assert _escalations(conn, owner, n.id) == []


def test_when_the_owner_is_the_unresponsive_one_the_security_officers_are_told(conn):
    """The owner cannot be escalated to about their own silence. The
    officer alert carries NO case material -- the officer holds no
    case-content permission -- so it is GREEN and case-less, exactly like
    the break-glass alert."""
    from noctornal_api.notifications import escalate_unacknowledged

    officer = _user(conn, "GREEN", "SECURITY_OFFICER")
    owner, actor = _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, actor, owner)
    n = _urgent(conn, owner, case_id, actor)

    assert escalate_unacknowledged(conn, after=timedelta(hours=1)) == 1
    rows = _escalations(conn, officer, n.id)
    assert len(rows) == 1
    assert rows[0][1] is None and rows[0][2] == "GREEN"
    body = conn.execute("SELECT subject, summary, body FROM notify.notification WHERE id = %s",
                        (rows[0][0],)).fetchone()
    assert "OP-" not in "".join(body), "no case code reaches the officer"
    assert _escalations(conn, owner, n.id) == []


def test_an_escalation_does_not_itself_escalate(conn):
    """Otherwise an unacknowledged escalation escalates, and that one
    escalates, and the outbox fills with a chain about one silence."""
    from noctornal_api.notifications import escalate_unacknowledged

    owner, analyst, actor = _user(conn), _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, analyst, owner)
    _assign(conn, case_id, actor, owner)
    n = _urgent(conn, analyst, case_id, actor)
    assert escalate_unacknowledged(conn, after=timedelta(hours=1)) == 1
    conn.execute(
        """UPDATE notify.notification SET created_at = now() - interval '3 hours'
            WHERE kind = 'ESCALATION' AND object_id = %s""", (n.id,))
    assert escalate_unacknowledged(conn, after=timedelta(hours=1)) == 0


# ---------------------------------------------------------------------------
# one drain does all three, and the HTTP model declares every counter
# ---------------------------------------------------------------------------

def test_the_drain_escalates_and_sweeps_reviews_and_reports_both(conn):
    from noctornal_api.http.routers.notifications import DrainOut
    from noctornal_api.transports import dispatch_due

    owner, analyst, actor = _user(conn), _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, analyst, owner)
    _assign(conn, case_id, actor, owner)
    n = _urgent(conn, analyst, case_id, actor)

    counters = dispatch_due(conn, send_mail=lambda m: None)
    assert "escalated" in counters and "reviews_due" in counters
    assert counters["escalated"] >= 1
    assert len(_escalations(conn, owner, n.id)) == 1
    # Both halves of the contract: the dict the drain returns is the model
    # the endpoint declares. An undeclared key is dropped without a sound.
    out = DrainOut(**counters)
    assert set(counters) == set(DrainOut.model_fields), (
        set(counters) ^ set(DrainOut.model_fields))
    assert out.escalated == counters["escalated"]


# ---------------------------------------------------------------------------
# scripts/notify_drain.py: the cron entry
# ---------------------------------------------------------------------------

def _load_drain_script():
    path = Path(__file__).resolve().parents[3] / "scripts" / "notify_drain.py"
    assert path.is_file(), path
    spec = importlib.util.spec_from_file_location("notify_drain", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_drain_script_exits_non_zero_when_a_delivery_failed(monkeypatch, capsys):
    """A cron entry has one channel back to the operator: the exit code.
    A drain that failed a delivery and exited 0 is a failure reported as
    nothing at all."""
    drain = _load_drain_script()
    monkeypatch.setattr(drain, "dispatch_due", lambda conn: {
        "sent": 2, "redacted": 0, "refused": 0, "failed": 1, "revoked": 0,
        "escalated": 0, "reviews_due": 0})
    monkeypatch.setattr(drain, "connect", lambda: _FakeConn())
    assert drain.main() == 1
    out = capsys.readouterr().out
    assert "failed=1" in out and "sent=2" in out


def test_the_drain_script_exits_zero_on_a_clean_drain(monkeypatch):
    drain = _load_drain_script()
    monkeypatch.setattr(drain, "dispatch_due", lambda conn: {
        "sent": 0, "redacted": 0, "refused": 0, "failed": 0, "revoked": 0,
        "escalated": 0, "reviews_due": 0})
    monkeypatch.setattr(drain, "connect", lambda: _FakeConn())
    assert drain.main() == 0


class _FakeConn:
    def close(self):
        pass
