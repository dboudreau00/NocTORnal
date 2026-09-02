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
    ours = (f"(SELECT id FROM notify.notification "
            f"  WHERE recipient_id IN {sub} OR actor_id IN {sub} "
            f"     OR case_id IN {csub})")
    with c.transaction():
        # The officer copies FIRST, and before the originals they point at.
        #
        # `escalation_to_officer` is GREEN and case-less by design, and its
        # recipient is a real SECURITY_OFFICER of this database, not one of
        # this suite's users -- so none of the three clauses below reaches
        # it and every officer escalation this suite provoked survived
        # teardown. That was invisible while `dispatch_due` sent what it
        # raised in the same pass (the rows were left SENT). Once the
        # producers moved below the drain loop on 2026-09-02 the leftovers
        # stayed PENDING and URGENT, so the NEXT suite's drain sent them
        # first -- and `test_notifications_pg.py::
        # test_amber_strict_never_leaves_and_the_stub_goes_instead`, which
        # asserts on `sent[0]` of a global drain, read somebody else's
        # escalation stub. A test suite that leaves priority-1 rows behind
        # is a suite that decides what the next one sees.
        esc = (f"(SELECT id FROM notify.notification WHERE kind = 'ESCALATION' "
               f"   AND object_type = 'notification' AND object_id IN {ours})")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN {esc}")
        c.execute(f"DELETE FROM notify.notification WHERE kind = 'ESCALATION' "
                  f"  AND object_type = 'notification' AND object_id IN {ours}")
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


def test_the_drain_does_not_send_what_its_own_producers_raised(conn):
    """A drain sends what was ALREADY due when it started. What the
    producers raise goes out on the NEXT pass.

    This test reads both sides of one contract on purpose, because the
    contract crosses two files and each half was internally consistent:

    - `transports.dispatch_due` evaluated `escalate_unacknowledged(conn)`
      inside the `counters` literal, i.e. BEFORE `for out in due(conn,
      limit)`;
    - `notifications.deliver_after` returns `now` for priority 1, and
      ESCALATION is registered URGENT in `KINDS`.

    Neither is wrong alone. Together they made "drain the outbox" also
    manufacture its own outbound mail and send it in the same call, which
    silently converted the untouched
    `test_notifications_pg.py::test_a_deferred_delivery_is_not_drained_early`
    (`assert sent == []`) into a test that fails whenever the database
    holds one unacknowledged URGENT older than an hour -- the exact state
    the escalation feature exists to serve. It survived review because the
    database it was written against held zero escalation candidates and
    zero cases due for review, so both producers were inert and every new
    test passed over a no-op. Fixed 2026-09-02 by moving both producers
    below the drain loop.

    Asserted on the delivery ROW rather than on the length of `sent`,
    because the drain is global and a backlog another suite left behind is
    legitimately sent in the same pass and is not this test's business.
    """
    from noctornal_api.transports import dispatch_due

    owner, analyst, actor = _user(conn), _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, analyst, owner)
    _assign(conn, case_id, actor, owner)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]

    # (1) A deferred delivery: the shape test_a_deferred_delivery_is_not_
    # drained_early builds. Young, so it is not itself an escalation
    # candidate.
    deferred = _urgent(conn, analyst, case_id, actor, age=timedelta(minutes=1))
    conn.execute(
        """UPDATE notify.delivery SET deliver_after = now() + interval '1 hour'
            WHERE notification_id = %s AND channel = 'SMTP'""", (deferred.id,))

    # (2) An aged unacknowledged URGENT whose own SMTP row is already done,
    # so the ONLY thing this drain could send for our users is whatever the
    # escalation producer raises during it.
    n = _urgent(conn, analyst, case_id, actor)
    conn.execute(
        """UPDATE notify.delivery SET state = 'SENT', sent_at = now()
            WHERE notification_id = %s AND state = 'PENDING'""", (n.id,))

    sent = []
    counters = dispatch_due(conn, send_mail=lambda m: sent.append(m))
    assert counters["escalated"] >= 1, counters

    esc = _escalations(conn, owner, n.id)
    assert len(esc) == 1, esc
    delivery = conn.execute(
        """SELECT state, attempts, sent_at FROM notify.delivery
            WHERE notification_id = %s AND channel = 'SMTP'""",
        (esc[0][0],)).fetchone()
    assert delivery is not None, "the escalation should still have queued SMTP"
    assert delivery[0] == "PENDING" and delivery[1] == 0 and delivery[2] is None, (
        "the escalation this very drain raised was also SENT by it; the "
        "producers must run after the drain loop, not inside the counters "
        "literal above it")
    subjects = [m["Subject"] or "" for m in sent]
    assert not [s for s in subjects if code in s], (
        f"a message about {code} left in the pass that raised it: {subjects}")

    # The deferred row is untouched -- the half the untouched suite asserts.
    assert conn.execute(
        """SELECT state, attempts FROM notify.delivery
            WHERE notification_id = %s AND channel = 'SMTP'""",
        (deferred.id,)).fetchone() == ("PENDING", 0)

    # And the escalation goes out on the NEXT pass, so nothing was dropped.
    dispatch_due(conn, send_mail=lambda m: sent.append(m))
    assert conn.execute(
        """SELECT state FROM notify.delivery
            WHERE notification_id = %s AND channel = 'SMTP'""",
        (esc[0][0],)).fetchone()[0] == "SENT"


# ---------------------------------------------------------------------------
# two drains at once
# ---------------------------------------------------------------------------

def test_two_concurrent_drains_escalate_one_silence_once(conn):
    """`escalate_unacknowledged`'s dedupe is a SELECT followed by INSERTs on
    an autocommit connection, and `notify.notification` has NO unique index
    to fall back on -- `notification_object_idx` (migration 0029) is a plain
    partial btree on `object_id`. So the docstring's original unqualified
    claim of idempotence "by construction" was a read-then-write TOCTOU, and
    the concurrency it fails under is the ordinary one the same change
    introduced: `scripts/notify_drain.py` on a cron overlapping an
    operator's POST /notifications/dispatch, on a drain that takes minutes
    against a real relay. Duplicate ESCALATIONs are URGENT -- the one tier
    that overrides quiet hours and mails every security officer -- so the
    consequence is the alert fatigue this module argues against.

    Fixed 2026-09-02 by serialising the whole drain on a session advisory
    lock in `transports.dispatch_due`, so the loser returns an immediate
    all-zero drain rather than blocking behind somebody else's SMTP. This
    test reads both sides: the lock lives in transports.py and the property
    it guarantees is claimed in notifications.py.
    """
    import threading

    from noctornal_api.db import connect
    from noctornal_api.transports import dispatch_due

    owner, analyst, actor = _user(conn), _user(conn), _user(conn)
    case_id = _case(conn, owner)
    _assign(conn, case_id, analyst, owner)
    _assign(conn, case_id, actor, owner)
    n = _urgent(conn, analyst, case_id, actor)

    barrier = threading.Barrier(2)
    results: list = []

    def drain():
        c = connect()
        try:
            barrier.wait(timeout=30)
            results.append(dispatch_due(c, send_mail=lambda m: None))
        except Exception as exc:  # noqa: BLE001 - reported, not swallowed
            results.append(exc)
        finally:
            c.close()

    threads = [threading.Thread(target=drain) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
        assert not t.is_alive(), "a drain never returned; is the lock released?"

    assert all(isinstance(r, dict) for r in results), results
    assert len(_escalations(conn, owner, n.id)) == 1, (
        "one silence, escalated twice: the SELECT-then-INSERT dedupe raced")
    assert sum(r["escalated"] for r in results) == 1, (
        f"both drains counted the same escalation: {results}")


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
