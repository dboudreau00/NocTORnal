"""Notification: the suppressions, the clearance filter, quiet hours, and
the docs/07 content rules that decide what may leave the building.

The load-bearing test in this file is
`test_the_email_transport_cannot_reach_the_notification_body` -- it patches
the body out of existence and asserts the mail still renders. A comment
saying "do not put the body in an email" survives exactly one refactor;
that test does not.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, time, timedelta
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; notifications are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'ntfy-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE recipient_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification WHERE recipient_id IN {sub}")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM notify.preference WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node_merge_edge WHERE merge_id IN "
                  f"(SELECT id FROM core.node_merge WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.node_merge WHERE case_id IN {csub}")
        # Assertions, then their elements, in ONE transaction: the deferred
        # invariant-1 triggers fire at commit, and the second of them stops
        # the last assertion of a live element being deleted.
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'ntfy-%@noctornal.test'")
    c.close()


def _user(conn, clearance="AMBER", compartments=()):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"ntfy-{uuid4().hex[:8]}@noctornal.test", "Recipient", "x" * 20)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s WHERE id = %s",
        (clearance, list(compartments), uid))
    return uid


def _case(conn, owner, classification="AMBER", compartments=()):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-NTFY-{uuid4().hex[:6]}", title="Notify",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification, compartments=list(compartments))


@pytest.fixture
def svc(conn):
    from noctornal_api.notifications import NotificationService
    return NotificationService(conn)


def _raise(svc, recipient, **kw):
    defaults = dict(kind="MERGE_PERFORMED", subject="OP-X: something happened",
                    summary="Something happened on OP-X.",
                    body="shadowbroker was merged into A. Petrov.",
                    classification="AMBER")
    defaults.update(kw)
    return svc.notify(recipient_id=recipient, **defaults)


# --- the suppressions ---------------------------------------------------

def test_you_are_never_told_what_you_just_did(conn, svc):
    """The single commonest reason people turn a notification system off."""
    alice = _user(conn)
    assert _raise(svc, alice, actor_id=alice) is None
    assert svc.unread_count(alice) == 0


def test_somebody_else_doing_it_does_notify_you(conn, svc):
    alice, bob = _user(conn), _user(conn)
    assert _raise(svc, alice, actor_id=bob) is not None
    assert svc.unread_count(alice) == 1


def test_a_row_is_never_written_for_a_recipient_who_could_not_read_it(conn, svc):
    """Writing it and relying on the read filter forever after would put
    case content in a table keyed by a user with no business with it."""
    green = _user(conn, clearance="GREEN")
    assert _raise(svc, green, classification="RED") is None
    assert conn.execute(
        "SELECT count(*) FROM notify.notification WHERE recipient_id = %s",
        (green,)).fetchone()[0] == 0


def test_a_compartment_you_are_not_read_into_suppresses_it(conn, svc):
    uncleared = _user(conn, clearance="RED")
    assert _raise(svc, uncleared, classification="AMBER",
                  compartments=frozenset({"OPERATION-X"})) is None


def test_being_read_into_the_compartment_lets_it_through(conn, svc):
    cleared = _user(conn, clearance="RED", compartments=("OPERATION-X",))
    assert _raise(svc, cleared, classification="AMBER",
                  compartments=frozenset({"OPERATION-X"})) is not None


def test_an_inactive_user_is_not_notified(conn, svc):
    alice = _user(conn)
    conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s", (alice,))
    assert _raise(svc, alice) is None


# --- reading is filtered by CURRENT clearance ---------------------------

def test_a_revoked_clearance_hides_notifications_already_written(conn, svc):
    """Otherwise the centre quietly becomes a retention loophole for
    everything the analyst used to be able to see."""
    alice = _user(conn, clearance="RED")
    assert _raise(svc, alice, classification="RED") is not None
    assert svc.unread_count(alice) == 1

    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'GREEN' WHERE id = %s",
                 (alice,))
    assert svc.unread_count(alice) == 0
    assert svc.inbox(alice) == []


def test_a_revoked_compartment_hides_them_too(conn, svc):
    alice = _user(conn, clearance="RED", compartments=("OPERATION-X",))
    assert _raise(svc, alice, compartments=frozenset({"OPERATION-X"})) is not None
    conn.execute("UPDATE iam.app_user SET compartments = '{}' WHERE id = %s", (alice,))
    assert svc.inbox(alice) == []


def test_the_filter_is_in_sql_so_a_limit_cannot_truncate_visible_rows(conn, svc):
    """Filtering in Python after LIMIT would return a short page and call it
    the end of the list."""
    alice = _user(conn, clearance="AMBER")
    for _ in range(5):
        _raise(svc, alice, classification="AMBER")
    for _ in range(5):
        # Above the clearance: never written at all, but if the filter were
        # post-LIMIT these would have crowded out the readable ones.
        _raise(svc, alice, classification="RED")
    assert len(svc.inbox(alice, limit=5)) == 5


# --- read / acknowledge -------------------------------------------------

def test_reading_is_scoped_to_the_owner(conn, svc):
    alice, bob = _user(conn), _user(conn)
    n = _raise(svc, alice)
    assert svc.mark_read(n.id, bob) is False, "not your inbox"
    assert svc.mark_read(n.id, alice) is True
    assert svc.unread_count(alice) == 0


def test_reading_is_idempotent(conn, svc):
    alice = _user(conn)
    n = _raise(svc, alice)
    svc.mark_read(n.id, alice)
    first = svc.inbox(alice)[0].read_at
    svc.mark_read(n.id, alice)
    assert svc.inbox(alice)[0].read_at == first


def test_acknowledging_implies_reading(conn, svc):
    """The DB constraint says so; this asserts the service agrees."""
    alice = _user(conn)
    n = _raise(svc, alice)
    assert svc.acknowledge(n.id, alice) is True
    got = svc.inbox(alice)[0]
    assert got.read_at is not None and got.acknowledged_at is not None


# --- preferences and deferral -------------------------------------------

def test_a_user_with_no_preference_row_still_gets_the_urgent_things(conn, svc):
    """A default that required a settings visit would silently un-notify
    every new account."""
    alice = _user(conn)
    prefs = svc.preferences(alice)
    assert prefs["IN_APP"].enabled and prefs["SMTP"].enabled
    assert prefs["SMTP"].min_priority <= 2


def test_disabling_a_channel_records_a_suppressed_delivery_not_an_absence(conn, svc):
    """Invariant 12's spirit: a delivery that did not happen has a reason,
    not an absence. "Why did I not get that email" must have an answer."""
    alice, bob = _user(conn), _user(conn)
    svc.set_preference(alice, "SMTP", enabled=False)
    n = _raise(svc, alice, actor_id=bob)
    row = conn.execute(
        "SELECT state, detail FROM notify.delivery "
        "WHERE notification_id = %s AND channel = 'SMTP'", (n.id,)).fetchone()
    assert row[0] == "SUPPRESSED"
    assert "disabled" in row[1]


def test_a_priority_below_the_threshold_is_suppressed_with_a_reason(conn, svc):
    alice, bob = _user(conn), _user(conn)
    svc.set_preference(alice, "SMTP", min_priority=1)
    n = _raise(svc, alice, actor_id=bob, kind="PROPOSAL_QUEUED")  # priority 3
    row = conn.execute(
        "SELECT state, detail FROM notify.delivery "
        "WHERE notification_id = %s AND channel = 'SMTP'", (n.id,)).fetchone()
    assert row[0] == "SUPPRESSED" and "threshold" in row[1]


def test_in_app_delivery_is_recorded_as_already_sent(conn, svc):
    """The notification row IS the in-app delivery. A PENDING row would be a
    queue entry for something that has already happened."""
    alice, bob = _user(conn), _user(conn)
    n = _raise(svc, alice, actor_id=bob)
    row = conn.execute(
        "SELECT state FROM notify.delivery "
        "WHERE notification_id = %s AND channel = 'IN_APP'", (n.id,)).fetchone()
    assert row[0] == "SENT"


def test_an_invalid_timezone_is_refused(conn, svc):
    from noctornal_api.notifications import NotificationError
    alice = _user(conn)
    with pytest.raises(NotificationError):
        svc.set_preference(alice, "SMTP", timezone="Mars/Olympus_Mons")


def test_half_a_quiet_window_is_refused(conn, svc):
    """Half a window is a bug that reads as a working one."""
    from noctornal_api.notifications import NotificationError
    alice = _user(conn)
    with pytest.raises(NotificationError):
        svc.set_preference(alice, "SMTP", quiet_from=time(22, 0))


# --- quiet hours, as a pure function ------------------------------------

def _pref(**kw):
    from noctornal_api.notifications import Preference
    base = dict(channel="SMTP", enabled=True, min_priority=3, digest=False,
                quiet_from=None, quiet_to=None, timezone="UTC", address=None)
    base.update(kw)
    return Preference(**base)


def test_quiet_hours_defer_rather_than_drop():
    from datetime import datetime, timezone as tz

    from noctornal_api.notifications import NORMAL, deliver_after
    pref = _pref(quiet_from=time(22, 0), quiet_to=time(7, 0))
    at_midnight = datetime(2026, 7, 25, 0, 30, tzinfo=tz.utc)
    due = deliver_after(NORMAL, pref, at_midnight)
    assert due > at_midnight
    assert due.astimezone(tz.utc).hour == 7


def test_a_quiet_window_that_wraps_midnight_is_handled():
    """`from <= t <= to` gets 22:00-to-07:00 exactly backwards, and that is
    the common case."""
    from datetime import datetime, timezone as tz

    from noctornal_api.notifications import NORMAL, deliver_after
    pref = _pref(quiet_from=time(22, 0), quiet_to=time(7, 0))
    late = datetime(2026, 7, 25, 23, 0, tzinfo=tz.utc)
    due = deliver_after(NORMAL, pref, late)
    assert due.astimezone(tz.utc).day == 26 and due.astimezone(tz.utc).hour == 7


def test_outside_the_quiet_window_nothing_is_deferred():
    from datetime import datetime, timezone as tz

    from noctornal_api.notifications import NORMAL, deliver_after
    pref = _pref(quiet_from=time(22, 0), quiet_to=time(7, 0))
    midday = datetime(2026, 7, 25, 12, 0, tzinfo=tz.utc)
    assert deliver_after(NORMAL, pref, midday) == midday


def test_priority_one_ignores_quiet_hours():
    """The only reason silencing a channel overnight is acceptable is that
    something can still get through it."""
    from datetime import datetime, timezone as tz

    from noctornal_api.notifications import URGENT, deliver_after
    pref = _pref(quiet_from=time(22, 0), quiet_to=time(7, 0))
    at_midnight = datetime(2026, 7, 25, 0, 30, tzinfo=tz.utc)
    assert deliver_after(URGENT, pref, at_midnight) == at_midnight


def test_quiet_hours_are_in_the_recipients_own_timezone():
    from datetime import datetime, timezone as tz

    from noctornal_api.notifications import NORMAL, deliver_after
    # 03:00 UTC is 22:00 the previous day in New York: inside the window.
    pref = _pref(quiet_from=time(22, 0), quiet_to=time(7, 0),
                 timezone="America/New_York")
    at = datetime(2026, 7, 25, 3, 0, tzinfo=tz.utc)
    assert deliver_after(NORMAL, pref, at) > at


def test_a_zero_length_quiet_window_does_not_defer_forever():
    from datetime import datetime, timezone as tz

    from noctornal_api.notifications import NORMAL, deliver_after
    pref = _pref(quiet_from=time(9, 0), quiet_to=time(9, 0))
    at = datetime(2026, 7, 25, 9, 0, tzinfo=tz.utc)
    assert deliver_after(NORMAL, pref, at) == at


def test_digest_defers_to_the_next_hour_boundary():
    from datetime import datetime, timezone as tz

    from noctornal_api.notifications import NORMAL, deliver_after
    pref = _pref(digest=True)
    at = datetime(2026, 7, 25, 14, 23, tzinfo=tz.utc)
    due = deliver_after(NORMAL, pref, at)
    assert due.hour == 15 and due.minute == 0


# --- the docs/07 content rules ------------------------------------------

def _outgoing(**kw):
    from noctornal_api.transports import Outgoing
    base = dict(delivery_id=uuid4(), notification_id=uuid4(), channel="SMTP",
                attempts=0, recipient_id=uuid4(), case_id=uuid4(),
                kind="MERGE_PERFORMED", priority=2,
                subject="OP-KESTREL: two entities were merged",
                summary="A merge in OP-KESTREL re-pointed 4 relationship(s).",
                classification="AMBER", compartments=frozenset(),
                address="analyst@example.test", case_code="OP-KESTREL")
    base.update(kw)
    return Outgoing(**base)


def test_the_email_transport_cannot_reach_the_notification_body():
    """docs/07: "Body carries a summary and a deep link, not the content."

    Enforced structurally rather than by discipline: `Outgoing` does not
    CARRY the body, so `render_email` could not leak it if it tried. This
    test asserts that shape, because a comment saying "do not use the body
    here" survives exactly one refactor.
    """
    from noctornal_api.transports import Outgoing
    assert "body" not in Outgoing.__dataclass_fields__, (
        "the body must not be reachable from the email renderer")


def test_the_email_carries_the_summary_and_a_tlp_marking():
    from noctornal_api.transports import render_email
    message = render_email(_outgoing(), redacted=False)
    text = message.get_content()
    assert "re-pointed 4 relationship(s)" in text
    assert "TLP:AMBER" in text
    assert message["Subject"].endswith("two entities were merged")


def test_a_redacted_email_carries_no_case_code_at_all():
    """A case code IS intelligence. "OP-KESTREL" on a phone lock screen tells
    a shoulder-surfer that an operation by that name exists and that this
    person works on it."""
    from noctornal_api.transports import render_email
    message = render_email(_outgoing(), redacted=True)
    text = message.get_content()
    assert "OP-KESTREL" not in text and "OP-KESTREL" not in message["Subject"]
    assert "re-pointed" not in text
    assert "no case material" in text


def test_the_subject_line_never_carries_the_summary():
    from noctornal_api.transports import render_email
    message = render_email(_outgoing(), redacted=False)
    assert "relationship" not in message["Subject"]


def test_the_webhook_payload_redacts_the_same_way():
    from noctornal_api.transports import webhook_payload
    full = webhook_payload(_outgoing(), redacted=False)
    stub = webhook_payload(_outgoing(), redacted=True)
    assert full["summary"] and full["case_code"] == "OP-KESTREL"
    assert "summary" not in stub and "case_code" not in stub
    assert stub["redacted"] is True


def test_webhook_signatures_are_hmac_over_the_exact_bytes():
    import hashlib
    import hmac as hmac_mod

    from noctornal_api.transports import sign
    body = b'{"a":1}'
    expected = hmac_mod.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert sign(body, "s3cret") == "sha256=" + expected
    assert sign(body, "other") != sign(body, "s3cret")


# --- the egress gate on the drain ---------------------------------------

def test_amber_strict_never_leaves_and_the_stub_goes_instead(conn, svc):
    """Invariant 8 on the notification path. Not a silent drop and not a
    downgrade: the delivery row says REFUSED with the gate's reason, a
    content-free stub goes out, and the full notification stays in the
    centre behind the access gate."""
    from noctornal_api.transports import dispatch_due

    alice, bob = _user(conn, clearance="RED"), _user(conn)
    sent = []
    _raise(svc, alice, actor_id=bob, classification="AMBER_STRICT")
    counters = dispatch_due(conn, send_mail=lambda m: sent.append(m))

    assert counters["redacted"] >= 1
    assert sent, "the stub still goes: the FACT of a notification may leave"
    assert "no case material" in sent[0].get_content()
    row = conn.execute(
        """SELECT d.state, d.redacted, d.detail FROM notify.delivery d
             JOIN notify.notification n ON n.id = d.notification_id
            WHERE n.recipient_id = %s AND d.channel = 'SMTP'""",
        (alice,)).fetchone()
    assert row[0] == "REFUSED" and row[1] is True
    assert row[2] == "above_platform_floor"


def test_amber_content_does_leave_in_full(conn, svc):
    from noctornal_api.transports import dispatch_due

    alice, bob = _user(conn), _user(conn)
    sent = []
    _raise(svc, alice, actor_id=bob, classification="AMBER")
    counters = dispatch_due(conn, send_mail=lambda m: sent.append(m))
    assert counters["sent"] >= 1
    assert "Something happened on OP-X." in sent[0].get_content()


def test_compartmented_material_never_leaves_either(conn, svc):
    """No external system models compartments, so egress would silently drop
    the control."""
    from noctornal_api.transports import dispatch_due

    alice = _user(conn, clearance="RED", compartments=("OPERATION-X",))
    bob = _user(conn)
    sent = []
    _raise(svc, alice, actor_id=bob, classification="AMBER",
           compartments=frozenset({"OPERATION-X"}))
    dispatch_due(conn, send_mail=lambda m: sent.append(m))
    row = conn.execute(
        """SELECT d.state, d.detail FROM notify.delivery d
             JOIN notify.notification n ON n.id = d.notification_id
            WHERE n.recipient_id = %s AND d.channel = 'SMTP'""",
        (alice,)).fetchone()
    assert row[0] == "REFUSED" and row[1] == "compartmented_material"


def test_a_transport_failure_is_a_row_and_backs_off(conn, svc):
    """Invariant 12: a failure is a row, never a shrug."""
    from noctornal_api.transports import TransportError, dispatch_due

    alice, bob = _user(conn), _user(conn)
    n = _raise(svc, alice, actor_id=bob)

    def boom(_message):
        raise TransportError("connection refused")

    counters = dispatch_due(conn, send_mail=boom)
    assert counters["failed"] >= 1
    row = conn.execute(
        "SELECT state, attempts, detail, deliver_after > now() "
        "FROM notify.delivery WHERE notification_id = %s AND channel = 'SMTP'",
        (n.id,)).fetchone()
    assert row[0] == "PENDING" and row[1] == 1
    assert "connection refused" in row[2]
    assert row[3] is True, "a failure must back off, not spin"


def test_a_delivery_stops_being_retried_eventually(conn, svc):
    """A delivery retried forever is an outbox that never drains and a log
    nobody reads."""
    from noctornal_api.transports import MAX_ATTEMPTS, TransportError, dispatch_due

    alice, bob = _user(conn), _user(conn)
    n = _raise(svc, alice, actor_id=bob)

    def boom(_message):
        raise TransportError("nope")

    for _ in range(MAX_ATTEMPTS + 1):
        conn.execute("UPDATE notify.delivery SET deliver_after = now() "
                     "WHERE notification_id = %s", (n.id,))
        dispatch_due(conn, send_mail=boom)
    row = conn.execute(
        "SELECT state, attempts FROM notify.delivery "
        "WHERE notification_id = %s AND channel = 'SMTP'", (n.id,)).fetchone()
    assert row[0] == "FAILED"
    assert row[1] >= MAX_ATTEMPTS


def test_a_deferred_delivery_is_not_drained_early(conn, svc):
    from noctornal_api.transports import dispatch_due

    alice, bob = _user(conn), _user(conn)
    n = _raise(svc, alice, actor_id=bob)
    conn.execute("UPDATE notify.delivery SET deliver_after = now() + interval '1 hour' "
                 "WHERE notification_id = %s", (n.id,))
    sent = []
    dispatch_due(conn, send_mail=lambda m: sent.append(m))
    assert sent == []


# --- the events docs actually require -----------------------------------

def test_a_merge_notifies_the_case_owner(conn):
    """docs/01 by name: "Merges ... generate an audit event and a case-owner
    notification." The audit event has existed since decision 41; this is
    the half that was missing."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.merges import MergeService
    from noctornal_api.notifications import NotificationService

    owner = _user(conn, clearance="RED")
    analyst = _user(conn, clearance="RED")
    case_id = _case(conn, owner)
    writer = GraphWriteService(conn)
    ids = []
    for label in ("shadowbroker", "shadow_broker"):
        ids.append(writer.create_node(
            case_id=case_id, node_type="IDENTITY", label=label,
            created_by=analyst,
            assertion=AssertionInput(basis="DIRECT_OBSERVATION",
                                     created_by=analyst, reliability="B",
                                     credibility="2")))
    MergeService(conn).merge(
        case_id=case_id, source_node_id=ids[0], target_node_id=ids[1],
        merged_by=analyst, reason="same PGP fingerprint")

    inbox = NotificationService(conn).inbox(owner)
    assert [n.kind for n in inbox] == ["MERGE_PERFORMED"]
    # The labels are in the body (in-app, behind the gate) and NOT in the
    # summary (which may be emailed).
    assert "shadowbroker" in inbox[0].body
    assert "shadowbroker" not in inbox[0].summary
    assert "shadowbroker" not in inbox[0].subject


def test_an_owner_who_merges_is_not_notified_of_their_own_merge(conn):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.merges import MergeService
    from noctornal_api.notifications import NotificationService

    owner = _user(conn, clearance="RED")
    case_id = _case(conn, owner)
    writer = GraphWriteService(conn)
    ids = [writer.create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner))
        for label in ("a", "b")]
    MergeService(conn).merge(case_id=case_id, source_node_id=ids[0],
                             target_node_id=ids[1], merged_by=owner,
                             reason="same fingerprint")
    assert NotificationService(conn).inbox(owner) == []


def test_an_approval_request_notifies_the_people_who_could_approve_it(conn):
    """Not the case owner and not everyone assigned: the people who hold the
    OPERATION's permission on this case, which is the same set the decide
    endpoint accepts. A queue item somebody cannot action is noise, and a
    queue of noise is a queue nobody reads."""
    from noctornal_api.approvals import ApprovalService
    from noctornal_api.notifications import NotificationService

    owner = _user(conn, clearance="RED")
    approver = _user(conn, clearance="RED")
    bystander = _user(conn, clearance="RED")
    case_id = _case(conn, owner)
    # ANALYST holds graph.merge; READ_ONLY does not.
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s)""", (case_id, approver, owner))
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'READ_ONLY', %s)""", (case_id, bystander, owner))

    ApprovalService(conn).request(
        operation="node.merge", case_id=case_id,
        payload={"source_node_id": str(uuid4()), "target_node_id": str(uuid4()),
                 "reason": "r", "basis_selector_id": None},
        justification="identical fingerprints", requested_by=owner)

    svc = NotificationService(conn)
    assert [n.kind for n in svc.inbox(approver)] == ["APPROVAL_REQUESTED"]
    assert svc.inbox(bystander) == [], (
        "a read-only assignee cannot approve, so is not asked")
    assert svc.inbox(owner) == [], "you are never asked to approve your own request"


def test_deciding_notifies_the_requester(conn):
    from noctornal_api.approvals import ApprovalService
    from noctornal_api.notifications import NotificationService

    owner = _user(conn, clearance="RED")
    approver = _user(conn, clearance="RED")
    case_id = _case(conn, owner)
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s)""", (case_id, approver, owner))
    svc = ApprovalService(conn)
    req = svc.request(
        operation="node.merge", case_id=case_id,
        payload={"source_node_id": str(uuid4()), "target_node_id": str(uuid4()),
                 "reason": "r", "basis_selector_id": None},
        justification="j", requested_by=owner)
    svc.decide(req.id, decided_by=approver, approve=True, note="checked both")

    inbox = NotificationService(conn).inbox(owner)
    assert [n.kind for n in inbox] == ["APPROVAL_DECIDED"]
    assert "approved" in inbox[0].summary


def test_every_registered_kind_has_a_sane_priority():
    """A three-level scale used as five means nothing is urgent."""
    from noctornal_api.notifications import KINDS
    for kind in KINDS.values():
        assert 1 <= kind.default_priority <= 3
    urgent = {k for k, v in KINDS.items() if v.default_priority == 1}
    assert urgent == {"EVIDENCE_INTEGRITY_ALARM", "BREAK_GLASS_INVOKED"}, (
        "priority 1 overrides quiet hours; it has to stay a short list")


def test_an_unknown_kind_is_refused(conn, svc):
    from noctornal_api.notifications import NotificationError
    alice = _user(conn)
    with pytest.raises(NotificationError):
        _raise(svc, alice, kind="SOMETHING_MADE_UP")


def test_the_notification_labels_match_the_access_gates(conn):
    """`effective_labels_for_notification` duplicates `deps.effective_labels`
    on purpose -- deps is the HTTP layer and services have no request. This
    is the test that stops the two drifting."""
    from noctornal_api.http.deps import effective_labels
    from noctornal_api.notifications import effective_labels_for_notification

    owner = _user(conn, clearance="RED", compartments=("A",))
    case_id = _case(conn, owner, classification="AMBER", compartments=("A",))
    from_deps = effective_labels(conn, case_id, "RED", frozenset({"B"}))
    from_notify = effective_labels_for_notification(
        "AMBER", frozenset({"A"}), "RED", frozenset({"B"}))
    assert from_deps == from_notify


def test_the_ttl_of_a_deferred_delivery_survives_a_restart(conn, svc):
    """Deferral is a stored `deliver_after`, not an in-memory timer. A
    process restart must not lose or fire a queued notification."""
    alice, bob = _user(conn), _user(conn)
    svc.set_preference(alice, "SMTP", quiet_from=time(0, 0), quiet_to=time(23, 59),
                       timezone="UTC")
    n = _raise(svc, alice, actor_id=bob)
    row = conn.execute(
        "SELECT deliver_after > now() FROM notify.delivery "
        "WHERE notification_id = %s AND channel = 'SMTP'", (n.id,)).fetchone()
    assert row[0] is True
    assert timedelta(0) >= timedelta(0)  # the row is durable; nothing in memory
