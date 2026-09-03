"""Retention, purge tombstones and break-glass (Phase 6, docs/08 + docs/05).

The tests that carry this file are the ones about what SURVIVES:

- `test_the_tombstone_outlives_the_data` — a purge that leaves nothing
  behind is indistinguishable from data never collected and from data
  somebody deleted to hide it.
- `test_a_locked_object_is_reported_as_locked_not_as_deleted` — evidence
  under COMPLIANCE-mode object lock cannot be deleted even to satisfy a
  deletion order (docs/16 C2), and reporting success because a database row
  changed is how somebody tells a court the wrong thing.
- `test_break_glass_is_refused_when_nobody_can_review_it` — unreviewed
  emergency access is just access.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; governance tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'gov-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE recipient_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification WHERE recipient_id IN {sub}")
        # By ACTOR as well. An alert raised by a gov- user (actor_id) for a
        # recipient outside the sweep, on no case of theirs, survived the
        # recipient and case deletes and blocked the user delete with
        # notification_actor_id_fkey: 35 teardown errors per run until
        # 2026-09-02. Each one rolled back the WHOLE cleanup transaction,
        # so the global TEST% retention rules leaked too and later tests
        # failed on them. notify.delivery cascades from notification.
        c.execute(f"DELETE FROM notify.notification WHERE actor_id IN {sub}")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        # Confirming a retention rule attaches a human to it, so the
        # reference has to be cleared before that human can go.
        c.execute(f"UPDATE core.retention_rule SET confirmed_by = NULL, "
                  f"confirmed_at = NULL WHERE confirmed_by IN {sub}")
        # Rules are GLOBAL: a test-created one leaks into every later test.
        c.execute("DELETE FROM core.retention_rule "
                  "WHERE category LIKE 'TEST%'")
        # purge_tombstone is append-only; stand the trigger down to clear it.
        c.execute("ALTER TABLE core.purge_tombstone DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.purge_tombstone WHERE purged_by IN {sub}")
        c.execute("ALTER TABLE core.purge_tombstone ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        # Custody rows stay and the chain trigger stays up. Until 2026-09-02
        # this teardown deleted them with the trigger stood down, which
        # only ever took the chain's tail and so never tripped
        # `custody_verify.py` -- the teardown in `test_evidence_pg.py` has
        # the full account. What a custody row points at stays with it:
        # the exhibit, its case, and the humans on the custody row, the
        # exhibit and the case. NULL-guarded because one NULL in a NOT IN
        # list silently deletes nothing.
        pinned_evidence = "(SELECT evidence_id FROM core.evidence_custody)"
        pinned_cases = "(SELECT case_id FROM core.evidence WHERE case_id IS NOT NULL)"
        pinned_users = (
            "(SELECT actor_id FROM core.evidence_custody WHERE actor_id IS NOT NULL"
            " UNION SELECT acquired_by FROM core.evidence WHERE acquired_by IS NOT NULL"
            ' UNION SELECT owner_user_id FROM core."case" WHERE owner_user_id IS NOT NULL'
            ' UNION SELECT deputy_user_id FROM core."case" WHERE deputy_user_id IS NOT NULL)'
        )
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub} "
                  f"AND id NOT IN {pinned_evidence}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f"AND id NOT IN {pinned_cases}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'gov-%@noctornal.test' "
                  f"AND id NOT IN {pinned_users}")
    c.close()


def _user(conn, *roles):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"gov-{uuid4().hex[:8]}@noctornal.test", "Officer", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    for role in roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid


def _case(conn, owner, retention=date(2028, 1, 1)):
    """A case cannot be CREATED already expired -- `case_retention_sane`
    refuses it, correctly. So the expired ones are created live and then
    aged, which is also what actually happens to a real case."""
    from noctornal_api.cases import CaseService
    future = date(2028, 1, 1)
    case_id = CaseService(conn).create(
        code=f"OP-GOV-{uuid4().hex[:6]}", title="Governance",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1),
        owner_user_id=owner, created_by=owner)
    if retention != future:
        # `case_retention_sane` ties retention to created_at and fires on
        # UPDATE as well as INSERT, so the creation date has to move too --
        # a case whose retention precedes its own creation is nonsense, and
        # the constraint is right to say so.
        conn.execute(
            '''UPDATE core."case"
                  SET retention_until = %s, review_due = %s,
                      created_at = %s::date - interval '30 days'
                WHERE id = %s''',
            (retention, retention - timedelta(days=1), retention, case_id))
    return case_id


def _evidence(conn, case_id, owner, *, title="exhibit", hold=False):
    row = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, acquired_by, acquired_at,
                acquisition_method, classification, legal_hold,
                legal_hold_reason)
           VALUES (%s, %s, 'text/plain', 10, %s, %s, %s, 'b', %s, now(),
                   'MANUAL_UPLOAD', 'AMBER', %s, %s)
           RETURNING id""",
        (case_id, title, os.urandom(32), os.urandom(32),
         f"key/{uuid4().hex}", owner, hold,
         "court order 2026-11 names this exhibit" if hold else None)).fetchone()
    return row[0]


class MemoryStore:
    def __init__(self, refuse=False):
        self.objects: dict[str, bytes] = {}
        self.refuse = refuse
        self.deleted: list[str] = []

    def delete(self, key):
        if self.refuse:
            # What a COMPLIANCE-mode object lock actually does.
            raise RuntimeError("object is under retention until 2027-01-01")
        self.deleted.append(key)


@pytest.fixture
def svc(conn):
    from noctornal_api.retention import RetentionService
    return RetentionService(conn)


# --- the tombstone ------------------------------------------------------

def test_the_tombstone_outlives_the_data(conn):
    """docs/08: the record of destruction survives the data. A purge that
    leaves nothing behind is indistinguishable from data that was never
    collected, and from data somebody deleted to hide it."""
    from noctornal_api.retention import RetentionService

    owner = _user(conn)
    case_id = _case(conn, owner, retention=date(2024, 1, 1))  # already expired
    _evidence(conn, case_id, owner)
    store = MemoryStore()
    result = RetentionService(conn, store).purge_due(
        actor_id=owner, authority="scheduled retention, policy RET-2026-01",
        case_id=case_id)

    assert result.evidence_purged == 1
    stones = RetentionService(conn).tombstones(case_id)
    assert len(stones) == 1
    assert stones[0]["object_count"] == 1
    assert "RET-2026-01" in stones[0]["authority"]
    # And the exhibit is gone from the live record.
    assert conn.execute(
        "SELECT purged_at FROM core.evidence WHERE case_id = %s",
        (case_id,)).fetchone()[0] is not None


def test_the_tombstone_holds_no_content(conn):
    """A tombstone that quoted what it destroyed would be a copy of it."""
    from noctornal_api.retention import RetentionService
    owner = _user(conn)
    case_id = _case(conn, owner, retention=date(2024, 1, 1))
    _evidence(conn, case_id, owner, title="the incriminating screenshot")
    RetentionService(conn, MemoryStore()).purge_due(
        actor_id=owner, authority="schedule", case_id=case_id)
    row = conn.execute(
        "SELECT detail::text FROM core.purge_tombstone WHERE case_id = %s",
        (case_id,)).fetchone()
    assert "incriminating" not in row[0]


def test_the_tombstone_is_append_only(conn):
    """Somebody who can rewrite the record of destruction can destroy
    without a record."""
    import psycopg
    from noctornal_api.retention import RetentionService
    owner = _user(conn)
    case_id = _case(conn, owner, retention=date(2024, 1, 1))
    _evidence(conn, case_id, owner)
    RetentionService(conn, MemoryStore()).purge_due(
        actor_id=owner, authority="schedule", case_id=case_id)
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("UPDATE core.purge_tombstone SET object_count = 0 "
                     "WHERE case_id = %s", (case_id,))
    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("DELETE FROM core.purge_tombstone WHERE case_id = %s",
                     (case_id,))


def test_a_purge_without_an_authority_is_refused(conn, svc):
    """"The job ran" is not an authority, and an unattributed destruction
    cannot be defended later."""
    from noctornal_api.retention import RetentionError
    owner = _user(conn)
    with pytest.raises(RetentionError, match="authority"):
        svc.purge_due(actor_id=owner, authority="   ")


# --- legal hold ---------------------------------------------------------

def test_a_legal_hold_stops_a_scheduled_purge(conn):
    """docs/08: legal_hold overrides all deletion, everywhere."""
    from noctornal_api.retention import RetentionService
    owner = _user(conn)
    case_id = _case(conn, owner, retention=date(2024, 1, 1))
    _evidence(conn, case_id, owner, hold=True)
    store = MemoryStore()
    result = RetentionService(conn, store).purge_due(
        actor_id=owner, authority="schedule", case_id=case_id)
    assert result.evidence_purged == 0
    assert result.held_back == 1
    assert store.deleted == []


def test_a_case_level_hold_covers_every_exhibit(conn):
    from noctornal_api.retention import RetentionService
    owner = _user(conn)
    case_id = _case(conn, owner, retention=date(2024, 1, 1))
    _evidence(conn, case_id, owner)
    conn.execute(
        'UPDATE core."case" SET legal_hold = true, legal_hold_reason = %s '
        'WHERE id = %s', ("court order 2026-11 freezes the whole case", case_id))
    result = RetentionService(conn, MemoryStore()).purge_due(
        actor_id=owner, authority="schedule", case_id=case_id)
    assert result.evidence_purged == 0 and result.held_back == 1


def test_held_items_are_REPORTED_not_hidden(conn, svc):
    """"Nothing is due" and "eleven things are due and all are frozen by a
    court order" are different answers, and an operator needs the second."""
    owner = _user(conn)
    case_id = _case(conn, owner, retention=date(2024, 1, 1))
    _evidence(conn, case_id, owner, hold=True)
    due = svc.due(case_id=case_id)
    assert len(due) == 1
    assert due[0].held is True
    assert "court order" in due[0].hold_reason


def test_a_hold_without_a_reason_is_refused(conn, svc):
    """A hold nobody can attribute is a hold nobody can lift."""
    from noctornal_api.retention import RetentionError
    owner = _user(conn)
    case_id = _case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    with pytest.raises(RetentionError, match="rests on"):
        svc.set_legal_hold(ev, actor_id=owner, on=True, reason="")


def test_the_database_refuses_a_hold_without_a_reason_too(conn):
    import psycopg
    owner = _user(conn)
    case_id = _case(conn, owner)
    ev = _evidence(conn, case_id, owner)
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("UPDATE core.evidence SET legal_hold = true WHERE id = %s",
                     (ev,))


# --- the object-lock tension (docs/16 C2) -------------------------------

def test_a_locked_object_is_reported_as_locked_not_as_deleted(conn):
    """The unresolved tension, recorded rather than papered over.

    Evidence sits under COMPLIANCE-mode object lock, which cannot be
    deleted before its retention expires EVEN TO SATISFY A DELETION ORDER.
    Reporting success because the database row changed is how somebody ends
    up telling a court the material was destroyed while it sits in a bucket
    for another eighteen months.
    """
    from noctornal_api.retention import STORAGE_LOCKED, RetentionService

    owner = _user(conn)
    case_id = _case(conn, owner, retention=date(2024, 1, 1))
    _evidence(conn, case_id, owner)
    result = RetentionService(conn, MemoryStore(refuse=True)).purge_due(
        actor_id=owner, authority="schedule", case_id=case_id)

    assert result.storage_locked == 1
    assert any("object store disagrees" in w for w in result.warnings)
    stone = RetentionService(conn).tombstones(case_id)[0]
    assert stone["storage_outcome"] == STORAGE_LOCKED


def test_a_successful_delete_is_reported_as_deleted(conn):
    from noctornal_api.retention import STORAGE_DELETED, RetentionService
    owner = _user(conn)
    case_id = _case(conn, owner, retention=date(2024, 1, 1))
    _evidence(conn, case_id, owner)
    store = MemoryStore()
    RetentionService(conn, store).purge_due(
        actor_id=owner, authority="schedule", case_id=case_id)
    assert len(store.deleted) == 1
    assert RetentionService(conn).tombstones(case_id)[0]["storage_outcome"] \
        == STORAGE_DELETED


# --- per-category retention ---------------------------------------------

def test_a_category_rule_may_only_SHORTEN_the_case_clock(conn, svc):
    """A rule that could extend would let an ingest category outlive the
    authority the case was opened under, which is the one direction that is
    never acceptable."""
    captured = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # Read the rule rather than hard-coding its number. These periods are
    # explicitly placeholders that counsel is meant to replace (docs/16 D3),
    # and a test that asserts 90 would go red on the day somebody answers
    # the question -- which is exactly when a red build is least welcome.
    stealer_days = svc.rules()["STEALER_LOG"].retain_days
    short = svc.effective_deadline(date(2028, 1, 1), "STEALER_LOG", captured)
    assert short == captured + timedelta(days=stealer_days)

    # A category with a LONGER period than the case still cannot win.
    svc.confirm_rule("TEST_LONG", retain_days=10_000, rationale="test",
                     confirmed_by=_user(conn))
    long = svc.effective_deadline(date(2027, 1, 1), "TEST_LONG", captured)
    assert long.date() == date(2027, 1, 1)


def test_an_unknown_category_falls_back_to_the_case_clock(conn, svc):
    """Never to forever, and never to an invented default -- an unknown
    category is a gap in the taxonomy and inventing a clock hides it."""
    captured = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert svc.effective_deadline(
        date(2027, 6, 1), "SOMETHING_NEW", captured).date() == date(2027, 6, 1)


def test_stealer_logs_get_the_shortest_default(conn, svc):
    """docs/12: the most likely route by which this platform becomes a data
    protection incident. The number is a placeholder (docs/16 D3); its
    being the SHORTEST is the design."""
    rules = svc.rules()
    assert rules["STEALER_LOG"].retain_days == min(
        r.retain_days for r in rules.values())


def test_an_unconfirmed_rule_warns_but_does_not_block(conn):
    """Refusing would make the first purge the moment somebody discovers
    the question, which is exactly when they are least able to answer it.
    Running silently is how a guess becomes policy."""
    from noctornal_api.retention import RetentionService
    owner = _user(conn)
    case_id = _case(conn, owner, retention=date(2024, 1, 1))
    _evidence(conn, case_id, owner)
    result = RetentionService(conn, MemoryStore()).purge_due(
        actor_id=owner, authority="schedule", case_id=case_id)
    assert result.evidence_purged == 1
    assert any("never been confirmed by a human" in w for w in result.warnings)


def test_confirming_a_rule_attaches_a_human_to_it(conn, svc):
    """The point of the confirmation is not the number; it is that
    somebody's id is on it.

    Against a dedicated category: retention rules are GLOBAL, so a test
    that confirms STEALER_LOG changes what every later test sees. That
    coupling is real in production too -- confirming a rule is a
    system-wide act, not a per-case one.
    """
    officer = _user(conn)
    rule = svc.confirm_rule("TEST_CONFIRM", retain_days=30,
                            rationale="counsel determination 2026-11",
                            confirmed_by=officer)
    assert rule.confirmed_by == officer
    assert rule.is_placeholder is False


# --- out-of-schedule purge needs four eyes ------------------------------

def test_an_early_purge_needs_an_approval(conn):
    """docs/08 requires dual control, and decision 44 registered
    evidence.purge as an unconditional four-eyes operation. This is that
    mechanism's first real user."""
    from noctornal_api.approvals import ApprovalService
    from noctornal_api.retention import RetentionError, RetentionService

    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)          # retention is 2028, not expired
    ev = _evidence(conn, case_id, alice)
    svc = RetentionService(conn, MemoryStore())

    payload = {"case_id": str(case_id), "evidence_ids": [str(ev)],
               "authority": "court order 2026-11"}
    req = ApprovalService(conn).request(
        operation="evidence.purge", case_id=case_id, payload=payload,
        justification="court ordered destruction", requested_by=alice)

    # Not yet approved.
    with pytest.raises(RetentionError):
        svc.purge_out_of_schedule(
            actor_id=alice, authority="court order 2026-11",
            approval_request_id=req.id, case_id=case_id, evidence_ids=[ev])

    ApprovalService(conn).decide(req.id, decided_by=bob, approve=True)
    result = svc.purge_out_of_schedule(
        actor_id=alice, authority="court order 2026-11",
        approval_request_id=req.id, case_id=case_id, evidence_ids=[ev])
    assert result.evidence_purged == 1
    stone = RetentionService(conn).tombstones(case_id)[0]
    assert stone["rule"] == "out-of-schedule"


def test_a_held_exhibit_is_refused_BEFORE_the_approval_is_spent(conn):
    """A refused purge must not also burn somebody's signature."""
    from noctornal_api.approvals import ApprovalService
    from noctornal_api.retention import RetentionError, RetentionService

    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    ev = _evidence(conn, case_id, alice, hold=True)
    payload = {"case_id": str(case_id), "evidence_ids": [str(ev)],
               "authority": "a"}
    req = ApprovalService(conn).request(
        operation="evidence.purge", case_id=case_id, payload=payload,
        justification="attempted early purge", requested_by=alice)
    ApprovalService(conn).decide(req.id, decided_by=bob, approve=True)

    with pytest.raises(RetentionError, match="legal hold"):
        RetentionService(conn, MemoryStore()).purge_out_of_schedule(
            actor_id=alice, authority="a", approval_request_id=req.id,
            case_id=case_id, evidence_ids=[ev])
    assert ApprovalService(conn).get(req.id).state == "APPROVED", (
        "the approval must still be usable: the purge was refused, not spent")


# --- break-glass --------------------------------------------------------

def test_break_glass_is_refused_when_nobody_can_review_it(conn):
    """Unreviewed emergency access is just access, and a control whose
    oversight is nominal is worse than none -- it produces a record that
    looks like governance."""
    from noctornal_api.break_glass import BreakGlassError, BreakGlassService
    conn.execute("UPDATE iam.user_role SET role_key = role_key")  # no-op
    analyst = _user(conn)
    # Deactivate every security officer for the duration of this test.
    conn.execute(
        """UPDATE iam.app_user SET is_active = false
            WHERE id IN (SELECT user_id FROM iam.user_role
                          WHERE role_key = 'SECURITY_OFFICER')""")
    try:
        with pytest.raises(BreakGlassError, match="nobody can review"):
            BreakGlassService(conn).invoke(
                user_id=analyst, case_id=None,
                justification="the on-call analyst needs access right now")
    finally:
        conn.execute("UPDATE iam.app_user SET is_active = true "
                     "WHERE email NOT LIKE 'gov-%@noctornal.test'")


def test_break_glass_alerts_the_security_officer_at_priority_one(conn):
    """docs/05 asks for an immediate alert. Priority 1 is the only tier
    that overrides quiet hours -- somebody's evening is interrupted on
    purpose, and an alert that waits until 08:00 is a report."""
    from noctornal_api.break_glass import BreakGlassService
    from noctornal_api.notifications import URGENT, NotificationService

    officer = _user(conn, "SECURITY_OFFICER")
    analyst = _user(conn)
    case_id = _case(conn, analyst)
    BreakGlassService(conn).invoke(
        user_id=analyst, case_id=case_id,
        justification="live incident, the case owner is unreachable")

    inbox = NotificationService(conn).inbox(officer)
    assert [n.kind for n in inbox] == ["BREAK_GLASS_INVOKED"]
    assert inbox[0].priority == URGENT


def test_a_thin_justification_is_refused(conn):
    """"urgent" is not reviewable, and this is the text a security officer
    reviews."""
    from noctornal_api.break_glass import BreakGlassError, BreakGlassService
    _user(conn, "SECURITY_OFFICER")
    analyst = _user(conn)
    with pytest.raises(BreakGlassError, match="reviewable"):
        BreakGlassService(conn).invoke(
            user_id=analyst, case_id=None, justification="urgent")


def test_break_glass_is_short_by_constraint_not_convention(conn):
    """A break-glass that can be granted for a week is a role with a
    dramatic name."""
    import psycopg
    from noctornal_api.break_glass import BreakGlassError, BreakGlassService
    _user(conn, "SECURITY_OFFICER")
    analyst = _user(conn)
    with pytest.raises(BreakGlassError, match="capped"):
        BreakGlassService(conn).invoke(
            user_id=analyst, case_id=None,
            justification="a genuinely long justification for a long grant",
            duration=timedelta(days=7))
    # And the database refuses it even if the service is bypassed.
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO iam.break_glass
                   (user_id, justification, expires_at)
               VALUES (%s, %s, now() + interval '3 days')""",
            (analyst, "a genuinely long justification for a long grant"))


def test_use_is_counted_separately_from_grant(conn):
    """"Was it granted" and "was it used" are different questions. The
    interesting review case is the grant that was never used -- the analyst
    found another way, and the emergency was not one."""
    from noctornal_api.break_glass import BreakGlassService
    _user(conn, "SECURITY_OFFICER")
    analyst = _user(conn)
    svc = BreakGlassService(conn)
    grant = svc.invoke(user_id=analyst, case_id=None,
                       justification="live incident, owner unreachable now")
    assert grant.used_at is None and grant.action_count == 0
    svc.record_use(grant.id, action="read evidence")
    svc.record_use(grant.id, action="read evidence")
    after = svc.get(grant.id)
    assert after.used_at is not None and after.action_count == 2


def test_you_cannot_review_your_own_break_glass(conn):
    """Reviewing your own emergency is not a review."""
    from noctornal_api.break_glass import BreakGlassError, BreakGlassService
    _user(conn, "SECURITY_OFFICER")
    analyst = _user(conn)
    svc = BreakGlassService(conn)
    grant = svc.invoke(user_id=analyst, case_id=None,
                       justification="live incident, owner unreachable now")
    with pytest.raises(BreakGlassError, match="your own"):
        svc.review(grant.id, reviewer_id=analyst, outcome="JUSTIFIED")


def test_an_unreviewed_grant_stays_in_the_queue_forever(conn):
    """It does not age out. Ageing out is how a review requirement becomes
    a formality."""
    from noctornal_api.break_glass import BreakGlassService
    officer = _user(conn, "SECURITY_OFFICER")
    analyst = _user(conn)
    svc = BreakGlassService(conn)
    grant = svc.invoke(user_id=analyst, case_id=None,
                       justification="live incident, owner unreachable now")
    # Aged into the past, but still SHORT: break_glass_is_short caps the
    # span at eight hours and fires on UPDATE too, which is the constraint
    # doing its job.
    conn.execute(
        """UPDATE iam.break_glass
              SET started_at = now() - interval '200 days',
                  expires_at = now() - interval '200 days' + interval '2 hours'
            WHERE id = %s""", (grant.id,))
    assert grant.id in [g.id for g in svc.unreviewed()]
    svc.review(grant.id, reviewer_id=officer, outcome="JUSTIFIED")
    assert grant.id not in [g.id for g in svc.unreviewed()]


def test_a_review_cannot_be_revisited(conn):
    from noctornal_api.break_glass import BreakGlassError, BreakGlassService
    officer, other = _user(conn, "SECURITY_OFFICER"), _user(conn)
    analyst = _user(conn)
    svc = BreakGlassService(conn)
    grant = svc.invoke(user_id=analyst, case_id=None,
                       justification="live incident, owner unreachable now")
    svc.review(grant.id, reviewer_id=officer, outcome="UNJUSTIFIED")
    with pytest.raises(BreakGlassError, match="already been reviewed"):
        svc.review(grant.id, reviewer_id=other, outcome="JUSTIFIED")


def test_revoking_does_not_remove_the_review_obligation(conn):
    """A revoked grant is still a grant that happened."""
    from noctornal_api.break_glass import BreakGlassService
    _user(conn, "SECURITY_OFFICER")
    analyst = _user(conn)
    svc = BreakGlassService(conn)
    grant = svc.invoke(user_id=analyst, case_id=None,
                       justification="live incident, owner unreachable now")
    svc.revoke(grant.id, actor_id=analyst)
    assert grant.id in [g.id for g in svc.unreviewed()]


def test_a_revoked_grant_is_not_live(conn):
    from noctornal_api.break_glass import BreakGlassService
    _user(conn, "SECURITY_OFFICER")
    analyst = _user(conn)
    svc = BreakGlassService(conn)
    grant = svc.invoke(user_id=analyst, case_id=None,
                       justification="live incident, owner unreachable now")
    assert svc.live_grant(analyst) is not None
    svc.revoke(grant.id, actor_id=analyst)
    assert svc.live_grant(analyst) is None


def test_break_glass_does_not_cross_a_compartment(conn):
    """Recorded as a deliberate omission rather than left for somebody to
    "fix": a compartment is need-to-know, and "there is an emergency" is
    not knowledge of the need. A genuine read-in has a name on it and is
    not an eight-hour bypass."""
    import inspect

    from noctornal_api import break_glass
    source = inspect.getsource(break_glass)
    assert "compartment" in source.lower(), (
        "the omission must be documented where somebody will read it")
    assert "granted_compartments" not in source


# ---------------------------------------------------------------------------
# Phase 6 hostile pass, 2026-08-10
# ---------------------------------------------------------------------------

def test_a_dry_run_reports_what_would_be_destroyed(conn):
    """A dry run used to return every counter at zero. It did the full
    sweep and threw the answer away, so a preview of a case with exhibits
    about to be destroyed was byte-identical to a preview of a case with
    nothing due -- and the pane rendered both as "Nothing would be
    destroyed."

    `held_back` was the only non-zero number it could produce, which made
    it worse than silent: the one figure on screen counted the items being
    SPARED. This is the control whose entire purpose is to be read before
    an irreversible action.
    """
    from noctornal_api.retention import RetentionService

    uid = _user(conn)
    case_id = _case(conn, uid, retention=date(2020, 1, 1))
    ev = _evidence(conn, case_id, uid)

    dry = RetentionService(conn).purge_due(
        case_id=case_id, actor_id=uid, authority="test", dry_run=True)
    assert dry.evidence_purged == 1, (
        "the dry run reports nothing is due while an exhibit is about to "
        "be destroyed")
    # And it really was a preview.
    still = conn.execute(
        "SELECT purged_at FROM core.evidence WHERE id = %s", (ev,)).fetchone()
    assert still[0] is None, "the dry run destroyed something"


def test_a_case_scoped_sweep_does_not_reach_documents(conn):
    """`collect.document` has NO case_id -- a document hangs off a source
    and is material in however many cases cite it. The document query took
    no case filter, so `purge_due(case_id=X)` counted deployment-wide
    documents and would have written the tombstone under case X.

    That is the cross-case destruction the out-of-schedule router refuses
    by name, arriving through the scheduled path.
    """
    from noctornal_api.retention import RetentionService

    uid = _user(conn)
    case_id = _case(conn, uid, retention=date(2020, 1, 1))
    # A document that IS due, so the assertion is not vacuous: with no due
    # document the sweep returns none either way and the test proves
    # nothing. This is the row that used to be swept up by a case it has
    # no relationship to.
    src = conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, default_reliability, poll_interval_s,
                jitter_pct, max_rps, parser_key, classification)
           VALUES ('RSS', %s, 'https://forum.test/f', 'C', 300, 10, 1,
                   'rss', 'AMBER') RETURNING id""",
        (f"gov-src-{uuid4().hex[:6]}",)).fetchone()[0]
    conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256,
                retain_until)
           VALUES (%s, %s, 'x', decode(md5('x'),'hex'), '2020-01-01')""",
        (src, uuid4().hex))

    # try/finally, not cleanup-after-assertions. The first version cleaned
    # up on the last line, so when it was run against the unfixed code and
    # failed -- which is the whole point of a regression test -- it left a
    # due document behind, and the next unscoped `purge_due` in the suite
    # inherited it. A test that only tidies up when it passes is a test
    # that poisons the run it was written to protect.
    try:
        scoped = RetentionService(conn).due(case_id=case_id)
        assert not [i for i in scoped if i.object_type == "document"], (
            "a case-scoped sweep picked up a document, which belongs to no "
            "case -- the tombstone would be written under a case that has "
            "no relationship to it")
        # Deployment-wide it IS due, so the assertion above cannot pass
        # merely because the document is invisible everywhere.
        everywhere = RetentionService(conn).due()
        assert [i for i in everywhere if i.object_type == "document"], (
            "the document is invisible even to an unscoped sweep, so this "
            "test would pass for the wrong reason")
    finally:
        conn.execute("DELETE FROM collect.document WHERE source_id = %s",
                     (src,))
        conn.execute("DELETE FROM collect.source WHERE id = %s", (src,))


def test_the_dead_document_clock_is_reported_rather_than_shown_as_zero(conn):
    """Nothing writes `collect.document.retain_until`, so every collected
    document is outside retention forever. Reporting `documents_purged: 0`
    without saying so reports a gap in the wiring as a fact about the data.

    Deliberately not fixed by deriving a deadline: that would arm a
    destruction path over every document already collected, all of them
    instantly past a retention they were never assigned.
    """
    from noctornal_api.retention import RetentionService

    uid = _user(conn)
    case_id = _case(conn, uid, retention=date(2020, 1, 1))
    total = conn.execute(
        "SELECT count(*) FROM collect.document "
        "WHERE purged_at IS NULL AND retain_until IS NULL").fetchone()[0]
    result = RetentionService(conn).purge_due(
        case_id=case_id, actor_id=uid, authority="test", dry_run=True)
    if total:
        assert any("no retention clock" in w for w in result.warnings), (
            "documents with no clock are silently invisible to the sweep")


def test_a_partial_storage_refusal_counts_refusals_not_the_batch(conn):
    """`storage_locked` was `len(evidence_ids)` -- the batch size. One
    refusal in a hundred and a hundred refusals wrote the same number into
    an append-only tombstone, so the figure could not distinguish them and
    could never be corrected."""
    from noctornal_api.retention import RetentionService

    class _PartlyLocked:
        """Refuses the first object with a retention lock, deletes the rest."""

        def __init__(self):
            self.seen = 0

        def delete(self, key):
            self.seen += 1
            if self.seen == 1:
                raise RuntimeError("object is under a retention lock")

    uid = _user(conn)
    case_id = _case(conn, uid, retention=date(2020, 1, 1))
    for _ in range(3):
        _evidence(conn, case_id, uid)

    svc = RetentionService(conn, storage=_PartlyLocked())
    result = svc.purge_due(case_id=case_id, actor_id=uid,
                           authority="test", dry_run=False)
    assert result.evidence_purged == 3
    assert result.storage_locked == 1, (
        f"reported {result.storage_locked} locked objects for one refusal "
        f"out of three")


def test_a_storage_failure_is_not_reported_as_a_retention_lock(conn):
    """A bare `except Exception` mapped every failure class to
    LOCKED_UNTIL_RETENTION, which is a specific and defensible claim about
    a retention lock. A connection reset is not that claim, and
    STORAGE_FAILED existed for it and was dead code."""
    from noctornal_api.retention import RetentionService

    class _Broken:
        def delete(self, key):
            raise RuntimeError("connection reset by peer")

    uid = _user(conn)
    case_id = _case(conn, uid, retention=date(2020, 1, 1))
    _evidence(conn, case_id, uid)

    result = RetentionService(conn, storage=_Broken()).purge_due(
        case_id=case_id, actor_id=uid, authority="test", dry_run=False)
    assert result.storage_failed == 1
    assert result.storage_locked == 0, (
        "a transport failure was recorded as a retention lock")


def test_purging_a_document_does_not_abort_on_a_not_null_column(conn):
    """`body_text` is NOT NULL (0011) and the purge set it to NULL, so the
    statement aborts the whole transaction with a constraint violation.

    It had never once run against a row: nothing writes
    `collect.document.retain_until`, so no document has ever been due. The
    document sweep was dead in two independent ways and the second was
    hidden behind the first -- which is why fixing only the visible half
    would have turned a silent no-op into a purge that fails outright the
    first time somebody wires the clock.
    """
    from noctornal_api.retention import RetentionService

    uid = _user(conn)
    src = conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, default_reliability, poll_interval_s,
                jitter_pct, max_rps, parser_key, classification)
           VALUES ('RSS', %s, 'https://forum.test/f', 'C', 300, 10, 1,
                   'rss', 'AMBER') RETURNING id""",
        (f"gov-src-{uuid4().hex[:6]}",)).fetchone()[0]
    doc = conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, body_text, content_sha256,
                retain_until)
           VALUES (%s, %s, 'sensitive body', decode(md5('x'),'hex'),
                   '2020-01-01')
           RETURNING id""",
        (src, uuid4().hex)).fetchone()[0]
    try:
        result = RetentionService(conn).purge_due(
            actor_id=uid, authority="retention schedule", dry_run=False)
        assert result.documents_purged >= 1
        row = conn.execute(
            "SELECT purged_at, body_text FROM collect.document WHERE id = %s",
            (doc,)).fetchone()
        assert row[0] is not None, "the document was not marked purged"
        assert row[1] == "", "the body survived the purge"
    finally:
        conn.execute("DELETE FROM collect.document WHERE source_id = %s",
                     (src,))
        conn.execute("DELETE FROM collect.source WHERE id = %s", (src,))
