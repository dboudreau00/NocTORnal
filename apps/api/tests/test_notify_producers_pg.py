"""N2 (2026-09-02): three registered notification kinds had no producer.

`notifications.KINDS` registered EVIDENCE_INTEGRITY_ALARM at URGENT -- one
of two priority-1 kinds in the system -- and nothing raised it. The string
existed in `evidence.py` only as an AUDIT action on the incidental read
path, and the explicit POST /verify path wrote a HASH_VERIFIED custody row
and nothing else on a mismatch. PROPOSAL_QUEUED had a wording function
(`notify_events.proposals_queued`) that no router called. CASE_REVIEW_DUE
had a description and nothing behind it.

A kind in the preferences panel that can never fire is a promise the
system makes to the analyst and does not keep. These tests hold each of
the three to a producer.

**The email prefix is `nprod-` and must stay unique.** Document titles
are `nprod-` too, for the capture leg's cleanup.

Env-gated on DATABASE_URL; the evidence legs also need MINIO_ENDPOINT.
"""
from __future__ import annotations

import os
import time
from datetime import date, timedelta
from uuid import UUID, uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; producer tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple"
EMAIL_LIKE = "nprod-%@noctornal.test"

SAMPLE = """
Thread: re: escrow terms
spectre_lynx wrote:
  Contact me at spectre.lynx@protonmail.com or @spectre_lynx on tg.
  Payment to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq, no exceptions.
  Loader build 10.2.14.3, sample
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  beacons to 185.220.101.42.
"""


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    ours = (f"(SELECT id FROM notify.notification "
            f"  WHERE recipient_id IN {sub} OR actor_id IN {sub})")
    with c.transaction():
        # The officer copies FIRST, and before the originals they point at.
        # `escalation_to_officer` is case-less and goes to a real
        # SECURITY_OFFICER of this database, so neither clause below
        # reaches it: the integrity-alarm test's escalations outlived the
        # suite. Harmless while `dispatch_due` sent what it raised in the
        # same pass; once the producers moved below the drain loop
        # (2026-09-02) the leftovers stayed PENDING and URGENT and the next
        # suite's drain sent them first. See the same note in
        # test_notify_escalation_pg.py.
        esc = (f"(SELECT id FROM notify.notification WHERE kind = 'ESCALATION' "
               f"   AND object_type = 'notification' AND object_id IN {ours})")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN {esc}")
        c.execute(f"DELETE FROM notify.notification WHERE kind = 'ESCALATION' "
                  f"  AND object_type = 'notification' AND object_id IN {ours}")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification "
                  f"  WHERE recipient_id IN {sub} OR actor_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}")
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute("""DELETE FROM collect.extraction WHERE document_id IN
                     (SELECT id FROM collect.document WHERE title LIKE 'nprod-%')""")
        c.execute("DELETE FROM collect.document WHERE title LIKE 'nprod-%'")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _make_user(conn, *, clearance="AMBER", global_roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"nprod-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Prod", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email, secret


def _login(client, email, secret) -> str:
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _create_case(client, token, review_due=date(2027, 1, 1)) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-NPROD-{uuid4().hex[:6]}", "title": "Producers",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(review_due)})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _assign(conn, case_id, user_id, role, granted_by):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, user_id, role, granted_by))


def _inbox(conn, user_id, kind):
    from noctornal_api.notifications import NotificationService
    return [n for n in NotificationService(conn).inbox(user_id) if n.kind == kind]


# ---------------------------------------------------------------------------
# EVIDENCE_INTEGRITY_ALARM
# ---------------------------------------------------------------------------

def _owner_case_and_tampered_exhibit(conn, client):
    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    up = client.post(
        f"/api/v1/cases/{case_id}/evidence", headers=_auth(token),
        files={"file": ("shot.png", b"exhibit-" + uuid4().hex.encode(), "image/png")},
        data={"title": "ransom note screenshot", "acquisition_method": "MANUAL_UPLOAD"})
    assert up.status_code == 201, up.text
    ev_id = up.json()["evidence_id"]
    # Doctor the recorded hash: the bytes in WORM storage cannot be changed,
    # which is the point of WORM, so the mismatch is manufactured on the
    # other side of the comparison.
    conn.execute("UPDATE core.evidence SET sha256 = %s WHERE id = %s",
                 (b"\x00" * 32, UUID(ev_id)))
    return owner, UUID(case_id), UUID(ev_id)


@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required")
def test_an_explicit_verify_that_fails_raises_the_alarm_and_the_audit_row(conn, client):
    owner, case_id, ev_id = _owner_case_and_tampered_exhibit(conn, client)
    verifier, v_email, v_secret = _make_user(conn)
    _assign(conn, case_id, verifier, "ANALYST", owner)
    v_token = _login(client, v_email, v_secret)

    r = client.post(f"/api/v1/cases/{case_id}/evidence/{ev_id}/verify",
                    headers=_auth(v_token))
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is False

    alarms = _inbox(conn, owner, "EVIDENCE_INTEGRITY_ALARM")
    assert len(alarms) == 1, "the owner is told, once"
    alarm = alarms[0]
    assert alarm.priority == 1, "a tamper alarm wakes people up"
    assert alarm.object_type == "evidence" and alarm.object_id == ev_id
    assert "explicit verify" in alarm.body
    assert "failed its integrity check" in alarm.subject

    audit = conn.execute(
        """SELECT detail FROM audit.event
            WHERE action = 'EVIDENCE_INTEGRITY_ALARM' AND object_id = %s
            ORDER BY occurred_at DESC LIMIT 1""", (ev_id,)).fetchone()
    assert audit is not None, "the explicit path wrote only HASH_VERIFIED before N2"
    assert audit[0]["on_read"] is False
    assert audit[0]["sha256_ok"] is False and "blake3_ok" in audit[0]


@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required")
def test_a_mismatch_found_on_read_raises_the_alarm_too(conn, client):
    """The incidental path already wrote the AUDIT row; it never raised the
    notification that the kind's URGENT priority promises."""
    from noctornal_api.evidence import EvidenceService, EvidenceStorage, IntegrityError

    owner, case_id, ev_id = _owner_case_and_tampered_exhibit(conn, client)
    reader, _, _ = _make_user(conn)
    _assign(conn, case_id, reader, "ANALYST", owner)

    with pytest.raises(IntegrityError):
        EvidenceService(conn, EvidenceStorage()).view(ev_id, reader)

    alarms = _inbox(conn, owner, "EVIDENCE_INTEGRITY_ALARM")
    assert len(alarms) == 1
    assert "found on read" in alarms[0].body
    assert alarms[0].object_id == ev_id


@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required")
def test_re_reading_a_tampered_exhibit_does_not_mint_another_alarm(conn, client):
    """The read path is not an outbound-email amplifier.

    Before 2026-09-02 `evidence_integrity_alarm` was a bare
    `notify_case_owner` with no dedupe, no idempotence key and no throttle,
    fired from BOTH detection sites -- `_fetch_verified` (every read) and
    `verify_integrity` (every explicit verify). Neither
    `GET /cases/{id}/evidence/{id}/content` nor `POST /{id}/verify` carries
    a `rate_limit` dependency, and `notify.notification` has no unique
    constraint. So any caller holding `evidence.read` on a case with one
    corrupt exhibit minted one priority-1 notification and one PENDING SMTP
    delivery to the case owner PER REQUEST -- on a path that had previously
    written only a cheap internal audit row. Suppression 1 was no defence:
    the owner is the recipient and the looper is anybody else.

    The second half is why this is more than volume. Because the owner IS
    the recipient, `notifications.escalate_unacknowledged` skips
    `escalation_to_owner` and fans EVERY one of those alarms out to EVERY
    active SECURITY_OFFICER, repeating each drain until each is
    acknowledged individually -- so the party with the motive to bury the
    tamper alarm could drown it in copies of itself.

    This test therefore reads both sides: three detections through
    `evidence.py` must leave ONE alarm in `notify_events.py`, and therefore
    ONE fan-out through `notifications.py`, not three.
    """
    from noctornal_api.evidence import EvidenceService, EvidenceStorage, IntegrityError
    from noctornal_api.notifications import NotificationService, escalate_unacknowledged

    owner, case_id, ev_id = _owner_case_and_tampered_exhibit(conn, client)
    reader, _, _ = _make_user(conn)
    _assign(conn, case_id, reader, "ANALYST", owner)
    svc = EvidenceService(conn, EvidenceStorage())

    for _ in range(2):
        with pytest.raises(IntegrityError):
            svc.view(ev_id, reader)
    assert svc.verify_integrity(ev_id, reader) is False

    alarms = _inbox(conn, owner, "EVIDENCE_INTEGRITY_ALARM")
    mine = [a for a in alarms if a.object_id == ev_id]
    assert len(mine) == 1, (
        f"three detections minted {len(mine)} URGENT notifications; the read "
        f"path is an unbounded outbound-email amplifier")
    deliveries = conn.execute(
        """SELECT count(*) FROM notify.delivery
            WHERE notification_id = %s AND channel = 'SMTP'""",
        (mine[0].id,)).fetchone()[0]
    assert deliveries == 1, "one alarm, one queued email"

    # The consequence half, in the same test because the contract crosses
    # the two files: one outstanding alarm escalates to the officers once,
    # not once per attacker request.
    conn.execute("UPDATE notify.notification SET created_at = now() - interval "
                 "'3 hours' WHERE id = %s", (mine[0].id,))
    officers = [r[0] for r in conn.execute(
        """SELECT DISTINCT ur.user_id FROM iam.user_role ur
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.role_key = 'SECURITY_OFFICER' AND u.is_active""").fetchall()]
    escalate_unacknowledged(conn, after=timedelta(hours=1))
    fanned = conn.execute(
        """SELECT count(*) FROM notify.notification
            WHERE kind = 'ESCALATION' AND object_type = 'notification'
              AND object_id = %s""", (mine[0].id,)).fetchone()[0]
    assert fanned == len([o for o in officers if o != owner]), (
        "the alarm fans out to every security officer; it must do so for "
        "ONE alarm, which is why the alarm itself has to be deduped")

    # A genuinely new failure after the owner has answered is NOT lost: the
    # guard is keyed on `acknowledged_at IS NULL`, not on existence.
    assert NotificationService(conn).acknowledge(mine[0].id, owner)
    with pytest.raises(IntegrityError):
        svc.view(ev_id, reader)
    again = [a for a in _inbox(conn, owner, "EVIDENCE_INTEGRITY_ALARM")
             if a.object_id == ev_id]
    assert len(again) == 2, (
        "an acknowledged alarm must not suppress the next one; the exhibit "
        "is still failing and the owner has said they are done with the "
        "last report")


# ---------------------------------------------------------------------------
# PROPOSAL_QUEUED
# ---------------------------------------------------------------------------

def test_a_capture_that_queues_proposals_tells_the_owner(conn, client):
    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    uploader, u_email, u_secret = _make_user(conn)
    _assign(conn, case_id, uploader, "ANALYST", owner)
    u_token = _login(client, u_email, u_secret)

    r = client.post(f"/api/v1/cases/{case_id}/proposals/capture",
                    headers=_auth(u_token),
                    json={"text": SAMPLE, "title": f"nprod-{uuid4().hex[:6]}"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["proposals_created"] > 0, "the sample must yield proposals"
    assert body["owner_notified"] is True

    queued = _inbox(conn, owner, "PROPOSAL_QUEUED")
    assert len(queued) == 1
    assert str(body["proposals_created"]) in queued[0].subject
    assert queued[0].case_id == UUID(case_id)


def test_a_capture_notification_failure_is_null_not_false(conn, client, monkeypatch):
    """The document and the proposals committed before the notify write;
    a 500 here would tell the analyst the capture failed, and they would
    paste it again.

    And the failure is reported as `null`, NOT `false`. Until 2026-09-02
    the except path returned False -- the same value the endpoint uses for
    "there were no proposals" and "the owner is the person who pasted it"
    -- so a broken notifier and a deliberate suppression read identically
    to every caller. `NotificationService.notify` returns None for
    suppressed precisely to keep "we decided not to" apart from "we tried
    and could not"; conflating them one file downstream is this codebase's
    signature defect, a failure reported as the wrong thing rather than as
    a crash.

    `test_a_capture_that_queues_proposals_tells_the_owner` pins the True
    end of the same field; False remains what `proposals_queued` returns
    when it deliberately said nothing.
    """
    from noctornal_api import notify_events

    def boom(*a, **kw):
        raise RuntimeError("notify.notification is unreachable")
    monkeypatch.setattr(notify_events, "proposals_queued", boom)

    owner, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    uploader, u_email, u_secret = _make_user(conn)
    _assign(conn, case_id, uploader, "ANALYST", owner)
    u_token = _login(client, u_email, u_secret)

    r = client.post(f"/api/v1/cases/{case_id}/proposals/capture",
                    headers=_auth(u_token),
                    json={"text": SAMPLE, "title": f"nprod-{uuid4().hex[:6]}"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["owner_notified"] is None, (
        "a notify that FAILED must not report the same value as a notify "
        "that was deliberately suppressed")
    assert body["owner_notified"] is not False
    assert body["proposals_created"] > 0


# ---------------------------------------------------------------------------
# CASE_REVIEW_DUE
# ---------------------------------------------------------------------------

def test_a_review_due_within_the_horizon_notifies_the_owner_exactly_once(conn):
    """Idempotent by construction: the second sweep finds the row the first
    one wrote and writes nothing. The count is of rows WRITTEN, not of
    cases seen, so a sweep whose every owner is suppressed reports 0."""
    from noctornal_api.cases import CaseService
    from noctornal_api.notify_events import case_reviews_due

    owner, _, _ = _make_user(conn, clearance="AMBER")
    today = conn.execute("SELECT current_date").fetchone()[0]
    cases = CaseService(conn)
    case_id = cases.create(
        code=f"OP-NPROD-{uuid4().hex[:6]}", title="Review due", legal_basis="dev",
        retention_until=today + timedelta(days=400),
        review_due=today + timedelta(days=1),
        owner_user_id=owner, created_by=owner)
    cases.transition_status(case_id, "ACTIVE", actor_id=owner)

    first = case_reviews_due(conn, as_of=today)
    assert first >= 1
    mine = _inbox(conn, owner, "CASE_REVIEW_DUE")
    assert len(mine) == 1 and mine[0].case_id == case_id
    assert str(today + timedelta(days=1)) in mine[0].summary

    assert case_reviews_due(conn, as_of=today) == 0
    assert len(_inbox(conn, owner, "CASE_REVIEW_DUE")) == 1


def test_a_review_outside_the_horizon_is_not_announced_yet(conn):
    from noctornal_api.cases import CaseService
    from noctornal_api.notify_events import case_reviews_due

    owner, _, _ = _make_user(conn, clearance="AMBER")
    today = conn.execute("SELECT current_date").fetchone()[0]
    cases = CaseService(conn)
    case_id = cases.create(
        code=f"OP-NPROD-{uuid4().hex[:6]}", title="Review far", legal_basis="dev",
        retention_until=today + timedelta(days=400),
        review_due=today + timedelta(days=60),
        owner_user_id=owner, created_by=owner)
    cases.transition_status(case_id, "ACTIVE", actor_id=owner)
    case_reviews_due(conn, as_of=today, horizon_days=14)
    assert _inbox(conn, owner, "CASE_REVIEW_DUE") == []


def test_a_review_that_moves_is_announced_again_for_its_new_date(conn):
    """Idempotence is per (case, review_due), not per case: a review that
    was pushed back three months is a new deadline."""
    from noctornal_api.cases import CaseService
    from noctornal_api.notify_events import case_reviews_due

    owner, _, _ = _make_user(conn, clearance="AMBER")
    today = conn.execute("SELECT current_date").fetchone()[0]
    cases = CaseService(conn)
    case_id = cases.create(
        code=f"OP-NPROD-{uuid4().hex[:6]}", title="Review moves", legal_basis="dev",
        retention_until=today + timedelta(days=400),
        review_due=today + timedelta(days=2),
        owner_user_id=owner, created_by=owner)
    cases.transition_status(case_id, "ACTIVE", actor_id=owner)
    case_reviews_due(conn, as_of=today)
    conn.execute('UPDATE core."case" SET review_due = %s WHERE id = %s',
                 (today + timedelta(days=5), case_id))
    case_reviews_due(conn, as_of=today)
    assert len(_inbox(conn, owner, "CASE_REVIEW_DUE")) == 2


# ---------------------------------------------------------------------------
# every registered kind has a producer that names it
# ---------------------------------------------------------------------------

def test_every_registered_kind_is_raised_somewhere():
    """A kind in `KINDS` with no `kind="..."` call site anywhere in the
    package is a preference the user can set for an event that cannot
    happen. Read the source: a grep is the only test that survives the
    producer being deleted."""
    import re
    from pathlib import Path

    from noctornal_api import notifications
    from noctornal_api.notifications import KINDS

    src = Path(notifications.__file__).parent
    raised = set()
    for path in src.rglob("*.py"):
        if path.name == "notifications.py":
            continue
        raised |= set(re.findall(r'kind="([A-Z_]+)"', path.read_text(encoding="utf-8")))
    missing = set(KINDS) - raised
    assert not missing, f"registered kinds with no producer: {sorted(missing)}"
