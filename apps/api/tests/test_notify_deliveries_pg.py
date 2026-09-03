"""N4 (2026-09-02): the delivery ledger is read back, and a channel with no
transport cannot be switched on.

`notify.delivery` records every refusal with a reason and the address each
message actually reached (migration 0044), and until now nothing rendered
it: the one table that answers "did the summary leave the building, and
where did it go" was write-only. GET /notifications/deliveries is the read.

Separately, a user could enable JIRA -- for which no transport exists in
this build -- or WEBHOOK with no NOCTORNAL_WEBHOOK_URL configured, and the
drain then reported the impossibility as a retryable transport failure,
five times per notification, forever. Refusing at the preference is the
honest place: the user is told at the moment they ask.

**The email prefix is `ndel-` and must stay unique.**

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; delivery tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple"
EMAIL_LIKE = "ndel-%@noctornal.test"


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
        c.execute(f"DELETE FROM notify.preference WHERE user_id IN {sub}")
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
    email = f"ndel-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Del", PASSWORD)
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


def _raise(conn, recipient, actor, **kw):
    """Raised URGENT on purpose, whatever the kind's own priority: `due()`
    orders the outbox by priority then age and the drain is capped at
    MAX_PER_DRAIN, so a NORMAL row raised behind a backlog (a killed run of
    any suite leaves one) is simply not reached in one pass and the ledger
    row this test then reads is still PENDING for a reason that has nothing
    to do with what is being tested. URGENT puts it at the front."""
    from noctornal_api.notifications import URGENT, NotificationService
    defaults = dict(kind="MERGE_PERFORMED", subject="OP-X: something happened",
                    summary="Something happened on OP-X.", body="detail",
                    classification="AMBER", priority=URGENT)
    defaults.update(kw)
    n = NotificationService(conn).notify(recipient_id=recipient, actor_id=actor,
                                         **defaults)
    assert n is not None
    return n


def _drain_until_attempted(conn, notification_id, send_mail, *, passes=10):
    """Drain until OUR row has actually been tried, not just once.

    URGENT puts the row at the front of `due()`'s ordering, but `due()`
    orders by priority THEN age and caps at MAX_PER_DRAIN=200, so 200+
    older due URGENT rows -- which a killed run of any suite leaves behind
    -- starve it out of a single pass anyway. The ledger assertions below
    would then fail on a PENDING row that was never reached: a failure
    reported as the wrong thing, and the reason a hand-deletion of 676 rows
    from this database was load-bearing for these tests on 2026-09-02.

    Each pass backs the rows it touched off into the future
    (`transports._fail` sets `deliver_after = now() + 2^attempts minutes`),
    so the backlog drains rather than repeating. Bounded, because a loop
    that cannot terminate is worse than a starved assertion.
    """
    from noctornal_api.transports import dispatch_due
    for _ in range(passes):
        dispatch_due(conn, send_mail=send_mail)
        row = conn.execute(
            """SELECT last_attempt_at FROM notify.delivery
                WHERE notification_id = %s AND channel = 'SMTP'""",
            (notification_id,)).fetchone()
        if row is not None and row[0] is not None:
            return
    raise AssertionError(
        f"{passes} drains never reached notification {notification_id}; the "
        f"outbox backlog is deeper than {passes} x MAX_PER_DRAIN")


# ---------------------------------------------------------------------------
# GET /notifications/deliveries
# ---------------------------------------------------------------------------

def test_the_ledger_is_readable_with_reason_and_address(conn, client):
    from noctornal_api.transports import TransportError

    admin, a_email, a_secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    recipient, r_email, _ = _make_user(conn)
    actor, _, _ = _make_user(conn)
    n = _raise(conn, recipient, actor)

    def boom(message):
        raise TransportError("relay refused the connection")
    _drain_until_attempted(conn, n.id, boom)

    token = _login(client, a_email, a_secret)
    r = client.get("/api/v1/notifications/deliveries", headers=_auth(token),
                   params={"kind": "MERGE_PERFORMED", "limit": 50})
    assert r.status_code == 200, r.text
    rows = [d for d in r.json()["deliveries"] if d["notification_id"] == str(n.id)]
    by_channel = {d["channel"]: d for d in rows}
    assert set(by_channel) >= {"IN_APP", "SMTP"}

    smtp = by_channel["SMTP"]
    assert smtp["recipient"] == r_email
    assert smtp["outcome"] == "PENDING", "one failure backs off, it does not give up"
    assert "relay refused" in smtp["reason"]
    assert smtp["attempted_at"] is not None
    assert smtp["kind"] == "MERGE_PERFORMED"
    assert "subject" not in smtp and "summary" not in smtp, (
        "an operator with integration.manage holds no case-content "
        "permission; the ledger names the kind, never the content")

    in_app = by_channel["IN_APP"]
    assert in_app["outcome"] == "SENT"


def test_refused_only_hides_what_was_delivered(conn, client):
    from noctornal_api.transports import TransportError

    admin, a_email, a_secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    # Cleared for the row, or suppression 2 never writes it (an AMBER
    # clearance cannot read AMBER_STRICT) and there is nothing to refuse.
    # The refusal under test is the SMTP egress gate's, downstream of that.
    recipient, _, _ = _make_user(conn, clearance="AMBER_STRICT")
    actor, _, _ = _make_user(conn)
    n = _raise(conn, recipient, actor, classification="AMBER_STRICT")
    _drain_until_attempted(conn, n.id, lambda m: None)

    token = _login(client, a_email, a_secret)
    r = client.get("/api/v1/notifications/deliveries", headers=_auth(token),
                   params={"refused_only": "true", "limit": 100})
    assert r.status_code == 200, r.text
    mine = [d for d in r.json()["deliveries"] if d["notification_id"] == str(n.id)]
    assert [d["channel"] for d in mine] == ["SMTP"], mine
    assert mine[0]["outcome"] == "REFUSED"
    assert mine[0]["reason"] == "above_platform_floor"
    assert mine[0]["redacted"] is True

    # Silence the unused-variable lint on purpose: the TransportError import
    # documents the sibling test's shape.
    del TransportError


def test_refused_only_shows_a_revocation_but_not_a_channel_the_recipient_turned_off(conn, client):
    """The contract crosses two files. `transports.revoke_undeliverable`
    closes a queued row as SUPPRESSED and stamps `last_attempt_at`;
    `NotificationService._queue_deliveries` writes SUPPRESSED at raise time
    for a channel the recipient has off and stamps nothing. The router's
    `refused_only` tells them apart on that stamp, so the revocation -- the
    one row that says somebody was deliberately NOT told -- surfaces, and
    the two preference rows every notification carries do not. Read both
    writers if this fails: the stamp is the whole contract."""
    from noctornal_api.transports import dispatch_due

    admin, a_email, a_secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    recipient, _, _ = _make_user(conn)
    actor, _, _ = _make_user(conn)
    n = _raise(conn, recipient, actor, classification="AMBER")
    # Revoked AFTER the row was queued: the recipient can no longer read
    # what is waiting for them, and the next drain closes it out.
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'GREEN' WHERE id = %s",
                 (recipient,))
    counters = dispatch_due(conn, send_mail=lambda m: None)
    assert counters["revoked"] >= 1, counters

    token = _login(client, a_email, a_secret)
    r = client.get("/api/v1/notifications/deliveries", headers=_auth(token),
                   params={"refused_only": "true", "limit": 100})
    assert r.status_code == 200, r.text
    mine = [d for d in r.json()["deliveries"] if d["notification_id"] == str(n.id)]
    assert [d["channel"] for d in mine] == ["SMTP"], mine
    assert mine[0]["outcome"] == "SUPPRESSED"
    assert "may no longer read" in mine[0]["reason"]
    assert mine[0]["attempts"] == 0 and mine[0]["redacted"] is False, (
        "nothing was attempted and nothing went out; see _REVOKE_SQL")
    assert mine[0]["attempted_at"] is not None, "the stamp the filter cuts on"


def test_the_ledger_is_newest_first_and_capped(conn, client):
    admin, a_email, a_secret = _make_user(conn, global_roles=("SYS_ADMIN",))
    token = _login(client, a_email, a_secret)
    r = client.get("/api/v1/notifications/deliveries", headers=_auth(token),
                   params={"limit": 501})
    assert r.status_code == 422, "limit is capped at 500"

    recipient, _, _ = _make_user(conn)
    actor, _, _ = _make_user(conn)
    first = _raise(conn, recipient, actor)
    second = _raise(conn, recipient, actor)
    r = client.get("/api/v1/notifications/deliveries", headers=_auth(token),
                   params={"kind": "MERGE_PERFORMED", "limit": 500})
    ids = [d["notification_id"] for d in r.json()["deliveries"]]
    assert ids.index(str(second.id)) < ids.index(str(first.id))


def test_the_ledger_is_behind_integration_manage(conn, client):
    """An analyst must not learn who is notified of what across every case
    from a table that is not case-scoped."""
    _, email, secret = _make_user(conn)
    token = _login(client, email, secret)
    r = client.get("/api/v1/notifications/deliveries", headers=_auth(token))
    assert r.status_code == 403, r.text


# ---------------------------------------------------------------------------
# a channel with no transport cannot be enabled
# ---------------------------------------------------------------------------

def test_jira_cannot_be_enabled_because_no_transport_exists(conn, monkeypatch):
    from noctornal_api.notifications import NotificationError, NotificationService

    user, _, _ = _make_user(conn)
    with pytest.raises(NotificationError, match="no transport"):
        NotificationService(conn).set_preference(user, "JIRA", enabled=True)
    assert NotificationService(conn).preferences(user)["JIRA"].enabled is False


def test_webhook_cannot_be_enabled_without_a_url(conn, monkeypatch):
    from noctornal_api.notifications import NotificationError, NotificationService

    monkeypatch.delenv("NOCTORNAL_WEBHOOK_URL", raising=False)
    user, _, _ = _make_user(conn)
    with pytest.raises(NotificationError, match="NOCTORNAL_WEBHOOK_URL"):
        NotificationService(conn).set_preference(user, "WEBHOOK", enabled=True)

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.example/noctornal")
    pref = NotificationService(conn).set_preference(user, "WEBHOOK", enabled=True)
    assert pref.enabled is True


def test_editing_an_already_enabled_channel_is_not_a_new_enable(conn, monkeypatch):
    """`_require_transport`'s docstring has always promised that "editing
    the other settings of an already-enabled channel is not the moment to
    discover the URL was unset". Until 2026-09-02 the call site tested
    `fields.get("enabled") is True` -- the PAYLOAD, not the transition --
    so a client PUTting the whole preference object back (which is what a
    settings pane does when you change a quiet window) was refused with
    "WEBHOOK cannot be enabled: NOCTORNAL_WEBHOOK_URL is not configured".
    Nobody was enabling anything, and the operator reading that message
    would go looking for a URL they had never needed to unset.

    The docstring made the promise and the code did not keep it. This test
    reads both sides: the claim is in `notifications._require_transport`
    and the comparison that honours it is in
    `NotificationService.set_preference`.
    """
    from noctornal_api.notifications import NotificationService

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.example/noctornal")
    user, _, _ = _make_user(conn)
    svc = NotificationService(conn)
    assert svc.set_preference(user, "WEBHOOK", enabled=True).enabled is True

    # The URL goes away underneath an already-enabled channel.
    monkeypatch.delenv("NOCTORNAL_WEBHOOK_URL", raising=False)
    pref = svc.set_preference(user, "WEBHOOK", enabled=True, min_priority=1,
                              digest=True)
    assert pref.enabled is True and pref.digest is True and pref.min_priority == 1


def test_disabling_an_unconfigured_channel_is_always_allowed(conn, monkeypatch):
    """Off is the safe direction; refusing it would strand a preference."""
    from noctornal_api.notifications import NotificationService

    monkeypatch.delenv("NOCTORNAL_WEBHOOK_URL", raising=False)
    user, _, _ = _make_user(conn)
    pref = NotificationService(conn).set_preference(user, "WEBHOOK", enabled=False,
                                                    min_priority=1)
    assert pref.enabled is False and pref.min_priority == 1


def test_the_refusal_reaches_the_client_as_a_400(conn, client):
    _, email, secret = _make_user(conn)
    token = _login(client, email, secret)
    r = client.put("/api/v1/notifications/preferences/JIRA", headers=_auth(token),
                   json={"enabled": True})
    assert r.status_code == 400, r.text
    assert "no transport" in r.json()["detail"]
