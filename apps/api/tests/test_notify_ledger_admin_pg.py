"""The delivery ledger as an administrator surface (F8, 2026-09-24):
causes, exposure, paging, the per-channel summary, retry and the manual
drain, the webhook address withheld, and the audit of every channel
switched on or off.

**The email prefix is `nled-` and must stay unique.** Env-gated on
DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from outbound_support import (
    DATABASE_URL,
    assign,
    client as make_client,
    make_case,
    make_user,
    session,
    stale_session,
    teardown,
)

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "nled-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


@pytest.fixture
def client():
    return make_client()


def _notify(conn, recipient, *, actor=None, case_id=None, kind="EVIDENCE_INTEGRITY_ALARM",
            classification="AMBER", priority=1, event_id=None):
    from noctornal_api.notifications import NotificationService
    n = NotificationService(conn).notify(
        recipient_id=recipient, actor_id=actor, case_id=case_id, kind=kind,
        subject="OP-X: something happened", summary="Something happened.",
        body="detail", classification=classification, priority=priority,
        event_id=event_id)
    assert n is not None
    return n


def _row(conn, notification_id, channel):
    return conn.execute(
        """SELECT state, cause, exposure, sent_to, detail, attempts, redacted
             FROM notify.delivery WHERE notification_id = %s AND channel = %s""",
        (notification_id, channel)).fetchone()


def _admin(conn):
    uid, email = make_user(conn, PREFIX, clearance="RED", global_roles=("SYS_ADMIN",))
    return uid, email


def _mine_only(conn, n_id):
    """Every other due row pushed to later, so a drain reaches ours at once
    whatever a killed run left behind."""
    conn.execute("UPDATE notify.delivery SET deliver_after = now() + interval '1 day' "
                 "WHERE state = 'PENDING' AND notification_id <> %s", (n_id,))


# --- causes and exposure -------------------------------------------------------

def test_every_suppression_carries_a_cause(conn):
    from noctornal_api.notifications import NotificationService
    from noctornal_api.transports import revoke_undeliverable

    owner, _ = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    alice, _ = make_user(conn, PREFIX)
    assign(conn, case_id, alice)
    NotificationService(conn).set_preference(alice, "SMTP", enabled=False)
    n = _notify(conn, alice, case_id=case_id, priority=3, kind="PROPOSAL_QUEUED")
    assert _row(conn, n.id, "SMTP")[:2] == ("SUPPRESSED", "RECIPIENT_DISABLED")
    assert _row(conn, n.id, "WEBHOOK")[:2] == ("SUPPRESSED", "RECIPIENT_DISABLED")

    NotificationService(conn).set_preference(alice, "SMTP", enabled=True, min_priority=1)
    low = _notify(conn, alice, case_id=case_id, priority=2, kind="PROPOSAL_QUEUED")
    assert _row(conn, low.id, "SMTP")[:2] == ("SUPPRESSED", "BELOW_THRESHOLD")

    urgent = _notify(conn, alice, case_id=case_id, priority=1)
    assert _row(conn, urgent.id, "SMTP")[0] == "PENDING"
    conn.execute("DELETE FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
                 (case_id, alice))
    revoke_undeliverable(conn)
    assert _row(conn, urgent.id, "SMTP")[:2] == ("SUPPRESSED", "REVOKED")


def test_a_refused_stub_records_stub_exposure(conn, monkeypatch):
    from noctornal_api.transports import dispatch_due

    monkeypatch.setenv("NOCTORNAL_SMTP_CEILING", "GREEN")
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_CEILING", "GREEN")
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.example/T0/secret")
    from noctornal_api.notifications import NotificationService
    alice, _ = make_user(conn, PREFIX)
    NotificationService(conn).set_preference(alice, "WEBHOOK", enabled=True, min_priority=1)
    n = _notify(conn, alice, classification="AMBER")
    _mine_only(conn, n.id)
    sent, hooks = [], []
    dispatch_due(conn, send_mail=lambda m: sent.append(m),
                 post_webhook=lambda *a: hooks.append(a))
    smtp = _row(conn, n.id, "SMTP")
    assert smtp[0] == "REFUSED" and smtp[1] == "EGRESS_REFUSED" and smtp[2] == "STUB"
    hook = _row(conn, n.id, "WEBHOOK")
    assert hook[0] == "REFUSED" and hook[1] == "EGRESS_REFUSED" and hook[2] == "STUB"
    assert "secret" not in hook[3]


def test_a_full_send_records_summary_exposure(conn):
    from noctornal_api.transports import dispatch_due

    alice, _ = make_user(conn, PREFIX)
    n = _notify(conn, alice, classification="GREEN")
    _mine_only(conn, n.id)
    dispatch_due(conn, send_mail=lambda m: None)
    state, cause, exposure = _row(conn, n.id, "SMTP")[:3]
    assert (state, cause, exposure) == ("SENT", None, "SUMMARY")


def test_in_app_rows_never_record_an_exposure(conn):
    import psycopg

    alice, _ = make_user(conn, PREFIX)
    n = _notify(conn, alice)
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE notify.delivery SET exposure = 'SUMMARY' "
                     "WHERE notification_id = %s AND channel = 'IN_APP'", (n.id,))


def test_a_decided_row_without_a_cause_is_refused_by_the_database(conn):
    import psycopg

    alice, _ = make_user(conn, PREFIX)
    n = _notify(conn, alice)
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE notify.delivery SET state = 'FAILED', cause = NULL "
                     "WHERE notification_id = %s AND channel = 'SMTP'", (n.id,))


# --- the ledger route ------------------------------------------------------------

def _ledger(client, headers, **params):
    r = client.get("/api/v1/notifications/deliveries", headers=headers, params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_outbound_hides_in_app_rows_and_filters_compose(conn, client):
    admin, email = _admin(conn)
    alice, _ = make_user(conn, PREFIX)
    n = _notify(conn, alice)
    headers = session(conn, email)
    rows = _ledger(client, headers, recipient_id=str(alice), outbound="true")["deliveries"]
    assert {r["channel"] for r in rows} == {"SMTP", "WEBHOOK", "JIRA"}
    rows = _ledger(client, headers, recipient_id=str(alice), channel="IN_APP")["deliveries"]
    assert [r["channel"] for r in rows] == ["IN_APP"] and rows[0]["left"] is None
    rows = _ledger(client, headers, recipient_id=str(alice), outbound="true",
                   outcome="SUPPRESSED", cause="RECIPIENT_DISABLED")["deliveries"]
    assert {r["channel"] for r in rows} == {"WEBHOOK", "JIRA"}
    assert all(r["cause_text"] == "The recipient turned this channel off." for r in rows)
    assert all(r["notification_id"] == str(n.id) for r in rows)


def test_refused_only_leaves_routine_routing_choices_out(conn, client):
    admin, email = _admin(conn)
    alice, _ = make_user(conn, PREFIX)
    made = {}
    for cause in ("KIND_NOT_ROUTED", "CASE_NOT_ROUTED", "DESTINATION_OFF", "CASELESS",
                  "WITHDRAWN", "REVOKED"):
        n = _notify(conn, alice)
        conn.execute("UPDATE notify.delivery SET state = 'SUPPRESSED', cause = %s "
                     "WHERE notification_id = %s AND channel = 'JIRA'", (cause, n.id))
        made[cause] = str(n.id)
    rows = _ledger(client, session(conn, email), recipient_id=str(alice),
                   channel="JIRA", refused_only="true")["deliveries"]
    got = {r["cause"] for r in rows}
    assert got == {"WITHDRAWN", "REVOKED"}, got


def test_the_cursor_pages_without_gaps_or_repeats(conn, client):
    admin, email = _admin(conn)
    alice, _ = make_user(conn, PREFIX)
    with conn.transaction():   # one transaction: every queued_at is the same
        for _ in range(84):
            _notify(conn, alice)
    headers = session(conn, email)
    seen, cursor, pages = [], None, 0
    while True:
        params = {"recipient_id": str(alice), "outbound": "true", "limit": 100}
        if cursor:
            params["before"] = cursor
        body = _ledger(client, headers, **params)
        seen += [r["id"] for r in body["deliveries"]]
        pages += 1
        cursor = body["next"]
        if not cursor:
            break
    assert pages == 3
    assert len(seen) == len(set(seen)) == 84 * 3


def test_a_malformed_cursor_is_a_400(conn, client):
    admin, email = _admin(conn)
    r = client.get("/api/v1/notifications/deliveries", headers=session(conn, email),
                   params={"before": "not-a-cursor"})
    assert r.status_code == 400, r.text


def test_cause_text_for_an_egress_refusal_never_names_a_level_or_compartments(conn, client):
    admin, email = _admin(conn)
    alice, _ = make_user(conn, PREFIX, clearance="RED")
    n = _notify(conn, alice, classification="RED")
    conn.execute("UPDATE notify.delivery SET state = 'REFUSED', cause = 'EGRESS_REFUSED', "
                 "detail = 'above_platform_floor', exposure = 'STUB', redacted = true, "
                 "attempts = 1, last_attempt_at = now() "
                 "WHERE notification_id = %s AND channel = 'SMTP'", (n.id,))
    rows = _ledger(client, session(conn, email), recipient_id=str(alice), channel="SMTP")
    text = rows["deliveries"][0]["cause_text"]
    assert "RED" not in text and "AMBER" not in text and "TLP" not in text
    assert "compartment" not in text.lower() or "Compartmented material" not in text
    assert "stub" in text


# --- requeue --------------------------------------------------------------------------

def _failed(conn, recipient, **kw):
    n = _notify(conn, recipient, **kw)
    conn.execute("UPDATE notify.delivery SET state = 'FAILED', cause = 'GAVE_UP', "
                 "attempts = 5, last_attempt_at = now(), detail = 'boom' "
                 "WHERE notification_id = %s AND channel = 'SMTP'", (n.id,))
    return n, conn.execute("SELECT id FROM notify.delivery WHERE notification_id = %s "
                           "AND channel = 'SMTP'", (n.id,)).fetchone()[0]


def test_a_failed_delivery_can_be_requeued_and_the_drain_regates_it(conn, client):
    from noctornal_api.transports import dispatch_due

    admin, email = _admin(conn)
    owner, _ = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    alice, _ = make_user(conn, PREFIX)
    assign(conn, case_id, alice)
    n, delivery = _failed(conn, alice, case_id=case_id)
    r = client.post(f"/api/v1/notifications/deliveries/{delivery}/requeue",
                    headers=session(conn, email))
    assert r.status_code == 200, r.text
    assert r.json()["outcome"] == "PENDING" and r.json()["attempts"] == 0
    assert r.json()["cause"] == "REQUEUED"
    conn.execute("DELETE FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
                 (case_id, alice))
    sent = []
    dispatch_due(conn, send_mail=lambda m: sent.append(m))
    assert _row(conn, n.id, "SMTP")[:2] == ("SUPPRESSED", "REVOKED")
    assert not sent


def test_a_refused_or_suppressed_delivery_cannot_be_requeued(conn, client):
    admin, email = _admin(conn)
    alice, _ = make_user(conn, PREFIX)
    n = _notify(conn, alice)
    conn.execute("UPDATE notify.delivery SET state = 'REFUSED', cause = 'EGRESS_REFUSED', "
                 "detail = 'above_destination_ceiling' "
                 "WHERE notification_id = %s AND channel = 'SMTP'", (n.id,))
    ids = {c: conn.execute("SELECT id FROM notify.delivery WHERE notification_id = %s "
                           "AND channel = %s", (n.id, c)).fetchone()[0]
           for c in ("SMTP", "WEBHOOK")}
    headers = session(conn, email)
    r = client.post(f"/api/v1/notifications/deliveries/{ids['SMTP']}/requeue",
                    headers=headers)
    assert r.status_code == 409 and "egress gate" in r.json()["detail"]
    r = client.post(f"/api/v1/notifications/deliveries/{ids['WEBHOOK']}/requeue",
                    headers=headers)
    assert r.status_code == 409 and "Nothing was attempted" in r.json()["detail"]


def test_requeue_is_audited_with_the_prior_state(conn, client):
    admin, email = _admin(conn)
    alice, _ = make_user(conn, PREFIX)
    _n, delivery = _failed(conn, alice)
    client.post(f"/api/v1/notifications/deliveries/{delivery}/requeue",
                headers=session(conn, email))
    detail = conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'NOTIFY_DELIVERY_REQUEUED' "
        "AND object_id = %s", (delivery,)).fetchone()[0]
    assert detail == {"channel": "SMTP", "from_state": "FAILED", "from_attempts": 5,
                      "from_cause": "GAVE_UP"}


def test_bulk_requeue_is_bounded_to_one_channel_and_thirty_days(conn, client):
    admin, email = _admin(conn)
    alice, _ = make_user(conn, PREFIX)
    _n, delivery = _failed(conn, alice)
    headers = session(conn, email)
    old = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat()
    r = client.post("/api/v1/notifications/deliveries/requeue", headers=headers,
                    json={"channel": "SMTP", "since": old})
    assert r.status_code == 400
    r = client.post("/api/v1/notifications/deliveries/requeue", headers=headers,
                    json={"channel": "IN_APP", "since": datetime.now(timezone.utc).isoformat()})
    assert r.status_code == 400
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    r = client.post("/api/v1/notifications/deliveries/requeue", headers=headers,
                    json={"channel": "WEBHOOK", "since": since})
    assert r.status_code == 200
    assert conn.execute("SELECT state FROM notify.delivery WHERE id = %s",
                        (delivery,)).fetchone()[0] == "FAILED"
    r = client.post("/api/v1/notifications/deliveries/requeue", headers=headers,
                    json={"channel": "SMTP", "since": since})
    assert r.json()["requeued"] >= 1
    assert conn.execute("SELECT state FROM notify.delivery WHERE id = %s",
                        (delivery,)).fetchone()[0] == "PENDING"


def test_requeue_needs_integration_manage_and_a_fresh_step_up(conn, client):
    admin, email = _admin(conn)
    alice, alice_email = make_user(conn, PREFIX)
    _n, delivery = _failed(conn, alice)
    r = client.post(f"/api/v1/notifications/deliveries/{delivery}/requeue",
                    headers=session(conn, alice_email))
    assert r.status_code == 403
    r = client.post(f"/api/v1/notifications/deliveries/{delivery}/requeue",
                    headers=stale_session(conn, email))
    assert r.status_code == 403 and "re-authentication" in r.json()["detail"]


# --- summary, overview, drain -----------------------------------------------------

def test_the_summary_counts_the_window_and_excludes_in_app(conn, client):
    admin, email = _admin(conn)
    r = client.get("/api/v1/notifications/deliveries/summary", headers=session(conn, email),
                   params={"hours": 24})
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body["channels"]) == {"SMTP", "WEBHOOK", "JIRA"}
    assert body["outbox"]["overdue_after_minutes"] == 30
    for ch in body["channels"].values():
        assert set(ch["route"]) == {"name", "ok", "proxied", "why"}


def test_the_webhook_address_is_stored_withheld(conn, monkeypatch):
    from noctornal_api.notifications import NotificationService
    from noctornal_api.transports import dispatch_due

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL",
                       "https://user:pw@hooks.example.org:8443/T01/B02/abcSECRET")
    alice, _ = make_user(conn, PREFIX)
    NotificationService(conn).set_preference(alice, "WEBHOOK", enabled=True, min_priority=1)
    n = _notify(conn, alice, classification="GREEN")
    _mine_only(conn, n.id)
    dispatch_due(conn, send_mail=lambda m: None, post_webhook=lambda *a: None)
    sent_to = _row(conn, n.id, "WEBHOOK")[3]
    assert sent_to.startswith("https://hooks.example.org:8443/[path withheld: ")
    assert "SECRET" not in sent_to and "user" not in sent_to and "pw" not in sent_to


def test_the_integrations_overview_carries_no_secret(conn, client, monkeypatch):
    monkeypatch.setenv("SMTP_PASSWORD", "smtp-password-VALUE-1234")
    monkeypatch.setenv("SMTP_USERNAME", "relay-user")
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SECRET", "webhook-secret-VALUE-9876")
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.example.org/T01/pathSECRET")
    admin, email = _admin(conn)
    r = client.get("/api/v1/integrations", headers=session(conn, email))
    assert r.status_code == 200, r.text
    text = r.text
    for secret in ("smtp-password-VALUE-1234", "webhook-secret-VALUE-9876", "pathSECRET",
                   "T01"):
        assert secret not in text, secret
    assert r.json()["webhook"]["signed"] is True
    assert r.json()["smtp"]["auth"] is True


def test_the_overview_and_the_register_agree(conn, client):
    from noctornal_api import readiness
    admin, email = _admin(conn)
    body = client.get("/api/v1/integrations", headers=session(conn, email)).json()
    assert body["smtp"]["check"] == readiness.check("smtp_configured", conn).as_dict()
    assert body["drain"]["check"] == readiness.check("notify_outbox_draining",
                                                     conn).as_dict()


def test_a_manual_drain_is_audited_and_the_cron_drain_is_not(conn, client):
    import importlib.util
    import pathlib

    admin, email = _admin(conn)
    before = conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                          "'NOTIFY_DRAIN_RUN'").fetchone()[0]
    r = client.post("/api/v1/notifications/dispatch", headers=session(conn, email))
    assert r.status_code == 200, r.text
    for key in ("held", "deferred", "withdrawn"):
        assert key in r.json()
    row = conn.execute("SELECT actor_id, detail FROM audit.event WHERE action = "
                       "'NOTIFY_DRAIN_RUN' ORDER BY occurred_at DESC LIMIT 1").fetchone()
    assert row[0] == admin and "sent" in row[1]
    script = pathlib.Path(__file__).resolve().parents[3] / "scripts" / "notify_drain.py"
    spec = importlib.util.spec_from_file_location("notify_drain_ledger", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.main()
    after = conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                         "'NOTIFY_DRAIN_RUN'").fetchone()[0]
    assert after == before + 1


def test_switching_a_channel_on_or_off_is_audited(conn, monkeypatch):
    from noctornal_api import jira
    from noctornal_api.notifications import NotificationService

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.example.org/x")
    monkeypatch.setattr(jira, "routing", lambda c: jira.Routing(uuid4(), "ACTIVE",
                                                                frozenset()))
    alice, _ = make_user(conn, PREFIX)
    svc = NotificationService(conn)
    for channel, on_first in (("SMTP", False), ("WEBHOOK", True), ("JIRA", True)):
        svc.set_preference(alice, channel, enabled=on_first)
        svc.set_preference(alice, channel, enabled=not on_first)
    rows = conn.execute(
        "SELECT action, detail FROM audit.event WHERE object_id = %s AND action IN "
        "('NOTIFY_CHANNEL_ENABLED', 'NOTIFY_CHANNEL_DISABLED') ORDER BY seq",
        (alice,)).fetchall()
    assert [(a, d["channel"], d["to"]) for a, d in rows] == [
        ("NOTIFY_CHANNEL_DISABLED", "SMTP", False),
        ("NOTIFY_CHANNEL_ENABLED", "SMTP", True),
        ("NOTIFY_CHANNEL_ENABLED", "WEBHOOK", True),
        ("NOTIFY_CHANNEL_DISABLED", "WEBHOOK", False),
        ("NOTIFY_CHANNEL_ENABLED", "JIRA", True),
        ("NOTIFY_CHANNEL_DISABLED", "JIRA", False),
    ]


def test_one_approval_request_shares_one_event_id_across_its_recipients(conn):
    from noctornal_api import notify_events

    owner, _ = make_user(conn, PREFIX)
    case_id = make_case(conn, owner, PREFIX)
    a, _ = make_user(conn, PREFIX)
    b, _ = make_user(conn, PREFIX)
    for u in (a, b):
        assign(conn, case_id, u, role="CASE_OWNER")
    sent = notify_events.approval_requested(
        conn, case_id=case_id, request_id=uuid4(), operation="graph.merge",
        permission="graph.merge", justification="two accounts, one person",
        actor_id=owner)
    assert sent == 2
    events = conn.execute("SELECT DISTINCT event_id FROM notify.notification "
                          "WHERE case_id = %s AND kind = 'APPROVAL_REQUESTED'",
                          (case_id,)).fetchall()
    assert len(events) == 1 and events[0][0] is not None
    # Two separate notifications are two events.
    x = notify_events.approval_requested(
        conn, case_id=case_id, request_id=uuid4(), operation="graph.merge",
        permission="graph.merge", justification="another", actor_id=owner)
    assert x == 2
    assert conn.execute("SELECT count(DISTINCT event_id) FROM notify.notification "
                        "WHERE case_id = %s", (case_id,)).fetchone()[0] == 2


def test_admin_access_reports_integration_manage(conn, client):
    admin, email = _admin(conn)
    _u, analyst_email = make_user(conn, PREFIX)
    assert client.get("/api/v1/admin/access", headers=session(conn, email)
                      ).json()["integration_manage"] is True
    assert client.get("/api/v1/admin/access", headers=session(conn, analyst_email)
                      ).json()["integration_manage"] is False


def test_the_preferences_say_why_a_channel_cannot_deliver(conn, client, monkeypatch):
    monkeypatch.delenv("NOCTORNAL_WEBHOOK_URL", raising=False)
    _u, email = make_user(conn, PREFIX)
    body = client.get("/api/v1/notifications/preferences", headers=session(conn, email)).json()
    assert body["channels"]["WEBHOOK"]["available"] is False
    assert "NOCTORNAL_WEBHOOK_URL" in body["channels"]["WEBHOOK"]["why"]
    assert set(body["channels"]["JIRA"]) >= {"available", "why", "project_key", "host",
                                             "kinds", "case_blocks_apply"}


@pytest.mark.skipif(not os.environ.get("SMTP_HOST"), reason="no SMTP_HOST in this env")
def test_the_smtp_card_names_the_route(conn, client):
    admin, email = _admin(conn)
    body = client.get("/api/v1/integrations", headers=session(conn, email)).json()
    assert body["smtp"]["route"]["name"] == "smtp"
