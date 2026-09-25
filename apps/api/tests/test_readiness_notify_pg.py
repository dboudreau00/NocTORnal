"""The two readiness rows for notifications (F8 F and F7, 2026-09-24):
notify_outbox_draining and jira_destination. Neither is blocking; both
are settled under Administration, Integrations.

**The email prefix is `nrdy-`.** Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import pytest

from outbound_support import DATABASE_URL, FakeRoute, make_user, route_for_factory, teardown

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "nrdy-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    # Rows other suites left due must not decide this row's verdict.
    c.execute("UPDATE notify.delivery SET deliver_after = now() + interval '30 days' "
              "WHERE state = 'PENDING'")
    yield c
    teardown(c, PREFIX)
    c.close()


def _smtp_route(monkeypatch, *, ok=True):
    from noctornal_api import transports
    monkeypatch.setenv("SMTP_HOST", "relay.example.org")
    monkeypatch.setenv("SMTP_PORT", "587")
    route = FakeRoute("smtp", frozenset({("relay.example.org", 587)} if ok else set()))
    monkeypatch.setattr(transports, "_default_route_for",
                        lambda: route_for_factory({"smtp": route}))


def _queued(conn, channel="SMTP"):
    from noctornal_api.notifications import NotificationService
    uid, _ = make_user(conn, PREFIX)
    n = NotificationService(conn).notify(
        recipient_id=uid, kind="EVIDENCE_INTEGRITY_ALARM", subject="OP-X: y",
        summary="y", body="y", classification="GREEN", priority=1)
    return n


def test_notify_outbox_draining_passes_with_nothing_overdue(conn, monkeypatch):
    from noctornal_api import readiness
    _smtp_route(monkeypatch)
    check = readiness.check("notify_outbox_draining", conn)
    assert check.ok and "Nothing has waited more than 30 minutes" in check.evidence


def test_it_fails_with_an_smtp_row_due_31_minutes_ago(conn, monkeypatch):
    from noctornal_api import readiness
    _smtp_route(monkeypatch)
    n = _queued(conn)
    conn.execute("UPDATE notify.delivery SET deliver_after = now() - interval '31 minutes' "
                 "WHERE notification_id = %s AND channel = 'SMTP'", (n.id,))
    check = readiness.check("notify_outbox_draining", conn)
    assert not check.ok and "overdue" in check.evidence
    assert "scripts/notify_drain.py" in check.action
    assert check.ui_target == "admin/integrations" and not check.blocking


def test_it_ignores_jira_rows_and_held_channels(conn, monkeypatch):
    from noctornal_api import readiness
    _smtp_route(monkeypatch, ok=False)
    n = _queued(conn)
    conn.execute("UPDATE notify.delivery SET deliver_after = now() - interval '2 hours', "
                 "state = 'PENDING' WHERE notification_id = %s AND channel IN ('SMTP', 'JIRA')",
                 (n.id,))
    check = readiness.check("notify_outbox_draining", conn)
    assert check.ok, check.evidence
    assert "Email held:" in check.evidence


def test_jira_destination_verdicts(conn, monkeypatch):
    from noctornal_api import jira, readiness
    from noctornal_api.security import envelope
    check = readiness.check("jira_destination", conn)
    assert check.ok and "No Jira destination is configured" in check.evidence
    admin, _ = make_user(conn, PREFIX, global_roles=("SYS_ADMIN",))
    blob, kid = envelope.encrypt("credential-value-x")
    dest = conn.execute(
        """INSERT INTO notify.jira_destination (label, base_url, host, port, auth_kind,
               credential_ciphertext, credential_key_id, credential_set_by, project_key,
               created_by, updated_by)
           VALUES ('J', 'https://jira.example.org', 'jira.example.org', 443, 'DC_PAT',
                   %s, %s, %s, 'SOC', %s, %s) RETURNING id""",
        (blob, kid, admin, admin, admin)).fetchone()[0]
    check = readiness.check("jira_destination", conn)
    assert check.ok and "drafted, not active" in check.caveat
    conn.execute("""UPDATE notify.jira_destination SET state = 'ACTIVE', flavour =
                        'DATA_CENTER', issue_type_id = '1', tested_at = now(),
                        activated_at = now(), health = 'OK' WHERE id = %s""", (dest,))
    good = FakeRoute("jira", frozenset({("jira.example.org", 443)}), proxied=True)
    monkeypatch.setattr(jira, "_default_route_for", lambda: route_for_factory({}))
    check = readiness.check("jira_destination", conn)
    assert not check.ok and "jira route in Administration, Egress" in check.action
    monkeypatch.setattr(jira, "_default_route_for",
                        lambda: route_for_factory({"jira": good}))
    check = readiness.check("jira_destination", conn)
    assert check.ok and "through egress route jira, proxied" in check.evidence
    conn.execute("UPDATE notify.jira_destination SET health = 'BROKEN', health_detail = "
                 "'Jira refused the credential (HTTP 401)', health_changed_at = now() "
                 "WHERE id = %s", (dest,))
    check = readiness.check("jira_destination", conn)
    assert not check.ok and "HTTP 401" in check.evidence and "run Test" in check.action
    conn.execute("UPDATE notify.jira_destination SET health = 'UNTESTED' WHERE id = %s",
                 (dest,))
    check = readiness.check("jira_destination", conn)
    assert check.ok and "credential replaced, not yet tested" in check.caveat
    assert check.ui_target == "admin/integrations" and not check.blocking


def test_a_draining_backlog_is_not_reported_as_a_stopped_drain(conn, monkeypatch):
    from noctornal_api import jira, readiness
    from noctornal_api.security import envelope
    admin, _ = make_user(conn, PREFIX, global_roles=("SYS_ADMIN",))
    blob, kid = envelope.encrypt("credential-value-x")
    conn.execute(
        """INSERT INTO notify.jira_destination (label, base_url, host, port, flavour,
               auth_kind, credential_ciphertext, credential_key_id, credential_set_by,
               project_key, issue_type_id, state, health, tested_at, activated_at,
               created_by, updated_by)
           VALUES ('J', 'https://jira.example.org', 'jira.example.org', 443, 'DATA_CENTER',
                   'DC_PAT', %s, %s, %s, 'SOC', '1', 'ACTIVE', 'OK', now(), now(), %s, %s)""",
        (blob, kid, admin, admin, admin))
    good = FakeRoute("jira", frozenset({("jira.example.org", 443)}))
    monkeypatch.setattr(jira, "_default_route_for", lambda: route_for_factory({"jira": good}))
    n = _queued(conn)
    m = _queued(conn)
    conn.execute("UPDATE notify.delivery SET state = 'PENDING', cause = NULL, "
                 "deliver_after = now() - interval '2 hours' "
                 "WHERE notification_id IN (%s, %s) AND channel = 'JIRA'", (n.id, m.id))
    check = readiness.check("jira_destination", conn)
    assert not check.ok and "no drain is reaching them" in check.evidence
    conn.execute("UPDATE notify.delivery SET last_attempt_at = now() - interval '5 minutes' "
                 "WHERE notification_id = %s AND channel = 'JIRA'", (m.id,))
    check = readiness.check("jira_destination", conn)
    assert check.ok and "draining" in check.caveat
