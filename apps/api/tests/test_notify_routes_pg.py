"""Email and webhooks on their integration routes (docs/00 decision 68, F8,
2026-09-24): SMTP dials through pinned_http.open_connection on the route
"smtp", the webhook posts through pinned_http.fetch_response on the route
"webhook" and follows no redirect, a missing or refusing route HOLDS
deliveries rather than failing them, and production refuses http:// at
boot and at send time.

Nothing here reaches a real relay or hook: open_connection and
fetch_response are replaced by recorders. **The email prefix is `nroute-`.**
Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import pytest

from outbound_support import DATABASE_URL, FakeRoute, make_user, route_for_factory, teardown

pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "nroute-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def _queued(conn, *, webhook=False, classification="GREEN"):
    from noctornal_api.notifications import NotificationService
    uid, _ = make_user(conn, PREFIX)
    if webhook:
        NotificationService(conn).set_preference(uid, "WEBHOOK", enabled=True, min_priority=1)
    n = NotificationService(conn).notify(
        recipient_id=uid, kind="EVIDENCE_INTEGRITY_ALARM", subject="OP-X: y",
        summary="y", body="y", classification=classification, priority=1)
    conn.execute("UPDATE notify.delivery SET deliver_after = now() + interval '1 day' "
                 "WHERE state = 'PENDING' AND notification_id <> %s", (n.id,))
    return n


def _row(conn, n, channel):
    return conn.execute("SELECT state, attempts, cause, detail FROM notify.delivery "
                        "WHERE notification_id = %s AND channel = %s",
                        (n.id, channel)).fetchone()


def test_smtp_opens_its_socket_through_the_smtp_route(conn, monkeypatch):
    from noctornal_api import pinned_http
    from noctornal_api.transports import dispatch_due

    monkeypatch.setenv("SMTP_HOST", "relay.example.org")
    monkeypatch.setenv("SMTP_PORT", "587")
    seen = []

    def refuse(route, host, port, **kw):
        seen.append((route.name, route.context, host, port, kw["deadline"].entered))
        raise pinned_http.Unreachable("unreachable: refused by the test")

    monkeypatch.setattr(pinned_http, "open_connection", refuse)
    route = FakeRoute("smtp", frozenset({("relay.example.org", 587)}))
    n = _queued(conn)
    counters = dispatch_due(conn, route_for=route_for_factory({"smtp": route}))
    assert seen and seen[0][0] == "smtp" and seen[0][2:] == ("relay.example.org", 587, True)
    delivery = conn.execute("SELECT id FROM notify.delivery WHERE notification_id = %s "
                            "AND channel = 'SMTP'", (n.id,)).fetchone()[0]
    assert seen[0][1] == f"delivery:{delivery}"
    state, attempts, cause, detail = _row(conn, n, "SMTP")
    assert (state, attempts, cause) == ("PENDING", 1, "TRANSPORT_ERROR")
    assert "SMTP relay unreachable" in detail
    assert counters["failed"] >= 1


def test_the_webhook_posts_through_fetch_response_and_follows_no_redirect(conn, monkeypatch):
    from noctornal_api import pinned_http
    from noctornal_api.transports import dispatch_due

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.example.org/T0/x")
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_SECRET", "hook-signing-secret")
    calls = []

    def fake_fetch(url, **kw):
        calls.append((url, kw))
        from outbound_support import fetched
        return fetched(204, b"")

    monkeypatch.setattr(pinned_http, "fetch_response", fake_fetch)
    route = FakeRoute("webhook", frozenset({("hooks.example.org", 443)}))
    n = _queued(conn, webhook=True)
    dispatch_due(conn, send_mail=lambda m: None,
                 route_for=route_for_factory({"webhook": route}))
    assert calls, "nothing was posted"
    url, kw = calls[0]
    assert url == "https://hooks.example.org/T0/x"
    assert kw["method"] == "POST" and kw["max_redirects"] == 0
    assert kw["route"].name == "webhook" and kw["route"].context.startswith("delivery:")
    assert kw["user_agent"] == "NocTORnal-webhook/1"
    assert "X-NocTORnal-Signature" in kw["headers"]
    assert "Authorization" not in kw["headers"]
    assert _row(conn, n, "WEBHOOK")[0] == "SENT"


def test_a_webhook_redirect_is_a_failure_that_names_the_host_only(conn, monkeypatch):
    from noctornal_api import pinned_http
    from noctornal_api.transports import dispatch_due

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.example.org/T0/x")

    def redirect(url, **kw):
        raise pinned_http.HttpStatusError(
            302, retry_after=None, excerpt="", location="https://evil.example/steal?t=1",
            location_host="evil.example", headers=None)

    monkeypatch.setattr(pinned_http, "fetch_response", redirect)
    route = FakeRoute("webhook", frozenset({("hooks.example.org", 443)}))
    n = _queued(conn, webhook=True)
    dispatch_due(conn, send_mail=lambda m: None,
                 route_for=route_for_factory({"webhook": route}))
    state, attempts, cause, detail = _row(conn, n, "WEBHOOK")
    assert state == "PENDING" and attempts == 1
    assert "redirect to evil.example" in detail and "steal" not in detail


def test_a_webhook_429_backs_off_by_retry_after(conn, monkeypatch):
    from noctornal_api import pinned_http
    from noctornal_api.transports import dispatch_due

    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.example.org/T0/x")

    def slow_down(url, **kw):
        raise pinned_http.HttpStatusError(429, retry_after=1800.0, excerpt="",
                                          location=None, location_host=None, headers=None)

    monkeypatch.setattr(pinned_http, "fetch_response", slow_down)
    route = FakeRoute("webhook", frozenset({("hooks.example.org", 443)}))
    n = _queued(conn, webhook=True)
    dispatch_due(conn, send_mail=lambda m: None,
                 route_for=route_for_factory({"webhook": route}))
    state, attempts, cause, _ = _row(conn, n, "WEBHOOK")
    assert (state, attempts, cause) == ("PENDING", 1, "RATE_LIMITED")
    wait = conn.execute("SELECT extract(epoch FROM deliver_after - last_attempt_at) "
                        "FROM notify.delivery WHERE notification_id = %s "
                        "AND channel = 'WEBHOOK'", (n.id,)).fetchone()[0]
    assert 1790 <= float(wait) <= 1810


def test_a_missing_route_holds_email_rather_than_failing_it(conn, monkeypatch):
    from noctornal_api import pinned_http
    from noctornal_api.transports import dispatch_due

    monkeypatch.setenv("SMTP_HOST", "relay.example.org")
    dialled = []
    monkeypatch.setattr(pinned_http, "open_connection",
                        lambda *a, **k: dialled.append(a))
    n = _queued(conn)
    counters = dispatch_due(conn, route_for=route_for_factory({}))
    assert not dialled
    assert _row(conn, n, "SMTP")[:2] == ("PENDING", 0)
    assert counters["held"] >= 1 and counters["failed"] == 0


def test_a_route_that_does_not_allow_the_endpoint_holds_it(conn, monkeypatch):
    from noctornal_api.transports import SMTP, dispatch_due, route_state

    monkeypatch.setenv("SMTP_HOST", "relay.example.org")
    monkeypatch.setenv("SMTP_PORT", "587")
    route = FakeRoute("smtp", frozenset({("other.example.org", 587)}))
    rf = route_for_factory({"smtp": route})
    state = route_state(SMTP, conn, route_for=rf)
    assert not state.ok and "does not allow relay.example.org:587" in state.why
    n = _queued(conn)
    dispatch_due(conn, route_for=rf)
    assert _row(conn, n, "SMTP")[:2] == ("PENDING", 0)


def test_a_development_route_is_built_from_the_declared_endpoint(conn, monkeypatch):
    """No proxy and no route provider: route_for gives the DIRECT route of
    the declared relay (docs/20 section 6.2), which permits it."""
    from noctornal_api.transports import SMTP, route_state

    monkeypatch.setenv("SMTP_HOST", "localhost")
    monkeypatch.setenv("SMTP_PORT", "1025")
    monkeypatch.delenv("NOCTORNAL_EGRESS_PROXY_URL", raising=False)
    state = route_state(SMTP, conn)
    assert state.ok and not state.proxied


def test_production_refuses_an_http_webhook_and_the_http_flags():
    from noctornal_api.config import verify_environment

    env = {"NOCTORNAL_ENV": "production", "NOCTORNAL_WEBHOOK_URL": "http://hooks.example/x",
           "NOCTORNAL_WEBHOOK_ALLOW_HTTP": "1", "NOCTORNAL_JIRA_ALLOW_HTTP": "1",
           "NOCTORNAL_JIRA_CEILING": "RED"}
    problems = " ".join(verify_environment(env))
    assert "NOCTORNAL_WEBHOOK_URL is not an https address" in problems
    assert "NOCTORNAL_WEBHOOK_ALLOW_HTTP is set" in problems
    assert "NOCTORNAL_JIRA_ALLOW_HTTP is set" in problems
    assert "NOCTORNAL_JIRA_CEILING is not CLEAR, GREEN or AMBER" in problems
    assert "http://hooks.example/x" not in problems
    assert not any("WEBHOOK" in p for p in verify_environment(
        {"NOCTORNAL_WEBHOOK_URL": "http://hooks.example/x"}))


def test_the_drain_refuses_http_in_production_even_with_the_flag(conn, monkeypatch):
    """The cron sends, and the cron never ran
    verify_environment."""
    from noctornal_api import pinned_http
    from noctornal_api.transports import TransportError, send_webhook

    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_ALLOW_HTTP", "1")
    posted = []
    monkeypatch.setattr(pinned_http, "fetch_response", lambda *a, **k: posted.append(a))
    with pytest.raises(TransportError, match="not https"):
        send_webhook("http://hooks.example.org/x", {"a": 1}, None,
                     route=FakeRoute("webhook", frozenset({("hooks.example.org", 80)})))
    assert not posted
    monkeypatch.delenv("NOCTORNAL_ENV")
    send_webhook("http://hooks.example.org/x", {"a": 1}, None,
                 route=FakeRoute("webhook", frozenset({("hooks.example.org", 80)})))
    assert posted


def test_configured_integrations_names_smtp_and_webhook():
    from noctornal_api.transports import configured_integrations
    assert configured_integrations({}) == []
    assert configured_integrations({"SMTP_HOST": "relay", "NOCTORNAL_WEBHOOK_URL": "x"}
                                   ) == ["smtp", "webhook"]


def test_smtp_configured_fails_on_a_route_that_does_not_allow_smtp_host(conn, monkeypatch):
    from noctornal_api import readiness, transports

    monkeypatch.setenv("SMTP_HOST", "relay.example.org")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.delenv("SMTP_ALLOW_PLAINTEXT", raising=False)
    route = FakeRoute("smtp", frozenset({("other.example.org", 587)}))
    monkeypatch.setattr(transports, "_default_route_for",
                        lambda: route_for_factory({"smtp": route}))
    check = readiness.check("smtp_configured", conn)
    assert not check.ok and "email is held" in check.evidence
    assert "smtp route in Administration, Egress" in check.action
    ok = FakeRoute("smtp", frozenset({("relay.example.org", 587)}), proxied=True)
    monkeypatch.setattr(transports, "_default_route_for",
                        lambda: route_for_factory({"smtp": ok}))
    check = readiness.check("smtp_configured", conn)
    assert check.ok and "through egress route smtp, proxied" in check.evidence
