"""Upgrading an Alpha 6 deployment to the egress proxy (S2, 2026-09-24;
release/egress-upgrade/README.md).

An Alpha 6 deployment has feeds, an SMTP relay and a webhook, and no route
at all. adopt proposes the passive default and the two routes from its own
settings, creates nothing until an authenticated administrator confirms,
and afterwards a feed run leaves through the passive route and a delivery
through smtp, both via the real proxy. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
import socket
import threading
from pathlib import Path

import pytest

import egress_support as es
from noctornal_api import egress, pinned_http
from noctornal_api.egress_admin import EgressAdminService
from noctornal_api.egress_policy import Rule

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "egu-"
ROOT = Path(__file__).resolve().parents[3]


def _setup_module():
    spec = importlib.util.spec_from_file_location("egress_setup_u", ROOT / "scripts" /
                                                  "egress_setup.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect
    es.clear_egress_env(monkeypatch)
    for key, value in es.keys().items():
        monkeypatch.setenv(key, value)
    c = connect()
    # `preserved` brings back whatever live configuration this database had
    # (a developer's, the demo's) once the suite has made it look like Alpha
    # 6 by retiring it (2026-09-25).
    with es.preserved(c), es.collection_standin(c):
        admin = es.user(c, "SYS_ADMIN", prefix=PREFIX)
        # An Alpha 6 deployment: no passive default and no route.
        c.execute("""UPDATE collect.egress_profile SET is_passive_default = false,
                       is_active = false, retired_at = now(), retired_by = %s,
                       retire_reason = 'upgrade suite start'
                     WHERE retired_at IS NULL""", (admin,))
        c.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                       retired_at = now(), retired_by = %s, retire_reason = 'upgrade suite'
                     WHERE retired_at IS NULL""", (admin,))
        c.admin = admin
        yield c
        c.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                       retired_at = now(), retired_by = %s, retire_reason = 'upgrade suite'
                     WHERE retired_at IS NULL""", (admin,))
        # What adopt made here goes, not just retires: a profile's name is
        # unique for life, and a retired row per run would pile up.
        c.execute("ALTER TABLE collect.egress_profile DISABLE TRIGGER egress_profile_reach")
        c.execute("DELETE FROM collect.egress_profile WHERE created_by = %s", (admin,))
        c.execute("ALTER TABLE collect.egress_profile ENABLE TRIGGER egress_profile_reach")
        c.execute("""DELETE FROM collect.egress_destination WHERE route_id IN
                       (SELECT id FROM collect.egress_integration_route WHERE created_by = %s)""",
                  (admin,))
        c.execute("DELETE FROM collect.egress_integration_route WHERE created_by = %s", (admin,))
        es.teardown(c, PREFIX)
    c.close()


@pytest.fixture
def alpha6(conn, monkeypatch):
    monkeypatch.setenv("SMTP_HOST", "relay.unit.test")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("NOCTORNAL_WEBHOOK_URL", "https://hooks.unit.test/notify")
    es.source(conn, PREFIX, base_url="http://plain-feed.example/rss", classification="GREEN")
    es.source(conn, PREFIX, base_url="https://feeds.example:8443/atom",
              classification="AMBER_STRICT")
    resolver = es.FakeResolver({"relay.unit.test": ["10.1.2.3"],
                                "hooks.unit.test": ["93.184.216.34"]})
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    return resolver


def test_adopt_proposes_what_rss_and_the_relay_always_had(conn, alpha6):
    proposal = EgressAdminService(conn).adopt_proposal()
    passive = proposal["passive_default"]
    assert passive["any_public_host"] is True and passive["exit_kind"] == "DIRECT"
    assert {80, 443, 8443} <= set(passive["allowed_ports"])
    assert passive["ceiling"] == "AMBER_STRICT"
    routes = {r["name"]: r for r in proposal["routes"]}
    assert routes["smtp"]["entry"] == "relay.unit.test@10.1.2.0/24:587"
    assert routes["smtp"]["confirm_network"] is True
    assert routes["webhook"]["entry"] == "hooks.unit.test:443"


def test_adopt_creates_nothing_until_confirmed_and_then_everything(conn, alpha6):
    setup = _setup_module()
    said = []
    answers = iter(["", "no"])
    assert setup.adopt(conn, conn.admin, {"via": "test"}, ask=lambda _p: next(answers),
                       out=said.append) == []
    assert "Nothing was created." in said
    assert conn.execute("SELECT count(*) FROM collect.egress_integration_route "
                        "WHERE retired_at IS NULL").fetchone()[0] == 0
    answers = iter(["10.1.2.0/28", "yes"])
    created = setup.adopt(conn, conn.admin, {"via": "test"}, ask=lambda _p: next(answers),
                          out=said.append)
    assert created == ["passive default", "smtp route", "webhook route"]
    entry = conn.execute(
        """SELECT d.entry FROM collect.egress_destination d
             JOIN collect.egress_integration_route r ON r.id = d.route_id
            WHERE r.name = 'smtp' AND r.retired_at IS NULL""").fetchone()[0]
    assert entry == "relay.unit.test@10.1.2.0/28:587"
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = 'EGRESS_ADOPTED' "
                        "AND actor_id = %s", (conn.admin,)).fetchone()[0] == 1
    # Nothing left to propose.
    assert EgressAdminService(conn).adopt_proposal() == {"passive_default": None,
                                                         "routes": []}


def test_adopt_creates_everything_or_nothing(conn, alpha6):
    """A refused entry on the last route leaves no passive default and no
    earlier route behind (2026-09-25): adopt once ran each
    step in its own transaction."""
    from noctornal_api.egress_admin import EgressAdminError
    svc = EgressAdminService(conn)
    proposal = svc.adopt_proposal()
    assert proposal["passive_default"] and len(proposal["routes"]) == 2
    proposal["routes"][-1]["entry"] = "*:443"
    before = conn.execute("SELECT coalesce(max(seq), 0) FROM audit.event").fetchone()[0]
    with pytest.raises(EgressAdminError):
        svc.adopt(actor_id=conn.admin, proposal=proposal)
    assert conn.execute("SELECT count(*) FROM collect.egress_profile "
                        "WHERE created_by = %s", (conn.admin,)).fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM collect.egress_integration_route "
                        "WHERE retired_at IS NULL").fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM audit.event WHERE seq > %s AND action LIKE "
                        "'EGRESS_%%'", (before,)).fetchone()[0] == 0
    # The same proposal, corrected, then goes through whole.
    proposal["routes"][-1]["entry"] = "hooks.unit.test:443"
    assert svc.adopt(actor_id=conn.admin, proposal=proposal)["created"] == [
        "passive default", "smtp route", "webhook route"]


def test_after_adopt_a_feed_and_a_delivery_leave_through_the_proxy(conn, alpha6,
                                                                  monkeypatch):
    real_is_blocked = __import__("noctornal_api.egress_policy",
                                 fromlist=["is_blocked"]).is_blocked
    from noctornal_api import egress_policy

    def loopback_public(address):
        a = getattr(address, "ipv4_mapped", None) or address
        return False if str(a).startswith("127.") else real_is_blocked(address)

    monkeypatch.setattr(egress_policy, "is_blocked", loopback_public)
    relay = socket.socket()
    relay.bind(("127.0.0.1", 0))
    relay.listen(4)
    relay_port = relay.getsockname()[1]
    feed = socket.socket()
    feed.bind(("127.0.0.1", 0))
    feed.listen(4)
    feed_port = feed.getsockname()[1]

    def serve(listener, greeting):
        conn_, _ = listener.accept()
        conn_.sendall(greeting)
        conn_.close()

    threading.Thread(target=serve, args=(relay, b"220 relay ready\r\n"), daemon=True).start()
    threading.Thread(target=serve, args=(feed, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                               b"Connection: close\r\n\r\nok"),
                     daemon=True).start()
    alpha6.names["relay.unit.test"] = ["127.0.0.1"]
    alpha6.names["plain-feed.example"] = ["127.0.0.1"]
    monkeypatch.setenv("SMTP_PORT", str(relay_port))
    svc = EgressAdminService(conn)
    proposal = svc.adopt_proposal()
    proposal["passive_default"]["allowed_ports"].append(feed_port)
    for route in proposal["routes"]:
        if route["name"] == "smtp":
            route["entry"] = f"relay.unit.test@127.0.0.0/24:{relay_port}"
    svc.adopt(actor_id=conn.admin, proposal=proposal)
    with es.ProxyRunner() as runner:
        monkeypatch.setenv(egress.PROXY_URL_ENV, f"http://127.0.0.1:{runner.port}")
        egress._reset_route_provider()
        sid = es.source(conn, PREFIX, base_url=f"http://plain-feed.example:{feed_port}/")
        run = es.run(conn, sid)
        route = egress.route_for("persona", "passive", conn=conn, context=f"run:{run}")
        fetched = pinned_http.fetch_response(f"http://plain-feed.example:{feed_port}/",
                                             route=route, timeout=5)
        assert fetched.body == b"ok" and fetched.via == "PROXY"
        smtp = egress.route_for("integration", "smtp", conn=conn,
                                declared=(Rule.for_host("relay.unit.test", {relay_port}),))
        with pinned_http.Deadline(10) as deadline:
            sock = pinned_http.open_connection(smtp.tagged(
                "delivery:00000000-0000-4000-8000-000000000009"), "relay.unit.test",
                relay_port, timeout=5, deadline=deadline)
            try:
                assert sock.recv(64).startswith(b"220")
            finally:
                sock.close()
    relay.close()
    feed.close()
    egress._reset_route_provider()


def test_before_adopt_the_same_feed_is_refused_route_unknown(conn, alpha6, monkeypatch):
    monkeypatch.setenv(egress.PROXY_URL_ENV, "http://127.0.0.1:3128")
    egress._reset_route_provider()
    try:
        with pytest.raises(pinned_http.RouteUnavailable) as caught:
            egress.route_for("persona", "passive", conn=conn,
                             context="run:00000000-0000-4000-8000-00000000000a")
        assert caught.value.code == "route_unknown"
    finally:
        egress._reset_route_provider()
