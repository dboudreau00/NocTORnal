"""egress-rss-floor (review of 2026-10-03).

Invariant 8: AMBER_STRICT and RED never leave the boundary, and decision
103 says reading a source is itself a crossing. The floor
(`can_egress(..., COLLECTION_TARGET)`) was applied only to adapters that
enforce collection authority, so an RSS or WEB feed labelled RED or
AMBER_STRICT was fetched from this deployment's own address on every poll
interval, by the cron, with no human act. The proxy compared the label only
with the passive default's ceiling, which `adopt` proposed as the highest
feed label, and readiness then reported the route as covering the feed.

Fails on dc28ffa: the outbound client is reached for a RED feed, `adopt`
proposes a RED ceiling and readiness is green.

DATABASE_URL-gated; prefix `r46f-`.
"""
from __future__ import annotations

import os

import pytest

import collection_helpers as h
import egress_support as es
from noctornal_api import config, egress_routes, pinned_http

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "r46f-"


@pytest.fixture
def conn(monkeypatch):
    from noctornal_api.db import connect

    es.clear_egress_env(monkeypatch)
    for key, value in es.keys().items():
        monkeypatch.setenv(key, value)
    c = connect()
    with es.preserved(c), es.collection_standin(c):
        yield c
        h.teardown(c, P)
        es.teardown(c, P)
    c.close()


@pytest.fixture
def outbound(monkeypatch):
    """The outbound client, replaced by a recorder that raises before any
    socket is opened: nothing leaves this host."""
    calls = []

    def recorder(url, *, route, **kw):
        calls.append((url, route.route_id))
        raise pinned_http.Unreachable("recorder: nothing sent", code="unreachable")

    monkeypatch.setattr(pinned_http, "_fetch_response", recorder)
    return calls


def _alone(conn):
    """Only this test's feeds are active, inside a rolled-back transaction:
    the readiness row reads every source in the database."""
    conn.execute("UPDATE collect.source SET is_active = false WHERE name NOT LIKE %s",
                 (f"{P}%",))
    conn.execute("UPDATE collect.egress_profile SET is_passive_default = false "
                 "WHERE is_passive_default")


def _feed(conn, label, kind="RSS", **kw):
    return h.source(conn, P, kind=kind, parser="rss", classification=label,
                    base_url="https://red-feed.r46f.example/feed.xml", egress=None, **kw)


@pytest.mark.parametrize("label", ["RED", "AMBER_STRICT"])
def test_a_feed_above_amber_is_refused_before_any_request(conn, outbound, label):
    from noctornal_api.collection import CollectionService, SourceRefused, _source_row

    sid = _feed(conn, label)
    svc = CollectionService(conn)
    cause = svc.refusal_cause(_source_row(conn, sid, None), svc._adapters["rss"])
    assert cause is not None and cause[0] == "above_ceiling"
    assert f"TLP:{label}" in cause[1] and "never leaves this platform" in cause[1]
    with pytest.raises(SourceRefused):
        svc.run_once(sid, actor_id=None)
    assert outbound == [], "the outbound client was reached for a source above AMBER"
    assert conn.execute("SELECT count(*) FROM collect.collection_run WHERE source_id = %s",
                        (sid,)).fetchone()[0] == 0, "a refused source leaves no run row"


@pytest.mark.parametrize("label", ["CLEAR", "GREEN", "AMBER"])
@pytest.mark.parametrize("kind", ["RSS", "WEB"])
def test_a_feed_at_or_below_amber_is_still_read(conn, outbound, label, kind):
    from noctornal_api.collection import CollectionService, _source_row

    sid = _feed(conn, label, kind=kind)
    svc = CollectionService(conn)
    assert svc.refusal_cause(_source_row(conn, sid, None), svc._adapters["rss"]) is None
    svc.run_once(sid, actor_id=None)
    assert [c[0] for c in outbound] == ["https://red-feed.r46f.example/feed.xml"]


def test_the_cron_does_not_list_a_red_feed_as_due_and_says_why(conn):
    from noctornal_api.collection import CollectionService

    red = _feed(conn, "RED", due=True)
    green = _feed(conn, "GREEN", due=True)
    svc = CollectionService(conn)
    due = {str(d["id"]) for d in svc.due_sources(clearance=None)}
    assert str(green) in due and str(red) not in due
    held = {str(x["id"]): x for x in svc.held_sources(clearance=None)}
    assert held[str(red)]["reason"] == "REFUSED"
    assert "never leaves this platform" in held[str(red)]["sentence"]


def test_the_proxy_weighs_a_feed_against_amber_whatever_the_profile_ceiling_says():
    from noctornal_api.egress_authz import _above

    assert _above("RED", "RED") and _above("AMBER_STRICT", "AMBER_STRICT")
    assert _above("RED", "AMBER") and _above("AMBER_STRICT", "RED")
    assert not _above("AMBER", "RED") and not _above("AMBER", "AMBER_STRICT")
    assert not _above("GREEN", "AMBER") and not _above("AMBER", "AMBER")
    assert _above("GREEN", "CLEAR") and _above("AMBER", "GREEN"), "lower ceilings still bind"


def test_a_passive_default_set_to_red_no_longer_reads_as_covering_a_red_feed(
        conn, monkeypatch):
    monkeypatch.setenv(config.ENV_VAR, "production")
    with conn.transaction(force_rollback=True):
        _alone(conn)
        es.profile(conn, P, ceiling="RED", passive=True)
        _feed(conn, "RED")
        ok, evidence, _action, _caveat = egress_routes.cover_sources(conn)
        assert not ok and "above AMBER" in evidence
        assert "r46f" not in evidence, "the register names no source"


def test_an_amber_feed_under_an_amber_or_higher_passive_default_is_covered(
        conn, monkeypatch):
    monkeypatch.setenv(config.ENV_VAR, "production")
    with conn.transaction(force_rollback=True):
        _alone(conn)
        es.profile(conn, P, ceiling="AMBER", passive=True)
        _feed(conn, "AMBER")
        _ok, evidence, _action, _caveat = egress_routes.cover_sources(conn)
        # Other rows of the register (an SMTP route this host's environment
        # configures) are not this test's: only the feed's own gap is.
        assert "a feed source is labelled above" not in evidence, evidence
