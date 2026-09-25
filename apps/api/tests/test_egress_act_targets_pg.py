"""ACT tunnels are judged target by target (S2, 2026-09-25).

An act (enrolment, resolution, a join) once needed only SOME live authority
of the persona that met the recorded-and-confirmed-after rule, and then
opened the site of ANY source bound under any live target. So one fresh
authority for forum two opened forum one although forum one's authority
predated a widening, and a source moved to a new host opened there although
its target named the old one. Both went round the two-person control that
the same tunnel as a RUN refuses. Now each target is judged as a run's is.

A real proxy on an ephemeral loopback port, the fake chained exit and fake
resolver of test_egress_proxy_pg. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os

import pytest

import egress_support as es
from test_egress_proxy_pg import (
    PREFIX,
    FakeUpstream,
    _connect,
    _expect,
    _persona_user,
    _status,
    _world,
)
from noctornal_api import egress_policy

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

_REAL_IS_BLOCKED = egress_policy.is_blocked


@pytest.fixture(scope="module")
def conn():
    from noctornal_api.db import connect
    c = connect()
    with es.preserved(c), es.collection_standin(c):
        yield c
        es.teardown(c, PREFIX)
    c.close()


@pytest.fixture(scope="module")
def people(conn):
    return (es.user(conn, "CASE_OWNER", prefix=PREFIX, clearance="RED"),
            es.user(conn, "CASE_OWNER", prefix=PREFIX, clearance="RED"))


@pytest.fixture
def loopback_public(monkeypatch):
    def fake(address):
        address = getattr(address, "ipv4_mapped", None) or address
        if address.version == 4 and str(address).startswith("127."):
            return False
        return _REAL_IS_BLOCKED(address)
    monkeypatch.setattr(egress_policy, "is_blocked", fake)


@pytest.fixture
def resolver(monkeypatch):
    import socket
    fake = es.FakeResolver()
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return fake


@pytest.fixture
def proxy():
    runner = es.ProxyRunner()
    yield runner
    runner.stop()


@pytest.fixture
def upstream():
    up = FakeUpstream()
    yield up
    up.close()


def _act(proxy, pid, persona, target):
    head, sock = _connect(proxy, _persona_user(pid, f"act.{persona}"), target)
    sock.close()
    return _status(head)


def _second_forum(conn, people, pid, persona, host="forumtwo.rebind.test"):
    sid = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                    base_url=f"http://{host}:443/", classification="AMBER",
                    persona=persona)
    return sid


def test_a_fresh_authority_for_one_forum_does_not_open_another_whose_own_predates_a_widening(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, _stale = _world(conn, people, 443, upstream=upstream.port)
    two = _second_forum(conn, people, pid, persona)
    # A widening: forum two becomes reachable, and every authority recorded
    # before now is void for this profile.
    conn.execute("UPDATE collect.egress_profile SET allowed_host_suffixes = "
                 "allowed_host_suffixes || '{forumtwo.rebind.test}'::text[] WHERE id = %s",
                 (pid,))
    # Two people confirm a NEW authority, for forum two only.
    fresh = es.authority(conn, recorder=people[0], confirmer=people[1], persona=persona,
                         sources=(two,), classification="RED")
    assert _act(proxy, pid, persona, "forumtwo.rebind.test:443")[0] == 200
    # Forum one's own authority predates the widening: its act is refused
    # exactly as its run is.
    assert _act(proxy, pid, persona, "forum.rebind.test:443")[1] == \
        "authority_predates_route_change"
    run = es.run(conn, sid, profile=pid, persona=persona, authority=_stale)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "forum.rebind.test:443",
            "authority_predates_route_change")
    # The allowed act names the source it matched and that source's authority.
    row = conn.execute(
        """SELECT source_id, authority_id, dest_host FROM collect.egress_connection
            WHERE collection_account_id = %s AND context_kind = 'act' AND event = 'OPEN'
            ORDER BY seq DESC LIMIT 1""", (persona,)).fetchone()
    assert row == (two, fresh, "forumtwo.rebind.test")


def test_a_source_moved_to_a_new_host_after_its_target_opens_nothing_there(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
    assert _act(proxy, pid, persona, "forum.rebind.test:443")[0] == 200
    # The site moves, still inside the profile's suffix, after the target
    # named the old base_url: no confirmed decision covers the new host.
    conn.execute("UPDATE collect.source SET base_url = 'http://new.forum.rebind.test:443/' "
                 "WHERE id = %s", (sid,))
    assert _act(proxy, pid, persona, "new.forum.rebind.test:443")[1] == "authority_missing"
    run = es.run(conn, sid, profile=pid, persona=persona, authority=aid)
    _expect(proxy, _persona_user(pid, f"run.{run}"), "new.forum.rebind.test:443",
            "authority_missing")
    # Nor is the old host a site of the source any more.
    assert _act(proxy, pid, persona, "forum.rebind.test:443")[1] == \
        "destination_not_in_source"
    # A target confirmed for the new site opens it again.
    es.authority(conn, recorder=people[0], confirmer=people[1], persona=persona,
                 sources=(sid,), classification="RED")
    assert _act(proxy, pid, persona, "new.forum.rebind.test:443")[0] == 200


def test_a_revoked_target_closes_its_source_to_acts(conn, people, loopback_public,
                                                    resolver, proxy, upstream):
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
    two = _second_forum(conn, people, pid, persona, host="forum.rebind.test")
    es.authority(conn, recorder=people[0], confirmer=people[1], persona=persona,
                 sources=(two,), classification="RED")
    # Forum one's target is revoked; forum two (another source on the same
    # host) still has its own, so the host stays open through THAT target.
    conn.execute("ALTER TABLE collect.collection_authority_target DISABLE TRIGGER USER")
    conn.execute("UPDATE collect.collection_authority_target SET revoked_at = now(), "
                 "revoked_by = %s, revoke_reason = 'revoked for the act test' "
                 "WHERE authority_id = %s", (people[0], aid))
    conn.execute("ALTER TABLE collect.collection_authority_target ENABLE TRIGGER USER")
    assert _act(proxy, pid, persona, "forum.rebind.test:443")[0] == 200
    row = conn.execute(
        """SELECT source_id FROM collect.egress_connection
            WHERE collection_account_id = %s AND context_kind = 'act' AND event = 'OPEN'
            ORDER BY seq DESC LIMIT 1""", (persona,)).fetchone()
    assert row[0] == two


def test_a_host_shared_by_two_sources_is_carried_by_the_one_within_the_ceiling(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, _aid = _world(conn, people, 443, upstream=upstream.port)
    # A RED source on the same host, its target confirmed most recently.
    red = es.source(conn, PREFIX, kind="XENFORO", parser="xenforo",
                    base_url="http://forum.rebind.test:443/vault", classification="RED",
                    persona=persona)
    es.authority(conn, recorder=people[0], confirmer=people[1], persona=persona,
                 sources=(red,), classification="RED",
                 confirmed="clock_timestamp() + interval '1 second'",
                 target_confirmed="clock_timestamp() + interval '1 second'")
    assert _act(proxy, pid, persona, "forum.rebind.test:443")[0] == 200
    row = conn.execute(
        """SELECT source_id, classification::text FROM collect.egress_connection
            WHERE collection_account_id = %s AND context_kind = 'act' AND event = 'OPEN'
            ORDER BY seq DESC LIMIT 1""", (persona,)).fetchone()
    assert row == (sid, "AMBER")


def test_an_address_in_the_profiles_networks_needs_one_passing_target(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, _stale = _world(conn, people, 443, source_kind="TELEGRAM",
                                       host=None, cidrs=("127.0.0.0/24",),
                                       upstream=upstream.port)
    conn.execute("UPDATE collect.source SET base_url = 'https://t.me/s/egresschannel' "
                 "WHERE id = %s", (sid,))
    # The target was confirmed for the channel's old address: nothing passes.
    assert _act(proxy, pid, persona, "127.0.0.1:443")[1] == "authority_missing"
    # A widening, then a fresh authority for the channel: one passing target.
    conn.execute("UPDATE collect.egress_profile SET allowed_ports = allowed_ports || 5222 "
                 "WHERE id = %s", (pid,))
    es.authority(conn, recorder=people[0], confirmer=people[1], persona=persona,
                 sources=(sid,), classification="RED")
    assert _act(proxy, pid, persona, "127.0.0.1:443")[0] == 200


def test_a_persona_with_no_target_yet_reaches_only_its_profiles_networks(
        conn, people, loopback_public, resolver, proxy, upstream):
    """Enrolment and a chat lookup come before any source of the persona
    has a target: the profile's own networks open under a live authority
    of the persona, and a name does not (2026-09-25)."""
    pid, persona, sid, aid = _world(conn, people, 443, source_kind="TELEGRAM",
                                    host=None, cidrs=("127.0.0.0/24",),
                                    upstream=upstream.port)
    elsewhere = es.persona(conn, PREFIX, profile=es.profile(conn, PREFIX, kind="VPN",
                                                            exit_kind=None))
    conn.execute("UPDATE collect.source SET collection_account_id = %s WHERE id = %s",
                 (elsewhere, sid))
    assert _act(proxy, pid, persona, "127.0.0.1:443")[0] == 200
    assert _act(proxy, pid, persona, "forum.rebind.test:443")[1] == "authority_missing"
    # Revoked, the persona's own authority opens nothing either.
    conn.execute("UPDATE collect.collection_authority SET revoked_at = now(), "
                 "revoked_by = %s, revoke_reason = 'test' WHERE id = %s",
                 (people[1], aid))
    assert _act(proxy, pid, persona, "127.0.0.1:443")[1] == "authority_missing"


def test_an_act_with_no_target_on_its_own_sources_is_authority_missing(
        conn, people, loopback_public, resolver, proxy, upstream):
    pid, persona, sid, aid = _world(conn, people, 443, upstream=upstream.port)
    # The authority's only target is a source bound to ANOTHER persona.
    elsewhere = es.persona(conn, PREFIX, profile=es.profile(conn, PREFIX, kind="VPN",
                                                            exit_kind=None))
    conn.execute("UPDATE collect.source SET collection_account_id = %s WHERE id = %s",
                 (elsewhere, sid))
    assert _act(proxy, pid, persona, "forum.rebind.test:443")[1] == "authority_missing"
