"""A persona's run, act and stop contexts through the REAL egress listener,
from the persona gate and the shipped route provider (F31 part A, docs/17
F31; written 2026-10-03, after the authenticated forum build left it undelivered).

test_egress_proxy_pg.py drives the real listener with raw CONNECTs whose user
names the TEST builds, and test_forum_member.py drives the real adapter and
the real pinned client against the egress contract's stub proxy. Neither
goes from the code that decides a persona may be used, through
`egress.route_for` and the shipped provider (`egress_routes.route_parts`),
into the listener that decides again. So a bypass of `route_for`, a route
whose token the listener would not accept, a context the gate forgot to name
or a persona the listener does not withdraw would have passed every suite.
This one holds the whole path:

- a RUN through `CollectionService.run_once` with a stub authority adapter
  that reads through `RunContext.fetch`: the tunnel opens as that run, the
  exit is handed the NAME and nothing here resolved it, and the ledger
  records the open and the close against the run;
- an ACT through `collection.persona_session` (the gate's six steps) and a
  STOP through `PersonaGate(stopping=True)`, a stop needing no authority;
- a destination the run's source does not own is refused by the listener and
  reported by its code;
- a persona withdrawn mid-tunnel (burnt) closes the open run tunnel after the
  proxy's recheck, with the ledger saying why.

The exit is a fake SOCKS5 chain that, once told which NAME to reach, answers
as the forum. DATABASE_URL-gated; nothing leaves the loopback.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import threading
import time

import pytest

import collection_helpers as h
import egress_support as es
from noctornal_api import egress, egress_policy

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

P = "test-f31a-"
HOST = "forum.f31a.test"
PORT = 9443
_REAL_IS_BLOCKED = egress_policy.is_blocked


class ServingExit:
    """A chained SOCKS5 exit that records the name it was asked to reach and
    then answers HTTP as the far end, once per connection."""

    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.port = self.listener.getsockname()[1]
        self.seen: list[tuple] = []
        self.requests: list[str] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                sock, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(sock,), daemon=True).start()

    def _one(self, sock):
        try:
            sock.settimeout(10)
            sock.recv(2 + sock.recv(2, socket.MSG_PEEK)[1])
            sock.sendall(b"\x05\x00")
            _ver, _cmd, _r, atyp = sock.recv(4)
            if atyp == 3:
                length = sock.recv(1)[0]
                addr = sock.recv(length).decode()
            elif atyp == 1:
                addr = str(ipaddress.IPv4Address(sock.recv(4)))
            else:
                addr = str(ipaddress.IPv6Address(sock.recv(16)))
            port = int.from_bytes(sock.recv(2), "big")
            self.seen.append(("SOCKS5", atyp, addr, port))
            sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = sock.recv(4096)
                if not chunk:
                    return
                head += chunk
            self.requests.append(head.split(b"\r\n", 1)[0].decode("latin-1"))
            body = b"the board answered"
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                         b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                         b"Connection: close\r\n\r\n" + body)
            while sock.recv(65536):
                pass
        except OSError:
            pass
        finally:
            sock.close()

    def close(self):
        self.listener.close()


@pytest.fixture(scope="module")
def conn():
    from noctornal_api.db import connect

    c = connect()
    with es.preserved(c), es.collection_standin(c):
        yield c
        # The foundation's teardown: it knows the documents a run stored, and
        # keeps a persona on a platform (nothing deletes one: it is burnt).
        h.teardown(c, P)
        c.execute("UPDATE collect.collection_account SET status = 'BURNED', "
                  "burn_reason = 'a test persona' WHERE handle LIKE %s", (f"{P}%",))
        c.execute("UPDATE collect.egress_profile SET is_active = false "
                  "WHERE name LIKE %s", (f"{P}%",))
        h.retire_users(c, P)
    c.close()


@pytest.fixture
def listener(monkeypatch):
    """The real proxy, the shipped provider pointed at it, the keys, loopback
    admitted as a public forum, and names resolved by a fake that counts."""
    es.clear_egress_env(monkeypatch)
    es.env_with(monkeypatch, es.keys())
    monkeypatch.setenv("NOCTORNAL_FORUM_SOURCE_CEILING", "AMBER")

    def loopback_is_public(address):
        address = getattr(address, "ipv4_mapped", None) or address
        if address.version == 4 and str(address).startswith("127."):
            return False
        return _REAL_IS_BLOCKED(address)

    monkeypatch.setattr(egress_policy, "is_blocked", loopback_is_public)
    resolver = es.FakeResolver()
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    egress._reset_route_provider()
    with es.ProxyRunner() as runner:
        monkeypatch.setenv(egress.PROXY_URL_ENV, f"http://127.0.0.1:{runner.port}")
        runner.resolver = resolver
        yield runner
    egress._reset_route_provider()


@pytest.fixture
def far_end():
    exit_ = ServingExit()
    yield exit_
    exit_.close()


def _world(conn, far_end):
    """A persona with a credential on its own sealed exit, a forum source it
    reads, and a confirmed authority over it."""
    from noctornal_api.collection import FetchResult, Item

    recorder, _ = h.user(conn, P, roles=("COLLECTOR",))
    confirmer, _ = h.user(conn, P, roles=("SECURITY_OFFICER",))
    profile = es.profile(conn, P, kind="RESIDENTIAL", ceiling="AMBER", ports=(PORT, 443),
                         any_public_host=False, suffixes=(HOST,), exit_kind=None)
    blob, key_id, fingerprint = es.seal_for(profile, "SOCKS5", "127.0.0.1", far_end.port)
    conn.execute("""UPDATE collect.egress_profile SET exit_kind = 'SOCKS5', exit_sealed = %s,
                      exit_seal_key_id = %s, exit_fingerprint = %s WHERE id = %s""",
                 (blob, key_id, fingerprint, profile))
    persona = h.persona(conn, P, platform="XENFORO", egress=profile, secret="a-credential")
    read = []

    def produce(ctx):
        fetched = ctx.fetch(f"http://{HOST}:{PORT}/threads/1/", accept_status={200})
        read.append(fetched.body)
        return FetchResult(items=[Item(external_id="post:1",
                                       url=f"http://{HOST}:{PORT}/posts/1/",
                                       body="read through the exit", title="t")],
                           http_status=200)

    stub = h.StubAuthorityAdapter(produce=produce, persona_platform="XENFORO")
    source = h.source(conn, P, kind="XENFORO", parser="stubforum",
                      base_url=f"http://{HOST}:{PORT}/", persona=persona)
    view = h.authority(conn, recorder=recorder, confirmer=confirmer, persona_id=persona,
                       source_ids=[source], adapters=h.adapters(stub))
    return {"profile": profile, "persona": persona, "source": source, "stub": stub,
            "recorder": recorder, "confirmer": confirmer, "authority": view["id"],
            "read": read}


def _ledger(conn, **where):
    clause = " AND ".join(f"{k} = %s" for k in where)
    return conn.execute(
        f"""SELECT event, reason, context_kind, collection_run_id, collection_account_id,
                   egress_profile_id, source_id
              FROM collect.egress_connection WHERE {clause} ORDER BY seq""",
        tuple(where.values())).fetchall()


def _route_of(conn, world, run_id):
    """The shipped route of one poll, as run_once asks for it."""
    from noctornal_api.collection import _route_for_source, _source_row

    source = _source_row(conn, world["source"], None)
    persona = {"egress_profile_id": world["profile"]}
    return _route_for_source(conn, source, persona, adapter=world["stub"], run_id=run_id)


# ---------------------------------------------------------------------------
# The three contexts
# ---------------------------------------------------------------------------

def test_a_persona_run_goes_from_run_once_through_the_shipped_route_into_the_listener(
        conn, listener, far_end):
    from noctornal_api.collection import CollectionService

    w = _world(conn, far_end)
    result = CollectionService(conn, h.adapters(w["stub"]),
                               sleep=lambda _s: None).run_once(w["source"], actor_id=None)
    assert result.status == "OK", result
    assert w["read"] == [b"the board answered"]
    # The route the poll took was the shipped provider's: PROXY, at this
    # listener, authenticated well enough that the listener admitted it.
    route = w["stub"].last_context.route
    assert route.mode == "PROXY" and route.proxy_port == listener.port
    assert route.context == f"run:{result.run_id}" and route.kind == "persona"
    # The exit was handed the NAME, and nothing on this side looked it up.
    assert far_end.seen == [("SOCKS5", 3, HOST, PORT)]
    assert HOST not in listener.resolver.asked
    assert far_end.requests[0].startswith("GET /threads/1/")
    time.sleep(0.3)
    rows = _ledger(conn, collection_run_id=result.run_id)
    assert rows and rows[0][0] == "OPEN" and rows[-1][0] == "CLOSE"
    assert {r[2] for r in rows} == {"run"}
    assert rows[0][4] == w["persona"] and rows[0][5] == w["profile"]
    assert rows[0][6] == w["source"]


def test_a_persona_act_goes_through_the_gate_and_the_shipped_route_into_the_listener(
        conn, listener, far_end):
    from noctornal_api.collection import persona_session
    from noctornal_api.pinned_http import fetch_response

    w = _world(conn, far_end)
    with persona_session(conn, w["persona"], actor_id=None, clearance=None,
                         purpose="a test act", source_id=None, need="PUBLIC_READ",
                         platform="XENFORO", needs_secret=False) as ctx:
        assert ctx.route.mode == "PROXY" and ctx.route.context == f"act:{w['persona']}"
        fetched = fetch_response(f"http://{HOST}:{PORT}/", route=ctx.route,
                                 max_redirects=0, accept_status={200})
    assert fetched.status == 200 and fetched.body == b"the board answered"
    assert far_end.seen[-1] == ("SOCKS5", 3, HOST, PORT)
    time.sleep(0.3)
    rows = _ledger(conn, collection_account_id=w["persona"], context_kind="act")
    assert rows and rows[0][0] == "OPEN" and rows[-1][0] == "CLOSE"


def test_a_persona_stop_needs_no_authority_and_goes_the_same_way(conn, listener, far_end):
    from noctornal_api.collection import PersonaGate
    from noctornal_api.pinned_http import fetch_response

    w = _world(conn, far_end)
    # The authority is withdrawn: a stop is allowed regardless.
    conn.execute("ALTER TABLE collect.collection_authority DISABLE TRIGGER USER")
    conn.execute("UPDATE collect.collection_authority SET revoked_at = now(), "
                 "revoked_by = %s, revoke_reason = 'withdrawn for the stop test' "
                 "WHERE id = %s", (w["recorder"], w["authority"]))
    conn.execute("ALTER TABLE collect.collection_authority ENABLE TRIGGER USER")
    gate = PersonaGate(conn, w["persona"], actor_id=None, clearance=None,
                       purpose="a test stop", source_id=None, need=None, platform=None,
                       stopping=True, needs_secret=False)
    gate.check()
    gate.lock()
    try:
        route = gate.route()
        assert route.context == f"stop:{w['persona']}" and route.mode == "PROXY"
        fetched = fetch_response(f"http://{HOST}:{PORT}/", route=route,
                                 max_redirects=0, accept_status={200})
    finally:
        gate.release()
    assert fetched.status == 200
    time.sleep(0.3)
    rows = _ledger(conn, collection_account_id=w["persona"], context_kind="stop")
    assert rows and rows[0][0] == "OPEN"
    # The same persona, with no authority, is refused an ACT by the listener
    # and by the gate before it (the gate speaks first).
    from noctornal_api.collection_authority import AuthorityMissing
    from noctornal_api.collection import persona_session
    with pytest.raises(AuthorityMissing):
        with persona_session(conn, w["persona"], actor_id=None, clearance=None,
                             purpose="a refused act", source_id=None, need="PUBLIC_READ",
                             platform="XENFORO", needs_secret=False):
            raise AssertionError("an act without an authority must not start")


# ---------------------------------------------------------------------------
# What the listener refuses, and withdraws
# ---------------------------------------------------------------------------

def test_a_destination_the_runs_source_does_not_own_is_refused_and_reported_by_code(
        conn, listener, far_end):
    from noctornal_api.pinned_http import DestinationRefused, fetch_response

    w = _world(conn, far_end)
    # The profile may reach another name on that port; the run's source may not.
    conn.execute("UPDATE collect.egress_profile SET allowed_host_suffixes = "
                 "allowed_host_suffixes || ARRAY['other.f31a.test'] WHERE id = %s",
                 (w["profile"],))
    # The widening voids the first authority; a second follows it.
    authority = es.authority(conn, recorder=w["recorder"], confirmer=w["confirmer"],
                             persona=w["persona"], sources=(w["source"],),
                             classification="RED")
    run_id = es.run(conn, w["source"], profile=w["profile"], persona=w["persona"],
                    authority=authority)
    route = _route_of(conn, w, run_id)
    with pytest.raises(DestinationRefused) as refused:
        fetch_response(f"http://other.f31a.test:{PORT}/", route=route, max_redirects=0)
    assert refused.value.code == "destination_not_in_source"
    assert far_end.seen == [], "nothing was dialled for a refused destination"
    rows = _ledger(conn, collection_run_id=run_id)
    assert [r[0] for r in rows] == ["REFUSED"]


def test_a_persona_withdrawn_mid_tunnel_closes_an_open_run_tunnel(conn, listener, far_end):
    w = _world(conn, far_end)
    run_id = es.run(conn, w["source"], profile=w["profile"], persona=w["persona"],
                    authority=w["authority"])
    route = _route_of(conn, w, run_id)
    head, sock = es.raw_connect(listener.port, route.wire_username, route.token,
                                f"{HOST}:{PORT}")
    assert head.split(b"\r\n", 1)[0].split(b" ", 2)[1] == b"200"
    # The persona is burnt while the tunnel stands; the listener's recheck
    # (its own timer in production) finds the persona gone.
    conn.execute("UPDATE collect.collection_account SET status = 'BURNED' WHERE id = %s",
                 (w["persona"],))
    listener.call(listener.proxy.recheck_now())
    sock.settimeout(10)
    assert sock.recv(10) == b""
    sock.close()
    time.sleep(0.3)
    rows = _ledger(conn, collection_run_id=run_id)
    assert rows[0][0] == "OPEN" and rows[-1][:2] == ("CLOSE", "persona_withdrawn")


def test_a_route_the_shipped_provider_did_not_build_is_not_admitted(conn, listener, far_end):
    """A hand-made user name with the wrong token is refused: the listener
    admits only what `route_for` built, so a caller that skipped it is
    caught here rather than in production."""
    w = _world(conn, far_end)
    run_id = es.run(conn, w["source"], profile=w["profile"], persona=w["persona"],
                    authority=w["authority"])
    route = _route_of(conn, w, run_id)
    head, sock = es.raw_connect(listener.port, route.wire_username, "0" * 64,
                                f"{HOST}:{PORT}")
    sock.close()
    assert head.split(b"\r\n", 1)[0].split(b" ", 2)[1] != b"200"
    assert far_end.seen == []
