"""The ingest key's address allowlist is checked against an address the caller cannot choose.

`limits.authorised_client_ip` decides the address for the allowlist: the socket peer uvicorn
resolved, and the right-counted X-Forwarded-For entry only with two or more declared proxies and a
chain that ends at the peer. The router used to compare against `request.client.host`, which with two
proxies in front is the outer proxy, not the client; reading the header at one hop instead would let
a caller that reaches the API directly pick its address. These tests pin the helper and the route at
one and two hops, trusted and unvouched peers, and that no address is refused.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest
from noctornal_api.http.errors import Problem
from starlette.requests import Request

from noctornal_api.http import limits
from noctornal_api.http.routers import ingest as ingest_router
from noctornal_api.ingest import _admitted

ALLOWLIST = ["198.51.100.0/24"]


def _request(peer: str | None, *forwarded: str) -> Request:
    headers = [(b"x-forwarded-for", line.encode()) for line in forwarded]
    return Request({
        "type": "http", "method": "POST", "path": "/", "headers": headers,
        "client": (peer, 40000) if peer else None,
    })


def _passes(request: Request) -> bool:
    return _admitted(ALLOWLIST, limits.authorised_client_ip(request))


def test_the_ingest_router_asks_the_one_client_address_helper():
    source = inspect.getsource(ingest_router.submit)
    assert "authorised_client_ip(request)" in source
    assert "request.client" not in source


def test_allowlist_honoured_with_one_declared_hop(monkeypatch):
    monkeypatch.setenv(limits.HOPS_ENV, "1")
    # uvicorn has already put the address Caddy saw in the peer; the header is not read.
    assert _passes(_request("198.51.100.7", "198.51.100.7"))
    assert not _passes(_request("203.0.113.9", "198.51.100.7"))


def test_allowlist_honoured_with_two_declared_hops(monkeypatch):
    monkeypatch.setenv(limits.HOPS_ENV, "2")
    # The outer proxy is the socket peer uvicorn leaves; the client is two from the right.
    assert _passes(_request("192.0.2.50", "198.51.100.7, 192.0.2.50"))
    assert not _passes(_request("198.51.100.7", "203.0.113.9, 198.51.100.7"))


def test_a_forged_header_does_not_pass_when_no_proxy_is_declared(monkeypatch):
    monkeypatch.delenv(limits.HOPS_ENV, raising=False)
    assert not _passes(_request("203.0.113.9", "198.51.100.7"))


def test_a_forged_leading_entry_does_not_pass_with_proxies_declared(monkeypatch):
    monkeypatch.setenv(limits.HOPS_ENV, "1")
    # The caller wrote the first entry; the proxy appended the address it saw.
    assert not _passes(_request("203.0.113.9", "198.51.100.7, 203.0.113.9"))
    monkeypatch.setenv(limits.HOPS_ENV, "2")
    assert not _passes(_request("192.0.2.50", "198.51.100.7, 203.0.113.9, 192.0.2.50"))


def test_a_short_chain_falls_back_to_the_peer(monkeypatch):
    monkeypatch.setenv(limits.HOPS_ENV, "2")
    assert not _passes(_request("203.0.113.9", "198.51.100.7"))


def test_no_address_is_refused_when_an_allowlist_is_set(monkeypatch):
    monkeypatch.delenv(limits.HOPS_ENV, raising=False)
    assert limits.client_ip(_request(None)) is None
    assert limits.authorised_client_ip(_request(None)) is None
    assert not _passes(_request(None))
    assert not _passes(_request("not-an-address"))
    assert _admitted([], None)


@pytest.mark.parametrize("hops", ["0", "1"])
def test_the_allowlist_address_is_the_peer_where_the_peer_is_not_vouched_for(monkeypatch, hops):
    monkeypatch.setenv(limits.HOPS_ENV, hops)
    request = _request("198.51.100.20", "198.51.100.21")
    assert limits.client_ip(request) == ("198.51.100.21" if hops == "1" else "198.51.100.20")
    assert limits.authorised_client_ip(request) == "198.51.100.20"


@pytest.mark.parametrize("hops", ["1", "2"])
def test_a_forged_header_from_an_unvouched_peer_never_passes(monkeypatch, hops):
    """A caller that reaches the API directly (a container on the internal network) chooses the
    header, not the socket peer; the allowlisted address it writes must not be taken."""
    monkeypatch.setenv(limits.HOPS_ENV, hops)
    assert not _passes(_request("172.31.243.200", "198.51.100.7"))
    assert not _passes(_request("172.31.243.200", "198.51.100.7, 172.31.243.201"))
    assert not _passes(_request("172.31.243.200", "198.51.100.7, 198.51.100.8, 203.0.113.9"))


def _submit(peer: str, *forwarded: str):
    """Drive the real route function with a fake service and report the address it was given."""
    seen: dict = {}

    class _Svc:
        def authenticate(self, token, peer_ip=None):
            seen["peer"] = peer_ip
            if not _admitted(ALLOWLIST, peer_ip):
                return None
            return {"ip_allowlist": ALLOWLIST, "max_bytes_per_request": 1}

    class _Reached(Exception):
        pass

    async def _body(*_a, **_k):
        raise _Reached

    original = (ingest_router._with_raw, ingest_router.read_body_capped)
    ingest_router._with_raw = lambda conn, **kw: _Svc()
    ingest_router.read_body_capped = _body
    try:
        asyncio.run(ingest_router.submit(
            _request(peer, *forwarded), authorization="Bearer x",
            idempotency_key=None, conn=None))
    except _Reached:
        return "admitted", seen["peer"]
    except Problem as exc:
        return exc.status, seen["peer"]
    finally:
        ingest_router._with_raw, ingest_router.read_body_capped = original


@pytest.mark.parametrize("hops,peer,chain,outcome", [
    ("1", "198.51.100.7", (), "admitted"),
    ("1", "203.0.113.9", (), 401),
    ("2", "192.0.2.50", ("198.51.100.7, 192.0.2.50",), "admitted"),
    ("2", "198.51.100.7", ("203.0.113.9, 198.51.100.7",), 401),
    ("1", "172.31.243.200", ("198.51.100.7",), 401),
    ("2", "172.31.243.200", ("198.51.100.7",), 401),
])
def test_the_route_applies_the_allowlist_at_one_and_two_hops(monkeypatch, hops, peer, chain, outcome):
    monkeypatch.setenv(limits.HOPS_ENV, hops)
    assert _submit(peer, *chain)[0] == outcome
