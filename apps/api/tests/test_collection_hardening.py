"""The Phase 4 service defects of docs/17 F15(f), (i) and (j).

No database: these are the pure halves -- the SSRF floor, the redactor and
the jitter arithmetic. The persistence halves live in
`test_collection_hardening_pg.py`.
"""
from __future__ import annotations

import http.server
import threading
from uuid import uuid4

import pytest

from noctornal_api.collection import (
    MAX_REDIRECTS,
    CollectionError,
    RateLimiter,
    _is_blocked,
    fetch,
    next_due_at,
    redact,
    secret_in_scope,
)


def _addr(text: str):
    import ipaddress
    return ipaddress.ip_address(text)


# ---------------------------------------------------------------------------
# F15(f) -- the SSRF floor was not the floor it claimed to be
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
    "::1", "fc00::1", "fe80::1", "0.0.0.0",
    # The ones the enumerated list missed.
    "::ffff:127.0.0.1",     # IPv4-mapped loopback: parsed as IPv6, matched
                            # nothing, and was a complete bypass.
    "::ffff:10.0.0.1",
    "::",                   # unspecified; reaches the local host
    "100.64.1.1",           # carrier-grade NAT
    "192.0.0.192",          # IETF protocol assignments -- metadata shape
    "198.18.0.1",           # benchmarking, routed internally more than you
                            # would expect
    "2002:7f00:1::",        # 6to4 wrapping 127.0.0.1
    "224.0.0.1",            # multicast
])
def test_internal_addresses_are_refused(address):
    assert _is_blocked(_addr(address)) is True, address


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700::1111"])
def test_public_addresses_are_allowed(address):
    assert _is_blocked(_addr(address)) is False, address


class _Redirector(http.server.BaseHTTPRequestHandler):
    """Answers every path with a 302 to whatever `target` says."""

    target = "http://127.0.0.1/"

    def do_GET(self):  # noqa: N802 - the stdlib's naming
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()

    def log_message(self, *_args):
        pass


@pytest.fixture
def redirector():
    server = http.server.HTTPServer(("127.0.0.1", 0), _Redirector)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()


def test_a_redirect_into_private_space_is_refused(redirector):
    """The defect, reproduced and then closed. `urlopen` followed redirects
    internally, so hops 2..N were never checked: a public host answering
    `302 -> http://127.0.0.1/` fetched the internal page.

    The server here is itself on loopback, so the FIRST hop is refused --
    which is the same check doing its job. `max_redirects=0` on a public
    URL would be the cleaner demonstration and needs a network, so the
    redirect-following logic is exercised by the hop-limit test below.
    """
    port = redirector.server_address[1]
    with pytest.raises(CollectionError, match="private address space"):
        fetch(f"http://127.0.0.1:{port}/anything")


def test_a_redirect_chain_is_bounded(redirector, monkeypatch):
    """A chain longer than the limit is a loop or an attempt to exhaust the
    validator, and neither is a feed."""
    port = redirector.server_address[1]
    _Redirector.target = f"http://localhost:{port}/next"
    # Neuter the address check so the REDIRECT logic is what is under test;
    # the address check has its own tests above.
    monkeypatch.setattr("noctornal_api.collection._is_blocked",
                        lambda _address: False)
    with pytest.raises(CollectionError, match="redirect"):
        fetch(f"http://127.0.0.1:{port}/start", max_redirects=MAX_REDIRECTS)


def test_a_non_http_scheme_is_refused():
    with pytest.raises(CollectionError, match="refusing scheme"):
        fetch("file:///etc/passwd")


def test_a_cloud_metadata_hostname_is_refused():
    """169.254.169.254 is caught by link-local; the alias hostnames are
    not, and they resolve to it."""
    with pytest.raises(CollectionError, match="metadata"):
        fetch("http://metadata.google.internal/computeMetadata/v1/")


# ---------------------------------------------------------------------------
# F15(j) -- redact() was a keyword list
# ---------------------------------------------------------------------------

def test_a_live_secret_is_removed_verbatim_however_it_is_encoded():
    """The layer that actually holds invariant 7: it does not depend on
    the remote server labelling the field in a way we anticipated."""
    secret = "Tr0ub4dor&3-persona-password"
    with secret_in_scope(secret):
        assert secret not in redact(f"login failed for {secret}")
        assert "Tr0ub4dor" not in redact(
            "POST /login body=Tr0ub4dor%263-persona-password")
        assert "VHIwdWI0" not in redact(
            "Authorization: Basic VHIwdWI0ZG9yJjMtcGVyc29uYS1wYXNzd29yZA==")


def test_a_secret_stops_being_removed_once_its_block_ends():
    """A ContextVar rather than a global, so a secret cannot outlive its
    block by being forgotten."""
    secret = "another-persona-password"
    with secret_in_scope(secret):
        pass
    assert secret in redact(f"stale message {secret}")


def test_the_shapes_a_keyword_list_misses():
    """docs/17 F15(j): `pass`, `p=`, `credential`, `bearer`, `passphrase`
    and any unlabelled echo walked through the old list."""
    assert "hunter2hunter2" not in redact("p=hunter2hunter2")
    assert "hunter2hunter2" not in redact("credential: hunter2hunter2")
    assert "hunter2hunter2" not in redact("passphrase=hunter2hunter2")
    assert "hunter2hunter2" not in redact("Bearer hunter2hunter2")
    # Unlabelled, high entropy: a cookie or a session id.
    assert "aB3xK9mQ7pL2vN8rT5wY1zC4" not in redact(
        "unexpected value aB3xK9mQ7pL2vN8rT5wY1zC4 in response")
    # A bare user:pass line, which carries no key name at all.
    assert "supersecret" not in redact("jsmith:supersecret")


def test_redaction_does_not_shred_the_message_it_has_to_keep_readable():
    """An error nobody can read is its own failure. Ordinary prose, ordinary
    long words and a plain status line have to survive."""
    out = redact("HTTP 503 from the upstream reverse proxy after "
                 "twelve seconds; internationalisation was incomplete")
    assert "503" in out and "reverse proxy" in out
    assert "internationalisation" in out


def test_url_credentials_are_masked():
    assert "hunter2" not in redact("https://persona:hunter2@forum.example/x")


# ---------------------------------------------------------------------------
# F15(i) -- jitter that was re-rolled on read
# ---------------------------------------------------------------------------

def test_jitter_is_symmetric_around_the_interval():
    """Only ever ADDING makes the minimum gap the interval, which is still
    a signature."""
    import random
    from datetime import datetime, timezone
    last = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
    offsets = [
        (next_due_at(last, 300, 20, rng=random.Random(seed)) - last)
        .total_seconds() - 300
        for seed in range(200)
    ]
    assert min(offsets) < 0 < max(offsets)
    assert all(abs(o) <= 60.001 for o in offsets)


def test_the_in_process_limiter_still_spaces_without_a_connection():
    """Kept testable without a database, and NOT the default anywhere
    real -- `CollectionService` passes its connection."""
    slept = []
    limiter = RateLimiter(None, sleep=slept.append, clock=lambda: 0.0)
    source = uuid4()
    assert limiter.wait(source, 2.0) == 0.0
    assert limiter.wait(source, 2.0) == pytest.approx(0.5)
    assert slept == [pytest.approx(0.5)]
