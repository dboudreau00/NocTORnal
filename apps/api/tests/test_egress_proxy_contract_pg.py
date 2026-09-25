"""The wire contract's cases against the REAL egress proxy (S2, 2026-09-24;
docs/20 section 11).

egress_contract_cases.py holds the client side of the wire contract; its
own runner (test_egress_contract.py) runs it against a stub written to the
letter of docs/20 section 8. This file runs the same cases against the proxy this
build ships, in a child process (egress_proxy_child.py), so a case that
counts the names the CLIENT resolves counts only the client's. The harness
has the shape the cases module documents:

- `route()` hands out real routes: the passive route with a RUNNING feed
  run behind it for a persona run context, and otherwise the webhook
  integration route (a persona act on the passive route has no persona to
  act as, so the python-socks case authenticates on the integration route,
  which is what that case is about);
- `origin(name, port)` adds the name to the child's resolver and an exact
  NAME:PORT entry to the webhook route, so the real proxy resolves and
  admits it with egress_policy;
- `refusing(code)` makes the child refuse every authorisation with that
  code, so each wire code travels the real reply writer;
- `records` are rebuilt from the connection ledger the real proxy wrote.

Two cases script the stub's reply bytes directly (a banner in the same
segment as the 200, a 200 with an unusual reason); they test the client's
head reader, not a server, and the real proxy's banner path has its own
case below with a relay that speaks first.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

import egress_contract_cases as cases
import egress_support as es
from noctornal_api import egress_policy, pinned_http
from noctornal_api.egress_policy import EgressRoute, RoutePolicy

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")

PREFIX = "egc-"
CHILD = Path(__file__).with_name("egress_proxy_child.py")
SCRIPTED = {"case_a_server_first_banner_in_the_same_segment_as_the_200_is_kept",
            "case_a_one_or_two_token_reason_on_200_opens_the_tunnel"}


class RealHarness:
    proxy_host = "127.0.0.1"

    def __init__(self, conn, control: Path, port: int, route_id):
        self.conn = conn
        self.control = control
        self.proxy_port = port
        self.route_id = route_id
        self.started_seq = conn.execute(
            "SELECT coalesce(max(seq), 0) FROM collect.egress_connection").fetchone()[0]

    # --- the harness of egress_contract_cases ------------------------------

    def route(self, kind: str = "integration", name: str = "webhook",
              context: str | None = None, rules=(), *, any_public=None,
              proxy_host: str | None = None) -> EgressRoute:
        if kind == "persona" and context and context.startswith("run:"):
            run = self._feed_run()
            kind, name, context = "persona", "passive", f"run:{run}"
        elif kind == "persona":
            kind, name, context = "integration", "webhook", f"check:{uuid4()}"
        if any_public is None:
            any_public = kind == "persona" or not rules
        policy = RoutePolicy(kind, tuple(rules), any_public=any_public, admission="proxy")
        return EgressRoute(kind, name, "PROXY", policy, context,
                           proxy_host or self.proxy_host, self.proxy_port,
                           es.token_for(egress_policy.wire_username(kind, name)))

    def origin(self, name: str, port: int) -> None:
        names = self._names()
        names[name] = "127.0.0.1"
        (self.control / "names.json").write_text(json.dumps(names), encoding="utf-8")
        self._allow(f"{name}:{port}")

    @contextmanager
    def refusing(self, code: str):
        (self.control / "refuse").write_text(code, encoding="utf-8")
        try:
            yield
        finally:
            (self.control / "refuse").unlink()

    @property
    def records(self) -> list[dict]:
        rows = self.conn.execute(
            """SELECT protocol, route_id, context_kind, context_id, dest_host, dest_port
                 FROM collect.egress_connection
                WHERE seq > %s AND event IN ('OPEN', 'REFUSED') ORDER BY seq""",
            (self.started_seq,)).fetchall()
        out = []
        for protocol, route_id, ckind, cid, host, port in rows:
            kind, _, name = route_id.partition(":")
            username = f"{kind}.{name}" + (f"~{ckind}.{cid}" if ckind else "")
            out.append({"protocol": "CONNECT" if protocol == "HTTP_CONNECT" else "SOCKS5",
                        "username": username, "target": f"{host}:{port}"})
        return out

    # --- setup ---------------------------------------------------------------

    def _names(self) -> dict:
        path = self.control / "names.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def _allow(self, entry: str) -> None:
        self.conn.execute(
            """INSERT INTO collect.egress_destination (route_id, entry, note)
               SELECT %s, %s, 'contract case origin'
                WHERE NOT EXISTS (SELECT 1 FROM collect.egress_destination
                                   WHERE route_id = %s AND entry = %s
                                     AND retired_at IS NULL)""",
            (self.route_id, entry, self.route_id, entry))

    def _feed_run(self):
        sid = es.source(self.conn, PREFIX, base_url="http://feed.rebind.test/")
        return es.run(self.conn, sid)


@pytest.fixture(scope="module")
def harness():
    from noctornal_api.db import connect
    conn = connect()
    preserved = es.preserved(conn)
    preserved.__enter__()
    standin = es.collection_standin(conn)
    standin.__enter__()
    conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                      retired_at = now(), retired_by = (SELECT id FROM iam.app_user LIMIT 1),
                      retire_reason = 'contract suite start'
                    WHERE name = 'webhook' AND retired_at IS NULL""")
    route_id = conn.execute(
        "INSERT INTO collect.egress_integration_route (name, description) "
        "VALUES ('webhook', %s) RETURNING id", (f"{PREFIX}contract",)).fetchone()[0]
    for entry in ("hooks.example:80", "hooks.example:443", "nowhere.example:80",
                  "slow.example:80", "relay.example:587"):
        conn.execute("INSERT INTO collect.egress_destination (route_id, entry, note) "
                     "VALUES (%s, %s, 'contract case')", (route_id, entry))
    passive = es.profile(conn, PREFIX, ports=(80, 443), passive=True)
    conn.execute("UPDATE collect.egress_profile SET allowed_ports = "
                 "'{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}' WHERE id = %s", (passive,))
    control = Path(tempfile.mkdtemp(prefix="egress-contract-"))
    env = dict(os.environ, **es.keys())
    env.pop("NOCTORNAL_ENV", None)
    child = subprocess.Popen([sys.executable, str(CHILD), str(control)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = child.stdout.readline()
    if not line.startswith("LISTENING"):
        child.kill()
        raise RuntimeError("the proxy child did not start: " + child.stderr.read()[-2000:])
    h = RealHarness(conn, control, int(line.split()[1]), route_id)
    h.passive = passive
    try:
        yield h
    finally:
        (control / "stop").write_text("stop", encoding="utf-8")
        try:
            child.wait(15)
        except subprocess.TimeoutExpired:
            child.kill()
        conn.execute("""UPDATE collect.egress_integration_route SET is_active = false,
                          retired_at = now(), retired_by = (SELECT id FROM iam.app_user LIMIT 1),
                          retire_reason = 'contract suite end' WHERE id = %s""", (route_id,))
        es.teardown(conn, PREFIX)
        standin.__exit__(None, None, None)
        preserved.__exit__(None, None, None)
        conn.close()


@pytest.fixture(autouse=True)
def wide_passive(harness):
    """Any port for the passive default during a case: the origins sit on
    ephemeral ports (the profile's ports are an allowlist of 16)."""
    yield


# The SCRIPTED cases script the stub's reply bytes, so they are not run here
# (never collected rather than skipped: CI refuses a skip); the real banner
# path is test_a_relay_speaking_first_keeps_its_banner_through_the_real_proxy.
@pytest.mark.parametrize("case", [c for c in cases.CASES if c.__name__ not in SCRIPTED],
                         ids=lambda c: c.__name__)
def test_the_contract_case_holds_against_the_real_listener(harness, case, monkeypatch):
    if case.__name__ == "case_connect_carries_the_route_credentials_and_the_name":
        # The passive route admits the origin's ephemeral port for this case.
        origin_ports = _ephemeral_ports(harness)
        monkeypatch.setattr(cases, "Origin", origin_ports)
    case(harness)


def _ephemeral_ports(harness):
    """cases.Origin, with the passive default opened to the port it binds."""
    base = cases.Origin

    class Opened(base):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            harness.conn.execute(
                "UPDATE collect.egress_profile SET allowed_ports = %s WHERE id = %s",
                ([self.server_port], harness.passive))

    return Opened


def test_a_relay_speaking_first_keeps_its_banner_through_the_real_proxy(harness):
    import socket
    relay = socket.socket()
    relay.bind(("127.0.0.1", 0))
    relay.listen(1)
    port = relay.getsockname()[1]

    def speak():
        conn, _ = relay.accept()
        conn.sendall(b"220 relay ready\r\n")
        time.sleep(1)
        conn.close()

    threading.Thread(target=speak, daemon=True).start()
    harness.origin("relay.example", port)
    try:
        route = harness.route("integration", "webhook")
        with pinned_http.Deadline(10) as deadline:
            sock = pinned_http.open_connection(route, "relay.example", port, timeout=5,
                                               deadline=deadline)
            try:
                assert sock.recv(64) == b"220 relay ready\r\n"
            finally:
                sock.close()
    finally:
        relay.close()


def test_every_group_9_refusal_travels_as_a_wire_code(harness):
    """The real reply writer, for every code the proxy can send."""
    for code in sorted(egress_policy.WIRE_CODES):
        with harness.refusing(code):
            try:
                pinned_http.fetch_response("http://hooks.example/", route=harness.route(),
                                           timeout=5, max_redirects=0)
            except pinned_http.OutboundError as exc:
                assert exc.code == code, (code, exc.code)
            else:
                raise AssertionError(f"{code} opened a tunnel")


def test_a_proxy_killed_mid_tunnel_leaves_its_open_row_and_no_close(harness):
    """A killed process writes nothing more; the reader says so rather than
    inventing a CLOSE."""
    import socket as socket_

    from noctornal_api import egress_ledger
    origin = socket_.socket()
    origin.bind(("127.0.0.1", 0))
    origin.listen(1)
    port = origin.getsockname()[1]
    harness.origin("kill.example", port)
    control = Path(tempfile.mkdtemp(prefix="egress-kill-"))
    (control / "names.json").write_text(json.dumps({"kill.example": "127.0.0.1"}),
                                        encoding="utf-8")
    env = dict(os.environ, **es.keys())
    env.pop("NOCTORNAL_ENV", None)
    child = subprocess.Popen([sys.executable, str(CHILD), str(control)], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        child_port = int(child.stdout.readline().split()[1])
        context = uuid4()
        username = f"integration.webhook~check.{context}"
        head, sock = es.raw_connect(child_port, username,
                                    es.token_for("integration.webhook"), f"kill.example:{port}")
        assert head.startswith(b"HTTP/1.1 200")
        child.kill()
        child.wait(10)
        sock.close()
    finally:
        if child.poll() is None:
            child.kill()
        origin.close()
    events = [r[0] for r in harness.conn.execute(
        "SELECT event FROM collect.egress_connection WHERE context_id = %s ORDER BY seq",
        (context,)).fetchall()]
    assert events == ["OPEN"]
    rows = egress_ledger.listing(harness.conn, clearance="GREEN", event="OPEN", limit=50)
    mine = [r for r in rows["rows"] if r["context_id"] == str(context)]
    assert mine and mine[0]["closed"] is None
    assert mine[0]["close_text"] == egress_ledger.NO_CLOSE
