"""The first-run door needs proof of possession (http_ui-010 and infra-3; g45, 2026-10-03).

`POST /setup/first-admin` made the first caller SYS_ADMIN, SECURITY_OFFICER
and RED-cleared and handed back the password and the TOTP secret, so on an
internet-facing fresh deployment (Caddy publishes 80 and 443 as soon as the
API is up; the hostname is in certificate-transparency logs within seconds)
whoever called first owned it. Now:

- production with NO `NOCTORNAL_SETUP_TOKEN`: the route does not exist (404,
  the answer an unknown path gives) and the console never offers the card;
- a token configured: the request must carry it in `X-Setup-Token`;
- outside production with no token: unchanged, the door is open while the
  table is empty (a laptop, CI).

The table is not empty in the shared development database, so the emptiness
the route tests is narrowed to this file's own accounts (`g45setup-`),
which is the real rule applied to a smaller table. Accounts are created for
real by the route and removed afterwards.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "g45setup-"
PEER = "203.0.113.55"
TOKEN = "t" * 12 + "0123456789abcdef" * 2          # 44 characters
URL = "/api/v1/setup/first-admin"


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    c.execute("DELETE FROM iam.session WHERE user_id IN "
              f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%')")
    s.cleanup(c, prefix=PREFIX)
    c.close()


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    from noctornal_api import iam_admin
    from noctornal_api.http.app import create_app
    from noctornal_api.http.routers import setup as setup_router
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter

    def empty(conn) -> bool:
        return conn.execute("SELECT count(*) FROM iam.app_user WHERE email LIKE %s",
                            (PREFIX + "%",)).fetchone()[0] == 0

    monkeypatch.setattr(iam_admin, "needs_setup", empty)
    monkeypatch.setattr(setup_router, "needs_setup", empty)
    monkeypatch.delenv("NOCTORNAL_SETUP_TOKEN", raising=False)
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, client=(PEER, 52000), raise_server_exceptions=False)


@pytest.fixture
def production(monkeypatch):
    from noctornal_api.http import setup_token
    monkeypatch.setattr(setup_token, "_production", lambda: True)


def _body():
    return {"email": f"{PREFIX}{uuid4().hex[:8]}@noctornal.test", "display_name": "First Admin"}


def _accounts(owner) -> int:
    return owner.execute("SELECT count(*) FROM iam.app_user WHERE email LIKE %s",
                         (PREFIX + "%",)).fetchone()[0]


def test_in_production_with_no_token_the_door_does_not_exist(owner, client, production):
    unknown = client.post("/api/v1/setup/no-such-door", json=_body())
    got = client.post(URL, json=_body())
    assert got.status_code == 404
    # Indistinguishable from an unknown path: same status, type and body.
    assert (got.status_code, got.headers["content-type"], got.json()) == (
        unknown.status_code, unknown.headers["content-type"], unknown.json())
    assert client.post(URL, json=_body(),
                       headers={"X-Setup-Token": TOKEN}).status_code == 404
    assert _accounts(owner) == 0
    # The console is not invited to show the first-run card.
    assert client.get("/api/v1/setup/status").json() == {
        "needs_setup": False, "setup_token_required": False}


def test_in_production_a_token_is_required_and_only_the_right_one_opens_it(
        owner, client, production, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_SETUP_TOKEN", TOKEN)
    assert client.get("/api/v1/setup/status").json() == {
        "needs_setup": True, "setup_token_required": True}
    for headers in ({}, {"X-Setup-Token": ""}, {"X-Setup-Token": "wrong"},
                    {"X-Setup-Token": TOKEN[:-1]}, {"X-Setup-Token": TOKEN + "x"},
                    {"X-Setup-Token": TOKEN.upper()}):
        r = client.post(URL, json=_body(), headers=headers)
        assert r.status_code == 403, (headers, r.status_code, r.text)
        assert TOKEN not in r.text
    assert _accounts(owner) == 0, "a refused request created an account"
    # A caller without the token learns nothing from a malformed body either.
    assert client.post(URL, json={"email": 5}).status_code == 403

    ok = client.post(URL, json=_body(), headers={"X-Setup-Token": TOKEN})
    assert ok.status_code == 201, ok.text
    creds = ok.json()
    assert creds["password"] and creds["totp_secret"]
    roles = {r[0] for r in owner.execute(
        "SELECT role_key FROM iam.user_role WHERE user_id = %s", (creds["user_id"],))}
    assert {"SYS_ADMIN", "SECURITY_OFFICER"} <= roles
    # The door shuts behind the first account, token or no token.
    again = client.post(URL, json=_body(), headers={"X-Setup-Token": TOKEN})
    assert again.status_code == 409
    assert client.get("/api/v1/setup/status").json()["needs_setup"] is False


def test_guessing_the_token_spends_the_sign_in_failure_meter(owner, client, production,
                                                            monkeypatch):
    monkeypatch.setenv("NOCTORNAL_SETUP_TOKEN", TOKEN)
    statuses = [client.post(URL, json=_body(), headers={"X-Setup-Token": f"guess-{i}"}).status_code
                for i in range(40)]
    assert statuses[0] == 403
    assert 429 in statuses, "unlimited guesses at the setup token"
    # Once the meter is spent even the right token waits, as a password does.
    assert client.post(URL, json=_body(), headers={"X-Setup-Token": TOKEN}).status_code == 429
    assert _accounts(owner) == 0


def test_outside_production_with_no_token_the_door_is_as_it_was(owner, client):
    assert client.get("/api/v1/setup/status").json() == {
        "needs_setup": True, "setup_token_required": False}
    r = client.post(URL, json=_body())
    assert r.status_code == 201, r.text
    assert client.post(URL, json=_body()).status_code == 409


def test_a_token_set_outside_production_is_honoured_too(owner, client, monkeypatch):
    monkeypatch.setenv("NOCTORNAL_SETUP_TOKEN", TOKEN)
    assert client.post(URL, json=_body()).status_code == 403
    assert client.post(URL, json=_body(), headers={"X-Setup-Token": TOKEN}).status_code == 201


def test_the_first_admin_fields_are_bounded(client):
    for body in ({"email": "e" * 255, "display_name": "x"},
                 {"email": "a@b.test", "display_name": "n" * 201}):
        assert client.post(URL, json=body).status_code == 422


def test_the_comparison_is_constant_time_and_never_raises_on_odd_input(monkeypatch):
    import inspect

    from noctornal_api.http import setup_token
    monkeypatch.setenv("NOCTORNAL_SETUP_TOKEN", TOKEN)
    assert setup_token.matches(TOKEN) is True
    for presented in (None, "", "x", "é" * 44, "\ud800", TOKEN + " "):
        assert setup_token.matches(presented) is False
    assert "hmac.compare_digest" in inspect.getsource(setup_token.matches)
    monkeypatch.delenv("NOCTORNAL_SETUP_TOKEN")
    assert setup_token.matches(TOKEN) is False, "a token matched while none is configured"
    monkeypatch.setenv("NOCTORNAL_SETUP_TOKEN", "   ")
    assert setup_token.configured_token() is None


def test_production_is_read_from_the_environment_exactly_as_the_boot_check_reads_it(
        monkeypatch):
    from noctornal_api.http import setup_token
    monkeypatch.setenv("NOCTORNAL_ENV", " Production ")
    assert setup_token.door_closed() is True
    monkeypatch.setenv("NOCTORNAL_ENV", "prod")
    assert setup_token.door_closed() is False   # the boot check's own sharp edge
    monkeypatch.delenv("NOCTORNAL_ENV")
    assert setup_token.door_closed() is False
    monkeypatch.setenv("NOCTORNAL_ENV", "production")
    monkeypatch.setenv("NOCTORNAL_SETUP_TOKEN", TOKEN)
    assert setup_token.door_closed() is False and setup_token.token_required() is True


def test_a_production_boot_refuses_a_short_token_and_accepts_a_long_one_or_none():
    from noctornal_api.config import verify_environment
    base = {"NOCTORNAL_ENV": "production"}

    def refusals(**extra):
        return [p for p in verify_environment({**base, **extra})
                if "NOCTORNAL_SETUP_TOKEN" in p]

    short = refusals(NOCTORNAL_SETUP_TOKEN="abc123")
    assert len(short) == 1 and "shorter than 32" in short[0]
    assert "abc123" not in short[0], "the refusal quotes the value"
    assert refusals(NOCTORNAL_SETUP_TOKEN=TOKEN) == []
    assert refusals() == []
    assert refusals(NOCTORNAL_SETUP_TOKEN="  ") == []
    # Development is never refused: the boot check is production only.
    assert verify_environment({"NOCTORNAL_SETUP_TOKEN": "abc"}) == []


def test_the_operators_documents_say_how():
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    readme = (root / "infra" / "production" / "README.md").read_text(encoding="utf-8")
    example = (root / "infra" / "production" / "secrets.env.example").read_text(encoding="utf-8")
    for needle in ("NOCTORNAL_SETUP_TOKEN", "X-Setup-Token", "openssl rand -hex 32",
                   "bootstrap.py create-user"):
        assert needle in readme, needle
    assert "x-setup-token" in readme.lower()
    # The curl example reads a shell variable; the README must say to set it
    # (2026-10-03).
    assert "export NOCTORNAL_SETUP_TOKEN" in readme
    assert "# NOCTORNAL_SETUP_TOKEN=" in example, "the example must ship it commented out"
    assert "\nNOCTORNAL_SETUP_TOKEN=" not in example
    assert os.path.exists(root / "scripts" / "bootstrap.py")


# ---------------------------------------------------------------------------
# A closed door is indistinguishable from no door for EVERY request shape
# (2026-10-03)
# ---------------------------------------------------------------------------
#
# The first version closed the door in the route's dependency, which FastAPI
# runs after it has read the body and validated the headers, so a closed door
# answered 404 only to a well-formed request: invalid JSON got a 422, a long
# X-Setup-Token header a 422, a body over the 1 MiB ceiling a 413, a GET a 405
# and a trailing slash a redirect, where an unknown path answers each with the
# plain 404. `ClosedSetupDoor` answers the path before anything is read.

_JSON = {"content-type": "application/json"}
_OK_BODY = '{"email":"a@b.test","display_name":"x"}'
_SHAPES = {
    "valid body": ("POST", "", dict(content=_OK_BODY, headers=_JSON)),
    "invalid json": ("POST", "", dict(content="{", headers=_JSON)),
    "empty body": ("POST", "", dict(content="", headers=_JSON)),
    "no content type": ("POST", "", dict(content=_OK_BODY)),
    "token header over 512 characters": (
        "POST", "", dict(content=_OK_BODY, headers={**_JSON, "X-Setup-Token": "t" * 600})),
    "body over the ceiling": (
        "POST", "", dict(content='{"email":"' + "a" * (2 * 1024 * 1024) + '"}', headers=_JSON)),
    "declared length over the ceiling": (
        "POST", "", dict(content=_OK_BODY,
                         headers={**_JSON, "content-length": str(3 * 1024 * 1024)})),
    "form body": ("POST", "", dict(content="email=a", headers={
        "content-type": "application/x-www-form-urlencoded"})),
    "nul escape": ("POST", "", dict(content=r'{"email":"a\u0000b"}', headers=_JSON)),
    "trailing slash": ("POST", "/", dict(content=_OK_BODY, headers=_JSON)),
    "get": ("GET", "", {}),
    "get with trailing slash": ("GET", "/", {}),
    "put": ("PUT", "", dict(content=_OK_BODY, headers=_JSON)),
    "delete": ("DELETE", "", {}),
    "head": ("HEAD", "", {}),
    "options": ("OPTIONS", "", {}),
}


def _signature(response):
    return (response.status_code, response.headers.get("content-type"), response.content,
            sorted(k for k in response.headers if k != "date"))


@pytest.mark.parametrize("shape", list(_SHAPES), ids=list(_SHAPES))
def test_a_closed_door_answers_every_request_shape_as_an_unknown_path_does(
        owner, client, production, shape):
    method, suffix, kwargs = _SHAPES[shape]
    door = client.request(method, URL + suffix, follow_redirects=False, **kwargs)
    unknown = client.request(method, "/api/v1/setup/no-such-door" + suffix,
                             follow_redirects=False, **kwargs)
    assert door.status_code == 404, (shape, door.status_code, door.text[:120])
    assert _signature(door) == _signature(unknown), (
        shape, _signature(door)[:2], _signature(unknown)[:2])
    assert _accounts(owner) == 0


def test_the_gate_is_the_routes_own_path_and_the_innermost_middleware():
    """The gate takes its path from the router rather than a copy of it, so a
    renamed route cannot leave the door unguarded, and it is registered first
    so that the body ceiling, which wraps it, never sees a byte."""
    from noctornal_api.http.app import API_PREFIX, create_app
    from noctornal_api.http.routers import setup as setup_router
    from noctornal_api.http.setup_token import ClosedSetupDoor

    app = create_app()
    route = next(r for r in setup_router.router.routes
                 if r.endpoint is setup_router.first_admin)
    assert API_PREFIX + route.path == URL
    assert app.user_middleware[-1].cls is ClosedSetupDoor, "not the innermost middleware"
    assert app.user_middleware[-1].kwargs["path"] == URL


def test_a_closed_door_never_reads_the_request():
    """The point of the gate: a body that is never asked for cannot be too
    large, malformed or poisoned. The wrapped app and `receive` both fail the
    test if touched."""
    import asyncio

    from noctornal_api.http import setup_token

    async def never(*_a, **_k):
        raise AssertionError("the closed door read the request or called the app")

    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "POST", "path": URL, "root_path": "",
             "headers": [(b"content-length", b"999999999")], "query_string": b""}
    gate = setup_token.ClosedSetupDoor(never, path=URL)
    os.environ["NOCTORNAL_ENV"] = "production"
    os.environ.pop(setup_token.SETUP_TOKEN_ENV, None)
    try:
        asyncio.run(gate(scope, never, send))
    finally:
        os.environ.pop("NOCTORNAL_ENV", None)
    assert sent[0]["status"] == 404
    assert sent[1]["body"] == b'{"detail":"Not Found"}'


def test_the_gate_stands_aside_whenever_the_door_is_not_closed(owner, client, production,
                                                              monkeypatch):
    """Production with a token, and any environment without one that is not
    production, reach the route (its own 403, 201 and 409 are tested above);
    and a path that is not the door's is never intercepted."""
    monkeypatch.setenv("NOCTORNAL_SETUP_TOKEN", TOKEN)
    assert client.post(URL, json=_body()).status_code == 403
    assert client.post(URL + "/", json=_body(), follow_redirects=False).status_code in (307, 308)
    assert client.get("/api/v1/setup/status").status_code == 200
    assert client.post("/api/v1/setup/no-such-door", json=_body()).status_code == 404
    assert _accounts(owner) == 0


def test_the_gate_honours_a_root_path():
    """Behind a proxy that strips a prefix the router matches the path
    without `root_path`; the gate must compare the same string."""
    from noctornal_api.http import setup_token
    assert setup_token._route_path({"path": "/edge" + URL, "root_path": "/edge"}) == URL
    assert setup_token._route_path({"path": URL, "root_path": ""}) == URL
    assert setup_token._route_path({"path": "/elsewhere" + URL, "root_path": "/edge"}) == (
        "/elsewhere" + URL)
