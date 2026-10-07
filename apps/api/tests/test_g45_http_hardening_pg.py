"""Unauthenticated input and per-element lists after the 2026-10-03 review (g45).

- http_ui-004: a bad session token appended an undeletable audit row for
  EVERY request, with no source address, at up to the blanket ceiling.
- http_ui-005: no body ceiling on JSON or form routes, so the whole body was
  buffered before authentication, validation or rate limiting.
- http_ui-006: a failed login wrote the submitted email, unbounded, into the
  append-only audit log.
- http_ui-014: a NUL in a JSON string answered 500 on several routes.
- http_ui-015: per-element lists returned every row.

Every refusal is paired with the legitimate request that must still work.
Accounts carry the prefix `g45http-`, unique to this file.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from pathlib import Path
from uuid import uuid4

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "g45http-"
PEER = "203.0.113.9"      # TEST-NET, never a real peer
ROUTERS = Path(__file__).resolve().parents[1] / "src" / "noctornal_api" / "http" / "routers"


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    cases = ("(SELECT id FROM core.\"case\" WHERE owner_user_id IN "
             f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test'))")
    c.execute("DELETE FROM core.tag_assignment WHERE tag_id IN "
              f"(SELECT id FROM core.tag WHERE case_id IN {cases})")
    for table in ("core.selector", "core.tag"):
        c.execute(f"DELETE FROM {table} WHERE case_id IN {cases}")
    # Claims that name an exhibit hold it in place, and the shared helper
    # removes exhibits before claims: so the claims go first, the way the
    # helper itself removes them (append-only trigger off, restored).
    c.execute("ALTER TABLE core.assertion DISABLE TRIGGER USER")
    try:
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {cases}")
    finally:
        c.execute("ALTER TABLE core.assertion ENABLE TRIGGER USER")
    s.cleanup(c, prefix=PREFIX)
    c.close()


@pytest.fixture
def app():
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    application = create_app()
    application.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return application


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    return TestClient(app, client=(PEER, 50000), raise_server_exceptions=False)


@pytest.fixture
def world(owner):
    """A case owner (RED), an analyst assigned as CASE_OWNER on an AMBER case."""
    lead = s.user(owner, "RED", prefix=PREFIX)
    member = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, lead)
    s.assign(owner, case_id, lead, "CASE_OWNER")
    s.assign(owner, case_id, member, "CASE_OWNER")
    _sid, raw = s.session(owner, member)
    return {"lead": lead, "member": member, "case": case_id,
            "headers": {"Authorization": f"Bearer {raw}"}, "raw": raw}


def _count(conn, sql, *params):
    return conn.execute(sql, params).fetchone()[0]


REJECTED = "SELECT count(*) FROM audit.event WHERE action = 'AUTH_SESSION_REJECTED'"


# ---------------------------------------------------------------------------
# http_ui-004
# ---------------------------------------------------------------------------

def test_a_token_that_matches_no_session_appends_nothing_and_logs_one_sampled_line(
        owner, client, caplog, monkeypatch):
    from noctornal_api.http import session_rejections as rej
    monkeypatch.setattr(rej, "_unknown", rej._Sampler())
    before = _count(owner, REJECTED)
    with caplog.at_level(logging.WARNING, logger="noctornal.api"):
        codes = {client.get("/api/v1/auth/me",
                            headers={"Authorization": f"Bearer {uuid4().hex}"}).status_code
                 for _ in range(60)}
    assert codes == {401}
    assert _count(owner, REJECTED) == before, "a bad token still appends to the audit log"
    lines = [r for r in caplog.records if "matched no session" in r.getMessage()]
    assert len(lines) == 1, "the campaign is one sampled line, not one per request"
    # A junk cookie is the same thing.
    for _ in range(5):
        r = client.get("/api/v1/auth/me", headers={"Cookie": "__Host-session=nonsense"})
        assert r.status_code == 401
    assert _count(owner, REJECTED) == before


def test_a_revoked_session_is_audited_once_per_window_with_its_source(owner, client):
    from noctornal_api.http import session_rejections as rej
    rej._window.clear()
    uid = s.user(owner, prefix=PREFIX)
    sid, raw = s.session(owner, uid)
    owner.execute("UPDATE iam.session SET revoked_at = now(), revoke_reason = 'logout' "
                  "WHERE id = %s", (sid,))
    before = _count(owner, REJECTED)
    for _ in range(12):
        assert client.get("/api/v1/auth/me",
                          headers={"Authorization": f"Bearer {raw}"}).status_code == 401
    assert _count(owner, REJECTED) == before + 1, "a held token is an unbounded stream"
    row = owner.execute(
        "SELECT detail, ip_hash FROM audit.event WHERE action = 'AUTH_SESSION_REJECTED' "
        "ORDER BY seq DESC LIMIT 1").fetchone()
    assert row[0] == {"reason": "revoked", "session_id": str(sid)}
    assert bytes(row[1]) == hashlib.sha256(PEER.encode()).digest(), "the row names no source"
    # The window ends: the next presentation is worth another row.
    rej._window.clear()
    client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}"})
    assert _count(owner, REJECTED) == before + 2
    # Another real session has its own.
    uid2 = s.user(owner, prefix=PREFIX)
    sid2, raw2 = s.session(owner, uid2)
    owner.execute("UPDATE iam.session SET expires_at = now() - interval '1 minute' "
                  "WHERE id = %s", (sid2,))
    client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw2}"})
    last = owner.execute(
        "SELECT detail FROM audit.event WHERE action = 'AUTH_SESSION_REJECTED' "
        "ORDER BY seq DESC LIMIT 1").fetchone()[0]
    assert last == {"reason": "absolute_expired", "session_id": str(sid2)}


def test_a_live_session_writes_no_rejection_and_the_window_is_bounded(owner, client):
    from noctornal_api.http import session_rejections as rej
    uid = s.user(owner, prefix=PREFIX)
    _sid, raw = s.session(owner, uid)
    before = _count(owner, REJECTED)
    assert client.get("/api/v1/auth/me",
                      headers={"Authorization": f"Bearer {raw}"}).status_code == 200
    assert _count(owner, REJECTED) == before
    window = rej._Window()
    for _ in range(rej.REMEMBERED_SESSIONS + 50):
        assert window.due(uuid4()) is True
    assert len(window._seen) <= rej.REMEMBERED_SESSIONS, "the window's memory is unbounded"


# ---------------------------------------------------------------------------
# http_ui-005
# ---------------------------------------------------------------------------

def _asgi(app, method, path, *, first=b"", chunk=b"", chunks=0, headers=(),
          declared=None, content_type=b"application/json"):
    """Drive the real ASGI app with a streamed body and report what it did:
    {status, headers, body, consumed}. `consumed` is how many bytes the app
    pulled from `receive` before it answered."""
    async def run():
        sent = 0
        consumed = 0
        out = {"status": None, "headers": {}, "body": b""}

        async def receive():
            nonlocal sent, consumed
            if sent >= max(chunks, 1):
                return {"type": "http.request", "body": b"", "more_body": False}
            part = first + chunk if sent == 0 else chunk
            sent += 1
            consumed += len(part)
            return {"type": "http.request", "body": part,
                    "more_body": sent < max(chunks, 1)}

        async def send(message):
            if message["type"] == "http.response.start":
                out["status"] = message["status"]
                out["headers"] = {k.decode().lower(): v.decode()
                                  for k, v in message["headers"]}
            elif message["type"] == "http.response.body":
                out["body"] += message.get("body", b"")

        header_list = [(b"host", b"testserver"), (b"content-type", content_type)]
        header_list += [(k.lower().encode(), v.encode()) for k, v in headers]
        if declared is not None:
            header_list.append((b"content-length", str(declared).encode()))
        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "method": method, "scheme": "http", "path": path,
                 "raw_path": path.encode(), "query_string": b"", "root_path": "",
                 "headers": header_list, "client": (PEER, 4444),
                 "server": ("testserver", 80)}
        await app(scope, receive, send)
        out["consumed"] = consumed
        return out

    return asyncio.run(run())


MIB = 1024 * 1024
CHUNK = 64 * 1024


def test_a_huge_streamed_json_body_is_refused_at_the_ceiling_not_buffered(app):
    """The review's reproduction, scaled: 100 MiB streamed at login was read
    to the end before a 422. Now it is refused once the body passes the
    ceiling, having read no more than the ceiling plus one chunk."""
    for path in ("/api/v1/auth/login", "/api/v1/cases", "/api/v1/setup/first-admin"):
        got = _asgi(app, "POST", path, first=b'{"email":"' + b"a" * (CHUNK - 10),
                    chunk=b"a" * CHUNK, chunks=1600)       # 100 MiB on offer
        assert got["status"] == 413, (path, got["status"])
        assert got["consumed"] <= MIB + CHUNK, (path, got["consumed"])
        problem = json.loads(got["body"])
        assert problem["status"] == 413 and str(MIB) in problem["detail"]
        assert got["headers"]["content-type"].startswith("application/problem+json")
        assert got["headers"]["connection"] == "close"
        assert got["headers"]["x-content-type-options"] == "nosniff", (
            "the refusal did not leave through the security headers")


def test_a_declared_length_over_the_ceiling_is_refused_before_a_byte_is_read(app):
    got = _asgi(app, "POST", "/api/v1/auth/login", first=b"{}", chunk=b"", chunks=1,
                declared=50 * MIB)
    assert got["status"] == 413
    assert got["consumed"] == 0
    assert "declared 52428800 bytes" in json.loads(got["body"])["detail"]


def test_a_lying_content_length_is_still_measured_chunk_by_chunk(app):
    got = _asgi(app, "POST", "/api/v1/auth/login", first=b'{"email":"' + b"a" * (CHUNK - 10),
                chunk=b"a" * CHUNK, chunks=64, declared=10)
    assert got["status"] == 413
    assert got["consumed"] <= MIB + CHUNK


def test_a_form_body_is_held_to_the_same_ceiling(app):
    got = _asgi(app, "POST", "/api/v1/auth/login", first=b"email=" + b"a" * (CHUNK - 6),
                chunk=b"a" * CHUNK, chunks=64,
                content_type=b"application/x-www-form-urlencoded")
    assert got["status"] == 413 and got["consumed"] <= MIB + CHUNK


def test_a_body_under_the_ceiling_reaches_its_route(app, client):
    got = _asgi(app, "POST", "/api/v1/auth/login",
                first=json.dumps({"email": "nobody@example.test", "password": "x"}).encode())
    assert got["status"] == 401
    # A large legitimate body for an ordinary route: 900 KiB of note text.
    r = client.post("/api/v1/auth/login", json={
        "email": "nobody@example.test", "password": "x" * 4000})
    assert r.status_code == 401


def test_the_two_routes_with_a_legitimately_large_json_body_keep_room(app):
    case = uuid4()
    layout = f"/api/v1/cases/{case}/graph/layout"
    capture = f"/api/v1/cases/{case}/proposals/capture"
    body = b'{"positions":["' + b"a" * (2 * MIB) + b'"]}'
    got = _asgi(app, "PUT", layout, first=body)
    assert got["status"] == 401, "2 MiB of layout was refused as too large"
    got = _asgi(app, "PUT", layout, first=b'{"positions":["' + b"a" * (5 * MIB) + b'"]}')
    assert got["status"] == 413 and "4194304" in json.loads(got["body"])["detail"]
    got = _asgi(app, "POST", capture, first=b'{"text":"' + b"a" * (3 * MIB) + b'"}')
    assert got["status"] == 401, "a 3 MiB pasted capture was refused as too large"
    got = _asgi(app, "POST", capture, first=b'{"text":"' + b"a" * (9 * MIB) + b'"}')
    assert got["status"] == 413 and "8388608" in json.loads(got["body"])["detail"]


def test_a_route_that_reads_its_own_body_after_authenticating_is_left_alone(app):
    """The ingest submit authenticates the key FIRST and reads the body
    against the key's own cap: an unauthenticated 2 MiB body is a 401 and is
    never read, not a 413 from the default ceiling."""
    got = _asgi(app, "POST", "/api/v1/ingest", first=b"x" * (2 * MIB),
                content_type=b"text/csv",
                headers=[("authorization", "Bearer not-a-key")])
    assert got["status"] == 401, got["status"]
    assert got["consumed"] == 0, "the body of an unauthenticated submission was read"


def test_the_upload_routes_keep_their_own_caps_under_the_middleware(app):
    """BodyCappedRoute still decides for evidence: a declared length over its
    cap is a 413 naming its cap, not the default's."""
    from noctornal_api.http.routers.evidence import MAX_EVIDENCE_BYTES
    got = _asgi(app, "POST", f"/api/v1/cases/{uuid4()}/evidence",
                content_type=b"multipart/form-data; boundary=x",
                declared=MAX_EVIDENCE_BYTES + 1, first=b"--x--")
    assert got["status"] == 413
    assert str(MAX_EVIDENCE_BYTES) in json.loads(got["body"])["detail"]


def test_requests_without_a_body_and_the_static_console_are_untouched(client):
    assert client.get("/healthz").status_code == 200
    assert client.get("/ui/").status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


# ---------------------------------------------------------------------------
# http_ui-006
# ---------------------------------------------------------------------------

def _failed_login_row(conn, marker: str):
    return conn.execute(
        "SELECT detail, outcome, octet_length(detail::text) FROM audit.event "
        "WHERE action = 'AUTH_FAILED' AND detail->>'email' LIKE %s "
        "ORDER BY seq DESC LIMIT 1", (marker + "%",)).fetchone()


def test_a_failed_login_records_a_bounded_email_and_is_denied(owner, client):
    short = f"g45http-{uuid4().hex[:8]}@example.test"
    r = client.post("/api/v1/auth/login", json={
        "email": short, "password": "x", "totp_code": "000000"})
    assert r.status_code == 401
    detail, outcome, _size = _failed_login_row(owner, short[:20])
    assert detail["email"] == short and "email_sha256" not in detail
    assert outcome == "DENIED", "a refused sign-in was recorded as a success"

    marker = f"g45http-{uuid4().hex[:8]}"
    longest = marker + "A" * (254 - len(marker) - len("@example.test")) + "@example.test"
    assert len(longest) == 254
    r = client.post("/api/v1/auth/login", json={
        "email": longest, "password": "x", "totp_code": "000000"})
    assert r.status_code == 401
    detail, outcome, size = _failed_login_row(owner, marker)
    assert detail["email"] == longest[:64]
    assert detail["email_length"] == 254
    assert detail["email_sha256"] == hashlib.sha256(longest.encode()).hexdigest()[:16]
    assert outcome == "DENIED" and size < 400


@pytest.mark.parametrize("body", [
    {"email": "e" * 255, "password": "x"},
    {"email": "a@b.test", "password": "p" * 4097},
    {"email": "a@b.test", "password": "x", "totp_code": "1" * 65},
    {"email": "a@b.test", "password": "x", "new_password": "p" * 4097},
], ids=["email", "password", "totp", "new_password"])
def test_the_login_fields_are_bounded(owner, client, body):
    before = _count(owner, "SELECT count(*) FROM audit.event WHERE action = 'AUTH_FAILED'")
    r = client.post("/api/v1/auth/login", json=body)
    assert r.status_code == 422
    assert _count(owner, "SELECT count(*) FROM audit.event WHERE action = 'AUTH_FAILED'") == before


def test_a_three_mebibyte_email_is_refused_and_nothing_is_stored(owner, client):
    marker = f"g45http-{uuid4().hex[:8]}"
    r = client.post("/api/v1/auth/login", json={
        "email": marker + "A" * (3 * MIB) + "@example.test", "password": "x"})
    assert r.status_code == 413
    assert _failed_login_row(owner, marker) is None


def test_the_password_change_body_is_bounded_too(client, world):
    r = client.post("/api/v1/auth/password", headers=world["headers"], json={
        "current_password": "c" * 4097, "totp_code": "000000", "new_password": "n" * 20})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# http_ui-014
# ---------------------------------------------------------------------------

NUL_BODIES = [
    ("assumptions", "/assumptions", {"statement": "a\u0000b"}),
    ("curation sets", "/curation/sets", {"name": "a\u0000b"}),
    ("node check", "/graph/nodes/check", {"node_type": "IDENTITY", "label": "a\u0000b"}),
]


@pytest.mark.parametrize("name,suffix,body", NUL_BODIES, ids=[n[0] for n in NUL_BODIES])
def test_a_nul_in_a_json_string_is_a_422_not_a_500(client, world, name, suffix, body):
    r = client.post(f"/api/v1/cases/{world['case']}{suffix}", headers=world["headers"],
                    json=body)
    assert r.status_code == 422, r.text
    assert "NUL" in r.json()["detail"]
    assert r.headers["content-type"].startswith("application/problem+json")


def test_a_nul_split_across_chunks_is_still_found(app):
    body = b'{"statement":"a\\u00' + b"00b\"}"
    first, rest = body[:18], body[18:]
    # Two chunks, the escape cut in the middle.
    async def run():
        out = {}
        parts = [first, rest]
        sent = 0

        async def receive():
            nonlocal sent
            part = parts[sent] if sent < len(parts) else b""
            sent += 1
            return {"type": "http.request", "body": part, "more_body": sent < len(parts)}

        async def send(message):
            if message["type"] == "http.response.start":
                out["status"] = message["status"]

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "method": "POST", "scheme": "http", "path": f"/api/v1/cases/{uuid4()}/assumptions",
                 "raw_path": b"", "query_string": b"", "root_path": "",
                 "headers": [(b"host", b"testserver"), (b"content-type", b"application/json")],
                 "client": (PEER, 4444), "server": ("testserver", 80)}
        await app(scope, receive, send)
        return out["status"]
    assert asyncio.run(run()) == 422


def test_an_escaped_backslash_followed_by_text_is_not_a_nul(client, world):
    """JSON `"a\\\\u0000b"` is a backslash, then the text u0000b: storable, so
    the check must not refuse it."""
    r = client.post(f"/api/v1/cases/{world['case']}/assumptions",
                    headers={**world["headers"], "content-type": "application/json"},
                    content=b'{"statement":"a\\\\u0000b"}')
    assert r.status_code == 201, r.text
    r = client.post(f"/api/v1/cases/{world['case']}/assumptions",
                    headers={**world["headers"], "content-type": "application/json"},
                    content=b'{"statement":"plain text, nothing odd"}')
    assert r.status_code == 201, r.text


@pytest.mark.parametrize("suffix,param", [
    ("/search", "q"), ("/search/nodes", "q"), ("/search/selectors", "q"),
    ("/search/evidence", "q"), ("/evidence", "q"), ("/nodes", "node_type"),
    ("/comms/co-declared", "reference"),
], ids=lambda v: v if isinstance(v, str) else None)
def test_a_nul_the_json_check_cannot_see_is_a_422_too(client, world, suffix, param):
    """A query string reaches Postgres without a body, so the middleware
    never sees it: a sweep of every GET route taking a string parameter
    found fourteen that answered 500 on base (this is seven of them). The
    DataError handler is what turns it into a 422."""
    r = client.get(f"/api/v1/cases/{world['case']}{suffix}", headers=world["headers"],
                   params={param: "a\u0000b", **({"limit": 5} if suffix == "/nodes" else {})})
    assert r.status_code == 422, (suffix, r.status_code, r.text)
    assert r.headers["content-type"].startswith("application/problem+json")
    assert "NUL" in r.json()["detail"] or "cannot be stored" in r.json()["detail"]
    # And the same route with ordinary text still works.
    ok = client.get(f"/api/v1/cases/{world['case']}{suffix}", headers=world["headers"],
                    params={param: "plain text", **({"reference": "x"} if suffix.endswith("co-declared") else {})})
    assert ok.status_code != 500


# ---------------------------------------------------------------------------
# http_ui-015
# ---------------------------------------------------------------------------

def _seed_node_with_claims(owner, world, extra):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    lead = world["lead"]
    node = s.node(owner, world["case"], lead, "many claims")
    for i in range(extra):
        GraphWriteService(owner).add_assertion(
            case_id=world["case"], node_id=node,
            assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=lead,
                                     rationale=f"claim {i}"))
    return node


def test_node_assertions_page_and_cap(owner, client, world):
    node = _seed_node_with_claims(owner, world, 5)          # six claims in all
    base = f"/api/v1/cases/{world['case']}/nodes/{node}/assertions"
    h = world["headers"]
    everything = client.get(base, headers=h).json()
    assert len(everything) == 6
    first = client.get(base, headers=h, params={"limit": 2}).json()
    second = client.get(base, headers=h, params={"limit": 2, "offset": 2}).json()
    last = client.get(base, headers=h, params={"limit": 2, "offset": 4}).json()
    assert [a["id"] for a in first + second + last] == [a["id"] for a in everything]
    assert client.get(base, headers=h, params={"limit": 0}).status_code == 422
    assert client.get(base, headers=h, params={"limit": 1001}).status_code == 422
    assert client.get(base, headers=h, params={"offset": -1}).status_code == 422


def test_edge_assertions_and_node_selectors_page(owner, client, world):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.selectors import SelectorStore
    lead, case_id = world["lead"], world["case"]
    a = s.node(owner, case_id, lead, "end one")
    b = s.node(owner, case_id, lead, "end two")
    edge = s.edge(owner, case_id, lead, a, b)
    for i in range(3):
        GraphWriteService(owner).add_assertion(
            case_id=case_id, edge_id=edge,
            assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=lead,
                                     rationale=f"tie claim {i}"))
    for i in range(4):
        SelectorStore(owner).record(case_id=case_id, selector_type="EMAIL",
                                    raw_value=f"g45-{i}@example.test", node_id=a)
    h = world["headers"]
    url = f"/api/v1/cases/{case_id}/edges/{edge}/assertions"
    assert len(client.get(url, headers=h).json()) == 4
    assert len(client.get(url, headers=h, params={"limit": 3}).json()) == 3
    url = f"/api/v1/cases/{case_id}/nodes/{a}/selectors"
    assert len(client.get(url, headers=h).json()) == 4
    page = client.get(url, headers=h, params={"limit": 3, "offset": 3}).json()
    assert len(page) == 1
    assert client.get(url, headers=h, params={"limit": 1001}).status_code == 422


def test_tags_sets_and_members_page_with_exact_withheld(owner, client, world):
    from noctornal_api.curation import NodeSetService, TagService
    lead, case_id = world["lead"], world["case"]
    h = world["headers"]
    for i in range(5):
        TagService(owner).create_tag(namespace="g45", name=f"tag{i}", case_id=case_id)
    set_ids = [NodeSetService(owner).create_set(case_id=case_id, name=f"set{i}",
                                                created_by=lead) for i in range(4)]
    nodes = [s.node(owner, case_id, lead, f"member {i}") for i in range(4)]
    hidden = s.node(owner, case_id, lead, "red member", "RED")
    for n in nodes + [hidden]:
        NodeSetService(owner).add_member(set_ids[0], n)
    tags = client.get(f"/api/v1/cases/{case_id}/curation/tags", headers=h,
                      params={"include_global": "false"}).json()
    assert len(tags) == 5
    assert len(client.get(f"/api/v1/cases/{case_id}/curation/tags", headers=h,
                          params={"include_global": "false", "limit": 2, "offset": 4}).json()) == 1
    assert len(client.get(f"/api/v1/cases/{case_id}/curation/sets", headers=h).json()) == 4
    assert len(client.get(f"/api/v1/cases/{case_id}/curation/sets", headers=h,
                          params={"limit": 3}).json()) == 3
    url = f"/api/v1/cases/{case_id}/curation/sets/{set_ids[0]}/members"
    # the exact count is said only under COUNT (rls-9, 2026-10-03): this test is
    # about paging, so the case declares COUNT
    owner.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                  ("COUNT", case_id))
    whole = client.get(url, headers=h).json()
    # The RED member is the caller's `withheld`, and stays exactly that.
    assert len(whole["members"]) == 4 and whole["withheld"] == 1
    assert whole["members_total"] == 4 and whole["truncated"] is False
    # The member list is paged; the count of what the caller may not see is
    # not changed by the page, and the page says it is not the whole set.
    page = client.get(url, headers=h, params={"limit": 2}).json()
    assert len(page["members"]) == 2 and page["truncated"] is True
    assert page["members_total"] == 4 and page["withheld"] == 1
    rest = client.get(url, headers=h, params={"limit": 2, "offset": 2}).json()
    assert [m["node_id"] for m in page["members"] + rest["members"]] == [
        m["node_id"] for m in whole["members"]]
    assert client.get(url, headers=h, params={"limit": 0}).status_code == 422


def test_a_nodes_tags_and_evidence_page(owner, client, world):
    from noctornal_api.curation import TagService
    from noctornal_api.graph import AssertionInput, GraphWriteService
    lead, case_id = world["lead"], world["case"]
    h = world["headers"]
    node = s.node(owner, case_id, lead, "tagged and evidenced")
    for i in range(3):
        tag = TagService(owner).create_tag(namespace="g45", name=f"nodetag{i}", case_id=case_id)
        TagService(owner).assign(tag, assigned_by=lead, node_id=node)
        exhibit = s.exhibit(owner, case_id, lead)
        GraphWriteService(owner).add_assertion(
            case_id=case_id, node_id=node,
            assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=lead,
                                     evidence_id=exhibit, rationale=f"exhibit {i}"))
    tags = f"/api/v1/cases/{case_id}/curation/nodes/{node}/tags"
    assert len(client.get(tags, headers=h).json()) == 3
    assert [len(client.get(tags, headers=h, params={"limit": 2, "offset": o}).json())
            for o in (0, 2)] == [2, 1]
    evidence = f"/api/v1/cases/{case_id}/nodes/{node}/evidence"
    whole = client.get(evidence, headers=h).json()
    assert len(whole) == 3
    first = client.get(evidence, headers=h, params={"limit": 2}).json()
    rest = client.get(evidence, headers=h, params={"limit": 2, "offset": 2}).json()
    assert [e["id"] for e in first + rest] == [e["id"] for e in whole]
    for url in (tags, evidence):
        assert client.get(url, headers=h, params={"limit": 0}).status_code == 422
        assert client.get(url, headers=h, params={"limit": 1001}).status_code == 422


def _fake_comms(monkeypatch, **returns):
    from noctornal_api.comms import CommsService
    for name, value in returns.items():
        monkeypatch.setattr(CommsService, name, lambda self, *a, _v=value, **k: list(_v))


@pytest.mark.parametrize("path,method,extra,key,field", [
    ("co-declared", "co_declared", {"reference": "r"}, "identifiers", "identifiers"),
    ("shared-devices", "shared_devices", {}, "leads", "leads"),
    ("contact-graph", "contact_graph", {}, "conversations", "conversations"),
], ids=["co-declared", "shared-devices", "contact-graph"])
def test_the_comms_lists_are_capped_and_say_so(client, world, monkeypatch,
                                               path, method, extra, key, field):
    _fake_comms(monkeypatch, **{method: [{"n": i} for i in range(7)]})
    base = f"/api/v1/cases/{world['case']}/comms/{path}"
    h = world["headers"]
    capped = client.get(base, headers=h, params={**extra, "limit": 3}).json()
    assert len(capped[key]) == 3 and capped["truncated"] is True
    whole = client.get(base, headers=h, params=extra).json()
    assert len(whole[key]) == 7 and whole["truncated"] is False
    assert client.get(base, headers=h, params={**extra, "limit": 1001}).status_code == 422


def test_the_correlate_and_impersonation_lists_are_capped(client, world, monkeypatch):
    from noctornal_api.comms import CommsService
    from noctornal_api.contact_blocks import ContactBlockService
    monkeypatch.setattr(CommsService, "correlate_handle",
                        lambda self, *a, **k: [{"n": i} for i in range(7)], raising=False)
    monkeypatch.setattr(ContactBlockService, "impersonation_candidates",
                        lambda self, *a, **k: [{"n": i} for i in range(7)])
    h = world["headers"]
    imp = client.get(f"/api/v1/cases/{world['case']}/comms/impersonation", headers=h,
                     params={"limit": 2}).json()
    assert len(imp["candidates"]) == 2 and imp["truncated"] is True


def test_the_co_participation_projection_keeps_the_strongest_ties_and_says_so(
        client, world, monkeypatch):
    from noctornal_api.coparticipation import CoParticipationService
    nodes = [{"key": f"n{i}", "kind": "HANDLE", "label": f"n{i}", "node_id": None}
             for i in range(6)]
    edges = [{"src": f"n{i}", "dst": f"n{i + 1}", "weight": w, "shared_conversations": 1,
              "is_inferred": True, "inference_method": "co_participation/NEWMAN"}
             for i, w in enumerate([0.1, 0.9, 0.2, 0.8, 0.3])]
    fake = {"projection": {}, "nodes": nodes, "edges": edges,
            "coverage": {"conversations_seen": 5}, "reading": "x"}
    monkeypatch.setattr(CoParticipationService, "project",
                        lambda self, p: json.loads(json.dumps(fake)))
    base = f"/api/v1/cases/{world['case']}/comms/co-participation"
    h = world["headers"]
    capped = client.get(base, headers=h, params={"limit": 2}).json()
    assert capped["truncated"] is True
    assert [e["weight"] for e in capped["edges"]] == [0.9, 0.8]
    assert {n["key"] for n in capped["nodes"]} == {"n1", "n2", "n3", "n4"}
    assert capped["coverage"]["edges_total"] == 5 and capped["coverage"]["edges_returned"] == 2
    whole = client.get(base, headers=h).json()
    assert whole["truncated"] is False and len(whole["edges"]) == 5
    assert len(whole["nodes"]) == 6 and "edges_total" not in whole["coverage"]


def test_no_router_takes_a_limit_above_1000_except_the_two_recorded_exceptions():
    """CONVENTIONS.md: `le=1000`. Two case-wide lists are exempt on the
    record (the edge list at 2000, the projected graph at 5000); a new one
    over 1000 has to be added here and to CONVENTIONS.md on purpose."""
    found = []
    for path in sorted(ROUTERS.glob("*.py")):
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"limit\s*:\s*int\s*=\s*Query\([^)]*le\s*=\s*([0-9_]+)", text):
            if int(m.group(1).replace("_", "")) > 1000:
                found.append((path.name, int(m.group(1).replace("_", ""))))
    assert sorted(found) == [("graphview.py", 5000), ("read.py", 2000)], found


# ---------------------------------------------------------------------------
# Beta 1 verification, Group G (2026-10-07)
# ---------------------------------------------------------------------------

BS = "\\"


def _json_with(basis: str) -> bytes:
    """An assumption body whose `basis` holds `basis` as the JSON TEXT given
    (escapes included), so a lone surrogate reaches the server as the six
    characters a peer would type, which `json=` cannot send."""
    return ('{"statement":"ok","basis":"' + basis + '"}').encode("ascii")


LONE_SURROGATES = [
    ("low alone", BS + "udc00"),
    ("high alone", BS + "ud800"),
    ("high then text", BS + "ud800x"),
    ("high then a non-surrogate escape", BS + "ud800" + BS + "u0041"),
    ("reversed pair", BS + "udc00" + BS + "ud800"),
    ("two highs", BS + "ud800" + BS + "ud800"),
    ("upper case hex", BS + "uDBFF"),
    ("after an escaped backslash pair", BS * 4 + BS + "udfff"),
]


@pytest.mark.parametrize("name,basis", LONE_SURROGATES, ids=[n for n, _ in LONE_SURROGATES])
def test_a_lone_surrogate_escape_is_a_422_not_a_500(client, world, name, basis):
    """G1 (verifier u4): `{"statement":"ok","basis":"\\udc00"}` reached
    Postgres as text no encoding can hold and answered 500 with a logged
    UnicodeEncodeError. Fields with a length bound happened to answer 422."""
    r = client.post(f"/api/v1/cases/{world['case']}/assumptions",
                    headers={**world["headers"], "content-type": "application/json"},
                    content=_json_with(basis))
    assert r.status_code == 422, (name, r.status_code, r.text)
    assert "surrogate" in r.json()["detail"]
    assert r.headers["content-type"].startswith("application/problem+json")


def test_a_lone_surrogate_in_a_key_or_a_constrained_field_is_a_422_too(client, world):
    h = {**world["headers"], "content-type": "application/json"}
    url = f"/api/v1/cases/{world['case']}/assumptions"
    assert client.post(url, headers=h, content=(
        '{"statement":"ok","' + BS + 'ud800":1}').encode()).status_code == 422
    assert client.post(url, headers=h, content=(
        '{"statement":"' + BS + 'udc00"}').encode()).status_code == 422


@pytest.mark.parametrize("basis", [
    BS + "ud83d" + BS + "ude00",            # a properly paired emoji
    BS + "uD83D" + BS + "uDE00 and text",   # upper case, then more text
    BS * 2 + "ud800",                       # a literal backslash, then text
    BS * 2 + BS + "ud83d" + BS + "ude00",   # a literal backslash, then a pair
    "plain text, nothing odd",
], ids=["pair", "pair_upper", "escaped_backslash", "backslash_then_pair", "plain"])
def test_a_properly_paired_surrogate_and_an_escaped_backslash_are_still_accepted(
        client, world, basis):
    r = client.post(f"/api/v1/cases/{world['case']}/assumptions",
                    headers={**world["headers"], "content-type": "application/json"},
                    content=_json_with(basis))
    assert r.status_code == 201, (basis, r.status_code, r.text)


def test_a_lone_surrogate_in_a_body_the_middleware_cannot_read_is_still_a_422(client, world):
    """The second line, as the DataError handler is for a NUL: a JSON body
    sent as UTF-16 hides the escape from the byte scan, and the handler
    for the encoding failure answers it."""
    body = _json_with(BS + "ud800").decode("ascii").encode("utf-16")
    r = client.post(f"/api/v1/cases/{world['case']}/assumptions",
                    headers={**world["headers"], "content-type": "application/json"},
                    content=body)
    assert r.status_code == 422, (r.status_code, r.text)
    assert r.headers["content-type"].startswith("application/problem+json")


def _multipart_head(boundary: str = "x") -> bytes:
    return (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
            f"filename=\"a.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            ).encode()


def _capped_routes():
    """Every (method, concrete path, endpoint) whose endpoint carries a
    `@body_cap`, read off the router modules so a route added later is
    covered. The paths are driven through the app below, so a router that
    is not mounted answers 404 and fails there."""
    import importlib
    import pkgutil

    from fastapi.routing import APIRoute

    from noctornal_api.http import routers
    from noctornal_api.http.app import API_PREFIX
    found = {}
    for info in pkgutil.iter_modules(routers.__path__):
        module = importlib.import_module(f"noctornal_api.http.routers.{info.name}")
        for route in getattr(getattr(module, "router", None), "routes", ()):
            endpoint = getattr(route, "endpoint", None)
            if not isinstance(route, APIRoute) or not getattr(endpoint, "__body_cap__", None):
                continue
            path = API_PREFIX + re.sub(r"\{[^}]+\}", lambda _m: str(uuid4()), route.path)
            found[(sorted(route.methods)[0], path)] = endpoint
    return [(m, p, e) for (m, p), e in found.items()]


def test_the_capped_upload_routes_are_found():
    names = {endpoint.__name__ for _m, _p, endpoint in _capped_routes()}
    assert {"upload", "submit", "upload_email", "add_version", "verify",
            "import_pgp_key", "import_screening_list", "similar_by_value",
            "search_documents_similar", "download", "produce"} <= names, names


def test_an_unauthenticated_upload_is_refused_before_a_byte_is_read(app, client):
    """G2 (verifier u4): FastAPI parses a form before any dependency runs,
    and Starlette spools the parse to disk, so 300 MiB streamed at
    `POST /cases/{id}/evidence` with no credential was read up to the
    route's 256 MiB cap before the 401 (the API container has no tmpfs
    /tmp and the proxy sets no body limit). The refusal is now the middleware's,
    ahead of the first read, and says what the route's own 401 says."""
    own = client.get(f"/api/v1/cases/{uuid4()}")
    assert own.status_code == 401
    mp = b"multipart/form-data; boundary=x"
    for method, path, endpoint in _capped_routes():
        if getattr(endpoint, "__body_credential__", False):
            continue
        got = _asgi(app, method, path, first=_multipart_head() + b"a" * CHUNK,
                    chunk=b"a" * CHUNK, chunks=4800, content_type=mp)   # 300 MiB on offer
        assert got["status"] == 401, (path, got["status"])
        assert got["consumed"] == 0, (path, got["consumed"], "an unauthenticated body was read")
        assert json.loads(got["body"]) == own.json(), (path, got["body"])
        assert got["headers"]["content-type"].startswith("application/problem+json")
        assert got["headers"]["x-content-type-options"] == "nosniff"


def test_the_refusal_is_the_route_own_401_for_every_way_of_presenting_nothing(app):
    path = f"/api/v1/cases/{uuid4()}/evidence"
    mp = b"multipart/form-data; boundary=x"
    for headers in ([], [("authorization", "Basic YTpi")], [("authorization", "Bearer ")],
                    [("authorization", "Bearer    ")], [("cookie", "other=1")],
                    [("cookie", "__Host-session=")]):
        got = _asgi(app, "POST", path, first=_multipart_head(), chunk=b"a" * CHUNK,
                    chunks=64, content_type=mp, headers=headers)
        assert got["status"] == 401 and got["consumed"] == 0, (headers, got["status"],
                                                               got["consumed"])
        assert json.loads(got["body"])["detail"] == "no session token"


def test_a_request_that_presents_any_credential_reads_as_it_always_did(app):
    """The pre-read check is only about presenting NOTHING: a bearer or the
    session cookie is read by the route and judged there (the rest of this
    suite and test_body_caps_http_pg cover what comes after)."""
    path = f"/api/v1/cases/{uuid4()}/evidence"
    mp = b"multipart/form-data; boundary=x"
    for headers in ([("authorization", f"Bearer {uuid4().hex}")],
                    [("cookie", f"__Host-session={uuid4().hex}")]):
        got = _asgi(app, "POST", path, first=_multipart_head(), chunk=b"a" * CHUNK,
                    chunks=8, content_type=mp, headers=headers)
        assert got["status"] in (401, 403), (headers, got["status"])
        assert got["consumed"] > 0, (headers, "the body was refused unread")


def test_the_two_ticket_routes_take_their_credential_from_the_body_and_are_left_alone(app):
    """A one-shot ticket in the form body IS the credential of a sample or
    exhibit download on the sample origin, where no session exists: the
    pre-read check must not turn a ticket away as an unauthenticated upload."""
    tickets = [(m, p, e) for m, p, e in _capped_routes()
               if getattr(e, "__body_credential__", False)]
    assert {e.__name__ for _m, _p, e in tickets} == {"download", "produce"}
    for method, path, _endpoint in tickets:
        got = _asgi(app, method, path, first=b"ticket=not-a-real-ticket",
                    content_type=b"application/x-www-form-urlencoded")
        assert got["consumed"] > 0, (path, "the ticket was never read")
        assert got["status"] in (401, 409), (path, got["status"])
        assert b"no session token" not in got["body"], path


def test_an_unauthenticated_declared_length_over_the_cap_is_still_the_413(app):
    """Unchanged order: a declared length over the cap is answered before a
    byte is read, whoever asks; the 401 is for a body that fits."""
    from noctornal_api.http.routers.evidence import MAX_EVIDENCE_BYTES
    got = _asgi(app, "POST", f"/api/v1/cases/{uuid4()}/evidence",
                content_type=b"multipart/form-data; boundary=x",
                declared=MAX_EVIDENCE_BYTES + 1, first=b"--x--")
    assert got["status"] == 413 and got["consumed"] == 0


def _failed_login_by_hash(conn, digest: str):
    return conn.execute(
        "SELECT detail, outcome FROM audit.event WHERE action = 'AUTH_FAILED' "
        "AND detail->>'email_sha256' = %s ORDER BY seq DESC LIMIT 1", (digest,)).fetchone()


def test_a_password_typed_into_the_email_box_is_not_stored(owner, client):
    """G5 (verifier u4, http_ui-006): the 'email' of a failed sign-in was
    kept verbatim up to 64 characters, so a password typed into the wrong
    box for an unknown account sat in the append-only log in clear."""
    typed = f"g45http-pw-{uuid4().hex[:6]}-Hunter2-typed-in-email-box"
    assert len(typed) <= 64
    r = client.post("/api/v1/auth/login", json={"email": typed, "password": "x"})
    assert r.status_code == 401
    digest = hashlib.sha256(typed.encode()).hexdigest()[:16]
    detail, outcome = _failed_login_by_hash(owner, digest)
    assert "email" not in detail and typed not in json.dumps(detail)
    assert detail["email_length"] == len(typed) and detail["email_sha256"] == digest
    assert detail["reason"] == "unknown_user" and outcome == "DENIED"
    # An address still names its officer: kept as typed.
    real = f"g45http-{uuid4().hex[:8]}@example.test"
    client.post("/api/v1/auth/login", json={"email": real, "password": "x"})
    detail, _outcome, _size = _failed_login_row(owner, real[:20])
    assert detail["email"] == real and "email_sha256" not in detail


@pytest.mark.parametrize("value,kept", [
    ("analyst@agency.example.org", True),
    ("a.b+tag@sub.example.test", True),
    ("Hunter2 is my password", False),
    ("correct-horse-battery-staple", False),
    ("two@signs@example.test", False),
    ("nodomain@localhost", False),
    ("spaced out@example.test", False),
    ("trailing@example.test ", False),
    ("new\nline@example.test", False),
    ("@example.test", False),
    ("x@.", False),
    ("", False),
], ids=lambda v: repr(v)[:30])
def test_only_an_address_shaped_value_is_recorded_as_typed(value, kept):
    from noctornal_api.http.routers.auth import _audit_email
    got = _audit_email(value)
    if kept:
        assert got == {"email": value}
    else:
        assert "email" not in got
        assert got == {"email_length": len(value),
                       "email_sha256": hashlib.sha256(value.encode()).hexdigest()[:16]}


def test_a_long_address_keeps_its_head_and_a_long_non_address_keeps_nothing():
    from noctornal_api.http.routers.auth import AUDIT_EMAIL_CHARS, _audit_email
    long_address = "a" * 70 + "@example.test"
    got = _audit_email(long_address)
    assert got["email"] == long_address[:AUDIT_EMAIL_CHARS]
    assert got["email_length"] == len(long_address)
    secret = "pw" * 40
    got = _audit_email(secret)
    assert "email" not in got and got["email_length"] == 80
    assert secret[:8] not in json.dumps(got)
