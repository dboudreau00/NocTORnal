"""End-to-end HTTP tests: the full analyst journey over the API, plus the
401/403 paths.

This is the test that proves the wiring — services are already unit-tested,
what matters here is that authentication, the five-part gate, problem+json
errors and the routers actually compose. Env-gated on DATABASE_URL (+ MINIO
for the evidence leg).
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; HTTP e2e is gated"
)

PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'e2e-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    psub = f"(SELECT id FROM analytics.projection WHERE case_id IN {csub})"
    rsub = f"(SELECT id FROM analytics.metric_run WHERE projection_id IN {psub})"
    with c.transaction():
        c.execute("ALTER TABLE core.evidence_custody DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence_custody WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node_merge_edge WHERE merge_id IN "
                  f"(SELECT id FROM core.node_merge WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.node_merge WHERE case_id IN {csub}")
        # An analytics run materialises a projection and its metrics, both of
        # which reference the case. They are cleaned up here rather than by a
        # cascade because a cascading delete on `case` is exactly what
        # invariant 6 and the retention design forbid in production.
        c.execute(f"DELETE FROM analytics.node_metric WHERE metric_run_id IN {rsub}")
        c.execute(f"DELETE FROM analytics.community_assignment WHERE metric_run_id IN {rsub}")
        c.execute(f"DELETE FROM analytics.metric_run WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.layout_position WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.projection WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'e2e-%@noctornal.test'")
        c.execute("ALTER TABLE core.evidence_custody ENABLE TRIGGER USER")
    c.close()


def _isolated_limiter(**overrides):
    """A rate limiter this test alone owns.

    The default limiter is backed by Redis when REDIS_URL is set, and Redis
    is shared, persistent and blind to test boundaries -- so one test's
    logins would spend the next test's budget and the suite would pass or
    fail depending on the order it ran in. A flaky security test is a
    deleted security test. The Redis path has its own proof in
    test_ratelimit_redis.py; what the e2e suite proves is the wiring.

    Pass overrides to shrink a limit so a test can reach it in three
    requests rather than a hundred.
    """
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    catalogue = dict(LIMITS)
    catalogue.update(overrides)
    return RateLimiter(InProcessBackend(), limits=catalogue)


@pytest.fixture
def client():
    from fastapi.testclient import TestClient
    from noctornal_api.http.app import create_app
    app = create_app()
    app.state.limiter = _isolated_limiter()
    return TestClient(app)


def _make_user(conn, *, clearance="AMBER", global_roles=(), compartments=()):
    """A user with TOTP enrolled, returning (user_id, email, totp_secret)."""
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"e2e-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "E2E", PASSWORD)
    secret = totp.generate_secret()
    store.enroll_totp(uid, secret)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s WHERE id = %s",
        (clearance, list(compartments), uid),
    )
    for role in global_roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role),
        )
    return uid, email, secret


def _login(client, email, secret) -> str:
    import time

    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time())),
    })
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _create_case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-E2E-{uuid4().hex[:6]}", "title": "Operation E2E",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)),
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


# --- authentication -----------------------------------------------------

def test_login_requires_totp(conn, client):
    _, email, _ = _make_user(conn)
    r = client.post("/api/v1/auth/login",
                    json={"email": email, "password": PASSWORD})
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")
    # Generic: the body must not reveal that the password was correct.
    assert "totp" not in r.text.lower() and "password" not in r.text.lower()


def test_login_then_me(conn, client):
    uid, email, secret = _make_user(conn)
    token = _login(client, email, secret)
    r = client.get("/api/v1/auth/me", headers=_auth(token))
    assert r.status_code == 200 and r.json()["user_id"] == str(uid)


def test_bad_token_rejected(client):
    r = client.get("/api/v1/auth/me", headers=_auth("not-a-real-token"))
    assert r.status_code == 401


def test_logout_revokes_session(conn, client):
    _, email, secret = _make_user(conn)
    token = _login(client, email, secret)
    assert client.post("/api/v1/auth/logout", headers=_auth(token)).status_code == 204
    assert client.get("/api/v1/auth/me", headers=_auth(token)).status_code == 401


# --- the analyst journey ------------------------------------------------

def test_case_create_requires_global_permission(conn, client):
    """A user with no global role cannot create a case (403), even
    authenticated — case.create is a global verb."""
    _, email, secret = _make_user(conn)  # no global roles
    token = _login(client, email, secret)
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-E2E-{uuid4().hex[:6]}", "title": "nope",
        "legal_basis": "x", "retention_until": "2028-01-01",
        "review_due": "2027-01-01",
    })
    assert r.status_code == 403
    assert r.headers["content-type"].startswith("application/problem+json")


def test_full_journey_case_node_edge_search(conn, client):
    """Create a case, add two nodes and an edge (each carrying an
    assertion), then find one by full-text search — the Phase 1 bar."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)

    n1 = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
        "node_type": "IDENTITY", "label": "bassterlord the broker",
        "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "B",
                      "credibility": "2"},
    })
    assert n1.status_code == 201, n1.text
    n2 = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
        "node_type": "GROUP", "label": "TestCrew",
        "assertion": {"basis": "DIRECT_OBSERVATION"},
    })
    assert n2.status_code == 201

    e = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
        "edge_type": "MEMBER_OF", "src_node_id": n1.json()["id"],
        "dst_node_id": n2.json()["id"],
        "assertion": {"basis": "DIRECT_OBSERVATION", "rationale": "membership post"},
    })
    assert e.status_code == 201, e.text

    # Invariant 1: the edge has a supporting assertion.
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE edge_id = %s", (e.json()["id"],)
    ).fetchone()[0] == 1

    s = client.get(f"/api/v1/cases/{case_id}/search/nodes",
                   headers=_auth(token), params={"q": "broker"})
    assert s.status_code == 200
    assert n1.json()["id"] in [h["id"] for h in s.json()]


def test_illegal_edge_is_400_not_500(conn, client):
    """An ontology violation surfaces as problem+json 400, not a leaked
    stack trace or SQL error."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    grp = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                      json={"node_type": "GROUP", "label": "crew"}).json()["id"]
    idn = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                      json={"node_type": "IDENTITY", "label": "member"}).json()["id"]
    # VOUCHED_FOR is IDENTITY->IDENTITY; a GROUP source is illegal.
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
        "edge_type": "VOUCHED_FOR", "src_node_id": grp, "dst_node_id": idn,
    })
    assert r.status_code == 400
    assert r.headers["content-type"].startswith("application/problem+json")
    assert "Traceback" not in r.text


def test_selector_recorded_and_found_normalised(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    rec = client.post(f"/api/v1/cases/{case_id}/selectors", headers=_auth(token),
                      json={"selector_type": "TELEGRAM_USER", "raw_value": "@DarkVendor"})
    assert rec.status_code == 201, rec.text
    assert rec.json()["norm_value"] == "darkvendor"
    # Found by a differently-cased query — the API normalises the lookup.
    got = client.get(f"/api/v1/cases/{case_id}/selectors", headers=_auth(token),
                     params={"selector_type": "TELEGRAM_USER", "value": "darkVENDOR"})
    assert got.status_code == 200 and got.json()["id"] == rec.json()["id"]


# --- authorization boundaries -------------------------------------------

def test_outsider_cannot_read_or_detect_another_users_case(conn, client):
    """A caller with no relationship to a case must not even learn it
    EXISTS: the response for a real case they are not assigned to is
    identical to the response for a random id."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)

    _, out_email, out_secret = _make_user(conn)
    out_token = _login(client, out_email, out_secret)
    real = client.get(f"/api/v1/cases/{case_id}", headers=_auth(out_token))
    fake = client.get(f"/api/v1/cases/{uuid4()}", headers=_auth(out_token))
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()          # no existence oracle
    assert client.get("/api/v1/cases", headers=_auth(out_token)).json() == []


def test_read_only_assignee_cannot_write(conn, client):
    """READ_ONLY may read the case but not create nodes (verb check)."""
    from noctornal_api.cases import CaseService
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)

    reader_id, reader_email, reader_secret = _make_user(conn)
    CaseService(conn).assign_user(case_id, reader_id, "READ_ONLY",
                                 granted_by=reader_id)
    reader_token = _login(client, reader_email, reader_secret)
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(reader_token)).status_code == 200
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(reader_token),
                    json={"node_type": "IDENTITY", "label": "sneaky"})
    assert r.status_code == 403


def test_under_cleared_assignee_denied_by_lattice(conn, client):
    """Clearance is a hard ceiling: a GREEN-cleared analyst assigned to an
    AMBER case is denied (the TLP check), even with the right verb."""
    from noctornal_api.cases import CaseService
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)  # AMBER

    green_id, green_email, green_secret = _make_user(conn, clearance="GREEN")
    CaseService(conn).assign_user(case_id, green_id, "ANALYST", granted_by=green_id)
    green_token = _login(client, green_email, green_secret)
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(green_token)).status_code == 403


def test_unknown_case_is_404(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.get(f"/api/v1/cases/{uuid4()}", headers=_auth(token))
    assert r.status_code == 404


def test_under_cleared_assignee_is_not_listed(conn, client):
    """The listing must return exactly what the gate would allow: an
    assigned-but-under-cleared analyst sees an empty list, not the case
    code, title and legal basis."""
    from noctornal_api.cases import CaseService
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)          # AMBER
    green_id, green_email, green_secret = _make_user(conn, clearance="GREEN")
    CaseService(conn).assign_user(case_id, green_id, "ANALYST", granted_by=green_id)
    green_token = _login(client, green_email, green_secret)
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(green_token)).status_code == 403
    assert client.get("/api/v1/cases", headers=_auth(green_token)).json() == []


def test_compartmented_case_hidden_from_uncompartmented_assignee(conn, client):
    """Need-to-know: an assignee without the case compartment sees it
    neither in the listing nor in detail, and cannot reach its evidence —
    the leg that passed vacuously before, because an uploaded exhibit
    carries no compartments of its own so the case must supply them."""
    from noctornal_api.cases import CaseService
    owner_id, owner_email, owner_secret = _make_user(
        conn, clearance="AMBER", global_roles=("CASE_OWNER",), compartments=("OP_X",))
    owner_token = _login(client, owner_email, owner_secret)
    r = client.post("/api/v1/cases", headers=_auth(owner_token), json={
        "code": f"OP-E2E-{uuid4().hex[:6]}", "title": "Compartmented Op",
        "legal_basis": "warrant", "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)), "compartments": ["OP_X"],
    })
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]

    plain_id, plain_email, plain_secret = _make_user(conn, clearance="AMBER")
    CaseService(conn).assign_user(case_id, plain_id, "ANALYST", granted_by=owner_id)
    plain_token = _login(client, plain_email, plain_secret)
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(plain_token)).status_code == 403
    assert client.get("/api/v1/cases", headers=_auth(plain_token)).json() == []
    if MINIO:
        up = client.post(
            f"/api/v1/cases/{case_id}/evidence", headers=_auth(owner_token),
            files={"file": ("c.txt", b"compartmented", "text/plain")},
            data={"title": "compartmented exhibit"},
        )
        assert up.status_code == 201, up.text
        ev_id = up.json()["evidence_id"]
        assert client.get(f"/api/v1/cases/{case_id}/evidence/{ev_id}/content",
                          headers=_auth(plain_token)).status_code == 403


def test_cannot_create_case_in_a_compartment_you_lack(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-E2E-{uuid4().hex[:6]}", "title": "nope",
        "legal_basis": "x", "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)), "compartments": ["OP_SECRET"],
    })
    assert r.status_code == 400 and "compartment" in r.text


def test_cannot_author_above_your_clearance(conn, client):
    """The write ceiling: an AMBER analyst cannot create a RED node it
    would immediately be unable to read back."""
    _, email, secret = _make_user(conn, clearance="AMBER",
                                  global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
        "node_type": "IDENTITY", "label": "too secret", "classification": "RED",
    })
    assert r.status_code == 403 and "clearance" in r.text


def test_over_classified_element_is_invisible_in_search(conn, client):
    """Discovery respects the lattice: a RED node label must not reach an
    AMBER analyst through search, even in an AMBER case."""
    from noctornal_api.cases import CaseService
    owner_id, owner_email, owner_secret = _make_user(
        conn, clearance="RED", global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)          # AMBER case
    red = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(owner_token),
                      json={"node_type": "IDENTITY", "label": "informant truename",
                            "classification": "RED"})
    assert red.status_code == 201, red.text

    amber_id, amber_email, amber_secret = _make_user(conn, clearance="AMBER")
    CaseService(conn).assign_user(case_id, amber_id, "ANALYST", granted_by=owner_id)
    amber_token = _login(client, amber_email, amber_secret)
    hits = client.get(f"/api/v1/cases/{case_id}/search/nodes",
                      headers=_auth(amber_token), params={"q": "informant"})
    assert hits.status_code == 200
    assert red.json()["id"] not in [h["id"] for h in hits.json()]
    # The cleared owner does see it.
    owner_hits = client.get(f"/api/v1/cases/{case_id}/search/nodes",
                            headers=_auth(owner_token), params={"q": "informant"})
    assert red.json()["id"] in [h["id"] for h in owner_hits.json()]


def test_validation_error_does_not_echo_password(conn, client):
    """A 422 must not reflect submitted credentials back — they would land
    in every proxy and APM access log."""
    r = client.post("/api/v1/auth/login",
                    json={"password": "S3cret-Horse", "totp_code": "418293"})
    assert r.status_code == 422
    assert "S3cret-Horse" not in r.text and "418293" not in r.text


def test_db_error_does_not_leak_schema_internals(conn, client):
    """An unknown node type must not return the constraint name, the
    offending value, or PL/pgSQL context."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                    json={"node_type": "NOT_A_TYPE", "label": "x"})
    assert r.status_code == 400
    body = r.text
    for leaked in ("node_node_type_fkey", "DETAIL:", "CONTEXT:", "PL/pgSQL",
                   "NOT_A_TYPE", "Traceback"):
        assert leaked not in body, f"leaked {leaked!r}"


def test_session_rejection_reason_is_not_disclosed(conn, client):
    """A revoked token and a nonsense token must be indistinguishable."""
    _, email, secret = _make_user(conn)
    token = _login(client, email, secret)
    client.post("/api/v1/auth/logout", headers=_auth(token))
    revoked = client.get("/api/v1/auth/me", headers=_auth(token))
    bogus = client.get("/api/v1/auth/me", headers=_auth("nonsense-token"))
    assert revoked.status_code == bogus.status_code == 401
    assert revoked.json() == bogus.json()
    assert "revoked" not in revoked.text and "not_found" not in revoked.text


def test_logout_revokes_only_the_presenting_session(conn, client):
    """Closing one device must not evict the analyst everywhere."""
    from uuid import uuid4 as _uuid4

    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid, email, secret = _make_user(conn)
    desktop = _login(client, email, secret)
    # The second session is minted directly: logging in twice would need a
    # fresh TOTP step (the replay guard is doing its job), and sleeping 30s
    # to prove an unrelated property is not worth the wall clock.
    _, laptop = SessionService(PgSessionStore(conn)).create(
        _uuid4(), uid, mfa_satisfied=True
    )
    assert client.post("/api/v1/auth/logout",
                       headers=_auth(desktop)).status_code == 204
    assert client.get("/api/v1/auth/me", headers=_auth(desktop)).status_code == 401
    assert client.get("/api/v1/auth/me", headers=_auth(laptop)).status_code == 200


def test_login_events_are_audited(conn, client):
    """Authentication success and failure both reach the audit chain."""
    uid, email, secret = _make_user(conn)
    client.post("/api/v1/auth/login",
                json={"email": email, "password": "wrong", "totp_code": "000000"})
    _login(client, email, secret)
    actions = [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE detail->>'email' = %s "
        "OR actor_id = %s ORDER BY seq", (email, uid),
    ).fetchall()]
    assert "AUTH_FAILED" in actions and "AUTH_SUCCEEDED" in actions


def test_authz_denial_is_audited(conn, client):
    """A denied request records WHICH checks failed, server-side only."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner_token = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner_token)
    reader_id, reader_email, reader_secret = _make_user(conn)
    from noctornal_api.cases import CaseService
    CaseService(conn).assign_user(case_id, reader_id, "READ_ONLY", granted_by=reader_id)
    reader_token = _login(client, reader_email, reader_secret)
    client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(reader_token),
                json={"node_type": "IDENTITY", "label": "nope"})
    row = conn.execute(
        "SELECT detail FROM audit.event WHERE action = 'AUTHZ_DENIED' "
        "AND actor_id = %s ORDER BY seq DESC LIMIT 1", (reader_id,),
    ).fetchone()
    assert row is not None
    assert row[0]["permission"] == "graph.node.create"
    assert "role_grants_permission" in row[0]["failed_checks"]


def test_negative_limit_is_422_not_500(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    r = client.get(f"/api/v1/cases/{case_id}/search/nodes", headers=_auth(token),
                   params={"q": "x", "limit": -1})
    assert r.status_code == 422


def test_cross_case_selector_node_rejected(conn, client):
    """A selector cannot be attributed to a node in another case."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_a = _create_case(client, token)
    case_b = _create_case(client, token)
    node_b = client.post(f"/api/v1/cases/{case_b}/nodes", headers=_auth(token),
                         json={"node_type": "IDENTITY", "label": "in b"}).json()["id"]
    r = client.post(f"/api/v1/cases/{case_a}/selectors", headers=_auth(token),
                    json={"selector_type": "HANDLE", "raw_value": "x",
                          "node_id": node_b})
    assert r.status_code == 400 and "case" in r.text


def test_status_transition_and_illegal_transition(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    ok = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(token),
                     json={"status": "ACTIVE"})
    assert ok.status_code == 200 and ok.json()["status"] == "ACTIVE"
    bad = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(token),
                      json={"status": "PURGED"})
    assert bad.status_code == 400


# --- evidence leg (needs MinIO) -----------------------------------------

@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required")
def test_evidence_upload_download_custody_and_link(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    node_id = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                          json={"node_type": "IDENTITY", "label": "subject"}).json()["id"]

    payload = b"exhibit-" + uuid4().hex.encode()
    up = client.post(
        f"/api/v1/cases/{case_id}/evidence", headers=_auth(token),
        files={"file": ("shot.png", payload, "image/png")},
        data={"title": "ransom note screenshot", "acquisition_method": "MANUAL_UPLOAD"},
    )
    assert up.status_code == 201, up.text
    ev_id = up.json()["evidence_id"]

    dl = client.get(f"/api/v1/cases/{case_id}/evidence/{ev_id}/content",
                    headers=_auth(token))
    assert dl.status_code == 200 and dl.content == payload
    assert "attachment" in dl.headers["content-disposition"]

    assert client.post(f"/api/v1/cases/{case_id}/evidence/{ev_id}/verify",
                       headers=_auth(token)).json()["ok"] is True

    link = client.post(f"/api/v1/cases/{case_id}/evidence/{ev_id}/links",
                       headers=_auth(token), json={"node_id": node_id,
                                                   "relevance": "depicts subject"})
    assert link.status_code == 204

    cust = client.get(f"/api/v1/cases/{case_id}/evidence/{ev_id}/custody",
                      headers=_auth(token))
    actions = [e["action"] for e in cust.json()]
    assert "ACQUIRED" in actions and "VIEWED" in actions and "HASH_VERIFIED" in actions

    found = client.get(f"/api/v1/cases/{case_id}/search/evidence",
                       headers=_auth(token), params={"q": "ransom"})
    assert ev_id in [h["id"] for h in found.json()]


@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required")
def test_export_requires_fresh_mfa_step_up(conn, client):
    """evidence.export is a step-up permission: it works on a fresh
    session, and 403s once the session's MFA clock goes stale — the fifth
    gate check, over HTTP."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    up = client.post(
        f"/api/v1/cases/{case_id}/evidence", headers=_auth(token),
        files={"file": ("a.txt", b"export-" + uuid4().hex.encode(), "text/plain")},
        data={"title": "exportable"},
    )
    ev_id = up.json()["evidence_id"]

    # Fresh MFA (set at login) → allowed.
    assert client.post(f"/api/v1/cases/{case_id}/evidence/{ev_id}/export",
                       headers=_auth(token)).status_code == 200

    # Age the session's MFA past the 15-minute step-up window.
    conn.execute(
        "UPDATE iam.session SET mfa_satisfied_at = now() - interval '20 minutes' "
        "WHERE user_id = (SELECT id FROM iam.app_user WHERE email = %s)",
        (email,),
    )
    stale = client.post(f"/api/v1/cases/{case_id}/evidence/{ev_id}/export",
                        headers=_auth(token))
    assert stale.status_code == 403
    # A plain read is unaffected — only step-up permissions re-challenge.
    assert client.get(f"/api/v1/cases/{case_id}/evidence/{ev_id}/content",
                      headers=_auth(token)).status_code == 200


@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required")
def test_red_evidence_export_refused(conn, client):
    """Invariant 8 over HTTP: RED evidence may not cross the boundary,
    even for a fully cleared owner with fresh MFA."""
    _, email, secret = _make_user(conn, clearance="RED", global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-E2E-{uuid4().hex[:6]}", "title": "Red Op",
        "legal_basis": "warrant", "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)), "classification": "RED",
    })
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    up = client.post(
        f"/api/v1/cases/{case_id}/evidence", headers=_auth(token),
        files={"file": ("s.txt", b"red-" + uuid4().hex.encode(), "text/plain")},
        data={"title": "sensitive", "classification": "RED"},
    )
    assert up.status_code == 201, up.text
    ev_id = up.json()["evidence_id"]
    # Reading inside the boundary is fine; exporting out of it is refused.
    assert client.get(f"/api/v1/cases/{case_id}/evidence/{ev_id}/content",
                      headers=_auth(token)).status_code == 200
    refused = client.post(f"/api/v1/cases/{case_id}/evidence/{ev_id}/export",
                          headers=_auth(token))
    assert refused.status_code == 400
    assert "invariant 8" in refused.text


# --- rate limiting ------------------------------------------------------

def _limited(app, **overrides):
    """Point a live app at a shrunk catalogue."""
    app.state.limiter = _isolated_limiter(**overrides)
    return app


def _tiny(name, **kwargs):
    from noctornal_api.ratelimit import LIMITS, Limit
    base = LIMITS[name]
    fields = {"name": name, "quota": base.quota, "per_seconds": base.per_seconds,
              "scope": base.scope, "burst": base.effective_burst,
              "on_backend_failure": base.on_backend_failure}
    fields.update(kwargs)
    return Limit(**fields)


def test_login_failures_are_rate_limited_by_source(conn, client):
    """The anti-spraying brake. IP-scoped and cheap to trip on failures, so
    it survives the attacker cycling the email — and deliberately NOT
    email-scoped, which would let anyone lock a named analyst out just by
    sending their address.

    The refusal must carry Retry-After: a 429 that does not say when to
    come back makes a compliant client indistinguishable from a hammering
    one.
    """
    _limited(client.app, **{
        "auth.login_failed": _tiny("auth.login_failed", quota=3, per_seconds=300,
                                   burst=3)})
    codes = []
    for i in range(8):
        r = client.post("/api/v1/auth/login", json={
            # A different email every time: the meter is on the SOURCE.
            "email": f"spray-{i}@noctornal.test", "password": "wrong",
            "totp_code": "000000",
        })
        codes.append(r.status_code)
        if r.status_code == 429:
            assert int(r.headers["Retry-After"]) >= 1
            assert r.headers["content-type"].startswith("application/problem+json")
    assert codes[0] == 401, "the first attempts must reach the authenticator"
    assert 429 in codes, "an unlimited login endpoint is a CPU amplifier"


def _seed_small_graph(client, token, case_id) -> None:
    """Three actors and two ties. Analytics over an EMPTY case is a 422
    ("cannot compute"), which is correct behaviour and useless as a
    baseline for a rate-limit test."""
    ids = []
    for label in ("alpha", "bravo", "charlie"):
        r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
            "node_type": "IDENTITY", "label": label,
            "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "B",
                          "credibility": "2"},
        })
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    for src, dst in ((0, 1), (1, 2)):
        r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
            "edge_type": "VOUCHED_FOR", "src_node_id": ids[src],
            "dst_node_id": ids[dst],
            "assertion": {"basis": "DIRECT_OBSERVATION", "rationale": "vouched"},
        })
        assert r.status_code == 201, r.text


def test_a_successful_login_does_not_move_the_failure_meter(conn, client):
    """The property that makes an IP-scoped login control usable at all.

    The customer is an organisation behind ONE egress address: two hundred
    analysts signing on within ten minutes of 09:00 look, to any per-IP
    counter, exactly like an attack. Metering failures instead of attempts
    is what separates them — a building full of correct passwords moves
    nothing, and a sprayer produces nothing else.

    The failure budget here is exactly ONE. A success is spent first; if it
    consumed the failure meter, the very next bad password would already be
    429 instead of reaching the authenticator.

    (One success, not several: TOTP codes are single-use by design — the
    counter advance is a compare-and-set that rejects a replay — so a loop
    of logins inside one 30-second step is not a thing this system permits.)
    """
    _limited(client.app, **{
        "auth.login_failed": _tiny("auth.login_failed", quota=1, per_seconds=300,
                                   burst=1)})
    _, email, secret = _make_user(conn)
    _login(client, email, secret)  # asserts 200 internally

    bad = {"email": email, "password": "wrong", "totp_code": "000000"}
    assert client.post("/api/v1/auth/login", json=bad).status_code == 401,         "the success must not have spent the failure budget"
    assert client.post("/api/v1/auth/login", json=bad).status_code == 429,         "but the failure must have"


def test_the_rate_limit_denial_is_audited_once_not_once_per_request(conn, client):
    """audit.event is append-only and hash-chained, and the chain trigger
    takes an advisory lock so rows serialise. Auditing every denial would
    let a caller who is ALREADY being throttled convert rejected requests
    into unbounded, undeletable, serialised writes — handing an attacker a
    better denial of service than the one being blocked. One row per window
    records the campaign; the count lives in the access log.
    """
    # ONLY the failure meter is shrunk, and the attempt meter is widened out
    # of the way. Both limits audit once per window, so leaving the attempt
    # meter at its real burst of 20 would put a second (correct) row in the
    # count and make this assert 2 for a reason that is not what it tests.
    _limited(client.app, **{
        "auth.login_failed": _tiny("auth.login_failed", quota=2, per_seconds=300,
                                   burst=2),
        "auth.login": _tiny("auth.login", quota=1000, per_seconds=60, burst=1000)})
    before = conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'RATE_LIMIT_EXCEEDED'"
    ).fetchone()[0]
    for i in range(25):
        client.post("/api/v1/auth/login", json={
            "email": f"flood-{i}@noctornal.test", "password": "wrong",
            "totp_code": "000000"})
    after = conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'RATE_LIMIT_EXCEEDED'"
    ).fetchone()[0]
    assert after > before, "a spraying campaign must leave a trace"
    assert after - before == 1, "and exactly one, not one per rejected request"


def test_analytics_is_rate_limited_per_user(conn, client):
    """decision 30 accepted a CPU-bound path behind a non-step-up
    permission as a known DoS surface, pending exactly this."""
    _limited(client.app, **{
        "analytics.suite": _tiny("analytics.suite", quota=3, per_seconds=300,
                                 burst=3)})
    _, email, secret = _make_user(conn, clearance="RED", global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    codes = [client.get(f"/api/v1/cases/{case_id}/analytics",
                        headers=_auth(token)).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3:] == [429, 429]


def test_one_analysts_flood_does_not_lock_out_another(conn, client):
    """Per-USER metering, asserted rather than assumed. Address-scoping this
    would meter a whole police force behind one NAT as a single caller, so
    one analyst's scripted loop would take the team offline."""
    _limited(client.app, **{
        "analytics.suite": _tiny("analytics.suite", quota=2, per_seconds=300,
                                 burst=2)})
    _, email_a, secret_a = _make_user(conn, clearance="RED",
                                      global_roles=("CASE_OWNER",))
    _, email_b, secret_b = _make_user(conn, clearance="RED",
                                      global_roles=("CASE_OWNER",))
    token_a = _login(client, email_a, secret_a)
    case_a = _create_case(client, token_a)
    _seed_small_graph(client, token_a, case_a)
    for _ in range(4):
        client.get(f"/api/v1/cases/{case_a}/analytics", headers=_auth(token_a))
    assert client.get(f"/api/v1/cases/{case_a}/analytics",
                      headers=_auth(token_a)).status_code == 429

    token_b = _login(client, email_b, secret_b)
    case_b = _create_case(client, token_b)
    _seed_small_graph(client, token_b, case_b)
    assert client.get(f"/api/v1/cases/{case_b}/analytics",
                      headers=_auth(token_b)).status_code == 200


def test_successful_responses_carry_the_limit_headers(conn, client):
    """A client that can only discover the limit by hitting it will hit
    it."""
    from noctornal_api.ratelimit import LIMITS
    _, email, secret = _make_user(conn, clearance="RED", global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    _seed_small_graph(client, token, case_id)
    r = client.get(f"/api/v1/cases/{case_id}/analytics", headers=_auth(token))
    assert r.status_code == 200, r.text
    assert r.headers["RateLimit-Limit"] == str(LIMITS["analytics.suite"].quota)
    assert int(r.headers["RateLimit-Remaining"]) < LIMITS["analytics.suite"].quota


# --- dual control on merge ----------------------------------------------

def _two_identities(client, token, case_id) -> tuple[str, str]:
    ids = []
    for label in (f"shadowbroker-{uuid4().hex[:6]}", f"shadow_broker-{uuid4().hex[:6]}"):
        r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
            "node_type": "IDENTITY", "label": label,
            "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "B",
                          "credibility": "2"},
        })
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    return ids[0], ids[1]


def _set_dual_control(client, token, case_id, on: bool) -> None:
    r = client.put(f"/api/v1/cases/{case_id}/policy", headers=_auth(token),
                   json={"dual_control_merge": on})
    assert r.status_code == 200, r.text
    assert r.json()["dual_control_merge"] is on


def _assign(conn, case_id, user_id, granted_by) -> None:
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, 'ANALYST', %s)""", (case_id, user_id, granted_by))


def test_dual_control_is_off_by_default_so_a_merge_still_works(conn, client):
    """docs/05 scopes dual control to "the genuinely irreversible", and a
    merge here is a ledger with an exact restore. Entity resolution is the
    daily work of this tool; a second signature on every merge is a control
    that gets switched off in week two."""
    _, email, secret = _make_user(conn, clearance="RED", global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    src, dst = _two_identities(client, token, case_id)

    assert client.get(f"/api/v1/cases/{case_id}/policy",
                      headers=_auth(token)).json()["dual_control_merge"] is False
    r = client.post(f"/api/v1/cases/{case_id}/merges", headers=_auth(token), json={
        "source_node_id": src, "target_node_id": dst,
        "reason": "same PGP fingerprint"})
    assert r.status_code == 201, r.text


def test_with_dual_control_on_a_lone_analyst_cannot_merge(conn, client):
    _, email, secret = _make_user(conn, clearance="RED", global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    src, dst = _two_identities(client, token, case_id)
    _set_dual_control(client, token, case_id, True)

    lone = client.post(f"/api/v1/cases/{case_id}/merges", headers=_auth(token), json={
        "source_node_id": src, "target_node_id": dst, "reason": "a hunch"})
    assert lone.status_code == 409
    assert "approval" in lone.text.lower()


def test_you_cannot_approve_your_own_request(conn, client):
    _, email, secret = _make_user(conn, clearance="RED", global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    src, dst = _two_identities(client, token, case_id)
    _set_dual_control(client, token, case_id, True)

    req = client.post(f"/api/v1/cases/{case_id}/approvals", headers=_auth(token), json={
        "operation": "node.merge",
        "payload": {"source_node_id": src, "target_node_id": dst,
                    "reason": "same PGP fingerprint", "basis_selector_id": None},
        "justification": "identical fingerprints on both profiles"})
    assert req.status_code == 201, req.text

    mine = client.post(
        f"/api/v1/cases/{case_id}/approvals/{req.json()['id']}/decide",
        headers=_auth(token), json={"approve": True})
    assert mine.status_code == 409
    assert "two distinct humans" in mine.text


def test_the_full_two_analyst_merge(conn, client):
    """The whole point, end to end: A raises, B approves, A merges."""
    uid_a, email_a, secret_a = _make_user(conn, clearance="RED",
                                          global_roles=("CASE_OWNER",))
    uid_b, email_b, secret_b = _make_user(conn, clearance="RED")
    token_a = _login(client, email_a, secret_a)
    case_id = _create_case(client, token_a)
    src, dst = _two_identities(client, token_a, case_id)
    _set_dual_control(client, token_a, case_id, True)

    _assign(conn, case_id, uid_b, uid_a)
    token_b = _login(client, email_b, secret_b)

    payload = {"source_node_id": src, "target_node_id": dst,
               "reason": "same PGP fingerprint", "basis_selector_id": None}
    req = client.post(f"/api/v1/cases/{case_id}/approvals", headers=_auth(token_a),
                      json={"operation": "node.merge", "payload": payload,
                            "justification": "identical fingerprints"})
    assert req.status_code == 201, req.text
    request_id = req.json()["id"]

    decided = client.post(f"/api/v1/cases/{case_id}/approvals/{request_id}/decide",
                          headers=_auth(token_b),
                          json={"approve": True, "note": "checked both"})
    assert decided.status_code == 200, decided.text
    assert decided.json()["state"] == "APPROVED"

    merged = client.post(f"/api/v1/cases/{case_id}/merges", headers=_auth(token_a),
                         json={"approval_request_id": request_id})
    assert merged.status_code == 201, merged.text
    assert merged.json()["source_node_id"] == src

    # Single use: the same approval cannot merge a second time.
    again = client.post(f"/api/v1/cases/{case_id}/merges", headers=_auth(token_a),
                        json={"approval_request_id": request_id})
    assert again.status_code == 409


def test_the_merge_executes_the_approved_parameters_not_the_posted_ones(conn, client):
    """The substitution attack, closed. An analyst gets a nod for merging
    two obviously-identical spam bots, then posts the ids of the two nodes
    the case actually turns on - and gets the bots merged, because the body
    is not read under dual control."""
    uid_a, email_a, secret_a = _make_user(conn, clearance="RED",
                                          global_roles=("CASE_OWNER",))
    uid_b, email_b, secret_b = _make_user(conn, clearance="RED")
    token_a = _login(client, email_a, secret_a)
    case_id = _create_case(client, token_a)
    approved_src, approved_dst = _two_identities(client, token_a, case_id)
    other_src, other_dst = _two_identities(client, token_a, case_id)
    _set_dual_control(client, token_a, case_id, True)

    _assign(conn, case_id, uid_b, uid_a)
    token_b = _login(client, email_b, secret_b)

    req = client.post(f"/api/v1/cases/{case_id}/approvals", headers=_auth(token_a),
                      json={"operation": "node.merge",
                            "payload": {"source_node_id": approved_src,
                                        "target_node_id": approved_dst,
                                        "reason": "duplicate spam accounts",
                                        "basis_selector_id": None},
                            "justification": "obvious duplicates"})
    request_id = req.json()["id"]
    client.post(f"/api/v1/cases/{case_id}/approvals/{request_id}/decide",
                headers=_auth(token_b), json={"approve": True})

    substituted = client.post(
        f"/api/v1/cases/{case_id}/merges", headers=_auth(token_a),
        json={"approval_request_id": request_id,
              "source_node_id": other_src, "target_node_id": other_dst,
              "reason": "not what was approved"})
    assert substituted.status_code == 201, substituted.text
    body = substituted.json()
    assert body["source_node_id"] == approved_src, \
        "the merge must run what was approved, not what was posted"
    assert body["target_node_id"] == approved_dst
    assert body["reason"] == "duplicate spam accounts"


def test_turning_dual_control_off_is_audited(conn, client):
    """When did this case stop requiring two signatures, is a question
    somebody eventually needs answered."""
    _, email, secret = _make_user(conn, clearance="RED", global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    _set_dual_control(client, token, case_id, True)
    _set_dual_control(client, token, case_id, False)
    rows = conn.execute(
        """SELECT detail->>'from', detail->>'to' FROM audit.event
            WHERE case_id = %s AND action = 'CASE_POLICY_CHANGED' ORDER BY seq""",
        (case_id,)).fetchall()
    assert [(r[0], r[1]) for r in rows] == [("false", "true"), ("true", "false")]


def test_an_approval_from_another_case_is_refused(conn, client):
    """The case is in the payload hash: an approval granted in a training
    case must not consume in a live one."""
    uid_a, email_a, secret_a = _make_user(conn, clearance="RED",
                                          global_roles=("CASE_OWNER",))
    uid_b, email_b, secret_b = _make_user(conn, clearance="RED")
    token_a = _login(client, email_a, secret_a)
    case_one = _create_case(client, token_a)
    case_two = _create_case(client, token_a)
    src, dst = _two_identities(client, token_a, case_one)
    _set_dual_control(client, token_a, case_two, True)

    _assign(conn, case_one, uid_b, uid_a)
    token_b = _login(client, email_b, secret_b)

    req = client.post(f"/api/v1/cases/{case_one}/approvals", headers=_auth(token_a),
                      json={"operation": "node.merge",
                            "payload": {"source_node_id": src, "target_node_id": dst,
                                        "reason": "r", "basis_selector_id": None},
                            "justification": "j"})
    request_id = req.json()["id"]
    client.post(f"/api/v1/cases/{case_one}/approvals/{request_id}/decide",
                headers=_auth(token_b), json={"approve": True})

    wrong_case = client.post(f"/api/v1/cases/{case_two}/merges",
                             headers=_auth(token_a),
                             json={"approval_request_id": request_id})
    assert wrong_case.status_code == 404


def test_reversal_is_not_dual_controlled(conn, client):
    """Undoing a merge restores the pre-merge state. Requiring two humans to
    correct a mistake is how mistakes stay in a case file."""
    _, email, secret = _make_user(conn, clearance="RED", global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    src, dst = _two_identities(client, token, case_id)
    merged = client.post(f"/api/v1/cases/{case_id}/merges", headers=_auth(token),
                         json={"source_node_id": src, "target_node_id": dst,
                               "reason": "same fingerprint"})
    assert merged.status_code == 201, merged.text
    _set_dual_control(client, token, case_id, True)
    reversed_ = client.post(
        f"/api/v1/cases/{case_id}/merges/{merged.json()['id']}/reverse",
        headers=_auth(token), json={"reason": "nickname coincidence after all"})
    assert reversed_.status_code == 200, reversed_.text
    assert reversed_.json()["is_live"] is False
