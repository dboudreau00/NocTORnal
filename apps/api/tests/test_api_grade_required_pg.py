"""Every write that records a claim must carry the claim's grading.

gap-api-grade-required (decided 2026-09-23). `AssertionBody` defaulted
basis, reliability, credibility and confidence to DIRECT_OBSERVATION, F, 6
and LOW, and `CreateNodeBody` / `CreateEdgeBody` defaulted the whole
assertion, so a script that posted a bare label recorded "we saw this
ourselves" in its caller's name at a grade nobody chose. ACH weights a
cell by that grade, the confidence filter acts on it, and a disclosure
reviewer cannot tell it from a considered F6.

Now a missing field is a 422 whose detail NAMES it, nothing is written,
and a graded write records exactly the grading sent. Six endpoints record
a claim: create an entity, create a tie, add a claim to either, and
correct either (a correction is a claim: invariant 1).

`test_api_grade_required.py` holds the pure half: the request models, and
that no product code builds a claim on the service's fixture defaults.

The email prefix is `agrq-` and must stay unique (see
test_graph_mutation_api_pg.py on why prefixes must not collide).

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; claim grading is gated"
)

PASSWORD = "correct-horse-battery-staple"
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

GRADING = ("basis", "reliability", "credibility", "confidence")

#: A grading nobody would get by default: if any of it comes back as F, 6,
#: LOW or DIRECT_OBSERVATION, something filled it in.
GRADED = {"basis": "THIRD_PARTY_REPORT", "reliability": "B",
          "credibility": "3", "confidence": "MODERATE"}


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()  # autocommit
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'agrq-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    # One transaction, so the deferred invariant-1 triggers see the final
    # state (every assertion and element gone together).
    with c.transaction():
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'agrq-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    """A TestClient with its own in-process rate limiter, so one test
    cannot spend the next one's budget."""
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _owner(conn) -> str:
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"agrq-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Agrq", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s",
                 (uid,))
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                 "VALUES (%s, 'CASE_OWNER')", (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(client, token) -> str:
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-AGRQ-{uuid4().hex[:6]}", "title": "Operation Graded",
        "legal_basis": "production order 2026-0001",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _counts(conn, case_id) -> tuple[int, int, int]:
    return conn.execute(
        """SELECT (SELECT count(*) FROM core.node WHERE case_id = %s),
                  (SELECT count(*) FROM core.edge WHERE case_id = %s),
                  (SELECT count(*) FROM core.assertion WHERE case_id = %s)""",
        (case_id, case_id, case_id)).fetchone()


def _without(field: str) -> dict:
    return {k: v for k, v in GRADED.items() if k != field}


def _pair(client, token, case_id) -> tuple[str, str, str]:
    ids = []
    for label in ("alpha", "bravo"):
        r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                        json={"node_type": "IDENTITY", "label": label,
                              "assertion": GRADED})
        assert r.status_code == 201, r.text
        ids.append(r.json()["id"])
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
                    json={"edge_type": "VOUCHED_FOR", "src_node_id": ids[0],
                          "dst_node_id": ids[1], "assertion": GRADED})
    assert r.status_code == 201, r.text
    return ids[0], ids[1], r.json()["id"]


def _refused(r, where: str) -> None:
    assert r.status_code == 422, r.text
    assert r.headers["content-type"].startswith("application/problem+json")
    assert f"{where}: Field required" in r.json()["detail"], r.json()["detail"]


# ---------------------------------------------------------------------------
# The two creates: the assertion itself, then each grading field
# ---------------------------------------------------------------------------

def test_a_create_without_an_assertion_is_422_and_writes_nothing(conn, client):
    token = _owner(conn)
    case_id = _case(client, token)
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                    json={"node_type": "IDENTITY", "label": "bare label"})
    _refused(r, "body.assertion")
    a, b, _tie = _pair(client, token, case_id)
    before = _counts(conn, case_id)
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
                    json={"edge_type": "VOUCHED_FOR", "src_node_id": b,
                          "dst_node_id": a})
    _refused(r, "body.assertion")
    assert _counts(conn, case_id) == before


@pytest.mark.parametrize("field", GRADING)
def test_each_grading_field_is_required_on_a_create(conn, client, field):
    token = _owner(conn)
    case_id = _case(client, token)
    a, b, _tie = _pair(client, token, case_id)
    before = _counts(conn, case_id)

    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                    json={"node_type": "IDENTITY", "label": "charlie",
                          "assertion": _without(field)})
    _refused(r, f"body.assertion.{field}")
    r = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token),
                    json={"edge_type": "VOUCHED_FOR", "src_node_id": b,
                          "dst_node_id": a, "assertion": _without(field)})
    _refused(r, f"body.assertion.{field}")
    assert _counts(conn, case_id) == before, "a refused create wrote something"


def test_every_missing_field_is_named_at_once(conn, client):
    """One round trip tells a script client everything it must send."""
    token = _owner(conn)
    case_id = _case(client, token)
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token),
                    json={"node_type": "IDENTITY", "label": "delta",
                          "assertion": {"rationale": "a note, no grading"}})
    assert r.status_code == 422, r.text
    for field in GRADING:
        assert f"body.assertion.{field}: Field required" in r.json()["detail"]


# ---------------------------------------------------------------------------
# Adding a claim, and correcting: the other four claim-recording writes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field", GRADING)
def test_each_grading_field_is_required_on_an_added_claim(conn, client, field):
    token = _owner(conn)
    case_id = _case(client, token)
    a, _b, tie = _pair(client, token, case_id)
    before = _counts(conn, case_id)
    for path in (f"nodes/{a}/assertions", f"edges/{tie}/assertions"):
        r = client.post(f"/api/v1/cases/{case_id}/{path}", headers=_auth(token),
                        json=_without(field))
        _refused(r, f"body.{field}")
    assert _counts(conn, case_id) == before


@pytest.mark.parametrize("field", GRADING)
def test_each_grading_field_is_required_on_a_correction(conn, client, field):
    """A correction is a claim ("this is now called X"), so it is graded
    like one. The console's Correct... used to send a rationale alone and
    the API graded the rest DIRECT_OBSERVATION F6 LOW."""
    token = _owner(conn)
    case_id = _case(client, token)
    a, _b, tie = _pair(client, token, case_id)
    before = _counts(conn, case_id)
    r = client.patch(f"/api/v1/cases/{case_id}/graph/nodes/{a}",
                     headers=_auth(token),
                     json={"label": "alpha prime", "assertion": _without(field)})
    _refused(r, f"body.assertion.{field}")
    r = client.patch(f"/api/v1/cases/{case_id}/graph/edges/{tie}",
                     headers=_auth(token),
                     json={"weight": 2, "assertion": _without(field)})
    _refused(r, f"body.assertion.{field}")
    assert _counts(conn, case_id) == before
    assert conn.execute("SELECT label FROM core.node WHERE id = %s",
                        (a,)).fetchone()[0] == "alpha"


def test_a_correction_without_an_assertion_is_422(conn, client):
    token = _owner(conn)
    case_id = _case(client, token)
    a, _b, tie = _pair(client, token, case_id)
    _refused(client.patch(f"/api/v1/cases/{case_id}/graph/nodes/{a}",
                          headers=_auth(token), json={"label": "x"}),
             "body.assertion")
    _refused(client.patch(f"/api/v1/cases/{case_id}/graph/edges/{tie}",
                          headers=_auth(token), json={"confidence": "HIGH"}),
             "body.assertion")


# ---------------------------------------------------------------------------
# A graded write records exactly what was sent
# ---------------------------------------------------------------------------

def _latest(conn, column: str, oid: str) -> tuple:
    assert column in ("node_id", "edge_id")
    return conn.execute(
        f"""SELECT basis::text, reliability::text, credibility::text,
                   confidence::text
              FROM core.assertion WHERE {column} = %s
             ORDER BY recorded_at DESC LIMIT 1""", (oid,)).fetchone()


def test_every_claim_is_recorded_at_the_grading_sent(conn, client):
    token = _owner(conn)
    case_id = _case(client, token)
    a, _b, tie = _pair(client, token, case_id)
    sent = tuple(GRADED[f] for f in GRADING)
    assert _latest(conn, "node_id", a) == sent
    assert _latest(conn, "edge_id", tie) == sent

    other = {"basis": "LEGAL_PROCESS", "reliability": "A", "credibility": "1",
             "confidence": "HIGH"}
    r = client.post(f"/api/v1/cases/{case_id}/nodes/{a}/assertions",
                    headers=_auth(token), json=other)
    assert r.status_code == 201, r.text
    assert _latest(conn, "node_id", a) == tuple(other[f] for f in GRADING)

    fix = {"basis": "ANALYST_INFERENCE", "reliability": "C", "credibility": "4",
           "confidence": "LOW", "rationale": "the handle was misread"}
    r = client.patch(f"/api/v1/cases/{case_id}/graph/nodes/{a}",
                     headers=_auth(token),
                     json={"label": "alpha prime", "assertion": fix})
    assert r.status_code == 200, r.text
    assert _latest(conn, "node_id", a) == tuple(fix[f] for f in GRADING)


def test_a_regrade_sends_its_value_in_both_places(conn, client):
    """`confidence` marks the correction as a re-grade of the tie, and the
    claim's own confidence is that grade. The two must agree."""
    token = _owner(conn)
    case_id = _case(client, token)
    _a, _b, tie = _pair(client, token, case_id)       # MODERATE
    r = client.patch(f"/api/v1/cases/{case_id}/graph/edges/{tie}",
                     headers=_auth(token),
                     json={"confidence": "HIGH",
                           "assertion": {**GRADED, "confidence": "MODERATE"}})
    assert r.status_code == 400, r.text
    assert "send the same value in both" in r.json()["detail"]
    r = client.patch(f"/api/v1/cases/{case_id}/graph/edges/{tie}",
                     headers=_auth(token),
                     json={"confidence": "HIGH",
                           "assertion": {**GRADED, "confidence": "HIGH"}})
    assert r.status_code == 200, r.text
    assert r.json()["confidence"] == "HIGH"
    assert _latest(conn, "edge_id", tie) == (
        "THIRD_PARTY_REPORT", "B", "3", "HIGH")
