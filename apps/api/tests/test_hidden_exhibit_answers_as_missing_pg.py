"""An exhibit above the caller's labels answers as a missing one (2026-10-07).

The exhibit routes gated the exhibit's own labels with `authorize_object`
and let its 403 through, so an AMBER analyst holding the id of a RED exhibit
in their own case got "missing permission evidence.read on this case" where
a random id got 404 "evidence does not exist in this case": the status told
an exhibit they may not see from one that does not exist. The element
routes of the graph were moved to one answer by http_ui-016; the exhibit
routes were not. Each row below is one route asked with a hidden exhibit, a
random id and another case's exhibit, and the three answers must be
identical. The refusal of the hidden one is still audited.

`POST /deception/captures` names exhibits in its body and had the same
split, and a second one for a caller holding `evidence.upload` without
`evidence.read` (the SERVICE role): a present exhibit answered 403 and a
missing one 404.

Runs with NOCTORNAL_TEST_ASSUME_ROLE, so every request connection is the
request role, as in production.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import rls_support as s

pytestmark = s.GATED

PREFIX = "gx63-"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    s.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def client():
    from noctornal_api.http.app import app
    return TestClient(app)


def _auth(conn, uid) -> dict:
    _, raw = s.session(conn, uid)
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture
def world(owner):
    boss = s.user(owner, "RED", prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    lead = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, boss)
    other = s.case(owner, boss)
    s.assign(owner, case_id, analyst, "ANALYST")
    s.assign(owner, case_id, lead, "CASE_OWNER")
    node = s.node(owner, case_id, boss, "gx63 visible")
    return {
        "case": case_id, "analyst": analyst, "lead": lead, "node": node,
        "hidden": s.exhibit(owner, case_id, boss, "RED"),
        "other": s.exhibit(owner, other, boss, "AMBER"),
    }


#: (method, path under the case, body, who asks). Every route that gates an
#: exhibit named in its path.
ROUTES = [
    ("GET", "/evidence/{}/content", None, "analyst"),
    ("GET", "/evidence/{}/custody", None, "analyst"),
    ("GET", "/evidence/{}/backs", None, "analyst"),
    ("POST", "/evidence/{}/verify", {}, "analyst"),
    ("POST", "/evidence/{}/links", {"relevance": "gx63"}, "analyst"),
    ("POST", "/evidence/{}/export", {}, "lead"),
    ("POST", "/evidence/{}/production-ticket", {}, "lead"),
]


def _answer(r) -> tuple[int, dict]:
    body = r.json()
    return r.status_code, {k: body.get(k) for k in ("title", "status", "detail")}


@pytest.mark.parametrize(("method", "path", "body", "who"), ROUTES,
                         ids=[f"{m} {p}" for m, p, _, _ in ROUTES])
def test_a_hidden_exhibit_answers_as_a_missing_one(owner, client, world,
                                                   method, path, body, who):
    w = world
    if body is not None and "relevance" in body:
        body = dict(body, node_id=str(w["node"]))
    auth = _auth(owner, w[who])
    base = f"/api/v1/cases/{w['case']}"
    answers = {
        kind: _answer(client.request(method, base + path.format(ident),
                                     headers=auth, json=body))
        for kind, ident in (("hidden", w["hidden"]), ("random", uuid4()),
                            ("other_case", w["other"]))}
    assert answers["random"][0] == 404, answers
    assert answers["hidden"] == answers["random"] == answers["other_case"], answers


def test_the_hidden_refusal_is_still_audited(owner, client, world):
    w = world
    before = s.count(owner, "SELECT count(*) FROM audit.event WHERE actor_id = %s "
                            "AND action = 'AUTHZ_DENIED' AND case_id = %s",
                     (w["analyst"], w["case"]))
    r = client.get(f"/api/v1/cases/{w['case']}/evidence/{w['hidden']}/custody",
                   headers=_auth(owner, w["analyst"]))
    assert r.status_code == 404, r.text
    after = s.count(owner, "SELECT count(*) FROM audit.event WHERE actor_id = %s "
                           "AND action = 'AUTHZ_DENIED' AND case_id = %s",
                    (w["analyst"], w["case"]))
    assert after == before + 1


def _capture(client, auth, case_id, exhibit) -> tuple[int, dict]:
    return _answer(client.post(
        f"/api/v1/cases/{case_id}/deception/captures", headers=auth,
        json={"requested_url": "https://lure.example/login",
              "capture_method": "MANUAL_BROWSER",
              "screenshot_evidence_id": str(exhibit)}))


def test_a_capture_naming_a_hidden_exhibit_answers_as_a_missing_one(
        owner, client, world):
    w = world
    auth = _auth(owner, w["analyst"])
    hidden = _capture(client, auth, w["case"], w["hidden"])
    random = _capture(client, auth, w["case"], uuid4())
    other = _capture(client, auth, w["case"], w["other"])
    assert random[0] == 404, random
    assert hidden == random == other


def test_an_uploader_without_read_is_refused_whether_or_not_the_exhibit_exists(
        owner, client, world):
    """SERVICE holds `evidence.upload` and not `evidence.read`: the verb
    the exhibit is gated with is refused before its existence is."""
    w = world
    uploader = s.user(owner, "AMBER", prefix=PREFIX)
    s.assign(owner, w["case"], uploader, "SERVICE")
    visible = s.exhibit(owner, w["case"], w["lead"], "AMBER")
    auth = _auth(owner, uploader)
    present = _capture(client, auth, w["case"], visible)
    missing = _capture(client, auth, w["case"], uuid4())
    assert present[0] == 403, present
    assert present == missing
