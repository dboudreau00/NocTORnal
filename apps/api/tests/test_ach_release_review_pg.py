"""GET /ach after the Alpha 6 release review (2026-09-24).

- c18: with every hypothesis ruled out and "Include rejected" ticked, the
  response sent evidence 0 beside cells 2, and the pane said nothing had
  been scored. The rows are sent now, so `evidence` and `cells` agree.
- x-ach-withheld (owner backlog): `ach_cells` drops a stance on material
  above the reader without a word, so a blank cell and a withheld one
  looked alike. The response now says so, under the case's withheld-
  disclosure setting as the graph does: no key under NONE, whether under
  PRESENCE, how many items of evidence under COUNT. Never which.

The console half is in test_ui_analysis_ach_release_review.py. Env-gated on
DATABASE_URL. The email prefix is `achrr-` and must stay unique.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; ACH tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "achrr-%@noctornal.test"
PASSWORD = "correct horse battery staple 1"
KEY = "OP-ACHRR"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.hypothesis_evidence WHERE hypothesis_id IN "
                  f"(SELECT id FROM core.hypothesis WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.hypothesis WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn):
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"achrr-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Ada Analyst", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (uid,))
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return uid, {"Authorization": f"Bearer {token}"}


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-ACHRR-{uuid4().hex[:6]}", title="ACH release review",
        legal_basis="production order 2026-0042",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, classification="GREEN")


def _node(conn, case_id, actor, label, *, compartments=None):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    node = GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification="GREEN", compartments=compartments,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="B", credibility="2",
                                 rationale=f"{label} seen posting"))
    aid = conn.execute("SELECT id FROM core.assertion WHERE node_id = %s",
                       (node,)).fetchone()[0]
    return node, aid


def _add(client, auth, case_id, statement):
    r = client.post(f"/api/v1/cases/{case_id}/ach/hypotheses",
                    json={"statement": statement, "confidence": "MODERATE"},
                    headers=auth)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _put(client, auth, case_id, hid, aid, stance):
    r = client.put(f"/api/v1/cases/{case_id}/ach/hypotheses/{hid}/stance",
                   json={"assertion_id": str(aid), "stance": stance}, headers=auth)
    assert r.status_code == 200, r.text


def _status(client, auth, case_id, hid, status, note=None):
    r = client.post(f"/api/v1/cases/{case_id}/ach/hypotheses/{hid}/status",
                    json={"status": status, "note": note}, headers=auth)
    assert r.status_code == 200, r.text


def _get(client, auth, case_id, **params):
    r = client.get(f"/api/v1/cases/{case_id}/ach", params=params, headers=auth)
    assert r.status_code == 200, r.text
    return r.json()


# --- c18 --------------------------------------------------------------------

def test_every_hypothesis_ruled_out_still_sends_its_rows(conn, client):
    owner, auth = _user(conn)
    case_id = _case(conn, owner)
    _, aid = _node(conn, case_id, owner, "rv_delta")
    h1 = _add(client, auth, case_id, "the same operator")
    h2 = _add(client, auth, case_id, "separate operators")
    h3 = _add(client, auth, case_id, "a law-enforcement persona")
    _put(client, auth, case_id, h2, aid, -2)
    _put(client, auth, case_id, h1, aid, 1)
    _status(client, auth, case_id, h1, "REJECTED", "the keys differ")
    _status(client, auth, case_id, h2, "REJECTED", "the panel logs rule it out")
    _status(client, auth, case_id, h3, "SUPERSEDED")

    body = _get(client, auth, case_id, include_rejected="true")
    assert len(body["cells"]) == 2
    assert [e["assertion_id"] for e in body["evidence"]] == [str(aid)], (
        "the cells were sent and the rows they sit in were not")
    assert body["evidence"][0]["is_incomplete"]
    two = next(h for h in body["hypotheses"] if h["id"] == h2)
    assert two["retired"] and two["assessed"] == 1 and two["inconsistency"] > 0


# --- x-ach-withheld ---------------------------------------------------------

def _withheld_setup(conn, client):
    """One visible row and one the reader is not read into. The stance on
    the hidden one is written directly: the reader cannot score what they
    cannot see, which is the point."""
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                 "ON CONFLICT (key) DO NOTHING", (KEY, f"{KEY} (ACH test)"))
    owner, auth = _user(conn)
    case_id = _case(conn, owner)
    _, seen = _node(conn, case_id, owner, "vellum_ram")
    _, hidden = _node(conn, case_id, owner, "walled_off_handle", compartments=[KEY])
    h1 = _add(client, auth, case_id, "the same operator")
    h2 = _add(client, auth, case_id, "separate operators")
    _put(client, auth, case_id, h1, seen, 1)
    _put(client, auth, case_id, h2, seen, -1)
    return owner, auth, case_id, hidden, h1


def _mode(conn, case_id, mode):
    conn.execute('UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
                 (mode, case_id))


def test_the_matrix_says_when_evidence_was_left_out_as_the_case_allows(conn, client):
    _, auth, case_id, hidden, h1 = _withheld_setup(conn, client)

    # Nothing hidden yet: PRESENCE says nothing was withheld.
    _mode(conn, case_id, "PRESENCE")
    assert _get(client, auth, case_id)["withheld"] == {
        "incomplete": False, "mode": "PRESENCE"}

    conn.execute("INSERT INTO core.hypothesis_evidence (hypothesis_id, assertion_id, stance) "
                 "VALUES (%s, %s, -2)", (h1, hidden))
    body = _get(client, auth, case_id)
    assert body["withheld"] == {"incomplete": True, "mode": "PRESENCE"}, (
        "PRESENCE may say that something was left out and nothing more")
    assert str(hidden) not in str(body), "the withheld row leaked into the body"
    assert len(body["evidence"]) == 1

    _mode(conn, case_id, "COUNT")
    assert _get(client, auth, case_id)["withheld"] == {
        "incomplete": True, "mode": "COUNT", "evidence": 1}
    # Counted over the whole matrix, so ticking "Include rejected" cannot
    # narrow it to one column.
    assert _get(client, auth, case_id, include_rejected="true")["withheld"]["evidence"] == 1

    # NONE: the key is absent, since "nothing withheld" would be an answer.
    _mode(conn, case_id, "NONE")
    assert "withheld" not in _get(client, auth, case_id)


def test_a_reader_cleared_for_everything_is_told_nothing_was_left_out(conn, client):
    owner, auth, case_id, hidden, h1 = _withheld_setup(conn, client)
    conn.execute("INSERT INTO core.hypothesis_evidence (hypothesis_id, assertion_id, stance) "
                 "VALUES (%s, %s, -2)", (h1, hidden))
    conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                 "ON CONFLICT (key) DO NOTHING", (KEY, KEY))
    conn.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                 ([KEY], owner))
    _mode(conn, case_id, "COUNT")
    body = _get(client, auth, case_id)
    assert body["withheld"] == {"incomplete": False, "mode": "COUNT"}
    assert len(body["evidence"]) == 2
