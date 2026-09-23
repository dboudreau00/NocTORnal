"""A report file comes out of the egress decision, and it is the document
the analyst previewed.

ux15-report:report-download-bypasses-egress and
report-preview-undefined-relationships (2026-09-22). Three things were
wrong together:

- `POST /report?fmt=markdown` handed over the file under
  `report.generate` alone, with no step-up and no egress check, so a RED
  document reached disk one click after Prepare, which invariant 8 says
  never happens ("webhooks and export alike").
- `/release` rebuilt with the builder's defaults, so a preview prepared
  with hypotheses OFF was cleared as a document with them ON.
- Nothing tied the preview, the verdict and the file to one document.

These drive the real routes. Also here, because they are the two small
API additions the console's case header and inspector now read:
`closed_at` on the case and the validity interval on a node.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; report route tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

EMAIL_LIKE = "rdl-%@noctornal.test"
PASSWORD = "correct horse battery staple 1"
SUSPECT = "HYPOTHESIS-NAMES-A-SUSPECT"


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


def _user(conn, clearance="RED"):
    """A TOTP-enrolled analyst; returns (id, session token)."""
    from noctornal_api.security import totp
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore, PgUserStore
    email = f"rdl-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Reporter", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    # mfa_satisfied=True: /release is step-up gated, and a session that
    # never satisfied MFA would be refused before the thing under test.
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return uid, token


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner, classification="GREEN"):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-RDL-{uuid4().hex[:6]}", title="Download",
        legal_basis="production order 2026-0042",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner, classification=classification)


def _node(conn, case_id, actor, label, classification="GREEN", **kw):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="B", credibility="2"), **kw)


def _edge(conn, case_id, actor, src, dst, classification="GREEN"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="COMMUNICATES_WITH", src_node_id=src,
        dst_node_id=dst, created_by=actor, classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 reliability="B", credibility="2"))


def _hypothesis(conn, case_id, actor, statement):
    conn.execute(
        """INSERT INTO core.hypothesis (case_id, statement, created_by)
           VALUES (%s, %s, %s)""", (case_id, statement, actor))


def _network(conn):
    """A GREEN case with two named actors, one tie and one hypothesis."""
    owner, token = _user(conn)
    case_id = _case(conn, owner)
    a = _node(conn, case_id, owner, "vesper_owl")
    b = _node(conn, case_id, owner, "quill_heron")
    _edge(conn, case_id, owner, a, b)
    _hypothesis(conn, case_id, owner, SUSPECT)
    return owner, token, case_id


def _build(client, token, case_id, **params):
    q = {"target_tlp": "GREEN", "preset": "all", "include_hypotheses": "true"}
    q.update(params)
    return client.post(f"/api/v1/cases/{case_id}/report", params=q,
                       headers=_auth(token))


def _release(client, token, case_id, **body):
    payload = {"target_tlp": "GREEN", "destination": "export",
               "include_hypotheses": True, "preset": "all"}
    payload.update(body)
    return client.post(f"/api/v1/cases/{case_id}/report/release",
                       json=payload, headers=_auth(token))


# --- the file has a gate in front of it ----------------------------------

def test_the_build_endpoint_no_longer_hands_over_a_file(conn, client):
    """`fmt=markdown` was the bypass: the file, as an attachment, under
    report.generate alone. It is refused and names the route that judges
    the document instead of silently answering JSON."""
    _, token, case_id = _network(conn)
    r = _build(client, token, case_id, fmt="markdown")
    assert r.status_code == 409, r.text
    assert "release" in r.json()["detail"]
    assert "attachment" not in r.headers.get("content-disposition", "")


def test_a_red_document_is_refused_and_no_file_comes_back(conn, client):
    """Invariant 8 on the one path that used to skip it."""
    owner, token = _user(conn)
    case_id = _case(conn, owner, classification="RED")
    _node(conn, case_id, owner, "red_actor", classification="RED")
    built = _build(client, token, case_id, target_tlp="RED")
    assert built.status_code == 200, built.text
    assert built.json()["classification"] == "RED"
    r = _release(client, token, case_id, target_tlp="RED")
    assert r.status_code == 403, r.text
    assert "document" not in r.json()
    assert "invariant 8" in r.json()["detail"]


def test_the_cleared_file_is_the_previewed_document(conn, client):
    """Build and release return the same digest for the same case, and the
    release carries the markdown and a filename with its classification
    in it, so the console can save exactly what the gate cleared."""
    _, token, case_id = _network(conn)
    built = _build(client, token, case_id)
    assert built.status_code == 200, built.text
    prepared = built.json()
    assert prepared["document"].startswith("# TLP:GREEN")
    assert len(prepared["content_digest"]) == 64

    # Deterministic: the same case built twice is the same document.
    again = _build(client, token, case_id).json()
    assert again["content_digest"] == prepared["content_digest"]

    cleared = _release(client, token, case_id)
    assert cleared.status_code == 200, cleared.text
    body = cleared.json()
    assert body["content_digest"] == prepared["content_digest"]
    assert body["filename"].endswith("-TLP-GREEN.md")
    strip = lambda text: [ln for ln in text.splitlines()  # noqa: E731
                          if not ln.startswith("Generated ")]
    assert strip(body["document"]) == strip(prepared["document"])


def test_the_release_judges_the_preview_s_hypotheses_choice(conn, client):
    """A preview prepared with hypotheses OFF used to be cleared as a
    document with them ON, so the file carried ACH statements, which often
    name suspects, that nobody had seen on screen."""
    _, token, case_id = _network(conn)
    off = _build(client, token, case_id, include_hypotheses="false").json()
    assert SUSPECT not in off["document"]

    cleared = _release(client, token, case_id, include_hypotheses=False).json()
    assert SUSPECT not in cleared["document"]
    assert cleared["content_digest"] == off["content_digest"]

    on = _release(client, token, case_id, include_hypotheses=True).json()
    assert SUSPECT in on["document"]
    assert on["content_digest"] != off["content_digest"]


def test_a_change_between_prepare_and_release_changes_the_digest(conn, client):
    """The console refuses to save when the digests differ. That only
    works if a write in between actually moves the digest."""
    owner, token, case_id = _network(conn)
    before = _build(client, token, case_id).json()["content_digest"]
    _node(conn, case_id, owner, "late_arrival")
    after = _release(client, token, case_id).json()["content_digest"]
    assert after != before


def test_the_audit_row_names_which_document_was_cleared(conn, client):
    _, token, case_id = _network(conn)
    digest = _release(client, token, case_id,
                      include_hypotheses=False).json()["content_digest"]
    detail = conn.execute(
        """SELECT detail FROM audit.event
            WHERE case_id = %s AND action = 'REPORT_RELEASED'
            ORDER BY seq DESC LIMIT 1""", (case_id,)).fetchone()[0]
    assert detail["content_digest"] == digest
    assert detail["include_hypotheses"] is False
    assert detail["preset"] == "all"


def _age_the_sign_in(conn, uid, minutes=20):
    """The session as it stands 20 minutes after sign-in: still live, but
    past the 15 minutes the step-up gate allows."""
    conn.execute(
        """UPDATE iam.session
              SET mfa_satisfied_at = now() - make_interval(mins => %s)
            WHERE user_id = %s""", (minutes, uid))


def test_a_stale_sign_in_is_asked_to_sign_in_not_told_it_lacks_the_role(
        conn, client):
    """Final review C15 (2026-09-23). `report.export` is a step-up
    permission, and the permission gate answered a stale sign-in with
    "missing permission report.export on this case", so a Lead investigator
    twenty minutes into a session read that they lacked the permission they
    hold, as an egress refusal, with no way to recover but signing out. The
    freshness check now runs first and says what it is."""
    owner, token, case_id = _network(conn)
    _age_the_sign_in(conn, owner)
    r = _release(client, token, case_id)
    assert r.status_code == 403, r.text
    detail = r.json()["detail"]
    assert "re-authenticate" in detail
    assert "missing permission" not in detail
    assert r.json()["title"] != "Egress refused"
    # The document was never judged, so no release decision is recorded.
    judged = conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE case_id = %s AND action LIKE 'REPORT_RELEASE%%'""",
        (case_id,)).fetchone()[0]
    assert judged == 0
    # ...but the refusal is, against the case and the permission, as the
    # permission gate always recorded it. The first C15 fix ran the bare
    # freshness check first and wrote this row with no case at all (final
    # review C15 follow-up, 2026-09-23).
    assert _denials(conn, owner) == [
        (case_id, {"permission": "report.export",
                   "failed_checks": ["step_up_freshness"]})]

    # After a fresh sign-in the same request goes through.
    conn.execute("UPDATE iam.session SET mfa_satisfied_at = now() "
                 "WHERE user_id = %s", (owner,))
    assert _release(client, token, case_id).status_code == 200


def _denials(conn, uid):
    """Every AUTHZ_DENIED row this caller has, oldest first."""
    return [(row[0], row[1]) for row in conn.execute(
        """SELECT case_id, detail FROM audit.event
            WHERE actor_id = %s AND action = 'AUTHZ_DENIED'
            ORDER BY seq""", (uid,)).fetchall()]


def _assign(conn, case_id, uid, role, granted_by):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, uid, role, granted_by))


def test_a_role_without_report_export_is_told_that_instead(conn, client):
    """The other 403 the console now tells apart: an ANALYST holds
    report.generate but not report.export (0021), with a fresh sign-in."""
    owner, _, case_id = _network(conn)
    analyst, analyst_token = _user(conn)
    _assign(conn, case_id, analyst, "ANALYST", owner)
    r = _release(client, analyst_token, case_id)
    assert r.status_code == 403, r.text
    assert "missing permission report.export" in r.json()["detail"]


def test_a_stale_role_refusal_is_not_sent_round_the_sign_in(conn, client):
    """A sign-in cannot give an ANALYST report.export, so a stale ANALYST
    is told about the role, not asked to sign in and then told about the
    role. The row still names the case and every check that failed."""
    owner, _, case_id = _network(conn)
    analyst, analyst_token = _user(conn)
    _assign(conn, case_id, analyst, "ANALYST", owner)
    _age_the_sign_in(conn, analyst)
    r = _release(client, analyst_token, case_id)
    assert r.status_code == 403, r.text
    assert "missing permission report.export" in r.json()["detail"]
    [(row_case, detail)] = _denials(conn, analyst)
    assert row_case == case_id
    assert detail["permission"] == "report.export"
    assert set(detail["failed_checks"]) == {
        "role_grants_permission", "step_up_freshness"}


def test_a_stale_caller_off_the_case_learns_nothing_and_is_recorded(
        conn, client):
    """The re-authenticate sentence is only for a caller who is on the
    case. Off it, a stale sign-in gets the same 404 a case that does not
    exist gets, so the sentence cannot be used to find cases, and the
    probe is recorded against the case it was aimed at."""
    _, _, case_id = _network(conn)
    outsider, outsider_token = _user(conn)
    _age_the_sign_in(conn, outsider)
    r = _release(client, outsider_token, case_id)
    assert r.status_code == 404, r.text
    nowhere = _release(client, outsider_token, uuid4())
    assert nowhere.status_code == 404
    assert nowhere.json()["detail"] == r.json()["detail"]
    [(row_case, detail)] = _denials(conn, outsider)
    assert row_case == case_id
    assert detail["permission"] == "report.export"
    assert "case_assignment_unexpired" in detail["failed_checks"]
    assert "step_up_freshness" in detail["failed_checks"]


def test_an_unknown_preset_is_the_callers_mistake_not_a_500(conn, client):
    _, token, case_id = _network(conn)
    assert _build(client, token, case_id, preset="nope").status_code == 400
    assert _release(client, token, case_id, preset="nope").status_code == 400


# --- the preview can name the ties, and so can the file --------------------

def test_the_document_lists_its_relationships_by_name(conn, client):
    """The preview printed "undefined -> undefined" for every tie because
    it read field names the server never sent; the file carried only a
    count. The server sends type/src/dst plus the actors that name them,
    and the markdown now has the ties themselves."""
    _, token, case_id = _network(conn)
    body = _build(client, token, case_id).json()
    rel = body["relationships"][0]
    assert {"type", "src", "dst", "sign", "confidence", "has_evidence"} <= set(rel)
    labels = {a["id"]: a["label"] for a in body["actors"]}
    assert {labels[rel["src"]], labels[rel["dst"]]} == {"vesper_owl", "quill_heron"}
    assert "type" in body["actors"][0] and "node_type" not in body["actors"][0]

    doc = body["document"]
    assert "## Relationships" in doc
    row = next(ln for ln in doc.splitlines() if "COMMUNICATES_WITH" in ln)
    assert "vesper_owl" in row and "quill_heron" in row


# --- the small API additions the console reads -----------------------------

def test_a_closed_case_says_since_when(conn, client):
    from noctornal_api.cases import CaseService
    owner, token = _user(conn)
    case_id = _case(conn, owner)
    svc = CaseService(conn)
    svc.transition_status(case_id, "ACTIVE", actor_id=owner)
    open_rec = client.get(f"/api/v1/cases/{case_id}", headers=_auth(token)).json()
    assert open_rec["status"] == "ACTIVE" and open_rec["closed_at"] is None
    svc.transition_status(case_id, "CLOSED", actor_id=owner)
    closed = client.get(f"/api/v1/cases/{case_id}", headers=_auth(token)).json()
    assert closed["status"] == "CLOSED"
    assert closed["closed_at"] is not None


def test_a_node_read_carries_its_validity_interval(conn, client):
    """The inspector prints a node's world-time interval; it can only print
    what the node read returns."""
    owner, token = _user(conn)
    case_id = _case(conn, owner)
    start = datetime(2025, 12, 14, tzinfo=timezone.utc)
    end = datetime(2026, 6, 30, 23, 59, 59, tzinfo=timezone.utc)
    node_id = _node(conn, case_id, owner, "dated", valid_from=start, valid_to=end)
    listed = client.get(f"/api/v1/cases/{case_id}/nodes",
                        headers=_auth(token)).json()
    one = next(n for n in listed if n["id"] == str(node_id))
    assert one["valid_from"].startswith("2025-12-14T00:00:00")
    assert one["valid_to"].startswith("2026-06-30T23:59:59")
    single = client.get(f"/api/v1/cases/{case_id}/nodes/{node_id}",
                        headers=_auth(token)).json()
    assert single["valid_from"] == one["valid_from"]
