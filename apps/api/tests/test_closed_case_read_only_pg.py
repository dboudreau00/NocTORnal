"""A CLOSED or ARCHIVED case is read-only for content, over HTTP.

gap-closed-case-writes (2026-09-23). Until this, a closed case accepted
every write the five-part gate allowed: an entity, a claim, an exhibit
link, a tag, an ACH hypothesis, all landing after `closed_at`, which
matters for disclosure. The console said "not taking new material" in a
strip and the server did nothing about it.

What this file holds, against the real gate and a real database:

- content writes on a CLOSED case are refused with a 409 titled "Case is
  read-only" that names the state, on every kind of content, including the
  routes whose verb also gates reads (`report.generate` on ACH,
  `case.update` on the assumptions register);
- reads still answer, and the case record says `read_only`;
- governance still works: the metadata PATCH, the approval policy, sharing,
  a legal hold on and off, a report build, and the status move back to
  ACTIVE, after which writes are accepted again;
- ARCHIVED refuses content the same way and says it cannot be reopened;
- the refusal comes AFTER the access decision: an outsider gets the gate's
  404 and an assignee without the verb its 403, never the 409 that names
  the state, and every refusal leaves an audit row.

The route-by-route inventory (every unsafe case route either guarded or
named as governance) is the pure half, `test_closed_case_read_only.py`.

**The email prefix is `ccro-` and must stay unique**: teardown deletes on
it. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the read-only gate is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

TITLE = "Case is read-only"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'ccro-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    psub = f"(SELECT id FROM analytics.projection WHERE case_id IN {csub})"
    rsub = f"(SELECT id FROM analytics.metric_run WHERE projection_id IN {psub})"
    with c.transaction():
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE case_id IN {csub} "
                  f"OR recipient_id IN {sub} OR actor_id IN {sub})")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub} "
                  f"OR recipient_id IN {sub} OR actor_id IN {sub}")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM analytics.node_metric WHERE metric_run_id IN {rsub}")
        c.execute(f"DELETE FROM analytics.community_assignment "
                  f"WHERE metric_run_id IN {rsub}")
        c.execute(f"DELETE FROM analytics.metric_run WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.layout_position WHERE projection_id IN {psub}")
        c.execute(f"DELETE FROM analytics.projection WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN "
                  f"(SELECT id FROM core.evidence WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'ccro-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    """A live app with a limiter this test alone owns (see
    test_case_lifecycle_api_pg.py for why Redis must not be shared)."""
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, *, roles=("CASE_OWNER",)):
    from noctornal_api.stores import PgUserStore
    email = f"ccro-{uuid4().hex[:8]}@noctornal.test"
    uid = PgUserStore(conn).create_user(email, "Read-only test", "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                 (uid,))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def _token(conn, uid) -> str:
    """Minted as `scripts/bootstrap.py session` mints, with MFA satisfied so
    the step-up verbs (sharing, legal holds) are not what a test trips on."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner) -> str:
    """An ACTIVE case: DRAFT -> ACTIVE is the first legal move, and ACTIVE
    -> CLOSED the one a closed case really came by."""
    from noctornal_api.cases import CaseService
    svc = CaseService(conn)
    case_id = svc.create(
        code=f"OP-CCRO-{uuid4().hex[:6]}", title="Read-only",
        legal_basis="production order 2026-0042",
        retention_until=date(2028, 1, 1), review_due=date(2027, 1, 1),
        owner_user_id=owner, created_by=owner)
    svc.transition_status(case_id, "ACTIVE", actor_id=owner)
    return str(case_id)


def _node(client, token, case_id, label="vesper_owl"):
    r = client.post(f"/api/v1/cases/{case_id}/nodes", headers=_auth(token), json={
        "node_type": "IDENTITY", "label": label,
        "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "B",
                      "credibility": "2", "confidence": "MODERATE"}})
    return r


def _evidence(conn, case_id, owner):
    """An exhibit row, written directly: the legal hold and the link refusal
    need an exhibit, not the object store behind one."""
    row = conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, acquired_by, acquired_at,
                acquisition_method, classification)
           VALUES (%s, 'forum post', 'text/plain', 10, %s, %s, %s, 'b', %s,
                   now(), 'MANUAL_UPLOAD', 'AMBER')
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"key/{uuid4().hex}",
         owner)).fetchone()
    return str(row[0])


def _set_status(client, token, case_id, status):
    r = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(token),
                    json={"status": status})
    assert r.status_code == 200, r.text
    return r.json()


def _refused(r, state: str) -> None:
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["title"] == TITLE, body
    assert state in body["detail"], body


def test_every_kind_of_content_write_is_refused_on_a_closed_case(conn, client):
    owner = _user(conn)
    token = _token(conn, owner)
    case_id = _case(conn, owner)
    a = _node(client, token, case_id, "vesper_owl")
    b = _node(client, token, case_id, "quill_heron")
    assert a.status_code == b.status_code == 201, a.text
    a_id, b_id = a.json()["id"], b.json()["id"]
    edge = client.post(f"/api/v1/cases/{case_id}/edges", headers=_auth(token), json={
        "edge_type": "COMMUNICATES_WITH", "src_node_id": a_id, "dst_node_id": b_id,
        "assertion": {"basis": "DIRECT_OBSERVATION", "reliability": "B",
                      "credibility": "2", "confidence": "MODERATE",
                      "rationale": "thread 8841"}})
    assert edge.status_code == 201, edge.text
    edge_id = edge.json()["id"]
    exhibit = _evidence(conn, case_id, owner)
    assertion_id = str(conn.execute(
        "SELECT id FROM core.assertion WHERE node_id = %s", (a_id,)).fetchone()[0])

    closed = _set_status(client, token, case_id, "CLOSED")
    assert closed["read_only"] is True

    h = _auth(token)
    base = f"/api/v1/cases/{case_id}"
    grade = {"basis": "DIRECT_OBSERVATION", "reliability": "B", "credibility": "2",
             "confidence": "MODERATE"}
    attempts = [
        # the graph
        ("POST", "/nodes", {"node_type": "IDENTITY", "label": "late",
                            "assertion": grade}),
        ("POST", "/edges", {"edge_type": "COMMUNICATES_WITH", "src_node_id": b_id,
                            "dst_node_id": a_id, "assertion": grade}),
        ("POST", f"/nodes/{a_id}/assertions", grade),
        ("POST", f"/edges/{edge_id}/assertions", grade),
        ("POST", f"/assertions/{assertion_id}/retract", {"reason": "wrong"}),
        ("PATCH", f"/graph/nodes/{a_id}", {"label": "renamed"}),
        ("PATCH", f"/graph/edges/{edge_id}", {"confidence": "LOW"}),
        ("DELETE", f"/graph/nodes/{b_id}", {"reason": "duplicate"}),
        ("DELETE", f"/graph/edges/{edge_id}", {"reason": "duplicate"}),
        ("PUT", "/graph/layout", {"positions": [
            {"node_id": a_id, "x": 1.0, "y": 2.0, "is_pinned": True}]}),
        ("POST", "/selectors", {"selector_type": "EMAIL",
                                "raw_value": "owl@example.org", "node_id": a_id}),
        ("POST", "/merges", {"source_node_id": b_id, "target_node_id": a_id}),
        # evidence and captures
        ("POST", f"/evidence/{exhibit}/links", {"node_id": a_id}),
        ("POST", "/proposals/capture", {"text": "owl@example.org said hello"}),
        ("POST", "/deception/calls", {"started_at": "2026-09-01T10:00:00Z",
                                     "direction": "INBOUND_TO_VICTIM",
                                     "record_source": "VICTIM_STATEMENT"}),
        # comms
        ("POST", "/comms/bindings", {"platform_key": "telegram",
                                     "observed": "@vesper_owl"}),
        ("POST", "/comms/stoplist", {"platform_key": "telegram",
                                     "handle": "@escrow"}),
        # analysis, including the verbs that also gate reads
        ("POST", "/ach/hypotheses", {"statement": "the same operator"}),
        ("POST", "/assumptions", {"statement": "the handle is not shared"}),
        # curation
        ("POST", "/curation/tags", {"namespace": "case", "name": "late"}),
        ("POST", "/curation/sets", {"name": "late"}),
        # a second signature for a content operation
        ("POST", "/approvals", {"operation": "node.merge", "payload": {},
                                "justification": "same person"}),
    ]
    for method, suffix, body in attempts:
        r = client.request(method, base + suffix, headers=h, json=body)
        assert r.status_code == 409, f"{method} {suffix}: {r.status_code} {r.text}"
        assert r.json()["title"] == TITLE, (method, suffix, r.json())
        assert "CLOSED" in r.json()["detail"], (method, suffix)
        assert "Reopen" in r.json()["detail"]

    # A multipart upload is refused at the gate too, before a byte is stored.
    up = client.post(f"{base}/evidence", headers=h,
                     files={"file": ("post.txt", b"late material", "text/plain")},
                     data={"title": "late", "acquisition_method": "MANUAL_UPLOAD"})
    _refused(up, "CLOSED")

    # Nothing landed.
    assert conn.execute("SELECT count(*) FROM core.node WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 2
    assert conn.execute(
        "SELECT count(*) FROM core.node WHERE case_id = %s AND deleted_at IS NOT NULL",
        (case_id,)).fetchone()[0] == 0
    assert conn.execute("SELECT label FROM core.node WHERE id = %s",
                        (a_id,)).fetchone()[0] == "vesper_owl"
    assert conn.execute("SELECT count(*) FROM core.evidence_link WHERE evidence_id = %s",
                        (exhibit,)).fetchone()[0] == 0
    assert conn.execute("SELECT count(*) FROM core.hypothesis WHERE case_id = %s",
                        (case_id,)).fetchone()[0] == 0


def test_reads_still_answer_and_the_record_says_read_only(conn, client):
    owner = _user(conn)
    token = _token(conn, owner)
    case_id = _case(conn, owner)
    assert _node(client, token, case_id).status_code == 201
    live = client.get(f"/api/v1/cases/{case_id}", headers=_auth(token)).json()
    assert live["read_only"] is False
    _set_status(client, token, case_id, "CLOSED")

    h = _auth(token)
    base = f"/api/v1/cases/{case_id}"
    assert client.get(base, headers=h).json()["read_only"] is True
    listed = {c["id"]: c for c in client.get("/api/v1/cases", headers=h).json()}
    assert listed[case_id]["read_only"] is True
    for suffix in ("/graph", "/nodes", "/ach", "/assumptions", "/curation/tags"):
        r = client.get(base + suffix, headers=h)
        assert r.status_code == 200, f"GET {suffix}: {r.text}"


def test_governance_still_works_on_a_closed_case_and_reopening_restores_writes(
        conn, client):
    owner = _user(conn)
    token = _token(conn, owner)
    colleague = _user(conn, roles=())
    case_id = _case(conn, owner)
    assert _node(client, token, case_id).status_code == 201
    exhibit = _evidence(conn, case_id, owner)
    _set_status(client, token, case_id, "CLOSED")
    h = _auth(token)
    base = f"/api/v1/cases/{case_id}"

    # The governance record.
    r = client.patch(base, headers=h, json={"authority_ref": "warrant 2026-0100"})
    assert r.status_code == 200, r.text
    # The approval policy.
    r = client.put(f"{base}/policy", headers=h, json={"dual_control_merge": True})
    assert r.status_code == 200, r.text
    # Sharing, both ways.
    r = client.post(f"{base}/users", headers=h,
                    json={"user_id": str(colleague), "role_key": "READ_ONLY"})
    assert r.status_code in (200, 201), r.text
    r = client.delete(f"{base}/users/{colleague}", headers=h)
    assert r.status_code in (200, 204), r.text
    # A legal hold, on and off: a hold overrides deletion whatever the
    # case's state.
    r = client.post("/api/v1/retention/legal-hold", headers=h,
                    json={"evidence_id": exhibit, "on": True,
                          "reason": "appeal lodged"})
    assert r.status_code == 200, r.text
    r = client.post("/api/v1/retention/legal-hold", headers=h,
                    json={"evidence_id": exhibit, "on": False,
                          "reason": "appeal withdrawn"})
    assert r.status_code == 200, r.text
    # A report build writes no content; a closed case is when one is wanted.
    r = client.post(f"{base}/report", headers=h)
    assert r.status_code == 200, r.text

    # Reopening is governance, and the content writes come back with it.
    reopened = _set_status(client, token, case_id, "ACTIVE")
    assert reopened["read_only"] is False
    assert _node(client, token, case_id, "after the reopen").status_code == 201


def test_an_archived_case_refuses_content_and_says_it_cannot_be_reopened(
        conn, client):
    owner = _user(conn)
    token = _token(conn, owner)
    case_id = _case(conn, owner)
    _set_status(client, token, case_id, "CLOSED")
    archived = _set_status(client, token, case_id, "ARCHIVED")
    assert archived["read_only"] is True

    r = _node(client, token, case_id)
    _refused(r, "ARCHIVED")
    assert "cannot be reopened" in r.json()["detail"]
    assert "Reopen it" not in r.json()["detail"]
    # Its governance record stays correctable, as it was before.
    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"authority_ref": "warrant 2026-0101"})
    assert r.status_code == 200, r.text


def test_the_refusal_follows_the_access_decision_and_is_audited(conn, client):
    """The 409 names the case's state, so it must never reach a caller the
    gate would refuse: that would be a state oracle for a case the caller
    cannot see (deps.py rule 2)."""
    from noctornal_api.cases import CaseService
    owner = _user(conn)
    token = _token(conn, owner)
    case_id = _case(conn, owner)
    _set_status(client, token, case_id, "CLOSED")

    outsider = _token(conn, _user(conn))
    r = _node(client, outsider, case_id)
    assert r.status_code == 404, r.text
    fake = _node(client, outsider, str(uuid4()))
    assert fake.status_code == 404 and fake.json() == r.json()

    reader_id = _user(conn, roles=())
    CaseService(conn).assign_user(case_id, reader_id, "READ_ONLY",
                                  granted_by=owner)
    r = _node(client, _token(conn, reader_id), case_id)
    assert r.status_code == 403, r.text

    r = _node(client, token, case_id)
    _refused(r, "CLOSED")
    row = conn.execute(
        """SELECT actor_id, outcome, detail FROM audit.event
            WHERE action = 'CASE_READ_ONLY_REFUSED' AND case_id = %s
            ORDER BY seq DESC LIMIT 1""", (case_id,)).fetchone()
    assert row is not None, "the refusal left no audit row"
    assert row[0] == owner and row[1] == "DENIED"
    assert row[2] == {"permission": "graph.node.create", "status": "CLOSED"}
    # Only the owner's attempt reached the lifecycle check: the outsider's
    # and the reader's were refused by the gate first.
    assert conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE action = 'CASE_READ_ONLY_REFUSED' AND case_id = %s""",
        (case_id,)).fetchone()[0] == 1
