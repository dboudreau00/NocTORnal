"""Break-glass after the final adversarial review (2026-09-23, group g02).

Each test here fails on the merged head 1667cc1 and passes with the fix
it names:

- C6: the sole Security Officer could invoke break-glass, and the grant
  could never be reviewed (`review()` refuses your own) nor was anybody
  alerted (notifications never tell you what you just did);
- C11 (and its duplicate U1): a grant scoped to one case raised the
  ceiling on the collected documents and sources an assertion names, which
  belong to no case;
- U2: a verdict on a LIVE grant took it out of the only queue and away
  from the only revoke control while the raise ran on;
- U19: `action_count` counted requests the gate then refused, and counted
  the question-form probe behind every inspector open as a second use;
- U23: a deception capture or message opened by id above the analyst's
  clearance under a grant was never counted.

The last three came from the verifier of the first pass, and each fails
on that pass: a capture or message opened on a case above the analyst's
clearance counted twice, the invoke notice said entity reads were counted
when they are not, and the live re-check and the ingest probe still
counted as uses. The first of them passes on 1667cc1, which never asked
the second gate at all (the U23 test pins what that missed).

**The email prefix is `bfr-` and must stay unique**: the fixture cleans
up by deleting on it, and two files sharing a prefix delete each other's
rows mid-run.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import UUID, uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; break-glass tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple"
WHY = ("Incident 2026-0923: a RED item on this case names the next target "
       "and it is needed within the hour.")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'bfr-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ssub = "(SELECT id FROM collect.source WHERE name LIKE 'bfr-%')"
    with c.transaction():
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification "
                  f"  WHERE recipient_id IN {sub} OR actor_id IN {sub}"
                  f"     OR case_id IN {csub})")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}"
                  f"    OR case_id IN {csub}")
        c.execute(f"DELETE FROM deception.capture_hop WHERE capture_id IN "
                  f"(SELECT id FROM deception.capture WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.capture WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM deception.email_hop WHERE message_id IN "
                  f"(SELECT id FROM deception.email_message "
                  f"  WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.email_message WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        # Exhibits inserted directly (no custody rows), so they can go.
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.document WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.source WHERE id IN {ssub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'bfr-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, *, name="BFR", clearance="AMBER", roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"bfr-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, name, PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return uid, email


def _session(conn, email) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _case(client, auth, classification="AMBER") -> str:
    r = client.post("/api/v1/cases", headers=auth, json={
        "code": f"OP-BFR-{uuid4().hex[:6].upper()}", "title": "Operation BFR",
        "legal_basis": "production order 2026-0923",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)),
        "classification": classification})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _officer(conn):
    """Break-glass refuses outright when nobody but the invoker could
    review it."""
    return _user(conn, name="BFR Officer", clearance="RED",
                 roles=("SECURITY_OFFICER",))


def _analyst_on_a_red_owners_case(conn, client, *, clearance="AMBER",
                                  case_level="AMBER"):
    """The shape every test below needs: a RED Lead investigator owns a
    case, and an analyst below RED is assigned to it. The analyst holds
    global CASE_OWNER, which carries `break_glass.invoke` and
    `collection.read` (migration 0039)."""
    owner, owner_email = _user(conn, name="Rhea Red", clearance="RED",
                               roles=("CASE_OWNER",))
    case_id = _case(client, _session(conn, owner_email), case_level)
    uid, email = _user(conn, name="Amy Analyst", clearance=clearance,
                       roles=("CASE_OWNER",))
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, 'ANALYST', %s)", (case_id, uid, owner))
    return owner, case_id, uid, _session(conn, email)


def _node(conn, case_id, owner, label, level="AMBER"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label,
        classification=level, created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner))


def _grant(client, auth, **body) -> str:
    r = client.post("/api/v1/break-glass", headers=auth,
                    json={"justification": WHY, "duration_hours": 1, **body})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _count(conn, grant_id) -> int:
    return conn.execute("SELECT action_count FROM iam.break_glass WHERE id = %s",
                        (grant_id,)).fetchone()[0]


# ---------------------------------------------------------------------------
# C6: the invoker is not a reviewer
# ---------------------------------------------------------------------------

def test_the_sole_officer_cannot_invoke_what_nobody_else_could_review(
        conn, client):
    """A fresh install's operator holds SYS_ADMIN, SECURITY_OFFICER and
    CASE_OWNER. Counted as their own reviewer, they were granted emergency
    access that `review()` then refused to let anybody review, and whose
    page to "every security officer" reached nobody."""
    uid, email = _user(conn, name="Solo Operator", clearance="AMBER",
                       roles=("SECURITY_OFFICER", "CASE_OWNER"))
    auth = _session(conn, email)
    # Global state: every OTHER active officer is stood down for the test
    # and restored by id in the finally, so no later test loses its
    # reviewer (test_governance_http_e2e learned this the hard way).
    others = [r[0] for r in conn.execute(
        """SELECT u.id FROM iam.app_user u
             JOIN iam.user_role ur ON ur.user_id = u.id
            WHERE ur.role_key = 'SECURITY_OFFICER' AND u.is_active
              AND u.id <> %s""", (uid,)).fetchall()]
    if others:
        conn.execute("UPDATE iam.app_user SET is_active = false "
                     " WHERE id = ANY(%s)", (others,))
    try:
        r = client.post("/api/v1/break-glass", headers=auth, json={
            "justification": WHY, "classification": "RED"})
        assert r.status_code == 409, r.text
        assert "the only active SECURITY_OFFICER is you" in r.json()["detail"]
        assert conn.execute(
            "SELECT count(*) FROM iam.break_glass WHERE user_id = %s",
            (uid,)).fetchone()[0] == 0, "no grant row may be written"

        # A second officer makes it reviewable, and it is THEY who are paged.
        second, _ = _officer(conn)
        gid = _grant(client, auth, classification="RED")
        paged = {r[0] for r in conn.execute(
            """SELECT recipient_id FROM notify.notification
                WHERE kind = 'BREAK_GLASS_INVOKED' AND object_id = %s""",
            (UUID(gid),)).fetchall()}
        assert paged == {second}, paged
    finally:
        if others:
            conn.execute("UPDATE iam.app_user SET is_active = true "
                         " WHERE id = ANY(%s)", (others,))


# ---------------------------------------------------------------------------
# C11 / U1: a case grant does not raise deployment-wide collection names
# ---------------------------------------------------------------------------

def _source(conn, level):
    return conn.execute(
        """INSERT INTO collect.source (kind, name, classification)
           VALUES ('MANUAL', %s, %s::core.tlp) RETURNING id""",
        (f"bfr-forum-{uuid4().hex[:6]}", level)).fetchone()[0]


def test_a_case_grant_does_not_name_a_red_document_or_forum(conn, client):
    """A RED document from a RED forum, cited by a claim on the granted
    case. `/collection/documents`, case search and watch hits all withhold
    both under a case-scoped grant; the inspector named them."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    _officer(conn)
    owner, case_id, _uid, auth = _analyst_on_a_red_owners_case(conn, client)
    node = _node(conn, case_id, owner, "bfr_claimed")
    forum = _source(conn, "RED")
    doc = conn.execute(
        """INSERT INTO collect.document (source_id, title, body_text,
                                         content_sha256, classification)
           VALUES (%s, 'the next target', 'tox: ABCD',
                   decode(md5(%s), 'hex'), 'RED') RETURNING id""",
        (forum, uuid4().hex)).fetchone()[0]
    lone = _source(conn, "RED")                  # the claim cites ONLY this
    svc = GraphWriteService(conn)
    for kw in ({"document_id": doc, "source_id": forum}, {"source_id": lone}):
        svc.add_assertion(case_id=case_id, node_id=node, assertion=AssertionInput(
            basis="AUTOMATED_INFERENCE", created_by=owner,
            rationale="[contact_block_parser/1] published",
            claim_path="comms.tox", claim_value="ABCD", **kw))

    def named():
        r = client.get(f"/api/v1/cases/{case_id}/nodes/{node}/assertions",
                       headers=auth)
        assert r.status_code == 200, r.text
        rows = r.json()
        by_doc = next(a for a in rows if a["document_id"] == str(doc))
        by_src = next(a for a in rows if a["source_id"] == str(lone))
        return (by_doc["document_title"], by_doc["source_name"],
                by_src["source_name"])

    assert named() == (None, None, None), "withheld before any grant"
    _grant(client, auth, case_id=case_id, classification="RED")
    assert named() == (None, None, None), (
        "a grant on this case must not raise rows that belong to no case")
    listed = client.get("/api/v1/collection/documents", headers=auth)
    assert listed.status_code == 200, listed.text
    assert str(doc) not in {d["id"] for d in listed.json()["documents"]}

    _grant(client, auth, classification="RED")                   # global
    title, via_doc, via_src = named()
    assert title == "the next target"
    assert via_doc is not None and via_doc.startswith("bfr-forum-")
    assert via_src is not None and via_src.startswith("bfr-forum-")


# ---------------------------------------------------------------------------
# U2: a live grant cannot be reviewed
# ---------------------------------------------------------------------------

def test_a_live_grant_cannot_be_reviewed_until_it_ends(conn, client):
    """A verdict on a live grant removed it from `/unreviewed`, the only
    list, and with it the console's End it now, while the analyst kept the
    raised clearance for the rest of the grant."""
    _, so_email = _officer(conn)
    so = _session(conn, so_email)
    _, email = _user(conn, clearance="AMBER", roles=("CASE_OWNER",))
    gid = _grant(client, _session(conn, email), classification="RED")

    def queued():
        q = client.get("/api/v1/break-glass/unreviewed", headers=so)
        assert q.status_code == 200, q.text
        return gid in {g["id"] for g in q.json()["grants"]}

    r = client.post(f"/api/v1/break-glass/{gid}/review", headers=so,
                    json={"outcome": "UNJUSTIFIED", "note": "no emergency"})
    assert r.status_code == 409, r.text
    assert "still live" in r.json()["detail"]
    assert "end it now" in r.json()["detail"]
    assert queued(), "a refused verdict leaves the grant in the queue"

    assert client.post(f"/api/v1/break-glass/{gid}/revoke",
                       headers=so).status_code == 200
    assert queued(), "ending a grant is not reviewing it"
    r = client.post(f"/api/v1/break-glass/{gid}/review", headers=so,
                    json={"outcome": "UNJUSTIFIED", "note": "no emergency"})
    assert r.status_code == 200, r.text
    assert r.json()["review_outcome"] == "UNJUSTIFIED"
    assert not queued()


def test_the_database_clock_decides_whether_a_grant_has_ended(
        conn, monkeypatch):
    """The readable refusal uses this process's clock; the write itself is
    guarded by the database's, so an app server running ahead cannot
    review a grant that is still raising clearance."""
    from noctornal_api.break_glass import BreakGlassError, BreakGlassService, Grant
    officer, _ = _officer(conn)
    analyst, _ = _user(conn, roles=("CASE_OWNER",))
    svc = BreakGlassService(conn)
    grant = svc.invoke(user_id=analyst, case_id=None, classification="RED",
                       justification=WHY)
    monkeypatch.setattr(Grant, "is_live", lambda self, now=None: False)
    with pytest.raises(BreakGlassError, match="still live"):
        svc.review(grant.id, reviewer_id=officer, outcome="JUSTIFIED")
    assert svc.get(grant.id).reviewed_at is None


# ---------------------------------------------------------------------------
# U19: a use is a request the gate ALLOWED, once
# ---------------------------------------------------------------------------

def test_a_refused_request_is_not_a_use_of_the_grant(conn, client):
    """The count was taken while the context was built, before
    `evaluate()` ran, so a request the gate refused still counted and wrote
    a BREAK_GLASS_ACTION row."""
    from noctornal_api.security.access import CHECK_ASSIGNMENT, CHECK_COMPARTMENTS
    from noctornal_api.security.access import evaluate
    from noctornal_api.stores import PgAccessResolver
    _officer(conn)
    owner, case_id, uid, auth = _analyst_on_a_red_owners_case(
        conn, client, clearance="GREEN", case_level="AMBER")
    stranger = _case(client, _session(conn, conn.execute(
        "SELECT email FROM iam.app_user WHERE id = %s",
        (owner,)).fetchone()[0]), "AMBER")                  # not assigned
    gid = _grant(client, auth, classification="AMBER")          # global

    def decide(case, compartments=frozenset(), count_use=True):
        ctx = PgAccessResolver(conn).resolve(
            user_id=uid, case_id=UUID(case), permission_key="case.read",
            object_classification="AMBER", object_compartments=compartments,
            mfa_satisfied_at=None, count_use=count_use)
        return evaluate(ctx)

    d = decide(case_id, frozenset({"BFR_NOT_READ_IN"}))
    assert not d.allowed and CHECK_COMPARTMENTS in d.failed_checks
    d = decide(stranger)
    assert not d.allowed and CHECK_ASSIGNMENT in d.failed_checks
    assert _count(conn, gid) == 0, "refused requests are not uses"
    assert conn.execute(
        """SELECT count(*) FROM audit.event WHERE action = 'BREAK_GLASS_ACTION'
             AND object_id = %s""", (UUID(gid),)).fetchone()[0] == 0

    assert decide(case_id, count_use=False).allowed
    assert _count(conn, gid) == 0, "a question is not a use"
    assert decide(case_id).allowed
    assert _count(conn, gid) == 1, "an allowed request above clearance is one"


def test_an_inspector_open_is_one_use_not_two(conn, client):
    """On a case classified above the analyst's clearance every request is
    possible only through the grant, so each counts. But once: the
    `evidence.read` probe behind the assertion names is a question about
    the same request, and it counted a second use."""
    _officer(conn)
    owner, case_id, _uid, auth = _analyst_on_a_red_owners_case(
        conn, client, clearance="GREEN", case_level="AMBER")
    node = _node(conn, case_id, owner, "bfr_inspected")
    gid = _grant(client, auth, case_id=case_id, classification="AMBER")
    assert _count(conn, gid) == 0
    r = client.get(f"/api/v1/cases/{case_id}/nodes/{node}/assertions",
                   headers=auth)
    assert r.status_code == 200, r.text
    assert _count(conn, gid) == 1


# ---------------------------------------------------------------------------
# U23: a deception item opened by id above clearance is counted
# ---------------------------------------------------------------------------

def _exhibit(conn, case_id, owner, level):
    """Inserted directly, with no custody rows, so the fixture may delete
    it. Only its labels matter here."""
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, 'bec.eml', 'message/rfc822', 64, %s, %s, %s,
                   'test-bucket', %s, 'MANUAL_UPLOAD', now(), %s)
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"k/{uuid4().hex}",
         level, owner)).fetchone()[0]


def _capture(conn, case_id, owner, level):
    from noctornal_api.deception import DeceptionService
    return DeceptionService(conn).record_capture(
        case_id=UUID(case_id), requested_url="https://lure.example/login",
        capture_method="ANALYST_UPLOAD", captured_by=owner,
        classification=level)


def _message(conn, case_id, owner, level):
    exhibit = _exhibit(conn, case_id, owner, level)
    return conn.execute(
        """INSERT INTO deception.email_message
               (case_id, evidence_id, recorded_by, body_text, classification)
           VALUES (%s, %s, %s, 'wire it today', %s) RETURNING id""",
        (case_id, exhibit, owner, level)).fetchone()[0]


def test_a_red_capture_or_message_opened_under_a_grant_is_counted(
        conn, client):
    """An AMBER analyst on an AMBER case, under a RED grant on it, opens a
    RED capture and a RED message (body and all). The route gated at the
    CASE's labels only, so neither was ever counted, while the officer's
    card says items opened one by one are. Lists stay uncounted."""
    _officer(conn)
    owner, case_id, _uid, auth = _analyst_on_a_red_owners_case(conn, client)
    capture = _capture(conn, case_id, owner, "RED")
    message = _message(conn, case_id, owner, "RED")
    base = f"/api/v1/cases/{case_id}/deception"
    assert client.get(f"{base}/captures/{capture}",
                      headers=auth).status_code == 404, "hidden before"

    gid = _grant(client, auth, case_id=case_id, classification="RED")
    listed = client.get(f"{base}/captures", headers=auth)
    assert listed.status_code == 200, listed.text
    assert str(capture) in {c["id"] for c in listed.json()["captures"]}
    assert client.get(f"{base}/emails", headers=auth).status_code == 200
    assert _count(conn, gid) == 0, "lists are widened, not counted"

    r = client.get(f"{base}/captures/{capture}", headers=auth)
    assert r.status_code == 200, r.text
    assert _count(conn, gid) == 1
    r = client.get(f"{base}/emails/{message}", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["body_text"] == "wire it today"
    assert _count(conn, gid) == 2


# ---------------------------------------------------------------------------
# Fix round (2026-09-23): what the verifier found in the first pass
# ---------------------------------------------------------------------------

def test_on_a_case_above_clearance_a_capture_or_message_counts_once(
        conn, client):
    """The first U23 fix asked the gate again at the item's labels. On a
    case classified above the analyst's own clearance the route's case
    gate had already counted the request, so one open counted two: the
    inflation U19 removed from the inspector, brought back."""
    _officer(conn)
    owner, case_id, _uid, auth = _analyst_on_a_red_owners_case(
        conn, client, clearance="GREEN", case_level="AMBER")
    same = _capture(conn, case_id, owner, "AMBER")       # the case's level
    stricter = _capture(conn, case_id, owner, "RED")     # above it
    message = _message(conn, case_id, owner, "RED")
    gid = _grant(client, auth, case_id=case_id, classification="RED")
    base = f"/api/v1/cases/{case_id}/deception"

    def uses(path) -> int:
        before = _count(conn, gid)
        r = client.get(path, headers=auth)
        assert r.status_code == 200, r.text
        return _count(conn, gid) - before

    assert uses(f"{base}/captures") == 1, (
        "every request on a case above clearance is a use of the grant")
    assert uses(f"{base}/captures/{same}") == 1
    assert uses(f"{base}/captures/{stricter}") == 1
    assert uses(f"{base}/emails/{message}") == 1


def test_the_invoke_notice_says_only_what_is_counted(conn, client):
    """The first U19 fix told the invoker "each item it opens above your
    own clearance is counted". An entity opened in the inspector is gated
    at its case's labels and never was. The notice now names what the
    counting gates see, and this pins the words to the behaviour: what it
    says is not counted is not, and what it says is counted is, once."""
    from noctornal_api.http.routers.governance import _COUNTED
    _officer(conn)
    owner, case_id, _uid, auth = _analyst_on_a_red_owners_case(conn, client)
    node = _node(conn, case_id, owner, "bfr_red_entity", level="RED")
    exhibit = _exhibit(conn, case_id, owner, "RED")
    capture = _capture(conn, case_id, owner, "RED")
    case = f"/api/v1/cases/{case_id}"
    assert client.get(f"{case}/nodes/{node}",
                      headers=auth).status_code == 404, "hidden before"

    r = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "duration_hours": 1, "case_id": case_id,
        "classification": "RED"})
    assert r.status_code == 201, r.text
    notice, gid = r.json()["notice"], r.json()["id"]
    assert _COUNTED in notice
    assert "Each item it opens" not in notice
    assert chr(0x2014) not in notice and chr(0x2013) not in notice

    # Not counted, as the notice says: the entity and the lists it widens.
    for path in (f"{case}/nodes/{node}", f"{case}/nodes/{node}/assertions",
                 f"{case}/nodes", f"{case}/deception/captures"):
        got = client.get(path, headers=auth)
        assert got.status_code == 200, (path, got.text)
    assert str(node) in {n["id"] for n in client.get(
        f"{case}/nodes", headers=auth).json()}, "the grant did widen it"
    assert _count(conn, gid) == 0

    # Counted, once each: an exhibit, a capture, a change to the entity.
    got = client.get(f"{case}/evidence/{exhibit}/custody", headers=auth)
    assert got.status_code == 200, got.text
    assert _count(conn, gid) == 1
    got = client.get(f"{case}/deception/captures/{capture}", headers=auth)
    assert got.status_code == 200, got.text
    assert _count(conn, gid) == 2
    got = client.post(f"{case}/nodes/{node}/assertions", headers=auth,
                      json={"basis": "DIRECT_OBSERVATION",
                            "reliability": "F", "credibility": "6",
                            "confidence": "LOW",
                            "rationale": "seen on the forum"})
    assert got.status_code == 201, got.text
    assert _count(conn, gid) == 3


def test_the_live_recheck_and_the_ingest_probe_are_questions(conn, client):
    """Two more gates asked as questions still counted after the first
    pass: the live socket's re-check before every delivery, and the ingest
    queue's per-case, per-label probe. The socket's opening still counts,
    once, as the request it is."""
    from noctornal_api.http.deps import CurrentUser
    from noctornal_api.http.routers.ingest import _case_allows
    from noctornal_api.http.routers.live import _may_read, _recheck
    _officer(conn)
    _owner, case_id, uid, auth = _analyst_on_a_red_owners_case(
        conn, client, clearance="GREEN", case_level="AMBER")
    gid = _grant(client, auth, case_id=case_id, classification="AMBER")
    case = UUID(case_id)
    me = CurrentUser(user_id=uid, session_id=uuid4(), session_mfa_at=None)

    assert _recheck(uid, case, None)
    assert _recheck(uid, case, None)
    assert _case_allows(conn, me, case, "ingest.read")
    assert _case_allows(conn, me, case, "ingest.read", classification="AMBER")
    assert _count(conn, gid) == 0, "questions are not uses"
    assert _may_read(conn, uid, case, None), "the socket's opening"
    assert _count(conn, gid) == 1
