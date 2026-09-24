"""A break-glass use is counted once per request, not once per gate
(sec-breakglass-double-count, 2026-09-23).

On a case classified above the invoker's own clearance, every request
passes the case's gate only through the grant, so `PgAccessResolver`
counts it there. A request that then passes a SECOND gate at an item's
labels (an exhibit route, a capture screenshot, an entity write, a tag
on a node, an approval) was counted again, so the officer's card read one
exhibit opened as two accesses. `deps.authorize_object` now passes
`count_use` through, and a second gate marked `after_case_gate=True`
counts only when the case's own gate did not.

Every "counts once" assertion below fails on the base commit (245cb57),
where each of those requests added two. The within-clearance test pins
what must NOT change: there the case's gate never counted, and an item
whose own labels need the grant is still counted, once.

The figure asserted is the one the Security Officer's review card prints:
`action_count` on `GET /break-glass/unreviewed`.

**The email prefix is `bco-` and must stay unique**: the fixture cleans
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
#: Every grading field, given: the API requires a claim's grading.
GRADE = {"basis": "DIRECT_OBSERVATION", "reliability": "B",
         "credibility": "2", "confidence": "LOW"}


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'bco-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification "
                  f"  WHERE recipient_id IN {sub} OR actor_id IN {sub}"
                  f"     OR case_id IN {csub})")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}"
                  f"    OR case_id IN {csub}")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.tag_assignment WHERE tag_id IN "
                  f"(SELECT id FROM core.tag WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.tag WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM deception.capture_hop WHERE capture_id IN "
                  f"(SELECT id FROM deception.capture WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM deception.capture WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        # Exhibits inserted directly (no custody rows), so they can go.
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'bco-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, *, name, clearance, roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"bco-{uuid4().hex[:8]}@noctornal.test"
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


def _setting(conn, client, *, clearance, case_level):
    """A RED Lead investigator owns a case at `case_level`; an analyst at
    `clearance` is assigned to it as ANALYST and holds global CASE_OWNER,
    which carries `break_glass.invoke`. A Security Officer who is not the
    invoker exists, or the grant is refused. Returns the owner, the case,
    the analyst's headers and the officer's."""
    _officer, officer_email = _user(conn, name="Otto Officer", clearance="RED",
                                    roles=("SECURITY_OFFICER",))
    owner, owner_email = _user(conn, name="Rhea Red", clearance="RED",
                               roles=("CASE_OWNER",))
    r = client.post("/api/v1/cases", headers=_session(conn, owner_email), json={
        "code": f"OP-BCO-{uuid4().hex[:6].upper()}", "title": "Operation BCO",
        "legal_basis": "production order 2026-0923",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)),
        "classification": case_level})
    assert r.status_code == 201, r.text
    case_id = r.json()["id"]
    uid, email = _user(conn, name="Gil Green", clearance=clearance,
                       roles=("CASE_OWNER",))
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, 'ANALYST', %s)", (case_id, uid, owner))
    return owner, case_id, _session(conn, email), _session(conn, officer_email)


def _grant(client, auth, case_id, level) -> str:
    r = client.post("/api/v1/break-glass", headers=auth,
                    json={"justification": WHY, "duration_hours": 1,
                          "case_id": case_id, "classification": level})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _count(conn, grant_id) -> int:
    return conn.execute("SELECT action_count FROM iam.break_glass WHERE id = %s",
                        (grant_id,)).fetchone()[0]


def _card_figure(client, officer, grant_id) -> int:
    """What the officer's review card prints as "used"."""
    r = client.get("/api/v1/break-glass/unreviewed", headers=officer)
    assert r.status_code == 200, r.text
    card = next(g for g in r.json()["grants"] if g["id"] == grant_id)
    return card["action_count"]


def _exhibit(conn, case_id, owner, level, *, hostile=False):
    """Inserted directly, with no custody rows, so the fixture may delete
    it. Only its labels matter, and `hostile` lets the screenshot route
    pass its gate and then refuse with a 409 before reading any bytes."""
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by,
                is_hostile_markup)
           VALUES (%s, 'shot.png', 'image/png', 64, %s, %s, %s,
                   'test-bucket', %s, 'MANUAL_UPLOAD', now(), %s, %s)
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"k/{uuid4().hex}",
         level, owner, hostile)).fetchone()[0]


def _capture_with_screenshot(conn, case_id, owner, level):
    from noctornal_api.deception import DeceptionService
    shot = _exhibit(conn, case_id, owner, level, hostile=True)
    return DeceptionService(conn).record_capture(
        case_id=UUID(case_id), requested_url="https://lure.example/login",
        capture_method="ANALYST_UPLOAD", captured_by=owner,
        classification=level, screenshot_evidence_id=shot)


def _node(conn, case_id, owner, label, level):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label,
        classification=level, created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner))


def _ledger(conn, gid) -> list[str]:
    """The verbs of the grant's BREAK_GLASS_ACTION audit rows, oldest first."""
    return [r[0] for r in conn.execute(
        "SELECT detail->>'action' FROM audit.event "
        " WHERE action = 'BREAK_GLASS_ACTION' AND object_id = %s "
        " ORDER BY seq", (gid,)).fetchall()]


def _uses(conn, client, gid, method, path, auth, expect, **kw) -> int:
    before = _count(conn, gid)
    r = client.request(method, path, headers=auth, **kw)
    assert r.status_code == expect, (path, r.status_code, r.text)
    return _count(conn, gid) - before


def test_on_a_case_above_clearance_each_request_is_one_use(conn, client):
    """A GREEN analyst on an AMBER case under a RED grant. Every request
    below passes the case's gate only through the grant and then a second
    gate at an item's labels; each added two to `action_count` before the
    passthrough, and adds one now, whether the item sits at the case's
    level or above it."""
    owner, case_id, auth, officer = _setting(
        conn, client, clearance="GREEN", case_level="AMBER")
    same = _exhibit(conn, case_id, owner, "AMBER")
    stricter = _exhibit(conn, case_id, owner, "RED")
    capture = _capture_with_screenshot(conn, case_id, owner, "RED")
    node = _node(conn, case_id, owner, "bco_red_entity", "RED")
    gid = _grant(client, auth, case_id, "RED")
    case = f"/api/v1/cases/{case_id}"

    assert _uses(conn, client, gid, "GET",
                 f"{case}/evidence/{same}/custody", auth, 200) == 1
    assert _uses(conn, client, gid, "GET",
                 f"{case}/evidence/{stricter}/custody", auth, 200) == 1
    # Gated, counted, then refused as hostile markup before any bytes are
    # read: the count is taken at the gate.
    assert _uses(conn, client, gid, "GET",
                 f"{case}/deception/captures/{capture}/screenshot",
                 auth, 409) == 1
    assert _uses(conn, client, gid, "GET",
                 f"{case}/deception/captures/{capture}", auth, 200) == 1
    assert _uses(conn, client, gid, "POST", f"{case}/nodes/{node}/assertions",
                 auth, 201, json={**GRADE, "rationale": "seen on the forum"}) == 1
    assert _uses(conn, client, gid, "PATCH", f"{case}/graph/nodes/{node}",
                 auth, 200, json={"label": "bco_red_entity_corrected",
                                  "assertion": GRADE}) == 1

    before = _count(conn, gid)
    tag = client.post(f"{case}/curation/tags", headers=auth,
                      json={"namespace": "bco", "name": "watched"})
    assert tag.status_code == 201, tag.text
    assert _count(conn, gid) - before == 1, "one gate, one use"
    assert _uses(conn, client, gid, "POST",
                 f"{case}/curation/tags/{tag.json()['id']}/nodes", auth, 201,
                 json={"node_id": str(node)}) == 1

    assert _uses(conn, client, gid, "POST", f"{case}/approvals", auth, 201,
                 json={"operation": "node.merge",
                       "payload": {"survivor": str(node), "loser": str(uuid4())},
                       "justification": "the same actor under two handles"}) == 1
    # The one use row names the case gate's verb (case.read); the operation
    # is the request's own audit event, by the same actor on the same case
    # (break_glass.py, property 4, "What the one row says").
    ledger = _ledger(conn, gid)
    assert ledger[-1] == "case.read"
    requested = conn.execute(
        "SELECT a.detail->>'operation' FROM audit.event a "
        " WHERE a.action = 'APPROVAL_REQUESTED' AND a.case_id = %s "
        "   AND a.actor_id = (SELECT user_id FROM iam.break_glass "
        "                      WHERE id = %s)", (case_id, gid)).fetchall()
    assert requested == [("node.merge",)]

    assertion = conn.execute(
        "SELECT id FROM core.assertion WHERE node_id = %s "
        "  AND retracted_at IS NULL ORDER BY recorded_at DESC LIMIT 1",
        (node,)).fetchone()[0]
    assert _uses(conn, client, gid, "POST",
                 f"{case}/assertions/{assertion}/retract", auth, 204,
                 json={"reason": "the forum post was a quote"}) == 1

    # Ten requests, ten uses, and the officer's card says ten. The audit
    # ledger agrees row for use: one BREAK_GLASS_ACTION per request.
    assert _count(conn, gid) == 10
    assert _card_figure(client, officer, gid) == 10
    assert len(_ledger(conn, gid)) == 10


def test_within_clearance_only_an_item_above_it_is_counted(conn, client):
    """What the passthrough must not change. An AMBER analyst on an AMBER
    case under a RED grant: the case's gate never needed the grant, so the
    second gate is the one that counts, and only for an item whose own
    labels sit above AMBER."""
    owner, case_id, auth, officer = _setting(
        conn, client, clearance="AMBER", case_level="AMBER")
    same = _exhibit(conn, case_id, owner, "AMBER")
    stricter = _exhibit(conn, case_id, owner, "RED")
    capture = _capture_with_screenshot(conn, case_id, owner, "RED")
    amber_node = _node(conn, case_id, owner, "bco_amber_entity", "AMBER")
    red_node = _node(conn, case_id, owner, "bco_red_entity", "RED")
    gid = _grant(client, auth, case_id, "RED")
    case = f"/api/v1/cases/{case_id}"

    assert _uses(conn, client, gid, "GET",
                 f"{case}/evidence/{same}/custody", auth, 200) == 0
    assert _uses(conn, client, gid, "GET",
                 f"{case}/evidence/{stricter}/custody", auth, 200) == 1
    assert _uses(conn, client, gid, "GET",
                 f"{case}/deception/captures/{capture}/screenshot",
                 auth, 409) == 1
    assert _uses(conn, client, gid, "POST",
                 f"{case}/nodes/{amber_node}/assertions", auth, 201,
                 json=GRADE) == 0
    assert _uses(conn, client, gid, "POST",
                 f"{case}/nodes/{red_node}/assertions", auth, 201,
                 json=GRADE) == 1
    assert _card_figure(client, officer, gid) == 3


def test_a_second_gate_refusal_keeps_the_case_gates_use(conn, client):
    """The one request `counted_at_case_gate` leaves counted although it
    was refused, pinned so it is a decision and not a surprise. A GREEN
    analyst on an AMBER case under an AMBER grant asks for a RED exhibit:
    the grant let the request past the case's gate (and so tells an
    exhibit that exists from one that does not), and the exhibit's gate
    refuses. One use, not two, and not none."""
    owner, case_id, auth, _officer = _setting(
        conn, client, clearance="GREEN", case_level="AMBER")
    stricter = _exhibit(conn, case_id, owner, "RED")
    gid = _grant(client, auth, case_id, "AMBER")
    case = f"/api/v1/cases/{case_id}"
    assert _uses(conn, client, gid, "GET",
                 f"{case}/evidence/{stricter}/custody", auth, 403) == 1
    assert _uses(conn, client, gid, "GET",
                 f"{case}/evidence/{uuid4()}/custody", auth, 404) == 1


def test_the_passthrough_and_the_second_gate_flag(conn, client):
    """`authorize_object` itself: `count_use=False` is a question at any
    gate, and `after_case_gate=True` counts only what the case's own gate
    did not, on each side of the caller's clearance."""
    from noctornal_api.http.deps import (
        CurrentUser,
        authorize_object,
        counted_at_case_gate,
    )
    owner, above, auth, _officer = _setting(
        conn, client, clearance="GREEN", case_level="AMBER")
    uid = conn.execute(
        "SELECT user_id FROM iam.case_assignment WHERE case_id = %s "
        "AND role_key = 'ANALYST'", (above,)).fetchone()[0]
    gid = _grant(client, auth, above, "RED")
    me = CurrentUser(user_id=uid, session_id=uuid4(), session_mfa_at=None)
    case = UUID(above)

    assert counted_at_case_gate(conn, me, case)
    authorize_object(conn, me, case_id=case, permission_key="evidence.read",
                     count_use=False)
    assert _count(conn, gid) == 0, "a question is not a use"
    authorize_object(conn, me, case_id=case, permission_key="evidence.read")
    assert _count(conn, gid) == 1, "the case's gate, through the grant"
    authorize_object(conn, me, case_id=case, permission_key="evidence.read",
                     after_case_gate=True, classification="RED")
    assert _count(conn, gid) == 1, "the second gate adds nothing here"

    conn.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' "
                 "WHERE id = %s", (uid,))
    assert not counted_at_case_gate(conn, me, case)
    authorize_object(conn, me, case_id=case, permission_key="evidence.read",
                     after_case_gate=True, classification="RED")
    assert _count(conn, gid) == 2, "the item needed the grant; the case did not"
    authorize_object(conn, me, case_id=case, permission_key="evidence.read",
                     after_case_gate=True, count_use=False,
                     classification="RED")
    assert _count(conn, gid) == 2, "count_use=False wins over the flag"
