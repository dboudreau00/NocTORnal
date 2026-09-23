"""Break-glass, sharing and the way into Administration, over HTTP.

The review of 2026-09-22 found each of these saying something the server
did not do, or asking for something nobody could supply:

- the console's break-glass grant named no level, so it raised nothing
  while the console said "Granted" (ux15 breakglass-grant-raises-nothing);
- the officer's review queue titled every card with a UUID and could not
  say which case a grant covered (ux15 glass-review-queue-uninformative);
- sharing a case needed an `iam.app_user.id` that no screen available to a
  case owner showed, and nothing could take a colleague off again (ux02,
  ux16, ux19);
- confirming a retention rule said the category "now retains" for the new
  period while every record on file kept its old clock (ux15
  rule-confirm-misstates-effect);
- the Destroyed list could not say who purged (ux15 tombstone-rows-blank);
- Administration was reachable only from inside a case (ux16);
- approvals named people by UUID (ux19 raw-ids-instead-of-names).

Each test here holds one of the server halves of those fixes. The console
halves are pinned by `test_ui_governance_invariants.py`.

**The email prefix is `bsa-` and must stay unique**: every fixture here
cleans up by deleting on it, and two files sharing a prefix delete each
other's rows mid-run.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; break-glass/share e2e is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple"

#: A throwaway retention category. Rules are GLOBAL, so confirming a seeded
#: one would change the deployment every later test runs against; a new
#: key is inserted by the upsert and deleted in teardown.
TEST_CATEGORY = "BSA_TEST_CATEGORY"



@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'bsa-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM notify.notification "
                  f" WHERE recipient_id IN {sub} OR actor_id IN {sub}"
                  f"    OR case_id IN {csub}")
        c.execute("DELETE FROM core.retention_rule WHERE category = %s",
                  (TEST_CATEGORY,))
        c.execute(f"UPDATE core.retention_rule SET confirmed_by = NULL, "
                  f"confirmed_at = NULL WHERE confirmed_by IN {sub}")
        c.execute("ALTER TABLE core.purge_tombstone DISABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.purge_tombstone WHERE purged_by IN {sub}")
        c.execute("ALTER TABLE core.purge_tombstone ENABLE TRIGGER USER")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN "
                  f"(SELECT id FROM core.evidence WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        # Exhibits inserted directly (no custody rows), so they can go.
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'bsa-%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, *, name="BSA", clearance="AMBER", roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"bsa-{uuid4().hex[:8]}@noctornal.test"
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


def _case(client, auth, classification="AMBER") -> tuple[str, str]:
    code = f"OP-BSA-{uuid4().hex[:6].upper()}"
    r = client.post("/api/v1/cases", headers=auth, json={
        "code": code, "title": "Operation BSA",
        "legal_basis": "production order 2026-0922",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)),
        "classification": classification})
    assert r.status_code == 201, r.text
    return r.json()["id"], code


def _officer(conn):
    """Break-glass refuses outright when nobody could review it."""
    return _user(conn, name="BSA Officer", clearance="RED",
                 roles=("SECURITY_OFFICER",))


WHY = ("Incident 2026-0922: a RED exhibit on this case names the next "
       "target and it is needed within the hour.")


# ---------------------------------------------------------------------------
# Break-glass: the grant says what it does
# ---------------------------------------------------------------------------

def test_a_grant_on_a_case_says_what_it_raises_and_where(conn, client):
    """The console's grant used to name no level and no case, and was
    reported as "Granted" while no access decision read it."""
    _officer(conn)
    _, email = _user(conn, name="Alex Amber", clearance="AMBER",
                     roles=("CASE_OWNER",))
    auth = _session(conn, email)
    case_id, code = _case(client, auth)
    r = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "case_id": case_id,
        "classification": "red", "duration_hours": 1})
    assert r.status_code == 201, r.text
    g = r.json()
    assert g["raises"] is True
    assert g["granted_classification"] == "RED", "the level is normalised"
    assert g["scope"] == "case" and g["case_code"] == code
    assert g["base_clearance"] == "AMBER"
    assert f"from AMBER to RED on {code}" in g["notice"]
    assert "raises nothing" not in g["notice"]


def test_a_grant_naming_no_level_says_it_raises_nothing(conn, client):
    """Still allowed (the door stays easy), but never described as access."""
    _officer(conn)
    _, email = _user(conn, roles=("CASE_OWNER",))
    r = client.post("/api/v1/break-glass", headers=_session(conn, email),
                    json={"justification": WHY})
    assert r.status_code == 201, r.text
    assert r.json()["raises"] is False
    assert "raises nothing" in r.json()["notice"]
    assert r.json()["granted_classification"] is None


def test_a_level_the_caller_already_holds_raises_nothing(conn, client):
    _officer(conn)
    _, email = _user(conn, clearance="RED", roles=("CASE_OWNER",))
    r = client.post("/api/v1/break-glass", headers=_session(conn, email),
                    json={"justification": WHY, "classification": "RED"})
    assert r.status_code == 201, r.text
    assert r.json()["raises"] is False
    assert "already RED" in r.json()["notice"]


def test_an_unknown_level_is_a_400_naming_the_levels_not_a_500(conn, client):
    """`granted_classification` is a `core.tlp` enum column, so an unknown
    value used to reach the database and surface as an unexplained 500."""
    _officer(conn)
    _, email = _user(conn, roles=("CASE_OWNER",))
    r = client.post("/api/v1/break-glass", headers=_session(conn, email),
                    json={"justification": WHY, "classification": "PURPLE"})
    assert r.status_code == 400, r.text
    assert "AMBER_STRICT" in r.json()["detail"]
    assert conn.execute(
        "SELECT count(*) FROM iam.break_glass bg JOIN iam.app_user u "
        "ON u.id = bg.user_id WHERE u.email = %s", (email,)).fetchone()[0] == 0


def test_a_grant_cannot_name_a_case_the_caller_is_not_on(conn, client):
    """The raise is to CLEARANCE only, so on a case the caller is not
    assigned to it opens nothing. And "no such case" and "not yours" must
    be one answer, or this confirms which case ids exist."""
    _officer(conn)
    _, owner_email = _user(conn, roles=("CASE_OWNER",))
    theirs, _ = _case(client, _session(conn, owner_email))
    _, email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, email)
    real = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "case_id": theirs, "classification": "RED"})
    fake = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "case_id": str(uuid4()), "classification": "RED"})
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()


def test_mine_lists_every_live_grant_with_the_callers_clearance(conn, client):
    """The header chip reads this on every screen. A grant scoped to case A
    must still show while the analyst is on case B or on the list."""
    _officer(conn)
    _, email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, email)
    case_id, code = _case(client, auth)
    assert client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "case_id": case_id,
        "classification": "RED"}).status_code == 201

    anywhere = client.get("/api/v1/break-glass/mine", headers=auth).json()
    assert anywhere["clearance"] == "AMBER"
    assert anywhere["live"] is False, "no GLOBAL grant is live"
    assert [g["case_code"] for g in anywhere["grants"]] == [code]
    here = client.get(f"/api/v1/break-glass/mine?case_id={case_id}",
                      headers=auth).json()
    assert here["live"] is True and here["grant"]["scope"] == "case"


def test_the_review_queue_names_the_person_the_case_and_the_level(conn, client):
    """The card printed `g.user_email || g.user_id` and no response carried
    the email, so every card was titled with a UUID."""
    _, so_email = _officer(conn)
    _, email = _user(conn, name="Alex Amber", clearance="AMBER",
                     roles=("CASE_OWNER",))
    auth = _session(conn, email)
    case_id, code = _case(client, auth)
    gid = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "case_id": case_id,
        "classification": "RED"}).json()["id"]
    q = client.get("/api/v1/break-glass/unreviewed",
                   headers=_session(conn, so_email)).json()
    card = next(g for g in q["grants"] if g["id"] == gid)
    assert card["user_display_name"] == "Alex Amber"
    assert card["user_email"] == email
    assert card["case_code"] == code
    assert card["granted_classification"] == "RED"
    assert card["is_live"] is True and card["revoked_at"] is None


def test_review_stays_with_the_officer_and_is_never_your_own(conn, client):
    """The console now names people and confirms verdicts; none of that may
    loosen the two-person rule. An account that is both an officer and an
    invoker still cannot review its own grant."""
    _officer(conn)                                   # somebody else can review
    _, email = _user(conn, clearance="AMBER",
                     roles=("SYS_ADMIN", "SECURITY_OFFICER"))
    auth = _session(conn, email)
    gid = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "classification": "RED"}).json()["id"]
    r = client.post(f"/api/v1/break-glass/{gid}/review", headers=auth,
                    json={"outcome": "JUSTIFIED", "note": "self review attempt"})
    assert r.status_code == 409, r.text
    assert "your own" in r.json()["detail"]

    _, analyst_email = _user(conn, roles=("CASE_OWNER",))
    r = client.post(f"/api/v1/break-glass/{gid}/review",
                    headers=_session(conn, analyst_email),
                    json={"outcome": "JUSTIFIED", "note": "not an officer"})
    assert r.status_code == 403


# --- fix round, 2026-09-23 --------------------------------------------------

def test_the_highest_live_grant_is_the_one_in_force(conn, client):
    """An 8-hour AMBER grant, then a 1-hour RED one on a case. The notice
    said "raised to RED" while the gate kept reading the AMBER row, because
    it ends later (`ORDER BY expires_at DESC LIMIT 1`). The gate now reads
    the highest live level, so the notice is true."""
    from uuid import UUID

    from noctornal_api.security.access import evaluate
    from noctornal_api.stores import PgAccessResolver
    _officer(conn)
    owner, owner_email = _user(conn, clearance="RED", roles=("CASE_OWNER",))
    case_id, code = _case(client, _session(conn, owner_email),
                          classification="RED")
    uid, email = _user(conn, name="Gale Green", clearance="GREEN",
                       roles=("CASE_OWNER",))
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, 'ANALYST', %s)", (case_id, uid, owner))
    auth = _session(conn, email)
    wide = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "classification": "AMBER", "duration_hours": 8})
    assert wide.status_code == 201, wide.text
    narrow = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "case_id": case_id, "classification": "RED",
        "duration_hours": 1})
    assert narrow.status_code == 201, narrow.text
    assert narrow.json()["raises"] is True
    assert f"from GREEN to RED on {code}" in narrow.json()["notice"]

    ctx = PgAccessResolver(conn).resolve(
        user_id=uid, case_id=UUID(case_id), permission_key="case.read",
        object_classification="RED", object_compartments=frozenset(),
        mfa_satisfied_at=None)
    assert evaluate(ctx).allowed, "the RED grant is the one in force here"
    mine = client.get(f"/api/v1/break-glass/mine?case_id={case_id}",
                      headers=auth).json()
    assert mine["grant"]["granted_classification"] == "RED"
    assert [g["granted_classification"] for g in mine["grants"]] == ["RED", "AMBER"]


def test_a_grant_covered_by_a_higher_longer_one_raises_nothing_more(conn, client):
    _officer(conn)
    _, email = _user(conn, clearance="GREEN", roles=("CASE_OWNER",))
    auth = _session(conn, email)
    case_id, _ = _case(client, auth, classification="GREEN")
    assert client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "classification": "RED",
        "duration_hours": 8}).status_code == 201
    r = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "case_id": case_id, "classification": "AMBER",
        "duration_hours": 1})
    assert r.status_code == 201, r.text
    assert r.json()["raises"] is False
    assert ("already hold a live RED grant on every case you are assigned to"
            in r.json()["notice"])


def test_the_notice_prints_utc_whatever_the_session_zone():
    """psycopg returns a timestamptz in the SESSION's zone and nothing pins
    it, so `strftime("%H:%M UTC")` on the raw value printed local hours
    labelled UTC. Built here with a -03:00 value, as a session in Halifax
    summer time would return it."""
    from datetime import datetime, timedelta, timezone

    from noctornal_api.break_glass import Grant
    from noctornal_api.http.routers.governance import _invoke_notice
    local = timezone(timedelta(hours=-3))
    g = Grant(id=uuid4(), user_id=uuid4(), case_id=None, justification=WHY,
              started_at=datetime(2026, 9, 22, 21, 30, tzinfo=local),
              expires_at=datetime(2026, 9, 22, 23, 30, tzinfo=local),
              granted_classification="RED", granted_permissions=[],
              used_at=None, action_count=0, revoked_at=None, reviewed_by=None,
              reviewed_at=None, review_outcome=None)
    text, raises = _invoke_notice(g, "AMBER", None)
    assert raises is True
    assert "until 02:30 UTC" in text and "23:30" not in text


def test_the_review_card_knows_whether_the_grant_raised_anything(conn, client):
    """The card said "raised to RED" for any grant naming RED, including
    one by somebody who already held RED. Their level at invoke is recorded
    with the invoke and read back."""
    _, so_email = _officer(conn)
    _, low = _user(conn, clearance="AMBER", roles=("CASE_OWNER",))
    _, high = _user(conn, clearance="RED", roles=("CASE_OWNER",))
    raised = client.post("/api/v1/break-glass", headers=_session(conn, low),
                         json={"justification": WHY,
                               "classification": "RED"}).json()["id"]
    held = client.post("/api/v1/break-glass", headers=_session(conn, high),
                       json={"justification": WHY,
                             "classification": "RED"}).json()["id"]
    q = {g["id"]: g for g in client.get(
        "/api/v1/break-glass/unreviewed",
        headers=_session(conn, so_email)).json()["grants"]}
    assert q[raised]["raised"] is True and q[raised]["base_clearance"] == "AMBER"
    assert q[held]["raised"] is False and q[held]["base_clearance"] == "RED"


# --- verifier follow-up, 2026-09-23 ------------------------------------------

def _exhibit(conn, case_id, owner, title, level):
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, %s, 'image/png', 1024, %s, %s, %s, 'test-bucket',
                   %s, 'SCREENSHOT', now(), %s)
           RETURNING id""",
        (case_id, title, os.urandom(32), os.urandom(32),
         f"k/{uuid4().hex}", level, owner)).fetchone()[0]


def _red_node(conn, case_id, owner, label):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label,
        classification="RED", created_by=owner,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=owner))


def _what_they_see(client, auth, case_id, node, exhibit, label) -> dict:
    """The reads the console makes of one case, reduced to "is the RED
    material in them"."""
    base = f"/api/v1/cases/{case_id}"

    def ids(path):
        r = client.get(base + path, headers=auth)
        if r.status_code == 404 and path.startswith("/nodes/"):
            return set()               # the node itself is hidden
        assert r.status_code == 200, (path, r.text)
        return {row["id"] for row in r.json()}

    graph = client.get(base + "/graph", headers=auth)
    assert graph.status_code == 200, graph.text
    return {
        "exhibit list": str(exhibit) in ids("/evidence-list"),
        "entity list": str(node) in ids("/nodes"),
        "entity": client.get(f"{base}/nodes/{node}",
                             headers=auth).status_code == 200,
        "entity exhibits": str(exhibit) in ids(f"/nodes/{node}/evidence"),
        "graph": str(node) in {n["id"] for n in graph.json()["nodes"]},
        "search": str(node) in ids(f"/search/nodes?q={label}"),
    }


def test_a_case_grant_opens_what_the_console_reads_on_that_case_only(
        conn, client):
    """The console's default scope is the open case. A RED grant on it was
    announced as live emergency access, yet the graph, the entity and
    exhibit lists, the inspector and search on that case still hid every
    RED item, because they filtered on `deps.user_ceiling`, which ignored
    case-scoped grants. Only opening an exhibit by id was raised, and no
    list revealed the id. The 3am scenario of the finding survived."""
    from uuid import UUID

    from noctornal_api.http.deps import user_ceiling
    from noctornal_api.security.access import Tlp
    _officer(conn)
    red_owner, red_email = _user(conn, name="Rhea Red", clearance="RED",
                                 roles=("CASE_OWNER",))
    red_auth = _session(conn, red_email)
    here, code = _case(client, red_auth)                     # AMBER
    there, _ = _case(client, red_auth)                       # AMBER
    uid, email = _user(conn, name="Amy Amber", clearance="AMBER",
                       roles=("CASE_OWNER",))
    for case_id in (here, there):
        conn.execute(
            "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
            "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
            (case_id, uid, red_owner))
    seen = {}
    for case_id, label in ((here, "nightjar_red"), (there, "kestrel_red")):
        node = _red_node(conn, case_id, red_owner, label)
        ev = _exhibit(conn, case_id, red_owner, f"{label}.pdf", "RED")
        conn.execute(
            "INSERT INTO core.evidence_link (evidence_id, node_id, created_by) "
            "VALUES (%s, %s, %s)", (ev, node, red_owner))
        seen[case_id] = (node, ev, label)
    auth = _session(conn, email)

    def view(case_id):
        node, ev, label = seen[case_id]
        return _what_they_see(client, auth, case_id, node, ev, label)

    assert not any(view(here).values()), "RED hidden before the grant"
    r = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "case_id": here, "classification": "RED",
        "duration_hours": 1})
    assert r.status_code == 201, r.text
    assert r.json()["raises"] is True
    notice = r.json()["notice"]
    assert f"from AMBER to RED on {code}" in notice
    assert "the graph, the entity and exhibit lists" in notice
    assert "No other case changes" in notice
    assert "stay within AMBER" in notice

    assert all(view(here).values()), view(here)
    assert not any(view(there).values()), (
        "a grant on one case must not widen any other", view(there))
    # The case-less ceiling, behind writes, reports and the deployment
    # views, is untouched by a case grant...
    assert user_ceiling(conn, uid)[0] == Tlp.AMBER
    assert user_ceiling(conn, uid, case_id=UUID(there))[0] == Tlp.AMBER
    assert user_ceiling(conn, uid, case_id=UUID(here))[0] == Tlp.RED
    # ...so a report asked for at RED on the granted case is built at AMBER.
    rep = client.post(f"/api/v1/cases/{here}/report?target_tlp=RED",
                      headers=auth)
    assert rep.status_code == 200, rep.text
    built = conn.execute(
        """SELECT detail->>'target_tlp' FROM audit.event
            WHERE case_id = %s AND action = 'REPORT_GENERATED'
            ORDER BY seq DESC LIMIT 1""", (here,)).fetchone()
    assert built == ("AMBER",), built


def test_a_global_grant_still_opens_every_assigned_case(conn, client):
    """The case parameter must not narrow what a GLOBAL grant opens."""
    _officer(conn)
    red_owner, red_email = _user(conn, clearance="RED", roles=("CASE_OWNER",))
    case_id, _ = _case(client, _session(conn, red_email))
    uid, email = _user(conn, clearance="AMBER", roles=("CASE_OWNER",))
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, 'ANALYST', %s)", (case_id, uid, red_owner))
    node = _red_node(conn, case_id, red_owner, "global_red")
    ev = _exhibit(conn, case_id, red_owner, "global_red.pdf", "RED")
    conn.execute(
        "INSERT INTO core.evidence_link (evidence_id, node_id, created_by) "
        "VALUES (%s, %s, %s)", (ev, node, red_owner))
    auth = _session(conn, email)
    r = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "classification": "RED", "duration_hours": 1})
    assert r.status_code == 201, r.text
    assert "Lab, collection and ingest" in r.json()["notice"]
    assert all(_what_they_see(client, auth, case_id, node, ev,
                              "global_red").values())


def test_the_case_list_offers_a_case_a_grant_opens(conn, client):
    """The case list is the console's only way into a case, and it counted
    the analyst's own clearance alone. An analyst assigned to an AMBER case
    with GREEN clearance had the gate opened by a grant and still could not
    find the case to open."""
    _officer(conn)
    red_owner, red_email = _user(conn, clearance="RED", roles=("CASE_OWNER",))
    red_auth = _session(conn, red_email)
    here, code = _case(client, red_auth)                       # AMBER
    there, other = _case(client, red_auth)                     # AMBER
    uid, email = _user(conn, clearance="GREEN", roles=("CASE_OWNER",))
    for case_id in (here, there):
        conn.execute(
            "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
            "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
            (case_id, uid, red_owner))
    auth = _session(conn, email)

    def listed():
        r = client.get("/api/v1/cases", headers=auth)
        assert r.status_code == 200, r.text
        return {c["code"] for c in r.json()} & {code, other}

    assert listed() == set()
    assert client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "classification": "AMBER"}).json()["raises"] \
        is True                                              # global, AMBER
    assert listed() == {code, other}
    conn.execute("UPDATE iam.break_glass SET revoked_at = now() "
                 "WHERE user_id = %s", (uid,))
    assert listed() == set(), "a revoked grant lists nothing"
    r = client.post("/api/v1/break-glass", headers=auth, json={
        "justification": WHY, "case_id": here, "classification": "AMBER"})
    assert r.status_code == 201, r.text
    assert listed() == {code}, "a case grant lists its own case only"
    assert client.get(f"/api/v1/cases/{here}", headers=auth).status_code == 200
    assert client.get(f"/api/v1/cases/{there}", headers=auth).status_code != 200


def test_a_refused_grant_by_address_leaves_a_trace(conn, client):
    """Verifier follow-up, 2026-09-23. By address, a missing account is a
    404 and a known one that cannot open the case a 400: that answers
    whether an account exists, which a successful grant does anyway and a
    mistyped address has to be told. What was wrong is that the refusals
    wrote nothing, so a `case.grant` holder could walk a list of
    addresses unseen. Each is audited now, with the address asked about."""
    owner, owner_email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)                             # AMBER
    _, green_email = _user(conn, clearance="GREEN")
    for email, status in (("bsa-Nobody@noctornal.test", 404),
                          (green_email, 400), (owner_email, 400)):
        r = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                        json={"email": email, "role_key": "ANALYST"})
        assert r.status_code == status, (email, r.text)
    rows = conn.execute(
        """SELECT actor_id, detail->>'email', detail->>'reason'
             FROM audit.event WHERE case_id = %s
              AND action = 'CASE_SHARE_REFUSED' ORDER BY seq""",
        (case_id,)).fetchall()
    assert [(r[1], r[2]) for r in rows] == [
        ("bsa-nobody@noctornal.test", "no_active_account"),
        (green_email.lower(), "labels"),
        (owner_email.lower(), "owner")]
    assert {r[0] for r in rows} == {owner}


# ---------------------------------------------------------------------------
# Retention: the confirmation says what it does not do
# ---------------------------------------------------------------------------

def test_confirming_a_rule_says_it_moves_no_existing_clock(conn, client):
    """Ingest stamps each record's deadline at arrival, so a confirmation
    reaches only material ingested afterwards. The console said the
    category "now retains" for the new period."""
    _, email = _user(conn, name="Dana Legal", roles=("CASE_OWNER",))
    auth = _session(conn, email)
    r = client.post(f"/api/v1/retention/rules/{TEST_CATEGORY}", headers=auth,
                    json={"retain_days": 400,
                          "rationale": "records schedule 2026, section 4"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["existing_records_unchanged"] == 0
    assert "Nothing already on file is recomputed" in body["notice"]
    assert "every case in the deployment" in body["notice"]
    assert body["previous"] is None, "a brand-new category replaced nothing"

    again = client.post(f"/api/v1/retention/rules/{TEST_CATEGORY}", headers=auth,
                        json={"retain_days": 500,
                              "rationale": "records schedule 2027, section 4"})
    prev = again.json()["previous"]
    assert prev["retain_days"] == 400 and prev["was_placeholder"] is False
    assert prev["confirmed_by_name"] == "Dana Legal", (
        "replacing a confirmed period has to say whose decision it replaced")


def test_the_rule_list_names_who_confirmed(conn, client):
    _, email = _user(conn, name="Dana Legal", roles=("CASE_OWNER",))
    auth = _session(conn, email)
    client.post(f"/api/v1/retention/rules/{TEST_CATEGORY}", headers=auth,
                json={"retain_days": 400,
                      "rationale": "records schedule 2026, section 4"})
    rules = client.get("/api/v1/retention/rules", headers=auth).json()["rules"]
    mine = next(r for r in rules if r["category"] == TEST_CATEGORY)
    assert mine["confirmed_by_name"] == "Dana Legal"


def test_a_tombstone_says_who_purged(conn, client):
    """docs/08: a tombstone answers what, under what authority, and by whom.
    The list showed no actor at all."""
    uid, email = _user(conn, name="Pat Purger", roles=("CASE_OWNER",))
    auth = _session(conn, email)
    case_id, _ = _case(client, auth)
    conn.execute(
        """INSERT INTO core.purge_tombstone
               (case_id, object_type, object_count, rule, authority,
                purged_by, storage_outcome)
           VALUES (%s, 'evidence', 37, 'case.retention_until',
                   'scheduled retention run 2026-09', %s,
                   'LOCKED_UNTIL_RETENTION')""", (case_id, uid))
    r = client.get(f"/api/v1/retention/tombstones?case_id={case_id}",
                   headers=auth)
    assert r.status_code == 200, r.text
    t = r.json()["tombstones"][0]
    assert t["purged_by_name"] == "Pat Purger"
    assert t["object_count"] == 37
    assert t["storage_outcome"] == "LOCKED_UNTIL_RETENTION"


# ---------------------------------------------------------------------------
# Sharing: by name, by address, and reversibly
# ---------------------------------------------------------------------------

def test_a_colleague_is_added_by_work_email_and_bound_by_id(conn, client):
    """The only way in was a UUID no case owner could see. The address is
    resolved once, at grant time; the row still stores the account id, so
    the grant follows the person and not the mailbox (invariant 9)."""
    _, owner_email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)
    colleague, colleague_email = _user(conn, name="Casey Colleague")
    r = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                    json={"email": colleague_email.upper(),
                          "role_key": "ANALYST"})
    assert r.status_code == 200, r.text
    assert r.json()["user_id"] == str(colleague)
    assert r.json()["display_name"] == "Casey Colleague"
    assert conn.execute(
        "SELECT role_key FROM iam.case_assignment WHERE case_id = %s "
        "AND user_id = %s", (case_id, colleague)).fetchone()[0] == "ANALYST"


def test_no_account_and_a_deactivated_one_get_the_same_answer(conn, client):
    """An address is guessable where a UUID is not, so the refusal must not
    tell the two apart."""
    _, owner_email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)
    gone, gone_email = _user(conn)
    conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s",
                 (gone,))
    absent = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                         json={"email": "bsa-nobody@noctornal.test",
                               "role_key": "ANALYST"})
    inactive = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                           json={"email": gone_email, "role_key": "ANALYST"})
    assert absent.status_code == inactive.status_code == 404
    assert absent.json() == inactive.json()


def test_a_grant_names_exactly_one_person(conn, client):
    _, owner_email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)
    uid, email = _user(conn)
    both = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                       json={"user_id": str(uid), "email": email,
                             "role_key": "ANALYST"})
    neither = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                          json={"role_key": "ANALYST"})
    assert both.status_code == neither.status_code == 400


def test_a_colleague_can_be_taken_off_again(conn, client):
    """`revoke_user` had no route: a case shared from the console could not
    be unshared from it."""
    _, owner_email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)
    uid, email = _user(conn, name="Casey Colleague")
    client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                json={"email": email, "role_key": "REVIEWER"})
    r = client.delete(f"/api/v1/cases/{case_id}/users/{uid}", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json()["revoked_role"] == "REVIEWER"
    assert r.json()["display_name"] == "Casey Colleague"
    roster = client.get(f"/api/v1/cases/{case_id}/users", headers=auth).json()
    assert str(uid) not in {u["user_id"] for u in roster["users"]}
    actions = [row[0] for row in conn.execute(
        "SELECT action FROM audit.event WHERE case_id = %s", (case_id,))]
    assert "CASE_ACCESS_REVOKED" in actions
    again = client.delete(f"/api/v1/cases/{case_id}/users/{uid}", headers=auth)
    assert again.status_code == 404


def test_the_owner_cannot_be_taken_off_their_own_case(conn, client):
    owner, owner_email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)
    r = client.delete(f"/api/v1/cases/{case_id}/users/{owner}", headers=auth)
    assert r.status_code == 400, r.text
    assert "owns this case" in r.json()["detail"]


def test_taking_someone_off_needs_the_grant_verb(conn, client):
    _, owner_email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)
    a, a_email = _user(conn)
    b, b_email = _user(conn)
    for email in (a_email, b_email):
        client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                    json={"email": email, "role_key": "ANALYST"})
    r = client.delete(f"/api/v1/cases/{case_id}/users/{b}",
                      headers=_session(conn, a_email))
    assert r.status_code == 403
    assert conn.execute(
        "SELECT count(*) FROM iam.case_assignment WHERE case_id = %s "
        "AND user_id = %s", (case_id, b)).fetchone()[0] == 1


def test_the_roster_says_why_an_assignment_does_not_work(conn, client):
    """`effective: false` alone left the owner to guess which of five checks
    failed. The reason is given, without naming the colleague's clearance:
    LIAISON can read this roster."""
    owner, owner_email = _user(conn, name="Olive Owner", roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)                          # AMBER
    green, _ = _user(conn, clearance="GREEN")
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
        "granted_by) VALUES (%s, %s, 'ANALYST', %s)", (case_id, green, owner))
    users = {u["user_id"]: u for u in client.get(
        f"/api/v1/cases/{case_id}/users", headers=auth).json()["users"]}
    row = users[str(green)]
    assert row["effective"] is False
    assert row["reasons"] == [
        "their clearance is below the case's classification"]
    assert "GREEN" not in " ".join(row["reasons"])
    assert row["granted_by_name"] == "Olive Owner"
    assert users[str(owner)]["is_owner"] is True
    assert users[str(owner)]["reasons"] == []


def test_the_address_is_looked_up_only_after_the_request_is_valid(conn, client):
    """Fix round, 2026-09-23. The address was resolved before the role was
    checked, so a request with a bad role answered 404 for an unknown
    address and 400 for a known one, wrote nothing and audited nothing: a
    free account-existence probe."""
    _, owner_email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)
    _, known = _user(conn)
    for bad in ({"role_key": "NOT_A_ROLE"},
                {"role_key": "ANALYST", "expires_at": "2020-01-01T00:00:00Z"},
                {"role_key": "ANALYST", "expires_at": "2027-03-14T17:00:00"}):
        a = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                        json={"email": known, **bad})
        b = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                        json={"email": "bsa-nobody@noctornal.test", **bad})
        assert a.status_code == b.status_code == 400, (bad, a.text, b.text)
        assert a.json() == b.json(), bad


def test_a_refusal_reached_by_address_does_not_name_their_clearance(conn, client):
    """By UUID the service's refusal named the assignee's clearance to a
    caller who already held their id. By a guessable address it would hand
    a case owner any colleague's clearance, so it is said without it."""
    _, owner_email = _user(conn, roles=("CASE_OWNER",))       # AMBER
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)                           # AMBER
    green, green_email = _user(conn, clearance="GREEN")
    r = client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                    json={"email": green_email, "role_key": "ANALYST"})
    assert r.status_code == 400, r.text
    assert "GREEN" not in r.json()["detail"]
    assert "could not open this case" in r.json()["detail"]
    assert conn.execute(
        "SELECT count(*) FROM iam.case_assignment WHERE case_id = %s "
        "AND user_id = %s", (case_id, green)).fetchone()[0] == 0


def test_the_roster_says_whether_the_caller_can_add_people(conn, client):
    """Fix round, 2026-09-23: the Share panel offered Add and Remove to every
    roster reader and each click was a 403. The hint gates nothing."""
    _, owner_email = _user(conn, roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)
    _, reader_email = _user(conn)
    assert client.post(f"/api/v1/cases/{case_id}/users", headers=auth,
                       json={"email": reader_email, "role_key": "READ_ONLY"}
                       ).status_code == 200
    roster = f"/api/v1/cases/{case_id}/users"
    assert client.get(roster, headers=auth).json()["you_can_grant"] is True
    reader = _session(conn, reader_email)
    assert client.get(roster, headers=reader).json()["you_can_grant"] is False


# ---------------------------------------------------------------------------
# Administration without a case
# ---------------------------------------------------------------------------

def test_the_way_in_is_answered_for_the_caller_alone(conn, client):
    """SYS_ADMIN holds user.manage and no case.read; SECURITY_OFFICER holds
    break_glass.review and no case. Both were stranded on an empty case
    list. The answer is about the caller's own roles and gates nothing."""
    assert client.get("/api/v1/admin/access").status_code == 401
    _, analyst = _user(conn, roles=("ANALYST",))
    _, admin = _user(conn, roles=("SYS_ADMIN",))
    _, officer = _officer(conn)
    assert client.get("/api/v1/admin/access", headers=_session(conn, analyst)
                      ).json() == {"user_manage": False,
                                   "break_glass_review": False}
    assert client.get("/api/v1/admin/access", headers=_session(conn, admin)
                      ).json()["user_manage"] is True
    assert client.get("/api/v1/admin/access", headers=_session(conn, officer)
                      ).json() == {"user_manage": False,
                                   "break_glass_review": True}
    # ...and it opens nothing: the list still wants user.manage.
    assert client.get("/api/v1/admin/users",
                      headers=_session(conn, analyst)).status_code == 403


# ---------------------------------------------------------------------------
# Names, not ids (ux19 raw-ids-instead-of-names)
# ---------------------------------------------------------------------------

def test_an_approval_names_who_asked(conn, client):
    """The approval card printed the payload's UUIDs and nothing about the
    requester, so a second signature was given to a stranger's request."""
    from noctornal_api.approvals import ApprovalService
    owner, owner_email = _user(conn, name="Rae Requester", roles=("CASE_OWNER",))
    auth = _session(conn, owner_email)
    case_id, _ = _case(client, auth)
    ApprovalService(conn).request(
        operation="node.merge", case_id=case_id,
        payload={"source_node_id": str(uuid4()),
                 "target_node_id": str(uuid4()),
                 "reason": "same crew, renamed", "basis_selector_id": None},
        justification="Same crew, renamed after the March takedown",
        requested_by=owner)
    r = client.get(f"/api/v1/cases/{case_id}/approvals", headers=auth)
    assert r.status_code == 200, r.text
    row = r.json()["approvals"][0]
    assert row["requested_by_name"] == "Rae Requester"
    assert row["requested_by"] == str(owner), "the durable id stays"
    assert row["decided_by_name"] is None
