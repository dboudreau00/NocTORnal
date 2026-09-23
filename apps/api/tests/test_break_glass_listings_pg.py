"""A break-glass grant opens a case everywhere the gate does, not just
where somebody remembered.

The gate (`PgAccessResolver.resolve`) and `CaseService.list_for_user`
count a live grant, global or on that case, at its level. Three other
answers to "can this person open that case" were restatements in SQL that
still compared `u.tlp_clearance` alone (final review, 2026-09-23):

- U7: governance's `_authorised_cases`, behind `/retention/due` and the
  Destroyed list with no case id and the "records unchanged" count on a
  rule confirmation, and comms' `_visible_cases`, behind the impersonation
  candidates. A case a grant opened answered per case and was missing
  from the cross-case forms.
- U22: the Share roster's `effective` and `reasons`, which told a case's
  owner that a colleague working in it under an emergency grant "cannot
  open the case" because "their clearance is below the case's
  classification".

Seven of the nine fail on 1667cc1. The two that pass there (no grant, and
a revoked grant) are guards that the fixes opened nothing a live grant
does not open. Email prefix `bgl-`, unique to this file. Env-gated on
DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; break-glass listings are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "bgl-"
WHY = "Incident 2026-0923: the next target is named in this case, needed now."
#: After every test case's retention_until (2028-01-01), so its exhibits
#: are due and /retention/due has something to list.
LATER = "2029-01-01T00:00:00Z"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM notify.notification WHERE recipient_id IN {sub} "
                  f"OR actor_id IN {sub} OR case_id IN {csub}")
        # Exhibits inserted directly (no custody rows), so they can go.
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test'")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _user(conn, clearance, *global_roles, name="BGL"):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{PREFIX}{uuid4().hex[:8]}@noctornal.test", name, "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in global_roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return uid


def _auth(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _me(uid):
    from noctornal_api.http.deps import CurrentUser
    return CurrentUser(user_id=uid, session_id=uuid4(),
                       session_mfa_at=datetime.now(timezone.utc))


def _case(conn, owner, classification):
    from noctornal_api.cases import CaseService
    future = date(2028, 1, 1)
    return CaseService(conn).create(
        code=f"OP-BGL-{uuid4().hex[:6]}", title="Break-glass listings",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=owner,
        created_by=owner, classification=classification)


def _assign(conn, case_id, uid, role, by):
    """Directly, as `assign_user` does: no clearance check, which is how an
    assignment to a case above somebody's clearance comes about."""
    conn.execute(
        "INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by) "
        "VALUES (%s, %s, %s, %s)", (case_id, uid, role, by))


def _grant(conn, uid, level, *, case_id=None, hours=1):
    return conn.execute(
        """INSERT INTO iam.break_glass
               (user_id, case_id, justification, expires_at,
                granted_classification)
           VALUES (%s, %s, %s, now() + make_interval(hours => %s), %s)
           RETURNING id, expires_at""",
        (uid, case_id, WHY, hours, level)).fetchone()


def _exhibit(conn, case_id, owner, level):
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, 'bgl exhibit', 'image/png', 1024, %s, %s, %s,
                   'test-bucket', %s, 'SCREENSHOT', now(), %s)
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"k/{uuid4().hex}",
         level, owner)).fetchone()[0]


# ---------------------------------------------------------------------------
# U7: the cross-case lists
# ---------------------------------------------------------------------------

@pytest.fixture
def estate(conn):
    """A RED owner's AMBER case X and RED case Y, each holding one exhibit
    past its retention; a GREEN analyst assigned to both, holding global
    retention.read (ANALYST carries it) and nothing that opens either."""
    owner = _user(conn, "RED")
    analyst = _user(conn, "GREEN", "ANALYST")
    x = _case(conn, owner, "AMBER")
    y = _case(conn, owner, "RED")
    _assign(conn, x, analyst, "ANALYST", owner)
    _assign(conn, y, analyst, "ANALYST", owner)
    return {"owner": owner, "analyst": analyst, "x": x, "y": y,
            "ex": _exhibit(conn, x, owner, "AMBER"),
            "ey": _exhibit(conn, y, owner, "RED")}


def _due_cases(client, conn, uid, case_id=None):
    params = {"as_of": LATER}
    if case_id is not None:
        params["case_id"] = str(case_id)
    r = client.get("/api/v1/retention/due", headers=_auth(conn, uid),
                   params=params)
    return r.status_code, {d["case_id"] for d in r.json().get("due", [])}


def test_without_a_grant_neither_form_lists_a_case_above_the_analyst(
        conn, client, estate):
    """The guard: a GREEN analyst assigned to an AMBER case sees nothing
    of it, per case or across cases."""
    e = estate
    status, cases = _due_cases(client, conn, e["analyst"])
    assert status == 200
    assert str(e["x"]) not in cases and str(e["y"]) not in cases
    status, _ = _due_cases(client, conn, e["analyst"], e["x"])
    assert status == 403


def test_a_global_grant_opens_the_cross_case_retention_list_as_it_does_per_case(
        conn, client, estate):
    """The finding's scenario: the per-case form answered for X and the
    cross-case form left it out. The RED case stays out: AMBER does not
    open it. The grant's use is counted, as the per-case form counts it."""
    e = estate
    grant_id, _ = _grant(conn, e["analyst"], "AMBER")
    status, per_case = _due_cases(client, conn, e["analyst"], e["x"])
    assert status == 200 and per_case == {str(e["x"])}
    status, cases = _due_cases(client, conn, e["analyst"])
    assert status == 200
    assert str(e["x"]) in cases, "the cross-case list disagrees with the gate"
    assert str(e["y"]) not in cases, "an AMBER grant does not open a RED case"
    used = conn.execute("SELECT action_count FROM iam.break_glass WHERE id = %s",
                        (grant_id,)).fetchone()[0]
    assert used >= 2, "a listing the grant made possible is a use of it"


def test_a_grant_on_one_case_opens_that_case_and_no_other(conn, client, estate):
    """A case-scoped grant counts only for its own case, as in the gate."""
    from noctornal_api.http.routers.governance import _authorised_cases
    e = estate
    _grant(conn, e["analyst"], "RED", case_id=e["x"])
    got = set(_authorised_cases(conn, _me(e["analyst"]), "retention.read"))
    assert e["x"] in got
    assert e["y"] not in got, "a grant on X must not open Y"


def test_the_impersonation_candidates_count_a_global_grant(conn, estate):
    """comms `_visible_cases`: the block ceiling it is used with is raised
    by a global grant, so the candidate cases must be too."""
    from noctornal_api.http.routers.comms import _visible_cases
    e = estate
    # The case the request is made from; excluded from the result itself.
    here = _case(conn, e["owner"], "GREEN")
    _assign(conn, here, e["analyst"], "ANALYST", e["owner"])
    me = _me(e["analyst"])
    assert e["x"] not in _visible_cases(conn, me, here)
    _grant(conn, e["analyst"], "AMBER")
    visible = _visible_cases(conn, me, here)
    assert e["x"] in visible
    assert e["y"] not in visible


def test_an_expired_or_revoked_grant_opens_nothing(conn, estate):
    from noctornal_api.http.routers.comms import _visible_cases
    from noctornal_api.http.routers.governance import _authorised_cases
    e = estate
    gid, _ = _grant(conn, e["analyst"], "RED")
    conn.execute("UPDATE iam.break_glass SET revoked_at = now() WHERE id = %s",
                 (gid,))
    me = _me(e["analyst"])
    assert not {e["x"], e["y"]} & set(_authorised_cases(conn, me, "retention.read"))
    assert not {e["x"], e["y"]} & set(_visible_cases(conn, me, uuid4()))


# ---------------------------------------------------------------------------
# U22: the Share roster
# ---------------------------------------------------------------------------

@pytest.fixture
def team(conn):
    """An AMBER owner's AMBER case C, a GREEN analyst assigned to it, and a
    LIAISON partner who can read the roster but not manage it."""
    owner = _user(conn, "AMBER", name="Olive Owner")
    analyst = _user(conn, "GREEN", name="Gary Green")
    partner = _user(conn, "AMBER", name="Pat Partner")
    c = _case(conn, owner, "AMBER")
    _assign(conn, c, analyst, "ANALYST", owner)
    _assign(conn, c, partner, "LIAISON", owner)
    return {"owner": owner, "analyst": analyst, "partner": partner, "case": c}


def _roster(client, conn, reader, case_id):
    r = client.get(f"/api/v1/cases/{case_id}/users", headers=_auth(conn, reader))
    assert r.status_code == 200, r.text
    return r.json(), {u["user_id"]: u for u in r.json()["users"]}


def _lists(client, conn, uid, case_id) -> bool:
    r = client.get("/api/v1/cases", headers=_auth(conn, uid))
    assert r.status_code == 200, r.text
    body = r.json()
    rows = body if isinstance(body, list) else body.get("cases", [])
    return str(case_id) in {row["id"] for row in rows}


def test_a_colleague_open_under_a_grant_is_shown_as_able_to_open(conn, client, team):
    """The finding's scenario: the analyst is working in C under a grant on
    C while the owner's roster said they could not open it."""
    t = team
    _, expires = _grant(conn, t["analyst"], "AMBER", case_id=t["case"])
    assert _lists(client, conn, t["analyst"], t["case"]), \
        "precondition: list_for_user opens the case under the grant"
    body, users = _roster(client, conn, t["owner"], t["case"])
    row = users[str(t["analyst"])]
    assert row["effective"] is True, row
    assert row["reasons"] == []
    # The owner manages the roster, so is told when the cover ends, in UTC.
    until = datetime.fromisoformat(row["emergency_access_until"])
    assert until.utcoffset() == timedelta(0)
    assert until == expires
    # Nobody else on the roster is described as being on emergency access.
    for uid, other in users.items():
        if uid != str(t["analyst"]):
            assert other["emergency_access_until"] is None, other


def test_a_partner_reading_the_roster_is_not_told_who_is_on_emergency_access(
        conn, client, team):
    t = team
    _grant(conn, t["analyst"], "AMBER", case_id=t["case"])
    body, users = _roster(client, conn, t["partner"], t["case"])
    assert body["you_can_grant"] is False
    row = users[str(t["analyst"])]
    assert row["effective"] is True, "the flag is the gate's answer for everyone"
    assert row["emergency_access_until"] is None


def test_the_roster_and_the_case_list_agree_with_and_without_a_grant(
        conn, client, team):
    """The docstring's promise, held: recomputed from the same predicates
    as list_for_user, "so the two cannot drift"."""
    t = team
    _, users = _roster(client, conn, t["owner"], t["case"])
    assert users[str(t["analyst"])]["effective"] is False
    assert users[str(t["analyst"])]["reasons"] == [
        "their clearance is below the case's classification"]
    assert not _lists(client, conn, t["analyst"], t["case"])

    # A grant too low to open the case, and one on another case: neither
    # counts, in either answer.
    other = _case(conn, t["owner"], "AMBER")
    _grant(conn, t["analyst"], "GREEN", case_id=t["case"])
    _grant(conn, t["analyst"], "AMBER", case_id=other)
    _, users = _roster(client, conn, t["owner"], t["case"])
    assert users[str(t["analyst"])]["effective"] is False
    assert not _lists(client, conn, t["analyst"], t["case"])

    # A global grant at the case's level: both answers open it.
    _grant(conn, t["analyst"], "AMBER")
    _, users = _roster(client, conn, t["owner"], t["case"])
    assert users[str(t["analyst"])]["effective"] is True
    assert _lists(client, conn, t["analyst"], t["case"])


def test_a_grant_does_not_excuse_any_other_failing_check(conn, client, team):
    """The grant stands in for clearance only. A deactivated colleague is
    still "cannot open", with the real reason and no emergency window."""
    t = team
    _grant(conn, t["analyst"], "AMBER", case_id=t["case"])
    conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s",
                 (t["analyst"],))
    _, users = _roster(client, conn, t["owner"], t["case"])
    row = users[str(t["analyst"])]
    assert row["effective"] is False
    assert row["reasons"] == ["the account is deactivated"]
    assert row["emergency_access_until"] is None
