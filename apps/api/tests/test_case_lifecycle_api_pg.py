"""The case-lifecycle router over HTTP: what it applies, and what it refuses.

`cases.py` exposes four operations that existed in `CaseService` since
Phase 1 and that no endpoint reached (migration 0053 recorded the gap:
`case.update`, `case.close` and `case.grant` were seeded, granted, and
checked by nothing). Everything reachable is now a place a mistake can be
made, so the tests that carry this file are the refusals:

- a caller with no relationship to a case gets the SAME 404 a nonexistent
  case gives, on every case-scoped verb — never 403 (which would confirm
  the case exists) and never 200,
- a caller who is assigned but lacks the verb gets 403, not 200,
- the classification may be raised and never lowered, and a raise is
  capped by the caller's own clearance,
- a grant that would confer nothing is refused rather than written and
  then silently filtered away by every read path,
- `ARCHIVED -> PURGED` re-enters the gate under `case.delete`, so a
  permission holding neither step-up nor dual control cannot set the flag
  that authorises destroying a case file,
- nothing is answered 200 having done nothing (invariant 12): a no-op
  PATCH is refused, a replaced grade is named, and the assignees a
  classification raise evicts are reported rather than discovered.

**The email prefix is `clc-` and must stay unique.** Every fixture in this
suite tears down by deleting on an email pattern, so two files sharing a
prefix delete each other's rows — which surfaces as a foreign-key error in
whichever file tears down second, pointing at a table neither test
touched. `cs-` belongs to test_cases_pg.py and `e2e-` to test_http_e2e.py.

**Two throwaway ROLES are created here** (`CLC_CLOSER`, `CLC_EMPTY`),
because two properties cannot be reproduced with the seeded matrix at all:
0021 grants `case.close` to CASE_OWNER alone, and CASE_OWNER also holds
`case.delete` — so proving the re-gating needs a principal holding one and
not the other. Both are deleted in teardown, AFTER the assignments and
user_roles that reference `role(key)`. They are new rows with unused keys,
not edits to seeded ones, so no other suite can observe them.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
import time
from datetime import date, datetime, timedelta, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; case lifecycle API is gated"
)

PASSWORD = "correct-horse-battery-staple"

# Set at import, exactly as the other _pg suites do. Skipping on a missing
# KEK would be worse than useless: CI fails the run if ANY test skips, and
# `enroll_totp` envelope-encrypts through it on every user this file makes.
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

#: Throwaway roles, keyed so they can never collide with the seeded set.
TEST_ROLES = ("CLC_CLOSER", "CLC_EMPTY")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'clc-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    roles = ",".join(f"'{r}'" for r in TEST_ROLES)
    with c.transaction():
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        # Belt and braces before the roles go: iam.case_assignment and
        # iam.user_role both reference role(key) with no ON DELETE, so ONE
        # leaked row from a previously-failed teardown would make the role
        # delete below fail forever — and a failing teardown leaks fixtures
        # into every later test in the run.
        c.execute(f"DELETE FROM iam.case_assignment WHERE role_key IN ({roles})")
        c.execute(f"DELETE FROM iam.user_role WHERE role_key IN ({roles})")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'clc-%@noctornal.test'")
        # role_permission before role: it references role(key).
        c.execute(f"DELETE FROM iam.role_permission WHERE role_key IN ({roles})")
        c.execute(f"DELETE FROM iam.role WHERE key IN ({roles})")
    c.close()


@pytest.fixture
def client():
    """A live app with a rate limiter this test alone owns.

    The default limiter is Redis-backed when REDIS_URL is set, and Redis is
    shared, persistent and blind to test boundaries — one test's writes
    would spend the next test's budget and the suite would pass or fail
    depending on the order it ran in.
    """
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


@pytest.fixture
def closer_role(conn):
    """`case.read` + `case.close`, and deliberately NOT `case.update` or
    `case.delete` — the principal the re-gating in `transition()` exists
    for. CASE_OWNER holds all four, so with the seeded matrix alone every
    "may close but may not purge" assertion would pass vacuously."""
    conn.execute(
        """INSERT INTO iam.role (key, display_name, description, is_system)
           VALUES ('CLC_CLOSER', 'Test closer',
                   'case.read + case.close only; no update, no delete', false)
           ON CONFLICT (key) DO NOTHING""")
    conn.execute(
        """INSERT INTO iam.role_permission (role_key, permission_key)
           VALUES ('CLC_CLOSER', 'case.read'), ('CLC_CLOSER', 'case.close')
           ON CONFLICT DO NOTHING""")
    return "CLC_CLOSER"


@pytest.fixture
def empty_role(conn):
    """A real role holding no permissions at all. Every seeded role grants
    something, so this branch of `assign_case_user` is otherwise
    unreachable — and it is the branch that stops a grant being written
    that confers nothing."""
    conn.execute(
        """INSERT INTO iam.role (key, display_name, description, is_system)
           VALUES ('CLC_EMPTY', 'Test empty role', 'grants nothing', false)
           ON CONFLICT (key) DO NOTHING""")
    return "CLC_EMPTY"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(conn, *, clearance="AMBER", global_roles=(), compartments=()):
    """A user with TOTP enrolled, returning (user_id, email, totp_secret).

    Every user here may log in AT MOST ONCE per test: the TOTP counter
    advance is a compare-and-set that rejects a replay, so a second login
    inside the same 30-second step fails on the code, not on the policy
    under test.
    """
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"clc-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Case Lifecycle", PASSWORD)
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
    from noctornal_api.security import totp
    r = client.post("/api/v1/auth/login", json={
        "email": email, "password": PASSWORD,
        "totp_code": totp.code_at(secret, int(time.time()))})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _create_case(client, token, **overrides) -> str:
    body = {
        "code": f"OP-CLC-{uuid4().hex[:6]}",
        "title": "Operation Clockwork",
        "legal_basis": "production order 2026-0042",
        "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1)),
    }
    body.update(overrides)
    r = client.post("/api/v1/cases", headers=_auth(token), json=body)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _assign(conn, case_id, user_id, role_key, granted_by, expires_at=None):
    """A raw assignment row, bypassing `assign_user_checked`.

    Used to MANUFACTURE the broken states the roster endpoint has to
    report — an expired grant, an under-cleared assignee — which the API
    correctly refuses to create.
    """
    conn.execute(
        """INSERT INTO iam.case_assignment
               (case_id, user_id, role_key, granted_by, expires_at)
           VALUES (%s, %s, %s, %s, %s)
           ON CONFLICT (case_id, user_id) DO UPDATE
               SET role_key = EXCLUDED.role_key,
                   expires_at = EXCLUDED.expires_at""",
        (case_id, user_id, role_key, granted_by, expires_at),
    )


def _stale_mfa(conn, email: str) -> None:
    """Age this user's sessions past the 15-minute step-up window without
    revoking them, so a step-up refusal is distinguishable from a dead
    session (every test that uses this asserts a non-step-up call still
    succeeds on the same token)."""
    conn.execute(
        "UPDATE iam.session SET mfa_satisfied_at = now() - interval '20 minutes' "
        "WHERE user_id = (SELECT id FROM iam.app_user WHERE email = %s)",
        (email,),
    )


def _assignment_count(conn, case_id, user_id) -> int:
    return conn.execute(
        "SELECT count(*) FROM iam.case_assignment WHERE case_id = %s AND user_id = %s",
        (case_id, user_id),
    ).fetchone()[0]


def _audit_actions(conn, case_id) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE case_id = %s ORDER BY seq",
        (case_id,)).fetchall()]


# ---------------------------------------------------------------------------
# POST /cases, GET /cases, GET /cases/{case_id}
# ---------------------------------------------------------------------------

def test_creating_a_case_needs_the_global_verb(conn, client):
    """`case.create` is global — there is no case to be assigned to yet —
    so authentication alone must not reach it."""
    _, email, secret = _make_user(conn)          # no global roles
    token = _login(client, email, secret)
    r = client.post("/api/v1/cases", headers=_auth(token), json={
        "code": f"OP-CLC-{uuid4().hex[:6]}", "title": "nope",
        "legal_basis": "x", "retention_until": str(date(2028, 1, 1)),
        "review_due": str(date(2027, 1, 1))})
    assert r.status_code == 403
    assert r.headers["content-type"].startswith("application/problem+json")


def test_a_new_case_is_a_draft_its_creator_owns_and_can_read(conn, client):
    """Creation grants the owner CASE_OWNER in the same transaction — the
    gate reads a user's role off `case_assignment`, not off
    `case.owner_user_id`, so without that the owner could not act on their
    own case."""
    uid, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)

    got = client.get(f"/api/v1/cases/{case_id}", headers=_auth(token))
    assert got.status_code == 200, got.text
    assert got.json()["status"] == "DRAFT"
    assert got.json()["owner_user_id"] == str(uid)
    assert case_id in [c["id"] for c in
                       client.get("/api/v1/cases", headers=_auth(token)).json()]


def test_an_outsider_neither_lists_nor_detects_another_case(conn, client):
    """The listing must return exactly the set the gate would allow, and a
    caller with no relationship to a case must not learn it EXISTS: the
    answer for a real case is byte-identical to the answer for a random
    id."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    case_id = _create_case(client, _login(client, owner_email, owner_secret))

    _, out_email, out_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    outsider = _login(client, out_email, out_secret)

    real = client.get(f"/api/v1/cases/{case_id}", headers=_auth(outsider))
    fake = client.get(f"/api/v1/cases/{uuid4()}", headers=_auth(outsider))
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json(), "the status code must not be an oracle"
    assert client.get("/api/v1/cases", headers=_auth(outsider)).json() == []


# ---------------------------------------------------------------------------
# PATCH /cases/{case_id}
# ---------------------------------------------------------------------------

def test_a_metadata_edit_applies_and_is_audited_exactly_once(conn, client):
    """The router deliberately writes no audit row of its own on the
    success path: `update_metadata` audits inside the same transaction as
    the write, and two rows per action — one of which can commit without
    the other — is worse than one."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)

    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"title": "Operation Clockwork (corrected)",
                           "authority_ref": "warrant 2026-0099"})
    assert r.status_code == 200, r.text
    # Flattened, not nested under a "case" key: a client that reads
    # .title/.status sees the same shape GET /cases/{id} returns.
    assert r.json()["title"] == "Operation Clockwork (corrected)"
    assert r.json()["access_lost"] == []
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(token)).json()["title"] == \
        "Operation Clockwork (corrected)"
    assert _audit_actions(conn, case_id).count("CASE_UPDATED") == 1


def test_lowering_the_classification_is_refused(conn, client):
    """Declassification is not "raising with a different sign". It cannot
    be undone by raising it back — whoever read it in the meantime has
    read it — and everything protected ONLY by the case label drops in one
    statement with no review and no second signature. `case.update` is
    "Edit case metadata" and was never meant to carry that.
    """
    _, email, secret = _make_user(conn, clearance="RED",
                                  global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token, classification="RED")

    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"classification": "AMBER"})
    assert r.status_code == 400, r.text
    assert "lower" in r.text
    # Refused, not partially applied.
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(token)).json()["classification"] == "RED"
    assert "CASE_UPDATED" not in _audit_actions(conn, case_id)


def test_raising_the_classification_names_who_it_evicts(conn, client):
    """Invariant 12. A raise silently evicts every assignee cleared below
    the new level: `list_for_user` filters them out and the gate 404s them,
    with no error anywhere. The caller may well intend it; they should not
    have to find out by being asked."""
    from noctornal_api.cases import CaseService
    owner_id, owner_email, owner_secret = _make_user(
        conn, clearance="RED", global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)                       # AMBER

    analyst_id, analyst_email, analyst_secret = _make_user(conn, clearance="AMBER")
    CaseService(conn).assign_user(case_id, analyst_id, "ANALYST",
                                  granted_by=owner_id)

    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(owner),
                     json={"classification": "RED"})
    assert r.status_code == 200, r.text
    assert r.json()["classification"] == "RED"
    lost = {u["user_id"] for u in r.json()["access_lost"]}
    assert str(analyst_id) in lost, "the evicted assignee must be reported"
    assert str(owner_id) not in lost, "the RED-cleared owner keeps the case"

    # And the eviction is real, not just reported.
    analyst = _login(client, analyst_email, analyst_secret)
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(analyst)).status_code == 403
    assert client.get("/api/v1/cases", headers=_auth(analyst)).json() == []


def test_a_raise_is_capped_by_the_callers_own_clearance(conn, client):
    """Without this an AMBER-cleared CASE_OWNER could raise their case to
    RED and instantly lose the case they were half way through running —
    the "wrote it, cannot see it" trap `check_writable_labels` exists
    for."""
    _, email, secret = _make_user(conn, clearance="AMBER",
                                  global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)                       # AMBER

    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"classification": "RED"})
    assert r.status_code == 403, r.text
    assert "clearance" in r.text
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(token)).json()["classification"] == "AMBER"


def test_an_unknown_classification_is_400_not_500(conn, client):
    """An unknown label reaching the `tlp` enum column surfaces as a
    psycopg InvalidTextRepresentation and comes back as a 500 — which also
    means the request got as far as the write."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)

    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"classification": "PUCE"})
    assert r.status_code == 400, r.text
    assert "unknown classification" in r.text
    assert "Traceback" not in r.text


def test_a_no_op_patch_is_refused_rather_than_answered_200(conn, client):
    """`update_metadata` returns early and writes no audit row when nothing
    changed, so each of these would otherwise answer 200 having done
    nothing and left no trace it was attempted (invariant 12)."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)                       # AMBER
    url = f"/api/v1/cases/{case_id}"

    # Nothing supplied at all.
    assert client.patch(url, headers=_auth(token), json={}).status_code == 400
    # A JSON null cannot clear a field: `update_metadata` reads None as
    # "not supplied", so it is indistinguishable from omitting the key.
    assert client.patch(url, headers=_auth(token),
                        json={"summary": None}).status_code == 400
    # The classification it already has is dropped, so a PATCH whose ONLY
    # field was that label is refused rather than answered 200.
    same = client.patch(url, headers=_auth(token), json={"classification": "AMBER"})
    assert same.status_code == 400, same.text
    assert "nothing to change" in same.text
    assert "CASE_UPDATED" not in _audit_actions(conn, case_id)


def test_an_empty_title_is_refused(conn, client):
    """`update_metadata` treats None as "not supplied", so an empty string
    is NOT a no-op — it would write an untitled case."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"title": ""})
    assert r.status_code == 422, r.text
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(token)).json()["title"] != ""


def test_the_durable_identifier_and_the_status_are_not_metadata(conn, client):
    """Invariant 9: `code` is quoted in warrants, exhibit labels and other
    agencies' correspondence, so renaming it would silently invalidate
    every external reference. `status` has a validated transition table and
    moves through its own endpoint. Both are absent from the model, so
    Pydantic ignores them — the assertion is that they do NOT take
    effect."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    before = client.get(f"/api/v1/cases/{case_id}", headers=_auth(token)).json()

    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"title": "renamed", "code": "OP-SOMETHING-ELSE",
                           "status": "PURGED", "owner_user_id": str(uuid4())})
    assert r.status_code == 200, r.text
    after = client.get(f"/api/v1/cases/{case_id}", headers=_auth(token)).json()
    assert after["code"] == before["code"]
    assert after["status"] == before["status"] == "DRAFT"
    assert after["owner_user_id"] == before["owner_user_id"]
    assert after["title"] == "renamed"


def test_a_purged_case_cannot_be_edited(conn, client):
    """Editing the governance record of a case marked for destruction
    rewrites the very metadata a retention review reads to justify the
    purge."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    for status in ("ARCHIVED", "PURGED"):
        step = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(token),
                           json={"status": status})
        assert step.status_code == 200, step.text

    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"authority_ref": "warrant 2026-0099"})
    assert r.status_code == 400, r.text
    assert "PURGED" in r.text
    # An ARCHIVED case, by contrast, stays correctable.
    other = _create_case(client, token)
    assert client.post(f"/api/v1/cases/{other}/status", headers=_auth(token),
                       json={"status": "ARCHIVED"}).status_code == 200
    assert client.patch(f"/api/v1/cases/{other}", headers=_auth(token),
                        json={"authority_ref": "warrant 2026-0100"}
                        ).status_code == 200


def test_editing_another_users_case_is_404_and_changes_nothing(conn, client):
    """404, not 403: a caller with no relationship to the case must not
    learn that it exists, and PATCH is a mutation, so a 403 here would also
    be a free existence probe on a write path."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)

    _, out_email, out_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    outsider = _login(client, out_email, out_secret)

    body = {"title": "hijacked", "classification": "RED"}
    real = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(outsider), json=body)
    fake = client.patch(f"/api/v1/cases/{uuid4()}", headers=_auth(outsider), json=body)
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()

    got = client.get(f"/api/v1/cases/{case_id}", headers=_auth(owner)).json()
    assert got["title"] == "Operation Clockwork"
    assert got["classification"] == "AMBER"


def test_an_assignee_without_the_verb_is_403_not_404(conn, client):
    """The other half of the oracle rule. Once a caller IS assigned, 403
    reveals nothing they do not already know — they can see their own
    assignments — and is far more useful than a 404 that reads as "your
    case vanished"."""
    from noctornal_api.cases import CaseService
    owner_id, owner_email, owner_secret = _make_user(
        conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)

    reader_id, reader_email, reader_secret = _make_user(conn)
    CaseService(conn).assign_user(case_id, reader_id, "READ_ONLY",
                                  granted_by=owner_id)
    reader = _login(client, reader_email, reader_secret)

    # READ_ONLY holds case.read and nothing else on this case.
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(reader)).status_code == 200
    assert client.patch(f"/api/v1/cases/{case_id}", headers=_auth(reader),
                        json={"title": "not yours"}).status_code == 403
    assert client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(reader),
                       json={"status": "ACTIVE"}).status_code == 403
    assert client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(reader),
                       json={"user_id": str(reader_id),
                             "role_key": "CASE_OWNER"}).status_code == 403
    # None of it took effect.
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(owner)).json()["status"] == "DRAFT"


# ---------------------------------------------------------------------------
# POST /cases/{case_id}/users
# ---------------------------------------------------------------------------

def test_a_grant_reports_what_it_confers_and_what_it_replaced(conn, client):
    """Invariant 12 on the UPSERT: `_grant` is `ON CONFLICT (case_id,
    user_id) DO UPDATE`, so demoting a colleague looks identical to adding
    a new one unless the replaced grade is named."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)
    analyst_id, _, _ = _make_user(conn, clearance="AMBER")

    first = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                        json={"user_id": str(analyst_id), "role_key": "ANALYST"})
    assert first.status_code == 200, first.text
    assert first.json()["replaced_role"] is None
    assert "case.read" in first.json()["grants"]
    assert "graph.node.create" in first.json()["grants"]

    second = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                         json={"user_id": str(analyst_id), "role_key": "READ_ONLY"})
    assert second.status_code == 200, second.text
    assert second.json()["replaced_role"] == "ANALYST", \
        "a regrade that replaced an existing grant must say so"
    assert conn.execute(
        "SELECT role_key FROM iam.case_assignment WHERE case_id=%s AND user_id=%s",
        (case_id, analyst_id)).fetchone()[0] == "READ_ONLY"
    assert _audit_actions(conn, case_id).count("CASE_ACCESS_GRANTED") == 2


def test_an_unknown_role_is_400_and_writes_nothing(conn, client):
    """`_grant` inserts straight into `case_assignment`, so an unknown
    role_key trips a foreign key and would surface as a 500."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)
    victim_id, _, _ = _make_user(conn)

    r = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                    json={"user_id": str(victim_id), "role_key": "NOT_A_ROLE"})
    assert r.status_code == 400, r.text
    assert "Traceback" not in r.text and "fkey" not in r.text
    assert _assignment_count(conn, case_id, victim_id) == 0


def test_a_role_that_confers_nothing_is_refused(conn, client, empty_role):
    """A grant that appears to succeed and confers nothing is worse than a
    refusal: it reads as access in the roster and behaves as none."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)
    victim_id, _, _ = _make_user(conn)

    r = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                    json={"user_id": str(victim_id), "role_key": empty_role})
    assert r.status_code == 400, r.text
    assert "confer" in r.text
    assert _assignment_count(conn, case_id, victim_id) == 0


def test_an_under_cleared_assignee_is_refused(conn, client):
    """`assign_user_checked`, not `assign_user`: clearance is a hard
    ceiling, so a GREEN analyst on an AMBER case is a row every listing
    then quietly filters away."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)                       # AMBER
    green_id, _, _ = _make_user(conn, clearance="GREEN")

    r = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                    json={"user_id": str(green_id), "role_key": "ANALYST"})
    assert r.status_code == 400, r.text
    assert "clearance" in r.text
    assert _assignment_count(conn, case_id, green_id) == 0


def test_an_assignee_outside_the_compartment_is_refused(conn, client):
    """Need-to-know is not implied by clearance: an AMBER analyst who is
    not read into the case's compartment could not see it."""
    _, owner_email, owner_secret = _make_user(
        conn, clearance="AMBER", global_roles=("CASE_OWNER",),
        compartments=("OP_CLC",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner, compartments=["OP_CLC"])
    plain_id, _, _ = _make_user(conn, clearance="AMBER")        # no compartments

    r = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                    json={"user_id": str(plain_id), "role_key": "ANALYST"})
    assert r.status_code == 400, r.text
    assert "compartment" in r.text
    assert _assignment_count(conn, case_id, plain_id) == 0


def test_a_deactivated_account_cannot_be_assigned(conn, client):
    """`list_for_user` and the gate both require `is_active`, so this
    writes a row no code path will ever honour."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)
    gone_id, _, _ = _make_user(conn)
    conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s", (gone_id,))

    r = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                    json={"user_id": str(gone_id), "role_key": "ANALYST"})
    assert r.status_code == 400, r.text
    assert "deactivated" in r.text
    assert _assignment_count(conn, case_id, gone_id) == 0


def test_an_unknown_assignee_is_404_not_a_500(conn, client):
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)
    r = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                    json={"user_id": str(uuid4()), "role_key": "ANALYST"})
    assert r.status_code == 404, r.text


def test_a_grant_cannot_be_born_already_dead(conn, client):
    """docs/05 wants case access time-boxed, which makes a past expiry a
    realistic typo rather than an exotic one — and it commits an assignment
    that is expired the instant it is written."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)
    analyst_id, _, _ = _make_user(conn, clearance="AMBER")

    past = datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat()
    dead = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                       json={"user_id": str(analyst_id), "role_key": "ANALYST",
                             "expires_at": past})
    assert dead.status_code == 400, dead.text
    assert _assignment_count(conn, case_id, analyst_id) == 0

    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    ok = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                     json={"user_id": str(analyst_id), "role_key": "ANALYST",
                           "expires_at": future})
    assert ok.status_code == 200, ok.text
    assert ok.json()["expires_at"] is not None
    assert _assignment_count(conn, case_id, analyst_id) == 1


def test_the_owner_cannot_be_regraded_out_of_their_own_case(conn, client):
    """`revoke_user` refuses to strip the owner; nothing stopped you
    achieving the same thing by regrading them to READ_ONLY, which locks
    the owner out with no way back short of SQL. The two are the same act
    by different routes."""
    owner_id, owner_email, owner_secret = _make_user(
        conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)

    r = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                    json={"user_id": str(owner_id), "role_key": "READ_ONLY"})
    assert r.status_code == 400, r.text
    assert "owns this case" in r.text
    assert conn.execute(
        "SELECT role_key FROM iam.case_assignment WHERE case_id=%s AND user_id=%s",
        (case_id, owner_id)).fetchone()[0] == "CASE_OWNER"

    # Re-affirming the owner AS owner is not a demotion and is allowed —
    # it is how an expiry gets extended.
    again = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                        json={"user_id": str(owner_id), "role_key": "CASE_OWNER"})
    assert again.status_code == 200, again.text


def test_granting_access_needs_a_fresh_second_factor(conn, client):
    """`case.grant` is `requires_step_up = true` in the seed and
    `require()` enforces it as check five. There is deliberately no
    hand-rolled step-up call in the router, so this is the only thing
    proving the flag is read."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)
    analyst_id, _, _ = _make_user(conn, clearance="AMBER")

    _stale_mfa(conn, owner_email)
    stale = client.post(f"/api/v1/cases/{case_id}/users", headers=_auth(owner),
                        json={"user_id": str(analyst_id), "role_key": "ANALYST"})
    assert stale.status_code == 403, stale.text
    assert _assignment_count(conn, case_id, analyst_id) == 0
    # The session is still perfectly alive: `case.update` is not a step-up
    # permission, so a metadata edit on the SAME token still succeeds.
    assert client.patch(f"/api/v1/cases/{case_id}", headers=_auth(owner),
                        json={"title": "still me"}).status_code == 200


def test_granting_on_another_users_case_is_404(conn, client):
    """The grant endpoint is the most valuable one to probe with — it is
    how an attacker would write themselves in — so it must be the same
    non-oracle 404 as everything else."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    case_id = _create_case(client, _login(client, owner_email, owner_secret))

    attacker_id, att_email, att_secret = _make_user(
        conn, clearance="AMBER", global_roles=("CASE_OWNER",))
    attacker = _login(client, att_email, att_secret)

    body = {"user_id": str(attacker_id), "role_key": "CASE_OWNER"}
    real = client.post(f"/api/v1/cases/{case_id}/users",
                       headers=_auth(attacker), json=body)
    fake = client.post(f"/api/v1/cases/{uuid4()}/users",
                       headers=_auth(attacker), json=body)
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()
    assert _assignment_count(conn, case_id, attacker_id) == 0


# ---------------------------------------------------------------------------
# GET /cases/{case_id}/users
# ---------------------------------------------------------------------------

def test_the_roster_answers_the_whole_gate_not_one_check(conn, client):
    """An assignment row is only half of access. A row that fails any of
    the other four checks is invisible in its effects and
    indistinguishable from a working one in the table — which is how
    somebody ends up asking why a colleague they "added last week" cannot
    open the case.

    Both broken rows are inserted directly: the API correctly refuses to
    create either, and the point of `effective` is the rows that already
    exist.
    """
    owner_id, owner_email, owner_secret = _make_user(
        conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)                       # AMBER

    expired_id, _, _ = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, expired_id, "ANALYST", owner_id,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1))
    green_id, _, _ = _make_user(conn, clearance="GREEN")
    _assign(conn, case_id, green_id, "ANALYST", owner_id)
    service_id, _, _ = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, service_id, "SERVICE", owner_id)

    r = client.get(f"/api/v1/cases/{case_id}/users", headers=_auth(owner))
    assert r.status_code == 200, r.text
    by_id = {u["user_id"]: u for u in r.json()["users"]}
    assert r.json()["classification"] == "AMBER"

    assert by_id[str(owner_id)]["effective"] is True

    expired = by_id[str(expired_id)]
    assert expired["expired"] is True and expired["effective"] is False

    # Cleared below the case: the row is live and the account is active,
    # so ONLY the lattice check fails.
    green = by_id[str(green_id)]
    assert green["expired"] is False and green["is_active"] is True
    assert green["effective"] is False

    # SERVICE holds evidence.upload and NOT case.read, so the verb check
    # alone sinks it.
    assert by_id[str(service_id)]["effective"] is False


def test_the_roster_is_not_the_staff_directory(conn, client):
    """LIAISON holds `case.read`, so this endpoint is reachable by an
    external partner. Answering "who is on this case" does not require
    handing out everybody's mailbox."""
    owner_id, owner_email, owner_secret = _make_user(
        conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)
    analyst_id, analyst_email, _ = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, analyst_id, "ANALYST", owner_id)

    r = client.get(f"/api/v1/cases/{case_id}/users", headers=_auth(owner))
    assert r.status_code == 200, r.text
    assert owner_email not in r.text and analyst_email not in r.text
    # ...while still answering the question it exists to answer.
    assert all(u["display_name"] for u in r.json()["users"])
    assert str(analyst_id) in {u["user_id"] for u in r.json()["users"]}


def test_the_roster_of_another_case_is_404(conn, client):
    """The roster names every analyst on a case. It is exactly the shape of
    thing a caller with no relationship to the case must not be able to
    confirm the existence of."""
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    case_id = _create_case(client, _login(client, owner_email, owner_secret))

    _, out_email, out_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    outsider = _login(client, out_email, out_secret)
    real = client.get(f"/api/v1/cases/{case_id}/users", headers=_auth(outsider))
    fake = client.get(f"/api/v1/cases/{uuid4()}/users", headers=_auth(outsider))
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()


# ---------------------------------------------------------------------------
# POST /cases/{case_id}/status
# ---------------------------------------------------------------------------

def test_the_lifecycle_moves_and_refuses_an_illegal_move(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)

    ok = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(token),
                     json={"status": "ACTIVE"})
    assert ok.status_code == 200 and ok.json()["status"] == "ACTIVE"
    assert _audit_actions(conn, case_id).count("CASE_STATUS_CHANGED") == 1

    # DRAFT/ACTIVE -> PURGED is not in the transition table. The re-gate on
    # `case.delete` passes for a CASE_OWNER with fresh MFA, so what refuses
    # this is the lifecycle itself — and it must be a 400, not a 500 from
    # an unhandled CaseError.
    bad = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(token),
                      json={"status": "PURGED"})
    assert bad.status_code == 400, bad.text
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(token)).json()["status"] == "ACTIVE"


def test_marking_a_case_purged_is_regated_onto_case_delete(
        conn, client, closer_role):
    """`ARCHIVED -> PURGED` marks a case for destruction. Reaching it
    through the close verb would let a permission with neither step-up nor
    dual control set the flag that authorises destroying a case file, while
    `case.delete` sits in the seed with BOTH.

    0021 grants `case.close` and `case.delete` to CASE_OWNER and to nobody
    else, so this needs a principal holding one and not the other —
    otherwise the re-gate is untested by construction.
    """
    owner_id, owner_email, owner_secret = _make_user(
        conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)

    closer_id, closer_email, closer_secret = _make_user(conn, clearance="AMBER")
    _assign(conn, case_id, closer_id, closer_role, owner_id)
    closer = _login(client, closer_email, closer_secret)

    # Holds case.close: the ordinary lifecycle works, with FRESH MFA, so
    # the refusal below cannot be blamed on step-up staleness.
    archived = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(closer),
                           json={"status": "ARCHIVED"})
    assert archived.status_code == 200, archived.text

    # Does not hold case.delete.
    purge = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(closer),
                        json={"status": "PURGED"})
    assert purge.status_code == 403, purge.text
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(owner)).json()["status"] == "ARCHIVED"

    # Nor case.update — "may close" must be grantable without "may correct
    # the case file", which is the whole reason the two verbs are separate.
    assert client.patch(f"/api/v1/cases/{case_id}", headers=_auth(closer),
                        json={"title": "not my job"}).status_code == 403

    # And the owner, who holds case.delete, can complete it.
    done = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(owner),
                       json={"status": "PURGED"})
    assert done.status_code == 200, done.text
    assert done.json()["status"] == "PURGED"


def test_purging_demands_a_fresh_second_factor_when_closing_does_not(conn, client):
    """The half of `case.delete` that IS enforced. `evaluate()` reads
    `requires_step_up` off the permission row, so re-entering the gate
    under `case.delete` buys a re-challenge that `case.close` (and the
    `case.update` this endpoint used to ask for) would not have.

    Dual control is NOT bought and is not asserted here: it is the
    approvals subsystem's job and is not wired to this transition. A single
    authoriser can still mark a case PURGED.
    """
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    archived_case = _create_case(client, token)
    draft_case = _create_case(client, token)
    assert client.post(f"/api/v1/cases/{archived_case}/status", headers=_auth(token),
                       json={"status": "ARCHIVED"}).status_code == 200

    _stale_mfa(conn, email)
    refused = client.post(f"/api/v1/cases/{archived_case}/status",
                          headers=_auth(token), json={"status": "PURGED"})
    assert refused.status_code == 403, refused.text
    assert client.get(f"/api/v1/cases/{archived_case}",
                      headers=_auth(token)).json()["status"] == "ARCHIVED"

    # Same stale token, ordinary close verb: unaffected. Without this the
    # 403 above would be consistent with the session simply being dead.
    assert client.post(f"/api/v1/cases/{draft_case}/status", headers=_auth(token),
                       json={"status": "ACTIVE"}).status_code == 200


def test_an_unknown_status_is_400_not_500(conn, client):
    """`case_status` is a Postgres enum; an unvalidated value reaching the
    UPDATE would be an InvalidTextRepresentation and a 500."""
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    case_id = _create_case(client, token)
    r = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(token),
                    json={"status": "DELETED"})
    assert r.status_code == 400, r.text
    assert "Traceback" not in r.text


def test_changing_the_status_of_another_users_case_is_404(conn, client):
    _, owner_email, owner_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    owner = _login(client, owner_email, owner_secret)
    case_id = _create_case(client, owner)

    _, out_email, out_secret = _make_user(conn, global_roles=("CASE_OWNER",))
    outsider = _login(client, out_email, out_secret)

    real = client.post(f"/api/v1/cases/{case_id}/status", headers=_auth(outsider),
                       json={"status": "ACTIVE"})
    fake = client.post(f"/api/v1/cases/{uuid4()}/status", headers=_auth(outsider),
                       json={"status": "ACTIVE"})
    assert real.status_code == fake.status_code == 404
    assert real.json() == fake.json()
    assert client.get(f"/api/v1/cases/{case_id}",
                      headers=_auth(owner)).json()["status"] == "DRAFT"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def test_every_case_route_needs_a_session(client):
    """Cheap, and it is the check that a router wired in the wrong order
    (UI mount shadowing the API, a dependency dropped in a refactor) breaks
    first."""
    case_id = uuid4()
    assert client.get("/api/v1/cases").status_code == 401
    assert client.post("/api/v1/cases", json={}).status_code == 401
    assert client.get(f"/api/v1/cases/{case_id}").status_code == 401
    assert client.patch(f"/api/v1/cases/{case_id}", json={}).status_code == 401
    assert client.get(f"/api/v1/cases/{case_id}/users").status_code == 401
    assert client.post(f"/api/v1/cases/{case_id}/users", json={}).status_code == 401
    assert client.post(f"/api/v1/cases/{case_id}/status", json={}).status_code == 401


# --- retention may be extended, never shortened --------------------------
#
# Found by an adversarial pass on 2026-08-07. `retention.py` selects
# evidence for destruction with `c.retention_until <= today`, and
# `evidence.purge` is dual-controlled (decision 44). Backdating this field
# under `case.update` therefore let ONE person schedule the destruction
# that TWO are required to authorise -- and the audit trail would record a
# metadata edit rather than a destruction.

def _open_case(conn, client):
    _, email, secret = _make_user(conn, global_roles=("CASE_OWNER",))
    token = _login(client, email, secret)
    return token, _create_case(client, token)


def _retention_of(client, token, case_id) -> str:
    r = client.get(f"/api/v1/cases/{case_id}", headers=_auth(token))
    assert r.status_code == 200, r.text
    return r.json()["retention_until"]


def test_retention_cannot_be_shortened(conn, client):
    token, case_id = _open_case(conn, client)
    before = _retention_of(client, token, case_id)

    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"retention_until": "2026-01-01"})
    assert r.status_code == 400, r.text
    assert "dual-controlled" in r.text
    assert _retention_of(client, token, case_id) == before, "the date moved anyway"


def test_retention_can_still_be_extended(conn, client):
    """The refusal must be about SHORTENING, not a blanket block.

    Without this the test above passes against an endpoint that refuses
    every retention edit, which would be a worse product and a green suite.
    """
    token, case_id = _open_case(conn, client)
    r = client.patch(f"/api/v1/cases/{case_id}", headers=_auth(token),
                     json={"retention_until": "2099-12-31"})
    assert r.status_code == 200, r.text
    assert _retention_of(client, token, case_id) == "2099-12-31"
