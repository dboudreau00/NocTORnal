"""Case membership under row-level security (rls-6): who may read who holds which role on which case.

0192's policy shows a request its own assignments, whatever the case's labels, and every assignment on
a case in `iam.rls_cases()`, the team the roster already shows the case's members; a connection bound
to nobody reads none. The Lab reads a case's lead investigators through `iam.case_leads` (0191), the one
reader that needs another person's assignment on a case the caller is not on. Each refusal is paired
with the legitimate readers still working, over HTTP in production's shape. Run as the request role
bound by a real session's proof, and as the system role, seeded as the owner. Account prefix `rlsca-`,
unique to this file.
"""
from __future__ import annotations

import importlib.util
import re
from datetime import date, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

import rls_support as s

pytestmark = s.GATED

P = "rlsca-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"


def _migration(prefix: str):
    path = next(VERSIONS.glob(f"{prefix}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{prefix}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{P}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    with c.transaction():
        c.execute(f"""DELETE FROM notify.delivery WHERE notification_id IN
                        (SELECT id FROM notify.notification
                          WHERE recipient_id IN {users} OR case_id IN {cases}
                             OR actor_id IN {users})""")
        c.execute(f"""DELETE FROM notify.notification
                       WHERE recipient_id IN {users} OR case_id IN {cases}
                          OR actor_id IN {users}""")
        c.execute(f"DELETE FROM core.approval_request "
                  f"WHERE requested_by IN {users} OR case_id IN {cases}")
    s.cleanup(c, P)
    c.close()


@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient

    from noctornal_api.db import ASSUME_ROLE_ENV
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    monkeypatch.delenv("NOCTORNAL_RELAX_SEASONING_DAYS", raising=False)
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _auth(owner, uid) -> dict:
    _sid, raw = s.session(owner, uid)
    return {"Authorization": f"Bearer {raw}"}


def _bound(owner, uid):
    _sid, raw = s.session(owner, uid)
    return s.app_conn(raw)


def _leads(conn, case_id) -> set:
    return {r[0] for r in conn.execute("SELECT * FROM iam.case_leads(%s)", (case_id,))}


def _rows(conn, *cases) -> set:
    return {(r[0], r[1]) for r in conn.execute(
        "SELECT case_id, user_id FROM iam.case_assignment WHERE case_id = ANY(%s)",
        (list(cases),))}


@pytest.fixture
def world(owner):
    """`a` (AMBER) is on x (AMBER) with `b`, and on y (RED, above `a`) with `c`; `b` is on z, which `a`
    is not. Each case's lead holds CASE_OWNER on it from its opening."""
    out = {}
    for name, level in (("x", "AMBER"), ("y", "RED"), ("z", "AMBER")):
        out[f"lead_{name}"] = s.user(owner, level, prefix=P)
        out[name] = s.case(owner, out[f"lead_{name}"], level)
    out["a"] = s.user(owner, "AMBER", prefix=P)
    out["b"] = s.user(owner, "AMBER", prefix=P)
    out["c"] = s.user(owner, "RED", prefix=P)
    for case, who in (("x", "a"), ("x", "b"), ("y", "a"), ("y", "c"), ("z", "b")):
        s.assign(owner, out[case], out[who])
    return out


def _everyone(w) -> set:
    return {(w["x"], w["lead_x"]), (w["x"], w["a"]), (w["x"], w["b"]),
            (w["y"], w["lead_y"]), (w["y"], w["a"]), (w["y"], w["c"]),
            (w["z"], w["lead_z"]), (w["z"], w["b"])}


def test_the_request_role_reads_only_its_own_assignments_and_the_teams_of_cases_it_can_open(
        owner, world):
    w = world
    app = _bound(owner, w["a"])
    try:
        seen = _rows(app, w["x"], w["y"], w["z"])
    finally:
        app.close()
    # Its own rows on x and on y (a case above it), and x's team; nothing of y's team or of z.
    assert seen == {(w["x"], w["lead_x"]), (w["x"], w["a"]), (w["x"], w["b"]),
                    (w["y"], w["a"])}, seen


def test_an_unbound_request_connection_reads_no_assignment(owner, world):
    app = s.app_conn()
    try:
        assert s.count(app, "SELECT count(*) FROM iam.case_assignment") == 0
    finally:
        app.close()


def test_the_system_role_and_the_owner_read_every_assignment(owner, world):
    w = world
    worker = s.owner_conn()
    try:
        worker.execute(f"SET ROLE {s.WORKER_ROLE}")
        assert _rows(worker, w["x"], w["y"], w["z"]) == _everyone(w)
    finally:
        worker.close()
    assert _rows(owner, w["x"], w["y"], w["z"]) == _everyone(w)


def test_an_expired_assignment_closes_the_team_arm_but_not_the_own_row(owner, world):
    w = world
    owner.execute("UPDATE iam.case_assignment SET expires_at = now() - interval '1 minute' "
                  "WHERE case_id = %s AND user_id = %s", (w["x"], w["a"]))
    app = _bound(owner, w["a"])
    try:
        assert _rows(app, w["x"], w["y"], w["z"]) == {(w["x"], w["a"]), (w["y"], w["a"])}
    finally:
        app.close()


@pytest.mark.parametrize("scope", ["this case", "every case"])
def test_a_break_glass_grant_opens_the_team_arm_as_it_opens_the_case(owner, world, scope):
    """`iam.rls_cases()` counts a live grant, as the gate does: under one at RED, y is a case `a` may
    open, so its team is readable too. A revoked grant takes it away again."""
    w = world
    grant = s.break_glass(owner, w["a"], "RED", w["y"] if scope == "this case" else None)
    app = _bound(owner, w["a"])
    try:
        assert _rows(app, w["y"]) == {(w["y"], w["lead_y"]), (w["y"], w["a"]),
                                      (w["y"], w["c"])}
        owner.execute("UPDATE iam.break_glass SET revoked_at = now() WHERE id = %s", (grant,))
        assert _rows(app, w["y"]) == {(w["y"], w["a"])}
    finally:
        app.close()


def test_the_resolvers_assignment_read_is_still_an_index_probe(owner, world):
    """Every gated request reads one assignment. Under the policy it is still an index probe on the
    reader (the primary key, or the (user_id, expires_at) index when the statistics favour it), never a
    scan of the table, and the policy's helpers run once per statement as initplans, never once per
    row."""
    w = world
    statement = ("SELECT role_key, (expires_at IS NULL OR expires_at > now()) AS unexpired "
                 "FROM iam.case_assignment WHERE case_id = %s AND user_id = %s")
    app = _bound(owner, w["a"])
    try:
        app.execute("SET enable_seqscan = off")
        plan = "\n".join(r[0] for r in app.execute("EXPLAIN " + statement, (w["x"], w["a"])))
        assert re.search(r"Index (Only )?Scan using case_assignment_|Bitmap Index Scan on case_assignment_", plan), plan
        assert "Seq Scan" not in plan, plan
        assert s.per_row_definer_calls(app, statement, (w["x"], w["a"])) == []
        assert app.execute(statement, (w["x"], w["a"])).fetchone() == ("ANALYST", True)
    finally:
        app.close()


def test_case_leads_answers_only_the_lab_the_team_and_the_exempt(owner):
    """A member of the case is told its leads, and so is a Lab analyst on no case for a case within
    their reach; a bound stranger, a connection bound to nobody and the Lab above its reach are told
    nobody. Only live CASE_OWNER assignments are leads."""
    lead = s.user(owner, "RED", prefix=P)
    amber = s.case(owner, lead, "AMBER")
    red = s.case(owner, lead, "RED")
    lapsed = s.user(owner, "RED", prefix=P)
    s.assign(owner, amber, lapsed, "CASE_OWNER", expires_at=s.now() - timedelta(hours=1))
    member = s.user(owner, "AMBER", prefix=P)
    s.assign(owner, amber, member)
    lab = s.user(owner, "AMBER", prefix=P)
    s.grant_global(owner, lab, "MALWARE_ANALYST")
    stranger = s.user(owner, "RED", prefix=P)

    told = {}
    for who in (member, lab, stranger):
        app = _bound(owner, who)
        try:
            told[who] = (_leads(app, amber), _leads(app, red))
        finally:
            app.close()
    assert told[member] == ({lead}, set()), told[member]
    assert told[lab] == ({lead}, set()), "the Lab is told the leads of a case within its reach only"
    assert told[stranger] == (set(), set()), told[stranger]

    unbound = s.app_conn()
    worker = s.owner_conn()
    try:
        worker.execute(f"SET ROLE {s.WORKER_ROLE}")
        assert _leads(unbound, amber) == set()
        assert _leads(worker, amber) == {lead} and _leads(worker, red) == {lead}
    finally:
        unbound.close()
        worker.close()
    assert _leads(owner, amber) == {lead}, "the lapsed lead and the analyst are not leads"


def test_a_member_whose_case_rose_above_them_is_told_no_leads(owner):
    """The team arm is the row policy's own (`iam.rls_cases()`): a member whose clearance no longer
    reaches the case cannot open it, and is told nothing about its team either."""
    lead = s.user(owner, "RED", prefix=P)
    case_id = s.case(owner, lead, "AMBER")
    member = s.user(owner, "AMBER", prefix=P)
    s.assign(owner, case_id, member)
    app = _bound(owner, member)
    try:
        assert _leads(app, case_id) == {lead}
        owner.execute('UPDATE core."case" SET classification = \'RED\' WHERE id = %s',
                      (case_id,))
        assert _leads(app, case_id) == set()
    finally:
        app.close()


def test_execute_on_case_leads_is_the_runtime_roles_and_not_public(owner):
    fn = _migration("0191").FUNCTION
    acl = owner.execute("SELECT coalesce(proacl::text, '') FROM pg_proc "
                        "WHERE oid = %s::regprocedure", (fn,)).fetchone()[0]
    assert not re.search(r"(^|[{,])=X/", acl), acl
    for role in (s.APP_ROLE, s.WORKER_ROLE):
        assert owner.execute("SELECT has_function_privilege(%s, %s, 'EXECUTE')",
                             (role, fn)).fetchone()[0] is True, role


def test_the_team_list_and_the_roster_survive_the_policy(owner, client):
    """As the request role, over HTTP. Each reader of other people's assignments on a case its caller
    has opened still finds them: the roster a member reads, a grant that replaces a grade, a revoke,
    the colleagues who could relax the merge switch, the lookup authorisers, an approval's fan-out and
    the spend of a relax. Without the team term each would come back empty, and quietly."""
    from noctornal_api.cases import CaseService
    lead = s.user(owner, "RED", prefix=P)
    deputy = s.user(owner, "AMBER", prefix=P)
    analyst = s.user(owner, "AMBER", prefix=P)
    colleague = s.user(owner, "AMBER", prefix=P)
    case_id = CaseService(owner).create(
        code=f"OP-RLSCA-{uuid4().hex[:6].upper()}", title="Case membership",
        legal_basis="test authority", retention_until=date(2030, 1, 1),
        review_due=date(2029, 1, 1), owner_user_id=lead, created_by=lead,
        deputy_user_id=deputy, classification="AMBER")
    s.assign(owner, case_id, analyst)
    # The deputy has held case.update past the seasoning window, as a second person on the switch must.
    owner.execute("UPDATE iam.case_assignment SET granted_at = now() - interval '8 days' "
                  "WHERE case_id = %s AND user_id = %s", (case_id, deputy))
    as_lead, as_deputy, as_analyst = (_auth(owner, u) for u in (lead, deputy, analyst))
    base = f"/api/v1/cases/{case_id}"

    roster = client.get(f"{base}/users", headers=as_analyst)
    assert roster.status_code == 200, roster.text
    assert {u["user_id"] for u in roster.json()["users"]} == {
        str(lead), str(deputy), str(analyst)}

    for role, replaced in (("ANALYST", None), ("REVIEWER", "ANALYST")):
        granted = client.post(f"{base}/users", headers=as_lead,
                              json={"user_id": str(colleague), "role_key": role})
        assert granted.status_code == 200, granted.text
        assert granted.json()["replaced_role"] == replaced
    revoked = client.delete(f"{base}/users/{colleague}", headers=as_lead)
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked_role"] == "REVIEWER"

    policy = client.get(f"{base}/policy", headers=as_lead)
    assert policy.status_code == 200, policy.text
    assert policy.json()["relax_signers"] == 1

    authorisers = client.get(f"{base}/lookups/authorisers", headers=as_analyst)
    assert authorisers.status_code == 200, authorisers.text
    assert {a["id"] for a in authorisers.json()["authorisers"]} == {str(lead), str(deputy)}

    owner.execute('UPDATE core."case" SET dual_control_merge = true WHERE id = %s', (case_id,))
    epoch = owner.execute('SELECT dual_control_merge_epoch FROM core."case" WHERE id = %s',
                          (case_id,)).fetchone()[0]
    raised = client.post(f"{base}/approvals", headers=as_lead, json={
        "operation": "case.policy.relax",
        "payload": {"setting": "dual_control_merge", "from": True, "to": False,
                    "epoch": epoch},
        "justification": "no longer contested"})
    assert raised.status_code == 201, raised.text
    assert raised.json()["approvers_notified"] == 1, "the fan-out found nobody to ask"
    decided = client.post(f"{base}/approvals/{raised.json()['id']}/decide",
                          headers=as_deputy, json={"approve": True})
    assert decided.status_code == 200, decided.text
    spent = client.put(f"{base}/policy", headers=as_lead, json={
        "dual_control_merge": False, "approval_request_id": raised.json()["id"]})
    assert spent.status_code == 200, spent.text
    assert spent.json()["dual_control_merge"] is False
