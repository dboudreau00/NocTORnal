"""Row-level security does what the gate does, as the request role (S1,
2026-09-25).

Each test seeds as the owner and asserts what a
connection SET ROLE to the request role and bound with a real session's
proof can see and write. Each would pass on a database with no policy only
if the policy were absent AND the assertion were wrong; the unbound test
and the insert refusals fail outright without 0114, and the endpoint test
fails without 0113.
"""
from __future__ import annotations

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

POLICIED = ('core."case"', "core.node", "core.edge", "core.evidence",
            "core.assertion", "core.evidence_link", "core.evidence_custody",
            "core.hypothesis", "core.assumption", "core.node_set", "core.node_merge",
            "core.hypothesis_evidence", "core.node_set_member")


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    s.cleanup(c)
    c.close()


@pytest.fixture
def world(owner):
    """An owner, two AMBER cases (the analyst on one), a RED case, and
    nodes at three labels in the analyst's case."""
    boss = s.user(owner, "RED", (s.COMPARTMENT,))
    analyst = s.user(owner, "AMBER")
    mine = s.case(owner, boss)
    other = s.case(owner, boss)
    red_case = s.case(owner, boss, "RED")
    s.assign(owner, mine, analyst)
    s.assign(owner, red_case, analyst)
    amber = s.node(owner, mine, boss, "amber")
    red = s.node(owner, mine, boss, "red", "RED")
    boxed = s.node(owner, mine, boss, "boxed", "AMBER", (s.COMPARTMENT,))
    elsewhere = s.node(owner, other, boss, "elsewhere")
    red_there = s.node(owner, red_case, boss, "red there", "RED")
    return {"boss": boss, "analyst": analyst, "mine": mine, "other": other,
            "red_case": red_case, "amber": amber, "red": red, "boxed": boxed,
            "elsewhere": elsewhere, "red_there": red_there}


def _visible_nodes(conn, case_id=None) -> set:
    if case_id is None:
        return {r[0] for r in conn.execute("SELECT id FROM core.node")}
    return {r[0] for r in conn.execute(
        "SELECT id FROM core.node WHERE case_id = %s", (case_id,))}


def test_an_unbound_request_connection_sees_nothing_and_writes_nothing(owner, world):
    app = s.app_conn()
    try:
        for table in POLICIED:
            assert s.count(app, f"SELECT count(*) FROM {table}") == 0, table
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO core.node (case_id, node_type, label, created_by)
                   VALUES (%s, 'IDENTITY', 'forged', %s)""",
                (world["mine"], world["analyst"]))
    finally:
        app.close()


def test_an_assigned_amber_analyst_sees_the_amber_rows_of_their_case_only(owner, world):
    _, raw = s.session(owner, world["analyst"])
    app = s.app_conn(raw)
    try:
        seen = _visible_nodes(app)
        assert world["amber"] in seen
        assert world["red"] not in seen, "above clearance"
        assert world["boxed"] not in seen, "compartment not held"
        assert world["elsewhere"] not in seen, "not assigned to that case"
        assert world["red_there"] not in seen, "a RED case above clearance"
        cases = {r[0] for r in app.execute('SELECT id FROM core."case"')}
        assert world["mine"] in cases
        assert world["other"] not in cases and world["red_case"] not in cases
    finally:
        app.close()


def test_a_case_scoped_grant_raises_that_case_only_and_stops_when_revoked(owner, world):
    grant = s.break_glass(owner, world["analyst"], "RED", world["mine"])
    _, raw = s.session(owner, world["analyst"])
    app = s.app_conn(raw)
    try:
        seen = _visible_nodes(app)
        assert world["red"] in seen, "the grant raises its own case"
        assert world["red_there"] not in seen, "and no other"
        assert world["boxed"] not in seen, "compartments are never widened"
        owner.execute("UPDATE iam.break_glass SET revoked_at = now() WHERE id = %s", (grant,))
        assert world["red"] not in _visible_nodes(app), "revocation is immediate"
    finally:
        app.close()


def test_a_global_grant_raises_every_assigned_case(owner, world):
    s.break_glass(owner, world["analyst"], "RED")
    _, raw = s.session(owner, world["analyst"])
    app = s.app_conn(raw)
    try:
        seen = _visible_nodes(app)
        assert {world["red"], world["red_there"]} <= seen
        assert world["elsewhere"] not in seen, "a grant does not assign"
    finally:
        app.close()


@pytest.mark.parametrize("how", ["assignment_expired", "account_inactive",
                                 "session_revoked", "session_expired"])
def test_a_dead_relationship_binds_nobody_or_shows_nothing(owner, world, how):
    sid, raw = s.session(owner, world["analyst"])
    if how == "assignment_expired":
        s.assign(owner, world["mine"], world["analyst"],
                 expires_at=s.now() - s.timedelta(minutes=1))
    elif how == "account_inactive":
        owner.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s",
                      (world["analyst"],))
    elif how == "session_revoked":
        owner.execute("UPDATE iam.session SET revoked_at = now(), revoke_reason = 't' "
                      "WHERE id = %s", (sid,))
    else:
        owner.execute("UPDATE iam.session SET expires_at = now() - interval '1 second', "
                      "issued_at = now() - interval '2 seconds' WHERE id = %s", (sid,))
    app = s.app_conn(raw)
    try:
        assert world["amber"] not in _visible_nodes(app), how
    finally:
        app.close()


def test_writes_above_clearance_or_into_an_unassigned_case_are_refused(owner, world):
    _, raw = s.session(owner, world["analyst"])
    app = s.app_conn(raw)
    try:
        for case_id, label in ((world["mine"], "RED"), (world["other"], "AMBER")):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(
                    """INSERT INTO core.node
                           (case_id, node_type, label, created_by, classification)
                       VALUES (%s, 'IDENTITY', 'forged', %s, %s)""",
                    (case_id, world["analyst"], label))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute('UPDATE core."case" SET classification = \'RED\' WHERE id = %s',
                        (world["mine"],))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO core."case" (code, title, owner_user_id, legal_basis,
                                              retention_until, review_due)
                   VALUES ('OP-RLS-FORGED', 'forged', %s, 'x', '2030-01-01', '2029-01-01')""",
                (world["analyst"],))
        # An UPDATE of a row the connection cannot see changes nothing.
        cur = app.execute("UPDATE core.node SET label = 'renamed' WHERE id = %s",
                          (world["red"],))
        assert cur.rowcount == 0
    finally:
        app.close()


def test_a_claim_link_and_custody_are_never_more_visible_than_their_subject(owner, world):
    red_claims = s.count(owner, "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                         (world["red"],))
    assert red_claims >= 1
    ev = s.exhibit(owner, world["mine"], world["boss"], "RED")
    owner.execute("INSERT INTO core.evidence_link (evidence_id, node_id, created_by) "
                  "VALUES (%s, %s, %s)", (ev, world["amber"], world["boss"]))
    _, raw = s.session(owner, world["analyst"])
    app = s.app_conn(raw)
    try:
        assert s.count(app, "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                       (world["red"],)) == 0
        assert s.count(app, "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                       (world["amber"],)) >= 1
        assert s.count(app, "SELECT count(*) FROM core.evidence WHERE id = %s", (ev,)) == 0
        assert s.count(app, "SELECT count(*) FROM core.evidence_link WHERE evidence_id = %s",
                       (ev,)) == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("INSERT INTO core.evidence_custody (evidence_id, action, actor_id) "
                        "VALUES (%s, 'VIEWED', %s)", (ev, world["analyst"]))
    finally:
        app.close()


def test_one_token_cannot_bind_as_another_and_resetting_unbinds(owner, world):
    from noctornal_api.db import bind_session
    _, raw_a = s.session(owner, world["analyst"])
    _, raw_b = s.session(owner, world["boss"])
    app = s.app_conn(raw_a)
    try:
        assert bind_session(app, raw_a).actor == world["analyst"]
        assert bind_session(app, raw_b).actor == world["boss"]
        # The token hash is readable to the request role; binding with it
        # (or with the raw token itself) must not work.
        stored = owner.execute("SELECT token_hash FROM iam.session WHERE user_id = %s",
                               (world["analyst"],)).fetchone()[0]
        for forged in (bytes(stored).hex(), raw_a):
            app.execute("SELECT set_config('noctornal.rls_proof', %s, false)", (forged,))
            assert app.execute("SELECT iam.rls_actor()").fetchone()[0] is None
        app.execute("SELECT set_config('noctornal.rls_proof', '', false)")
        assert _visible_nodes(app) == set()
    finally:
        app.close()


def test_the_invariant_triggers_see_rows_the_writer_cannot(owner, world):
    """0113. An edge from a node the analyst can see to one in another case
    they cannot: validate_edge_endpoints must still see the endpoint and
    refuse the cross-case edge, where a filtered read would read NULL and
    let it through."""
    _, raw = s.session(owner, world["analyst"])
    app = s.app_conn(raw)
    try:
        # The endpoint trigger's own refusal, not the deferred assertion
        # check a commit would raise anyway: only a trigger that SEES the
        # other case's node can say the edge spans cases.
        with pytest.raises(psycopg.errors.RaiseException, match="spans cases"):
            app.execute(
                """INSERT INTO core.edge (case_id, edge_type, src_node_id, dst_node_id,
                                          created_by, classification)
                   VALUES (%s, 'VOUCHED_FOR', %s, %s, %s, 'AMBER')""",
                (world["mine"], world["amber"], world["elsewhere"], world["analyst"]))
    finally:
        app.close()


def test_turning_row_security_off_is_an_error_not_a_bypass(owner, world):
    _, raw = s.session(owner, world["analyst"])
    app = s.app_conn(raw)
    try:
        app.execute("SET row_security = off")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("SELECT count(*) FROM core.node")
    finally:
        app.close()


def test_the_system_role_sees_every_row(owner, world):
    from noctornal_api.db import connect
    w = connect()
    try:
        w.execute(f"SET ROLE {s.WORKER_ROLE}")
        seen = {r[0] for r in w.execute("SELECT id FROM core.node WHERE case_id = ANY(%s)",
                                        ([world["mine"], world["other"]],))}
        assert {world["red"], world["boxed"], world["elsewhere"]} <= seen
    finally:
        w.close()


def test_the_analysis_follows_its_case_and_its_subject(owner, world):
    """0116: a hypothesis is visible in a readable case only; a stance is
    never more visible than the claim it scores; a set membership never
    more visible than its node."""
    boss = world["boss"]
    mine = owner.execute(
        "INSERT INTO core.hypothesis (case_id, statement, created_by) "
        "VALUES (%s, 'theirs', %s) RETURNING id", (world["mine"], boss)).fetchone()[0]
    other = owner.execute(
        "INSERT INTO core.hypothesis (case_id, statement, created_by) "
        "VALUES (%s, 'elsewhere', %s) RETURNING id", (world["other"], boss)).fetchone()[0]
    red_claim = owner.execute("SELECT id FROM core.assertion WHERE node_id = %s LIMIT 1",
                              (world["red"],)).fetchone()[0]
    amber_claim = owner.execute("SELECT id FROM core.assertion WHERE node_id = %s LIMIT 1",
                                (world["amber"],)).fetchone()[0]
    for claim in (red_claim, amber_claim):
        owner.execute("INSERT INTO core.hypothesis_evidence (hypothesis_id, assertion_id, "
                      "stance) VALUES (%s, %s, 1)", (mine, claim))
    node_set = owner.execute(
        "INSERT INTO core.node_set (case_id, name, created_by) VALUES (%s, 'set', %s) "
        "RETURNING id", (world["mine"], boss)).fetchone()[0]
    for node_id in (world["amber"], world["red"]):
        owner.execute("INSERT INTO core.node_set_member (set_id, node_id) VALUES (%s, %s)",
                      (node_set, node_id))
    _, raw = s.session(owner, world["analyst"])
    app = s.app_conn(raw)
    try:
        seen = {r[0] for r in app.execute("SELECT id FROM core.hypothesis")}
        assert mine in seen and other not in seen
        stances = {r[0] for r in app.execute(
            "SELECT assertion_id FROM core.hypothesis_evidence WHERE hypothesis_id = %s",
            (mine,))}
        assert stances == {amber_claim}
        members = {r[0] for r in app.execute(
            "SELECT node_id FROM core.node_set_member WHERE set_id = %s", (node_set,))}
        assert members == {world["amber"]}
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute("INSERT INTO core.hypothesis (case_id, statement, created_by) "
                        "VALUES (%s, 'forged', %s)", (world["other"], world["analyst"]))
    finally:
        app.close()


def test_the_policy_helpers_run_once_per_statement_not_once_per_row(owner, world):
    """The bound on per-row work: every helper call in the ELEMENT policy is an
    uncorrelated initplan, so the plan for a case read carries InitPlans
    and no SubPlan. EXPLAIN at default settings; nothing forced."""
    import json

    _, raw = s.session(owner, world["analyst"])
    app = s.app_conn(raw)
    try:
        plan = app.execute("EXPLAIN (FORMAT JSON, VERBOSE) SELECT id FROM core.node WHERE case_id = %s",
                           (world["mine"],)).fetchone()[0]
    finally:
        app.close()
    text = json.dumps(plan)
    assert '"InitPlan"' in text, text
    assert '"SubPlan"' not in text, "a policy helper is evaluated per row"
    assert "rls_cases" in text and "rls_compartments" in text
