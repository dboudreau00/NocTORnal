"""Invariant 5 at the database: a recorded claim is never rewritten, never
un-retracted and never deleted by the runtime roles
(graph-assertion-claims-mutable-by-request-role, review 2026-10-03,
migration 0135).

Until 0135 the request role held UPDATE and DELETE on `core.assertion`
(0060, and 0108 for the system role), so one statement on its connection
could re-grade a claim, rewrite its rationale, un-retract a withdrawn
source or delete a claim that was not an element's last, with no audit row.
"Stamps `retracted_at` once from NULL" was a convention of `graph.py`.

What these tests hold, in both directions:

- the runtime roles cannot UPDATE any claim column and cannot DELETE, by
  privilege, whatever the statement;
- the five mark columns still take their one write from NULL, for both
  roles, and nothing takes it back (a trigger, which holds the owner too);
- every legitimate write path still works as the request role and as the
  system role: create, add a claim, correct, retract once, supersede once;
- TRUNCATE is refused;
- the migration's grant text is idempotent and replayed by
  `scripts/runtime_roles.py ensure`, and the migration round-trips.

Email prefix `g43a-`. Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import psycopg
import pytest
import review_graph_support as g
import rls_support as s

pytestmark = s.GATED

PREFIX = "g43a-"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"

#: The only columns a runtime role may write once a claim is recorded.
MARKS = frozenset({"retracted_at", "retracted_by", "retraction_reason",
                   "superseded_at", "superseded_by"})


def _migration(prefix: str):
    path = next(VERSIONS.glob(f"{prefix}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{prefix}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _RollBack(Exception):
    pass


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    g.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def world(owner):
    """A case with an owner and an AMBER analyst, one entity with its
    founding claim and a second, retracted claim."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    boss = s.user(owner, "RED", prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, boss, "CASE_OWNER")
    s.assign(owner, case_id, analyst, "ANALYST")
    node = s.node(owner, case_id, boss, "g43a entity")
    svc = GraphWriteService(owner)
    spare = svc.add_assertion(case_id=case_id, node_id=node, assertion=AssertionInput(
        basis="DIRECT_OBSERVATION", created_by=boss, reliability="A",
        credibility="1", confidence="HIGH", rationale="a second claim"))
    svc.retract_assertion(spare, retracted_by=boss, reason="withdrawn",
                          at=g.now())
    return {"case": case_id, "boss": boss, "analyst": analyst, "node": node,
            "retracted": spare}


def _live_claim(owner, world, rationale="a live second claim"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(owner).add_assertion(
        case_id=world["case"], node_id=world["node"],
        assertion=AssertionInput(
            basis="DIRECT_OBSERVATION", created_by=world["boss"],
            reliability="A", credibility="1", confidence="HIGH",
            rationale=rationale))


def _claim_columns(owner) -> list[str]:
    return [r[0] for r in owner.execute(
        """SELECT column_name FROM information_schema.columns
            WHERE table_schema = 'core' AND table_name = 'assertion'
            ORDER BY ordinal_position""").fetchall()]


# --- the privileges ---------------------------------------------------------

@pytest.mark.parametrize("role", [s.APP_ROLE, s.WORKER_ROLE])
def test_a_runtime_role_can_write_only_the_mark_columns_of_a_claim(owner, role):
    columns = _claim_columns(owner)
    assert "rationale" in columns and "claim_value" in columns, columns
    writable = {c for c in columns if owner.execute(
        "SELECT has_column_privilege(%s, 'core.assertion', %s, 'UPDATE')",
        (role, c)).fetchone()[0]}
    assert writable == MARKS, sorted(writable ^ MARKS)
    held = {p: owner.execute(
        "SELECT has_table_privilege(%s, 'core.assertion', %s)",
        (role, p)).fetchone()[0]
        for p in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE")}
    assert held == {"SELECT": True, "INSERT": True, "UPDATE": False,
                    "DELETE": False, "TRUNCATE": False}


def test_the_request_role_cannot_rewrite_any_claim_column(owner, world):
    """The review's reproduction, column by column. `SET c = c` is enough:
    the privilege is checked on the column named, not on the value."""
    app = g.bound(owner, world["analyst"])
    try:
        assert app.execute("SELECT current_user").fetchone()[0] == s.APP_ROLE
        before = owner.execute(
            "SELECT * FROM core.assertion WHERE id = %s",
            (world["retracted"],)).fetchone()
        for column in _claim_columns(owner):
            if column in MARKS:
                continue
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(f"UPDATE core.assertion SET {column} = {column} "
                            f"WHERE id = %s", (world["retracted"],))
        # The review's own statement, whole.
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """UPDATE core.assertion
                      SET retracted_at = NULL, retracted_by = NULL,
                          retraction_reason = NULL, reliability = 'A',
                          credibility = '1', confidence = 'HIGH',
                          rationale = 'rewritten by request role',
                          claim_value = '{"x":1}'::jsonb
                    WHERE id = %s""", (world["retracted"],))
        after = owner.execute(
            "SELECT * FROM core.assertion WHERE id = %s",
            (world["retracted"],)).fetchone()
        assert after == before
    finally:
        app.close()


def test_no_other_statement_shape_gets_past_the_privilege(owner, world):
    """INSERT ... ON CONFLICT DO UPDATE, MERGE and UPDATE ... FROM are all
    checked against the same column privileges, so none is a way round."""
    app = g.bound(owner, world["analyst"])
    try:
        claim = world["retracted"]
        for sql in (
            """INSERT INTO core.assertion (id, case_id, node_id, basis, created_by)
               VALUES (%s, %s, %s, 'DIRECT_OBSERVATION', %s)
               ON CONFLICT (id) DO UPDATE SET rationale = 'rewritten'""",
            """MERGE INTO core.assertion t
               USING (SELECT %s::uuid AS id) s ON t.id = s.id
               WHEN MATCHED THEN UPDATE SET rationale = 'rewritten'""",
            """MERGE INTO core.assertion t
               USING (SELECT %s::uuid AS id) s ON t.id = s.id
               WHEN MATCHED THEN DELETE""",
            """UPDATE core.assertion t SET rationale = 'rewritten'
                 FROM (SELECT %s::uuid AS id) s WHERE t.id = s.id""",
        ):
            params = ((claim, world["case"], world["node"], world["analyst"])
                      if "VALUES" in sql else (claim,))
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                app.execute(sql, params)
        assert g.one(owner, "SELECT rationale FROM core.assertion WHERE id = %s",
                     (claim,)) == "a second claim"
    finally:
        app.close()


def test_the_request_role_cannot_delete_a_claim(owner, world):
    app = g.bound(owner, world["analyst"])
    try:
        for target in (world["retracted"], None):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                if target is None:
                    app.execute("DELETE FROM core.assertion WHERE case_id = %s",
                                (world["case"],))
                else:
                    app.execute("DELETE FROM core.assertion WHERE id = %s",
                                (target,))
        assert g.one(owner, "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                     (world["node"],)) == 2
    finally:
        app.close()


def test_the_system_role_cannot_rewrite_or_delete_a_claim_either(owner, world):
    system = g.worker()
    try:
        assert system.execute("SELECT current_user").fetchone()[0] == s.WORKER_ROLE
        for sql in ("UPDATE core.assertion SET rationale = 'x' WHERE id = %s",
                    "UPDATE core.assertion SET claim_value = '{}'::jsonb WHERE id = %s",
                    "DELETE FROM core.assertion WHERE id = %s"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                system.execute(sql, (world["retracted"],))
    finally:
        system.close()


# --- the marks: once, from NULL ---------------------------------------------

@pytest.mark.parametrize("who", ["app", "system", "owner"])
def test_a_retraction_is_never_withdrawn_or_changed(owner, world, who):
    """Invariant 5's one exception is a marked row stamped once. The trigger
    holds every role, the schema owner included."""
    conn = {"app": lambda: g.bound(owner, world["analyst"]),
            "system": g.worker, "owner": lambda: owner}[who]()
    try:
        for sql in (
            "UPDATE core.assertion SET retracted_at = NULL, retracted_by = NULL, "
            "retraction_reason = NULL WHERE id = %s",
            "UPDATE core.assertion SET retracted_at = NULL WHERE id = %s",
            "UPDATE core.assertion SET retraction_reason = 'a kinder reason' "
            "WHERE id = %s",
            "UPDATE core.assertion SET retracted_at = now() WHERE id = %s",
            "UPDATE core.assertion SET retracted_by = NULL WHERE id = %s",
        ):
            with pytest.raises(psycopg.errors.RaiseException) as raised:
                conn.execute(sql, (world["retracted"],))
            assert "retraction" in str(raised.value)
        row = owner.execute(
            "SELECT retracted_at IS NOT NULL, retracted_by, retraction_reason "
            "FROM core.assertion WHERE id = %s", (world["retracted"],)).fetchone()
        assert row == (True, world["boss"], "withdrawn")
    finally:
        if conn is not owner:
            conn.close()


def test_a_retraction_cannot_arrive_without_its_time(owner, world):
    live = _live_claim(owner, world)
    for sql in ("UPDATE core.assertion SET retracted_by = %s WHERE id = %s",
                "UPDATE core.assertion SET retraction_reason = 'x' WHERE id = %s"):
        params = (world["boss"], live) if "retracted_by" in sql else (live,)
        with pytest.raises(psycopg.errors.RaiseException) as raised:
            owner.execute(sql, params)
        assert "together" in str(raised.value)


def test_a_supersession_is_stamped_once_from_null_and_never_changed(owner, world):
    live = _live_claim(owner, world)
    other = _live_claim(owner, world, "another live claim")
    owner.execute("UPDATE core.assertion SET superseded_at = now(), "
                  "superseded_by = %s WHERE id = %s", (other, live))
    for sql, params in (
        ("UPDATE core.assertion SET superseded_at = NULL, superseded_by = NULL "
         "WHERE id = %s", (live,)),
        ("UPDATE core.assertion SET superseded_by = %s WHERE id = %s",
         (live, live)),
        ("UPDATE core.assertion SET superseded_at = now() WHERE id = %s", (live,)),
    ):
        with pytest.raises(psycopg.errors.RaiseException) as raised:
            owner.execute(sql, params)
        assert "supersession" in str(raised.value)
    # A mark stamped without its time is refused too.
    third = _live_claim(owner, world, "a third live claim")
    with pytest.raises(psycopg.errors.RaiseException):
        owner.execute("UPDATE core.assertion SET superseded_by = %s WHERE id = %s",
                      (other, third))


def test_an_update_that_leaves_the_marks_alone_is_not_refused(owner, world):
    """The guard is on the marks only: a statement that names them but does
    not change them (an ORM writing every column back) is harmless."""
    live = _live_claim(owner, world)
    owner.execute("UPDATE core.assertion SET retracted_at = retracted_at, "
                  "superseded_at = superseded_at WHERE id = %s", (live,))
    owner.execute("UPDATE core.assertion SET retracted_at = retracted_at "
                  "WHERE id = %s", (world["retracted"],))


# --- the marks: coherent, for a runtime role (the verifier's round) ----------

def _runtime(owner, world, who):
    return (g.bound(owner, world["analyst"]) if who == "app" else g.worker())


@pytest.mark.parametrize("who", ["app", "system"])
def test_a_runtime_role_cannot_retract_without_its_author_and_its_reason(owner, world, who):
    """The verifier's reproduction: `UPDATE core.assertion SET retracted_at =
    now() WHERE id = <live claim>` stamped a retraction with no author and no
    reason, and nothing in the audit log. The time alone no longer passes."""
    conn = _runtime(owner, world, who)
    try:
        live = _live_claim(owner, world)
        for sql, params in (
            ("UPDATE core.assertion SET retracted_at = now() WHERE id = %s", (live,)),
            ("UPDATE core.assertion SET retracted_at = now(), retracted_by = %s "
             "WHERE id = %s", (world["boss"], live)),
            ("UPDATE core.assertion SET retracted_at = now(), "
             "retraction_reason = 'a reason' WHERE id = %s", (live,)),
            ("UPDATE core.assertion SET retracted_at = now(), retracted_by = %s, "
             "retraction_reason = '   ' WHERE id = %s", (world["boss"], live)),
        ):
            with pytest.raises(psycopg.errors.RaiseException) as raised:
                conn.execute(sql, params)
            assert "author" in str(raised.value) or "together" in str(raised.value)
        assert g.one(owner, "SELECT retracted_at IS NULL FROM core.assertion "
                            "WHERE id = %s", (live,)) is True
    finally:
        conn.close()


@pytest.mark.parametrize("who", ["app", "system"])
def test_a_retraction_names_a_real_person(owner, world, who):
    from uuid import uuid4
    conn = _runtime(owner, world, who)
    try:
        live = _live_claim(owner, world)
        with pytest.raises(psycopg.errors.RaiseException) as raised:
            conn.execute(
                "UPDATE core.assertion SET retracted_at = now(), retracted_by = %s, "
                "retraction_reason = 'invented' WHERE id = %s", (uuid4(), live))
        assert "person" in str(raised.value)
    finally:
        conn.close()


def test_a_request_role_retracts_as_the_person_signed_in_and_nobody_else(owner, world):
    """The session bound to the connection is the one author a statement of
    that connection may name: another user's id is refused, the signed-in
    person's is not."""
    conn = g.bound(owner, world["analyst"])
    try:
        live = _live_claim(owner, world)
        with pytest.raises(psycopg.errors.RaiseException) as raised:
            conn.execute(
                "UPDATE core.assertion SET retracted_at = now(), retracted_by = %s, "
                "retraction_reason = 'framing the boss' WHERE id = %s",
                (world["boss"], live))
        assert "signed in" in str(raised.value)
        conn.execute(
            "UPDATE core.assertion SET retracted_at = now(), retracted_by = %s, "
            "retraction_reason = 'my own' WHERE id = %s", (world["analyst"], live))
        assert g.one(owner, "SELECT retracted_by FROM core.assertion WHERE id = %s",
                     (live,)) == world["analyst"]
    finally:
        conn.close()


@pytest.mark.parametrize("who", ["app", "system"])
def test_a_runtime_role_cannot_supersede_a_claim_with_one_that_does_not_replace_it(owner, world, who):
    """The verifier's reproduction: `superseded_by` could name a claim on
    another element, the claim itself, or any other claim, hiding a live
    claim with no replacement. It must name the claim whose `supersedes_id`
    points back at this one."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    conn = _runtime(owner, world, who)
    try:
        live = _live_claim(owner, world, "to be hidden")
        same_element = _live_claim(owner, world, "another claim, same element")
        twin = s.node(owner, world["case"], world["boss"], "g43a other element")
        elsewhere = GraphWriteService(owner).add_assertion(
            case_id=world["case"], node_id=twin, assertion=AssertionInput(
                basis="DIRECT_OBSERVATION", created_by=world["boss"],
                reliability="A", credibility="1", confidence="HIGH",
                rationale="on another element"))
        for named in (elsewhere, live, same_element, None):
            with pytest.raises(psycopg.errors.RaiseException) as raised:
                conn.execute(
                    "UPDATE core.assertion SET superseded_at = now(), "
                    "superseded_by = %s WHERE id = %s", (named, live))
            assert "replaces this one" in str(raised.value)
        # a claim that replaces ANOTHER claim is not this claim's replacement
        replaces_other = GraphWriteService(owner).supersede_assertion(
            same_element, case_id=world["case"], observed_at=g.now(),
            rationale="dated", created_by=world["boss"])
        with pytest.raises(psycopg.errors.RaiseException):
            conn.execute("UPDATE core.assertion SET superseded_at = now(), "
                         "superseded_by = %s WHERE id = %s", (replaces_other, live))
        assert g.one(owner, "SELECT superseded_at IS NULL FROM core.assertion "
                            "WHERE id = %s", (live,)) is True
    finally:
        conn.close()


def test_the_schema_owner_is_exempt_from_the_coherence_rules_and_still_held_to_once(owner, world):
    """Repair and seeding run as the owner, which disables the trigger by
    name when it must: the coherence rules are for the runtime roles, the
    once-from-NULL rule is for everyone."""
    live = _live_claim(owner, world)
    other = _live_claim(owner, world, "another live claim")
    owner.execute("UPDATE core.assertion SET retracted_at = now() WHERE id = %s", (live,))
    owner.execute("UPDATE core.assertion SET superseded_at = now(), "
                  "superseded_by = %s WHERE id = %s", (live, other))
    with pytest.raises(psycopg.errors.RaiseException):
        owner.execute("UPDATE core.assertion SET retracted_at = NULL WHERE id = %s",
                      (live,))


def test_truncate_of_the_claims_is_refused(owner, world):
    with pytest.raises(psycopg.errors.RaiseException) as raised:
        with owner.transaction():
            owner.execute("TRUNCATE core.assertion CASCADE")
    assert "never deleted" in str(raised.value)
    assert g.one(owner, "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                 (world["node"],)) == 2


# --- every legitimate write still works -------------------------------------

def test_every_write_path_of_the_graph_works_as_the_request_role(owner, world):
    from noctornal_api.graph import AssertionInput, GraphWriteError, GraphWriteService
    app = g.bound(owner, world["analyst"])
    try:
        svc = GraphWriteService(app)
        analyst = world["analyst"]
        # create: an element and its founding claim
        node = svc.create_node(
            case_id=world["case"], node_type="IDENTITY", label="g43a created",
            created_by=analyst, classification="AMBER",
            assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=analyst))
        # add a claim
        extra = svc.add_assertion(
            case_id=world["case"], node_id=node, assertion=AssertionInput(
                basis="DIRECT_OBSERVATION", created_by=analyst, reliability="B",
                credibility="2", confidence="MODERATE", rationale="second"))
        # correct (a correction is a new claim)
        svc.update_node(node, case_id=world["case"], label="g43a corrected",
                        assertion=AssertionInput(
                            basis="DIRECT_OBSERVATION", created_by=analyst,
                            rationale="a typo", claim_path="label",
                            claim_value={"label": "g43a corrected"}))
        # retract once from NULL; the second is an error, not a rewrite
        svc.retract_assertion(extra, retracted_by=analyst, reason="withdrawn", at=g.now())
        with pytest.raises(GraphWriteError):
            svc.retract_assertion(extra, retracted_by=analyst, reason="again",
                                  at=g.now())
        # supersede once: the 0131 path inserts the copy and stamps the old
        undated = svc.add_assertion(
            case_id=world["case"], node_id=node, assertion=AssertionInput(
                basis="DIRECT_OBSERVATION", created_by=analyst, reliability="A",
                credibility="1", confidence="HIGH", rationale="no date"))
        new = svc.supersede_assertion(
            undated, case_id=world["case"], observed_at=g.now(),
            rationale="dated now", created_by=analyst)
        row = owner.execute(
            "SELECT superseded_at IS NOT NULL, superseded_by FROM core.assertion "
            "WHERE id = %s", (undated,)).fetchone()
        assert row == (True, new)
        assert g.one(owner, "SELECT supersedes_id FROM core.assertion WHERE id = %s",
                     (new,)) == undated
    finally:
        app.close()


def test_a_retraction_and_a_supersession_work_as_the_system_role(owner, world):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    system = g.worker()
    try:
        svc = GraphWriteService(system)
        victim = _live_claim(owner, world, "to be retracted by the system role")
        svc.retract_assertion(victim, retracted_by=world["boss"],
                              reason="swept", at=g.now())
        undated = _live_claim(owner, world, "to be dated by the system role")
        svc.supersede_assertion(undated, case_id=world["case"], observed_at=g.now(),
                                rationale="dated", created_by=world["boss"])
        assert g.one(owner, "SELECT retracted_at IS NOT NULL FROM core.assertion "
                            "WHERE id = %s", (victim,)) is True
        assert g.one(owner, "SELECT superseded_at IS NOT NULL FROM core.assertion "
                            "WHERE id = %s", (undated,)) is True
        # and the claims of a case it did not write can be added to
        svc.add_assertion(case_id=world["case"], node_id=world["node"],
                          assertion=AssertionInput(
                              basis="DIRECT_OBSERVATION", created_by=world["boss"],
                              rationale="from the system role"))
    finally:
        system.close()


def test_a_merge_and_its_reversal_work_as_the_system_role_and_touch_no_claim(owner, world):
    """Merges re-point ties and never write a claim; with the claim columns
    closed to the system role they still run."""
    from noctornal_api.merges import MergeService
    twin = s.node(owner, world["case"], world["boss"], "g43a twin")
    third = s.node(owner, world["case"], world["boss"], "g43a third")
    s.edge(owner, world["case"], world["boss"], twin, third)
    before = owner.execute(
        "SELECT id, retracted_at, superseded_at, rationale FROM core.assertion "
        "WHERE case_id = %s ORDER BY id", (world["case"],)).fetchall()
    system = g.worker()
    try:
        service = MergeService(system)
        merged = service.merge(case_id=world["case"], source_node_id=twin,
                               target_node_id=world["node"], merged_by=world["boss"],
                               reason="the same actor")
        assert merged.edges_repointed == 1
        undone = service.unmerge(merged.id, reversed_by=world["boss"],
                                 reason="not the same actor")
        assert undone.reversed_at is not None
    finally:
        system.close()
    assert owner.execute(
        "SELECT id, retracted_at, superseded_at, rationale FROM core.assertion "
        "WHERE case_id = %s ORDER BY id", (world["case"],)).fetchall() == before


def test_the_http_retract_still_returns_204_for_a_member_and_409_the_second_time(
        owner, world):
    client = g.make_client()
    headers = g.auth(owner, world["analyst"])
    claim = _live_claim(owner, world, "to be withdrawn over HTTP")
    url = f"/api/v1/cases/{world['case']}/assertions/{claim}/retract"
    first = client.post(url, headers=headers, json={"reason": "withdrawn"})
    assert first.status_code == 204, first.text
    second = client.post(url, headers=headers, json={"reason": "again"})
    assert second.status_code == 409, second.text
    assert g.one(owner, "SELECT retraction_reason FROM core.assertion WHERE id = %s",
                 (claim,)) == "withdrawn"


# --- the migration ----------------------------------------------------------

def test_the_migration_names_what_the_runtime_role_keeps():
    m = _migration("0135")
    # follows whatever precedes it in the final chain (0131 when it was
    # written), and 0136 and 0137 follow it
    assert m.down_revision < "0135"
    assert (_migration("0136").down_revision, _migration("0137").down_revision) == (
        "0135", "0136")
    assert m.GUARDED_TABLES == {"core.assertion": ("SELECT", "INSERT")}
    assert set(m.MARK_COLUMNS) == MARKS


def test_the_grants_are_idempotent_and_a_replay_of_0108_is_narrowed_again(owner):
    """`scripts/runtime_roles.py ensure` runs 0108's blanket grant (which
    hands UPDATE and DELETE back on every table) and then this revision's
    GRANTS_SQL. Run twice, in a transaction that is rolled back."""
    m = _migration("0135")
    grants = _migration("0108")
    try:
        with owner.transaction():
            for role in (s.APP_ROLE, s.WORKER_ROLE):
                owner.execute(grants.grants_sql(role))
                assert owner.execute(
                    "SELECT has_table_privilege(%s, 'core.assertion', 'DELETE')",
                    (role,)).fetchone()[0] is True      # what 0108 alone leaves
            owner.execute(m.GRANTS_SQL)
            owner.execute(m.GRANTS_SQL)
            for role in (s.APP_ROLE, s.WORKER_ROLE):
                held = {p: owner.execute(
                    "SELECT has_table_privilege(%s, 'core.assertion', %s)",
                    (role, p)).fetchone()[0] for p in ("UPDATE", "DELETE")}
                assert held == {"UPDATE": False, "DELETE": False}, (role, held)
                assert owner.execute(
                    "SELECT has_column_privilege(%s, 'core.assertion', "
                    "'retracted_at', 'UPDATE')", (role,)).fetchone()[0] is True
            raise _RollBack
    except _RollBack:
        pass


def test_runtime_roles_ensure_replays_the_grant(owner):
    import sys
    sys.path.insert(0, str(SCRIPTS))
    try:
        import runtime_roles
    finally:
        sys.path.remove(str(SCRIPTS))
    try:
        with owner.transaction():
            assert runtime_roles.ensure(owner) == 0
            for role in (s.APP_ROLE, s.WORKER_ROLE):
                assert owner.execute(
                    "SELECT has_table_privilege(%s, 'core.assertion', 'UPDATE') "
                    "OR has_table_privilege(%s, 'core.assertion', 'DELETE')",
                    (role, role)).fetchone()[0] is False, role
            raise _RollBack
    except _RollBack:
        pass


def test_runtime_roles_finds_the_guard_by_name_so_a_renumbering_cannot_break_the_replay():
    """The verifier's observation: `ensure` named revision 0135 twice, so
    renumbering it when the branches are merged would have broken the
    replay. It loads the guard by its file name and reads the revision
    from it."""
    import sys
    sys.path.insert(0, str(SCRIPTS))
    try:
        import runtime_roles
    finally:
        sys.path.remove(str(SCRIPTS))
    found = runtime_roles._migration_named("assertion_marked_once")
    assert found.revision == _migration("0135").revision
    assert found.GRANTS_SQL == _migration("0135").GRANTS_SQL
    source = (SCRIPTS / "runtime_roles.py").read_text(encoding="utf-8")
    assert '"0135"' not in source


def test_the_migration_round_trips_and_the_downgrade_gives_back_what_0060_left(owner):
    m = _migration("0135")
    names = ("assertion_marked_once", "assertion_never_truncated")
    try:
        with owner.transaction():
            owner.execute(m.UNGRANTS_SQL)
            owner.execute(m.DROP_TRIGGERS_SQL)
            for role in (s.APP_ROLE, s.WORKER_ROLE):
                assert owner.execute(
                    "SELECT has_table_privilege(%s, 'core.assertion', 'UPDATE') "
                    "AND has_table_privilege(%s, 'core.assertion', 'DELETE')",
                    (role, role)).fetchone()[0] is True, role
            assert not owner.execute(
                "SELECT 1 FROM pg_trigger WHERE tgrelid = 'core.assertion'::regclass "
                "AND tgname = ANY(%s)", (list(names),)).fetchall()
            assert not owner.execute(
                "SELECT 1 FROM pg_proc WHERE pronamespace = 'core'::regnamespace "
                "AND proname IN ('assertion_marked_once', 'assertion_kept')"
            ).fetchall()
            # upgrade again
            owner.execute(m.TRIGGERS_SQL)
            owner.execute(m.GRANTS_SQL)
            assert {r[0] for r in owner.execute(
                "SELECT tgname FROM pg_trigger WHERE tgrelid = 'core.assertion'::regclass "
                "AND tgname = ANY(%s)", (list(names),)).fetchall()} == set(names)
            for role in (s.APP_ROLE, s.WORKER_ROLE):
                assert owner.execute(
                    "SELECT has_table_privilege(%s, 'core.assertion', 'UPDATE') "
                    "OR has_table_privilege(%s, 'core.assertion', 'DELETE')",
                    (role, role)).fetchone()[0] is False, role
            raise _RollBack
    except _RollBack:
        pass


def test_the_grants_do_nothing_where_a_runtime_role_does_not_exist(owner):
    """As 0060 and 0108: a development database with no runtime roles
    migrates exactly as before, and the text names no other role."""
    m = _migration("0135")
    assert "pg_roles" in m.GRANTS_SQL and "pg_roles" in m.UNGRANTS_SQL
    assert m.GRANTS_SQL.count("IF EXISTS (SELECT 1 FROM pg_roles") == 1
