"""A claim is recorded live, as the user its connection is bound to, at the
database's time (graph-assertion-insert-unguarded, verifier N3, 2026-10-07,
migration 0171).

0135 closed UPDATE, DELETE and TRUNCATE on `core.assertion` to the runtime
roles. INSERT stayed open and nothing looked at what an INSERT named: bound
to an AMBER analyst as `noctornal_app`, one statement each forged a claim
authored by another user, backdated a claim 400 days, inserted a claim
already retracted with no author and no reason, and inserted a claim
already superseded.

What these tests hold, in both directions:

- the four forgeries are refused (or, for the date, overridden), as the
  request role bound to the analyst; so is every one of the five mark
  columns on its own, a connection bound to nobody and a connection whose
  user was deactivated after it was bound;
- `recorded_at` is the database's clock at the moment of the INSERT, and not
  the start of a transaction a caller holds open;
- every legitimate writer still works as the request role: create, add a
  claim, correct, retract, supersede, the accept of a machine proposal
  (service and HTTP), and the HTTP routes of the same;
- the machine path writes no claim at all until an analyst accepts;
- the owner and the system role are exempt exactly as 0150 exempts them
  from the audit log's attribution rule, and keep their control;
- the migration is one revision after 0170, one head, the function is a
  pinned definer that fires first, and the pair goes down and up again.

Email prefix `g55a-`. Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE.
"""
from __future__ import annotations

import importlib.util
from datetime import timedelta
from pathlib import Path

import psycopg
import pytest
import review_graph_support as g
import rls_support as s

pytestmark = s.GATED

PREFIX = "g55a-"
ROOT = Path(__file__).resolve().parents[3]
VERSIONS = ROOT / "db" / "migrations" / "versions"

#: The marker every claim a forger writes carries, so a count says whether one
#: got in.
FORGED = "g55a forged"

#: What each mark column is given when it is the only one set.
MARKS = ("retracted_at", "retracted_by", "retraction_reason",
         "superseded_at", "superseded_by")


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
    """A case with an owner, an AMBER analyst and an AMBER reviewer
    (accepting a proposal needs `proposal.review`, which an ANALYST lacks), one entity with its founding claim and a
    live second claim the forgeries can name."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    boss = s.user(owner, "RED", prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    reviewer = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, boss, "CASE_OWNER")
    s.assign(owner, case_id, analyst, "ANALYST")
    s.assign(owner, case_id, reviewer, "REVIEWER")
    node = s.node(owner, case_id, boss, "g55a entity")
    live = GraphWriteService(owner).add_assertion(
        case_id=case_id, node_id=node, assertion=AssertionInput(
            basis="DIRECT_OBSERVATION", created_by=boss, reliability="A",
            credibility="1", confidence="HIGH", rationale="a live claim"))
    return {"case": case_id, "boss": boss, "analyst": analyst,
            "reviewer": reviewer, "node": node, "live": live}


def _insert(conn, world, created_by, **extra):
    """One claim, with whatever columns `extra` adds, as `conn`. Returns its id."""
    cols = {"case_id": world["case"], "node_id": world["node"],
            "created_by": created_by, "basis": "DIRECT_OBSERVATION",
            "reliability": "A", "credibility": "1", "confidence": "HIGH",
            "rationale": FORGED, **extra}
    return conn.execute(
        f"INSERT INTO core.assertion ({', '.join(cols)}) "
        f"VALUES ({', '.join(['%s'] * len(cols))}) RETURNING id",
        list(cols.values())).fetchone()[0]


def _forged_rows(owner, world) -> int:
    return g.one(owner, "SELECT count(*) FROM core.assertion "
                        "WHERE case_id = %s AND rationale = %s",
                 (world["case"], FORGED))


def _clock(owner):
    return owner.execute("SELECT clock_timestamp()").fetchone()[0]


# --- the verifier's four forgeries ------------------------------------------

def test_a_claim_cannot_be_attributed_to_another_user(owner, world):
    """Forgery 1: `created_by` is a user the connection is not bound to."""
    app = g.bound(owner, world["analyst"])
    try:
        assert app.execute("SELECT current_user").fetchone()[0] == s.APP_ROLE
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as raised:
            _insert(app, world, world["boss"])
        assert "may not attribute a claim to another" in str(raised.value)
    finally:
        app.close()
    assert _forged_rows(owner, world) == 0


def test_a_backdated_claim_is_dated_by_the_database_not_the_statement(owner, world):
    """Forgery 2: `recorded_at` 400 days in the past (and, as the same hole,
    400 days ahead). The row is written and the date is the database's."""
    app = g.bound(owner, world["analyst"])
    try:
        before = _clock(owner)
        ids = [_insert(app, world, world["analyst"],
                       recorded_at=s.now() - timedelta(days=400)),
               _insert(app, world, world["analyst"],
                       recorded_at=s.now() + timedelta(days=400)),
               _insert(app, world, world["analyst"])]
        after = _clock(owner)
    finally:
        app.close()
    for claim in ids:
        recorded = g.one(owner, "SELECT recorded_at FROM core.assertion WHERE id = %s",
                         (claim,))
        assert before <= recorded <= after, (claim, before, recorded, after)


def test_a_claim_cannot_be_inserted_already_retracted(owner, world):
    """Forgery 3: `retracted_at` set, with no author and no reason."""
    app = g.bound(owner, world["analyst"])
    try:
        with pytest.raises(psycopg.errors.RaiseException) as raised:
            _insert(app, world, world["analyst"], retracted_at=s.now())
        assert "recorded live" in str(raised.value)
    finally:
        app.close()
    assert _forged_rows(owner, world) == 0


def test_a_claim_cannot_be_inserted_already_superseded(owner, world):
    """Forgery 4: `superseded_at` and `superseded_by` set, naming a claim."""
    app = g.bound(owner, world["analyst"])
    try:
        with pytest.raises(psycopg.errors.RaiseException) as raised:
            _insert(app, world, world["analyst"], superseded_at=s.now(),
                    superseded_by=world["live"])
        assert "recorded live" in str(raised.value)
    finally:
        app.close()
    assert _forged_rows(owner, world) == 0


@pytest.mark.parametrize("column", MARKS)
def test_no_mark_column_can_be_set_on_insert_on_its_own(owner, world, column):
    """The guard is on every mark, not on the ones the verifier tried."""
    given = {"retracted_at": s.now(), "retracted_by": world["analyst"],
             "retraction_reason": "withdrawn before it was made",
             "superseded_at": s.now(), "superseded_by": world["live"]}
    app = g.bound(owner, world["analyst"])
    try:
        with pytest.raises(psycopg.errors.RaiseException) as raised:
            _insert(app, world, world["analyst"], **{column: given[column]})
        assert "recorded live" in str(raised.value)
    finally:
        app.close()
    assert _forged_rows(owner, world) == 0


def test_a_forgery_that_is_several_at_once_is_refused_whole(owner, world):
    app = g.bound(owner, world["analyst"])
    try:
        with pytest.raises(psycopg.errors.RaiseException) as raised:
            _insert(app, world, world["boss"], retracted_at=s.now(),
                    retracted_by=world["boss"], retraction_reason="framed",
                    recorded_at=s.now() - timedelta(days=400))
        assert "recorded live" in str(raised.value)
    finally:
        app.close()
    assert _forged_rows(owner, world) == 0


# --- a connection that is bound to nobody -----------------------------------

def test_a_connection_bound_to_nobody_records_no_claim(owner, world):
    """0150 demotes an audit row it cannot attribute; a claim's author is
    NOT NULL and there is nothing to demote it to. The refusal is the
    trigger's own, not a side effect of the case gate."""
    app = s.app_conn()
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as raised:
            _insert(app, world, world["analyst"])
        assert "bound to nobody" in str(raised.value)
    finally:
        app.close()
    assert _forged_rows(owner, world) == 0


def test_a_user_deactivated_after_binding_records_no_claim(owner, world):
    """`iam.rls_actor()` binds only an active account, so the connection is
    bound to nobody the moment the account is switched off."""
    app = g.bound(owner, world["analyst"])
    try:
        _insert(app, world, world["analyst"], rationale="written while active")
        owner.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s",
                      (world["analyst"],))
        with pytest.raises(psycopg.errors.InsufficientPrivilege) as raised:
            _insert(app, world, world["analyst"])
        assert "bound to nobody" in str(raised.value)
    finally:
        app.close()
    assert _forged_rows(owner, world) == 0


# --- the time ---------------------------------------------------------------

def test_a_transaction_held_open_does_not_date_its_claims_by_its_start(owner, world):
    """`now()` is the start of the caller's transaction, and the request role
    chooses how long one lasts. The claim is dated when it is inserted."""
    app = g.bound(owner, world["analyst"])
    try:
        with app.transaction():
            started = app.execute("SELECT now()").fetchone()[0]
            app.execute("SELECT pg_sleep(1.5)")
            claim = _insert(app, world, world["analyst"], rationale="held open")
    finally:
        app.close()
    recorded = g.one(owner, "SELECT recorded_at FROM core.assertion WHERE id = %s",
                     (claim,))
    assert recorded - started >= timedelta(seconds=1.4), (started, recorded)


def test_claims_recorded_in_one_transaction_are_in_the_order_written(owner, world):
    app = g.bound(owner, world["analyst"])
    try:
        with app.transaction():
            first = _insert(app, world, world["analyst"], rationale="first")
            second = _insert(app, world, world["analyst"], rationale="second")
    finally:
        app.close()
    first_at, second_at = (g.one(
        owner, "SELECT recorded_at FROM core.assertion WHERE id = %s", (c,))
        for c in (first, second))
    assert first_at < second_at


# --- every legitimate writer still works ------------------------------------

def test_every_write_path_of_the_graph_still_works_as_the_request_role(owner, world):
    from noctornal_api.graph import AssertionInput, GraphWriteError, GraphWriteService
    analyst = world["analyst"]
    app = g.bound(owner, analyst)
    try:
        svc = GraphWriteService(app)
        before = _clock(owner)
        node = svc.create_node(
            case_id=world["case"], node_type="IDENTITY", label="g55a created",
            created_by=analyst, classification="AMBER",
            assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=analyst))
        extra = svc.add_assertion(
            case_id=world["case"], node_id=node, assertion=AssertionInput(
                basis="DIRECT_OBSERVATION", created_by=analyst, reliability="B",
                credibility="2", confidence="MODERATE", rationale="second"))
        svc.update_node(node, case_id=world["case"], label="g55a corrected",
                        assertion=AssertionInput(
                            basis="DIRECT_OBSERVATION", created_by=analyst,
                            rationale="a typo", claim_path="label",
                            claim_value={"label": "g55a corrected"}))
        other = s.node(owner, world["case"], world["boss"], "g55a other")
        tie = svc.create_edge(
            case_id=world["case"], edge_type="VOUCHED_FOR", src_node_id=node,
            dst_node_id=other, created_by=analyst, classification="AMBER",
            assertion=AssertionInput(basis="DIRECT_OBSERVATION",
                                     created_by=analyst, rationale="vouched"))
        undated = svc.add_assertion(
            case_id=world["case"], node_id=node, assertion=AssertionInput(
                basis="DIRECT_OBSERVATION", created_by=analyst, reliability="A",
                credibility="1", confidence="HIGH", rationale="no date"))
        dated = svc.supersede_assertion(
            undated, case_id=world["case"], observed_at=g.now(),
            rationale="dated now", created_by=analyst)
        svc.retract_assertion(extra, retracted_by=analyst, reason="withdrawn",
                              at=g.now())
        with pytest.raises(GraphWriteError):
            svc.retract_assertion(extra, retracted_by=analyst, reason="again",
                                  at=g.now())
        after = _clock(owner)
    finally:
        app.close()
    rows = owner.execute(
        """SELECT created_by, recorded_at FROM core.assertion
            WHERE node_id = %s OR edge_id = %s""", (node, tie)).fetchall()
    assert len(rows) >= 6
    for created_by, recorded in rows:
        assert created_by == analyst
        assert before <= recorded <= after
    assert g.one(owner, "SELECT supersedes_id FROM core.assertion WHERE id = %s",
                 (dated,)) == undated
    assert g.one(owner, "SELECT retracted_by FROM core.assertion WHERE id = %s",
                 (extra,)) == analyst


def test_a_machine_proposal_writes_no_claim_until_an_analyst_accepts_it(owner, world):
    """The machine path: an extractor writes `collect.proposal` and never a
    claim (invariant 3). The claim exists only at the accept, authored by the
    analyst who accepted, as the request role bound to them."""
    from noctornal_api.proposals import ProposalReview, ProposalStore
    claims = "SELECT count(*) FROM core.assertion WHERE case_id = %s"
    start = g.one(owner, claims, (world["case"],))
    machine = g.worker()
    try:
        pid = ProposalStore(machine).propose(
            case_id=world["case"], kind="NODE",
            payload={"node_type": "IDENTITY", "label": "g55a suggested"},
            origin="g55a_test_v1", rationale="raised by the insert guard test",
            score=0.5)
    finally:
        machine.close()
    assert g.one(owner, claims, (world["case"],)) == start, \
        "proposing must not record a claim"
    app = g.bound(owner, world["analyst"])
    try:
        accepted = ProposalReview(app).accept(pid, reviewed_by=world["analyst"])
    finally:
        app.close()
    node_id = accepted.applied_node_id
    row = owner.execute(
        "SELECT created_by, basis::text, recorded_at IS NOT NULL FROM core.assertion "
        "WHERE node_id = %s", (node_id,)).fetchone()
    assert row == (world["analyst"], "AUTOMATED_INFERENCE", True)
    assert g.one(owner, claims, (world["case"],)) == start + 1


def test_an_accept_that_names_another_reviewer_is_refused_and_writes_nothing(owner, world):
    """The same accept with `reviewed_by` set to somebody else is the forgery
    in application clothes: the database refuses it and the proposal stays
    in the queue."""
    from noctornal_api.proposals import ProposalError, ProposalReview, ProposalStore
    machine = g.worker()
    try:
        pid = ProposalStore(machine).propose(
            case_id=world["case"], kind="NODE",
            payload={"node_type": "IDENTITY", "label": "g55a not accepted"},
            origin="g55a_test_v1", rationale="raised by the insert guard test",
            score=0.5)
    finally:
        machine.close()
    app = g.bound(owner, world["analyst"])
    try:
        # The claim is written before the accept's own audit row, which the
        # audit log's attribution rule (0150) would also refuse: the cause
        # says which trigger it was.
        with pytest.raises(ProposalError) as raised:
            ProposalReview(app).accept(pid, reviewed_by=world["boss"])
        cause = raised.value
        while cause.__cause__ is not None:
            cause = cause.__cause__
        assert isinstance(cause, psycopg.errors.InsufficientPrivilege), cause
        assert "attribute a claim to another" in str(cause)
    finally:
        app.close()
    assert g.one(owner, "SELECT state FROM collect.proposal WHERE id = %s",
                 (pid,)) == "PROPOSED"
    assert g.one(owner, "SELECT count(*) FROM core.node WHERE case_id = %s "
                        "AND label = 'g55a not accepted'", (world["case"],)) == 0


def test_the_http_routes_still_write_claims_in_the_request_roles_posture(owner, world):
    """The suite's other HTTP tests run as the owner, which the trigger
    leaves alone; `owner` here sets the assume-role switch, so every request
    connection is `noctornal_app` bound to the session's user."""
    client = g.make_client()
    headers = g.auth(owner, world["analyst"])
    base = f"/api/v1/cases/{world['case']}"
    made = client.post(f"{base}/nodes/{world['node']}/assertions", headers=headers,
                       json=g.grade("added over HTTP"))
    assert made.status_code == 201, made.text
    claim = made.json()["id"]
    assert owner.execute(
        "SELECT created_by FROM core.assertion WHERE id = %s", (claim,)
    ).fetchone()[0] == world["analyst"]
    dated = client.post(f"{base}/assertions/{claim}/supersede", headers=headers,
                        json={"observed_at": g.now().isoformat(),
                              "rationale": "dated over HTTP"})
    assert dated.status_code == 201, dated.text
    successor = dated.json()["id"]
    assert owner.execute(
        "SELECT created_by FROM core.assertion WHERE id = %s", (successor,)
    ).fetchone()[0] == world["analyst"]
    gone = client.post(f"{base}/assertions/{successor}/retract", headers=headers,
                       json={"reason": "withdrawn over HTTP"})
    assert gone.status_code == 204, gone.text
    assert owner.execute(
        "SELECT retracted_by FROM core.assertion WHERE id = %s", (successor,)
    ).fetchone()[0] == world["analyst"]
    created = client.post(
        f"{base}/nodes", headers=headers,
        json={"node_type": "IDENTITY", "label": "g55a over http",
              "classification": "AMBER", "assertion": g.grade("founding claim")})
    assert created.status_code == 201, created.text


def test_accepting_a_proposal_over_http_still_works_in_the_request_roles_posture(
        owner, world):
    from noctornal_api.proposals import ProposalStore
    machine = g.worker()
    try:
        pid = ProposalStore(machine).propose(
            case_id=world["case"], kind="NODE",
            payload={"node_type": "IDENTITY", "label": "g55a accepted over http"},
            origin="g55a_test_v1", rationale="raised by the insert guard test",
            score=0.5)
    finally:
        machine.close()
    client = g.make_client()
    done = client.post(
        f"/api/v1/cases/{world['case']}/proposals/{pid}/accept",
        headers=g.auth(owner, world["reviewer"]), json={})
    assert done.status_code == 200, done.text
    assert g.one(owner, "SELECT created_by FROM core.assertion WHERE node_id = %s",
                 (done.json()["applied_node_id"],)) == world["reviewer"]


# --- the roles the trigger leaves alone -------------------------------------

def test_the_system_role_keeps_its_control_of_attribution_time_and_marks(owner, world):
    """The system role writes on behalf of people it has authenticated by
    other means (the seeders), so it is exempt as 0150 exempts it: another
    user as the author, a date of its own, a claim already marked. This is
    the residual the migration documents."""
    system = g.worker()
    try:
        assert system.execute("SELECT current_user").fetchone()[0] == s.WORKER_ROLE
        named = _insert(system, world, world["boss"], rationale="by the system role")
        dated = _insert(system, world, world["analyst"], rationale="dated by it",
                        recorded_at=s.now() - timedelta(days=400))
        marked = _insert(system, world, world["boss"], rationale="already marked",
                         retracted_at=s.now(), retracted_by=world["boss"],
                         retraction_reason="seeded as withdrawn")
    finally:
        system.close()
    assert g.one(owner, "SELECT created_by FROM core.assertion WHERE id = %s",
                 (named,)) == world["boss"]
    assert g.one(owner, "SELECT recorded_at < now() - interval '300 days' "
                        "FROM core.assertion WHERE id = %s", (dated,)) is True
    assert g.one(owner, "SELECT retracted_at IS NOT NULL FROM core.assertion "
                        "WHERE id = %s", (marked,)) is True


def test_the_owner_keeps_full_control_of_the_table(owner, world):
    """Migrations, restores and the suite's seeding run as the owner."""
    named = _insert(owner, world, world["boss"], rationale="by the owner")
    dated = _insert(owner, world, world["analyst"], rationale="restored",
                    recorded_at=s.now() - timedelta(days=400))
    marked = _insert(owner, world, world["boss"], rationale="restored marked",
                     superseded_at=s.now(), superseded_by=world["live"])
    assert g.one(owner, "SELECT created_by FROM core.assertion WHERE id = %s",
                 (named,)) == world["boss"]
    assert g.one(owner, "SELECT recorded_at < now() - interval '300 days' "
                        "FROM core.assertion WHERE id = %s", (dated,)) is True
    assert g.one(owner, "SELECT superseded_by FROM core.assertion WHERE id = %s",
                 (marked,)) == world["live"]


# --- the migration ----------------------------------------------------------

def test_the_migration_is_one_revision_after_0170_and_the_chain_has_one_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    m = _migration("0171")
    assert (m.revision, m.down_revision) == ("0171", "0170")
    cfg = Config()
    cfg.set_main_option("script_location", str(ROOT / "db" / "migrations"))
    heads = ScriptDirectory.from_config(cfg).get_heads()
    assert len(heads) == 1, heads


def test_the_function_is_a_pinned_definer_and_fires_before_the_other_insert_trigger(owner):
    definer, config = owner.execute(
        """SELECT prosecdef, coalesce(proconfig, '{}')
             FROM pg_proc
            WHERE oid = 'core.assertion_insert_guard()'::regprocedure""").fetchone()
    assert definer, "core.assertion_insert_guard must be SECURITY DEFINER"
    paths = [c for c in config if c.startswith("search_path=")]
    assert paths, "no pinned search_path"
    names = [n.strip() for n in paths[0].split("=", 1)[1].split(",")]
    assert names[0] == "pg_catalog" and names[-1] == "pg_temp", names
    before_insert = [r[0] for r in owner.execute(
        """SELECT tgname FROM pg_trigger
            WHERE tgrelid = 'core.assertion'::regclass AND NOT tgisinternal
              AND (tgtype & 2) = 2 AND (tgtype & 4) = 4 AND (tgtype & 1) = 1
            ORDER BY tgname""").fetchall()]
    assert before_insert == ["assertion_insert_guarded",
                             "assertion_supersedes_guarded"], before_insert


def _state(conn) -> dict:
    return {
        "function": conn.execute(
            "SELECT to_regprocedure('core.assertion_insert_guard()')").fetchone()[0],
        "trigger": [r[0] for r in conn.execute(
            """SELECT pg_get_triggerdef(oid) FROM pg_trigger
                WHERE tgrelid = 'core.assertion'::regclass AND NOT tgisinternal
                  AND tgname = 'assertion_insert_guarded'""").fetchall()],
        "all_triggers": [r[0] for r in conn.execute(
            """SELECT tgname FROM pg_trigger
                WHERE tgrelid = 'core.assertion'::regclass AND NOT tgisinternal
                ORDER BY tgname""").fetchall()],
    }


def test_the_migration_goes_down_and_up_again_and_the_trigger_is_what_refuses(owner, world):
    """In a transaction that is rolled back: downgrade removes the guard (and
    the forgeries succeed again, so it is the guard that refuses them),
    upgrade restores exactly what was there, twice."""
    m = _migration("0171")
    before = _state(owner)
    assert before["trigger"], "0171 is not applied on this database"
    analyst = world["analyst"]
    app = g.bound(owner, analyst)
    try:
        with pytest.raises(_RollBack):
            with app.transaction():
                for _ in range(2):
                    app.execute("RESET ROLE")
                    app.execute(m.DOWNGRADE_SQL)
                    down = _state(app)
                    assert down["function"] is None and not down["trigger"]
                    assert down["all_triggers"] == [
                        t for t in before["all_triggers"]
                        if t != "assertion_insert_guarded"]
                    app.execute(f"SET ROLE {s.APP_ROLE}")
                    # The forgeries land (the transaction is rolled back below).
                    assert _insert(app, world, world["boss"], retracted_at=s.now(),
                                   recorded_at=s.now() - timedelta(days=400))
                    app.execute("RESET ROLE")
                    app.execute(m.UPGRADE_SQL)
                    assert _state(app) == before
                    app.execute(f"SET ROLE {s.APP_ROLE}")
                    with pytest.raises(psycopg.errors.InsufficientPrivilege):
                        with app.transaction():   # a savepoint
                            _insert(app, world, world["boss"])
                raise _RollBack
    finally:
        app.close()
    assert _state(owner) == before
