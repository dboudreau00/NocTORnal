"""A tie's review state: born right, and a person can move it.

gap-tie-review and ux05 review-state-never-leaves-proposed (2026-09-23).
`core.edge.review` defaulted to PROPOSED and no statement in the API ever
set it, so every tie in every case read "review PROPOSED": an analyst's
own direct observation, a suggestion already accepted in Triage, all of
them. The canvas rang every node and the inspector's "Unreviewed
proposals" always equalled "Ties in projection", a signal that could never
clear and so carried no information.

Held here:

- a tie a person asserts is born ACCEPTED, one founded on a machine's
  claim (AUTOMATED_INFERENCE) is born PROPOSED, and a Triage acceptance is
  born ACCEPTED although its claim keeps the machine's basis;
- `POST .../graph/edges/{id}/review` moves it, audited (EDGE_REVIEWED with
  the state left and the note, in the same transaction), and the projection
  the canvas rings from reads the new state;
- what it refuses: REJECTED and SUPERSEDED, a dispute or reopening with no
  note, the state the tie is already in (with no audit row), a retired tie,
  another case's tie, a caller without `proposal.review` (the ANALYST), and
  a caller below the tie's own label;
- `GET .../review` reads the decision back, and hides a tie above the
  caller's clearance behind the same 404 as a missing one;
- migration 0067's statement gives the ties entered before Alpha 6 (all
  PROPOSED) the state the same rule would have given them, audited,
  leaving a machine's unaccepted tie and anything a person has reviewed
  alone, and the Review history names it rather than "unknown". It began
  as an upgrade-kit file for operators to run by hand; an upgrade that
  forgot it rang every node, so the migration runs it.

Every test that exercises the route or the born state fails on 245cb57.
Email prefix `trev-`, unique to this file. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; tie review test is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "trev-"

#: Every write here carries its whole grading: the API is moving to refuse
#: a claim whose grading is left to defaults (gap-api-grade-required).
GRADED = {"basis": "DIRECT_OBSERVATION", "reliability": "B",
          "credibility": "2", "confidence": "MODERATE"}


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    # One transaction: the deferred invariant-1 triggers fire at commit, so
    # assertions and their elements must go together. audit.event is
    # append-only and left alone.
    with c.transaction():
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
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


def _user(conn, clearance, name="Trev"):
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{PREFIX}{uuid4().hex[:8]}@noctornal.test", name, "x" * 20)
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    return uid


def _auth(conn, uid) -> dict:
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return {"Authorization": f"Bearer {token}"}


def _assign(conn, case_id, uid, role, owner):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, uid, role, owner))


@pytest.fixture
def world(conn):
    """A RED Lead investigator's AMBER case holding two personas and an
    AMBER tie between them, plus an AMBER REVIEWER and an AMBER ANALYST."""
    from noctornal_api.cases import CaseService
    from noctornal_api.graph import AssertionInput, GraphWriteService
    owner = _user(conn, "RED", "Trev Owner")
    reviewer = _user(conn, "AMBER", "Trev Reviewer")
    analyst = _user(conn, "AMBER", "Trev Analyst")
    future = date(2028, 1, 1)
    case_id = CaseService(conn).create(
        code=f"OP-TREV-{uuid4().hex[:6]}", title="Tie review",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=owner,
        created_by=owner, classification="AMBER")
    _assign(conn, case_id, reviewer, "REVIEWER", owner)
    _assign(conn, case_id, analyst, "ANALYST", owner)
    g = GraphWriteService(conn)
    a = AssertionInput(created_by=owner, **GRADED)
    src = g.create_node(case_id=case_id, node_type="IDENTITY",
                        label="trev_src", created_by=owner, assertion=a)
    dst = g.create_node(case_id=case_id, node_type="IDENTITY",
                        label="trev_dst", created_by=owner, assertion=a)
    return {"case": case_id, "owner": owner, "reviewer": reviewer,
            "analyst": analyst, "src": src, "dst": dst, "g": g, "a": a}


def _tie(w, *, basis="DIRECT_OBSERVATION", classification="AMBER",
         edge_type="COMMUNICATES_WITH", **kw):
    from dataclasses import replace
    rationale = "the collector matched them" if basis.endswith("INFERENCE") else None
    return w["g"].create_edge(
        case_id=w["case"], edge_type=edge_type, src_node_id=w["src"],
        dst_node_id=w["dst"], created_by=w["owner"],
        assertion=replace(w["a"], basis=basis, rationale=rationale),
        classification=classification, **kw)


def _review_col(conn, edge_id) -> str:
    return conn.execute("SELECT review::text FROM core.edge WHERE id = %s",
                        (edge_id,)).fetchone()[0]


def _review(client, conn, w, edge_id, body, who="owner", case_id=None):
    return client.post(
        f"/api/v1/cases/{case_id or w['case']}/graph/edges/{edge_id}/review",
        headers=_auth(conn, w[who]), json=body)


def _audits(conn, edge_id) -> list:
    return [r[0] for r in conn.execute(
        """SELECT detail FROM audit.event
            WHERE action = 'EDGE_REVIEWED' AND object_id = %s
            ORDER BY seq""", (edge_id,)).fetchall()]


# ---------------------------------------------------------------------------
# Born in the right state
# ---------------------------------------------------------------------------

def test_a_tie_a_person_asserts_is_born_accepted(conn, client, world):
    """Over HTTP, the route the Link form posts to."""
    w = world
    r = client.post(f"/api/v1/cases/{w['case']}/edges",
                    headers=_auth(conn, w["owner"]),
                    json={"edge_type": "VOUCHED_FOR",
                          "src_node_id": str(w["src"]),
                          "dst_node_id": str(w["dst"]), "assertion": GRADED})
    assert r.status_code == 201, r.text
    assert _review_col(conn, r.json()["id"]) == "ACCEPTED"


def test_a_tie_founded_on_a_machines_claim_is_born_proposed(conn, world):
    """Machines propose, analysts dispose: AUTOMATED_INFERENCE waits for a
    person, whoever typed it in."""
    assert _review_col(conn, _tie(world, basis="AUTOMATED_INFERENCE")) == "PROPOSED"
    assert _review_col(conn, _tie(world, basis="ANALYST_INFERENCE",
                                  edge_type="VOUCHED_FOR")) == "ACCEPTED", (
        "an analyst's own inference is their assertion, not a proposal")


def test_a_triage_acceptance_is_born_accepted(conn, client, world):
    """The claim keeps the machine's basis on purpose (docs/03), so the
    acceptance has to say it was disposed of, or the tie is ringed as
    awaiting the review the click has just given it."""
    from noctornal_api.proposals import ProposalStore
    w = world
    pid = ProposalStore(conn).propose(
        case_id=w["case"], kind="EDGE", origin="trev_test_v1",
        payload={"edge_type": "COMMUNICATES_WITH",
                 "src_node_id": str(w["src"]), "dst_node_id": str(w["dst"])},
        rationale="raised by the tie review test", score=0.5)
    r = client.post(f"/api/v1/cases/{w['case']}/proposals/{pid}/accept",
                    headers=_auth(conn, w["reviewer"]), json={})
    assert r.status_code == 200, r.text
    edge_id = r.json()["applied_edge_id"]
    assert _review_col(conn, edge_id) == "ACCEPTED"
    basis = conn.execute("SELECT basis::text FROM core.assertion WHERE edge_id = %s",
                         (edge_id,)).fetchone()[0]
    assert basis == "AUTOMATED_INFERENCE", "the machine's basis is kept"

    got = client.get(f"/api/v1/cases/{w['case']}/graph/edges/{edge_id}/review",
                     headers=_auth(conn, w["reviewer"])).json()
    assert got["accepted_from_triage_by"] == "Trev Reviewer"
    assert got["accepted_from_triage_at"]


def test_the_service_refuses_a_state_nobody_may_be_born_in(world):
    from noctornal_api.graph import GraphWriteError
    with pytest.raises(GraphWriteError):
        _tie(world, review="REJECTED")


# ---------------------------------------------------------------------------
# Moving it
# ---------------------------------------------------------------------------

def test_accepting_a_proposed_tie_is_recorded_and_read_back(conn, client, world):
    w = world
    tie = _tie(w, basis="AUTOMATED_INFERENCE")
    r = _review(client, conn, w, tie, {"review": "ACCEPTED",
                                       "note": "two captures agree"},
                who="reviewer")
    assert r.status_code == 200, r.text
    assert r.json() == {"edge_id": str(tie), "review": "ACCEPTED",
                        "previous": "PROPOSED"}
    assert _review_col(conn, tie) == "ACCEPTED"
    assert _audits(conn, tie) == [{"review": "ACCEPTED", "previous": "PROPOSED",
                                   "note": "two captures agree"}]

    got = client.get(f"/api/v1/cases/{w['case']}/graph/edges/{tie}/review",
                     headers=_auth(conn, w["analyst"]))
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["review"] == "ACCEPTED"
    assert body["created_by_name"] == "Trev Owner"
    assert [(h["review"], h["previous"], h["note"], h["by_name"])
            for h in body["history"]] == [
        ("ACCEPTED", "PROPOSED", "two captures agree", "Trev Reviewer")]


def test_the_projection_the_canvas_rings_from_follows_the_review(conn, client, world):
    """The ring and the inspector's count come from `review` on the
    projection's edges (`indexProjection`), so the projection must read the
    column the review wrote, and the case's tie list with it."""
    w = world
    tie = _tie(w, basis="AUTOMATED_INFERENCE")
    headers = _auth(conn, w["owner"])

    def seen():
        g = client.get(f"/api/v1/cases/{w['case']}/graph", headers=headers).json()
        e = client.get(f"/api/v1/cases/{w['case']}/edges", headers=headers).json()
        return ({x["id"]: x["review"] for x in g["edges"]}.get(str(tie)),
                {x["id"]: x["review"] for x in e}.get(str(tie)))

    assert seen() == ("PROPOSED", "PROPOSED")
    assert _review(client, conn, w, tie, {"review": "DISPUTED",
                                          "note": "the handle is reused"}
                   ).status_code == 200
    assert seen() == ("DISPUTED", "DISPUTED")
    assert _review(client, conn, w, tie, {"review": "PROPOSED",
                                          "note": "a new capture came in"}
                   ).status_code == 200
    assert seen() == ("PROPOSED", "PROPOSED")


@pytest.mark.parametrize("state", ["DISPUTED", "PROPOSED"])
def test_a_dispute_or_a_reopening_needs_a_note(conn, client, world, state):
    w = world
    tie = _tie(w)            # born ACCEPTED, so PROPOSED is a reopening
    for note in (None, "   "):
        r = _review(client, conn, w, tie, {"review": state, "note": note})
        assert r.status_code == 400, r.text
        assert "needs a note" in r.json()["detail"]
    assert _review_col(conn, tie) == "ACCEPTED"
    assert _audits(conn, tie) == []


@pytest.mark.parametrize("state", ["REJECTED", "SUPERSEDED", "maybe"])
def test_states_a_reviewer_does_not_set_are_refused_with_the_remedy(
        conn, client, world, state):
    w = world
    tie = _tie(w, basis="AUTOMATED_INFERENCE")
    r = _review(client, conn, w, tie, {"review": state, "note": "no"})
    assert r.status_code == 400, r.text
    assert "retired" in r.json()["detail"], "the refusal names the remedy"
    assert _review_col(conn, tie) == "PROPOSED"


def test_the_state_a_tie_is_already_in_is_a_409_with_no_audit_row(
        conn, client, world):
    """A double click is not a second decision."""
    w = world
    tie = _tie(w)
    r = _review(client, conn, w, tie, {"review": "accepted"})
    assert r.status_code == 409, r.text
    assert "already ACCEPTED" in r.json()["detail"]
    assert _audits(conn, tie) == []


def test_a_retired_tie_is_not_reviewed(conn, client, world):
    from datetime import datetime, timezone
    w = world
    tie = _tie(w, basis="AUTOMATED_INFERENCE")
    w["g"].soft_delete_edge(tie, case_id=w["case"], deleted_by=w["owner"],
                            at=datetime.now(timezone.utc))
    r = _review(client, conn, w, tie, {"review": "ACCEPTED"})
    assert r.status_code == 409, r.text
    assert _review_col(conn, tie) == "PROPOSED"


# ---------------------------------------------------------------------------
# Who may
# ---------------------------------------------------------------------------

def test_an_analyst_without_the_verb_is_refused(conn, client, world):
    """The owner's decision: `proposal.review`, which the Lead investigator
    and the REVIEWER hold and the ANALYST does not."""
    w = world
    tie = _tie(w, basis="AUTOMATED_INFERENCE")
    r = _review(client, conn, w, tie, {"review": "ACCEPTED"}, who="analyst")
    assert r.status_code == 403, r.text
    assert _review_col(conn, tie) == "PROPOSED"
    assert _audits(conn, tie) == []


def test_another_cases_tie_is_the_same_404_as_a_missing_one(conn, client, world):
    from noctornal_api.cases import CaseService
    w = world
    tie = _tie(w, basis="AUTOMATED_INFERENCE")
    future = date(2028, 1, 1)
    other = CaseService(conn).create(
        code=f"OP-TREV-{uuid4().hex[:6]}", title="Another",
        legal_basis="production order", retention_until=future,
        review_due=future - timedelta(days=1), owner_user_id=w["owner"],
        created_by=w["owner"], classification="AMBER")
    through_other = _review(client, conn, w, tie, {"review": "ACCEPTED"},
                            case_id=other)
    missing = _review(client, conn, w, uuid4(), {"review": "ACCEPTED"},
                      case_id=other)
    assert through_other.status_code == missing.status_code == 404
    assert through_other.json()["detail"] == missing.json()["detail"]
    assert _review_col(conn, tie) == "PROPOSED"


def test_a_tie_above_the_callers_clearance_is_refused_and_unreadable(
        conn, client, world):
    """CR7: the tie's own label gates the review, not only the case's; and
    its review record is a 404 to a reader who cannot see it."""
    w = world
    red = _tie(w, basis="AUTOMATED_INFERENCE", classification="RED")
    r = _review(client, conn, w, red, {"review": "ACCEPTED"}, who="reviewer")
    assert r.status_code == 403, r.text
    assert _review_col(conn, red) == "PROPOSED"
    got = client.get(f"/api/v1/cases/{w['case']}/graph/edges/{red}/review",
                     headers=_auth(conn, w["reviewer"]))
    assert got.status_code == 404, got.text
    # The RED owner may do both.
    assert _review(client, conn, w, red, {"review": "ACCEPTED"}).status_code == 200


def test_the_review_routes_need_authentication(client):
    case_id, oid = uuid4(), uuid4()
    path = f"/api/v1/cases/{case_id}/graph/edges/{oid}/review"
    assert client.post(path, json={"review": "ACCEPTED"}).status_code == 401
    assert client.get(path).status_code == 401


# ---------------------------------------------------------------------------
# Ties entered before Alpha 6: migration 0067
# ---------------------------------------------------------------------------

MIGRATION = (Path(__file__).resolve().parents[3] / "db" / "migrations"
             / "versions" / "0067_tie_review_born_state.py")


def _born_state_sql() -> str:
    """The statement 0067 runs, read from the migration itself, so the test
    and the upgrade cannot drift apart."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("m0067", MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.BORN_STATE_SQL


def _entered_before_alpha6(conn, edge_id):
    """What every tie entered before Alpha 6 holds, whoever entered it: the
    column default, because nothing set it."""
    conn.execute("UPDATE core.edge SET review = 'PROPOSED' WHERE id = %s",
                 (edge_id,))


def _accepted_from_triage(conn, client, w):
    from noctornal_api.proposals import ProposalStore
    pid = ProposalStore(conn).propose(
        case_id=w["case"], kind="EDGE", origin="trev_test_v1",
        payload={"edge_type": "COMMUNICATES_WITH",
                 "src_node_id": str(w["src"]), "dst_node_id": str(w["dst"])},
        rationale="raised by the tie review test", score=0.5)
    r = client.post(f"/api/v1/cases/{w['case']}/proposals/{pid}/accept",
                    headers=_auth(conn, w["reviewer"]), json={})
    assert r.status_code == 200, r.text
    return r.json()["applied_edge_id"]


def test_the_upgrade_gives_old_ties_the_state_they_would_be_born_in(
        conn, client, world):
    """ux05-inspector:review-state-never-leaves-proposed, the 2026-09-23
    verifier: with only the born rule, every tie on an upgraded estate
    stayed PROPOSED (quill_shrike66 read 14 unreviewed of 14, its own
    direct observation among them), and the only way out was one click per
    tie. The migration's statement is run as it stands, inside a
    transaction that is rolled back, so the estate this suite runs on is
    left as it was."""
    from datetime import datetime, timezone

    from psycopg.rows import dict_row
    w = world

    def day(n):
        """Parallel ties between one pair differ by when they began
        (edge_uniq_active)."""
        return datetime(2025, 1, n, tzinfo=timezone.utc)

    person = _tie(w, valid_from=day(1))
    inferred = _tie(w, basis="ANALYST_INFERENCE", edge_type="VOUCHED_FOR")
    machine = _tie(w, basis="AUTOMATED_INFERENCE", valid_from=day(2))
    triaged = _accepted_from_triage(conn, client, w)
    reopened = _tie(w, valid_from=day(3))
    for body in ({"review": "DISPUTED", "note": "the handle is reused"},
                 {"review": "PROPOSED", "note": "a new capture came in"}):
        assert _review(client, conn, w, reopened, body).status_code == 200
    disputed = _tie(w, valid_from=day(4))
    assert _review(client, conn, w, disputed,
                   {"review": "DISPUTED", "note": "one source only"}
                   ).status_code == 200
    retired = _tie(w, valid_from=day(5))
    w["g"].soft_delete_edge(retired, case_id=w["case"], deleted_by=w["owner"],
                            at=datetime.now(timezone.utc))
    for e in (person, inferred, triaged, retired):
        _entered_before_alpha6(conn, e)
    code = conn.execute('SELECT code FROM core."case" WHERE id = %s',
                        (w["case"],)).fetchone()[0]
    sql = _born_state_sql()

    def run() -> dict[str, str]:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql)
            return {str(r["edge_id"]): r["reason"] for r in cur.fetchall()
                    if r["case_code"] == code}

    with conn.transaction(force_rollback=True):
        moved = run()
        assert set(moved) == {str(person), str(inferred), str(triaged)}
        assert "Triage" in moved[str(triaged)]
        assert "their own claim" in moved[str(person)]
        assert {e: _review_col(conn, e) for e in
                (person, inferred, triaged, machine, reopened, disputed, retired)} == {
            person: "ACCEPTED", inferred: "ACCEPTED", triaged: "ACCEPTED",
            machine: "PROPOSED",    # a machine's, and nobody accepted it
            reopened: "PROPOSED",   # a person reopened it and meant it
            disputed: "DISPUTED", retired: "PROPOSED"}
        rows = conn.execute(
            """SELECT actor_id, actor_kind, detail FROM audit.event
                WHERE action = 'EDGE_REVIEWED' AND object_id = %s""",
            (person,)).fetchall()
        assert len(rows) == 1 and rows[0][:2] == (None, "SYSTEM"), rows
        assert {k: rows[0][2][k] for k in ("review", "previous", "by")} == {
            "review": "ACCEPTED", "previous": "PROPOSED",
            "by": "the Alpha 6 upgrade"}
        written = rows[0][2]
        assert run() == {}, "a second run changes nothing"
    assert _review_col(conn, person) == "PROPOSED", "the test rolled back"

    # What the tie inspector's Review history then says: the upgrade, by
    # name, not "by unknown". The row is written as the migration writes it.
    from psycopg.types.json import Jsonb
    conn.execute(
        """INSERT INTO audit.event
                  (actor_id, actor_kind, action, object_type, object_id,
                   case_id, detail)
           VALUES (NULL, 'SYSTEM', 'EDGE_REVIEWED', 'edge', %s, %s, %s)""",
        (person, w["case"], Jsonb(written)))
    got = client.get(f"/api/v1/cases/{w['case']}/graph/edges/{person}/review",
                     headers=_auth(conn, w["analyst"]))
    assert got.status_code == 200, got.text
    [event] = got.json()["history"]
    assert (event["by"], event["by_name"], event["review"]) == (
        None, "the Alpha 6 upgrade", "ACCEPTED")
    assert "their own claim" in event["note"]


def test_the_upgrade_restates_the_rule_create_edge_applies():
    """0067 and `create_edge` must mean the same thing by "a machine's
    claim", and the statement must be one statement, so it commits whole
    or not at all."""
    from noctornal_api.graph import MACHINE_BASIS
    sql = _born_state_sql()
    body = "\n".join(line for line in sql.splitlines()
                     if not line.startswith("--"))
    assert f"f.basis <> '{MACHINE_BASIS}'" in body
    assert body.strip().endswith(";") and body.count(";") == 1
    assert "\\" not in body, "no psql meta-command: it runs through any driver"
