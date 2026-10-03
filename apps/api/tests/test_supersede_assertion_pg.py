"""Giving a claim that never had an observation date one, by supersession
(docs/00 open question 11, settled by the owner 2026-10-02; migration 0131).

Claims accepted from Triage before Alpha 6 carry no `observed_at`. Writing a
date onto a recorded claim rewrites it, which invariant 5 forbids, and the
owner decided it is NOT amended. The way a claim gains a date is the
supersession the model already had: the old claim is superseded, never
overwritten, by a new claim carrying the date and the analyst's rationale.
Until this file's subject the model had half of it: `superseded_at` and
`superseded_by` were honoured by every reader and written by nothing in the
product, and a new claim could not say what it replaced.

What these tests hold, end to end for the legacy estate of
test_legacy_records_pg.py (a NODE, an EDGE and an ATTRIBUTE claim accepted
from Triage and stripped of their dates, as Alpha 5.2 wrote them):

- the OLD row is untouched in every column but the two supersession stamps,
  and those are stamped once, from NULL;
- the NEW row cites it (`supersedes_id`), carries the date and the reason,
  and is the old claim in every other column;
- the legacy listing and the readiness count drop the claim, the element
  keeps a live claim at the same grade, and the audit trail records it;
- the route is gated on both verbs it uses, against the element's labels,
  and refuses a claim that is dated, withdrawn, replaced, in another case or
  in a closed case;
- the database itself refuses a replacement across cases, across elements,
  of a withdrawn claim, of itself, or twice.

The fixture, the estate builder and the `lgr-` prefix are
test_legacy_records_pg.py's, so its teardown removes everything here.
Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest

from test_case_merge_relax_pg import session
from test_legacy_records_pg import (
    _case,
    _estate,
    _node,
    _reuse,
    _user,
)
from test_legacy_records_pg import conn as legacy_conn  # noqa: F401 - the fixture

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; supersession is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

API = "/api/v1"
VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
OBSERVED = "2026-03-01T22:30:00Z"
REASON = "Dated from the post's own timestamp, 1 March 2026 22:30 UTC."


class _RollBack(Exception):
    pass


@pytest.fixture
def conn(legacy_conn):  # noqa: F811 - the fixture, by its own name
    """test_legacy_records_pg's connection and teardown (prefix `lgr-`)."""
    return legacy_conn


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


@pytest.fixture(autouse=True)
def _script_module(monkeypatch):
    """scripts/legacy_records.py, importable as `legacy_records_script`."""
    import sys
    scripts = Path(__file__).resolve().parents[3] / "scripts"
    monkeypatch.syspath_prepend(str(scripts))
    spec = importlib.util.spec_from_file_location(
        "legacy_records_script", scripts / "legacy_records.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setitem(sys.modules, "legacy_records_script", module)


def _row(conn, assertion_id) -> dict:
    """Every column of one assertion, as JSON text would carry it."""
    return conn.execute("SELECT to_jsonb(a) FROM core.assertion a WHERE id = %s",
                        (assertion_id,)).fetchone()[0]


_STAMPS = ("superseded_at", "superseded_by")


def _unstamped(row: dict) -> dict:
    return {k: v for k, v in row.items() if k not in _STAMPS}


def _supersede(conn, e, kind="attr", *, by=None, at=None, why=REASON):
    from noctornal_api.graph import GraphWriteService
    return GraphWriteService(conn).supersede_assertion(
        e["claims"][kind], case_id=e["case"], observed_at=at or datetime(
            2026, 3, 1, 22, 30, tzinfo=timezone.utc),
        rationale=why, created_by=by or e["owner"])


def _undated_ids(conn, e) -> set:
    from noctornal_api.legacy_records import undated_triage_claims
    return {c.assertion_id for c in undated_triage_claims(conn)
            if c.case_id == e["case"]}


# ---------------------------------------------------------------------------
# The model: the old row untouched, the new row citing it
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kind", ["node", "edge", "attr"])
def test_invariant_5_dating_a_legacy_claim_supersedes_it_and_rewrites_nothing(
        conn, kind):
    """CONVENTIONS invariant 5: the old row's two stamps are written once, from
    NULL, and every other column is as it was. Columns come from the row as
    the catalogue holds it, so one added later is held to the same rule."""
    e = _estate(conn)
    analyst = _user(conn)
    before = _row(conn, e["claims"][kind])
    assert before["observed_at"] is None and before["superseded_at"] is None
    new_id = _supersede(conn, e, kind, by=analyst)
    after = _row(conn, e["claims"][kind])
    # The old row: every column as it was, but the two stamps.
    assert _unstamped(after) == _unstamped(before)
    assert after["observed_at"] is None, "the date is not written onto it"
    assert after["superseded_at"] is not None
    assert after["superseded_by"] == str(new_id)
    assert after["retracted_at"] is None
    # The new row cites it, carries the date and the reason, and is the old
    # claim in every column but the three that differ.
    new = _row(conn, new_id)
    assert new["supersedes_id"] == str(e["claims"][kind])
    assert datetime.fromisoformat(new["observed_at"]) == datetime(
        2026, 3, 1, 22, 30, tzinfo=timezone.utc)
    assert new["rationale"] == REASON
    assert new["created_by"] == str(analyst) != before["created_by"]
    assert new["superseded_at"] is None and new["superseded_by"] is None
    assert new["retracted_at"] is None
    same = ("case_id", "node_id", "edge_id", "claim_path", "claim_value",
            "basis", "reliability", "credibility", "confidence", "source_id",
            "document_id", "evidence_id", "external_ref", "lookup_result_id")
    assert {k: new[k] for k in same} == {k: before[k] for k in same}


def test_the_dated_claim_leaves_the_legacy_listing_and_the_register_count(conn):
    from noctornal_api import readiness
    from noctornal_api.legacy_records import undated_count
    e = _estate(conn)
    assert _undated_ids(conn, e) == set(e["claims"].values())
    count = undated_count(conn)
    _supersede(conn, e, "attr")
    assert _undated_ids(conn, e) == {e["claims"]["node"], e["claims"]["edge"]}
    assert undated_count(conn) == count - 1
    # The register's sentence follows the count it reads.
    assert readiness._triage_claims_dated(conn).ok


def test_the_new_claim_is_not_itself_listed_and_cannot_be_dated_again(conn):
    from noctornal_api.graph import ClaimNotDatable
    e = _estate(conn)
    new_id = _supersede(conn, e, "node")
    assert new_id not in _undated_ids(conn, e)
    with pytest.raises(ClaimNotDatable, match="already has an observation date"):
        from noctornal_api.graph import GraphWriteService
        GraphWriteService(conn).supersede_assertion(
            new_id, case_id=e["case"], observed_at=datetime.now(timezone.utc),
            rationale="again", created_by=e["owner"])


def test_the_element_keeps_a_live_claim_and_a_tie_keeps_its_grade(conn):
    e = _estate(conn)
    edge_id = conn.execute("SELECT edge_id FROM core.assertion WHERE id = %s",
                           (e["claims"]["edge"],)).fetchone()[0]
    node_id = conn.execute("SELECT node_id FROM core.assertion WHERE id = %s",
                           (e["claims"]["node"],)).fetchone()[0]
    tie = conn.execute("SELECT confidence FROM core.edge WHERE id = %s",
                       (edge_id,)).fetchone()[0]
    new_edge = _supersede(conn, e, "edge")
    new_node = _supersede(conn, e, "node")
    assert conn.execute("SELECT confidence FROM core.edge WHERE id = %s",
                        (edge_id,)).fetchone()[0] == tie
    for column, element, claim in (("edge_id", edge_id, new_edge),
                                   ("node_id", node_id, new_node)):
        live = [r[0] for r in conn.execute(
            f"SELECT id FROM core.assertion WHERE {column} = %s "
            f"AND retracted_at IS NULL AND superseded_at IS NULL", (element,))]
        assert claim in live and e["claims"][
            "edge" if column == "edge_id" else "node"] not in live


def test_a_claim_is_refused_when_it_cannot_be_dated_and_nothing_is_written(conn):
    from noctornal_api.graph import ClaimNotDatable, GraphWriteError, GraphWriteService
    e = _estate(conn)
    g = GraphWriteService(conn)
    other_owner = _user(conn)
    other_case = _case(conn, other_owner)

    def attempt(claim, *, case=None, why=REASON):
        return g.supersede_assertion(
            claim, case_id=case or e["case"], observed_at=datetime.now(
                timezone.utc) - timedelta(days=1), rationale=why,
            created_by=e["owner"])

    retracted, replaced, dated = (e["claims"]["node"], e["claims"]["edge"],
                                  e["claims"]["attr"])
    conn.execute("UPDATE core.assertion SET retracted_at = now(), "
                 "retracted_by = %s, retraction_reason = 'wrong' WHERE id = %s",
                 (e["owner"], retracted))
    _supersede(conn, e, "edge")
    conn.execute("UPDATE core.assertion SET observed_at = now() WHERE id = %s",
                 (dated,))
    snapshot = {c: _row(conn, c) for c in (retracted, replaced, dated)}
    count = conn.execute("SELECT count(*) FROM core.assertion").fetchone()[0]
    for claim, words in ((retracted, "retracted"), (replaced, "replaced"),
                         (dated, "already has an observation date")):
        with pytest.raises(ClaimNotDatable, match=words):
            attempt(claim)
    with pytest.raises(GraphWriteError, match="not found in this case"):
        attempt(dated, case=other_case)
    with pytest.raises(GraphWriteError, match="not found in this case"):
        attempt(uuid4())
    for blank in ("", "   "):
        with pytest.raises(GraphWriteError, match="say why this date"):
            attempt(replaced, why=blank)
    assert {c: _row(conn, c) for c in snapshot} == snapshot
    assert conn.execute("SELECT count(*) FROM core.assertion").fetchone()[0] == count


def test_a_failed_dating_rolls_back_the_new_claim_too(conn, monkeypatch):
    """The new claim goes in first, so a failure to stamp the old one must
    take it out again: no live twin, no half-dated claim."""
    from noctornal_api.graph import ClaimNotDatable, GraphWriteService
    e = _estate(conn)
    claim = e["claims"]["attr"]
    real = psycopg.Connection.execute

    class _NoStamp:
        rowcount = 0

    def execute(self, query, params=None, **kw):
        if "SET superseded_at = now()" in str(query):
            return _NoStamp()
        return real(self, query, params, **kw)

    monkeypatch.setattr(psycopg.Connection, "execute", execute)
    count = conn.execute("SELECT count(*) FROM core.assertion").fetchone()[0]
    with pytest.raises(ClaimNotDatable, match="withdrawn or replaced while"):
        GraphWriteService(conn).supersede_assertion(
            claim, case_id=e["case"], observed_at=datetime.now(timezone.utc),
            rationale=REASON, created_by=e["owner"])
    monkeypatch.undo()
    assert conn.execute("SELECT count(*) FROM core.assertion").fetchone()[0] == count
    assert _row(conn, claim)["superseded_at"] is None


# ---------------------------------------------------------------------------
# The database
# ---------------------------------------------------------------------------

def _insert_citing(conn, case_id, node_id, supersedes, by):
    return conn.execute(
        """INSERT INTO core.assertion (case_id, node_id, basis, created_by,
                                       supersedes_id)
           VALUES (%s, %s, 'DIRECT_OBSERVATION', %s, %s) RETURNING id""",
        (case_id, node_id, by, supersedes)).fetchone()[0]


def test_the_database_refuses_a_replacement_that_is_not_one(conn):
    e = _estate(conn)
    owner, case = e["owner"], e["case"]
    other_case = _case(conn, owner)
    stranger = _node(conn, other_case, owner, "ssd-stranger")
    a_claim = e["claims"]["attr"]
    node_a = conn.execute("SELECT node_id FROM core.assertion WHERE id = %s",
                          (a_claim,)).fetchone()[0]
    stranger_claim = conn.execute(
        "SELECT id FROM core.assertion WHERE node_id = %s", (stranger,)
    ).fetchone()[0]
    other_node = _node(conn, case, owner, "ssd-other")

    def refused(supersedes, node, case_id=case, match=None, error=None):
        with pytest.raises(error or psycopg.errors.RaiseException,
                           match=match), conn.transaction():
            _insert_citing(conn, case_id, node, supersedes, owner)

    refused(stranger_claim, node_a, match="only a claim in its own case")
    refused(a_claim, other_node, match="about the same entity or tie")
    refused(uuid4(), node_a, match="must name a claim that exists")
    conn.execute("UPDATE core.assertion SET retracted_at = now(), "
                 "retracted_by = %s, retraction_reason = 'x' WHERE id = %s",
                 (owner, e["claims"]["node"]))
    node_of_node = conn.execute("SELECT node_id FROM core.assertion WHERE id = %s",
                                (e["claims"]["node"],)).fetchone()[0]
    refused(e["claims"]["node"], node_of_node, match="history and is not replaced")
    # Itself: refused whichever guard sees it first (no such row yet, or the
    # check that a claim is not its own replacement).
    mine = uuid4()
    with pytest.raises((psycopg.errors.RaiseException,
                        psycopg.errors.CheckViolation)), conn.transaction():
        conn.execute(
            """INSERT INTO core.assertion (id, case_id, node_id, basis,
                                           created_by, supersedes_id)
               VALUES (%s, %s, %s, 'DIRECT_OBSERVATION', %s, %s)""",
            (mine, case, node_a, owner, mine))
    # Written once: a claim's citation is not changed after the insert, by
    # anybody, so a replacement cannot be re-aimed.
    cited = _insert_citing(conn, case, other_node, None, owner)
    with pytest.raises(psycopg.errors.RaiseException,
                       match="is recorded once"), conn.transaction():
        conn.execute("UPDATE core.assertion SET supersedes_id = %s WHERE id = %s",
                     (a_claim, cited))
    # Once: two claims cannot both replace the same one.
    first = _insert_citing(conn, case, node_a, a_claim, owner)
    assert first
    conn.execute("UPDATE core.assertion SET superseded_at = now() WHERE id = %s",
                 (a_claim,))
    with pytest.raises((psycopg.errors.UniqueViolation,
                        psycopg.errors.RaiseException)), conn.transaction():
        _insert_citing(conn, case, node_a, a_claim, owner)


def test_the_unique_index_alone_stops_two_replacements_of_one_claim(conn):
    """Past the guard (the claim still looks live to it): the index."""
    e = _estate(conn)
    claim = e["claims"]["attr"]
    node_id = conn.execute("SELECT node_id FROM core.assertion WHERE id = %s",
                           (claim,)).fetchone()[0]
    _insert_citing(conn, e["case"], node_id, claim, e["owner"])
    with pytest.raises(psycopg.errors.UniqueViolation) as err, conn.transaction():
        _insert_citing(conn, e["case"], node_id, claim, e["owner"])
    assert err.value.diag.constraint_name == "assertion_replaced_once"


def test_the_migration_round_trips(conn):
    path = next(VERSIONS.glob("*_assertion_supersedes.py"))
    spec = importlib.util.spec_from_file_location("m_ssd", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    m.run = lambda sql: conn.execute(sql)
    assert (m.revision, m.down_revision) == ("0131", "0130")

    def has_column() -> bool:
        return bool(conn.execute(
            "SELECT count(*) FROM information_schema.columns WHERE "
            "table_schema = 'core' AND table_name = 'assertion' AND "
            "column_name = 'supersedes_id'").fetchone()[0])

    def has_guard() -> bool:
        return conn.execute(
            "SELECT count(*) FROM pg_trigger WHERE tgname IN "
            "('assertion_supersedes_guarded', 'assertion_supersedes_unchanged') "
            "AND NOT tgisinternal").fetchone()[0] == 2

    assert has_column() and has_guard()
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        assert not has_column() and not has_guard()
        m.upgrade()
        assert has_column() and has_guard()
        raise _RollBack
    assert has_column() and has_guard()


# ---------------------------------------------------------------------------
# The route
# ---------------------------------------------------------------------------

def _supersede_url(case_id, assertion_id) -> str:
    return f"{API}/cases/{case_id}/assertions/{assertion_id}/supersede"


def _post(client, headers, path_case, assertion_id, **body):
    body.setdefault("observed_at", OBSERVED)
    body.setdefault("rationale", REASON)
    return client.post(_supersede_url(path_case, assertion_id), headers=headers,
                       json=body)


def test_an_analyst_dates_a_legacy_claim_end_to_end_over_http(conn, client):
    e = _estate(conn)
    analyst = _user(conn)
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'ANALYST', %s)",
                 (e["case"], analyst, e["owner"]))
    headers = session(conn, analyst)
    old = e["claims"]["attr"]
    before = _row(conn, old)
    # Body fields that would regrade, rebase or re-aim the claim are not part
    # of the verb: they are ignored, and the copy is the old claim's.
    r = _post(client, headers, e["case"], old, confidence="HIGH",
              basis="DIRECT_OBSERVATION", reliability="A", claim_value="x",
              node_id=str(uuid4()), case_id=str(uuid4()))
    assert r.status_code == 201, r.text
    new_id = r.json()["id"]
    assert r.json()["supersedes"] == str(old)
    new = _row(conn, new_id)
    for column in ("basis", "confidence", "reliability", "credibility",
                   "claim_value", "node_id", "case_id", "document_id"):
        assert new[column] == before[column], column
    assert new["supersedes_id"] == str(old) and new["created_by"] == str(analyst)
    assert _unstamped(_row(conn, old)) == _unstamped(before)
    # The inspector's read: the old claim is hidden, then listed with the
    # pair named from both sides.
    node = before["node_id"]
    live = client.get(f"{API}/cases/{e['case']}/nodes/{node}/assertions",
                      headers=headers).json()
    assert str(old) not in {a["id"] for a in live}
    dated = next(a for a in live if a["id"] == new_id)
    assert dated["supersedes_id"] == str(old) and dated["observed_at"]
    both = client.get(f"{API}/cases/{e['case']}/nodes/{node}/assertions",
                      headers=headers, params={"include_retracted": "true"}
                      ).json()
    gone = next(a for a in both if a["id"] == str(old))
    assert gone["superseded_at"] and gone["superseded_by"] == new_id
    assert gone["observed_at"] is None
    # The audit trail has it, once, with the pair and the date and no text.
    rows = conn.execute(
        """SELECT actor_id, object_id, case_id, detail FROM audit.event
            WHERE action = 'ASSERTION_SUPERSEDED' AND object_id = %s""",
        (old,)).fetchall()
    assert len(rows) == 1
    actor, obj, case_id, detail = rows[0]
    assert (actor, obj, case_id) == (analyst, old, e["case"])
    assert detail == {"superseded_by": new_id,
                      "observed_at": "2026-03-01T22:30:00+00:00"}
    assert REASON not in json.dumps(detail)


def test_the_route_is_gated_on_both_verbs_and_the_elements_labels(conn, client):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    e = _estate(conn)
    reader, stranger, junior = _user(conn), _user(conn), _user(conn, "AMBER")
    conn.execute("INSERT INTO iam.case_assignment (case_id, user_id, role_key, "
                 "granted_by) VALUES (%s, %s, 'READ_ONLY', %s), "
                 "(%s, %s, 'ANALYST', %s)",
                 (e["case"], reader, e["owner"], e["case"], junior, e["owner"]))
    old = e["claims"]["attr"]
    before = _row(conn, old)
    denied = _post(client, session(conn, reader), e["case"], old)
    assert denied.status_code == 403, denied.text
    assert "assertion.retract" in denied.json()["detail"]
    assert _post(client, session(conn, stranger), e["case"], old
                 ).status_code == 404
    # A RED entity in an AMBER case: the junior analyst holds both verbs on
    # the case and is still refused at the element's own label (CR7).
    red = _node(conn, e["case"], e["owner"], "ssd-red", classification="RED")
    red_claim = conn.execute("SELECT id FROM core.assertion WHERE node_id = %s",
                             (red,)).fetchone()[0]
    undated = GraphWriteService(conn).add_assertion(
        case_id=e["case"], node_id=red, assertion=AssertionInput(
            basis="DIRECT_OBSERVATION", created_by=e["owner"]))
    for claim in (red_claim, undated):
        r = _post(client, session(conn, junior), e["case"], claim)
        assert r.status_code == 403, r.text
        assert "missing permission" in r.json()["detail"]
        assert _row(conn, claim)["superseded_at"] is None
    assert _row(conn, old) == before
    assert conn.execute(
        "SELECT count(*) FROM core.assertion WHERE supersedes_id IS NOT NULL "
        "AND case_id = %s", (e["case"],)).fetchone()[0] == 0


def test_the_route_refuses_what_cannot_be_dated_with_the_reason(conn, client):
    e = _estate(conn)
    headers = session(conn, e["owner"])
    other = _case(conn, e["owner"])
    c = e["claims"]
    # Another case's claim and an unknown id are the same 404.
    assert _post(client, headers, other, c["attr"]).status_code == 404
    assert _post(client, headers, e["case"], uuid4()).status_code == 404
    first = _post(client, headers, e["case"], c["attr"])
    assert first.status_code == 201, first.text
    again = _post(client, headers, e["case"], c["attr"])
    assert again.status_code == 409
    assert "replaced" in again.json()["detail"]
    twice = _post(client, headers, e["case"], first.json()["id"])
    assert twice.status_code == 409
    assert "already has an observation date" in twice.json()["detail"]
    conn.execute("UPDATE core.assertion SET retracted_at = now(), "
                 "retracted_by = %s, retraction_reason = 'x' WHERE id = %s",
                 (e["owner"], c["node"]))
    gone = _post(client, headers, e["case"], c["node"])
    assert gone.status_code == 409 and "retracted" in gone.json()["detail"]
    # Bad bodies: no instant, a naive instant, the future, no reason.
    assert _post(client, headers, e["case"], c["edge"], observed_at="not a time"
                 ).status_code == 422
    naive = _post(client, headers, e["case"], c["edge"],
                  observed_at="2026-03-01T22:30:00")
    assert naive.status_code == 400 and "no UTC offset" in naive.json()["detail"]
    soon = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    future = _post(client, headers, e["case"], c["edge"], observed_at=soon)
    assert future.status_code == 400 and "in the future" in future.json()["detail"]
    assert _post(client, headers, e["case"], c["edge"], rationale=""
                 ).status_code == 422
    blank = _post(client, headers, e["case"], c["edge"], rationale="   ")
    assert blank.status_code == 400 and "say why this date" in blank.json()["detail"]
    assert _row(conn, c["edge"])["superseded_at"] is None
    refused = conn.execute(
        "SELECT count(*) FROM audit.event WHERE action = 'ASSERTION_SUPERSEDED' "
        "AND case_id = %s", (e["case"],)).fetchone()[0]
    assert refused == 1, "only the one that happened is audited"


def test_a_closed_case_takes_no_dating(conn, client):
    from noctornal_api.cases import CaseService
    e = _estate(conn)
    svc = CaseService(conn)
    svc.transition_status(e["case"], "ACTIVE", actor_id=e["owner"])
    svc.transition_status(e["case"], "CLOSED", actor_id=e["owner"])
    r = _post(client, session(conn, e["owner"]), e["case"], e["claims"]["attr"])
    assert r.status_code == 409, r.text
    assert r.json()["title"] == "Case is read-only"
    assert _row(conn, e["claims"]["attr"])["superseded_at"] is None


def test_the_listing_script_and_the_register_say_how_a_claim_gets_its_date(conn):
    """The wording that used to say the fill waits on an owner decision."""
    from noctornal_api import readiness
    from legacy_records_script import main
    e = _estate(conn)
    out = io.StringIO()
    with redirect_stdout(out):
        assert main(["--section", "undated"], connect=_reuse(conn)) == 1
    text = out.getvalue()
    assert "Date this claim" in text and "superseded" in text
    assert "decision" not in text and "amend" not in text.lower()
    caveat = readiness._triage_claims_dated(conn).caveat
    assert "Date this claim" in caveat and "supersedes" in caveat
    assert "decision" not in caveat and "amend" not in caveat.lower()
    for bad in (chr(0x2014), chr(0x2013), " -- ", "(s)"):
        assert bad not in text and bad not in caveat
    assert e
