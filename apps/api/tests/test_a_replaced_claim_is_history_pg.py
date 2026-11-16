"""A claim that a newer one replaced is history, in every read that asks whether a claim is live.

Dating an undated claim records a copy and stamps the old row `superseded_at` (`supersede_assertion`). The
copy carries the same exhibit, the same document and the same grade, so while it stands the element rests
on it. When the copy is then withdrawn, the old row is still `retracted_at IS NULL`, and a read that asks
only that question counts it as live again: the exhibit goes on backing the element, the stance an analyst
put on it goes on scoring, and the analyst can "retract" a claim that is already history, which
`supersede_assertion` refuses for the same reason.

These tests build exactly that: a claim, its replacement, and the replacement withdrawn. What they hold:

- the exhibit a replaced claim carried backs nothing once its replacement is withdrawn, on the canvas
  mark, in the inspector's list, in the register's counts and in the backs route, for an entity and a tie;
  while the replacement stands it is the one backing, once;
- a replaced claim is not retracted, by the service or by the route, and writes no audit row;
- a stance on a replaced claim is kept and shown as stale, scores nothing, and cannot be written
  afresh, in the live matrix and in the report; a retracted claim still leaves the matrix altogether
  (decision 24);
- a replaced claim's label above the reader's ceiling still does not reach the reader.

Everything is created in one transaction that is rolled back. Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.environ.get("DATABASE_URL"),
    reason="needs a migrated database")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

DATED = datetime(2026, 3, 1, 22, 30, tzinfo=timezone.utc)


@pytest.fixture()
def conn():
    import psycopg

    from noctornal_api.db import dsn

    c = psycopg.connect(dsn())
    try:
        yield c
    finally:
        c.rollback()
        c.close()


def _user(conn, *, clearance="RED", name="Replaced Analyst", global_roles=("CASE_OWNER",)):
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, %s, 'x', %s) RETURNING id""",
        (f"rpl-{uuid4().hex[:8]}@noctornal.test", name, clearance),
    ).fetchone()[0]
    for role in global_roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid


def _assign(conn, case_id, uid, role):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, uid, role, uid))


def _who(uid):
    from noctornal_api.http.deps import CurrentUser
    return CurrentUser(user_id=uid, session_id=uuid4(),
                       session_mfa_at=datetime.now(timezone.utc))


def _node(conn, case_id, uid, label, *, grade=("B", "2"), classification="AMBER"):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=uid,
        classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid,
                                 reliability=grade[0], credibility=grade[1]))


@pytest.fixture()
def world(conn):
    """A case, an owner, two entities and a tie, each with one live claim and no exhibit."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    uid = _user(conn)
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Replaced claims', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-RPL-{uuid4().hex[:6]}", uid))
    _assign(conn, case_id, uid, "CASE_OWNER")
    n1 = _node(conn, case_id, uid, "one")
    n2 = _node(conn, case_id, uid, "two")
    edge = GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="VOUCHED_FOR", src_node_id=n1, dst_node_id=n2,
        created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid))
    return case_id, uid, n1, n2, edge


def _exhibit(conn, case_id, uid, *, title="screenshot.png"):
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, %s, 'image/png', 1024, %s, %s, %s, 'test-bucket',
                   'AMBER', 'SCREENSHOT', now(), %s)
           RETURNING id""",
        (case_id, title, os.urandom(32), os.urandom(32), f"rpl/{uuid4().hex}", uid),
    ).fetchone()[0]


def _carry(conn, case_id, uid, ev, *, node_id=None, edge_id=None):
    """An undated claim carrying the exhibit, which is the kind `supersede_assertion` dates."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).add_assertion(
        case_id=case_id, node_id=node_id, edge_id=edge_id,
        assertion=AssertionInput(basis="THIRD_PARTY_REPORT", created_by=uid,
                                 evidence_id=ev, reliability="B", credibility="2"))


def _link(conn, uid, ev, *, node_id=None, edge_id=None):
    conn.execute(
        """INSERT INTO core.evidence_link (evidence_id, node_id, edge_id, created_by)
           VALUES (%s, %s, %s, %s)""", (ev, node_id, edge_id, uid))


def _replace(conn, case_id, uid, claim):
    """Date the claim by supersession; returns the replacing claim's id."""
    from noctornal_api.graph import GraphWriteService
    return GraphWriteService(conn).supersede_assertion(
        claim, case_id=case_id, observed_at=DATED,
        rationale="Dated from the post's own timestamp.", created_by=uid)


def _withdraw(conn, uid, claim):
    from noctornal_api.graph import GraphWriteService
    return GraphWriteService(conn).retract_assertion(
        claim, retracted_by=uid, reason="the date was wrong",
        at=datetime.now(timezone.utc))


def _row(conn, claim):
    return conn.execute(
        "SELECT retracted_at, superseded_at FROM core.assertion WHERE id = %s",
        (claim,)).fetchone()


# --- what an exhibit backs ----------------------------------------------------

def _drawn_with_evidence(conn, case_id, *, node_id=None, edge_id=None):
    """The canvas mark `has_evidence` of one element, as the projection computes it."""
    from noctornal_api.projections import GraphService, Projection
    sub = GraphService(conn, clearance="RED", compartments=frozenset()).project(
        Projection(case_id=case_id))
    if node_id is not None:
        return next(n for n in sub.nodes if n["id"] == node_id)["has_evidence"]
    return next(e for e in sub.edges if e["id"] == edge_id)["has_evidence"]


def _inspector(conn, case_id, uid, *, node_id=None, edge_id=None):
    """The inspector's Evidence list, through the route function itself."""
    from noctornal_api.http.routers.read import edge_evidence, node_evidence
    if node_id is not None:
        return node_evidence(case_id, node_id, limit=1000, offset=0,
                             user=_who(uid), conn=conn)
    return edge_evidence(case_id, edge_id, limit=1000, offset=0,
                         user=_who(uid), conn=conn)


def _register(conn, case_id, **kw):
    from noctornal_api.http.routers.evidence import exhibit_register
    return exhibit_register(conn, case_id=case_id, clearance="RED", compartments=[], **kw)


def _backs(conn, case_id, uid, ev, surface, **element):
    """Whether one surface says the exhibit `ev` backs the element."""
    from noctornal_api.http.routers import evidence as route
    if surface == "canvas mark":
        return _drawn_with_evidence(conn, case_id, **element)
    if surface == "inspector list":
        return bool(_inspector(conn, case_id, uid, **element))
    if surface == "register count":
        [row] = _register(conn, case_id)["items"]
        return (row.backs_nodes + row.backs_edges) > 0
    if surface == "register backs-nothing":
        return _register(conn, case_id, backs_nothing=True)["backs_nothing"] == 0
    assert surface == "backs route"
    return bool(route.backs(case_id, ev, user=_who(uid), conn=conn).items)


_SURFACES = ["canvas mark", "inspector list", "register count", "register backs-nothing",
             "backs route"]


@pytest.mark.parametrize("surface", _SURFACES)
@pytest.mark.parametrize("kind", ["node", "edge"])
def test_the_exhibit_of_a_replaced_claim_backs_nothing_once_its_replacement_is_withdrawn(
        conn, world, kind, surface):
    """The defect: the replacing claim is retracted, the old row is only superseded, and every read that
    asked `retracted_at IS NULL` alone went on counting it. The element keeps its own first claim, so it is
    still drawn; what must go is the exhibit's backing of it, on every surface that says what backs what."""
    case_id, uid, n1, _n2, edge = world
    element = {"node_id": n1} if kind == "node" else {"edge_id": edge}
    ev = _exhibit(conn, case_id, uid, title="handle-screenshot.png")
    replacement = _replace(conn, case_id, uid, _carry(conn, case_id, uid, ev, **element))
    assert _backs(conn, case_id, uid, ev, surface, **element) is True, (
        "the control: the replacement carries the exhibit while it stands")
    _withdraw(conn, uid, replacement)
    assert _backs(conn, case_id, uid, ev, surface, **element) is False, (
        f"the {surface} still said a replaced claim's exhibit backs the element")


@pytest.mark.parametrize("kind", ["node", "edge"])
def test_a_replaced_claim_is_not_listed_as_backing_beside_the_claim_that_replaced_it(
        conn, world, kind):
    """While the replacement stands the exhibit reaches the element through it, once: the inspector lists
    the claim that backs it, not the claim's history beside it."""
    from noctornal_api.http.routers import evidence as route
    case_id, uid, n1, _n2, edge = world
    element = {"node_id": n1} if kind == "node" else {"edge_id": edge}
    ev = _exhibit(conn, case_id, uid)
    replacement = _replace(conn, case_id, uid, _carry(conn, case_id, uid, ev, **element))
    [row] = _inspector(conn, case_id, uid, **element)
    assert [b.assertion_id for b in row.backing] == [str(replacement)]
    backed = route.backs(case_id, ev, user=_who(uid), conn=conn)
    assert (backed.nodes, backed.edges) == ((1, 0) if kind == "node" else (0, 1))


def test_the_backs_route_names_a_link_and_not_the_replaced_claim_beside_it(conn, world):
    """`via` says by which routes an exhibit reaches an element: a link, and a live claim. A replaced claim
    whose replacement is withdrawn is neither."""
    from noctornal_api.http.routers import evidence as route
    case_id, uid, n1, _n2, _edge = world
    ev = _exhibit(conn, case_id, uid)
    _link(conn, uid, ev, node_id=n1)
    claim = _carry(conn, case_id, uid, ev, node_id=n1)
    replacement = _replace(conn, case_id, uid, claim)
    [item] = route.backs(case_id, ev, user=_who(uid), conn=conn).items
    assert sorted(item.via) == ["ASSERTION", "LINK"]
    _withdraw(conn, uid, replacement)
    [item] = route.backs(case_id, ev, user=_who(uid), conn=conn).items
    assert item.via == ["LINK"], "a replaced claim still counted as a route"


def test_a_retracted_claims_exhibit_still_stops_backing(conn, world):
    """The rule the fix extends, held where it already held."""
    from noctornal_api.http.routers import evidence as route
    case_id, uid, n1, _n2, _edge = world
    ev = _exhibit(conn, case_id, uid)
    claim = _carry(conn, case_id, uid, ev, node_id=n1)
    assert _drawn_with_evidence(conn, case_id, node_id=n1) is True
    _withdraw(conn, uid, claim)
    assert _drawn_with_evidence(conn, case_id, node_id=n1) is False
    assert route.backs(case_id, ev, user=_who(uid), conn=conn).items == []


# --- retracting ----------------------------------------------------------------

def test_a_replaced_claim_is_history_and_is_not_retracted(conn, world):
    """`supersede_assertion` refuses a claim that is withdrawn or replaced, as history. Retraction is the
    same: the old row would be stamped as withdrawn by a person who withdrew nothing, and the audit log
    would say so."""
    from noctornal_api.graph import GraphWriteError
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers.graph import RetractBody, retract_assertion
    case_id, uid, n1, _n2, _edge = world
    claim = _carry(conn, case_id, uid, _exhibit(conn, case_id, uid), node_id=n1)
    replacement = _replace(conn, case_id, uid, claim)

    with pytest.raises(GraphWriteError, match="replaced"):
        _withdraw(conn, uid, claim)
    assert _row(conn, claim)[0] is None, "a replaced claim was stamped retracted"

    with pytest.raises(Problem) as refused:
        retract_assertion(case_id, claim, RetractBody(reason="not this one"),
                          user=_who(uid), conn=conn)
    assert refused.value.status == 409 and "replaced" in refused.value.detail
    assert _row(conn, claim)[0] is None
    assert conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE action = 'ASSERTION_RETRACTED' AND object_id = %s""",
        (claim,)).fetchone()[0] == 0

    # The claim that replaced it is live, and withdrawing it is how the replacement is undone.
    _withdraw(conn, uid, replacement)
    assert _row(conn, replacement)[0] is not None


def test_an_unknown_or_already_retracted_claim_is_still_refused(conn, world):
    from noctornal_api.graph import GraphWriteError
    case_id, uid, n1, _n2, _edge = world
    claim = _carry(conn, case_id, uid, _exhibit(conn, case_id, uid), node_id=n1)
    _withdraw(conn, uid, claim)
    with pytest.raises(GraphWriteError, match="already retracted"):
        _withdraw(conn, uid, claim)
    with pytest.raises(GraphWriteError, match="not found"):
        _withdraw(conn, uid, uuid4())


# --- the matrix ------------------------------------------------------------------

def _matrix_world(conn, world):
    """Two hypotheses, one claim on the first entity graded B2, and the stances an analyst put on it:
    strongly inconsistent with H1 and strongly consistent with H2, so H1 carries inconsistency."""
    case_id, uid, n1, _n2, _edge = world
    claim = conn.execute("SELECT id FROM core.assertion WHERE node_id = %s",
                         (n1,)).fetchone()[0]
    hyp = [conn.execute(
        """INSERT INTO core.hypothesis (case_id, statement, created_by)
           VALUES (%s, %s, %s) RETURNING id""",
        (case_id, text, uid)).fetchone()[0]
        for text in ("The handle is run by one person", "The handle is shared")]
    for hid, stance in zip(hyp, (-2, 2), strict=True):
        conn.execute(
            """INSERT INTO core.hypothesis_evidence
                   (hypothesis_id, assertion_id, stance, note) VALUES (%s, %s, %s, 'seen twice')""",
            (hid, claim, stance))
    return case_id, uid, claim, hyp


def _matrix(conn, case_id, uid):
    from noctornal_api.http.routers.ach import matrix
    return matrix(case_id, include_rejected=False, user=_who(uid), conn=conn)


def _scores(body):
    return {h["id"]: (h["inconsistency"], h["support"], h["assessed"])
            for h in body["hypotheses"]}


def test_a_stance_scores_while_its_claim_is_live(conn, world):
    """The control: the arithmetic the other tests take away from."""
    case_id, uid, claim, (h1, h2) = _matrix_world(conn, world)
    body = _matrix(conn, case_id, uid)
    assert _scores(body)[str(h1)][0] > 0 and _scores(body)[str(h2)][1] > 0
    [row] = body["evidence"]
    assert row["assertion_id"] == str(claim) and row["stale"] is False


@pytest.mark.parametrize("withdrawn", [False, True])
def test_a_stance_on_a_replaced_claim_is_kept_and_shown_stale_and_scores_nothing(
        conn, world, withdrawn):
    """The conservative rule. The claim was replaced, so what an analyst judged is the claim as it was
    recorded and the replacement carries a date and a new rationale: the stance stays in the record, is
    marked stale, and counts for nothing until somebody scores the replacement. Withdrawing the
    replacement changes nothing here: the old claim does not come back to life."""
    case_id, uid, claim, (h1, h2) = _matrix_world(conn, world)
    replacement = _replace(conn, case_id, uid, claim)
    if withdrawn:
        _withdraw(conn, uid, replacement)

    body = _matrix(conn, case_id, uid)
    assert _scores(body)[str(h1)] == (0.0, 0.0, 0), "a stance on a replaced claim still scored"
    assert _scores(body)[str(h2)] == (0.0, 0.0, 0)
    assert body["least_inconsistent"] is None, "a hypothesis was ranked on a replaced claim"
    [row] = body["evidence"]
    assert row["assertion_id"] == str(claim) and row["stale"] is True
    assert row["is_incomplete"] is False and row["is_diagnostic"] is False
    cells = {(c["hypothesis_id"], c["assertion_id"]): c for c in body["cells"]}
    assert cells[(str(h1), str(claim))]["stance"] == -2, "the stance was deleted, not shown stale"
    assert cells[(str(h2), str(claim))]["stance"] == 2
    assert any("replaced" in w for w in body["warnings"]), body["warnings"]
    assert conn.execute("SELECT count(*) FROM core.hypothesis_evidence WHERE assertion_id = %s",
                        (claim,)).fetchone()[0] == 2, "nothing is deleted from the record"


def test_a_stale_row_neither_fills_a_gap_nor_is_the_next_test(conn, world):
    """A replaced claim's blank cells are not owed a score: its row is not the cheapest next test."""
    case_id, uid, claim, (h1, _h2) = _matrix_world(conn, world)
    conn.execute("DELETE FROM core.hypothesis_evidence WHERE hypothesis_id = %s AND assertion_id = %s",
                 (h1, claim))
    assert _matrix(conn, case_id, uid)["refute_first"] == str(claim)
    _replace(conn, case_id, uid, claim)
    body = _matrix(conn, case_id, uid)
    assert body["refute_first"] is None
    assert all(not e["is_incomplete"] for e in body["evidence"])


def test_a_retracted_claim_still_leaves_the_matrix_altogether(conn, world):
    """Decision 24, held where it already held: a retracted claim is not a stale row, it is not there."""
    case_id, uid, claim, _hyp = _matrix_world(conn, world)
    _withdraw(conn, uid, claim)
    body = _matrix(conn, case_id, uid)
    assert body["evidence"] == [] and body["cells"] == []


def test_a_new_stance_cannot_be_put_on_a_replaced_claim_but_a_stale_one_can_be_cleared(conn, world):
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers import ach
    case_id, uid, claim, (h1, h2) = _matrix_world(conn, world)
    replacement = _replace(conn, case_id, uid, claim)

    with pytest.raises(Problem) as refused:
        ach.set_stance(case_id, h1, ach.StanceBody(assertion_id=claim, stance=1),
                       user=_who(uid), conn=conn)
    assert refused.value.status == 409 and "replaced" in refused.value.detail
    assert conn.execute(
        "SELECT stance FROM core.hypothesis_evidence WHERE hypothesis_id = %s AND assertion_id = %s",
        (h1, claim)).fetchone()[0] == -2, "the stale stance was overwritten"

    # The replacement is a live claim and takes a stance.
    ach.set_stance(case_id, h1, ach.StanceBody(assertion_id=replacement, stance=-1),
                   user=_who(uid), conn=conn)
    body = _matrix(conn, case_id, uid)
    assert _scores(body)[str(h1)][0] > 0
    assert {e["assertion_id"]: e["stale"] for e in body["evidence"]} == {
        str(claim): True, str(replacement): False}

    # A stale stance is cleared like any other, and the clearing is audited.
    out = ach.clear_stance(case_id, h2, claim, user=_who(uid), conn=conn)
    assert out["stance"] is None
    assert conn.execute(
        """SELECT count(*) FROM audit.event
            WHERE action = 'HYPOTHESIS_STANCE_CLEARED' AND object_id = %s""",
        (h2,)).fetchone()[0] == 1


def test_a_retracted_claim_still_takes_no_stance(conn, world):
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers import ach
    case_id, uid, claim, (h1, _h2) = _matrix_world(conn, world)
    _withdraw(conn, uid, claim)
    with pytest.raises(Problem) as refused:
        ach.set_stance(case_id, h1, ach.StanceBody(assertion_id=claim, stance=1),
                       user=_who(uid), conn=conn)
    assert refused.value.status == 404


def test_a_replaced_claims_label_above_the_ceiling_does_not_reach_the_reader(conn, world):
    """A stale row is still a row in the answer: the ceiling that hides a live row hides it too."""
    case_id, uid, _n1, _n2, _edge = world
    secret = _node(conn, case_id, uid, "RED-ONLY-HANDLE", classification="RED")
    claim = conn.execute("SELECT id FROM core.assertion WHERE node_id = %s",
                         (secret,)).fetchone()[0]
    hid = conn.execute(
        "INSERT INTO core.hypothesis (case_id, statement, created_by) VALUES (%s, 'H', %s) RETURNING id",
        (case_id, uid)).fetchone()[0]
    conn.execute("INSERT INTO core.hypothesis_evidence (hypothesis_id, assertion_id, stance) "
                 "VALUES (%s, %s, 1)", (hid, claim))
    _replace(conn, case_id, uid, claim)
    amber = _user(conn, clearance="AMBER", name="Amber Reader", global_roles=("ANALYST",))
    _assign(conn, case_id, amber, "ANALYST")
    assert "RED-ONLY-HANDLE" not in repr(_matrix(conn, case_id, amber))
    assert "RED-ONLY-HANDLE" in repr(_matrix(conn, case_id, uid)), "the control: the owner sees it"


# --- the report ---------------------------------------------------------------------

def _report(conn, case_id, uid):
    from noctornal_api.reports import ReportBuilder
    return ReportBuilder(conn).build(case_id, target_tlp="RED", generated_by=uid,
                                     include_hypotheses=True, compartments=frozenset())


def test_the_report_scores_without_a_replaced_claim_and_says_so(conn, world):
    """The report reads the matrix through the same `ach_cells` as GET /ach, so it prints the same
    scores: a document that went to a prosecutor must not rank a hypothesis on a claim that was
    replaced."""
    from noctornal_api.reports import render_markdown
    case_id, uid, claim, (h1, _h2) = _matrix_world(conn, world)
    assert {h["id"]: h for h in _report(conn, case_id, uid).hypotheses["hypotheses"]
            }[str(h1)]["inconsistency"] > 0, "the control: it scores while the claim is live"

    _replace(conn, case_id, uid, claim)
    report = _report(conn, case_id, uid)
    scored = {h["id"]: h for h in report.hypotheses["hypotheses"]}
    assert scored[str(h1)]["inconsistency"] == 0.0 and scored[str(h1)]["assessed"] == 0
    assert any("replaced" in w for w in report.hypotheses["warnings"])
    [why] = [r for r in report.hypotheses["reasoning"] if r["hypothesis"].endswith("one person")]
    assert "not scored" in why["stance"], "a stale stance's reasoning was printed as if it counted"
    assert "replaced" in render_markdown(report)
