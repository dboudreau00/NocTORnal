"""Invariant 3: machines propose, analysts dispose (docs/01, Phase 4).

    Extractors and inference jobs write to `proposal`. They never write to
    `node` or `edge` directly.

Until now this invariant was true by accident: `collect.proposal` had
existed since Phase 0 and nothing wrote it, because nothing extracts yet.
These tests make it true by construction instead — the extractor-facing
class cannot reach the graph, and the only path from a proposal into the
graph goes through a human reviewer.

Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; proposal test is gated"
)

EMAIL_LIKE = "pr-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
    c.close()


@pytest.fixture
def world(conn):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    uid = conn.execute(
        """INSERT INTO iam.app_user (email, display_name, password_hash, tlp_clearance)
           VALUES (%s, 'PR', 'x', 'RED') RETURNING id""",
        (f"pr-{uuid4().hex[:8]}@noctornal.test",),
    ).fetchone()[0]
    case_id = uuid4()
    conn.execute(
        """INSERT INTO core."case" (id, code, title, classification,
               owner_user_id, legal_basis, retention_until, review_due)
           VALUES (%s, %s, 'Proposal IT', 'AMBER', %s, 'dev',
                   '2028-01-01', '2027-01-01')""",
        (case_id, f"OP-PR-{uuid4().hex[:6]}", uid),
    )
    g = GraphWriteService(conn)
    a = AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid)
    n1 = g.create_node(case_id=case_id, node_type="IDENTITY", label="known_one",
                       created_by=uid, assertion=a)
    n2 = g.create_node(case_id=case_id, node_type="IDENTITY", label="known_two",
                       created_by=uid, assertion=a)
    return case_id, uid, n1, n2


def _store(conn):
    from noctornal_api.proposals import ProposalStore
    return ProposalStore(conn)


def _review(conn):
    from noctornal_api.proposals import ProposalReview
    return ProposalReview(conn)


def _counts(conn, case_id):
    return conn.execute(
        "SELECT count(*) FROM core.node WHERE case_id=%s", (case_id,)
    ).fetchone()[0], conn.execute(
        "SELECT count(*) FROM core.edge WHERE case_id=%s", (case_id,)
    ).fetchone()[0]


# --- invariant 3 ---------------------------------------------------------

def test_invariant_3_an_extractor_cannot_reach_the_graph(conn, world):
    """The extractor-facing class holds no GraphWriteService and has no
    method that writes a node or an edge. This is enforced by what the
    class IS, not by remembering not to call something."""
    from noctornal_api.proposals import ProposalStore
    forbidden = {"create_node", "create_edge", "add_assertion"}
    assert not (forbidden & set(dir(ProposalStore)))
    assert not any("graph" in a.lower() for a in vars(ProposalStore(conn)))


def test_invariant_3_proposing_writes_no_graph_element(conn, world):
    case_id, uid, n1, n2 = world
    before = _counts(conn, case_id)
    _store(conn).propose(
        case_id=case_id, kind="NODE", origin="handle_extractor_v1",
        payload={"node_type": "IDENTITY", "label": "suggested_persona"},
        rationale="handle appeared in 14 posts across 3 threads",
        score=0.82,
    )
    assert _counts(conn, case_id) == before


def test_invariant_3_only_review_puts_a_proposal_in_the_graph(conn, world):
    case_id, uid, n1, n2 = world
    pid = _store(conn).propose(
        case_id=case_id, kind="NODE", origin="handle_extractor_v1",
        payload={"node_type": "IDENTITY", "label": "suggested_persona"},
        rationale="handle appeared in 14 posts across 3 threads", score=0.82)
    nodes_before, _ = _counts(conn, case_id)
    row = _review(conn).accept(pid, reviewed_by=uid, note="checked the threads")
    nodes_after, _ = _counts(conn, case_id)
    assert nodes_after == nodes_before + 1
    assert row.state == "ACCEPTED"
    assert row.reviewed_by == uid
    assert row.applied_node_id is not None


def test_an_accepted_proposal_records_what_it_created(conn, world):
    """Otherwise there is no way back from a graph element to the machine
    suggestion that produced it."""
    case_id, uid, n1, n2 = world
    pid = _store(conn).propose(
        case_id=case_id, kind="EDGE", origin="co_occurrence_v2",
        payload={"edge_type": "COMMUNICATES_WITH",
                 "src_node_id": str(n1), "dst_node_id": str(n2)},
        rationale="posted within 90 seconds of each other in 14 threads")
    row = _review(conn).accept(pid, reviewed_by=uid)
    assert row.applied_edge_id is not None
    edge = conn.execute(
        "SELECT is_inferred, inference_method FROM core.edge WHERE id = %s",
        (row.applied_edge_id,)).fetchone()
    # Invariant 4: born inferred, and it says which extractor produced it.
    assert edge[0] is True
    assert edge[1] == "co_occurrence_v2"


def test_an_accepted_edge_stays_out_of_the_default_projection(conn, world):
    """Invariant 4 end to end: accepting a machine suggestion must not
    silently change anybody's centrality."""
    from noctornal_api.projections import GraphService, Projection
    case_id, uid, n1, n2 = world
    pid = _store(conn).propose(
        case_id=case_id, kind="EDGE", origin="co_occurrence_v2",
        payload={"edge_type": "COMMUNICATES_WITH",
                 "src_node_id": str(n1), "dst_node_id": str(n2)},
        rationale="temporal co-presence across 3 venues")
    _review(conn).accept(pid, reviewed_by=uid)
    svc = GraphService(conn, clearance="RED", compartments=frozenset())
    assert svc.project(Projection(case_id=case_id)).edges == []
    opted = svc.project(Projection(case_id=case_id, include_inferred=True))
    assert len(opted.edges) == 1


def test_an_accepted_proposal_creates_its_assertion_atomically(conn, world):
    """Invariant 1 is not weakened by the proposal path: an accepted
    suggestion is an analyst making a claim, not a back door."""
    case_id, uid, n1, n2 = world
    pid = _store(conn).propose(
        case_id=case_id, kind="NODE", origin="handle_extractor_v1",
        payload={"node_type": "IDENTITY", "label": "from_a_machine"},
        rationale="handle appeared in 14 posts")
    row = _review(conn).accept(pid, reviewed_by=uid)
    a = conn.execute(
        """SELECT basis, rationale, created_by, confidence
             FROM core.assertion WHERE node_id = %s""",
        (row.applied_node_id,)).fetchone()
    assert a[0] == "AUTOMATED_INFERENCE"
    # The rationale keeps the extractor's name and its words.
    assert "handle_extractor_v1" in a[1] and "14 posts" in a[1]
    # Attributed to the human who accepted it -- accountability is theirs.
    assert a[2] == uid
    # Accepting does not launder a machine guess into high confidence.
    assert a[3] == "LOW"


def test_a_proposal_cannot_be_applied_twice(conn, world):
    """Applying twice would create a second element from one suggestion and
    silently double an actor's degree."""
    from noctornal_api.proposals import ProposalError
    case_id, uid, n1, n2 = world
    pid = _store(conn).propose(
        case_id=case_id, kind="NODE", origin="x",
        payload={"node_type": "IDENTITY", "label": "once_only"},
        rationale="seen repeatedly")
    _review(conn).accept(pid, reviewed_by=uid)
    nodes_before, _ = _counts(conn, case_id)
    with pytest.raises(ProposalError, match="already been dispositioned"):
        _review(conn).accept(pid, reviewed_by=uid)
    assert _counts(conn, case_id)[0] == nodes_before


def test_an_accepted_proposal_cannot_be_re_dispositioned(conn, world):
    """Its element already exists; flipping the state would orphan the
    record of where that element came from."""
    from noctornal_api.proposals import ProposalError
    case_id, uid, n1, n2 = world
    pid = _store(conn).propose(
        case_id=case_id, kind="NODE", origin="x",
        payload={"node_type": "IDENTITY", "label": "settled"},
        rationale="seen repeatedly")
    _review(conn).accept(pid, reviewed_by=uid)
    with pytest.raises(ProposalError, match="retract the assertion"):
        _review(conn).reject(pid, reviewed_by=uid, note="changed my mind")


# --- what a proposal must carry -----------------------------------------

def test_a_proposal_must_explain_its_signal_in_words(conn, world):
    """docs/03: a bare 0.87 similarity score "will be either over-trusted
    or ignored"."""
    from noctornal_api.proposals import ProposalError
    case_id, *_ = world
    with pytest.raises(ProposalError, match="not reviewable"):
        _store(conn).propose(
            case_id=case_id, kind="NODE", origin="x",
            payload={"node_type": "IDENTITY", "label": "y"},
            rationale="   ", score=0.87)


def test_a_proposal_must_name_what_produced_it(conn, world):
    from noctornal_api.proposals import ProposalError
    case_id, *_ = world
    with pytest.raises(ProposalError, match="name what produced it"):
        _store(conn).propose(
            case_id=case_id, kind="NODE", origin="",
            payload={"node_type": "IDENTITY", "label": "y"},
            rationale="because")


def test_an_unknown_kind_is_refused(conn, world):
    from noctornal_api.proposals import ProposalError
    case_id, *_ = world
    with pytest.raises(ProposalError, match="unknown proposal kind"):
        _store(conn).propose(case_id=case_id, kind="DELETE_EVERYTHING",
                             origin="x", payload={}, rationale="because")


def test_a_score_outside_zero_to_one_is_refused(conn, world):
    from noctornal_api.proposals import ProposalError
    case_id, *_ = world
    with pytest.raises(ProposalError, match="between 0 and 1"):
        _store(conn).propose(case_id=case_id, kind="NODE", origin="x",
                             payload={"node_type": "IDENTITY", "label": "y"},
                             rationale="because", score=1.4)


def test_a_malformed_payload_fails_without_half_applying(conn, world):
    from noctornal_api.proposals import ProposalError
    case_id, uid, *_ = world
    pid = _store(conn).propose(
        case_id=case_id, kind="EDGE", origin="x",
        payload={"edge_type": "COMMUNICATES_WITH"},   # no endpoints
        rationale="incomplete on purpose")
    before = _counts(conn, case_id)
    with pytest.raises(ProposalError, match="missing"):
        _review(conn).accept(pid, reviewed_by=uid)
    assert _counts(conn, case_id) == before
    assert _store(conn).get(pid).state == "PROPOSED"


# --- the triage queue ----------------------------------------------------

def test_the_queue_surfaces_the_most_confident_first(conn, world):
    case_id, uid, *_ = world
    s = _store(conn)
    for label, score in (("low", 0.2), ("high", 0.9), ("mid", 0.5)):
        s.propose(case_id=case_id, kind="NODE", origin="x",
                  payload={"node_type": "IDENTITY", "label": label},
                  rationale="seen", score=score)
    labels = [p.payload["label"] for p in s.queue(case_id)]
    assert labels == ["high", "mid", "low"]


def test_dispositioned_proposals_leave_the_queue(conn, world):
    case_id, uid, *_ = world
    s = _store(conn)
    keep = s.propose(case_id=case_id, kind="NODE", origin="x",
                     payload={"node_type": "IDENTITY", "label": "keep"},
                     rationale="seen", score=0.5)
    drop = s.propose(case_id=case_id, kind="NODE", origin="x",
                     payload={"node_type": "IDENTITY", "label": "drop"},
                     rationale="seen", score=0.4)
    _review(conn).reject(drop, reviewed_by=uid, note="forum signature block")
    assert [p.id for p in s.queue(case_id)] == [keep]
    assert s.counts(case_id)["REJECTED"] == 1


def test_an_ambiguous_proposal_can_be_deferred_rather_than_forced(conn, world):
    """A queue whose only options are yes and no forces a decision on items
    that do not deserve one yet, and that is how junk gets accepted."""
    case_id, uid, *_ = world
    s = _store(conn)
    pid = s.propose(case_id=case_id, kind="NODE", origin="x",
                    payload={"node_type": "IDENTITY", "label": "maybe"},
                    rationale="one weak co-occurrence", score=0.3)
    row = _review(conn).defer(pid, reviewed_by=uid,
                              note="need a second sighting before accepting")
    assert row.state == "DISPUTED"
    assert s.queue(case_id) == []
    assert len(s.queue(case_id, state="DISPUTED")) == 1


def test_a_rejection_must_say_why(conn, world):
    """Parser drift is found by reading these."""
    from noctornal_api.proposals import ProposalError
    case_id, uid, *_ = world
    pid = _store(conn).propose(
        case_id=case_id, kind="NODE", origin="x",
        payload={"node_type": "IDENTITY", "label": "y"}, rationale="seen")
    with pytest.raises(ProposalError, match="say why"):
        _review(conn).reject(pid, reviewed_by=uid, note="  ")


def test_every_disposition_is_audited(conn, world):
    case_id, uid, *_ = world
    s = _store(conn)
    accepted = s.propose(case_id=case_id, kind="NODE", origin="ext",
                         payload={"node_type": "IDENTITY", "label": "a"},
                         rationale="seen")
    rejected = s.propose(case_id=case_id, kind="NODE", origin="ext",
                         payload={"node_type": "IDENTITY", "label": "b"},
                         rationale="seen")
    _review(conn).accept(accepted, reviewed_by=uid)
    _review(conn).reject(rejected, reviewed_by=uid, note="boilerplate")
    actions = {r[0] for r in conn.execute(
        """SELECT action FROM audit.event
            WHERE case_id = %s AND object_type = 'proposal'""",
        (case_id,)).fetchall()}
    assert actions == {"PROPOSAL_ACCEPTED", "PROPOSAL_REJECTED"}


def test_an_attribute_proposal_becomes_an_assertion_not_a_column(conn, world):
    """A claim about an entity is an assertion with a claim_path, which is
    what makes it retractable and disputable like any other claim."""
    case_id, uid, n1, _n2 = world
    pid = _store(conn).propose(
        case_id=case_id, kind="ATTRIBUTE", origin="role_classifier_v1",
        payload={"node_id": str(n1), "claim_path": "attrs.role",
                 "claim_value": {"role": "initial access broker"}},
        rationale="advertised access in 6 posts", score=0.7)
    _review(conn).accept(pid, reviewed_by=uid)
    a = conn.execute(
        """SELECT claim_path, claim_value, basis FROM core.assertion
            WHERE node_id = %s AND claim_path IS NOT NULL""", (n1,)).fetchone()
    assert a[0] == "attrs.role"
    assert a[1] == {"role": "initial access broker"}
    assert a[2] == "AUTOMATED_INFERENCE"
