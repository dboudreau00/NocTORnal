"""A merge, its reversal and its approval are visible only where both of the
entities they name are (beta review, 2026-10-03).

The findings, each held here by a test that fails without its fix:

- rls-1, graph-merge-ledger-and-approvals-leak: the merge ledger served every
  merge of the case, with both entity ids and the merger's free reason, to
  every case reader, merges of entities above them included.
- graph-merge-no-element-label-gate, http_ui-001: merge and reverse never
  resolved the entities they named, so a caller below an entity merged it
  away, or reversed the merge of it, by id, and a hidden id answered 201
  where a random one answered 409. The survivor also kept its own lower
  labels, so a RED entity's AMBER ties were shown at the survivor's label.
- http_ui-011: a node.merge approval was listed, with both ids, the reason
  and the justification, to every case reader, raised against any id, and
  signed by someone shown `subjects` of None.
- graph-unmerge-500-and-ties-to-merged-nodes: a reversal that would
  duplicate a live tie was a 500.
- graph-unmerge-loses-ties-after-target-retired: retiring the surviving side
  of a live merge, then reversing it, said ties were restored that stayed
  retired.

Everything runs through the real route as the request role, seeded as the
owner. `core.node_merge`'s own policy (0132) is held at the database as well.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest

import review_g42_support as g
import rls_support as s

pytestmark = g.GATED

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
SECRET = "g42 SECRET same PGP key as the informant"
JUSTIFICATION = "g42 SECRET justification: the informant's second handle"


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


def _merge(client, w, uid, source, target, reason="same operator behind both"):
    return client.post(
        w.url("/merges"), headers=w.headers(uid),
        json={"source_node_id": str(source), "target_node_id": str(target),
              "reason": reason})


def _merged_flag(owner, node) -> bool:
    return owner.execute("SELECT merged_into_id IS NOT NULL FROM core.node "
                         "WHERE id = %s", (node,)).fetchone()[0]


def _service_merge(owner, w, source, target, reason="same operator", by=None):
    from noctornal_api.merges import MergeService
    return MergeService(owner).merge(
        case_id=w.case_id, source_node_id=source, target_node_id=target,
        merged_by=by or w.boss, reason=reason)


# --- the ledger (rls-1, graph-merge-ledger-and-approvals-leak) --------------

def test_the_ledger_shows_a_reader_only_the_merges_of_entities_they_can_read(
        owner, client):
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    amber1, amber2 = w.node("g42 amber one"), w.node("g42 amber two")
    amber_into_red = w.node("g42 amber handle")
    assert _merge(client, w, w.boss, red2, red1, SECRET).status_code == 201
    assert _merge(client, w, w.boss, amber2, amber1,
                  "same handle, spelled twice").status_code == 201
    # A visible entity merged into a RED survivor: the merge names a RED one.
    assert _merge(client, w, w.boss, amber_into_red, red1,
                  "an amber handle of the red one").status_code == 201

    for who in (w.lead, w.analyst, w.reader):
        r = client.get(w.url("/merges"), headers=w.headers(who))
        assert r.status_code == 200, r.text
        assert [m["reason"] for m in r.json()["merges"]] == [
            "same handle, spelled twice"]
        for hidden in (SECRET, "informant", str(red1), str(red2),
                       str(amber_into_red), "an amber handle of the red one"):
            assert hidden not in r.text, hidden

    r = client.get(w.url("/merges"), headers=w.headers(w.boss))
    assert len(r.json()["merges"]) == 3


def test_the_ledger_says_what_it_left_out_as_the_case_allows(owner, client):
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    amber1, amber2 = w.node("g42 amber one"), w.node("g42 amber two")
    assert _merge(client, w, w.boss, red2, red1, SECRET).status_code == 201
    assert _merge(client, w, w.boss, amber2, amber1).status_code == 201

    def ledger(uid, mode):
        w.disclose(mode)
        return client.get(w.url("/merges"), headers=w.headers(uid)).json()

    # NONE: nothing at all, since "nothing withheld" is itself an answer.
    assert set(ledger(w.analyst, "NONE")) == {"merges"}
    assert ledger(w.analyst, "PRESENCE")["withheld"] == {
        "incomplete": True, "mode": "PRESENCE"}
    assert ledger(w.analyst, "COUNT")["withheld"] == {
        "incomplete": True, "mode": "COUNT", "merges": 1}
    # A reader who is shown everything is told so, under the modes that say.
    assert ledger(w.boss, "COUNT")["withheld"] == {
        "incomplete": False, "mode": "COUNT"}
    assert set(ledger(w.boss, "NONE")) == {"merges"}


def test_the_policy_shows_the_request_role_a_merge_only_when_both_ends_are_visible(
        owner):
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    amber1, amber2, amber3 = (w.node("g42 amber one"), w.node("g42 amber two"),
                              w.node("g42 amber three"))
    mixed = w.node("g42 amber mixed")
    w.edge(red2, amber1)
    w.edge(amber2, amber3)
    w.edge(mixed, amber3)
    _service_merge(owner, w, red2, red1, SECRET)
    _service_merge(owner, w, amber2, amber1, "visible")
    _service_merge(owner, w, mixed, red1, "one end is red")

    def seen(uid, sql):
        _, raw = s.session(owner, uid)
        conn = s.app_conn(raw)
        try:
            return conn.execute(sql, (w.case_id,)).fetchone()[0]
        finally:
            conn.close()

    merges = "SELECT count(*) FROM core.node_merge WHERE case_id = %s"
    moved = ("SELECT count(*) FROM core.node_merge_edge e JOIN core.node_merge m "
             "ON m.id = e.merge_id WHERE m.case_id = %s")
    assert seen(w.analyst, merges) == 1
    assert seen(w.boss, merges) == 3
    # What a merge moved follows the merge (0123's CHILD template).
    assert seen(w.analyst, moved) == 1
    assert seen(w.boss, moved) == 3
    # The system role still counts every merge, as the withheld count needs.
    from noctornal_api.db import SystemPurpose, system_connection
    from noctornal_api.merges import MergeService
    with system_connection(SystemPurpose.WITHHELD, reuse=owner) as counter:
        assert MergeService(counter).count_hidden_from_reader(
            w.case_id, clearance="AMBER", compartments=frozenset()) == 2


# --- merge and reverse (graph-merge-no-element-label-gate, http_ui-001) -----

def test_reversing_a_merge_the_caller_cannot_see_is_the_answer_for_no_such_merge(
        owner, client):
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    made = _merge(client, w, w.boss, red2, red1, SECRET)
    assert made.status_code == 201
    merge_id = made.json()["id"]

    probe = {"reason": "g42 probe: a merge I cannot see"}
    hit = client.post(w.url(f"/merges/{merge_id}/reverse"),
                      headers=w.headers(w.lead), json=probe)
    miss = client.post(w.url(f"/merges/{uuid4()}/reverse"),
                       headers=w.headers(w.lead), json=probe)
    assert g.answer(hit) == g.answer(miss) == (404, "no such merge in this case")
    assert _merged_flag(owner, red2), "the merge was reversed by someone below it"

    # The cleared owner still reverses it: nothing a legitimate caller could
    # do is taken away.
    ok = client.post(w.url(f"/merges/{merge_id}/reverse"),
                     headers=w.headers(w.boss), json={"reason": "wrong call"})
    assert ok.status_code == 200, ok.text
    assert not _merged_flag(owner, red2)


def test_a_reader_still_reverses_a_merge_of_entities_they_can_read(owner, client):
    w = g.World(owner)
    a, b = w.node("g42 a"), w.node("g42 b")
    made = _merge(client, w, w.lead, a, b)
    assert made.status_code == 201, made.text
    ok = client.post(w.url(f"/merges/{made.json()['id']}/reverse"),
                     headers=w.headers(w.analyst), json={"reason": "wrong call"})
    assert ok.status_code == 200, ok.text
    assert not _merged_flag(owner, a)


def test_a_merge_naming_a_node_above_the_caller_is_the_missing_node(owner, client):
    w = g.World(owner)
    red = w.node("g42 red source", "RED")
    keeper, contact = w.node("g42 keeper"), w.node("g42 contact")
    w.edge(red, contact, "AMBER")
    assert client.get(w.url(f"/nodes/{red}"),
                      headers=w.headers(w.lead)).status_code == 404
    before = client.get(w.url("/edges"), headers=w.headers(w.lead)).json()

    for position in ("source", "target"):
        def attempt(hidden_or_random, position=position):
            pair = ((hidden_or_random, keeper) if position == "source"
                    else (keeper, hidden_or_random))
            return _merge(client, w, w.lead, *pair, reason="g42 probe")

        hit, miss = attempt(red), attempt(uuid4())
        assert g.answer(hit) == g.answer(miss) == (
            404, "no such node in this case"), position
    assert not _merged_flag(owner, red)
    # No tie of the hidden entity appeared on the lead's graph.
    assert client.get(w.url("/edges"), headers=w.headers(w.lead)).json() == before


def test_a_merge_may_not_show_an_entitys_ties_at_the_survivors_lower_labels(
        owner, client):
    """graph-merge-no-element-label-gate, second half: the survivor keeps its
    own labels and takes every tie of the entity merged into it, so a RED
    entity's AMBER-labelled tie, hidden because one end is RED, became a
    visible tie of an AMBER survivor."""
    from noctornal_api.merges import MergeError
    w = g.World(owner)
    red = w.node("g42 red", "RED")
    contact, keeper = w.node("g42 contact"), w.node("g42 keeper")
    w.edge(red, contact, "AMBER")

    refused = _merge(client, w, w.boss, red, keeper)
    assert refused.status_code == 409, refused.text
    assert "less restricted" in refused.json()["detail"]
    assert not _merged_flag(owner, red)
    assert client.get(w.url("/edges"), headers=w.headers(w.lead)).json() == []
    with pytest.raises(MergeError, match="less restricted"):
        _service_merge(owner, w, red, keeper)

    # Nothing a legitimate caller could do is taken away: the other way
    # round, into the more restricted survivor, and between equals.
    assert _merge(client, w, w.boss, keeper, red).status_code == 201
    a, b = w.node("g42 a"), w.node("g42 b")
    assert _merge(client, w, w.boss, a, b).status_code == 201


def test_a_compartmented_entity_may_not_be_merged_into_an_open_survivor(
        owner, client):
    w = g.World(owner)
    walled_boss = s.user(owner, "RED", (s.COMPARTMENT,), prefix=g.PREFIX)
    s.assign(owner, w.case_id, walled_boss, "CASE_OWNER")
    walled = s.node(owner, w.case_id, walled_boss, "g42 walled", "AMBER",
                    (s.COMPARTMENT,))
    open_survivor = w.node("g42 open survivor")
    refused = _merge(client, w, walled_boss, walled, open_survivor)
    assert refused.status_code == 409, refused.text
    assert "less restricted" in refused.json()["detail"]
    ok = _merge(client, w, walled_boss, open_survivor, walled)
    assert ok.status_code == 201, ok.text


def test_a_merge_reports_only_the_ties_its_merger_can_see(owner, client):
    """The counts a merge answers with are the merger's own view: a tie to an
    entity above them is counted nowhere they can read."""
    w = g.World(owner)
    a, b = w.node("g42 a"), w.node("g42 b")
    visible, red = w.node("g42 visible tie"), w.node("g42 red tie", "RED")
    w.edge(a, visible)
    w.edge(a, red, "AMBER")
    made = _merge(client, w, w.lead, a, b)
    assert made.status_code == 201, made.text
    assert made.json()["edges_repointed"] == 1
    from noctornal_api.merges import MergeService
    assert MergeService(owner).get(made.json()["id"]).edges_repointed == 2


# --- approvals (http_ui-011) -------------------------------------------------

def _payload(source, target, reason="g42 SECRET reason text"):
    return {"source_node_id": str(source), "target_node_id": str(target),
            "reason": reason, "basis_selector_id": None}


def _raise(client, w, uid, source, target, justification=JUSTIFICATION,
           reason="g42 SECRET reason text"):
    return client.post(
        w.url("/approvals"), headers=w.headers(uid),
        json={"operation": "node.merge",
              "payload": _payload(source, target, reason),
              "justification": justification})


def test_the_approvals_list_shows_a_merge_request_only_where_both_nodes_are_visible(
        owner, client):
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    a, b = w.node("g42 a"), w.node("g42 b")
    assert _raise(client, w, w.boss, red2, red1).status_code == 201
    assert _raise(client, w, w.boss, a, b, "g42 plain justification",
                  "g42 plain reason").status_code == 201

    for who in (w.lead, w.analyst, w.reader):
        r = client.get(w.url("/approvals"), headers=w.headers(who))
        assert r.status_code == 200, r.text
        rows = r.json()["approvals"]
        assert [x["justification"] for x in rows] == ["g42 plain justification"]
        for hidden in ("SECRET", str(red1), str(red2), "informant"):
            assert hidden not in r.text, hidden
    assert len(client.get(w.url("/approvals"), headers=w.headers(w.boss)
                          ).json()["approvals"]) == 2


def test_the_approvals_list_says_what_it_left_out_as_the_case_allows(
        owner, client):
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    assert _raise(client, w, w.boss, red2, red1).status_code == 201

    def listing(uid, mode, state=None):
        w.disclose(mode)
        query = f"?state={state}" if state else ""
        return client.get(w.url("/approvals" + query),
                          headers=w.headers(uid)).json()

    assert "withheld" not in listing(w.analyst, "NONE")
    assert listing(w.analyst, "PRESENCE")["withheld"] == {
        "incomplete": True, "mode": "PRESENCE"}
    assert listing(w.analyst, "COUNT")["withheld"] == {
        "incomplete": True, "mode": "COUNT", "requests": 1}
    # Counted under the listing's own state filter, over the whole case.
    assert listing(w.analyst, "COUNT", "CONSUMED")["withheld"] == {
        "incomplete": False, "mode": "COUNT"}


def test_a_page_is_cut_after_the_requests_the_viewer_cannot_see_are_left_out(
        owner, client):
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    a, b = w.node("g42 a"), w.node("g42 b")
    assert _raise(client, w, w.boss, a, b, "g42 plain", "g42 plain reason"
                  ).status_code == 201
    for n in range(3):
        assert _raise(client, w, w.boss, red2, red1, JUSTIFICATION,
                      f"g42 SECRET reason {n}").status_code == 201
    page = client.get(w.url("/approvals?limit=1"), headers=w.headers(w.analyst))
    assert [x["justification"] for x in page.json()["approvals"]] == ["g42 plain"]


def test_a_merge_request_names_two_entities_the_requester_may_merge(owner, client):
    w = g.World(owner)
    red = w.node("g42 red", "RED")
    a, b = w.node("g42 a"), w.node("g42 b")
    other_case_owner = s.user(owner, "RED", prefix=g.PREFIX)
    other_case = s.case(owner, other_case_owner, "AMBER")
    foreign = s.node(owner, other_case, other_case_owner, "g42 foreign")

    for position in ("source", "target"):
        def attempt(named, position=position):
            pair = (named, b) if position == "source" else (a, named)
            return _raise(client, w, w.analyst, *pair)

        hit, miss = attempt(red), attempt(uuid4())
        assert g.answer(hit) == g.answer(miss) == (
            404, "no such node in this case"), position
        assert g.answer(attempt(foreign)) == g.answer(miss), position
    malformed = client.post(
        w.url("/approvals"), headers=w.headers(w.analyst),
        json={"operation": "node.merge", "payload": {"reason": "x"},
              "justification": "g42"})
    assert malformed.status_code == 400
    assert owner.execute(
        "SELECT count(*) FROM core.approval_request WHERE case_id = %s",
        (w.case_id,)).fetchone()[0] == 0
    # A request naming two entities they may merge is still raised.
    assert _raise(client, w, w.analyst, a, b).status_code == 201


def test_a_signer_who_cannot_see_both_entities_cannot_decide_or_withdraw(
        owner, client):
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    second = s.user(owner, "RED", prefix=g.PREFIX)
    s.assign(owner, w.case_id, second, "CASE_OWNER")
    raised = _raise(client, w, w.boss, red2, red1)
    assert raised.status_code == 201, raised.text
    request_id = raised.json()["id"]
    state = lambda: owner.execute(  # noqa: E731
        "SELECT state FROM core.approval_request WHERE id = %s",
        (request_id,)).fetchone()[0]

    below = client.post(w.url(f"/approvals/{request_id}/decide"),
                        headers=w.headers(w.lead),
                        json={"approve": True, "note": "g42"})
    missing = client.post(w.url(f"/approvals/{uuid4()}/decide"),
                          headers=w.headers(w.lead),
                          json={"approve": True, "note": "g42"})
    assert g.answer(below) == g.answer(missing) == (
        404, "no such approval request in this case")
    assert "SECRET" not in below.text and str(red1) not in below.text
    assert state() == "PENDING"

    # A requester who can no longer see the entities cannot read the request
    # back through a withdrawal either.
    owner.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s",
                  (w.boss,))
    gone = client.post(w.url(f"/approvals/{request_id}/withdraw"),
                       headers=w.headers(w.boss))
    assert g.answer(gone) == (404, "no such approval request in this case")
    assert state() == "PENDING"
    owner.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                  (w.boss,))

    # The cleared second signer decides it: nothing taken from a legitimate one.
    ok = client.post(w.url(f"/approvals/{request_id}/decide"),
                     headers=w.headers(second),
                     json={"approve": True, "note": "g42"})
    assert ok.status_code == 200, ok.text
    assert state() == "APPROVED"


def test_a_merge_request_is_told_only_to_signers_who_can_read_what_it_names(
        owner, client):
    """The notice quotes the justification, so it carries the stricter of the
    two entities' labels and a signer below them is not sent it."""
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    a, b = w.node("g42 a"), w.node("g42 b")
    second = s.user(owner, "RED", prefix=g.PREFIX)
    s.assign(owner, w.case_id, second, "CASE_OWNER")

    def told(request_id):
        return {r[0] for r in owner.execute(
            "SELECT recipient_id FROM notify.notification "
            "WHERE kind = 'APPROVAL_REQUESTED' AND object_id = %s",
            (request_id,)).fetchall()}

    red = _raise(client, w, w.boss, red2, red1)
    plain = _raise(client, w, w.boss, a, b, "g42 plain")
    assert told(red.json()["id"]) == {second}
    assert red.json()["approvers_notified"] == 1
    # Every signer below the stricter label is told of the plain one.
    assert told(plain.json()["id"]) == {second, w.lead, w.analyst}


def test_a_signers_pending_count_leaves_out_the_requests_they_cannot_read(
        owner, client):
    from noctornal_api.approvals import ApprovalService
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    a, b = w.node("g42 a"), w.node("g42 b")
    assert _raise(client, w, w.boss, red2, red1).status_code == 201
    count = lambda clearance: ApprovalService(owner).awaiting_signature(  # noqa: E731
        w.lead, clearance=clearance, compartments=frozenset()
    ).get(str(w.case_id), 0)
    assert count("AMBER") == 0
    assert _raise(client, w, w.boss, a, b, "g42 plain").status_code == 201
    assert count("AMBER") == 1
    assert count("RED") == 2


def test_spending_an_approval_needs_the_merger_to_still_read_both_entities(
        owner, client):
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    second = s.user(owner, "RED", prefix=g.PREFIX)
    s.assign(owner, w.case_id, second, "CASE_OWNER")
    owner.execute('UPDATE core."case" SET dual_control_merge = true WHERE id = %s',
                  (w.case_id,))
    raised = _raise(client, w, w.boss, red2, red1)
    assert raised.status_code == 201, raised.text
    request_id = raised.json()["id"]
    assert client.post(w.url(f"/approvals/{request_id}/decide"),
                       headers=w.headers(second),
                       json={"approve": True, "note": "g42"}).status_code == 200

    owner.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s",
                  (w.boss,))
    body = {"approval_request_id": request_id}
    refused = client.post(w.url("/merges"), headers=w.headers(w.boss), json=body)
    # The sentence for an approval that is not there (second round): a
    # request naming entities above the caller is not theirs to have seen.
    assert g.answer(refused) == (404, "no such approval request in this case")
    assert owner.execute("SELECT state FROM core.approval_request WHERE id = %s",
                         (request_id,)).fetchone()[0] == "APPROVED"
    assert not _merged_flag(owner, red2)

    owner.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s",
                  (w.boss,))
    ok = client.post(w.url("/merges"), headers=w.headers(w.boss), json=body)
    assert ok.status_code == 201, ok.text
    assert _merged_flag(owner, red2)


def test_a_hidden_merge_requests_id_is_the_missing_requests_answer_whoever_asks(
        owner, client):
    """Second round (graph-merge-approval-hidden): a caller without the
    signer permission was told 403 for a request naming entities above them
    and 404 for a random id, and spending such a request answered
    "no such node" where a random id answered "no such approval request"."""
    w = g.World(owner)
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    owner.execute('UPDATE core."case" SET dual_control_merge = true WHERE id = %s',
                  (w.case_id,))
    raised = _raise(client, w, w.boss, red2, red1)
    assert raised.status_code == 201, raised.text
    request_id = raised.json()["id"]
    missing = (404, "no such approval request in this case")

    for who in (w.reader, w.lead):
        hidden = client.post(w.url(f"/approvals/{request_id}/decide"),
                             headers=w.headers(who),
                             json={"approve": True, "note": "g42"})
        random = client.post(w.url(f"/approvals/{uuid4()}/decide"),
                             headers=w.headers(who),
                             json={"approve": True, "note": "g42"})
        assert g.answer(hidden) == g.answer(random) == missing, who

    spent = client.post(w.url("/merges"), headers=w.headers(w.lead),
                        json={"approval_request_id": request_id})
    random_spend = client.post(w.url("/merges"), headers=w.headers(w.lead),
                               json={"approval_request_id": str(uuid4())})
    assert g.answer(spent) == g.answer(random_spend) == missing
    assert owner.execute("SELECT state FROM core.approval_request WHERE id = %s",
                         (request_id,)).fetchone()[0] == "PENDING"


# --- the redirect pointer (graph-merged-into-pointer, second round) -----------

def _merged_into(client, w, uid, node):
    """What PATCH on a merged-away entity and the working set's listing say
    the survivor is."""
    from noctornal_api.curation import NodeSetService
    patched = client.patch(w.url(f"/graph/nodes/{node}"), headers=w.headers(uid),
                           json={"label": "g42 renamed", "assertion": g.CLAIM})
    assert patched.status_code == 200, patched.text
    set_id = NodeSetService(w.owner).create_set(
        case_id=w.case_id, name=f"g42 set {uuid4().hex[:6]}", created_by=w.boss)
    NodeSetService(w.owner).add_member(set_id, node)
    listed = client.get(w.url(f"/curation/sets/{set_id}/members"),
                        headers=w.headers(uid))
    assert listed.status_code == 200, listed.text
    members = listed.json()["merged_away"]
    assert [m["node_id"] for m in members] == [str(node)]
    return patched.json(), members[0]["merged_into_id"]


def test_the_survivor_of_a_merge_is_named_only_to_a_reader_who_may_read_it(
        owner, client):
    """An AMBER entity folded into a RED survivor is an alias of it; the
    ledger withholds the merge for exactly that, and the redirect pointer
    was the one place it was still said."""
    w = g.World(owner)
    amber_into_red, amber_into_amber = w.node("g42 amber a"), w.node("g42 amber b")
    red, amber_survivor = w.node("g42 red survivor", "RED"), w.node("g42 amber s")
    assert _merge(client, w, w.boss, amber_into_red, red).status_code == 201
    assert _merge(client, w, w.boss, amber_into_amber, amber_survivor).status_code == 201

    patched, listed = _merged_into(client, w, w.analyst, amber_into_red)
    assert patched["merged_into_id"] is None and listed is None
    assert str(red) not in str(patched) and "note" in patched
    assert patched["note"]
    # A survivor the reader may read is still named: nothing taken from them.
    patched, listed = _merged_into(client, w, w.analyst, amber_into_amber)
    assert patched["merged_into_id"] == listed == str(amber_survivor)
    # And the cleared owner of the RED survivor is told, as before.
    patched, listed = _merged_into(client, w, w.boss, amber_into_red)
    assert patched["merged_into_id"] == listed == str(red)


def test_a_duplicate_tie_refusal_names_the_third_party_only_to_a_merger_who_may_read_it(
        owner, client):
    """A merge that would give one entity two live ties of a type to one third
    party is refused. The sentence named the third party, and so that two ties
    to it existed, whoever the merger was (and, for an outgoing tie, named the
    merge's own target in its place)."""
    w = g.World(owner)
    source, target = w.node("g42 source"), w.node("g42 target")
    open_third = w.node("g42 third party")
    w.edge(source, open_third)
    w.edge(target, open_third)
    refused = _merge(client, w, w.lead, source, target)
    assert refused.status_code == 409, refused.text
    detail = refused.json()["detail"]
    assert "VOUCHED_FOR" in detail and "already exists" not in detail
    assert str(open_third) in detail and str(target) not in detail

    # Ties to a third party the merger cannot read are theirs to see neither,
    # so the merge is made as one with no such tie is and the duplicate is set
    # aside (verification round three, A2, 2026-10-07). This block asserted the
    # refusal, which told an AMBER lead that two ties to a RED entity existed.
    source2, target2 = w.node("g42 source two"), w.node("g42 target two")
    red_third = w.node("g42 red third party", "RED")
    w.edge(source2, red_third, "AMBER")
    w.edge(target2, red_third, "AMBER")
    made = _merge(client, w, w.lead, source2, target2)
    assert made.status_code == 201, made.text
    assert str(red_third) not in made.text
    assert not _merged_flag(owner, source) and _merged_flag(owner, source2)


# --- the reversal's two failures ---------------------------------------------

def test_a_reversal_that_would_duplicate_a_live_tie_is_a_conflict_not_a_500(
        owner, client):
    """graph-unmerge-500-and-ties-to-merged-nodes. A tie recorded against the
    merged-away entity by a writer that does not go through the route (the
    service takes any endpoint) made the reversal's UPDATE meet
    edge_uniq_active, which reached the catch-all as a 500."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    from noctornal_api.merges import MergeError, MergeService
    w = g.World(owner)
    a, b, c = w.node("g42 a"), w.node("g42 b"), w.node("g42 c")
    w.edge(a, c)
    merge = _service_merge(owner, w, a, b)
    GraphWriteService(owner).create_edge(
        case_id=w.case_id, edge_type="VOUCHED_FOR", src_node_id=a, dst_node_id=c,
        created_by=w.boss, classification="AMBER",
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=w.boss))

    reversed_ = client.post(w.url(f"/merges/{merge.id}/reverse"),
                            headers=w.headers(w.boss), json={"reason": "wrong"})
    assert reversed_.status_code == 409, reversed_.text
    assert "VOUCHED_FOR" in reversed_.json()["detail"]
    assert "Retire the later tie" in reversed_.json()["detail"]
    with pytest.raises(MergeError, match="VOUCHED_FOR"):
        MergeService(owner).unmerge(merge.id, reversed_by=w.boss, reason="again")
    # Refused whole: still merged, and the record says so.
    assert _merged_flag(owner, a)
    assert MergeService(owner).get(merge.id).is_live


def test_a_tie_retired_after_the_merge_is_not_counted_as_restored(owner):
    """graph-unmerge-loses-ties-after-target-retired. A reversal gives every
    tie its endpoints back and, rightly, leaves retired the ones an analyst
    retired; the audit row said they were all restored."""
    from datetime import datetime, timezone

    from noctornal_api.graph import GraphWriteService
    from noctornal_api.merges import MergeService
    w = g.World(owner)
    a, b, c, d = (w.node("g42 a"), w.node("g42 b"), w.node("g42 c"),
                  w.node("g42 d"))
    w.edge(a, c)
    retired = w.edge(a, d)
    merge = _service_merge(owner, w, a, b)
    GraphWriteService(owner).soft_delete_edge(
        retired, case_id=w.case_id, deleted_by=w.boss,
        at=datetime.now(timezone.utc))

    MergeService(owner).unmerge(merge.id, reversed_by=w.boss, reason="wrong")
    detail = owner.execute(
        "SELECT detail FROM audit.event WHERE action = 'NODE_UNMERGED' "
        "AND object_id = %s", (merge.id,)).fetchone()[0]
    assert (detail["edges_restored"], detail["edges_left_retired"]) == (1, 1)
    assert owner.execute("SELECT deleted_at IS NOT NULL FROM core.edge "
                         "WHERE id = %s", (retired,)).fetchone()[0]


def test_the_surviving_side_of_a_live_merge_cannot_be_retired(owner, client):
    """The same order the route refuses for the merged-away side: retiring the
    survivor retired the ties the merge had moved onto it, and the reversal
    gave them back still retired."""
    w = g.World(owner)
    a, b, c = w.node("g42 a"), w.node("g42 b"), w.node("g42 c")
    tie = w.edge(a, c)
    made = _merge(client, w, w.lead, a, b)
    assert made.status_code == 201, made.text

    refused = client.request("DELETE", w.url(f"/graph/nodes/{b}"),
                             headers=w.headers(w.lead), json={"reason": "retire"})
    assert refused.status_code == 409, refused.text
    assert made.json()["id"] in refused.json()["detail"]
    assert owner.execute("SELECT deleted_at IS NULL FROM core.node WHERE id = %s",
                         (b,)).fetchone()[0]
    assert owner.execute("SELECT deleted_at IS NULL FROM core.edge WHERE id = %s",
                         (tie,)).fetchone()[0]

    # Reversed, the survivor retires as before.
    assert client.post(w.url(f"/merges/{made.json()['id']}/reverse"),
                       headers=w.headers(w.lead),
                       json={"reason": "wrong"}).status_code == 200
    assert client.request("DELETE", w.url(f"/graph/nodes/{b}"),
                          headers=w.headers(w.lead),
                          json={"reason": "retire"}).status_code == 200


def test_retiring_a_survivor_whose_merge_is_hidden_names_nothing(owner, client):
    """A live merge into the entity that the caller cannot see the merged side
    of is refused in the words of the hidden-ties refusal, which already owns
    up to material above the caller and names nothing."""
    w = g.World(owner)
    red, keeper = w.node("g42 red", "RED"), w.node("g42 keeper")
    contact = w.node("g42 contact")
    w.edge(contact, keeper)
    # A RED entity merged into an AMBER survivor is itself refused now, so the
    # ledger row is seeded as the owner: the guard reads every merge whatever
    # its labels, which is the point of running it on a system connection.
    from noctornal_api.graph import HIDDEN_TIES_REFUSAL
    owner.execute(
        "INSERT INTO core.node_merge (case_id, source_node_id, target_node_id, "
        "reason, merged_at, merged_by) VALUES (%s, %s, %s, 'g42 seeded', now(), %s)",
        (w.case_id, red, keeper, w.boss))
    refused = client.request("DELETE", w.url(f"/graph/nodes/{keeper}"),
                             headers=w.headers(w.lead), json={"reason": "retire"})
    assert refused.status_code in (400, 409), refused.text
    assert HIDDEN_TIES_REFUSAL in refused.json()["detail"]
    assert str(red) not in refused.text
    assert owner.execute("SELECT deleted_at IS NULL FROM core.node WHERE id = %s",
                         (keeper,)).fetchone()[0]


# --- the migration ------------------------------------------------------------

class _RollBack(Exception):
    pass


def _migration(conn, name):
    path = next(VERSIONS.glob(f"{name}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m_g42_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


def _policy_text(conn) -> str:
    qual, check = conn.execute(
        "SELECT qual, with_check FROM pg_policies "
        "WHERE schemaname = 'core' AND tablename = 'node_merge'").fetchone()
    return f"{qual} {check}"


def test_0132_round_trips_and_restores_the_case_term_alone(owner):
    m = _migration(owner, "0132")
    both = _policy_text(owner)
    assert both.count("EXISTS") == 4  # two ends, in USING and in WITH CHECK
    assert "source_node_id" in both and "target_node_id" in both
    with pytest.raises(_RollBack), owner.transaction():
        m.downgrade()
        case_only = _policy_text(owner)
        assert "EXISTS" not in case_only and "iam.rls_cases" in case_only
        m.upgrade()
        assert _policy_text(owner) == both
        raise _RollBack
    assert _policy_text(owner) == both
    # Frozen text, restated by nothing but a later revision.
    assert "node_merge.source_node_id" in m.upgrade_sql()
    assert "EXISTS" not in m.downgrade_sql()


def test_the_registry_names_the_policy_the_database_carries(owner):
    from noctornal_api import rls_registry as reg
    assert reg.POLICY["core.node_merge"] == "CUSTOM_MERGE"
    assert owner.execute(
        "SELECT relrowsecurity FROM pg_class WHERE oid = 'core.node_merge'::regclass"
    ).fetchone()[0]
    # A statement from the request role names no caller-settable value and no
    # anti-join: the registry test's rule, held on this policy by name.
    lowered = _policy_text(owner).lower()
    for word in ("current_setting", "not exists", "not in (", "set_config"):
        assert word not in lowered

