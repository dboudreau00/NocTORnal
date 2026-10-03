"""The selector index follows the graph (graph-selector-index-drift, review
2026-10-03).

`core.selector` is the join key of entity resolution (invariant 9): a
selector search finds the entity that carries a value, and a strong value
held by two entities is surfaced as a merge lead. Only `create_node` wrote
it, so after that:

1. correcting the label of a SELECTOR, COMMS_ACCOUNT or WALLET entity left
   the index on the old value and the new value unindexed;
2. a retired entity kept its selector row, so recreating the entity
   recorded nothing against the live one and answered `selector_owner_id`
   null;
3. accepting a NODE proposal that named a selector type never indexed it:
   the index stayed empty, selector search returned null, and a strong
   duplicate was never a lead.

Both directions are held: the index follows each of those writes, and
nothing the caller could not do before is widened. A merge lead names only
an entity the caller can see, and a hidden one reads exactly as no owner
(status, body, wording); an index row owned by a retired entity the caller
cannot see is never taken over.

Email prefix `g43c-`. Gated on DATABASE_URL and NOCTORNAL_APP_DB_ROLE.
"""
from __future__ import annotations

from uuid import UUID, uuid4

import pytest
import review_graph_support as g
import rls_support as s

pytestmark = s.GATED

PREFIX = "g43c-"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    g.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def w(owner):
    boss = s.user(owner, "RED", prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    lead = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, boss, "CASE_OWNER")
    s.assign(owner, case_id, analyst, "ANALYST")
    s.assign(owner, case_id, lead, "CASE_OWNER")
    return {"case": case_id, "boss": boss, "analyst": analyst, "owner": owner,
            "client": g.make_client(), "h": g.auth(owner, boss),
            "ha": g.auth(owner, analyst), "hl": g.auth(owner, lead)}


def _url(w, tail: str) -> str:
    return f"/api/v1/cases/{w['case']}{tail}"


def _create(w, label: str, selector_type: str = "DISCORD_ID", *,
            node_type: str = "COMMS_ACCOUNT", classification: str = "AMBER",
            headers=None) -> dict:
    r = w["client"].post(_url(w, "/nodes"), headers=headers or w["h"], json={
        "node_type": node_type, "label": label, "selector_type": selector_type,
        "classification": classification, "assertion": g.grade()})
    assert r.status_code == 201, r.text
    return r.json()


def _patch_label(w, node_id, label: str, headers=None):
    return w["client"].patch(
        _url(w, f"/graph/nodes/{node_id}"), headers=headers or w["h"],
        json={"label": label, "assertion": g.grade("a correction")})


def _held(w, node_id) -> list[tuple]:
    """(selector_type, norm_value) the index holds against the entity."""
    return w["owner"].execute(
        "SELECT selector_type, norm_value FROM core.selector WHERE case_id = %s "
        "AND node_id = %s ORDER BY norm_value", (w["case"], node_id)).fetchall()


def _digits() -> str:
    return str(uuid4().int)[:12]


# --- 1. a corrected label ----------------------------------------------------

def test_a_corrected_selector_label_moves_the_index_with_it(w):
    """graph_poc3 C4."""
    old, new = _digits(), _digits()
    node = _create(w, old)["id"]
    assert _held(w, node) == [("DISCORD_ID", old)]
    r = _patch_label(w, node, new)
    assert r.status_code == 200, r.text
    assert r.json()["selector_owner_id"] is None
    assert _held(w, node) == [("DISCORD_ID", new)]
    # the old value is let go, not deleted: it was observed
    assert g.selector_rows(w["owner"], w["case"], old) == [
        ("DISCORD_ID", old, None, 1)]
    found = w["client"].get(_url(w, "/selectors"), headers=w["h"], params={
        "selector_type": "DISCORD_ID", "value": new}).json()
    assert found["node_id"] == node
    listed = w["client"].get(_url(w, f"/nodes/{node}/selectors"),
                             headers=w["h"]).json()
    assert [row["norm_value"] for row in listed] == [new]


def test_a_correction_that_is_not_a_value_of_that_type_is_refused_whole(w):
    """The ontology's own reason, as create gives it, and nothing is
    written: not the label, not the index, not a claim."""
    old = _digits()
    node = _create(w, old)["id"]
    claims = g.one(w["owner"], "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                   (node,))
    r = _patch_label(w, node, "no digits in here")
    assert r.status_code == 400, r.text
    assert "digit" in r.json()["detail"].lower() or "discord" in r.json()["detail"].lower()
    assert w["owner"].execute("SELECT label FROM core.node WHERE id = %s",
                              (node,)).fetchone()[0] == old
    assert _held(w, node) == [("DISCORD_ID", old)]
    assert g.one(w["owner"], "SELECT count(*) FROM core.assertion WHERE node_id = %s",
                 (node,)) == claims


def test_a_correction_to_a_value_another_entity_holds_names_that_entity(w):
    """A strong value held by two entities is how one actor becomes two:
    the lead is returned, the index keeps its first owner, and the
    corrected entity's old value is let go."""
    first_value, second_value = _digits(), _digits()
    first = _create(w, first_value)["id"]
    second = _create(w, second_value)["id"]
    r = _patch_label(w, second, first_value)
    assert r.status_code == 200, r.text
    assert r.json()["selector_owner_id"] == first
    assert _held(w, first) == [("DISCORD_ID", first_value)]
    assert _held(w, second) == []


def test_a_hidden_owner_reads_exactly_as_no_owner(owner, w):
    """An AMBER analyst corrects their own entity to a value a RED entity
    holds: status and body are those of a value nobody holds, but for the
    value itself, and no id is named."""
    held_value, free_value = _digits(), _digits()
    _create(w, held_value, classification="RED")
    mine = _create(w, _digits(), headers=w["ha"])["id"]
    hidden = _patch_label(w, mine, held_value, headers=w["ha"])
    other = _create(w, _digits(), headers=w["ha"])["id"]
    free = _patch_label(w, other, free_value, headers=w["ha"])
    assert hidden.status_code == free.status_code == 200
    def body(response):
        return {k: v for k, v in response.json().items() if k != "node_id"}

    assert body(hidden) == body(free)
    assert hidden.json()["selector_owner_id"] is None
    assert hidden.text.replace(str(mine), "") == free.text.replace(str(other), "")


def test_a_correction_that_keeps_the_canonical_value_releases_nothing(w):
    """Case is not identity for a handle: the row stays with its entity."""
    node = _create(w, "Vendor_" + _digits()[:4], "HANDLE", node_type="SELECTOR")["id"]
    before = w["owner"].execute(
        "SELECT norm_value, observation_cnt FROM core.selector WHERE node_id = %s",
        (node,)).fetchall()
    r = _patch_label(w, node, before[0][0].upper())
    assert r.status_code == 200, r.text
    assert w["owner"].execute(
        "SELECT norm_value, observation_cnt FROM core.selector WHERE node_id = %s",
        (node,)).fetchall() == before


def test_a_selector_recorded_by_hand_for_another_value_is_left_alone(w):
    from noctornal_api.selectors import SelectorStore
    old, new, other = _digits(), _digits(), _digits()
    node = _create(w, old)["id"]
    SelectorStore(w["owner"]).record(
        case_id=w["case"], selector_type="DISCORD_ID", raw_value=other, node_id=node)
    assert _patch_label(w, node, new).status_code == 200
    assert sorted(v for _t, v in _held(w, node)) == sorted([new, other])


def test_correcting_an_entity_that_is_not_a_selector_writes_no_index(w):
    boss = w["boss"]
    node = s.node(w["owner"], w["case"], boss, "an identity")
    r = _patch_label(w, node, "an identity renamed")
    assert r.status_code == 200, r.text
    assert g.selector_rows(w["owner"], w["case"]) == []


def test_an_accepted_selector_entity_is_indexed_when_its_label_is_corrected(w):
    """A Triage entity whose value was never indexed (accepted before this
    fix): correcting its label records the new value against it."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    node = GraphWriteService(w["owner"]).create_node(
        case_id=w["case"], node_type="SELECTOR", label="old.mail@example.org",
        created_by=w["boss"], attrs={"selector_type": "EMAIL",
                                     "raw_value": "old.mail@example.org"},
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=w["boss"]))
    assert g.selector_rows(w["owner"], w["case"]) == []
    assert _patch_label(w, node, "new.mail@example.org").status_code == 200
    assert _held(w, node) == [("EMAIL", "new.mail@example.org")]


# --- 2. retire and recreate ---------------------------------------------------

def test_a_retired_entity_lets_go_of_its_selector_and_the_new_one_holds_it(w):
    """graph_poc7."""
    value = _digits()
    first = _create(w, value)["id"]
    r = w["client"].request("DELETE", _url(w, f"/graph/nodes/{first}"),
                            headers=w["h"], json={"reason": "wrong type"})
    assert r.status_code == 200, r.text
    assert g.selector_rows(w["owner"], w["case"], value) == [
        ("DISCORD_ID", value, None, 1)]
    again = _create(w, value)
    assert again["selector_owner_id"] is None
    second = again["id"]
    assert g.selector_rows(w["owner"], w["case"], value) == [
        ("DISCORD_ID", value, UUID(second), 2)]
    listed = w["client"].get(_url(w, f"/nodes/{second}/selectors"),
                             headers=w["h"]).json()
    assert [row["norm_value"] for row in listed] == [value]
    found = w["client"].get(_url(w, "/selectors"), headers=w["h"], params={
        "selector_type": "DISCORD_ID", "value": value}).json()
    assert found["node_id"] == second


def test_a_row_still_owned_by_a_retired_entity_is_taken_over(w):
    """Data from before the fix: the owner is retired, the index row names
    it. A live entity recording the same value takes the row."""
    from noctornal_api.selectors import SelectorStore
    value = _digits()
    first = _create(w, value)["id"]
    w["owner"].execute("UPDATE core.node SET deleted_at = now() WHERE id = %s",
                       (first,))
    w["owner"].execute("UPDATE core.selector SET node_id = %s WHERE case_id = %s "
                       "AND norm_value = %s", (first, w["case"], value))
    second = s.node(w["owner"], w["case"], w["boss"], "second entity")
    row = SelectorStore(w["owner"]).record(
        case_id=w["case"], selector_type="DISCORD_ID", raw_value=value,
        node_id=second)
    assert row.node_id == second


def test_a_row_owned_by_a_live_entity_is_never_taken_over(w):
    from noctornal_api.selectors import SelectorStore
    value = _digits()
    first = _create(w, value)["id"]
    second = s.node(w["owner"], w["case"], w["boss"], "second entity")
    row = SelectorStore(w["owner"]).record(
        case_id=w["case"], selector_type="DISCORD_ID", raw_value=value,
        node_id=second)
    assert str(row.node_id) == first
    again = _create(w, value)
    assert again["selector_owner_id"] == first


def test_a_retired_owner_the_caller_cannot_see_is_not_taken_over(owner, w):
    """Under row security a retired RED entity is invisible to an AMBER
    analyst, so the take-over rule's positive test of 'retired' finds no
    row and the row stays where it is (never a guess from absence)."""
    from noctornal_api.selectors import SelectorStore
    value = _digits()
    red = _create(w, value, classification="RED")["id"]
    owner.execute("UPDATE core.node SET deleted_at = now() WHERE id = %s", (red,))
    mine = s.node(owner, w["case"], w["analyst"], "analyst entity")
    app = g.bound(owner, w["analyst"])
    try:
        row = SelectorStore(app).record(
            case_id=w["case"], selector_type="DISCORD_ID", raw_value=value,
            node_id=mine)
        # keys are per labels since the selector-key fix (2026-10-03): the
        # analyst's sighting is its own row at its own labels, and the hidden
        # retired RED owner keeps the row it has, untouched and unread
        assert str(row.node_id) == str(mine)
    finally:
        app.close()
    held = {str(r[2]) for r in g.selector_rows(owner, w["case"], value)}
    assert held == {red, str(mine)}


def test_retiring_an_entity_works_as_the_request_role_and_frees_its_rows(owner, w):
    from noctornal_api.graph import GraphWriteService
    value = _digits()
    node = _create(w, value, headers=w["ha"])["id"]
    app = g.bound(owner, w["analyst"])
    try:
        GraphWriteService(app).soft_delete_node(
            UUID(node), case_id=w["case"], deleted_by=w["analyst"],
            at=g.now(), clearance="AMBER", compartments=[])
    finally:
        app.close()
    assert g.selector_rows(owner, w["case"], value) == [("DISCORD_ID", value, None, 1)]


# --- 3. an accepted proposal -------------------------------------------------

def _capture(w, text: str):
    r = w["client"].post(_url(w, "/proposals/capture"), headers=w["h"],
                         json={"text": text, "classification": "AMBER"})
    assert r.status_code == 201, r.text
    return r.json()


def _proposals(w, label_contains: str) -> list[dict]:
    queue = w["client"].get(_url(w, "/proposals"), headers=w["h"]).json()["proposals"]
    return [p for p in queue
            if p["kind"] == "NODE" and label_contains in (p["payload"].get("label") or "")]


def _accept(w, proposal, headers=None):
    return w["client"].post(_url(w, f"/proposals/{proposal['id']}/accept"),
                            headers=headers or w["h"], json={})


def test_accepting_a_captured_selector_records_it_in_the_index(w):
    """graph_poc8."""
    tag = uuid4().hex[:8]
    text = f"reach me on jabber v{tag}@xmpp.example.org or mail v{tag}@example.org"
    _capture(w, text)
    for value in (f"v{tag}@xmpp.example.org", f"v{tag}@example.org"):
        (proposal,) = _proposals(w, value)
        done = _accept(w, proposal)
        assert done.status_code == 200, done.text
        assert done.json()["selector_owner_id"] is None
    rows = g.selector_rows(w["owner"], w["case"])
    assert {(t, v) for t, v, _n, _c in rows} >= {
        ("EMAIL", f"v{tag}@example.org")} and all(n is not None for _t, _v, n, _c in rows)
    found = w["client"].get(_url(w, "/selectors"), headers=w["h"], params={
        "selector_type": "EMAIL", "value": f"v{tag}@example.org"}).json()
    assert found is not None and found["node_id"] is not None
    # a second paste of the same value is now known, not proposed again
    again = _capture(w, f"again v{tag}@example.org")
    assert again["already_known"] >= 1 and again["proposals_created"] == 0


def test_an_accepted_selector_already_held_by_a_visible_entity_names_it(w):
    tag = uuid4().hex[:8]
    value = f"lead{tag}@example.org"
    _capture(w, f"found {value} in the thread")
    (proposal,) = _proposals(w, value)
    held = _create(w, value, "EMAIL", node_type="SELECTOR")["id"]
    done = _accept(w, proposal)
    assert done.status_code == 200, done.text
    assert done.json()["selector_owner_id"] == held
    rows = g.selector_rows(w["owner"], w["case"], value)
    assert [str(n) for _t, _v, n, _c in rows] == [held]


def test_an_accepted_selector_held_by_a_hidden_entity_names_nobody(w):
    tag = uuid4().hex[:8]
    value = f"hid{tag}@example.org"
    _capture(w, f"found {value} in the thread")
    (proposal,) = _proposals(w, value)
    _create(w, value, "EMAIL", node_type="SELECTOR", classification="RED")
    done = _accept(w, proposal, headers=w["hl"])      # an AMBER reviewer
    assert done.status_code == 200, done.text
    assert done.json()["selector_owner_id"] is None


def test_a_proposal_whose_selector_the_ontology_refuses_is_refused_and_writes_nothing(w):
    from noctornal_api.proposals import KIND_NODE, ProposalStore
    nodes = g.one(w["owner"], "SELECT count(*) FROM core.node WHERE case_id = %s",
                  (w["case"],))
    pid = ProposalStore(w["owner"]).propose(
        case_id=w["case"], kind=KIND_NODE, origin="g43c/test", rationale="a test",
        payload={"node_type": "COMMS_ACCOUNT", "label": "no digits in here",
                 "classification": "AMBER",
                 "attrs": {"selector_type": "DISCORD_ID"}})
    done = w["client"].post(_url(w, f"/proposals/{pid}/accept"), headers=w["h"],
                            json={})
    assert done.status_code == 409, done.text
    assert "reject the proposal" in done.json()["detail"]
    assert g.one(w["owner"], "SELECT count(*) FROM core.node WHERE case_id = %s",
                 (w["case"],)) == nodes
    assert w["owner"].execute("SELECT state::text FROM collect.proposal WHERE id = %s",
                              (pid,)).fetchone()[0] == "PROPOSED"


def test_an_infrastructure_proposal_that_names_a_selector_type_is_indexed(w):
    """Other producers (a deception capture, a lookup) raise NODE proposals
    that name a selector type; they are the same path."""
    from noctornal_api.proposals import KIND_NODE, ProposalStore
    host = f"h{uuid4().hex[:8]}.example.org"
    pid = ProposalStore(w["owner"]).propose(
        case_id=w["case"], kind=KIND_NODE, origin="g43c/test", rationale="a test",
        payload={"node_type": "INFRA", "label": host, "classification": "AMBER",
                 "attrs": {"selector_type": "DOMAIN"}})
    done = w["client"].post(_url(w, f"/proposals/{pid}/accept"), headers=w["h"],
                            json={})
    assert done.status_code == 200, done.text
    assert [(t, v) for t, v, _n, _c in g.selector_rows(w["owner"], w["case"])] == [
        ("DOMAIN", host)]


def test_a_node_proposal_without_a_selector_type_indexes_nothing(w):
    from noctornal_api.proposals import KIND_NODE, ProposalStore
    pid = ProposalStore(w["owner"]).propose(
        case_id=w["case"], kind=KIND_NODE, origin="g43c/test", rationale="a test",
        payload={"node_type": "LURE", "label": "a pretext", "classification": "AMBER",
                 "attrs": {}})
    done = w["client"].post(_url(w, f"/proposals/{pid}/accept"), headers=w["h"],
                            json={})
    assert done.status_code == 200, done.text
    assert g.selector_rows(w["owner"], w["case"]) == []


# --- retracting a corrected label --------------------------------------------

def test_retracting_a_label_correction_moves_the_index_back(w):
    old, new = _digits(), _digits()
    node = _create(w, old)["id"]
    assert _patch_label(w, node, new).status_code == 200
    claim = w["owner"].execute(
        "SELECT id FROM core.assertion WHERE node_id = %s AND claim_path = 'label'",
        (node,)).fetchone()[0]
    r = w["client"].post(_url(w, f"/assertions/{claim}/retract"), headers=w["h"],
                         json={"reason": "wrong"})
    assert r.status_code == 204, r.text
    assert w["owner"].execute("SELECT label FROM core.node WHERE id = %s",
                              (node,)).fetchone()[0] == old
    assert _held(w, node) == [("DISCORD_ID", old)]
    assert g.selector_rows(w["owner"], w["case"], new)[0][2] is None


def test_a_restored_label_the_ontology_no_longer_accepts_is_still_restored(w):
    """A retraction never refuses and never keeps a withdrawn claim live
    because a rule has tightened since: `strict=False` lets the label go
    back and the index simply holds nothing for it; a new label is refused
    with the ontology's reason (`strict`)."""
    from noctornal_api.selectors import SelectorError, SelectorStore
    node = UUID(_create(w, _digits())["id"])
    old = w["owner"].execute("SELECT label FROM core.node WHERE id = %s",
                             (node,)).fetchone()[0]
    store = SelectorStore(w["owner"])
    with pytest.raises(SelectorError):
        store.follow_label(case_id=w["case"], node_id=node, old_label=old,
                           new_label="no digits", strict=True)
    assert _held(w, node) == [("DISCORD_ID", old)]
    assert store.follow_label(case_id=w["case"], node_id=node, old_label=old,
                              new_label="no digits", strict=False) is None
    assert _held(w, node) == []


# --- the verifier's round: a duplicate, and a retired owner ------------------
#
# The index keeps its first owner and reports a second entity holding the same
# value as a lead, so a duplicate owns no row. Three orders of events then
# left the index, or the correction rules, behind the graph.

def test_a_duplicate_is_validated_and_followed_like_the_entity_that_owns_the_row(w):
    """The verifier's reproduction. E1 owns the row, E2 was created while E1
    held the value. A label that is not a value of the type was refused for
    E1 and accepted for E2, and E2's new value was never indexed."""
    value, new = _digits(), _digits()
    first = _create(w, value)["id"]
    again = _create(w, value)
    assert again["selector_owner_id"] == first
    second = again["id"]
    assert _held(w, second) == []
    for node in (first, second):
        r = _patch_label(w, node, "not a discord id")
        assert r.status_code == 400, (node, r.text)
        assert "canonical DISCORD_ID" in r.json()["detail"]
    assert w["owner"].execute("SELECT label FROM core.node WHERE id = %s",
                              (second,)).fetchone()[0] == value
    r = _patch_label(w, second, new)
    assert r.status_code == 200, r.text
    assert _held(w, second) == [("DISCORD_ID", new)]
    # the owner keeps what it holds
    assert _held(w, first) == [("DISCORD_ID", value)]


def test_a_duplicate_that_is_corrected_to_a_value_another_entity_holds_names_it(w):
    value, other = _digits(), _digits()
    first = _create(w, value)["id"]
    second = _create(w, value)["id"]
    holder = _create(w, other)["id"]
    r = _patch_label(w, second, other)
    assert r.status_code == 200, r.text
    assert r.json()["selector_owner_id"] == holder
    assert _held(w, second) == []
    assert _held(w, first) == [("DISCORD_ID", value)]


def test_retiring_the_owner_hands_the_row_to_the_live_duplicate(w):
    """The verifier's second order: E3 owns, E4 is its duplicate, E3 is
    retired. The row went ownerless and E4 stayed unindexed."""
    value = _digits()
    first = _create(w, value)["id"]
    second = _create(w, value)["id"]
    r = w["client"].request("DELETE", _url(w, f"/graph/nodes/{first}"),
                            headers=w["h"], json={"reason": "duplicate"})
    assert r.status_code == 200, r.text
    assert g.selector_rows(w["owner"], w["case"], value) == [
        ("DISCORD_ID", value, UUID(second), 2)]
    found = w["client"].get(_url(w, "/selectors"), headers=w["h"], params={
        "selector_type": "DISCORD_ID", "value": value}).json()
    assert found["node_id"] == second
    listed = w["client"].get(_url(w, f"/nodes/{second}/selectors"),
                             headers=w["h"]).json()
    assert [row["norm_value"] for row in listed] == [value]


def test_the_oldest_live_duplicate_gets_the_row_and_a_second_retirement_passes_it_on(w):
    value = _digits()
    ids = [_create(w, value)["id"] for _ in range(3)]
    for retired, heir in ((ids[0], ids[1]), (ids[1], ids[2])):
        r = w["client"].request("DELETE", _url(w, f"/graph/nodes/{retired}"),
                                headers=w["h"], json={"reason": "duplicate"})
        assert r.status_code == 200, r.text
        assert g.selector_rows(w["owner"], w["case"], value)[0][2] == UUID(heir)


def test_a_duplicate_written_in_another_letter_case_is_found_by_its_fold(w):
    """The create form's duplicate check folds case and runs of whitespace,
    and so does the hand-over: `Alice@Example.org` and `alice@example.org`
    are one e-mail address."""
    first = _create(w, "Alice@Example.org", "EMAIL", node_type="SELECTOR")["id"]
    second = _create(w, "alice@example.org", "EMAIL", node_type="SELECTOR")["id"]
    w["client"].request("DELETE", _url(w, f"/graph/nodes/{first}"),
                        headers=w["h"], json={"reason": "duplicate"})
    assert g.selector_rows(w["owner"], w["case"], "alice@example.org")[0][2] == UUID(second)


def test_a_duplicate_the_caller_cannot_see_is_not_handed_the_row(owner, w):
    """Under row security a hidden RED duplicate is not found, so the row
    goes free as before and a hidden entity is never read from its absence."""
    from noctornal_api.graph import GraphWriteService
    value = _digits()
    mine = _create(w, value, headers=w["ha"])["id"]
    red = _create(w, value, classification="RED")
    assert red["selector_owner_id"] == mine
    app = g.bound(owner, w["analyst"])
    try:
        GraphWriteService(app).soft_delete_node(
            UUID(mine), case_id=w["case"], deleted_by=w["analyst"],
            at=g.now(), clearance="AMBER", compartments=[])
    finally:
        app.close()
    # one row per labels: the hidden RED entity keeps the row it holds, and
    # the analyst's own row is released with its deleted owner
    rows = g.selector_rows(owner, w["case"], value)
    assert sorted(rows, key=lambda r: str(r[2])) == sorted(
        [("DISCORD_ID", value, UUID(red["id"]), 1), ("DISCORD_ID", value, None, 1)],
        key=lambda r: str(r[2]))


def test_an_entity_that_is_not_a_selector_is_not_handed_a_row(w):
    """Only an entity whose label is a selector can take one: an identity
    that happens to carry the same text does not."""
    value = _digits()
    first = _create(w, value)["id"]
    s.node(w["owner"], w["case"], w["boss"], value)
    w["client"].request("DELETE", _url(w, f"/graph/nodes/{first}"),
                        headers=w["h"], json={"reason": "wrong"})
    assert g.selector_rows(w["owner"], w["case"], value) == [
        ("DISCORD_ID", value, None, 1)]


def _migration_named(stem: str):
    """A revision loaded by its file name, so renumbering it when the branches
    are merged does not break this test."""
    import importlib.util
    from pathlib import Path
    path = next((Path(__file__).resolve().parents[3] / "db" / "migrations"
                 / "versions").glob(f"*_{stem}.py"))
    spec = importlib.util.spec_from_file_location(f"m_{stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_0138_releases_the_rows_a_retired_entity_still_owns_and_nothing_else(w):
    """Data from before the fix: a retired owner is still named. The
    migration lets those go, and changes no value, count or live owner."""
    m = _migration_named("release_retired_selector_owners")
    retired_value, live_value = _digits(), _digits()
    retired = _create(w, retired_value)["id"]
    live = _create(w, live_value)["id"]
    w["owner"].execute("UPDATE core.node SET deleted_at = now() WHERE id = %s",
                       (retired,))
    w["owner"].execute("UPDATE core.selector SET node_id = %s WHERE case_id = %s "
                       "AND norm_value = %s", (retired, w["case"], retired_value))
    before = g.selector_rows(w["owner"], w["case"])
    assert dict((r[1], r[2]) for r in before)[retired_value] == UUID(retired)
    w["owner"].execute(m.UPGRADE_SQL)
    after = g.selector_rows(w["owner"], w["case"])
    assert dict((r[1], (r[0], r[2], r[3])) for r in after) == {
        retired_value: ("DISCORD_ID", None, 1),
        live_value: ("DISCORD_ID", UUID(live), 1)}
    # idempotent: a second run finds nothing
    w["owner"].execute(m.UPGRADE_SQL)
    assert g.selector_rows(w["owner"], w["case"]) == after
    assert m.down_revision == _migration_named("scrub_url_credentials").revision
    m.downgrade()      # a no-op, by design
