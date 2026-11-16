"""A record labelled below what it cites names no cited element its reader may not see.

A capture, a call and a contact block can cite an exhibit (and a block an entity) labelled above
themselves: whoever wrote the record could see both, and the record is not raised to them (that would
change what existing cases show). A reader cleared for the record and not for what it cites was handed
the cited id, and the screenshot route then answered a hidden exhibit 403 where another case's answered
404, so the status confirmed what the id named. An ATTRIBUTE proposal raised from such a block carried
the entity's id in its payload to every reader of the block (independent review ACCESS-02, ACCESS-05).

`element_gate.visible_element_ids` is the one answer to "may this reader see that cited element", and
`withhold_cited` leaves every id it refuses out of a capture, a call, a contact block and a proposal's
payload. The screenshot route gates its exhibit with `gate_element`, so a hidden exhibit, another case's
and a capture with none are one 404 with one denial row; `absent_families` holds their statements equal.

A block whose text was parsed already in this case at labels the caller does not hold is answered as a
duplicate is, 201, with one sentence that names no label and no field of the hidden block, where it was
a 400 saying "at a label you do not hold" (independent review, ACCESS-06). It is decided by the caller's own ceiling,
so an owner connection with no row security answers the same.

Runs with NOCTORNAL_TEST_ASSUME_ROLE, so every request connection is the request role, as in
production, except where a test says otherwise.
"""
from __future__ import annotations

from uuid import UUID

import pytest

import rls_support as s
from absent_families import make_client

pytestmark = s.GATED

PREFIX = "k2c-"
TOX_ID = "C3" * 38
CALL = {"started_at": "2026-01-01T00:00:00Z", "direction": "INBOUND_TO_VICTIM",
        "record_source": "PBX_LOG"}


def _cleanup(c) -> None:
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    for statement in (
            f"DELETE FROM deception.capture_hop WHERE capture_id IN "
            f"(SELECT id FROM deception.capture WHERE case_id IN {cases})",
            f"DELETE FROM deception.capture WHERE case_id IN {cases}",
            f"DELETE FROM deception.call_record WHERE case_id IN {cases}",
            f"DELETE FROM comms.contact_block_entry WHERE block_id IN "
            f"(SELECT id FROM comms.contact_block WHERE case_id IN {cases})",
            f"DELETE FROM comms.contact_block WHERE case_id IN {cases}",
            f"DELETE FROM collect.proposal WHERE case_id IN {cases}"):
        try:
            with c.transaction():
                c.execute(statement)
        except Exception:  # noqa: BLE001 - a row a later suite can live with
            pass
    s.cleanup(c, PREFIX)


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    _cleanup(c)
    c.close()


@pytest.fixture
def client():
    return make_client()


def _auth(conn, uid) -> dict:
    _, raw = s.session(conn, uid)
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture
def world(owner):
    """An AMBER case with a RED lead and an AMBER analyst, an exhibit and an entity in it above the
    analyst, an exhibit the analyst may read, and an exhibit of another case."""
    boss = s.user(owner, "RED", prefix=PREFIX)
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, boss, "CASE_OWNER")
    s.assign(owner, case_id, analyst, "ANALYST")
    other = s.case(owner, boss)
    return {
        "case": case_id, "boss": boss, "analyst": analyst,
        "boss_auth": _auth(owner, boss), "analyst_auth": _auth(owner, analyst),
        "hidden": s.exhibit(owner, case_id, boss, "RED"),
        "seen": s.exhibit(owner, case_id, boss, "AMBER"),
        "other": s.exhibit(owner, other, boss, "AMBER"),
        "hidden_node": s.node(owner, case_id, boss, "k2c hidden vendor", "RED"),
    }


def _url(w, tail: str) -> str:
    return f"/api/v1/cases/{w['case']}{tail}"


def _ok(r, status: int = 200) -> dict:
    assert r.status_code == status, r.text
    return r.json()


def test_a_capture_names_no_exhibit_above_its_reader(client, world):
    w = world
    made = _ok(client.post(_url(w, "/deception/captures"), headers=w["boss_auth"], json={
        "requested_url": "https://lure.example/k2c", "capture_method": "ANALYST_UPLOAD",
        "classification": "AMBER", "screenshot_evidence_id": str(w["hidden"]),
        "dom_evidence_id": str(w["hidden"]), "har_evidence_id": str(w["seen"])}), 201)
    cited = {"screenshot_evidence_id": None, "dom_evidence_id": None,
             "har_evidence_id": str(w["seen"])}

    one = _ok(client.get(_url(w, f"/deception/captures/{made['id']}"),
                         headers=w["analyst_auth"]))
    listed = _ok(client.get(_url(w, "/deception/captures"), headers=w["analyst_auth"]))
    (row,) = [c for c in listed["captures"] if c["id"] == made["id"]]
    for shown in (one, row):
        assert {k: shown[k] for k in cited} == cited, shown
    # The writer, who may see the exhibit, is still shown it.
    mine = _ok(client.get(_url(w, f"/deception/captures/{made['id']}"),
                          headers=w["boss_auth"]))
    assert mine["screenshot_evidence_id"] == str(w["hidden"])


def test_a_call_names_no_exhibit_above_its_reader(client, world):
    w = world
    made = _ok(client.post(_url(w, "/deception/calls"), headers=w["boss_auth"], json={
        **CALL, "classification": "AMBER", "evidence_id": str(w["hidden"]),
        "recording_evidence_id": str(w["hidden"]),
        "recording_lawful_basis": "k2c warrant"}), 201)

    def shown(auth) -> dict:
        listed = _ok(client.get(_url(w, "/deception/calls"), headers=auth))
        (row,) = [c for c in listed["calls"] if c["id"] == made["id"]]
        return {k: row[k] for k in ("evidence_id", "recording_evidence_id")}

    assert shown(w["analyst_auth"]) == {"evidence_id": None, "recording_evidence_id": None}
    assert shown(w["boss_auth"]) == {"evidence_id": str(w["hidden"]),
                                     "recording_evidence_id": str(w["hidden"])}


def _block(client, w, auth, *, text: str, classification: str = "AMBER", **cited) -> dict:
    return client.post(_url(w, "/comms/contact-blocks"), headers=auth, json={
        "raw_text": text, "source_ref": "https://forum.example/k2c",
        "classification": classification,
        **{k: str(v) for k, v in cited.items()}})


def test_a_contact_block_names_no_exhibit_or_entity_above_its_reader(client, world):
    """And neither does the ATTRIBUTE proposal its parse raised about that entity, which the
    analyst's queue lists at the block's labels."""
    w = world
    made = _ok(_block(client, w, w["boss_auth"], text=f"TOX: {TOX_ID}",
                      evidence_id=w["hidden"],
                      publisher_identity_node_id=w["hidden_node"]), 201)
    assert any(e["proposal_id"] for e in made["entries"]), made

    def cited(auth) -> tuple:
        block = _ok(client.get(_url(w, f"/comms/contact-blocks/{made['id']}"), headers=auth))
        queue = _ok(client.get(_url(w, "/proposals"), headers=auth))
        (proposal,) = [p for p in queue["proposals"]
                       if p["kind"] == "ATTRIBUTE"
                       and p["id"] in {e["proposal_id"] for e in made["entries"]}]
        return (block["evidence_id"], block["publisher_identity_node_id"],
                proposal["payload"]["node_id"], proposal["refs"])

    assert cited(w["analyst_auth"]) == (None, None, None, {})
    hidden_node = str(w["hidden_node"])
    evidence, publisher, node, refs = cited(w["boss_auth"])
    assert (evidence, publisher, node) == (str(w["hidden"]), hidden_node, hidden_node)
    assert set(refs) == {hidden_node}


@pytest.mark.parametrize("row_security", [True, False], ids=["request role", "owner"])
def test_a_block_parsed_above_the_caller_is_answered_as_a_duplicate_without_its_fields(
        client, world, monkeypatch, row_security):
    w = world
    if not row_security:
        from noctornal_api.db import ASSUME_ROLE_ENV
        monkeypatch.delenv(ASSUME_ROLE_ENV)
    above = f"Jabber: k2c-above@forum.example\nTOX: {TOX_ID}"
    _ok(_block(client, w, w["boss_auth"], text=above, classification="RED"), 201)
    refused = _block(client, w, w["analyst_auth"], text=above)
    assert refused.status_code == 201, refused.text
    body = refused.json()
    assert body["already_parsed"] is True
    assert body["id"] is None
    assert body["entries"] == [] and body["co_declaration"] == []
    assert set(body) == {"id", "already_parsed", "entries", "co_declaration", "notice"}, body
    for word in ("label", "RED", "hold", "k2c-above", TOX_ID):
        assert word not in body["notice"], body["notice"]

    # A duplicate the caller may see is answered with the same status, and with the block.
    mine = "Jabber: k2c-mine@forum.example"
    first = _ok(_block(client, w, w["analyst_auth"], text=mine), 201)
    again = _block(client, w, w["analyst_auth"], text=mine)
    assert again.status_code == refused.status_code
    assert again.json()["already_parsed"] is True and again.json()["id"] == first["id"]


def test_the_screenshot_route_gates_its_exhibit_with_the_element_gate():
    """The route reads its exhibit's labels through `gate_element` and nowhere else, so a hidden,
    a missing and another case's exhibit cannot be told apart by it (decision 230)."""
    import ast
    import inspect

    from noctornal_api.http.routers import deception

    tree = ast.parse(inspect.getsource(deception.capture_screenshot))
    called = {n.func.id if isinstance(n.func, ast.Name) else n.func.attr
              for n in ast.walk(tree) if isinstance(n, ast.Call)
              and isinstance(n.func, (ast.Name, ast.Attribute))}
    assert "gate_element" in called
    assert "element_labels" not in called


def test_visible_element_ids_answers_for_entities_and_exhibits(owner, world):
    """The one helper: an id of this case at or below the reader's ceiling, of the kind asked;
    another case's, a hidden one, one of another kind and one that names nothing are not. A tie is
    read at its own labels and a claim at its subject's."""
    from noctornal_api.http.deps import CurrentUser
    from noctornal_api.http.element_gate import visible_element_ids
    w = world
    seen_node = s.node(owner, w["case"], w["boss"], "k2c seen")
    near = s.node(owner, w["case"], w["boss"], "k2c near")
    seen_edge = s.edge(owner, w["case"], w["boss"], seen_node, near)
    hidden_edge = s.edge(owner, w["case"], w["boss"], near, seen_node, "RED")

    def claim_on(column: str, element: UUID) -> UUID:
        return owner.execute(f"SELECT id FROM core.assertion WHERE {column} = %s",  # noqa: S608
                             (element,)).fetchone()[0]

    seen_claims = {claim_on("node_id", seen_node), claim_on("edge_id", seen_edge)}
    hidden_claims = {claim_on("node_id", w["hidden_node"]), claim_on("edge_id", hidden_edge)}
    reader = CurrentUser(w["analyst"], w["analyst"], None)
    asked = [w["hidden"], w["seen"], w["other"], w["hidden_node"], seen_node, seen_edge,
             hidden_edge, *seen_claims, *hidden_claims, UUID(int=7), None, "not an id"]
    assert visible_element_ids(owner, reader, w["case"], "evidence", asked) == {w["seen"]}
    assert visible_element_ids(owner, reader, w["case"], "node", asked) == {seen_node}
    assert visible_element_ids(owner, reader, w["case"], "edge", asked) == {seen_edge}
    assert visible_element_ids(owner, reader, w["case"], "assertion", asked) == seen_claims
    with pytest.raises(ValueError):
        visible_element_ids(owner, reader, w["case"], "sample", asked)


def test_impersonation_names_no_publisher_entity_above_its_reader(client, world):
    """A block names its publisher by the entity alone; another block with the same selectors
    names a handle. The lead is shown both publishers; the analyst, who may read both blocks and
    not the entity, is shown neither the entity's id nor a candidate it alone makes."""
    w = world
    text = f"TOX: {TOX_ID}"
    _ok(_block(client, w, w["boss_auth"], text=text,
               publisher_identity_node_id=w["hidden_node"]), 201)
    _ok(client.post(_url(w, "/comms/contact-blocks"), headers=w["boss_auth"], json={
        "raw_text": f"Reach me on\n{text}", "source_ref": "https://forum.example/k2c-other",
        "publisher_handle": "k2c-other", "classification": "AMBER"}), 201)

    def publishers(auth) -> list[list[str]]:
        listed = _ok(client.get(_url(w, "/comms/impersonation"), headers=auth))
        return [c["publishers"] for c in listed["candidates"]]

    assert [str(w["hidden_node"]), "k2c-other"] in publishers(w["boss_auth"])
    shown = publishers(w["analyst_auth"])
    assert not any(str(w["hidden_node"]) in p for p in shown), shown
    assert not any("k2c-other" in p for p in shown), shown


@pytest.mark.parametrize("kind", ["NODE", "EDGE"])
def test_an_accepted_proposal_names_no_element_written_above_its_reader(
        client, owner, world, kind):
    """A reviewer may raise the label on accept, so the proposal stays readable at its own label
    while what it wrote is above some of its readers."""
    from noctornal_api.proposals import ProposalStore
    w = world
    if kind == "NODE":
        payload = {"node_type": "IDENTITY", "label": "k2c raised", "classification": "AMBER"}
        field = "applied_node_id"
    else:
        src = s.node(owner, w["case"], w["boss"], "k2c src")
        dst = s.node(owner, w["case"], w["boss"], "k2c dst")
        payload = {"edge_type": "COMMUNICATES_WITH", "src_node_id": str(src),
                   "dst_node_id": str(dst), "classification": "AMBER"}
        field = "applied_edge_id"
    pid = ProposalStore(owner).propose(
        case_id=w["case"], kind=kind, payload=payload, origin="k2c_test_v1",
        rationale="raised by the cited-ids test", score=0.5)
    accepted = _ok(client.post(_url(w, f"/proposals/{pid}/accept"), headers=w["boss_auth"],
                               json={"classification": "RED"}))
    written = accepted[field]
    assert written is not None

    def applied(auth) -> str | None:
        queue = _ok(client.get(_url(w, "/proposals?state=ACCEPTED"), headers=auth))
        (row,) = [p for p in queue["proposals"] if p["id"] == str(pid)]
        return row[field]

    assert applied(w["boss_auth"]) == written
    assert applied(w["analyst_auth"]) is None


@pytest.mark.parametrize("verb", ["reject", "defer"])
def test_a_disposed_proposal_names_no_entity_above_its_reviewer(client, owner, world, verb):
    """The answer to a reject or a defer is the proposal as its reviewer is shown it."""
    w = world
    reviewer = s.user(owner, "AMBER", prefix=PREFIX)
    s.assign(owner, w["case"], reviewer, "REVIEWER")
    auth = _auth(owner, reviewer)
    made = _ok(_block(client, w, w["boss_auth"], text=f"TOX: {TOX_ID}",
                      publisher_identity_node_id=w["hidden_node"]), 201)
    raised = {e["proposal_id"] for e in made["entries"] if e["proposal_id"]}
    queue = _ok(client.get(_url(w, "/proposals"), headers=auth))
    (proposal,) = [p for p in queue["proposals"]
                   if p["kind"] == "ATTRIBUTE" and p["id"] in raised]
    answer = _ok(client.post(_url(w, f"/proposals/{proposal['id']}/{verb}"),
                             headers=auth, json={"note": "k2c not ours"}))
    assert answer["state"] == {"reject": "REJECTED", "defer": "DISPUTED"}[verb]
    assert answer["payload"]["node_id"] is None


def test_a_duplicate_block_handed_back_names_no_exhibit_or_entity_above_its_reader(
        client, world):
    """Text an earlier block at the caller's labels parsed is answered with that block, which can
    cite what the caller may not see."""
    w = world
    text = f"Jabber: k2c-again@forum.example\nTOX: {TOX_ID}"
    first = _ok(_block(client, w, w["boss_auth"], text=text, evidence_id=w["hidden"],
                       publisher_identity_node_id=w["hidden_node"]), 201)
    again = _ok(_block(client, w, w["analyst_auth"], text=text), 201)
    assert again["already_parsed"] is True and again["id"] == first["id"]
    assert again["evidence_id"] is None
    assert again["publisher_identity_node_id"] is None
