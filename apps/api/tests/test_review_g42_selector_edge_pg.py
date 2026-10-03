"""Selectors and ties against entities above the caller (beta review,
2026-10-03).

- graph-selector-record-oracle, http_ui-002, rls-2: POST /selectors upserted
  the same (case, type, value) row GET /selectors withholds and handed back
  its owner, its stored spelling and its count, and bumped the count of a
  row owned by an entity the caller cannot read.
- graph-edge-endpoints-not-gated: a tie could be made to an entity above the
  caller, and the retirement guard compared only a tie's own labels, so a
  retirement cascaded through (and counted) a tie to such an entity.
- rls-3: edge_uniq_active spanned labels, so making a tie between two
  entities the caller can see answered 400 "already exists" exactly when a
  tie of that type, above them, already joined the pair.
- graph-unmerge-500-and-ties-to-merged-nodes: a tie could be made to a
  merged-away or retired entity.

Through the real route as the request role (`review_g42_support`).
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import psycopg
import pytest

import review_g42_support as g
import rls_support as s

pytestmark = g.GATED

CLAIM = g.CLAIM


@pytest.fixture
def owner(monkeypatch):
    c = g.make_owner(monkeypatch)
    yield c
    g.cleanup(c)
    c.close()


@pytest.fixture
def client():
    return g.make_client()


def _email() -> str:
    return f"informant-{uuid4().hex[:8]}@example.org"


def _selector_node(client, w, uid, email, classification="AMBER"):
    r = client.post(w.url("/nodes"), headers=w.headers(uid), json={
        "node_type": "SELECTOR", "selector_type": "EMAIL", "label": email,
        "classification": classification, "assertion": CLAIM})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _selector_row(owner, w, email):
    """The strictest row of the value (the RED entity's, where there is one):
    a value is one row per labels since 0134."""
    return owner.execute(
        "SELECT id, observation_cnt, last_seen, node_id FROM core.selector "
        "WHERE case_id = %s AND norm_value = %s "
        "ORDER BY classification DESC LIMIT 1", (w.case_id, email.lower())
    ).fetchone()


def _post_selector(client, w, uid, **body):
    body.setdefault("selector_type", "EMAIL")
    return client.post(w.url("/selectors"), headers=w.headers(uid), json=body)


# --- POST /selectors (graph-selector-record-oracle, http_ui-002, rls-2) -----

def test_posting_a_selector_a_hidden_entity_holds_answers_as_a_first_sighting(
        owner, client):
    w = g.World(owner)
    email = _email()
    red = _selector_node(client, w, w.boss, email, "RED")
    assert client.get(w.url(f"/nodes/{red}"),
                      headers=w.headers(w.analyst)).status_code == 404
    before = _selector_row(owner, w, email)

    hit = _post_selector(client, w, w.analyst, raw_value=email.upper())
    miss = _post_selector(client, w, w.analyst, raw_value=_email())
    assert hit.status_code == miss.status_code == 201, (hit.text, miss.text)
    for body in (hit.json(), miss.json()):
        assert body["node_id"] is None
        assert body["observation_cnt"] == 1
    # The caller's own spelling comes back, never the stored one.
    assert hit.json()["raw_value"] == email.upper() != email
    assert hit.json()["id"] != str(before[0])
    assert str(red) not in hit.text
    # Nothing was written to the hidden row.
    assert _selector_row(owner, w, email) == before


def test_a_selector_the_caller_may_see_is_still_counted_and_attributed(
        owner, client):
    w = g.World(owner)
    email = _email()
    mine = _selector_node(client, w, w.analyst, email)
    again = _post_selector(client, w, w.analyst, raw_value=email)
    assert again.status_code == 201, again.text
    assert (again.json()["node_id"], again.json()["observation_cnt"]) == (mine, 2)
    # A sighting nobody has attributed stays where it is when an entity is
    # named for the same value later: the entity's own row is made at its
    # own labels (0134), so nothing recorded below it is ever narrowed.
    loose = _post_selector(client, w, w.analyst, raw_value=_email())
    named = _post_selector(client, w, w.analyst, raw_value=loose.json()["raw_value"],
                           node_id=mine)
    assert (named.json()["node_id"], named.json()["observation_cnt"]) == (mine, 1)
    assert named.json()["id"] != loose.json()["id"]
    again = client.get(w.url("/selectors"), headers=w.headers(w.analyst),
                       params={"selector_type": "EMAIL",
                               "value": loose.json()["raw_value"]})
    assert again.json()["id"] == named.json()["id"]


def test_a_selector_may_only_be_attributed_to_an_entity_the_caller_may_name(
        owner, client):
    w = g.World(owner)
    red = w.node("g42 red", "RED")
    other_owner = s.user(owner, "RED", prefix=g.PREFIX)
    other_case = s.case(owner, other_owner, "AMBER")
    foreign = s.node(owner, other_case, other_owner, "g42 foreign")
    email = _email()
    answers = []
    for named in (red, uuid4(), foreign):
        r = _post_selector(client, w, w.analyst, raw_value=email, node_id=str(named))
        answers.append(g.answer(r))
    # One 400 and one sentence, the contract this route has always had for a
    # node that is not this case's to name (test_http_e2e), however it fails.
    assert answers == [(400, "node_id does not belong to this case")] * 3
    assert _selector_row(owner, w, email) is None


def test_creating_an_entity_with_a_value_a_hidden_entity_holds_leaves_it_alone(
        owner, client):
    w = g.World(owner)
    email = _email()
    _selector_node(client, w, w.boss, email, "RED")
    before = _selector_row(owner, w, email)
    made = client.post(w.url("/nodes"), headers=w.headers(w.analyst), json={
        "node_type": "SELECTOR", "selector_type": "EMAIL", "label": email,
        "assertion": CLAIM})
    assert made.status_code == 201, made.text
    assert made.json()["selector_owner_id"] is None
    assert _selector_row(owner, w, email) == before


# --- the membership oracle, second round (0134) --------------------------------
#
# Round one stopped POST /selectors handing back and bumping a row owned above
# the caller by answering such a value as a first sighting and storing
# nothing. The verifier's second round: a repeat post, a read after a post, a
# second entity and the id as a merge's basis each still told a held value
# from an unheld one. The index is keyed by labels now, so the caller's own
# sighting is a row of their own.

def _shape(client, w, uid, value):
    """What a caller can tell about a value from two posts and a read."""
    first = _post_selector(client, w, uid, raw_value=value)
    second = _post_selector(client, w, uid, raw_value=value)
    read = client.get(w.url("/selectors"), headers=w.headers(uid),
                      params={"selector_type": "EMAIL", "value": value})
    row = read.json()
    return {
        "status": (first.status_code, second.status_code),
        "counts": (first.json()["observation_cnt"],
                   second.json()["observation_cnt"]),
        "same_id": first.json()["id"] == second.json()["id"],
        "owners": (first.json()["node_id"], second.json()["node_id"]),
        "read": (read.status_code, row is not None
                 and row["id"] == first.json()["id"],
                 row and row["observation_cnt"]),
    }


def test_a_value_held_above_the_caller_answers_repeat_posts_and_reads_as_one_held_nowhere(
        owner, client):
    w = g.World(owner)
    held, absent = _email(), _email()
    _selector_node(client, w, w.boss, held, "RED")
    before = _selector_row(owner, w, held)

    expected = {"status": (201, 201), "counts": (1, 2), "same_id": True,
                "owners": (None, None), "read": (200, True, 2)}
    assert _shape(client, w, w.analyst, absent) == expected
    assert _shape(client, w, w.analyst, held) == expected
    # The hidden row is the RED entity's alone, and the analyst's two
    # sightings are a row of their own beside it.
    assert _selector_row(owner, w, held) == before
    rows = owner.execute(
        "SELECT classification::text, observation_cnt, node_id IS NULL "
        "FROM core.selector WHERE case_id = %s AND norm_value = %s "
        "ORDER BY classification", (w.case_id, held.lower())).fetchall()
    assert rows == [("CLEAR", 2, True), ("RED", 1, False)]


def test_the_id_a_post_answers_is_a_real_row_a_merge_may_cite(owner, client):
    w = g.World(owner)
    held, absent = _email(), _email()
    _selector_node(client, w, w.boss, held, "RED")
    outcomes = []
    for value in (held, absent):
        sel = _post_selector(client, w, w.lead, raw_value=value).json()["id"]
        a, b = w.node("g42 basis a"), w.node("g42 basis b")
        merged = client.post(w.url("/merges"), headers=w.headers(w.lead), json={
            "source_node_id": str(a), "target_node_id": str(b),
            "reason": "g42 basis", "basis_selector_id": sel})
        outcomes.append(merged.status_code)
        assert owner.execute(
            "SELECT basis_selector_id FROM core.node_merge WHERE id = %s",
            (merged.json()["id"],)).fetchone()[0] is not None
    assert outcomes == [201, 201]


def test_a_second_entity_of_a_value_is_told_of_the_first_whether_or_not_a_hidden_one_holds_it(
        owner, client):
    w = g.World(owner)
    held, absent = _email(), _email()
    _selector_node(client, w, w.boss, held, "RED")
    seen = {}
    for label, value in (("held", held), ("absent", absent)):
        first = _selector_node(client, w, w.analyst, value)
        second = client.post(w.url("/nodes"), headers=w.headers(w.analyst), json={
            "node_type": "SELECTOR", "selector_type": "EMAIL", "label": value,
            "assertion": CLAIM})
        assert second.status_code == 201, second.text
        seen[label] = (first, second.json()["selector_owner_id"])
    # The first is told of nobody (a hidden holder is nobody to them), the
    # second of the first, in both worlds.
    assert seen["held"][1] == seen["held"][0]
    assert seen["absent"][1] == seen["absent"][0]
    first_again = client.get(
        w.url(f"/nodes/{seen['held'][0]}/selectors"),
        headers=w.headers(w.analyst)).json()
    assert [r["norm_value"] for r in first_again] == [held.lower()]


def test_an_entity_attributed_later_does_not_narrow_what_a_lower_caller_recorded(
        owner, client):
    """The honeytrap: record every value of interest at AMBER and poll the
    read. A row that a later RED entity took over, and so hid, would flip
    from the analyst's row to none exactly when a hidden entity came to hold
    the value."""
    w = g.World(owner)
    value = _email()
    mine = _post_selector(client, w, w.analyst, raw_value=value).json()
    red = _selector_node(client, w, w.boss, value, "RED")

    def read(uid):
        return client.get(w.url("/selectors"), headers=w.headers(uid),
                          params={"selector_type": "EMAIL", "value": value}).json()

    still = read(w.analyst)
    assert (still["id"], still["node_id"], still["observation_cnt"]) == (
        mine["id"], None, 1)
    cleared = read(w.boss)
    assert (cleared["node_id"], cleared["id"] != mine["id"]) == (red, True)
    # The cleared caller's sighting is counted on the row they can read, and
    # does not touch the analyst's.
    again = _post_selector(client, w, w.boss, raw_value=value).json()
    assert (again["id"], again["node_id"], again["observation_cnt"]) == (
        cleared["id"], red, 2)
    assert read(w.analyst)["observation_cnt"] == 1


def test_a_row_owned_above_the_caller_is_never_shown_or_counted_even_if_mislabelled(
        owner, client):
    """A row written below its owner's labels is what a restore with triggers
    off could leave (the trigger makes it impossible otherwise, and is
    switched off here to forge it). The readers test the owner as well as the
    row, and a sighting that would collide with it is refused, not answered
    with what it holds."""
    w = g.World(owner)
    value = _email()
    _selector_node(client, w, w.boss, value, "RED")
    owner.execute("ALTER TABLE core.selector DISABLE TRIGGER "
                  "selector_labels_follow_owner")
    try:
        owner.execute("UPDATE core.selector SET classification = 'CLEAR' "
                      "WHERE case_id = %s AND norm_value = %s",
                      (w.case_id, value.lower()))
    finally:
        owner.execute("ALTER TABLE core.selector ENABLE TRIGGER "
                      "selector_labels_follow_owner")
    read = client.get(w.url("/selectors"), headers=w.headers(w.analyst),
                      params={"selector_type": "EMAIL", "value": value})
    assert read.status_code == 200 and read.json() is None
    sighting = _post_selector(client, w, w.analyst, raw_value=value)
    assert g.answer(sighting) == (400, "that selector could not be recorded")
    assert str(owner.execute("SELECT node_id FROM core.selector WHERE case_id = %s "
                             "AND norm_value = %s", (w.case_id, value.lower())
                             ).fetchone()[0]) not in sighting.text
    assert owner.execute("SELECT observation_cnt FROM core.selector WHERE case_id = %s "
                         "AND norm_value = %s", (w.case_id, value.lower())
                         ).fetchone()[0] == 1


def test_a_merges_basis_selector_is_a_row_of_this_case_the_merger_may_read(
        owner, client):
    w = g.World(owner)
    red_value = _email()
    _selector_node(client, w, w.boss, red_value, "RED")
    hidden = owner.execute(
        "SELECT id FROM core.selector WHERE case_id = %s AND classification = 'RED'",
        (w.case_id,)).fetchone()[0]
    other_owner = s.user(owner, "RED", prefix=g.PREFIX)
    other_case = s.case(owner, other_owner, "AMBER")
    foreign = owner.execute(
        "INSERT INTO core.selector (case_id, selector_type, raw_value, norm_value) "
        "VALUES (%s, 'EMAIL', 'g42@example.org', 'g42@example.org') RETURNING id",
        (other_case,)).fetchone()[0]
    mine = _post_selector(client, w, w.lead, raw_value=_email()).json()["id"]

    def merge(basis):
        a, b = w.node("g42 a"), w.node("g42 b")
        return client.post(w.url("/merges"), headers=w.headers(w.lead), json={
            "source_node_id": str(a), "target_node_id": str(b),
            "reason": "g42 basis", "basis_selector_id": str(basis)})

    refused = [g.answer(merge(x)) for x in (uuid4(), foreign, hidden)]
    assert refused == [(400, "basis_selector_id does not name a selector of "
                             "this case")] * 3
    assert merge(mine).status_code == 201
    # Raised as a two-person request, the same check before a signer is asked.
    a, b = w.node("g42 a2"), w.node("g42 b2")
    request = client.post(w.url("/approvals"), headers=w.headers(w.lead), json={
        "operation": "node.merge", "justification": "g42 basis",
        "payload": {"source_node_id": str(a), "target_node_id": str(b),
                    "reason": "g42", "basis_selector_id": str(hidden)}})
    assert g.answer(request) == (400, "basis_selector_id does not name a "
                                      "selector of this case")


# --- ties to an entity above the caller (graph-edge-endpoints-not-gated) ----

def _edge(client, w, uid, src, dst, edge_type="VOUCHED_FOR", **extra):
    return client.post(w.url("/edges"), headers=w.headers(uid), json={
        "edge_type": edge_type, "src_node_id": str(src), "dst_node_id": str(dst),
        "assertion": CLAIM, **extra})


def _live_ties(owner, w) -> int:
    return owner.execute("SELECT count(*) FROM core.edge WHERE case_id = %s "
                         "AND deleted_at IS NULL", (w.case_id,)).fetchone()[0]


def test_a_tie_to_an_entity_above_the_caller_is_the_missing_entity(owner, client):
    w = g.World(owner)
    red, amber = w.node("g42 red", "RED"), w.node("g42 amber")
    other_owner = s.user(owner, "RED", prefix=g.PREFIX)
    other_case = s.case(owner, other_owner, "AMBER")
    foreign = s.node(owner, other_case, other_owner, "g42 foreign")
    # The caller is refused a claim on the same entity: the gate is one.
    assert client.post(w.url(f"/nodes/{red}/assertions"), headers=w.headers(w.lead),
                       json=CLAIM).status_code == 404

    for end in ("dst", "src"):
        def attempt(named, end=end):
            pair = (amber, named) if end == "dst" else (named, amber)
            return _edge(client, w, w.lead, *pair)

        miss = attempt(uuid4())
        assert g.answer(attempt(red)) == g.answer(miss) == (
            404, "no such node in this case"), end
        assert g.answer(attempt(foreign)) == g.answer(miss), end
    assert _live_ties(owner, w) == 0
    assert client.get(w.url("/edges"), headers=w.headers(w.boss)).json() == []


def test_a_tie_between_entities_the_caller_can_read_is_still_made(owner, client):
    w = g.World(owner)
    a, b = w.node("g42 a"), w.node("g42 b")
    red1, red2 = w.node("g42 red one", "RED"), w.node("g42 red two", "RED")
    assert _edge(client, w, w.lead, a, b).status_code == 201
    # The cleared owner ties RED entities as before.
    assert _edge(client, w, w.boss, red1, red2).status_code == 201
    assert _edge(client, w, w.boss, a, red1).status_code == 201


def test_a_tie_to_a_merged_away_or_retired_entity_is_refused(owner, client):
    """graph-unmerge-500-and-ties-to-merged-nodes: such a tie was accepted,
    drawn nowhere, listed by GET /edges, and made the merge's reversal fail."""
    from noctornal_api.graph import GraphWriteService
    from noctornal_api.merges import MergeService
    w = g.World(owner)
    a, b, c = w.node("g42 a"), w.node("g42 b"), w.node("g42 c")
    MergeService(owner).merge(case_id=w.case_id, source_node_id=a,
                              target_node_id=b, merged_by=w.boss, reason="same")
    refused = _edge(client, w, w.lead, a, c)
    assert refused.status_code == 409, refused.text
    assert "merged into another" in refused.json()["detail"]
    assert str(b) in refused.json()["detail"]
    assert _live_ties(owner, w) == 0

    gone = w.node("g42 gone")
    GraphWriteService(owner).soft_delete_node(
        gone, case_id=w.case_id, deleted_by=w.boss,
        at=datetime.now(timezone.utc), clearance="RED", compartments=[])
    retired = _edge(client, w, w.lead, gone, c)
    assert retired.status_code == 409 and "retired" in retired.json()["detail"]

    # A survivor the caller cannot read is not named to them.
    d, red_keeper = w.node("g42 d"), w.node("g42 red keeper", "RED")
    MergeService(owner).merge(case_id=w.case_id, source_node_id=d,
                              target_node_id=red_keeper, merged_by=w.boss,
                              reason="the amber handle of the red one")
    hidden_survivor = _edge(client, w, w.lead, d, c)
    assert hidden_survivor.status_code == 409
    assert str(red_keeper) not in hidden_survivor.text

    # An entity above the caller that is also merged is still just missing.
    hidden_and_merged = w.node("g42 red merged", "RED")
    MergeService(owner).merge(case_id=w.case_id, source_node_id=hidden_and_merged,
                              target_node_id=red_keeper, merged_by=w.boss,
                              reason="two red handles")
    miss = _edge(client, w, w.lead, uuid4(), c)
    assert g.answer(_edge(client, w, w.lead, hidden_and_merged, c)) == g.answer(miss)


def test_a_write_on_a_tie_to_an_entity_above_the_caller_is_the_missing_tie(
        owner, client):
    """The tie is labelled AMBER and joins an AMBER entity to a RED one: drawn
    for no AMBER reader, but its own label let one who held its id correct,
    retire or add a claim to it."""
    w = g.World(owner)
    amber, red = w.node("g42 amber"), w.node("g42 red", "RED")
    tie = w.edge(amber, red, "AMBER")
    H = w.headers(w.analyst)
    calls = {
        "correct": lambda i: client.patch(
            w.url(f"/graph/edges/{i}"), headers=H,
            json={"weight": 0.5, "assertion": CLAIM}),
        "retire": lambda i: client.request(
            "DELETE", w.url(f"/graph/edges/{i}"), headers=H,
            json={"reason": "probe"}),
        "claim": lambda i: client.post(
            w.url(f"/edges/{i}/assertions"), headers=H, json=CLAIM),
    }
    for name, call in calls.items():
        hit, miss = call(tie), call(uuid4())
        assert g.answer(hit) == g.answer(miss) == (
            404, "no such edge in this case"), name
    assert owner.execute("SELECT deleted_at IS NULL FROM core.edge WHERE id = %s",
                         (tie,)).fetchone()[0]
    # The cleared owner still changes it, and the caller still changes a tie
    # between entities they can read.
    assert client.patch(w.url(f"/graph/edges/{tie}"), headers=w.headers(w.boss),
                        json={"weight": 0.5, "assertion": CLAIM}
                        ).status_code == 200
    a, b = w.node("g42 a"), w.node("g42 b")
    own = w.edge(a, b)
    assert client.patch(w.url(f"/graph/edges/{own}"), headers=H,
                        json={"weight": 0.5, "assertion": CLAIM}
                        ).status_code == 200


# --- retirement through a tie to an entity above the caller -----------------

def test_retiring_an_entity_tied_to_one_above_the_caller_is_refused_whole(
        owner, client):
    from noctornal_api.graph import HIDDEN_TIES_REFUSAL
    w = g.World(owner)
    red = w.node("g42 red", "RED")
    amber, plain = w.node("g42 amber"), w.node("g42 plain")
    low_tie = w.edge(amber, red, "AMBER")
    # Reference: a tie that is itself above the caller, the case the guard
    # always refused. Both refusals must read the same.
    amber2, amber3 = w.node("g42 amber two"), w.node("g42 amber three")
    w.edge(amber2, amber3, "RED")

    refused = client.request("DELETE", w.url(f"/graph/nodes/{amber}"),
                             headers=w.headers(w.lead), json={"reason": "probe"})
    reference = client.request("DELETE", w.url(f"/graph/nodes/{amber2}"),
                               headers=w.headers(w.lead), json={"reason": "probe"})
    assert refused.status_code == reference.status_code
    assert g.answer(refused) == g.answer(reference)
    assert HIDDEN_TIES_REFUSAL in refused.json()["detail"]
    assert "edges_retired" not in refused.text
    assert owner.execute("SELECT deleted_at IS NULL FROM core.edge WHERE id = %s",
                         (low_tie,)).fetchone()[0]
    assert owner.execute("SELECT deleted_at IS NULL FROM core.node WHERE id = %s",
                         (amber,)).fetchone()[0]

    # Nothing a legitimate caller could do is taken away: the cleared owner
    # retires it, and the caller retires an entity whose ties they can all see.
    ok = client.request("DELETE", w.url(f"/graph/nodes/{amber}"),
                        headers=w.headers(w.boss), json={"reason": "retire"})
    assert ok.status_code == 200 and ok.json()["edges_retired"] == 1
    w.edge(plain, amber2)
    own = client.request("DELETE", w.url(f"/graph/nodes/{plain}"),
                         headers=w.headers(w.lead), json={"reason": "retire"})
    assert own.status_code == 200 and own.json()["edges_retired"] == 1


# --- edge_uniq_active (rls-3) --------------------------------------------------

def test_a_tie_beside_a_hidden_one_of_the_same_type_is_made_not_refused(
        owner, client):
    w = g.World(owner)
    a, b, c = w.node("g42 a"), w.node("g42 b"), w.node("g42 c")
    w.edge(a, b, "RED")
    assert client.get(w.url("/edges"), headers=w.headers(w.analyst)).json() == []

    beside_hidden = _edge(client, w, w.analyst, a, b)
    no_hidden = _edge(client, w, w.analyst, b, c)
    assert beside_hidden.status_code == no_hidden.status_code == 201, (
        beside_hidden.text, no_hidden.text)
    # The tie at the caller's own label is now theirs to see, and a second one
    # at the same labels is the duplicate it always was.
    dup = _edge(client, w, w.analyst, a, b)
    assert dup.status_code == 400 and "already exists" in dup.json()["detail"]
    # The cleared owner is not blocked by the lower one, nor does the lower
    # one shadow the RED duplicate.
    assert _edge(client, w, w.boss, a, b, classification="RED").status_code == 400


def test_the_key_names_the_labels_and_0133_round_trips(owner):
    m = _migration(owner, "0133")
    keyed = _index(owner)
    assert "classification" in keyed and "compartments" in keyed
    w = g.World(owner)
    a, b = w.node("g42 a"), w.node("g42 b")
    w.edge(a, b, "RED")
    w.edge(a, b, "AMBER")
    with pytest.raises(_RollBack), owner.transaction():
        # Two live ties at different labels cannot go back under the 0006 key:
        # the honest answer of a downgrade over data the old key forbade.
        with pytest.raises(psycopg.errors.UniqueViolation), owner.transaction():
            m.downgrade()
        owner.execute("UPDATE core.edge SET deleted_at = now() "
                      "WHERE case_id = %s AND classification = 'RED'", (w.case_id,))
        m.downgrade()
        assert "classification" not in _index(owner)
        m.upgrade()
        assert _index(owner) == keyed
        raise _RollBack
    assert _index(owner) == keyed


class _RollBack(Exception):
    pass


def _migration(conn, name):
    import importlib.util
    from pathlib import Path
    versions = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
    path = next(versions.glob(f"{name}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m_g42_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


def _index(conn) -> str:
    return conn.execute(
        "SELECT indexdef FROM pg_indexes WHERE schemaname = 'core' "
        "AND indexname = 'edge_uniq_active'").fetchone()[0]
