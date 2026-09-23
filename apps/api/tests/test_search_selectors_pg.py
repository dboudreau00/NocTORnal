"""Search finds entities by their selectors, by fragments, and says when a
list is capped (ux09-search, 2026-09-22).

Three findings from the 2026-09-22 review, each a way the Search pane gave
an analyst a clean answer that was wrong:

- selectors-unsearchable: ember_hobby held a wallet and a Jabber id, and
  pasting either into Search answered "No matches." The node search vector
  is label plus attrs and nothing joined `core.selector`.
- whole-token-false-negatives: "skua" missed harrow_skua2, "hostmarket"
  missed 26 vps-*.hostmarket.example hosts and "remittance" missed
  remittance-change.eml, because `plainto_tsquery` matched whole lexemes
  and the 'simple' parser keeps a host or a file name as one.
- silent-truncation-50: 73 matches, 50 drawn, nothing said, and ties
  broken by whatever order the plan produced.

Every selector test also asserts the gate: a selector is an observable
ABOUT its node, so it is matched only through a node the caller may see,
exactly as `GET /selectors` and `GET /nodes/{id}/selectors` withhold it.

Env-gated on DATABASE_URL (and MINIO_ENDPOINT for the exhibit test).
Users are `ssel-`; no other suite's teardown pattern matches them.
"""
from __future__ import annotations

import os
from datetime import date
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
MINIO = os.environ.get("MINIO_ENDPOINT", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; search tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple"
EMAIL_LIKE = "ssel-%@noctornal.test"
#: Left registered on purpose, for the reason test_case_lifecycle_api_pg
#: gives: withdrawing a compartment key is refused once anything used it.
TEST_COMPARTMENT = "OP_SSEL"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    esub = f"(SELECT id FROM core.evidence WHERE case_id IN {csub})"
    # Custody rows stay and the chain trigger stays up, as in
    # test_curation_pg: what a custody row points at stays with it.
    pinned_evidence = "(SELECT evidence_id FROM core.evidence_custody)"
    pinned_cases = "(SELECT case_id FROM core.evidence WHERE case_id IS NOT NULL)"
    pinned_users = (
        "(SELECT actor_id FROM core.evidence_custody WHERE actor_id IS NOT NULL"
        " UNION SELECT acquired_by FROM core.evidence WHERE acquired_by IS NOT NULL"
        ' UNION SELECT owner_user_id FROM core."case" WHERE owner_user_id IS NOT NULL'
        ' UNION SELECT deputy_user_id FROM core."case" WHERE deputy_user_id IS NOT NULL)'
    )
    # ONE transaction: `assertion_protects_element` (0022) is a deferred
    # constraint trigger, so assertions and nodes must vanish together.
    with c.transaction():
        c.execute(f"DELETE FROM core.selector WHERE case_id IN {csub}")
        c.execute(f"""DELETE FROM core.node_merge_edge WHERE merge_id IN
                      (SELECT id FROM core.node_merge WHERE case_id IN {csub})""")
        c.execute(f"DELETE FROM core.node_merge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN {esub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub} "
                  f"AND id NOT IN {pinned_evidence}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub} '
                  f"AND id NOT IN {pinned_cases}")
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub} "
                  f"AND user_id NOT IN {pinned_users}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub} "
                  f"AND user_id NOT IN {pinned_users}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}' "
                  f"AND id NOT IN {pinned_users}")
    c.close()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


# --- helpers ------------------------------------------------------------

def _user(conn, *, clearance="RED", roles=()):
    from noctornal_api.security import totp
    from noctornal_api.stores import PgUserStore
    email = f"ssel-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Selector searcher", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute(
            "INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
            (uid, role))
    return uid, email


def _session(conn, email) -> str:
    """Minted the way test_search_documents_pg mints one, for its reasons."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    uid = conn.execute("SELECT id FROM iam.app_user WHERE email = %s",
                       (email,)).fetchone()[0]
    _, token = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=True)
    return token


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _case(conn, owner):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-SSEL-{uuid4().hex[:6]}", title="Selector search",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _node(conn, case_id, uid, label, *, classification="AMBER",
          compartments=None, attrs=None):
    """Through the real write path, so it carries its assertion."""
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=uid,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid),
        classification=classification, compartments=compartments, attrs=attrs)


def _selector(conn, case_id, node_id, selector_type, value):
    from noctornal_api.selectors import SelectorStore
    return SelectorStore(conn).record(case_id=case_id, selector_type=selector_type,
                                      raw_value=value, node_id=node_id)


def _tok() -> str:
    """Letters only, so no digit run turns into a separate lexeme and no
    other row in the database can contain it."""
    return "zq" + "".join(chr(ord("a") + int(c, 16) % 26) for c in uuid4().hex[:10])


def _wallet() -> str:
    """A bech32-shaped address no other row holds."""
    body = "".join(chr(ord("a") + int(c, 16) % 26) for c in uuid4().hex)
    return ("bc1q" + body)[:42]


def _svc(conn):
    from noctornal_api.curation import SearchService
    return SearchService(conn)


def _nodes(conn, case_id, q, *, clearance="RED", compartments=frozenset(), limit=50):
    return _svc(conn).node_page(case_id=case_id, query=q, limit=limit,
                                clearance=clearance, compartments=compartments)


@pytest.fixture
def world(conn):
    owner, email = _user(conn, roles=("CASE_OWNER",))
    return owner, email, _case(conn, owner)


# --- selectors-unsearchable ---------------------------------------------

def test_a_wallet_finds_the_entity_that_holds_it_exact_and_partial(conn, world):
    """The finding's own repro: the wallet, pasted whole, finds its holder
    and says it was an exact selector match; typed in capitals it still
    does (the ontology's BTC normaliser); a fragment finds it too, and
    says it was not exact."""
    owner, _, case_id = world
    tok = _tok()
    holder = _node(conn, case_id, owner, f"ember_{tok}")
    bystander = _node(conn, case_id, owner, f"other_{tok}")
    wallet = _wallet()
    _selector(conn, case_id, holder, "BTC_ADDR", wallet)

    for query in (wallet, wallet.upper()):
        page = _nodes(conn, case_id, query)
        assert [h.id for h in page.hits] == [holder], (
            f"{query!r} did not find exactly the entity holding the wallet")
        hit = page.hits[0]
        assert hit.via is not None and hit.via.selector_type == "BTC_ADDR"
        assert hit.via.value == wallet and hit.via.exact
        assert hit.rank == 1.0

    part = _nodes(conn, case_id, wallet[:12])
    assert [h.id for h in part.hits] == [holder]
    assert part.hits[0].via.exact is False
    assert bystander not in [h.id for h in part.hits]


def test_a_jabber_domain_fragment_finds_every_holder(conn, world):
    """"nightmarket" found none of the 73 personas holding a
    @nightmarket.im id. A domain fragment now finds each holder, once,
    with the selector that matched."""
    owner, _, case_id = world
    tok = _tok()
    a = _node(conn, case_id, owner, "first persona")
    b = _node(conn, case_id, owner, "second persona")
    c = _node(conn, case_id, owner, "third persona")
    _selector(conn, case_id, a, "JABBER", f"alpha@{tok}market.im")
    _selector(conn, case_id, b, "JABBER", f"bravo@{tok}market.im")
    _selector(conn, case_id, b, "EMAIL", f"bravo@{tok}market.im")
    _selector(conn, case_id, c, "JABBER", "charlie@elsewhere.im")

    page = _nodes(conn, case_id, f"{tok}market")
    assert sorted(h.id for h in page.hits) == sorted([a, b])
    assert page.total == 2
    by_id = {h.id: h for h in page.hits}
    assert by_id[a].via.selector_type == "JABBER"
    assert by_id[b].via.more == 1, (
        "the second matching selector on the same entity must be counted, "
        "not listed as a second hit")

    exact = _nodes(conn, case_id, f"alpha@{tok}market.im")
    assert [h.id for h in exact.hits] == [a] and exact.hits[0].via.exact


def test_the_selector_lookup_lists_only_selector_matches(conn, world):
    """`selector_page` is the palette's lookup: entities whose NAME matches
    are the palette's own business, so they are not returned here."""
    owner, _, case_id = world
    tok = _tok()
    by_name = _node(conn, case_id, owner, f"{tok}market fan")
    by_selector = _node(conn, case_id, owner, "quiet persona")
    _selector(conn, case_id, by_selector, "JABBER", f"quiet@{tok}market.im")

    page = _svc(conn).selector_page(case_id=case_id, query=f"{tok}market",
                                    limit=10, clearance="RED",
                                    compartments=frozenset())
    assert [h.id for h in page.hits] == [by_selector]
    assert page.total == 1
    assert by_name not in [h.id for h in page.hits]
    assert page.hits[0].via.value == f"quiet@{tok}market.im"


def test_a_selector_never_reaches_past_the_callers_ceiling(conn, world):
    """The gate: a RED entity's wallet must not make it findable by an
    AMBER caller, nor a compartmented entity's by a caller outside the
    compartment. Neither the hit nor the count may betray it."""
    owner, _, case_id = world
    conn.execute(
        "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
        "ON CONFLICT (key) DO NOTHING", (TEST_COMPARTMENT, "Selector search test"))
    red = _node(conn, case_id, owner, "red persona", classification="RED")
    walled = _node(conn, case_id, owner, "walled persona",
                   compartments=[TEST_COMPARTMENT])
    red_wallet, walled_wallet = _wallet(), _wallet()
    _selector(conn, case_id, red, "BTC_ADDR", red_wallet)
    _selector(conn, case_id, walled, "BTC_ADDR", walled_wallet)

    svc = _svc(conn)
    for wallet in (red_wallet, walled_wallet, red_wallet[:12]):
        amber = _nodes(conn, case_id, wallet, clearance="AMBER")
        assert amber.hits == [] and amber.total == 0
        assert svc.selector_page(case_id=case_id, query=wallet, clearance="AMBER",
                                 compartments=frozenset()).total == 0

    outside = _nodes(conn, case_id, walled_wallet, clearance="RED")
    assert outside.hits == [] and outside.total == 0

    assert [h.id for h in _nodes(conn, case_id, red_wallet).hits] == [red]
    inside = _nodes(conn, case_id, walled_wallet,
                    compartments=frozenset({TEST_COMPARTMENT}))
    assert [h.id for h in inside.hits] == [walled]


def test_a_selector_on_a_deleted_entity_is_not_matched(conn, world):
    owner, _, case_id = world
    gone = _node(conn, case_id, owner, "deleted persona")
    wallet = _wallet()
    _selector(conn, case_id, gone, "BTC_ADDR", wallet)
    conn.execute("UPDATE core.node SET deleted_at = now() WHERE id = %s", (gone,))
    assert _nodes(conn, case_id, wallet).total == 0


def test_a_selector_on_a_merged_record_finds_the_survivor(conn, world):
    """A merge moves edges, not selectors (merges.py), so the wallet stays
    on the merged record. Without following the redirect the wallet found
    nothing at all: the loser is excluded as merged and the survivor does
    not hold it. The hit names the record that does."""
    from noctornal_api.merges import MergeService
    owner, _, case_id = world
    loser = _node(conn, case_id, owner, "alt persona")
    survivor = _node(conn, case_id, owner, "main persona")
    final = _node(conn, case_id, owner, "final persona")
    wallet = _wallet()
    _selector(conn, case_id, loser, "BTC_ADDR", wallet)
    merges = MergeService(conn)
    merges.merge(case_id=case_id, source_node_id=loser, target_node_id=survivor,
                 merged_by=owner, reason="same wallet, same writing style")

    page = _nodes(conn, case_id, wallet)
    assert [h.id for h in page.hits] == [survivor]
    assert page.hits[0].via.merged_from == "alt persona"

    merges.merge(case_id=case_id, source_node_id=survivor, target_node_id=final,
                 merged_by=owner, reason="one operator behind both")
    assert [h.id for h in _nodes(conn, case_id, wallet).hits] == [final]


def test_a_merge_chain_never_reaches_past_the_callers_ceiling(conn, client, world):
    """The merge chain is walked with the caller's ceiling at EVERY hop.
    Two shapes, each of which an AMBER analyst must not see through:

    - a visible record merged into a RED survivor. The wallet is on the
      AMBER record, so without the gate the RED survivor's label comes
      back as the hit (the verifier's probe, 2026-09-22 fix round);
    - a visible record merged through a RED record into a visible
      survivor. Reaching the survivor would disclose the RED link in the
      chain, and only the per-hop predicate stops it: the survivor itself
      passes every later filter, so this is the shape that fails if the
      recursive step loses its predicate.
    """
    from noctornal_api.cases import CaseService
    from noctornal_api.merges import MergeService
    owner, _, case_id = world
    merges = MergeService(conn)

    alt = _node(conn, case_id, owner, "amber alt")
    red_survivor = _node(conn, case_id, owner, "red truename", classification="RED")
    up_wallet = _wallet()
    _selector(conn, case_id, alt, "BTC_ADDR", up_wallet)
    merges.merge(case_id=case_id, source_node_id=alt, target_node_id=red_survivor,
                 merged_by=owner, reason="same wallet")

    first = _node(conn, case_id, owner, "amber first")
    red_middle = _node(conn, case_id, owner, "red middle", classification="RED")
    last = _node(conn, case_id, owner, "amber last")
    through_wallet = _wallet()
    _selector(conn, case_id, first, "BTC_ADDR", through_wallet)
    merges.merge(case_id=case_id, source_node_id=first, target_node_id=red_middle,
                 merged_by=owner, reason="same wallet")
    merges.merge(case_id=case_id, source_node_id=red_middle, target_node_id=last,
                 merged_by=owner, reason="same operator")

    svc = _svc(conn)
    for wallet in (up_wallet, through_wallet, up_wallet[:12], through_wallet[:12]):
        amber = _nodes(conn, case_id, wallet, clearance="AMBER")
        assert amber.hits == [] and amber.total == 0, wallet
        sel = svc.selector_page(case_id=case_id, query=wallet, clearance="AMBER",
                                compartments=frozenset())
        assert sel.hits == [] and sel.total == 0, wallet

    amber_user, amber_email = _user(conn, clearance="AMBER")
    CaseService(conn).assign_user(case_id, amber_user, "ANALYST", granted_by=owner)
    ah = _auth(_session(conn, amber_email))
    base = f"/api/v1/cases/{case_id}"
    for wallet in (up_wallet, through_wallet):
        for route in ("/search/nodes", "/search/selectors"):
            r = client.get(base + route, headers=ah,
                           params={"q": wallet, "with_total": "true"})
            assert r.status_code == 200, r.text
            assert r.json() == {"hits": [], "total": 0, "limit": 50}, (route, r.text)
            assert "red" not in r.text
        combined = client.get(base + "/search", headers=ah, params={"q": wallet})
        assert combined.json()["totals"]["node"] == 0 and "red" not in combined.text

    # A caller cleared for the whole chain is taken to the live survivor.
    up = _nodes(conn, case_id, up_wallet)
    assert [h.id for h in up.hits] == [red_survivor]
    assert up.hits[0].via.merged_from == "amber alt"
    assert [h.id for h in _nodes(conn, case_id, through_wallet).hits] == [last]
    assert [h.id for h in svc.selector_page(
        case_id=case_id, query=through_wallet, clearance="RED",
        compartments=frozenset()).hits] == [last]


def test_a_hidden_record_merged_into_a_visible_one_does_not_lend_it_its_selectors(
        conn, client, world):
    """The chain's ANCHOR (depth 0) is gated as well as every hop after it.

    A record the caller may not see holds the wallet and is merged INTO a
    survivor they may see. MergeService does not raise the survivor's
    label, so the survivor passes every later filter, and the anchor's
    predicate is the only thing that keeps the hidden record's label (sent
    as `via.merged_from`) and its wallet (sent as `via.value`) from the
    caller. No test held it: an in-memory mutant that removed the anchor's
    classification and compartments lines passed all 17 (verifier of the
    second 2026-09-22 fix round). One shape per line of the predicate, so
    removing either one alone fails here:

    - a RED record merged into an AMBER survivor, searched by an AMBER
      caller (the classification line);
    - a compartmented record merged into an uncompartmented survivor,
      searched by a RED caller outside the compartment (the compartments
      line).
    """
    from noctornal_api.cases import CaseService
    from noctornal_api.merges import MergeService
    owner, _, case_id = world
    conn.execute(
        "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
        "ON CONFLICT (key) DO NOTHING", (TEST_COMPARTMENT, "Selector search test"))
    merges = MergeService(conn)
    tok = _tok()

    red_holder = _node(conn, case_id, owner, f"RED holder {tok}", classification="RED")
    amber_survivor = _node(conn, case_id, owner, "amber survivor")
    red_wallet = _wallet()
    _selector(conn, case_id, red_holder, "BTC_ADDR", red_wallet)
    merges.merge(case_id=case_id, source_node_id=red_holder,
                 target_node_id=amber_survivor, merged_by=owner, reason="same wallet")

    walled_holder = _node(conn, case_id, owner, f"walled holder {tok}",
                          compartments=[TEST_COMPARTMENT])
    open_survivor = _node(conn, case_id, owner, "open survivor")
    walled_wallet = _wallet()
    _selector(conn, case_id, walled_holder, "BTC_ADDR", walled_wallet)
    merges.merge(case_id=case_id, source_node_id=walled_holder,
                 target_node_id=open_survivor, merged_by=owner, reason="same wallet")

    svc = _svc(conn)
    for wallet, clearance in ((red_wallet, "AMBER"), (walled_wallet, "RED")):
        for query in (wallet, wallet.upper(), wallet[:12]):
            nodes = _nodes(conn, case_id, query, clearance=clearance)
            assert nodes.hits == [] and nodes.total == 0, (query, nodes)
            sel = svc.selector_page(case_id=case_id, query=query, clearance=clearance,
                                    compartments=frozenset())
            assert sel.hits == [] and sel.total == 0, (query, sel)

    # Over HTTP, as an AMBER analyst assigned to the case: nothing, and
    # neither hidden label nor either wallet anywhere in the body.
    amber_user, amber_email = _user(conn, clearance="AMBER")
    CaseService(conn).assign_user(case_id, amber_user, "ANALYST", granted_by=owner)
    ah = _auth(_session(conn, amber_email))
    base = f"/api/v1/cases/{case_id}"
    for wallet in (red_wallet, walled_wallet):
        for query in (wallet, wallet[:12]):
            for route in ("/search/nodes", "/search/selectors"):
                r = client.get(base + route, headers=ah,
                               params={"q": query, "with_total": "true"})
                assert r.status_code == 200, r.text
                assert r.json() == {"hits": [], "total": 0, "limit": 50}, (route, r.text)
                assert tok not in r.text and wallet not in r.text
            combined = client.get(base + "/search", headers=ah, params={"q": query})
            assert combined.status_code == 200, combined.text
            assert combined.json()["totals"]["node"] == 0, combined.text
            assert tok not in combined.text and wallet not in combined.text

    # The control: a caller cleared for the hidden record, and inside the
    # compartment, is taken to the survivor and told which record holds
    # the wallet. Without this the empty answers above could be a merge
    # that never happened.
    cleared = frozenset({TEST_COMPARTMENT})
    for wallet, survivor, holder in ((red_wallet, amber_survivor, f"RED holder {tok}"),
                                     (walled_wallet, open_survivor, f"walled holder {tok}")):
        page = _nodes(conn, case_id, wallet, compartments=cleared)
        assert [h.id for h in page.hits] == [survivor]
        assert page.hits[0].via.merged_from == holder
        assert page.hits[0].via.value == wallet and page.hits[0].via.exact
        sel = svc.selector_page(case_id=case_id, query=wallet[:12], clearance="RED",
                                compartments=cleared)
        assert [h.id for h in sel.hits] == [survivor]


def test_a_lossy_normalisation_is_not_reported_as_an_exact_match(conn, world):
    """The digits-only normalisers turn the wallet fragment "bc1q7t0p"
    into "170". Matched on that, an unrelated Discord id 170 would come
    back as an EXACT selector match for a wallet it has nothing to do
    with."""
    owner, _, case_id = world
    discord = _node(conn, case_id, owner, "discord persona")
    _selector(conn, case_id, discord, "DISCORD_ID", "170")
    assert _nodes(conn, case_id, "bc1q7t0p").total == 0


def test_an_exact_selector_beats_a_fragment_on_the_same_entity(conn, client, world):
    """The commonest real shape: a persona holds its handle as HANDLE "x"
    and as JABBER "x@host", or a wallet and a block-explorer URL that
    contains it. Searching the handle or the wallet must report the EXACT
    selector at rank 1.0. The third fix round reported the Jabber id or
    the URL instead, not exact, at 0.46 and 0.57: with no type label in
    the query `exact` was NULL rather than false, and NULL sorted first
    (verifier of the third 2026-09-22 fix round). Neither the node search,
    the palette's lookup nor either route may disagree."""
    owner, email, case_id = world
    tok = _tok()
    persona = _node(conn, case_id, owner, "Person X")
    payer = _node(conn, case_id, owner, "Payer Y")
    handle = f"ember_{tok}"
    wallet = _wallet()
    _selector(conn, case_id, persona, "HANDLE", handle)
    _selector(conn, case_id, persona, "JABBER", f"{handle}@nightmarket.im")
    _selector(conn, case_id, payer, "BTC_ADDR", wallet)
    _selector(conn, case_id, payer, "URL", "https://mempool.space/address/" + wallet)

    svc = _svc(conn)
    for query, holder, via_type, value in (
        (handle, persona, "HANDLE", handle),
        (wallet, payer, "BTC_ADDR", wallet),
    ):
        for page in (_nodes(conn, case_id, query),
                     svc.selector_page(case_id=case_id, query=query, clearance="RED",
                                       compartments=frozenset())):
            assert [h.id for h in page.hits] == [holder], (query, page.hits)
            hit = page.hits[0]
            assert hit.via.selector_type == via_type, (query, hit.via)
            assert hit.via.value == value and hit.via.exact is True, (query, hit.via)
            assert hit.via.more == 1, (query, hit.via)
            assert hit.rank == 1.0, (query, hit.rank)

    oh = _auth(_session(conn, email))
    base = f"/api/v1/cases/{case_id}"
    for route in ("/search/nodes", "/search/selectors"):
        r = client.get(base + route, headers=oh,
                       params={"q": handle, "with_total": "true"})
        assert r.status_code == 200, r.text
        row = r.json()["hits"][0]
        assert row["via"]["selector_type"] == "HANDLE", (route, row)
        assert row["via"]["exact"] is True and row["rank"] == 1.0, (route, row)


def test_a_case_only_difference_is_exact_only_where_the_type_folds_case(conn, world):
    """A Matrix localpart, a SIP user part and a base58 wallet are
    case-sensitive: "@alice:x" is a different account from "@Alice:x".
    The first fix compared raw values case-blind and printed "(exact)" on
    the other account at rank 1.0 (verifier, 2026-09-22 fix round). They
    are still found, as fragments, and never as exact. Where the type
    DOES fold case (a Matrix server name, a SIP host, an email address),
    the case variant is the same identifier and stays exact."""
    owner, _, case_id = world
    tok = _tok()
    mx = _node(conn, case_id, owner, "matrix persona")
    sip = _node(conn, case_id, owner, "sip persona")
    b58 = _node(conn, case_id, owner, "base58 persona")
    mail = _node(conn, case_id, owner, "mail persona")
    base58 = "1Bo" + tok[:6].upper() + tok[6:]
    _selector(conn, case_id, mx, "MATRIX_MXID", f"@Alice{tok}:example.org")
    _selector(conn, case_id, sip, "SIP_URI", f"sip:Bob{tok}@voip.example")
    _selector(conn, case_id, b58, "BTC_ADDR", base58)
    _selector(conn, case_id, mail, "EMAIL", f"Carol{tok}@Example.org")

    for query, holder, exact in (
        (f"@alice{tok}:example.org", mx, False),
        (f"@Alice{tok}:EXAMPLE.org", mx, True),
        (f"sip:bob{tok}@voip.example", sip, False),
        (f"SIP:Bob{tok}@VOIP.example", sip, True),
        (base58.lower(), b58, False),
        (base58, b58, True),
        (f"carol{tok}@example.org", mail, True),
    ):
        page = _nodes(conn, case_id, query)
        assert [h.id for h in page.hits] == [holder], query
        hit = page.hits[0]
        assert hit.via.exact is exact, query
        assert (hit.rank == 1.0) is exact, (query, hit.rank)


def test_a_types_own_notation_is_exact_and_a_namespace_is_not_dropped(conn, world):
    """"u:139292958" is the ontology's namespaced Telegram user. Its digits
    are not a Discord id, and the first fix reported them as an EXACT
    Discord match because the lost "u" was under a quarter of the query.
    Conversely "AS13335" IS the ASN 13335 and a Bot-API "-100..." chat id
    IS the channel c:<id>: both were missed, because the normaliser drops
    or decodes characters on purpose (verifier, 2026-09-22 fix round)."""
    owner, _, case_id = world
    discord = _node(conn, case_id, owner, "discord persona")
    telegram = _node(conn, case_id, owner, "telegram persona")
    asn = _node(conn, case_id, owner, "hosting provider")
    channel = _node(conn, case_id, owner, "channel persona")
    _selector(conn, case_id, discord, "DISCORD_ID", "139292958")
    _selector(conn, case_id, telegram, "TELEGRAM_ID", "u:139292958")
    _selector(conn, case_id, asn, "ASN", "13335")
    _selector(conn, case_id, channel, "TELEGRAM_ID", "c:1234567890")

    tg = _nodes(conn, case_id, "u:139292958")
    assert [h.id for h in tg.hits] == [telegram] and tg.hits[0].via.exact
    for query, holder, stored in (("AS13335", asn, "13335"),
                                  ("-1001234567890", channel, "c:1234567890")):
        page = _nodes(conn, case_id, query)
        assert [h.id for h in page.hits] == [holder], query
        assert page.hits[0].via.exact and page.hits[0].via.value == stored


def test_punctuation_that_names_another_identifier_is_never_an_exact_match(conn, world):
    """The digits-only normalisers keep the digits of anything. Before the
    printed-form rule, "-123456789" (a Telegram basic group in Bot-API
    form) came back as the ICQ number 123456789 marked exact at rank 1.0
    beside the real group, and "10.0.0.1" as the ASN 10001 (verifier of
    the second 2026-09-22 fix round). The punctuation that is only
    formatting for the type still is: an ICQ number in its hyphenated
    groups and a phone number in any of its usual shapes stay exact."""
    owner, _, case_id = world
    icq = _node(conn, case_id, owner, "icq persona")
    group = _node(conn, case_id, owner, "telegram group")
    asn = _node(conn, case_id, owner, "asn holder")
    phone = _node(conn, case_id, owner, "short phone")
    imei = _node(conn, case_id, owner, "short imei")
    host = _node(conn, case_id, owner, "ipv4 host")
    dated = _node(conn, case_id, owner, "dated phone")
    caller = _node(conn, case_id, owner, "phone persona")
    national = _node(conn, case_id, owner, "national phone")
    nine = _node(conn, case_id, owner, "nine digit phone")
    _selector(conn, case_id, icq, "ICQ", "123456789")
    _selector(conn, case_id, group, "TELEGRAM_ID", "-123456789")
    _selector(conn, case_id, asn, "ASN", "10001")
    _selector(conn, case_id, phone, "PHONE", "10001")
    _selector(conn, case_id, imei, "IMEI", "10001")
    _selector(conn, case_id, host, "IPV4", "10.0.0.1")
    _selector(conn, case_id, dated, "PHONE", "20260923")
    _selector(conn, case_id, caller, "PHONE", "+1 555 123 4567")
    _selector(conn, case_id, national, "PHONE", "555-123-4567")
    _selector(conn, case_id, nine, "PHONE", "123456789")

    for query, holders in (
        ("-123456789", {group}),       # not the ICQ or phone number 123456789
        ("10.0.0.1", {host}),          # not the ASN, phone or IMEI 10001
        ("12.345.67.89", set()),       # an IPv4 shape: no ICQ, no phone
        ("12/34/56789", set()),        # slashes are nobody's formatting here
        ("2026-09-23", set()),         # a date, not the phone number 20260923
        ("123-456-789", {icq, nine}),  # ICQ's grouping, a phone's hyphens
        ("+1 (555) 123-4567", {caller}),
        ("555.123.4567", {national}),  # a phone number's dots: formatting
    ):
        page = _nodes(conn, case_id, query)
        exact = {h.id for h in page.hits if h.via is not None and h.via.exact}
        assert exact == holders, (query, page.hits)
        for hit in page.hits:
            if hit.id not in holders:
                assert hit.rank < 1.0, (query, hit)


def test_a_number_pasted_with_its_type_label_finds_its_holder(conn, client, world):
    """"ICQ: 123456789", "ICQ 123456789" and "IMEI 490154203237518" found
    nothing at all after the letters rule (verifier of the second
    2026-09-22 fix round): the label made the whole string no ICQ number,
    and no stored value contains the label for a fragment to match. The
    label names the type, so the value is searched as that type, exactly
    and as a fragment, and never as another type that holds the same
    digits."""
    from noctornal_api.cases import CaseService
    owner, email, case_id = world
    tok = _tok()
    icq = _node(conn, case_id, owner, "icq persona")
    discord = _node(conn, case_id, owner, "discord persona")
    handset = _node(conn, case_id, owner, "handset")
    jabber = _node(conn, case_id, owner, "jabber persona")
    red_icq = _node(conn, case_id, owner, f"red icq {tok}", classification="RED")
    _selector(conn, case_id, icq, "ICQ", "123456789")
    _selector(conn, case_id, discord, "DISCORD_ID", "123456789")
    _selector(conn, case_id, handset, "IMEI", "490154203237518")
    _selector(conn, case_id, jabber, "JABBER", f"ember_{tok}@nightmarket.im")
    _selector(conn, case_id, red_icq, "ICQ", "987654321")

    for query, holder in (("ICQ: 123456789", icq), ("ICQ 123456789", icq),
                          ("icq:123456789", icq), ("ICQ number: 123-456-789", icq),
                          ("IMEI 490154203237518", handset),
                          ("imei: 49-015420-323751-8", handset)):
        page = _nodes(conn, case_id, query)
        assert [h.id for h in page.hits] == [holder], (query, page.hits)
        assert page.hits[0].via.exact and page.hits[0].rank == 1.0, query

    # The value is a fragment of the labelled type too, and only of it:
    # the Discord id holds the same digits and is not listed.
    part = _nodes(conn, case_id, "ICQ: 1234567")
    assert [h.id for h in part.hits] == [icq]
    assert part.hits[0].via.exact is False and part.hits[0].rank < 1.0
    jab = _nodes(conn, case_id, f"Jabber: ember_{tok}")
    assert [h.id for h in jab.hits] == [jabber] and jab.hits[0].via.exact is False
    # A label does not relax the value's own printed form.
    assert _nodes(conn, case_id, "ICQ: -123456789").total == 0

    # Through the same gate: the RED holder is not found by an AMBER caller,
    # by the labelled number or by a labelled fragment of it.
    svc = _svc(conn)
    for query in ("ICQ: 987654321", "ICQ 9876543"):
        assert _nodes(conn, case_id, query, clearance="AMBER").total == 0
        assert svc.selector_page(case_id=case_id, query=query, clearance="AMBER",
                                 compartments=frozenset()).total == 0
    assert [h.id for h in _nodes(conn, case_id, "ICQ: 987654321").hits] == [red_icq]
    amber_user, amber_email = _user(conn, clearance="AMBER")
    CaseService(conn).assign_user(case_id, amber_user, "ANALYST", granted_by=owner)
    ah = _auth(_session(conn, amber_email))
    base = f"/api/v1/cases/{case_id}"
    r = client.get(base + "/search/selectors", headers=ah,
                   params={"q": "ICQ 987654321", "with_total": "true"})
    assert r.json() == {"hits": [], "total": 0, "limit": 50} and tok not in r.text

    # The palette's route, as the owner.
    oh = _auth(_session(conn, email))
    r = client.get(base + "/search/selectors", headers=oh,
                   params={"q": "ICQ 123456789", "with_total": "true"})
    assert r.status_code == 200, r.text
    assert [row["id"] for row in r.json()["hits"]] == [str(icq)]
    assert r.json()["hits"][0]["via"]["exact"] is True


# --- whole-token-false-negatives ----------------------------------------

def test_fragments_word_starts_and_near_duplicates_match(conn, world):
    """The review's own queries, with a unique token standing in for
    "skua", "hostmarket" and "halcyon_owl"."""
    owner, _, case_id = world
    tok = _tok()
    tandem = _node(conn, case_id, owner, f"tandem_{tok}")
    harrow = _node(conn, case_id, owner, f"harrow_{tok}2")
    host = _node(conn, case_id, owner, f"vps-3930.{tok}market.example")
    owl = _node(conn, case_id, owner, f"halcyon_{tok}")
    owl8 = _node(conn, case_id, owner, f"halcyon_{tok}8")

    assert {h.id for h in _nodes(conn, case_id, tok).hits} == {
        tandem, harrow, host, owl, owl8}
    assert [h.id for h in _nodes(conn, case_id, f"{tok}market").hits] == [host]
    assert [h.id for h in _nodes(conn, case_id, f"vps-3930.{tok}").hits] == [host]
    near = _nodes(conn, case_id, f"halcyon_{tok}")
    assert [h.id for h in near.hits] == [owl, owl8], (
        "the exact handle first, then the near-duplicate sock puppet")
    assert near.hits[0].rank == 1.0 and near.hits[1].rank < 1.0
    assert {h.id for h in _nodes(conn, case_id, f"halcyon {tok}").hits} == {owl, owl8}


def test_like_wildcards_in_a_query_are_literal(conn, world):
    """An underscore or a percent sign in a handle is a character, not a
    LIKE wildcard: "a_b" must not match "aXb", and "%%%" must not match
    every row."""
    owner, _, case_id = world
    tok = _tok()
    _node(conn, case_id, owner, f"a{tok}Xb")
    assert _nodes(conn, case_id, f"a{tok}_b").total == 0
    assert _nodes(conn, case_id, "%%%").total == 0
    assert _nodes(conn, case_id, "':*|&!()").total == 0, (
        "tsquery syntax in the query must be a separator, never an operator")


def test_attributes_match_on_word_starts(conn, world):
    owner, _, case_id = world
    tok = _tok()
    n = _node(conn, case_id, owner, "attr persona",
              attrs={"first_seen_on": f"{tok}exchange forum"})
    assert [h.id for h in _nodes(conn, case_id, tok).hits] == [n]


# --- silent-truncation-50 -----------------------------------------------

def test_total_counts_past_the_cap_and_ties_break_on_the_label(conn, world):
    """Seven equal matches, a cap of five: the page says seven, and the
    five it shows are the first five by name, every time."""
    owner, _, case_id = world
    tok = _tok()
    for letter in "gfedcba":
        _node(conn, case_id, owner, f"{letter}_{tok}")
    first = _nodes(conn, case_id, tok, limit=5)
    assert first.total == 7 and len(first.hits) == 5
    assert [h.label for h in first.hits] == [f"{c}_{tok}" for c in "abcde"]
    assert len({h.rank for h in first.hits}) == 1, "the fixture meant a tie"
    again = _nodes(conn, case_id, tok, limit=5)
    assert [h.id for h in again.hits] == [h.id for h in first.hits]


def test_the_search_routes_say_how_many_matched(conn, client, world):
    """`with_total=true` wraps the capped list with its total; the default
    stays the bare list every existing client reads, now with `via`; the
    combined `/search` reports `total` and per-kind `totals`."""
    owner, email, case_id = world
    tok = _tok()
    for letter in "gfedcba":
        _node(conn, case_id, owner, f"{letter}_{tok}")
    holder = _node(conn, case_id, owner, "wallet holder")
    wallet = _wallet()
    _selector(conn, case_id, holder, "BTC_ADDR", wallet)
    h = _auth(_session(conn, email))
    base = f"/api/v1/cases/{case_id}"

    bare = client.get(f"{base}/search/nodes", headers=h, params={"q": tok, "limit": 5})
    assert bare.status_code == 200, bare.text
    assert isinstance(bare.json(), list) and len(bare.json()) == 5
    assert all("via" in row for row in bare.json())

    paged = client.get(f"{base}/search/nodes", headers=h,
                       params={"q": tok, "limit": 5, "with_total": "true"})
    assert paged.status_code == 200, paged.text
    body = paged.json()
    assert body["total"] == 7 and body["limit"] == 5 and len(body["hits"]) == 5
    assert [row["label"] for row in body["hits"]] == [f"{c}_{tok}" for c in "abcde"]

    via = client.get(f"{base}/search/nodes", headers=h, params={"q": wallet}).json()
    assert [row["id"] for row in via] == [str(holder)]
    assert via[0]["via"]["selector_type"] == "BTC_ADDR"
    assert via[0]["via"]["exact"] is True

    sel = client.get(f"{base}/search/selectors", headers=h,
                     params={"q": wallet[:12], "with_total": "true"})
    assert sel.status_code == 200, sel.text
    assert sel.json()["total"] == 1
    assert sel.json()["hits"][0]["via"]["value"] == wallet

    combined = client.get(f"{base}/search", headers=h, params={"q": tok, "limit": 5})
    assert combined.status_code == 200, combined.text
    body = combined.json()
    assert body["count"] == 5 and body["totals"]["node"] == 7
    assert body["total"] >= 7

    # Fragment matching costs an index lookup per character, so the query
    # is bounded: longer than any pasted selector is refused, not scanned.
    for route in ("/search", "/search/nodes", "/search/selectors", "/search/evidence"):
        r = client.get(base + route, headers=h, params={"q": "x" * 1025})
        assert r.status_code == 422, (route, r.status_code)


def test_the_selector_routes_apply_the_callers_ceiling(conn, client, world):
    """Through HTTP, as an AMBER analyst on the case: the router has to
    pass the caller's own ceiling, not the case's, or the RED persona's
    wallet finds it."""
    from noctornal_api.cases import CaseService
    owner, owner_email, case_id = world
    red = _node(conn, case_id, owner, "red truename", classification="RED")
    wallet = _wallet()
    _selector(conn, case_id, red, "BTC_ADDR", wallet)
    amber, amber_email = _user(conn, clearance="AMBER")
    CaseService(conn).assign_user(case_id, amber, "ANALYST", granted_by=owner)
    base = f"/api/v1/cases/{case_id}"

    ah = _auth(_session(conn, amber_email))
    for route in ("/search/nodes", "/search/selectors"):
        r = client.get(base + route, headers=ah,
                       params={"q": wallet, "with_total": "true"})
        assert r.status_code == 200, r.text
        assert r.json() == {"hits": [], "total": 0, "limit": 50}
    combined = client.get(base + "/search", headers=ah, params={"q": wallet}).json()
    assert combined["hits"] == [] and combined["totals"]["node"] == 0

    oh = _auth(_session(conn, owner_email))
    r = client.get(base + "/search/selectors", headers=oh, params={"q": wallet})
    assert [row["id"] for row in r.json()] == [str(red)]


# --- exhibits -----------------------------------------------------------

@pytest.mark.skipif(not MINIO, reason="MINIO_ENDPOINT required for evidence search")
def test_an_exhibit_is_found_by_a_fragment_of_its_file_name(conn, world):
    """"remittance" and "eml" both missed remittance-change.eml: the parser
    keeps a file name as one lexeme."""
    from noctornal_api.evidence import EvidenceService, EvidenceStorage
    owner, _, case_id = world
    tok = _tok()
    EvidenceService(conn, EvidenceStorage()).ingest(
        case_id=case_id, title=f"remit{tok}-change.eml", media_type="message/rfc822",
        data=b"exhibit-" + uuid4().hex.encode(), acquired_by=owner,
        acquisition_method="MANUAL_UPLOAD")
    svc = _svc(conn)
    for query in (f"remit{tok}", f"{tok}-change", ".eml", f"remit{tok}-change.eml"):
        page = svc.evidence_page(case_id=case_id, query=query, clearance="RED",
                                 compartments=frozenset())
        assert [h.label for h in page.hits] == [f"remit{tok}-change.eml"], query
        assert page.total == 1


# --- final review, 2026-09-23 -------------------------------------------

def test_an_identity_preserving_rewrite_finds_its_selector_exactly(conn, world):
    """final review U8: a Gmail "+tag", googlemail.com, a Unicode domain
    and a URL's default port normalise to the stored selector's own
    norm_value, and found nothing. The canonical form was dropped as "not
    one contiguous run of the query", and the fragment pattern is the
    query as typed, which the stored value does not contain. The pasted
    chat-log address is the same mailbox, so it is an exact match."""
    from noctornal_ontology import normalise
    owner, _, case_id = world
    tok = _tok()
    mailbox = _node(conn, case_id, owner, "gmail persona")
    site = _node(conn, case_id, owner, "idn site")
    shop = _node(conn, case_id, owner, "url persona")
    _selector(conn, case_id, mailbox, "EMAIL", f"ember{tok}@gmail.com")
    unicode_domain = f"bücher{tok}.example"
    punycode = normalise("DOMAIN", unicode_domain)
    assert punycode.startswith("xn--"), punycode
    _selector(conn, case_id, site, "DOMAIN", punycode)
    _selector(conn, case_id, shop, "URL", f"https://{tok}.example/Shop")

    svc = _svc(conn)
    for query, holder in ((f"ember.{tok}+shop@gmail.com", mailbox),
                          (f"Ember{tok}@GoogleMail.com", mailbox),
                          (unicode_domain, site),
                          (f"HTTPS://{tok}.example:443/Shop", shop)):
        for page in (_nodes(conn, case_id, query),
                     svc.selector_page(case_id=case_id, query=query, clearance="RED",
                                       compartments=frozenset())):
            assert [h.id for h in page.hits] == [holder], (query, page.hits)
            assert page.hits[0].via.exact and page.hits[0].rank == 1.0, query


def test_every_way_to_match_a_selector_has_an_index(conn, world):
    """final review U9: the selector match was ONE WHERE joining an
    IN-subquery and the fragment ILIKEs by OR. A sublink under an OR is a
    hashed SubPlan no index serves, so Postgres could not build a BitmapOr
    and scanned every selector in the case, and the raw_value trigram
    index 0065 built for this query was never used.

    Planner costs mean nothing on a few dozen rows, so the case is given
    ten thousand selectors inside a transaction that is rolled back. Each
    way to match must then reach its own index: both trigram indexes for
    the fragment arms, labelled or not, and no sequential scan of
    core.selector in the node search or the palette's lookup. The old
    shape cannot pass this at any size or setting: no plan for it uses a
    trigram index."""
    import psycopg

    from noctornal_api.curation import SearchService
    owner, _, case_id = world
    holder = _node(conn, case_id, owner, "bulk holder")
    tok = _tok()

    class Spy:
        """Keeps the SQL and parameters a search would run."""
        sql = params = None

        def execute(self, sql, params=None):
            Spy.sql, Spy.params = sql, params
            return conn.execute("SELECT 1 WHERE false")

    def plan(method: str, query: str) -> str:
        getattr(SearchService(Spy()), method)(
            case_id=case_id, query=query, limit=50, clearance="RED",
            compartments=frozenset())
        return "\n".join(r[0] for r in conn.execute("EXPLAIN " + Spy.sql,
                                                    Spy.params).fetchall())

    try:
        with conn.transaction():
            # md5 is hex, so no generated value contains the "zq" of a token.
            conn.execute(
                """INSERT INTO core.selector
                          (case_id, selector_type, raw_value, norm_value, node_id)
                   SELECT %s, 'HANDLE', 'h' || md5(i::text), 'h' || md5(i::text), %s
                     FROM generate_series(1, 10000) AS i""", (case_id, holder))
            # Fresh rows sit in each GIN index's pending list, which the
            # planner prices as a scan of the list; a live table's has been
            # merged by autovacuum. Merge it here, or the costs are a bulk
            # load's and not a case's.
            for index in ("selector_norm_value_idx", "selector_raw_value_trgm_idx"):
                conn.execute("SELECT gin_clean_pending_list(%s::regclass)",
                             ("core." + index,))
            conn.execute("ANALYZE core.selector")
            for method in ("node_page", "selector_page"):
                for query in (tok, f"Handle: {tok}"):
                    shown = plan(method, query)
                    assert "Seq Scan on selector" not in shown, (method, query, shown)
                    for index in ("selector_norm_value_idx", "selector_raw_value_trgm_idx"):
                        assert f"Bitmap Index Scan on {index}" in shown, (
                            method, query, index, shown)
            raise psycopg.Rollback()
    finally:
        # ANALYZE records the row count outside the transaction; put the
        # statistics back to what the table holds.
        conn.execute("ANALYZE core.selector")


def test_a_merged_records_own_name_finds_its_survivor(conn, client, world):
    """final review U10: the pane printed a merged record's name ("held by
    merged record old_alias") and searching that name answered "No
    entities match", which reads as "not in this case". The name arms were
    dropped as merged and nothing put the survivor in their place. Now the
    name resolves to the live survivor through the same gated chain as a
    selector, and the hit says which merged record's name matched, only
    when the survivor's own name did not."""
    from noctornal_api.merges import MergeService
    owner, email, case_id = world
    tok = _tok()
    merges = MergeService(conn)
    alias = f"oldalias_{tok}"
    loser = _node(conn, case_id, owner, alias)
    survivor = _node(conn, case_id, owner, "main persona")
    wallet = _wallet()
    _selector(conn, case_id, loser, "BTC_ADDR", wallet)
    merges.merge(case_id=case_id, source_node_id=loser, target_node_id=survivor,
                 merged_by=owner, reason="same wallet, same writing style")

    assert _nodes(conn, case_id, wallet).hits[0].via.merged_from == alias, (
        "the fixture meant the name the finding saw on screen")
    for query, exact in ((alias, True), (alias.upper(), True),
                         (f"alias_{tok[:6]}", False), (tok, False)):
        page = _nodes(conn, case_id, query)
        assert [h.id for h in page.hits] == [survivor], (query, page.hits)
        assert page.total == 1, query
        hit = page.hits[0]
        assert hit.merged_name == alias, (query, hit)
        assert (hit.rank == 1.0) is exact, (query, hit.rank)

    own = _nodes(conn, case_id, "main persona")
    assert [h.id for h in own.hits] == [survivor]
    assert own.hits[0].merged_name is None, "its own name needs no explaining"
    # The palette's lookup is selectors only, and stays so.
    assert _svc(conn).selector_page(case_id=case_id, query=alias, clearance="RED",
                                    compartments=frozenset()).total == 0

    # Over HTTP: the kind route and the combined search both carry it.
    oh = _auth(_session(conn, email))
    base = f"/api/v1/cases/{case_id}"
    r = client.get(base + "/search/nodes", headers=oh,
                   params={"q": alias, "with_total": "true"})
    assert r.status_code == 200, r.text
    row = r.json()["hits"][0]
    assert row["id"] == str(survivor) and row["merged_name"] == alias, row
    combined = client.get(base + "/search", headers=oh, params={"q": alias})
    assert combined.status_code == 200, combined.text
    nodes = [h for h in combined.json()["hits"] if h["kind"] == "node"]
    assert [(h["id"], h["merged_name"]) for h in nodes] == [(str(survivor), alias)]

    # A longer chain ends at the live record.
    final = _node(conn, case_id, owner, "final persona")
    merges.merge(case_id=case_id, source_node_id=survivor, target_node_id=final,
                 merged_by=owner, reason="one operator behind both")
    page = _nodes(conn, case_id, alias)
    assert [h.id for h in page.hits] == [final] and page.hits[0].merged_name == alias


def test_a_merged_name_never_reaches_past_the_callers_ceiling(conn, client, world):
    """The name chain is the selector chain's, gated at its anchor and at
    every hop, so an AMBER caller searching a name finds nothing through:

    - a RED record merged into an AMBER survivor (the anchor: the hidden
      record's name must neither find the survivor nor be sent back);
    - an AMBER record merged into a RED survivor;
    - an AMBER record merged through a RED record into an AMBER survivor
      (the hop);
    - a compartmented record merged into an open survivor, for a RED
      caller outside the compartment.
    """
    from noctornal_api.cases import CaseService
    from noctornal_api.merges import MergeService
    owner, _, case_id = world
    conn.execute(
        "INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
        "ON CONFLICT (key) DO NOTHING", (TEST_COMPARTMENT, "Selector search test"))
    merges = MergeService(conn)
    tok = _tok()

    def merge(src, dst):
        merges.merge(case_id=case_id, source_node_id=src, target_node_id=dst,
                     merged_by=owner, reason="same operator")

    red_alias = _node(conn, case_id, owner, f"redalias_{tok}", classification="RED")
    merge(red_alias, _node(conn, case_id, owner, "amber survivor one"))
    merge(_node(conn, case_id, owner, f"upalias_{tok}"),
          _node(conn, case_id, owner, "red survivor", classification="RED"))
    red_middle = _node(conn, case_id, owner, "red middle", classification="RED")
    merge(_node(conn, case_id, owner, f"thrualias_{tok}"), red_middle)
    merge(red_middle, _node(conn, case_id, owner, "amber survivor two"))
    walled = _node(conn, case_id, owner, f"walledalias_{tok}",
                   compartments=[TEST_COMPARTMENT])
    merge(walled, _node(conn, case_id, owner, "open survivor"))

    for name in ("redalias", "upalias", "thrualias"):
        page = _nodes(conn, case_id, f"{name}_{tok}", clearance="AMBER")
        assert page.hits == [] and page.total == 0, (name, page)
    page = _nodes(conn, case_id, f"walledalias_{tok}", clearance="RED")
    assert page.hits == [] and page.total == 0, page
    # The token is in every alias: none of them reaches through for AMBER.
    assert _nodes(conn, case_id, tok, clearance="AMBER").total == 0

    amber_user, amber_email = _user(conn, clearance="AMBER")
    CaseService(conn).assign_user(case_id, amber_user, "ANALYST", granted_by=owner)
    ah = _auth(_session(conn, amber_email))
    base = f"/api/v1/cases/{case_id}"
    for query in (tok, f"redalias_{tok}", f"upalias_{tok}", f"thrualias_{tok}"):
        r = client.get(base + "/search/nodes", headers=ah,
                       params={"q": query, "with_total": "true"})
        assert r.status_code == 200, r.text
        assert r.json() == {"hits": [], "total": 0, "limit": 50}, (query, r.text)
        combined = client.get(base + "/search", headers=ah, params={"q": query})
        assert combined.status_code == 200, combined.text
        assert combined.json()["totals"]["node"] == 0 and tok not in combined.text

    # The control: cleared for all of it, and inside the compartment, each
    # name reaches its live survivor.
    cleared = frozenset({TEST_COMPARTMENT})
    for name, survivor_label in (("redalias", "amber survivor one"),
                                 ("upalias", "red survivor"),
                                 ("thrualias", "amber survivor two"),
                                 ("walledalias", "open survivor")):
        page = _nodes(conn, case_id, f"{name}_{tok}", compartments=cleared)
        assert [h.label for h in page.hits] == [survivor_label], (name, page.hits)
        assert page.hits[0].merged_name == f"{name}_{tok}"


def test_a_merged_name_ranks_and_is_named_only_when_it_says_more(conn, world):
    """The rank on screen is the reason on screen (verifier of the U10
    fix, 2026-09-23: nothing held this rule, and a mutant that always
    named the merged record passed). The first rule was "only when the
    survivor's own name did not match", which demoted an EXACT merged name
    below any weak match of the survivor's own: "ember" merged into
    "ember_hobby" ranked 0.5 under unrelated near misses, and a survivor
    whose attributes merely mentioned the word ranked 0.06 with no reason
    shown at all. So a merged name ranks its survivor whenever it matches
    better, and is named whenever it is the better reason, or the only
    one."""
    from noctornal_api.merges import MergeService
    owner, _, case_id = world
    merges = MergeService(conn)

    def merged(alias_label, survivor_label, *, attrs=None):
        loser = _node(conn, case_id, owner, alias_label)
        survivor = _node(conn, case_id, owner, survivor_label, attrs=attrs)
        return loser, survivor

    def merge(loser, survivor):
        merges.merge(case_id=case_id, source_node_id=loser, target_node_id=survivor,
                     merged_by=owner, reason="same operator")

    def only(query):
        page = _nodes(conn, case_id, query)
        assert len(page.hits) == 1 and page.total == 1, (query, page.hits)
        return page.hits[0]

    # An exact merged name outranks a partial own name, and says so.
    t1 = _tok()
    loser, survivor = merged(t1, f"{t1} harbour ops")
    merge(loser, survivor)
    hit = only(t1)
    assert (hit.id, hit.rank, hit.merged_name) == (survivor, 1.0, t1), hit
    # The same where only the survivor's attributes matched: its name on
    # screen says nothing, so the merged record's name must.
    t2 = _tok()
    loser, survivor = merged(t2, "quiet persona",
                             attrs={"first_seen_on": f"{t2} forum"})
    merge(loser, survivor)
    hit = only(t2)
    assert (hit.id, hit.rank, hit.merged_name) == (survivor, 1.0, t2), hit

    # The survivor's own name says as much or more: its rank is its own,
    # to the digit, and no merged record is named.
    for own_label, alias_label in (
            ("{t}", "{t} old handle"),                                  # exact own
            ("{t}", "{T}"),                                             # a tie
            ("{t} ops", "archived notes mentioning {t} among others")):  # better own
        t = _tok()
        loser, survivor = merged(alias_label.format(t=t, T=t.upper()),
                                 own_label.format(t=t))
        before = {h.id: h.rank for h in _nodes(conn, case_id, t).hits}
        merge(loser, survivor)
        hit = only(t)
        assert hit.id == survivor and hit.merged_name is None, (own_label, hit)
        assert hit.rank == pytest.approx(before[survivor]), (own_label, hit, before)

    # Found only through the merged name, though the survivor's own label
    # is the closer trigram match: the merged record is still the reason it
    # is a result at all, so it is named.
    t3 = _tok()
    alias_label = f"old handle {t3}q from the forum archive"
    loser, survivor = merged(alias_label, t3)
    merge(loser, survivor)
    hit = only(f"{t3}q")
    assert hit.id == survivor and hit.merged_name == alias_label, hit
