"""The Search pane's four columns and what each row says (ux09-search,
2026-09-23), against a real database.

- hit-rows-unexplained: a row was a label and a bare rank. Hits now carry
  the entity's type and TLP and whether their own name matched, and an
  attribute KEY is never the reason an entity is found ("role" returned
  seven broker personas, "seen" every crew member through first_seen_forum).
- documents-unsearchable: the console never searched collected documents.
  `/search/documents` is the pane's third column, and says `not_searched`
  (naming the roles that read documents) rather than an empty list to a
  caller without the global collection.read.
- assertions-unsearchable: nothing searched a claim. `/search/assertions`
  finds live claims by rationale, reference, cited exhibit title or exact
  grading, gated as the inspector's assertion list is.
- ux19-copy developer-speak-in-copy: `/roles/holders` is the grant table a
  refusal is explained by, and the comms notice names no design document.

The pure half is test_search_ui_invariants.py. Env-gated on DATABASE_URL.
Users are `scol-`, sources `test-scol-`; no other suite's teardown pattern
matches either.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timezone
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; search tests are gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PASSWORD = "correct-horse-battery-staple"
EMAIL_LIKE = "scol-%@noctornal.test"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    ssub = "(SELECT id FROM collect.source WHERE name LIKE 'test-scol-%')"
    # ONE transaction: `assertion_protects_element` (0022) is a deferred
    # constraint trigger, so assertions and elements vanish together.
    convs = f"(SELECT id FROM comms.conversation WHERE case_id IN {csub})"
    with c.transaction():
        c.execute(f"DELETE FROM comms.message WHERE conversation_id IN {convs}")
        c.execute(f"DELETE FROM comms.participant WHERE conversation_id IN {convs}")
        c.execute(f"DELETE FROM comms.conversation WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM collect.document WHERE source_id IN {ssub}")
        c.execute(f"DELETE FROM collect.source WHERE id IN {ssub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.evidence WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute(f"DELETE FROM iam.app_user WHERE email LIKE '{EMAIL_LIKE}'")
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
    email = f"scol-{uuid4().hex[:8]}@noctornal.test"
    store = PgUserStore(conn)
    uid = store.create_user(email, "Column searcher", PASSWORD)
    store.enroll_totp(uid, totp.generate_secret())
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s)",
                     (uid, role))
    return uid, email


def _session(conn, email) -> str:
    """Minted as test_search_documents_pg mints one, for its reasons."""
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
        code=f"OP-SCOL-{uuid4().hex[:6]}", title="Search columns",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _assign(conn, case_id, user, role, owner):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""", (case_id, user, role, owner))


def _claim(uid, **kw):
    from noctornal_api.graph import AssertionInput
    return AssertionInput(basis="DIRECT_OBSERVATION", created_by=uid, **kw)


def _node(conn, case_id, uid, label, *, node_type="IDENTITY",
          classification="AMBER", attrs=None, **claim):
    from noctornal_api.graph import GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type=node_type, label=label, created_by=uid,
        assertion=_claim(uid, **claim), classification=classification,
        attrs=attrs)


def _edge(conn, case_id, uid, src, dst, **claim):
    from noctornal_api.graph import GraphWriteService
    return GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="COMMUNICATES_WITH", src_node_id=src,
        dst_node_id=dst, created_by=uid, assertion=_claim(uid, **claim))


def _exhibit(conn, case_id, owner, title, level="AMBER"):
    """Inserted directly with no custody rows, so the fixture may delete
    it; only its title and labels matter here."""
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, classification,
                acquisition_method, acquired_at, acquired_by)
           VALUES (%s, %s, 'message/rfc822', 64, %s, %s, %s, 'test-bucket',
                   %s, 'MANUAL_UPLOAD', now(), %s)
           RETURNING id""",
        (case_id, title, os.urandom(32), os.urandom(32), f"k/{uuid4().hex}",
         level, owner)).fetchone()[0]


def _source(conn, level="AMBER"):
    return conn.execute(
        """INSERT INTO collect.source
               (kind, name, base_url, default_reliability, parser_key,
                classification)
           VALUES ('RSS', %s, 'https://forum.test/feed', 'C', 'rss', %s::core.tlp)
           RETURNING id""",
        (f"test-scol-{uuid4().hex[:6]}", level)).fetchone()[0]


def _doc(conn, source_id, *, body, title="A thread", classification="AMBER",
         author="vendor01"):
    return conn.execute(
        """INSERT INTO collect.document
               (source_id, external_id, external_url, title, body_text,
                author_handle, posted_at, content_sha256, classification)
           VALUES (%s, %s, 'https://forum.test/t/9', %s, %s, %s, %s,
                   decode(md5(%s), 'hex'), %s::core.tlp)
           RETURNING id""",
        (source_id, uuid4().hex, title, body, author,
         datetime.now(timezone.utc), body, classification)).fetchone()[0]


def _tok() -> str:
    """Letters only, so the 'simple' parser keeps it one lexeme and no
    other row can contain it."""
    return "zq" + "".join(chr(ord("a") + int(c, 16) % 26) for c in uuid4().hex[:10])


def _nodes(conn, case_id, q, *, clearance="RED"):
    from noctornal_api.curation import SearchService
    return SearchService(conn).node_page(
        case_id=case_id, query=q, limit=50, clearance=clearance,
        compartments=frozenset())


def _claims(conn, case_id, q, *, clearance="RED", exhibits=True):
    from noctornal_api.curation import SearchService
    return SearchService(conn).assertion_page(
        case_id=case_id, query=q, limit=50, clearance=clearance,
        compartments=frozenset(), may_see_exhibits=exhibits)


@pytest.fixture
def world(conn):
    owner, email = _user(conn, roles=("CASE_OWNER",))
    return owner, email, _case(conn, owner)


# --- hit-rows-unexplained ------------------------------------------------

def test_an_attribute_key_is_never_why_an_entity_is_found(conn, world):
    """The finding's repro: a key name ("role", "first_seen_forum") found
    every entity carrying the key. A VALUE still finds it, and names the
    attribute."""
    owner, _, case_id = world
    tok = _tok()
    key = f"{tok}role"
    n = _node(conn, case_id, owner, "quiet broker",
              attrs={key: "broker", "first_seen_forum": f"{tok}forum"})
    assert _nodes(conn, case_id, key).total == 0, (
        "an attribute key found the entity")
    page = _nodes(conn, case_id, f"{tok}forum")
    assert [h.id for h in page.hits] == [n]
    assert page.hits[0].attribute == "first_seen_forum"
    assert page.hits[0].in_label is False


def test_a_nested_or_numeric_value_still_matches_and_its_key_does_not(conn, world):
    owner, _, case_id = world
    tok = _tok()
    n = _node(conn, case_id, owner, "nested persona",
              attrs={"profile": {"alias": f"{tok}alias", "posts": 4711},
                     f"{tok}outer": {"inner": "x"}})
    assert [h.id for h in _nodes(conn, case_id, f"{tok}alias").hits] == [n]
    assert _nodes(conn, case_id, f"{tok}outer").total == 0


def test_a_hit_says_what_it_is_and_whether_its_name_matched(conn, client, world):
    """Type and TLP chips in place of the bare rank: the GROUP and the
    personas it found must not look identical."""
    owner, email, case_id = world
    tok = _tok()
    group = _node(conn, case_id, owner, f"{tok} crew", node_type="GROUP",
                  classification="RED")
    member = _node(conn, case_id, owner, "null_adder",
                   attrs={"crew": f"{tok} crew"})
    got = {h.id: h for h in _nodes(conn, case_id, tok).hits}
    assert got[group].node_type == "GROUP" and got[group].classification == "RED"
    assert got[group].in_label is True
    assert got[member].node_type == "IDENTITY"
    assert got[member].classification == "AMBER"
    assert got[member].in_label is False and got[member].attribute == "crew"

    r = client.get(f"/api/v1/cases/{case_id}/search/nodes",
                   headers=_auth(_session(conn, email)),
                   params={"q": tok, "with_total": "true"})
    assert r.status_code == 200, r.text
    rows = {row["id"]: row for row in r.json()["hits"]}
    assert rows[str(group)]["node_type"] == "GROUP"
    assert rows[str(group)]["classification"] == "RED"
    assert rows[str(group)]["in_label"] is True
    assert rows[str(member)]["in_label"] is False


def test_a_query_split_across_parts_names_every_part_and_claims_no_name(
        conn, client, world):
    """"meridian exchange" found 18 personas through crew plus
    first_seen_forum, none carried an attribute reason, and the pane said
    "via the name and attributes together" for names holding neither word
    (verifier of hit-rows-unexplained, 2026-09-23)."""
    owner, email, case_id = world
    crew, forum, name = _tok(), _tok(), _tok()
    two_attrs = _node(conn, case_id, owner, "quiet persona",
                      attrs={"crew": f"{crew} crew", "first_seen_forum": forum,
                             "role": "broker"})
    name_and_attr = _node(conn, case_id, owner, f"{name} persona",
                          attrs={"crew": f"{crew} crew"})

    got = {h.id: h for h in _nodes(conn, case_id, f"{crew} {forum}").hits}
    assert set(got) == {two_attrs}
    hit = got[two_attrs]
    assert hit.in_label is False and hit.attribute is None
    assert hit.attributes == ("crew", "first_seen_forum")
    assert hit.label_part is False, "the name was claimed and holds no word"

    got = {h.id: h for h in _nodes(conn, case_id, f"{name} {crew}").hits}
    assert set(got) == {name_and_attr}
    hit = got[name_and_attr]
    assert hit.in_label is False and hit.attribute is None
    assert hit.attributes == ("crew",) and hit.label_part is True

    # One attribute holding the whole query is still named alone.
    one = _nodes(conn, case_id, f"{crew} crew").hits
    assert {h.attribute for h in one} == {"crew"}
    assert all(h.attributes == () for h in one)

    r = client.get(f"/api/v1/cases/{case_id}/search/nodes",
                   headers=_auth(_session(conn, email)),
                   params={"q": f"{crew} {forum}", "with_total": "true"})
    assert r.status_code == 200, r.text
    row = r.json()["hits"][0]
    assert row["attributes"] == ["crew", "first_seen_forum"]
    assert row["label_part"] is False and row["in_label"] is False


def test_an_exhibit_hit_carries_its_tlp_and_whether_its_title_matched(conn, world):
    from noctornal_api.curation import SearchService
    owner, _, case_id = world
    tok = _tok()
    by_title = _exhibit(conn, case_id, owner, f"{tok}-change.eml", "RED")
    page = SearchService(conn).evidence_page(
        case_id=case_id, query=tok, limit=50, clearance="RED",
        compartments=frozenset())
    hit = next(h for h in page.hits if h.id == by_title)
    assert hit.classification == "RED" and hit.in_label is True
    assert hit.node_type is None


# --- documents-unsearchable ----------------------------------------------

def test_the_documents_column_finds_documents_at_the_callers_own_ceiling(
        conn, client, world):
    owner, email, case_id = world
    tok = _tok()
    amber = _doc(conn, _source(conn), body=f"contact {tok} on jabber",
                 title="Access for sale")
    red = _doc(conn, _source(conn), body=f"also {tok}", classification="RED")
    reader, reader_email = _user(conn, clearance="AMBER", roles=("ANALYST",))
    _assign(conn, case_id, reader, "ANALYST", owner)

    r = client.get(f"/api/v1/cases/{case_id}/search/documents",
                   headers=_auth(_session(conn, email)), params={"q": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["not_searched"] is None
    assert {h["id"] for h in body["hits"]} == {str(amber), str(red)}
    assert body["total"] == 2 and body["limit"] == 50
    hit = next(h for h in body["hits"] if h["id"] == str(amber))
    assert hit["label"] == "Access for sale" and tok in hit["excerpt"]
    assert hit["source_name"].startswith("test-scol-")
    assert hit["author_handle"] == "vendor01" and hit["classification"] == "AMBER"
    assert "external_url" not in hit, "the pane draws no link to a forum"

    r = client.get(f"/api/v1/cases/{case_id}/search/documents",
                   headers=_auth(_session(conn, reader_email)), params={"q": tok})
    assert r.status_code == 200, r.text
    assert [h["id"] for h in r.json()["hits"]] == [str(amber)], (
        "a RED document reached an AMBER analyst")


def test_a_caller_who_may_not_read_documents_is_told_so_not_shown_none(
        conn, client, world):
    """READ_ONLY holds case.read and no collection.read: the column says
    it was not searched, and names the roles that read documents."""
    owner, _, case_id = world
    tok = _tok()
    _doc(conn, _source(conn), body=f"contact {tok}")
    reader, reader_email = _user(conn)
    _assign(conn, case_id, reader, "READ_ONLY", owner)
    r = client.get(f"/api/v1/cases/{case_id}/search/documents",
                   headers=_auth(_session(conn, reader_email)), params={"q": tok})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["hits"] == [] and body["total"] == 0
    said = body["not_searched"]
    assert said and "not searched" in said
    for name in ("Analyst", "Lead investigator", "Collection manager", "Reviewer"):
        assert name in said, (name, said)
    assert "collection.read" not in said, "a permission code reached the analyst"


# --- assertions-unsearchable ---------------------------------------------

def test_claims_are_found_by_rationale_reference_value_and_grading(conn, client, world):
    owner, email, case_id = world
    tok = _tok()
    wallet = _node(conn, case_id, owner, "bc1qexample", node_type="WALLET",
                   rationale=f"address quoted in an {tok} message",
                   reliability="C", credibility="3", confidence="MODERATE")
    other = _node(conn, case_id, owner, "other persona",
                  external_ref=f"{tok}-ticket-7", reliability="B",
                  credibility="2")
    valued = _node(conn, case_id, owner, "valued persona")
    from noctornal_api.graph import GraphWriteService
    GraphWriteService(conn).add_assertion(
        case_id=case_id, node_id=valued,
        assertion=_claim(owner, claim_path="attrs.handle",
                         claim_value={"handle": f"{tok}handle"}))

    hits, total = _claims(conn, case_id, tok)
    got = {h.element_id: h for h in hits}
    assert total == 3 and set(got) == {wallet, other, valued}
    assert got[wallet].matched_in == "rationale"
    assert got[wallet].element_kind == "node"
    assert got[wallet].element_label == "bc1qexample"
    assert got[wallet].grading == "C3" and got[wallet].confidence == "MODERATE"
    assert got[other].matched_in == "reference"
    assert got[valued].matched_in == "claim"

    graded, _ = _claims(conn, case_id, "c3")
    assert wallet in {h.element_id for h in graded}
    assert all(h.grading == "C3" for h in graded)
    assert graded[0].matched_in == "grading" and graded[0].rank == 1.0

    r = client.get(f"/api/v1/cases/{case_id}/search/assertions",
                   headers=_auth(_session(conn, email)), params={"q": tok})
    assert r.status_code == 200, r.text
    rows = {row["element_id"]: row for row in r.json()["hits"]}
    assert rows[str(wallet)]["matched_in"] == "rationale"
    assert r.json()["total"] == 3


def test_a_claim_is_found_by_its_exhibit_title_only_by_those_who_may_read_it(
        conn, world):
    """The inspector names a claim's exhibit only under evidence.read, so
    the title must not be the reason a claim is found without it."""
    owner, _, case_id = world
    tok = _tok()
    exhibit = _exhibit(conn, case_id, owner, f"{tok}-escrow.eml")
    n = _node(conn, case_id, owner, "escrow agent", evidence_id=exhibit)
    hits, _ = _claims(conn, case_id, tok)
    assert [h.element_id for h in hits] == [n]
    assert hits[0].matched_in == "exhibit"
    assert hits[0].exhibit_title == f"{tok}-escrow.eml"
    assert _claims(conn, case_id, tok, exhibits=False) == ([], 0)
    # And never above the caller's own ceiling.
    red = _exhibit(conn, case_id, owner, f"{tok}-red.eml", "RED")
    _node(conn, case_id, owner, "red cited", evidence_id=red)
    amber_hits, _ = _claims(conn, case_id, f"{tok}-red", clearance="AMBER")
    assert amber_hits == []


def test_a_claim_on_anything_the_caller_may_not_see_is_not_found(conn, world):
    """A RED entity's claim, a tie with a RED end, a retracted claim and a
    merged-away record's claim: none reaches an AMBER caller (or anyone,
    for the last two)."""
    owner, _, case_id = world
    tok = _tok()
    red = _node(conn, case_id, owner, "red persona", classification="RED",
                rationale=f"{tok} red node")
    amber = _node(conn, case_id, owner, "amber persona",
                  rationale=f"{tok} amber node")
    tie = _edge(conn, case_id, owner, amber, red, rationale=f"{tok} red tie")
    live = _claims(conn, case_id, tok)
    assert {h.element_id for h in live[0]} == {red, amber, tie}
    edge_hit = next(h for h in live[0] if h.element_id == tie)
    assert edge_hit.element_kind == "edge"
    assert edge_hit.element_label == "amber persona → red persona"
    assert edge_hit.src_node_id == amber
    amber_view = {h.element_id for h in _claims(conn, case_id, tok,
                                                clearance="AMBER")[0]}
    assert amber_view == {amber}, "a RED entity or a tie to one leaked"

    from noctornal_api.graph import GraphWriteService
    gws = GraphWriteService(conn)
    extra = gws.add_assertion(case_id=case_id, node_id=amber,
                              assertion=_claim(owner, rationale="kept"))
    first = conn.execute(
        "SELECT id FROM core.assertion WHERE node_id = %s AND id <> %s",
        (amber, extra)).fetchone()[0]
    gws.retract_assertion(first, retracted_by=owner, reason="wrong",
                          at=datetime.now(timezone.utc))
    assert amber not in {h.element_id for h in _claims(conn, case_id,
                                                       f"{tok} amber")[0]}


def test_the_assertions_route_needs_case_read(conn, client, world):
    owner, _, case_id = world
    outsider, outsider_email = _user(conn)
    r = client.get(f"/api/v1/cases/{case_id}/search/assertions",
                   headers=_auth(_session(conn, outsider_email)),
                   params={"q": "anything"})
    assert r.status_code == 404, "an unassigned caller learns the case exists"


# --- developer-speak: the grant table and the comms notice ----------------

def test_any_signed_in_account_reads_the_grant_table_as_the_database_holds_it(
        conn, client):
    uid, email = _user(conn)            # no role at all
    r = client.get("/api/v1/roles/holders", headers=_auth(_session(conn, email)))
    assert r.status_code == 200, r.text
    body = r.json()
    names = {row["key"]: row["display_name"] for row in body["roles"]}
    assert names["CASE_OWNER"] == "Lead investigator"
    assert "SERVICE" not in names, "a person is never told to become the service"
    want: dict[str, list[str]] = {
        k: [] for (k,) in conn.execute("SELECT key FROM iam.permission")}
    for perm, role in conn.execute(
            "SELECT permission_key, role_key FROM iam.role_permission "
            "WHERE role_key <> 'SERVICE' ORDER BY 1, 2"):
        want[perm].append(role)
    assert body["holders"] == want
    assert body["holders"]["sample.detonate"] == [], (
        "a permission no role holds is listed, so the console can say so")


def test_the_grant_table_needs_a_session(client):
    assert client.get("/api/v1/roles/holders").status_code == 401


def _refusal_contexts(js: str) -> list[str]:
    """The written context of every `refusalText(err, ...)` in the console:
    its string literals joined, which is the whole context for all of them
    but those built from a variable (and those are checked where built)."""
    import re
    found = []
    for m in re.finditer(r"refusalText\(", js):
        depth = 0
        for i in range(m.end() - 1, min(len(js), m.end() + 1200)):
            if js[i] == "(":
                depth += 1
            elif js[i] == ")":
                depth -= 1
                if depth == 0:
                    break
        call = js[m.end():i]
        text = "".join(re.findall(r"'((?:[^'\\\n]|\\.)*)'", call)).replace("\\'", "'")
        if text.strip():
            found.append(text)
    return found


def test_every_refusal_reads_as_a_sentence_against_the_real_grant_table(
        conn, client, tmp_path):
    """With the grant table as the database holds it, every context the
    console gives `refusalText` becomes role names and still reads as a
    sentence. The Audit chain refusal most accounts see had become
    "Refused. the Security officer role is granted to Security officer
    alone: ..." (verifier of ux19-copy developer-speak-in-copy, 2026-09-23),
    and nothing ran the contexts against the real table."""
    import json
    import re

    from test_search_palette_copy_ui import _API_ERROR, NODE, _fn, _js, _run
    if not NODE:
        pytest.skip("Node is not installed here")
    _, email = _user(conn)
    table = client.get("/api/v1/roles/holders",
                       headers=_auth(_session(conn, email))).json()
    contexts = _refusal_contexts(_js())
    assert len(contexts) >= 20, "the extraction no longer finds the contexts"
    got = _run([_API_ERROR, _fn("refusalText"), _fn("closeClause"),
                _fn("permissionRefusal"), _fn("roleWords"), _fn("rolesFor"),
                _fn("listWords"),
                "const table = " + json.dumps(table) + ";",
                "let permissionRoles = { names: new Map(table.roles.map("
                "(r) => [r.key, r.display_name])), holders: table.holders };",
                "const contexts = " + json.dumps(contexts) + ";"], r"""
const out = contexts.map((c) => {
  const code = (/\b([a-z_]+(?:\.[a-z_]+)+)\b/.exec(c) || [])[1];
  const held = code && table.holders[code] !== undefined;
  return { c, words: roleWords(c), full: held ? refusalText(new ApiError(403,
    'Forbidden', 'missing permission ' + code + ' on this case'), c) : null };
});
console.log(JSON.stringify(out));
""", tmp_path)
    names = [r["display_name"] for r in table["roles"]]
    keys = [r["key"] for r in table["roles"]]
    for row in got:
        words = row["words"]
        assert words[:1].isupper(), (row["c"], words)
        for code in table["holders"]:
            assert not re.search(rf"(?<![\w.]){re.escape(code)}(?![\w.])", words), (
                code, words)
        for key in keys:
            assert not re.search(rf"\b{key}\b", words), (key, words)
        for sentence in re.split(r"(?<=[.!?])\s+", words):
            for name in names:
                assert len(re.findall(rf"\b{re.escape(name)}\b", sentence)) <= 1, (
                    f"{name} twice in one sentence: {sentence}")
        if row["full"]:
            # The context names the code the detail refuses, so the detail
            # is only "Refused." and the context follows as a sentence.
            assert re.match(r"Refused\. [A-Z]", row["full"]), row["full"]
    audit = next(row for row in got
                 if row["c"].startswith("Verifying the audit chain needs"))
    held = [n for k, n in zip(keys, names, strict=True)
            if k in table["holders"]["audit.read"]]
    said = held[0] if len(held) == 1 else ", ".join(held[:-1]) + " or " + held[-1]
    assert audit["words"].startswith(
        f"Verifying the audit chain needs the {said} role: the administrator")


def test_the_comms_notice_names_the_review_item_and_no_design_document(conn, client, world):
    owner, email, case_id = world
    r = client.post(f"/api/v1/cases/{case_id}/comms/conversations",
                    headers=_auth(_session(conn, email)),
                    json={"platform_key": "MATRIX", "provenance_class": "OPEN_GROUP"})
    assert r.status_code == 201, r.text
    notice = r.json()["notice"]
    assert "L4" in notice and "docs/" not in notice
