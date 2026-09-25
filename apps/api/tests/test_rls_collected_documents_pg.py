"""Row-level security on collected documents and proposals (S1, 2026-09-25).

0118 puts `collect.document`, what hangs off it (extractions, forum and
Telegram side rows, vectors) and `collect.proposal` under policy. Each test
runs the policy, a service or a route as the request role, bound by a real
session's proof, with the fixtures seeded as the owner (rls_support):

- a document is held to the reader's CASE-LESS ceiling and compartments:
  a grant scoped to a case never raises it, a global one does; its
  children follow it; an unbound connection sees and writes nothing;
- a proposal is visible in a readable case only, and its label never
  reads LOW because its document is hidden (the fact read, not a join);
- the cross-case document search runs as the definer and is narrowed to
  the bound reader, never widened by the caller's own arguments;
- the work that must see every document still does: a pasted capture
  dedupes onto a document above the capturer, the readiness register
  counts documents its reader cannot see, and a source's reclassification
  requeues every document of it;
- the document policy is initplans only, never a per-row definer call.

Gated like the other row-security tests (NOCTORNAL_APP_DB_ROLE). Account
prefix `rlsdoc-`, source names `rlsdoc-`.
"""
from __future__ import annotations

import hashlib
import json
import os
from uuid import UUID, uuid4

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "rlsdoc-"
KEY = "RLS-DOC-K"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    s.register(c, KEY)
    yield c
    sources = f"(SELECT id FROM collect.source WHERE name LIKE '{PREFIX}%')"
    docs = (f"(SELECT id FROM collect.document WHERE source_id IN {sources} "
            f"OR title LIKE '{PREFIX}%')")
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    with c.transaction():
        c.execute(f"DELETE FROM core.embedding_pending WHERE item_id IN {docs}")
        c.execute(f"DELETE FROM collect.proposal WHERE case_id IN {cases} "
                  f"OR document_id IN {docs}")
        c.execute(f"DELETE FROM collect.watch_hit WHERE document_id IN {docs}")
        c.execute(f"DELETE FROM collect.watch WHERE name LIKE '{PREFIX}%'")
        c.execute(f"DELETE FROM collect.extraction WHERE document_id IN {docs}")
        c.execute(f"DELETE FROM collect.forum_post WHERE document_id IN {docs}")
        c.execute(f"DELETE FROM collect.document WHERE id IN {docs}")
        c.execute(f"DELETE FROM collect.source WHERE name LIKE '{PREFIX}%'")
    s.cleanup(c, PREFIX)
    c.close()


def _source(conn, classification: str = "AMBER", kind: str = "FORUM") -> UUID:
    kind = "XENFORO" if kind == "FORUM" else kind
    return conn.execute(
        """INSERT INTO collect.source (kind, name, default_reliability, classification)
           VALUES (%s::collect.source_kind, %s, 'F', %s) RETURNING id""",
        (kind, f"{PREFIX}{uuid4().hex[:8]}", classification)).fetchone()[0]


def _registered(conn, *keys: str) -> None:
    """Every compartment a raw write carries is registered first (0059)."""
    s.register(conn, *keys)


def _document(conn, source: UUID, classification: str = "AMBER",
              keys: tuple[str, ...] = (), word: str | None = None,
              body: str | None = None) -> UUID:
    word = word or f"rlsdoczq{uuid4().hex[:8]}"
    text = body or f"the thread mentions {word}"
    _registered(conn, *keys)
    return conn.execute(
        """INSERT INTO collect.document (source_id, title, body_text,
                                         content_sha256, classification,
                                         compartments)
           VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
        (source, f"{PREFIX}{word}", text,
         hashlib.sha256(text.encode()).digest() if body else os.urandom(32),
         classification, list(keys))).fetchone()[0]


def _extraction(conn, document: UUID) -> UUID:
    return conn.execute(
        """INSERT INTO collect.extraction (document_id, selector_type, raw_value,
                                           norm_value, extractor)
           VALUES (%s, 'EMAIL', 'x@rlsdoc.test', 'x@rlsdoc.test', 'rlsdoc/1')
           RETURNING id""", (document,)).fetchone()[0]


def _proposal(conn, case_id: UUID, document: UUID | None = None,
              classification: str | None = "AMBER") -> UUID:
    payload = {"node_type": "SELECTOR", "label": f"{uuid4().hex[:6]}@rlsdoc.test",
               "attrs": {"selector_type": "EMAIL"}}
    if classification:
        payload["classification"] = classification
    return conn.execute(
        """INSERT INTO collect.proposal (case_id, kind, payload, origin, rationale,
                                         document_id)
           VALUES (%s, 'NODE', %s, 'rlsdoc/1', 'found in a captured thread', %s)
           RETURNING id""", (case_id, json.dumps(payload), document)).fetchone()[0]


def _ids(conn, sql: str, params=None) -> set[UUID]:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


# ---------------------------------------------------------------------------
# The document policy and its children
# ---------------------------------------------------------------------------

def test_a_document_is_held_to_the_case_less_ceiling_and_its_children_follow(owner):
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    red_case = s.case(owner, boss, "RED")
    s.assign(owner, red_case, analyst)
    src = _source(owner)
    amber = _document(owner, src)
    red = _document(owner, src, "RED")
    walled = _document(owner, src, keys=(KEY,))
    amber_x, red_x = _extraction(owner, amber), _extraction(owner, red)
    _, raw = s.session(owner, analyst)
    mine = f"SELECT id FROM collect.document WHERE source_id = '{src}'"

    app = s.app_conn(raw)
    try:
        assert _ids(app, mine) == {amber}
        assert _ids(app, "SELECT id FROM collect.extraction WHERE id = ANY(%s)",
                    ([amber_x, red_x],)) == {amber_x}
        # A grant scoped to a case never raises a row that belongs to no
        # case (final review C11); a global one does.
        s.break_glass(owner, analyst, "RED", red_case)
        assert _ids(app, mine) == {amber}
        s.break_glass(owner, analyst, "RED")
        assert _ids(app, mine) == {amber, red}
        assert walled not in _ids(app, mine), "compartments are never widened"
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO collect.document (source_id, body_text, content_sha256,
                                                 compartments)
                   VALUES (%s, 'x', %s, %s)""", (src, os.urandom(32), [KEY]))
    finally:
        app.close()
    unbound = s.app_conn()
    try:
        assert s.count(unbound, f"SELECT count(*) FROM collect.document "
                                f"WHERE source_id = '{src}'") == 0
        assert unbound.execute("UPDATE collect.document SET triage_state = 'LINKED' "
                               "WHERE id = %s", (amber,)).rowcount == 0
    finally:
        unbound.close()


def test_a_proposal_is_read_in_a_readable_case_and_never_below_its_document(owner):
    """The fail-open trap: Triage reads a proposal at the strictest of its
    own and its document's labels. Joined to `collect.document`, a RED
    document the AMBER reader cannot see read as no document, and the
    proposal as AMBER; through `iam.element_facts` it reads RED."""
    from noctornal_api.proposals import ProposalStore

    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    mine, other = s.case(owner, boss), s.case(owner, boss)
    s.assign(owner, mine, analyst)
    red_doc = _document(owner, _source(owner), "RED")
    plain = _proposal(owner, mine)
    from_red = _proposal(owner, mine, red_doc, classification=None)
    elsewhere = _proposal(owner, other)
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        assert _ids(app, "SELECT id FROM collect.proposal WHERE id = ANY(%s)",
                    ([plain, from_red, elsewhere],)) == {plain, from_red}
        store = ProposalStore(app)
        assert store.readable(plain, clearance="AMBER", compartments=frozenset())
        assert not store.readable(from_red, clearance="AMBER",
                                  compartments=frozenset())
        queued = {p.id for p in store.queue(mine, clearance="AMBER",
                                            compartments=frozenset())}
        assert plain in queued and from_red not in queued
    finally:
        app.close()


def _watch(conn, case_id, source, selector: str) -> UUID:
    owner_id = conn.execute("SELECT owner_user_id FROM core.\"case\" WHERE id = %s",
                            (case_id,)).fetchone() if case_id else None
    owner_id = owner_id[0] if owner_id else conn.execute(
        "SELECT id FROM iam.app_user WHERE email LIKE %s LIMIT 1",
        (f"{PREFIX}%@noctornal.test",)).fetchone()[0]
    return conn.execute(
        """INSERT INTO collect.watch (case_id, source_id, name, target_kind,
                                      target_ref, selector_watch, owner_user_id)
           VALUES (%s, %s, %s, 'FORUM', 'rlsdoc', %s, %s) RETURNING id""",
        (case_id, source, f"{PREFIX}{uuid4().hex[:6]}", [selector],
         owner_id)).fetchone()[0]


def test_a_watch_and_its_hits_keep_to_their_case(owner):
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    mine, other = s.case(owner, boss), s.case(owner, boss)
    s.assign(owner, mine, analyst)
    src = _source(owner)
    watches = {"mine": _watch(owner, mine, src, "x@rlsdoc.test"),
               "other": _watch(owner, other, src, "x@rlsdoc.test"),
               "shared": _watch(owner, None, src, "x@rlsdoc.test")}
    amber, red = _document(owner, src), _document(owner, src, "RED")
    hits = {}
    for name, watch in watches.items():
        for label, doc in (("amber", amber), ("red", red)):
            hits[(name, label)] = owner.execute(
                """INSERT INTO collect.watch_hit (watch_id, document_id, matched_on)
                   VALUES (%s, %s, '["selector:x@rlsdoc.test"]') RETURNING id""",
                (watch, doc)).fetchone()[0]
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        assert _ids(app, "SELECT id FROM collect.watch WHERE id = ANY(%s)",
                    (list(watches.values()),)) == {watches["mine"], watches["shared"]}
        assert _ids(app, "SELECT id FROM collect.watch_hit WHERE id = ANY(%s)",
                    (list(hits.values()),)) == {hits[("mine", "amber")],
                                                hits[("shared", "amber")]}
    finally:
        app.close()


def test_ingest_scoring_reads_every_watch_whatever_its_operator_may_read(owner):
    """A quarantined record scores against every watch in the deployment
    (`IngestService._watches_for`); as the request role it would have scored
    against the operator's own cases and the case-less watches alone."""
    from noctornal_api.ingest import IngestService

    operator = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    elsewhere = s.case(owner, boss)
    src = _source(owner)
    theirs = _watch(owner, elsewhere, src, f"{uuid4().hex[:8]}@rlsdoc.test")
    truth = {r[0] for r in IngestService(owner)._watches_for(None, {})}
    assert theirs in truth
    _, raw = s.session(owner, operator)
    app = s.app_conn(raw)
    try:
        assert app.execute("SELECT 1 FROM collect.watch WHERE id = %s",
                           (theirs,)).fetchone() is None
        seen = {r[0] for r in IngestService(app)._watches_for(None, {})}
    finally:
        app.close()
    assert seen == truth


# ---------------------------------------------------------------------------
# Cross-case search
# ---------------------------------------------------------------------------

def test_the_document_search_is_narrowed_to_the_bound_reader_and_never_widened(owner):
    from noctornal_api.curation import SearchService

    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    word = f"rlsdocsw{uuid4().hex[:8]}"
    src = _source(owner)
    amber = _document(owner, src, word=word + "a", body=f"{word} amber")
    red = _document(owner, src, "RED", body=f"{word} red")
    walled = _document(owner, src, keys=(KEY,), body=f"{word} walled")
    _, raw = s.session(owner, analyst)
    call = ("SELECT id FROM iam.search_document_hits(%s, %s, %s, 'RED', %s, 50)")
    args = (f"{word}:*", word, f"%{word}%", [KEY])

    assert _ids(owner, call, args) == {amber, red, walled}, (
        "an exempt caller is held to its own arguments only")
    app = s.app_conn(raw)
    try:
        assert _ids(app, call, args) == {amber}, (
            "RED and the compartment were asked for; the bound reader holds neither")
        rows, total = SearchService(app).document_page(
            query=word, clearance="AMBER", compartments=frozenset())
        assert {UUID(r["id"]) for r in rows} == {amber} and total == 1
    finally:
        app.close()
    unbound = s.app_conn()
    try:
        assert _ids(unbound, call, args) == set(), "unbound reads nothing"
    finally:
        unbound.close()


# ---------------------------------------------------------------------------
# Work that must see every document
# ---------------------------------------------------------------------------

@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def _auth(conn, uid) -> dict:
    _, raw = s.session(conn, uid)
    return {"Authorization": f"Bearer {raw}"}


def test_a_capture_dedupes_onto_a_document_above_the_capturer(owner, client):
    """As the request role the dedupe could not see the RED capture and
    stored the same text again at AMBER, readable by every AMBER collection
    reader: the stricter judgement lost. The capture runs as a system
    purpose, so it lands on the RED document."""
    from noctornal_api.extraction import CaptureService

    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    case_id = s.case(owner, analyst)
    s.assign(owner, case_id, analyst)
    text = f"vendor rlsdoc {uuid4().hex} wrote from red.{uuid4().hex[:6]}@rlsdoc.test"
    manual = CaptureService(owner).source_id()
    digest = hashlib.sha256(text.encode()).digest()
    red = owner.execute(
        """INSERT INTO collect.document (source_id, title, body_text,
                                         content_sha256, classification)
           VALUES (%s, %s, %s, %s, 'RED') RETURNING id""",
        (manual, f"{PREFIX}red", text, digest)).fetchone()[0]
    try:
        r = client.post(f"/api/v1/cases/{case_id}/proposals/capture",
                        headers=_auth(owner, analyst),
                        json={"text": text, "classification": "AMBER"})
        assert r.status_code == 201, r.text
        assert r.json()["deduplicated"] is True
        assert r.json()["document_classification"] is None, "above the caller"
        stored = s.count(owner, "SELECT count(*) FROM collect.document "
                                "WHERE content_sha256 = %s", (digest,))
        assert stored == 1
    finally:
        with owner.transaction():
            owner.execute("DELETE FROM collect.proposal WHERE document_id = %s", (red,))
            owner.execute("DELETE FROM collect.extraction WHERE document_id = %s", (red,))
            owner.execute("DELETE FROM collect.document WHERE content_sha256 = %s",
                          (digest,))


def test_the_readiness_register_counts_what_its_reader_cannot_see(owner):
    """A capture cited by a compartmented case, carrying no compartment, is
    counted by `captured_documents_compartmented`. Taken as an
    administrator on no case, the count read zero under row security and
    the row said every capture was labelled."""
    from noctornal_api import readiness
    from noctornal_api.extraction import CaptureService

    admin = s.user(owner, "AMBER", prefix=PREFIX)
    s.grant_global(owner, admin, "SYS_ADMIN")
    boss = s.user(owner, "RED", (KEY,), prefix=PREFIX)
    walled_case = s.case(owner, boss, compartments=(KEY,))
    doc = _document(owner, CaptureService(owner).source_id())
    _proposal(owner, walled_case, doc)
    truth = readiness.check("captured_documents_compartmented", owner)
    _, raw = s.session(owner, admin)
    app = s.app_conn(raw)
    try:
        seen = readiness.check("captured_documents_compartmented", app)
    finally:
        app.close()
    assert "no compartment" in truth.evidence and "carries a compartment" not in truth.evidence
    assert seen.evidence == truth.evidence


def test_a_source_reclassification_requeues_every_document_of_it(owner):
    """`collect.source_vectors_follow` is SECURITY DEFINER (0118): run as
    the writer it requeued only the documents the writer could see."""
    import embedding_pg as H
    from noctornal_api.embeddings import EmbeddingService

    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    src = _source(owner)
    red = _document(owner, src, "RED")
    H.reset(owner)
    try:
        EmbeddingService(owner, blocking_failures=lambda _c: []).ensure_spaces()
        assert s.count(owner, "SELECT count(*) FROM core.embedding_space "
                              "WHERE state = 'ACTIVE'") == 1
        owner.execute("DELETE FROM core.embedding_pending WHERE item_id = %s", (red,))
        _, raw = s.session(owner, analyst)
        app = s.app_conn(raw)
        try:
            app.execute("UPDATE collect.source SET classification = 'GREEN' "
                        "WHERE id = %s", (src,))
        finally:
            app.close()
        assert s.count(owner, "SELECT count(*) FROM core.embedding_pending "
                              "WHERE kind = 'document' AND item_id = %s", (red,)) == 1
    finally:
        H.reset(owner)


# ---------------------------------------------------------------------------
# Plans
# ---------------------------------------------------------------------------

def _plan_nodes(plan) -> list[dict]:
    out, stack = [], [plan]
    while stack:
        node = stack.pop()
        out.append(node)
        stack.extend(node.get("Plans", []))
    return out


@pytest.mark.parametrize("sql", [
    "SELECT id FROM collect.document WHERE source_id = %s",
    "SELECT id FROM collect.proposal WHERE case_id = %s",
])
def test_the_policy_is_initplans_never_a_per_row_call(owner, sql):
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        plan = app.execute("EXPLAIN (VERBOSE, FORMAT JSON) " + sql,
                           (uuid4(),)).fetchone()[0][0]["Plan"]
    finally:
        app.close()
    nodes = _plan_nodes(plan)
    kinds = {n.get("Parent Relationship") for n in nodes}
    assert "InitPlan" in kinds, plan
    assert "SubPlan" not in kinds, plan
