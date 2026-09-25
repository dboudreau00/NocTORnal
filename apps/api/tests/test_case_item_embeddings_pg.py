"""Exhibit and live-claim similarity, case-scoped and exact (F6.4,
embeddings, 2026-09-24).

An exact scan inside one case with every label predicate applied before
ordering: a reader outside a compartment neither sees nor is displaced by
compartmented exhibits; nothing comes from another case; a claim on a tie
with a hidden end is never returned; retracted claims are kept and left
out. The MEANING gate of a claim takes the cited material's labels and
withholds a claim whose material was purged; items of a closed case are
withheld outside this host and indexed on it; one EMBED_BATCH_SENT per case
per batch names exactly that case's items. The claim visibility rule is
one constant (curation.LIVE_CLAIMS_SQL) the text search and the similarity
search both read.

Env-gated on DATABASE_URL. Prefix `eci-`.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest

import embedding_pg as H
from embedding_stub import StubModel, meaning_env
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "eci-"
K1 = "ECI-K1"
AUTHORITY = "DPIA-2026-EMB-02"


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL") + tuple(
            n for n in os.environ if n.startswith("NOCTORNAL_EMBED_")):
        monkeypatch.delenv(name, raising=False)
    from noctornal_api import embeddings, readiness
    monkeypatch.setattr(readiness, "blocking_failures", lambda _c: [])
    monkeypatch.setattr(embeddings, "_BULK_ENQUEUE",
                        {k: "SELECT %s" for k in embeddings.KINDS})
    embeddings._COVERAGE_CACHE.clear()


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'Case item test') "
              "ON CONFLICT (key) DO NOTHING", (K1,))
    H.reset(c)
    yield c
    H.cleanup(c, PREFIX)
    c.close()


def _service(conn, cfg=None):
    from noctornal_api.embeddings import EmbeddingService
    return EmbeddingService(conn, embedders=cfg, blocking_failures=lambda _c: [])


@pytest.fixture
def wording(conn):
    svc = _service(conn)
    svc.ensure_spaces()
    return svc


def _drain(conn, svc, role="WORDING"):
    return svc.run_pass(role, limit=0, max_seconds=0)


EXHIBIT = ("Screenshot of the vendor thread offering rangefinder cameras with new "
           "light seals, escrow through the marketplace checkout")


def test_compartmented_exhibits_neither_appear_nor_displace(conn, wording):
    owner = H.user(conn, PREFIX, roles=("ANALYST",))
    reader = H.user(conn, PREFIX, clearance="RED", roles=("ANALYST",))
    case_id = H.case(conn, PREFIX, owner)
    other_case = H.case(conn, PREFIX, owner)
    H.assign(conn, case_id, reader, "ANALYST", owner)
    mine = [H.evidence(conn, case_id, owner, title=f"exhibit {i} rangefinder",
                       description=EXHIBIT[: 40 + 10 * i]) for i in range(5)]
    H.evidence(conn, other_case, owner, title="exhibit elsewhere", description=EXHIBIT)
    _drain(conn, wording)
    cl, auth = H.app_client(), H.auth(conn, reader)
    url = f"/api/v1/cases/{case_id}/search/evidence/similar"
    body = {"q": EXHIBIT, "mode": "wording", "limit": 5}
    alone = [h["id"] for h in cl.post(url, headers=auth, json=body).json()["hits"]]
    assert alone and set(alone) <= {str(e) for e in mine}
    for i in range(20):
        H.evidence(conn, case_id, owner, title=f"boxed {i}", description=EXHIBIT,
                   keys=[K1])
    _drain(conn, wording)
    again = cl.post(url, headers=auth, json=body).json()
    assert [h["id"] for h in again["hits"]] == alone
    assert "do not extract" in again["note"] or "does not extract" in again["note"]


def test_a_tie_with_a_hidden_end_and_a_retracted_claim_are_not_returned(conn, wording):
    from noctornal_api.graph import AssertionInput, GraphWriteService
    owner = H.user(conn, PREFIX, roles=("ANALYST",))
    reader = H.user(conn, PREFIX, clearance="AMBER", roles=("ANALYST",))
    case_id = H.case(conn, PREFIX, owner)
    H.assign(conn, case_id, reader, "ANALYST", owner)
    text = "the vendor ships rangefinder cameras from the same warehouse every week"
    visible, _ = H.node_with_claim(conn, case_id, owner, label="eci visible",
                                   rationale=text)
    hidden, _ = H.node_with_claim(conn, case_id, owner, label="eci hidden",
                                  rationale="another node", classification="RED")
    g = GraphWriteService(conn)
    g.create_edge(case_id=case_id, edge_type="COMMUNICATES_WITH", src_node_id=visible,
                  dst_node_id=hidden, created_by=owner,
                  assertion=AssertionInput(basis="ANALYST_INFERENCE", created_by=owner,
                                           rationale=text + " together"))
    retracted_node, retracted = H.node_with_claim(conn, case_id, owner,
                                                  label="eci retracted",
                                                  rationale=text + " retracted")
    _drain(conn, wording)
    g.retract_assertion(retracted, retracted_by=owner, reason="wrong",
                        at=datetime.now(timezone.utc))
    r = H.app_client().post(f"/api/v1/cases/{case_id}/search/assertions/similar",
                            headers=H.auth(conn, reader),
                            json={"q": text, "mode": "wording", "limit": 50})
    hits = r.json()["hits"]
    kinds = {h["element_kind"] for h in hits}
    assert kinds == {"node"}
    assert str(retracted) not in {h["id"] for h in hits}
    assert conn.execute("SELECT status FROM core.assertion_embedding WHERE "
                        "assertion_id = %s", (retracted,)).fetchone()[0] == "EMBEDDED"
    del retracted_node


def test_an_exhibit_edit_re_embeds_and_a_purge_removes(conn, wording):
    owner = H.user(conn, PREFIX)
    case_id = H.case(conn, PREFIX, owner)
    ev = H.evidence(conn, case_id, owner, title="first title", description=EXHIBIT)
    _drain(conn, wording)
    row = "SELECT status FROM core.evidence_embedding WHERE evidence_id = %s"
    assert conn.execute(row, (ev,)).fetchone()[0] == "EMBEDDED"
    conn.execute("UPDATE core.evidence SET title = 'second title' WHERE id = %s", (ev,))
    assert conn.execute(row, (ev,)).fetchone() is None
    _drain(conn, wording)
    assert conn.execute(row, (ev,)).fetchone()[0] == "EMBEDDED"
    conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s", (ev,))
    assert conn.execute(row, (ev,)).fetchone() is None
    assert conn.execute("SELECT count(*) FROM core.embedding_pending WHERE item_id = %s",
                        (ev,)).fetchone()[0] == 0


def test_break_glass_raises_case_items_and_never_documents(conn, wording):
    owner = H.user(conn, PREFIX, roles=("ANALYST",))
    reader = H.user(conn, PREFIX, clearance="AMBER", roles=("ANALYST",))
    case_id = H.case(conn, PREFIX, owner, classification="AMBER")
    H.assign(conn, case_id, reader, "ANALYST", owner)
    red = H.evidence(conn, case_id, owner, title="red exhibit", description=EXHIBIT,
                     classification="RED")
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body=EXHIBIT,
                     classification="RED")
    _drain(conn, wording)
    cl, auth = H.app_client(), H.auth(conn, reader)
    ev_url = f"/api/v1/cases/{case_id}/search/evidence/similar"
    doc_url = f"/api/v1/cases/{case_id}/search/documents/similar"
    body = {"q": EXHIBIT, "mode": "wording"}
    assert str(red) not in {h["id"] for h in cl.post(ev_url, headers=auth,
                                                     json=body).json()["hits"]}
    conn.execute("""INSERT INTO iam.break_glass (user_id, case_id, justification,
                        expires_at, granted_classification)
                    VALUES (%s, %s, 'an urgent threat to life needs this exhibit now',
                            now() + interval '1 hour', 'RED')""", (reader, case_id))
    assert str(red) in {h["id"] for h in cl.post(ev_url, headers=auth,
                                                 json=body).json()["hits"]}
    assert str(doc) not in {h["id"] for h in cl.post(doc_url, headers=auth,
                                                     json=body).json()["hits"]}


def test_the_similar_routes_gate_as_the_text_search_does(conn, wording):
    owner = H.user(conn, PREFIX, roles=("ANALYST",))
    outsider = H.user(conn, PREFIX, roles=("ANALYST",))
    case_id = H.case(conn, PREFIX, owner)
    ev = H.evidence(conn, case_id, owner, title="gated", description=EXHIBIT)
    _, claim = H.node_with_claim(conn, case_id, owner, label="eci gated",
                                 rationale=EXHIBIT)
    _drain(conn, wording)
    cl = H.app_client()
    auth = H.auth(conn, outsider)
    for url in (f"/api/v1/cases/{case_id}/evidence/{ev}/similar",
                f"/api/v1/cases/{case_id}/assertions/{claim}/similar",
                f"/api/v1/cases/{case_id}/search/evidence/similar",
                f"/api/v1/cases/{case_id}/search/assertions/similar"):
        body = {"q": EXHIBIT, "mode": "wording"} if "search" in url else {}
        assert cl.post(url, headers=auth, json=body).status_code in (403, 404), url
    auth = H.auth(conn, owner)
    r = cl.post(f"/api/v1/cases/{case_id}/evidence/{ev}/similar", headers=auth, json={})
    assert r.status_code == 200 and str(ev) not in {h["id"] for h in r.json()["hits"]}


def test_one_constant_is_the_claim_visibility_rule_for_both_searches(conn, wording,
                                                                     monkeypatch):
    from noctornal_api import curation
    from noctornal_api.curation import SearchService
    owner = H.user(conn, PREFIX, roles=("ANALYST",))
    case_id = H.case(conn, PREFIX, owner)
    H.node_with_claim(conn, case_id, owner, label="eci rule", rationale=EXHIBIT)
    _drain(conn, wording)
    svc = _service(conn)
    slot = svc.active("WORDING").slot
    query = E.vector_literal(E.builtin().embed_one(EXHIBIT).vector)

    def both():
        text, _ = SearchService(conn).assertion_page(
            case_id=case_id, query="rangefinder", limit=10, clearance="RED",
            compartments=frozenset(), may_see_exhibits=False)
        similar = svc.assertion_similar(case_id=case_id, slot=slot, query=query,
                                        clearance="RED", held=frozenset(), limit=10,
                                        may_see_exhibits=False)
        return len(text), len(similar)
    assert both() == (1, 1)
    monkeypatch.setattr(curation, "LIVE_CLAIMS_SQL",
                        curation.LIVE_CLAIMS_SQL.replace(
                            "WHERE n.case_id = %(case_id)s",
                            "WHERE false AND n.case_id = %(case_id)s"))
    assert both() == (0, 0)


# ---------------------------------------------------------------------------
# The MEANING gate for case items
# ---------------------------------------------------------------------------

@pytest.fixture
def stub():
    s = StubModel(dims=384)
    yield s
    s.close()


def _meaning(conn, stub, **env):
    cfg = E.configured(meaning_env(stub, **env))
    assert cfg.meaning_settings is not None, cfg.problems
    svc = _service(conn, cfg)
    return svc


def _status(conn, kind, item):
    table, col = {"evidence": ("core.evidence_embedding", "evidence_id"),
                  "assertion": ("core.assertion_embedding", "assertion_id")}[kind]
    return conn.execute(f"SELECT status, reason FROM {table} WHERE {col} = %s",
                        (item,)).fetchone()


def test_a_claims_gate_takes_its_cited_materials_labels(conn, stub):
    owner = H.user(conn, PREFIX)
    case_id = H.case(conn, PREFIX, owner, classification="AMBER")
    remote = _meaning(conn, stub, local=False, **{E.AUTHORITY_ENV: AUTHORITY})
    remote.run_pass("MEANING", max_seconds=0)
    src = H.source(conn, PREFIX)
    red_doc = H.document(conn, PREFIX, src=src, body="red material",
                         classification="RED")
    boxed_ev = H.evidence(conn, case_id, owner, title="boxed", keys=[K1])
    gone_doc = H.document(conn, PREFIX, src=src, body="soon purged")
    gone_ev = H.evidence(conn, case_id, owner, title="soon purged exhibit")
    fine_doc = H.document(conn, PREFIX, src=src, body="an ordinary forum post")
    _, cites_red = H.node_with_claim(conn, case_id, owner, label="eci a",
                                     rationale="quotes the red post", document_id=red_doc)
    _, cites_box = H.node_with_claim(conn, case_id, owner, label="eci b",
                                     rationale="cites the boxed exhibit",
                                     evidence_id=boxed_ev)
    _, cites_gone = H.node_with_claim(conn, case_id, owner, label="eci c",
                                      rationale="cites a purged post",
                                      document_id=gone_doc)
    _, cites_gone_ev = H.node_with_claim(conn, case_id, owner, label="eci d",
                                         rationale="cites a purged exhibit",
                                         evidence_id=gone_ev)
    _, fine = H.node_with_claim(conn, case_id, owner, label="eci e",
                                rationale="cites an ordinary post", document_id=fine_doc)
    conn.execute("UPDATE collect.document SET purged_at = now(), body_text = '' "
                 "WHERE id = %s", (gone_doc,))
    conn.execute("UPDATE core.evidence SET purged_at = now() WHERE id = %s", (gone_ev,))
    remote.run_pass("MEANING", max_seconds=0)
    assert _status(conn, "assertion", cites_red) == ("WITHHELD", "above_platform_floor")
    assert _status(conn, "assertion", cites_box) == ("WITHHELD", "compartmented_material")
    assert _status(conn, "assertion", cites_gone) == ("WITHHELD", "material_unavailable")
    assert _status(conn, "assertion", cites_gone_ev) == ("WITHHELD",
                                                         "material_unavailable")
    assert _status(conn, "assertion", fine) == ("EMBEDDED", None)
    assert "quotes the red post" not in "".join(stub.texts())
    # On this host with an AMBER ceiling the RED citation is above the ceiling.
    H.reset(conn)
    host = _meaning(conn, stub, **{E.CEILING_ENV: "AMBER"})
    host.run_pass("MEANING", max_seconds=0)
    conn.execute("INSERT INTO core.embedding_pending (slot, kind, item_id) "
                 "SELECT slot, 'assertion', %s FROM core.embedding_space", (cites_red,))
    host.run_pass("MEANING", max_seconds=0)
    assert _status(conn, "assertion", cites_red) == ("WITHHELD",
                                                     "above_destination_ceiling")


def test_a_closed_case_is_withheld_outside_and_indexed_on_this_host(conn, stub):
    owner = H.user(conn, PREFIX)
    case_id = H.case(conn, PREFIX, owner)
    remote = _meaning(conn, stub, local=False, **{E.AUTHORITY_ENV: AUTHORITY})
    remote.run_pass("MEANING", max_seconds=0)
    ev = H.evidence(conn, case_id, owner, title="closed case exhibit", description=EXHIBIT)
    conn.execute('UPDATE core."case" SET status = \'CLOSED\', closed_at = now() '
                 "WHERE id = %s", (case_id,))
    remote.run_pass("MEANING", max_seconds=0)
    assert _status(conn, "evidence", ev) == ("WITHHELD", "case_closed")
    conn.execute('UPDATE core."case" SET status = \'ACTIVE\', closed_at = NULL '
                 "WHERE id = %s", (case_id,))
    conn.execute("UPDATE core.evidence_embedding SET next_attempt_at = now() "
                 "WHERE evidence_id = %s", (ev,))
    remote.run_pass("MEANING", max_seconds=0)
    assert _status(conn, "evidence", ev) == ("EMBEDDED", None)
    H.reset(conn)
    host = _meaning(conn, stub)
    host.run_pass("MEANING", max_seconds=0)
    ev2 = H.evidence(conn, case_id, owner, title="second exhibit", description=EXHIBIT)
    conn.execute('UPDATE core."case" SET status = \'CLOSED\', closed_at = now() '
                 "WHERE id = %s", (case_id,))
    host.run_pass("MEANING", max_seconds=0)
    assert _status(conn, "evidence", ev2) == ("EMBEDDED", None)


def test_compartmented_items_are_withheld_and_one_audit_row_per_case(conn, stub):
    owner = H.user(conn, PREFIX)
    first, second = H.case(conn, PREFIX, owner), H.case(conn, PREFIX, owner)
    host = _meaning(conn, stub)
    host.run_pass("MEANING", max_seconds=0)
    a = [H.evidence(conn, first, owner, title=f"first {i}", description=EXHIBIT)
         for i in range(2)]
    b = [H.evidence(conn, second, owner, title=f"second {i}", description=EXHIBIT)
         for i in range(3)]
    boxed = H.evidence(conn, first, owner, title="boxed", description=EXHIBIT, keys=[K1])
    host.run_pass("MEANING", max_seconds=0)
    assert _status(conn, "evidence", boxed) == ("WITHHELD", "compartmented_material")
    rows = conn.execute("SELECT case_id, detail FROM audit.event WHERE action = "
                        "'EMBED_BATCH_SENT' AND case_id = ANY(%s)",
                        ([first, second],)).fetchall()
    by_case = {r[0]: sorted(r[1]["items"]) for r in rows}
    assert by_case == {first: sorted(str(x) for x in a), second: sorted(str(x) for x in b)}
