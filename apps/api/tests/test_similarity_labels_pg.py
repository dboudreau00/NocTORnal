"""Similarity reads never cross a label (F6.3, embeddings, 2026-09-24).

The invariant: a reader is never given, never answered about and never
counted a document above their clearance, of a source above it, or in a
compartment they do not hold, in either mode; and rows the reader may not
read can neither be returned nor DISPLACE rows the reader may read. The
displacement test has power: the same rows in one unpartitioned HNSW
index with a filter after it return fewer of the reader's rows, and the
per-level partial indexes return them all. The plan names exactly the
indexes of the levels at or below the reader.

Env-gated on DATABASE_URL. Prefix `esl-`.
"""
from __future__ import annotations

import os

from uuid import uuid4

import pytest
from psycopg import sql

import embedding_pg as H
from embedding_stub import StubModel, meaning_env
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "esl-"
K1 = "ESL-K1"
FIX = os.path.join(os.path.dirname(__file__), "fixtures", "embeddings")
BASE = open(os.path.join(FIX, "camera_shop.txt"), encoding="utf-8").read()[:1500]


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL") + tuple(
            n for n in os.environ if n.startswith("NOCTORNAL_EMBED_")):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def conn():
    from noctornal_api import embeddings
    from noctornal_api.db import connect
    c = connect()
    c.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, 'Label test') "
              "ON CONFLICT (key) DO NOTHING", (K1,))
    H.reset(c)
    embeddings._COVERAGE_CACHE.clear()
    yield c
    H.cleanup(c, PREFIX)
    c.close()


def _service(conn, cfg=None):
    from noctornal_api.embeddings import EmbeddingService
    return EmbeddingService(conn, embedders=cfg, blocking_failures=lambda _c: [])


@pytest.fixture
def svc(conn):
    s = _service(conn)
    s.ensure_spaces()
    return s


def _embed(conn, svc, docs):
    H.only_queue(conn, docs)
    result = svc.run_pass("WORDING", limit=0, max_seconds=0)
    assert result.embedded == len(docs), result


def _variant(i: int) -> str:
    """Further from BASE than any near copy, still about the same things."""
    words = BASE.split()
    return " ".join(f"changed{i}x{j}" if j % 3 == i % 3 else w
                    for j, w in enumerate(words))


def _query(svc):
    return E.vector_literal(E.builtin().embed_one(BASE).vector)


def _ids(conn, svc, *, clearance="AMBER", held=frozenset()):
    space = svc.active("WORDING")
    with conn.transaction():
        conn.execute("SET LOCAL enable_seqscan = off")
        hits = svc.document_candidates(slot=space.slot, query=_query(svc),
                                       clearance=clearance, held=held, k=11, limit=10)
    return [h["id"] for h in hits]


def test_rows_above_the_reader_neither_appear_nor_displace(conn, svc):
    open_src = H.source(conn, PREFIX, classification="AMBER")
    red_src = H.source(conn, PREFIX, classification="RED")
    amber = [H.document(conn, PREFIX, src=open_src, body=_variant(i)) for i in range(10)]
    _embed(conn, svc, amber)
    alone = _ids(conn, svc)
    assert sorted(alone) == sorted(str(d) for d in amber)
    # 60 near copies of the query, all closer than every AMBER row: 30 RED
    # documents, and 30 AMBER documents of a RED source.
    red = [H.document(conn, PREFIX, src=open_src, body=BASE + f" copy {i}",
                      classification="RED") for i in range(30)]
    red += [H.document(conn, PREFIX, src=red_src, body=BASE + f" copy {i}")
            for i in range(30, 60)]
    _embed(conn, svc, red)
    assert _ids(conn, svc) == alone
    # The RED source relabelled: its rows are deleted and re-embedded under
    # the new label, still above the reader.
    conn.execute("UPDATE collect.source SET classification = 'AMBER_STRICT' WHERE id = %s",
                 (red_src,))
    _embed(conn, svc, red[30:])
    assert _ids(conn, svc) == alone
    # And 60 near copies in a compartment the reader does not hold.
    boxed = [H.document(conn, PREFIX, src=open_src, body=BASE + f" boxed {i}", keys=[K1])
             for i in range(60)]
    _embed(conn, svc, boxed)
    assert _ids(conn, svc) == alone
    # A holder at RED sees the near copies first: the reads are live.
    holder = _ids(conn, svc, clearance="RED", held=frozenset({K1}))
    assert not set(holder) & set(alone)


def test_one_unpartitioned_index_with_a_filter_after_it_loses_the_readers_rows(conn, svc):
    """The power of the test above: the index layout it replaces fails it."""
    src = H.source(conn, PREFIX)
    amber = [H.document(conn, PREFIX, src=src, body=_variant(i)) for i in range(10)]
    red = [H.document(conn, PREFIX, src=src, body=BASE + f" copy {i}",
                      classification="RED") for i in range(60)]
    _embed(conn, svc, amber + red)
    space = svc.active("WORDING")
    with conn.transaction():
        conn.execute("""CREATE TEMP TABLE esl_scratch ON COMMIT DROP AS
                          SELECT document_id, read_classification, embedding
                            FROM collect.document_embedding
                           WHERE slot = %s AND embedding IS NOT NULL""", (space.slot,))
        conn.execute("CREATE INDEX ON esl_scratch USING hnsw (embedding vector_cosine_ops)")
        conn.execute("SET LOCAL enable_seqscan = off")
        conn.execute("SET LOCAL hnsw.ef_search = 40")
        rows = conn.execute(
            """SELECT document_id FROM esl_scratch
                WHERE read_classification <= 'AMBER'::core.tlp
                ORDER BY embedding <=> %s::vector(768) LIMIT 10""",
            (_query(svc),)).fetchall()
    assert len(rows) < 10
    assert len(_ids(conn, svc)) == 10


def test_the_plan_walks_only_the_readers_partitions(conn, svc):
    src = H.source(conn, PREFIX)
    docs = [H.document(conn, PREFIX, src=src, body=_variant(i), classification=level)
            for i, level in enumerate(["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"])]
    _embed(conn, svc, docs)
    space = svc.active("WORDING")
    statement = svc.candidate_sql(slot=space.slot, clearance="AMBER", held=frozenset())
    with conn.transaction():
        # A table of five rows is cheaper to scan exactly, and after the
        # churn of the tests before this one the planner may well say so;
        # these hold it to the plan a real estate gets, the ordered HNSW
        # scan of each partition. Correctness does not depend on the plan:
        # every branch carries its partition's predicate either way.
        conn.execute("SET LOCAL enable_seqscan = off")
        conn.execute("SET LOCAL enable_bitmapscan = off")
        conn.execute("SET LOCAL enable_sort = off")
        plan = "\n".join(r[0] for r in conn.execute(
            sql.SQL("EXPLAIN (COSTS OFF) ") + statement,
            {"q": _query(svc), "k": 10, "clearance": "AMBER", "held": [], "limit": 10,
             "exclude": []}).fetchall())
    for level in ("clear", "green", "amber"):
        assert f"document_embedding_s{space.slot}_{level}_hnsw" in plan, plan
    for level in ("amber_strict", "red"):
        assert f"document_embedding_s{space.slot}_{level}_hnsw" not in plan
    assert "read_classification" not in "".join(
        line for line in plan.splitlines() if "Filter" in line)


# ---------------------------------------------------------------------------
# Over HTTP, both modes
# ---------------------------------------------------------------------------

@pytest.fixture
def stub():
    s = StubModel(dims=384)
    yield s
    s.close()


@pytest.fixture
def estate(conn, svc, stub, monkeypatch):
    """An AMBER reader, a holder of K1 at RED, a case both read, and
    documents of every kind the invariant is about; embedded in WORDING and
    (on this host, ceiling RED) in MEANING."""
    from noctornal_api import readiness
    monkeypatch.setattr(readiness, "blocking_failures", lambda _c: [])
    for name, value in meaning_env(stub).items():
        monkeypatch.setenv(name, value)
    owner = H.user(conn, PREFIX, roles=("ANALYST",))
    reader = H.user(conn, PREFIX, clearance="AMBER", roles=("ANALYST",))
    holder = H.user(conn, PREFIX, clearance="RED", keys=[K1], roles=("ANALYST",))
    case_id = H.case(conn, PREFIX, owner, classification="AMBER")
    for who in (reader, holder):
        H.assign(conn, case_id, who, "ANALYST", owner)
    open_src = H.source(conn, PREFIX, classification="AMBER")
    red_src = H.source(conn, PREFIX, classification="RED")
    docs = {
        "open": H.document(conn, PREFIX, src=open_src, body=BASE),
        "near": H.document(conn, PREFIX, src=open_src, body=BASE + " and a spare lens"),
        "red": H.document(conn, PREFIX, src=open_src, body=BASE + " red copy",
                          classification="RED"),
        "red_source": H.document(conn, PREFIX, src=red_src, body=BASE + " red source"),
        "boxed": H.document(conn, PREFIX, src=open_src, body=BASE + " boxed copy",
                            keys=[K1]),
    }
    _embed(conn, svc, list(docs.values()))
    msvc = _service(conn, E.configured())
    msvc.run_pass("MEANING", max_seconds=0)
    H.only_queue(conn, list(docs.values()))
    msvc.run_pass("MEANING", max_seconds=0)
    return {"reader": reader, "holder": holder, "case": case_id, "docs": docs,
            "client": H.app_client()}


@pytest.mark.parametrize("mode", ["wording", "meaning"])
def test_a_reader_gets_only_what_they_may_read_on_every_route(conn, estate, mode):
    cl, docs = estate["client"], estate["docs"]
    hidden = {str(docs[k]) for k in ("red", "red_source", "boxed")}
    reader = H.auth(conn, estate["reader"])
    r = cl.post(f"/api/v1/collection/documents/{docs['open']}/similar", headers=reader,
                json={"space": mode, "limit": 50})
    assert r.status_code == 200, r.text
    got = {h["id"] for h in r.json()["hits"]}
    assert str(docs["near"]) in got and not got & hidden
    r = cl.post(f"/api/v1/cases/{estate['case']}/search/documents/similar",
                headers=reader, json={"q": BASE[:400], "mode": mode, "limit": 50})
    assert r.status_code == 200, r.text
    assert not {h["id"] for h in r.json()["hits"]} & hidden
    coverage = r.json()["coverage"]
    # Collected documents are the deployment's, not the case's: count what
    # other suites left at the reader's labels (AMBER, no compartment), so
    # the figure proves this estate's hidden three are not in it
    # (2026-09-25).
    others = conn.execute(
        """SELECT count(*) FROM collect.document d
             JOIN collect.source s ON s.id = d.source_id
            WHERE d.purged_at IS NULL AND d.classification <= 'AMBER'
              AND s.classification <= 'AMBER' AND d.compartments = '{}'
              AND d.id <> ALL(%s::uuid[])""",
        ([str(v) for v in docs.values()],)).fetchone()[0]
    assert coverage["readable"] == 2 + others
    unknown = cl.post(f"/api/v1/collection/documents/{uuid4()}/similar", headers=reader,
                      json={"space": mode})
    for key in ("red", "red_source", "boxed"):
        refused = cl.post(f"/api/v1/collection/documents/{docs[key]}/similar",
                          headers=reader, json={"space": mode})
        assert (refused.status_code, refused.json()) == (unknown.status_code,
                                                         unknown.json()) == \
            (404, unknown.json())


def test_a_holder_gets_the_compartmented_document_in_wording(conn, estate):
    cl, docs = estate["client"], estate["docs"]
    holder = H.auth(conn, estate["holder"])
    r = cl.post(f"/api/v1/collection/documents/{docs['open']}/similar", headers=holder,
                json={"space": "wording", "limit": 50})
    got = {h["id"] for h in r.json()["hits"]}
    assert {str(docs["boxed"]), str(docs["red"]), str(docs["red_source"])} <= got
    # MEANING never had it: compartments go to no endpoint.
    assert conn.execute("SELECT status, reason FROM collect.document_embedding e "
                        "JOIN core.embedding_space s ON s.id = e.space_id "
                        "WHERE e.document_id = %s AND s.role = 'MEANING'",
                        (docs["boxed"],)).fetchone() == ("WITHHELD",
                                                         "compartmented_material")


def test_a_break_glass_grant_on_a_case_raises_no_document(conn, estate):
    cl, docs = estate["client"], estate["docs"]
    conn.execute(
        """INSERT INTO iam.break_glass (user_id, case_id, justification, expires_at,
               granted_classification)
           VALUES (%s, %s, 'an urgent threat to life needs the red material now', now()
                   + interval '1 hour', 'RED')""", (estate["reader"], estate["case"]))
    reader = H.auth(conn, estate["reader"])
    r = cl.post(f"/api/v1/collection/documents/{docs['open']}/similar", headers=reader,
                json={"space": "wording", "limit": 50})
    assert str(docs["red"]) not in {h["id"] for h in r.json()["hits"]}
    r = cl.post(f"/api/v1/cases/{estate['case']}/search/documents/similar",
                headers=reader, json={"q": BASE[:400], "mode": "wording", "limit": 50})
    assert str(docs["red"]) not in {h["id"] for h in r.json()["hits"]}


def test_coverage_is_cached_per_held_set(conn, svc):
    src = H.source(conn, PREFIX)
    docs = [H.document(conn, PREFIX, src=src, body=_variant(0)),
            H.document(conn, PREFIX, src=src, body=_variant(1), keys=[K1])]
    _embed(conn, svc, docs)
    slot = svc.active("WORDING").slot
    holder = svc.document_coverage(slot, clearance="RED", held=frozenset({K1}))
    other = svc.document_coverage(slot, clearance="RED", held=frozenset())
    assert holder["readable"] == other["readable"] + 1



def test_the_compartmented_branch_reads_only_rows_sharing_a_held_key(conn, svc):
    """The exact branch's compartment predicates are
    served by the GIN index on read_compartments, so on an estate where
    compartmented rows are many the branch fetches rows sharing a key the
    reader holds rather than every compartmented row at the reader's level.
    Asked of the predicates the branch carries (the statement is scanned for
    them): on a table of a few rows the planner reasonably prefers the
    primary key, which says nothing about a large estate."""
    src = H.source(conn, PREFIX)
    docs = [H.document(conn, PREFIX, src=src, body=_variant(i), keys=[K1])
            for i in range(3)]
    _embed(conn, svc, docs)
    space = svc.active("WORDING")
    statement = svc.candidate_sql(slot=space.slot, clearance="AMBER",
                                  held=frozenset({K1})).as_string(conn)
    assert "read_compartments <> '{}'::text[]" in statement
    assert "read_compartments <@ %(held)s::text[]" in statement
    with conn.transaction():
        conn.execute("SET LOCAL enable_seqscan = off")
        plan = "\n".join(r[0] for r in conn.execute(
            """EXPLAIN (COSTS OFF) SELECT document_id FROM collect.document_embedding
                WHERE read_compartments <> '{}'::text[]
                  AND read_compartments <@ %s::text[]""", ([K1],)).fetchall())
    assert "document_embedding_compartmented" in plan, plan
