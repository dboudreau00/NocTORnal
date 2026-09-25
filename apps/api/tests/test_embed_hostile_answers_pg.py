"""A hostile or broken model endpoint cannot wedge the pass (F6.2,
2026-09-25).

The probe: an answer carrying a 400-digit integer raised
OverflowError in the parser, and a body nested 100,000 deep raised
RecursionError in the JSON decoder. Neither was caught, so the pass ended
after EMBED_BATCH_SENT with no FAILED row and no backoff: every pass sent
and audited the same newest-first batch again and never reached the rest
of the queue, and /similar answered 500. Now such an answer fails its
batch like any bad response (FAILED endpoint_bad_response, backoff,
EMBED_BATCH_FAILED), anything else that escapes the embedder fails the
batch as embed_error, and a route answers with a sentence.

Against a stub model server on loopback, through the real development
route. Env-gated on DATABASE_URL. Prefix `eha-`.
"""
from __future__ import annotations

import os

import pytest

import embedding_pg as H
from embedding_stub import StubModel, meaning_env
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "eha-"


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL",
                 "NOCTORNAL_EGRESS_INTERNAL_CIDRS") + tuple(
            n for n in os.environ if n.startswith("NOCTORNAL_EMBED_")):
        monkeypatch.delenv(name, raising=False)
    from noctornal_api import embeddings, readiness
    monkeypatch.setattr(readiness, "blocking_failures", lambda _c: [])
    monkeypatch.setattr(embeddings, "_BULK_ENQUEUE",
                        {k: "SELECT %s" for k in embeddings.KINDS})
    embeddings._STATUS_CACHE.clear()
    embeddings._COVERAGE_CACHE.clear()


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    H.reset(c)
    yield c
    H.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def stub():
    s = StubModel(dims=384)
    yield s
    s.close()


def _service(conn, stub, **env):
    from noctornal_api.embeddings import EmbeddingService
    cfg = E.configured(meaning_env(stub, **env))
    assert cfg.meaning_settings is not None, cfg.problems
    return EmbeddingService(conn, embedders=cfg, blocking_failures=lambda _c: [])


def _row(conn, doc):
    return conn.execute("SELECT status, reason, next_attempt_at > now() FROM "
                        "collect.document_embedding WHERE document_id = %s",
                        (doc,)).fetchone()


def _actions(conn, doc) -> list[str]:
    return [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE action LIKE 'EMBED_BATCH_%%' "
        "AND (detail->'items' ? %s OR detail->>'batch_id' IN ("
        "  SELECT detail->>'batch_id' FROM audit.event WHERE action = "
        "  'EMBED_BATCH_SENT' AND detail->'items' ? %s)) ORDER BY seq",
        (str(doc), str(doc))).fetchall()]


@pytest.mark.parametrize("mode", ["bigint", "deep", "zeros", "text_value"])
def test_a_hostile_answer_fails_its_batch_once_and_the_queue_moves_on(conn, stub, mode):
    svc = _service(conn, stub)
    assert svc.run_pass("MEANING", max_seconds=0).refused is None
    src = H.source(conn, PREFIX)
    doc = H.document(conn, PREFIX, src=src, body="a post the endpoint answers badly")
    stub.mode = mode
    result = svc.run_pass("MEANING", max_seconds=0)          # returns, never raises
    assert result.failed == 1 and result.embedded == 0
    status, reason, backing_off = _row(conn, doc)
    assert (status, reason, backing_off) == ("FAILED", "endpoint_bad_response", True)
    assert _actions(conn, doc) == ["EMBED_BATCH_SENT", "EMBED_BATCH_FAILED"]
    assert conn.execute("SELECT count(*) FROM core.embedding_pending WHERE item_id = %s",
                        (doc,)).fetchone()[0] == 0
    # The next pass does not send it again, and a newer item gets through.
    stub.mode = "ok"
    sent = len(stub.content_requests())
    newer = H.document(conn, PREFIX, src=src, body="a newer post the endpoint answers")
    result = svc.run_pass("MEANING", max_seconds=0)
    assert result.embedded == 1 and _row(conn, newer)[0] == "EMBEDDED"
    bodies = [t for r in stub.content_requests()[sent:] for t in r["body"]["input"]]
    assert len(bodies) == 1 and bodies[0].endswith("\na newer post the endpoint answers")
    assert _actions(conn, doc) == ["EMBED_BATCH_SENT", "EMBED_BATCH_FAILED"]


def test_anything_else_escaping_the_embedder_fails_the_batch_as_embed_error(
        conn, stub, monkeypatch):
    svc = _service(conn, stub)
    svc.run_pass("MEANING", max_seconds=0)
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body="a post")

    def broken(self, endpoint, texts, **_kw):
        raise ZeroDivisionError("a bug on this host")
    monkeypatch.setattr(E.EndpointEmbedder, "embed_via", broken)
    result = svc.run_pass("MEANING", max_seconds=0)
    assert result.failed == 1
    assert _row(conn, doc)[:2] == ("FAILED", "embed_error")
    detail = conn.execute("SELECT detail FROM audit.event WHERE action = "
                          "'EMBED_BATCH_FAILED' ORDER BY seq DESC LIMIT 1").fetchone()[0]
    assert detail["reason"] == "embed_error"


def test_the_built_in_embedder_failing_does_not_wedge_the_pass(conn, monkeypatch):
    from noctornal_api.embeddings import EmbeddingService
    svc = EmbeddingService(conn, blocking_failures=lambda _c: [])
    svc.ensure_spaces()
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body="a post to embed")
    H.only_queue(conn, [doc])

    def broken(self, texts, **_kw):
        raise ValueError("an input the built-in embedder cannot handle")
    monkeypatch.setattr(E.HashedNgramEmbedder, "embed", broken)
    result = svc.run_pass("WORDING", max_seconds=0)
    assert result.failed == 1
    assert conn.execute("SELECT status, reason FROM collect.document_embedding "
                        "WHERE document_id = %s", (doc,)).fetchone() == ("FAILED",
                                                                         "embed_error")


def test_a_hostile_canary_registers_nothing(conn, stub):
    svc = _service(conn, stub)
    stub.spare_canary = False
    stub.mode = "bigint"
    result = svc.run_pass("MEANING", max_seconds=0)
    assert result.refused == "endpoint_bad_response"
    assert svc.active("MEANING") is None
    stub.mode = "deep"
    assert svc.run_pass("MEANING", max_seconds=0).refused == "endpoint_bad_response"


@pytest.fixture
def routes(conn, stub, monkeypatch):
    for name, value in meaning_env(stub).items():
        monkeypatch.setenv(name, value)
    from noctornal_api.embeddings import EmbeddingService
    EmbeddingService(conn, blocking_failures=lambda _c: []).run_pass(
        "MEANING", max_seconds=0)
    owner = H.user(conn, PREFIX, roles=("ANALYST",))
    return {"owner": owner, "case": H.case(conn, PREFIX, owner),
            "src": H.source(conn, PREFIX), "client": H.app_client()}


@pytest.mark.parametrize("mode", ["bigint", "deep"])
def test_a_route_answers_a_hostile_answer_with_a_sentence(conn, stub, routes, mode):
    stub.mode = mode
    cl, auth = routes["client"], H.auth(conn, routes["owner"])
    doc = H.document(conn, PREFIX, src=routes["src"], body="a post compared on demand")
    r = cl.post(f"/api/v1/collection/documents/{doc}/similar", headers=auth,
                json={"space": "meaning"})
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == ("Not in the similar meaning index: the model endpoint "
                                  "answered with something that is not a set of vectors.")
    r = cl.post(f"/api/v1/cases/{routes['case']}/search/documents/similar", headers=auth,
                json={"q": "which posts are about shutters", "mode": "meaning"})
    assert r.status_code == 409, r.text
    assert r.json()["detail"] == ("Similar meaning could not ask the model endpoint: the "
                                  "model endpoint answered with something that is not a "
                                  "set of vectors.")
