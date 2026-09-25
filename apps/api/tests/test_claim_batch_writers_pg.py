"""A claim batch holds no lock while the model answers (F6.4, 2026-09-25).

This variant sits beside the document one in
test_embed_pass_meaning_pg.py: while a similar meaning batch of claims
waits on the model, an edit of the node a claim in the batch sits on, and
an audited edit of its case, each finish in under a second. A claim is
read in T1 without locks and re-read in T2, so the claim whose facts moved
during the send is left in the queue rather than written.

Against a stub model server on loopback that sleeps 3 s per request.
Env-gated on DATABASE_URL. Prefix `cbw-`.
"""
from __future__ import annotations

import os
import threading
import time

import pytest

import embedding_pg as H
from embedding_stub import StubModel, meaning_env
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "cbw-"


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL",
                 "NOCTORNAL_EGRESS_INTERNAL_CIDRS"):
        monkeypatch.delenv(name, raising=False)
    from noctornal_api import embeddings
    monkeypatch.setattr(embeddings, "_BULK_ENQUEUE",
                        {k: "SELECT %s" for k in embeddings.KINDS})


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


def _claim_row(conn, claim):
    return conn.execute("SELECT status FROM core.assertion_embedding WHERE "
                        "assertion_id = %s", (claim,)).fetchone()


def test_node_and_case_edits_never_wait_on_a_claim_batch(conn, stub):
    from noctornal_api.cases import CaseService
    from noctornal_api.db import connect
    from noctornal_api.embeddings import EmbeddingService
    from noctornal_api.graph import AssertionInput, GraphWriteService
    cfg = E.configured(meaning_env(stub))
    assert cfg.meaning_settings is not None, cfg.problems
    svc = EmbeddingService(conn, embedders=cfg, blocking_failures=lambda _c: [])
    assert svc.run_pass("MEANING", max_seconds=0).refused is None
    owner = H.user(conn, PREFIX)
    case_id = H.case(conn, PREFIX, owner)
    moved_node, moved = H.node_with_claim(conn, case_id, owner, label="cbw moved",
                                          rationale="a claim whose node is relabelled")
    edited_node, edited = H.node_with_claim(conn, case_id, owner, label="cbw edited",
                                            rationale="a claim whose node is renamed")
    stub.delay = 3.0
    before = len(stub.content_requests())
    results = {}

    def run():
        with connect() as other:
            results["pass"] = EmbeddingService(
                other, embedders=cfg, blocking_failures=lambda _c: []).run_pass(
                "MEANING", max_seconds=0)
    thread = threading.Thread(target=run)
    thread.start()
    for _ in range(300):
        if len(stub.content_requests()) > before:
            break
        time.sleep(0.05)
    else:
        raise AssertionError("the stub was never sent the claim batch")
    sent = " ".join(stub.content_requests()[-1]["body"]["input"])
    assert "relabelled" in sent and "renamed" in sent
    timings = {}
    with connect() as writer:
        writer.execute("SET lock_timeout = '2s'")
        started = time.monotonic()
        writer.execute("UPDATE core.node SET classification = 'RED' WHERE id = %s",
                       (moved_node,))
        timings["node relabel"] = time.monotonic() - started
        started = time.monotonic()
        GraphWriteService(writer).update_node(
            edited_node, case_id=case_id, label="cbw edited again",
            assertion=AssertionInput(basis="ANALYST_INFERENCE", created_by=owner,
                                     rationale="corrected the label"))
        timings["node edit"] = time.monotonic() - started
        started = time.monotonic()
        CaseService(writer).update_metadata(case_id, updated_by=owner,
                                            title="cbw similarity, retitled")
        timings["audited case edit"] = time.monotonic() - started
    assert all(t < 1.0 for t in timings.values()), timings
    thread.join(30)
    assert not thread.is_alive()
    # The relabelled claim's facts moved during the send: not written, and
    # queued again by its trigger or left for the next pass.
    assert _claim_row(conn, moved) is None
    assert results["pass"].busy >= 1
    assert _claim_row(conn, edited) is not None
