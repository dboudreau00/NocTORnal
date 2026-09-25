"""The two similarity rows of the readiness register (F6.1 and F6.2,
2026-09-24).

Neither is blocking; both open Administration, Embeddings. Neither carries
a count or a proportion: the register is read by administrators who need
not read collected documents. The meaning row reads the pass's stored
canary result and sends the canary again only when that is over an hour
old, never while a blocking check fails and never outside this host
without AUTHORITY.

Env-gated on DATABASE_URL. Prefix `erd-`.
"""
from __future__ import annotations

import os
import re

import pytest

import embedding_pg as H
from embedding_stub import StubModel, meaning_env
from noctornal_api import embedders as E
from noctornal_api import readiness

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "erd-"


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL") + tuple(
            n for n in os.environ if n.startswith("NOCTORNAL_EMBED_")):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _no_backfill(monkeypatch):
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


def _service(conn, cfg=None):
    from noctornal_api.embeddings import EmbeddingService
    return EmbeddingService(conn, embedders=cfg, blocking_failures=lambda _c: [])


def _row(conn, name):
    return next(c for c in readiness.run_checks(conn) if c.check == name)


def test_both_rows_are_registered_and_not_blocking():
    assert "embedding_wording_current" in readiness.CHECK_NAMES
    assert "embedding_meaning_endpoint" in readiness.CHECK_NAMES
    for name in ("embedding_wording_current", "embedding_meaning_endpoint"):
        assert name not in readiness.BLOCKING_CHECKS
        assert readiness.UI_TARGETS[name] == "admin/embeddings"


def test_wording_off_passes_with_the_caveat(conn, monkeypatch):
    monkeypatch.setenv(E.WORDING_ENV, "off")
    row = _row(conn, "embedding_wording_current")
    assert row.ok and "Similar wording is off by configuration" in row.caveat
    assert row.ui_target == "admin/embeddings"


def test_no_wording_index_fails_with_the_action(conn):
    row = _row(conn, "embedding_wording_current")
    assert not row.ok and "embed_pass.py" in row.action


def test_a_current_wording_index_passes_with_evidence_and_no_count(conn):
    _service(conn).ensure_spaces()
    src = H.source(conn, PREFIX)
    for i in range(3):
        H.document(conn, PREFIX, src=src, body=f"counted item {i}")
    row = _row(conn, "embedding_wording_current")
    assert row.ok, row
    assert re.fullmatch(r"Model hashed-ngrams-v1 in slot \d, active since "
                        r"\d{4}-\d\d-\d\d \d\d:\d\d UTC\.", row.evidence)


def test_a_canary_that_drifted_fails(conn, monkeypatch):
    _service(conn).ensure_spaces()

    class Drifted(E.HashedNgramEmbedder):
        def embed_one(self, text):
            out = super().embed_one(text + " drift")
            return out
    monkeypatch.setattr(E, "builtin", lambda *a, **k: Drifted())
    row = _row(conn, "embedding_wording_current")
    assert not row.ok and "no longer reproduces its own canary" in row.evidence


def test_a_failure_older_than_an_hour_fails(conn):
    svc = _service(conn)
    svc.ensure_spaces()
    doc = H.document(conn, PREFIX, src=H.source(conn, PREFIX), body="failing item")
    space = svc.active("WORDING")
    conn.execute(
        """INSERT INTO collect.document_embedding (document_id, slot, space_id, status,
               reason, read_classification, first_failed_at, next_attempt_at)
           VALUES (%s, %s, %s, 'FAILED', 'x', 'CLEAR', now() - interval '2 hours',
                   now() + interval '1 hour')""", (doc, space.slot, space.id))
    row = _row(conn, "embedding_wording_current")
    assert not row.ok and "failed to embed for over an hour" in row.evidence
    conn.execute("UPDATE collect.document_embedding SET first_failed_at = now() "
                 "WHERE document_id = %s", (doc,))
    assert _row(conn, "embedding_wording_current").ok


def test_meaning_unset_passes_with_the_exact_sentence(conn):
    row = _row(conn, "embedding_meaning_endpoint")
    assert row.ok and row.evidence == (
        "No model endpoint is configured, so no case text is sent anywhere to be "
        "embedded. Similar meaning is off.")


@pytest.fixture
def stub():
    s = StubModel(dims=384)
    yield s
    s.close()


def _configure(monkeypatch, env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)


def test_outside_this_host_without_authority_fails_and_sends_nothing(conn, stub, monkeypatch):
    _configure(monkeypatch, meaning_env(stub, local=False))
    row = _row(conn, "embedding_meaning_endpoint")
    assert not row.ok and "NOCTORNAL_EMBED_MEANING_AUTHORITY" in row.action
    assert stub.requests == []


def test_an_endpoint_no_route_reaches_fails_with_the_action(conn, stub, monkeypatch):
    _configure(monkeypatch, meaning_env(stub))

    def unrouted(*_a, **_k):
        raise E.EndpointError("unrouted", "no route", request_sent=False)
    monkeypatch.setattr(E, "open_endpoint", unrouted)
    row = _row(conn, "embedding_meaning_endpoint")
    assert not row.ok
    assert "create the integration route embeddings" in row.action
    assert f"127.0.0.1:{stub.port}" in row.action


def test_a_drifted_model_fails_and_a_fresh_result_is_not_probed_again(conn, stub,
                                                                     monkeypatch):
    env = meaning_env(stub, **{E.KEY_ENV: "sk-readiness-secret-001"})
    _configure(monkeypatch, env)
    # The register is otherwise red on a development clone, and the row
    # never probes while a blocking check fails.
    monkeypatch.setattr(readiness, "blocking_failures", lambda _c: [])
    svc = _service(conn, E.configured(env))
    svc.run_pass("MEANING", max_seconds=0)
    space = svc.active("MEANING")
    row = _row(conn, "embedding_meaning_endpoint")
    assert row.ok, row
    sent = len(stub.requests)
    _row(conn, "embedding_meaning_endpoint")
    assert len(stub.requests) == sent        # fresh: read, not probed
    stub.drift = True
    conn.execute("UPDATE core.embedding_space SET canary_checked_at = now() - "
                 "interval '2 hours' WHERE id = %s", (space.id,))
    row = _row(conn, "embedding_meaning_endpoint")
    assert not row.ok and "has changed since the index was built" in row.evidence
    assert "Rebuild" in row.action or "rebuild" in row.action
    for c in readiness.run_checks(conn):
        assert "sk-readiness" not in c.evidence + c.action + c.caveat
