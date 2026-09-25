"""A retired index stays retired (F6.1 and F6.2, embeddings, 2026-09-25).

Only a role's very first index registers itself (rebuilds are operator
acts). When the only similar meaning index was retired, the next pass once
registered a new ACTIVE one by itself, audited as SYSTEM with the reason
'first similar meaning index', and sent every eligible text to the
endpoint again, while the console's retire
confirmation had promised the index was never used again. Now the pass
refuses with `retired` and sends nothing at all, not even the canary; the
status, the readiness rows, the script's exit code and the console say so;
and an administrator's Rebuild is what starts the next index.

Env-gated on DATABASE_URL. Prefix `ert-`.
"""
from __future__ import annotations

import os

import pytest

import embedding_pg as H
from embedding_stub import StubModel, meaning_env
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "ert-"


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


def _service(conn, cfg=None):
    from noctornal_api.embeddings import EmbeddingService
    return EmbeddingService(conn, embedders=cfg, blocking_failures=lambda _c: [])


def _meaning(conn, stub):
    cfg = E.configured(meaning_env(stub))
    assert cfg.meaning_settings is not None, cfg.problems
    return _service(conn, cfg)


def test_retiring_the_meaning_index_sends_nothing_until_a_rebuild(conn, stub):
    admin = H.user(conn, PREFIX, roles=("SYS_ADMIN",))
    svc = _meaning(conn, stub)
    svc.run_pass("MEANING", max_seconds=0)
    first = svc.active("MEANING")
    src = H.source(conn, PREFIX)
    docs = [H.document(conn, PREFIX, src=src, body=f"eligible post {i}") for i in range(3)]
    svc.run_pass("MEANING", max_seconds=0)
    svc.retire(first.id, actor_id=admin, reason="the operator stops similar meaning")
    mark = conn.execute("SELECT max(seq) FROM audit.event").fetchone()[0]
    before = len(stub.requests)
    for _ in range(2):
        result = svc.run_pass("MEANING", max_seconds=0)
        assert result.refused == "retired"
    assert len(stub.requests) == before                   # not even the canary
    assert svc.active("MEANING") is None and svc.building("MEANING") is None
    assert conn.execute("SELECT count(*) FROM audit.event WHERE action = "
                        "'EMBED_SPACE_REGISTERED' AND seq > %s",
                        (mark,)).fetchone()[0] == 0
    status = svc.status()["meaning"]
    assert status["state"] == "retired" and not status["similar_available"]
    assert "retired" in status["reason"] and "Administration, Embeddings" in status["reason"]
    # An administrator's Rebuild starts the next one, and only then is text
    # sent again.
    made = svc.request_rebuild("MEANING", actor_id=admin, reason="start it again")
    assert made.state == "ACTIVE" and made.id != first.id
    registered = conn.execute(
        "SELECT actor_id, actor_kind FROM audit.event WHERE action = "
        "'EMBED_SPACE_REGISTERED' AND object_id = %s", (made.id,)).fetchone()
    assert registered == (admin, "USER")
    del docs


def test_the_script_treats_a_retired_index_as_no_failure(conn, stub, monkeypatch,
                                                        capsys):
    import importlib.util
    admin = H.user(conn, PREFIX, roles=("SYS_ADMIN",))
    svc = _meaning(conn, stub)
    svc.run_pass("MEANING", max_seconds=0)
    svc.retire(svc.active("MEANING").id, actor_id=admin, reason="stop it for now")
    for name, value in meaning_env(stub).items():
        monkeypatch.setenv(name, value)
    path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "scripts",
                        "embed_pass.py")
    spec = importlib.util.spec_from_file_location("embed_pass_retire", path)
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    monkeypatch.setattr(script, "EmbeddingService",
                        lambda c, **kw: _service(c, E.configured()))
    before = len(stub.requests)
    code = script.main(["--role", "meaning", "--max-seconds", "0"])
    out = capsys.readouterr().out
    assert "refused=retired" in out and code == 0
    assert len(stub.requests) == before


def test_retiring_the_wording_index_is_not_undone_by_the_next_pass(conn):
    admin = H.user(conn, PREFIX, roles=("SYS_ADMIN",))
    svc = _service(conn)
    svc.ensure_spaces()
    first = svc.active("WORDING")
    svc.retire(first.id, actor_id=admin, reason="the operator retires it")
    notes = svc.ensure_spaces()
    assert notes == [{"role": "WORDING", "registered": False, "retired": True}]
    assert svc.active("WORDING") is None
    assert svc.run_pass("WORDING", max_seconds=0).refused == "retired"
    assert svc.status()["wording"]["state"] == "retired"
    from noctornal_api.readiness import _embedding_wording_current
    check = _embedding_wording_current(conn)
    assert not check.ok and "retired" in check.evidence
    made = svc.request_rebuild("WORDING", actor_id=admin, reason="start it again")
    assert made.state == "ACTIVE" and svc.active("WORDING").id == made.id


def test_a_first_index_still_registers_itself(conn, stub):
    svc = _service(conn)
    assert svc.ever_registered("WORDING") is False
    svc.ensure_spaces()
    assert svc.active("WORDING") is not None and svc.ever_registered("WORDING")
    meaning = _meaning(conn, stub)
    assert meaning.run_pass("MEANING", max_seconds=0).refused is None
    assert meaning.active("MEANING") is not None


def test_the_readiness_row_says_a_retired_meaning_index_waits_for_a_rebuild(
        conn, stub, monkeypatch):
    admin = H.user(conn, PREFIX, roles=("SYS_ADMIN",))
    svc = _meaning(conn, stub)
    svc.run_pass("MEANING", max_seconds=0)
    svc.retire(svc.active("MEANING").id, actor_id=admin, reason="stop it for now")
    for name, value in meaning_env(stub).items():
        monkeypatch.setenv(name, value)
    from noctornal_api.readiness import _embedding_meaning_endpoint
    check = _embedding_meaning_endpoint(conn)
    assert check.ok
    assert "was retired, and nothing is sent until an administrator rebuilds it" \
        in check.caveat
