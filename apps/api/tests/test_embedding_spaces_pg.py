"""Similarity spaces: registration, rebuild, activation, retirement and
clean-up (F6.1, embeddings, 2026-09-24).

A space is one embedder fingerprint; per role at most one ACTIVE and one
BUILDING, three slots, a slot held until the retired space's rows are
cleared. The first space of a role is active at once; a new built-in
version is rebuilt in a free slot while the old one keeps receiving new
items in its own version; the rebuild activates itself when nothing is
left to do, and the old space's rows are cleared in bounded chunks.

Env-gated on DATABASE_URL. Prefix `esp-`.
"""
from __future__ import annotations

import os

import psycopg
import pytest

import embedding_pg as H
from noctornal_api import embedders as E

pytestmark = pytest.mark.skipif(not os.environ.get("DATABASE_URL"),
                                reason="DATABASE_URL not set; gated")
PREFIX = "esp-"


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    H.reset(c)
    yield c
    H.cleanup(c, PREFIX)
    c.close()


def _service(conn, **kw):
    from noctornal_api.embeddings import EmbeddingService
    return EmbeddingService(conn, blocking_failures=lambda _c: [], **kw)


def _audits(conn, space_id) -> list[tuple]:
    return conn.execute("SELECT action, actor_kind, actor_id FROM audit.event "
                        "WHERE object_type = 'embedding_space' AND object_id = %s "
                        "ORDER BY seq", (space_id,)).fetchall()


class _Endpoint:
    """A MEANING space's embedder, without an endpoint: only what
    registration reads."""
    provider = "endpoint"
    model = "stub-embed"

    def fingerprint(self) -> dict:
        return {"provider": "endpoint", "model": self.model}


def _meaning(svc, state):
    return svc.register_space("MEANING", state=state, embedder=_Endpoint(),
                              canary=[1.0] + [0.0] * 767, dims_native=384,
                              registered_endpoint="127.0.0.1:9")


@pytest.fixture
def v2(monkeypatch):
    monkeypatch.setitem(E.BUILTIN_VERSIONS, H.V2Builtin.model, H.V2Builtin)
    monkeypatch.setattr(E, "BUILTIN_CURRENT", H.V2Builtin.model)
    return H.V2Builtin.model


def test_the_first_wording_space_is_active_at_once_and_audited_as_the_system(conn):
    svc = _service(conn)
    notes = svc.ensure_spaces()
    assert notes == [{"role": "WORDING", "registered": True, "no_free_slot": False}]
    space = svc.active("WORDING")
    assert space.state == "ACTIVE" and space.slot == 1 and space.enqueued_at is not None
    assert [a[:2] for a in _audits(conn, space.id)] == [
        ("EMBED_SPACE_REGISTERED", "SYSTEM"), ("EMBED_SPACE_ACTIVATED", "SYSTEM")]
    assert all(a[2] is None for a in _audits(conn, space.id))
    assert svc.ensure_spaces() == []


def test_the_transition_trigger_refuses_what_a_space_may_not_do(conn):
    svc = _service(conn)
    svc.ensure_spaces()
    space = svc.active("WORDING")
    for statement in (
            "UPDATE core.embedding_space SET state = 'BUILDING' WHERE id = %s",
            "UPDATE core.embedding_space SET model = 'other' WHERE id = %s",
            "UPDATE core.embedding_space SET fingerprint = '{}'::jsonb WHERE id = %s",
            "UPDATE core.embedding_space SET canary = array_fill(0.5, ARRAY[768])::vector "
            "WHERE id = %s",
            "UPDATE core.embedding_space SET slot = 2 WHERE id = %s"):
        with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
            conn.execute(statement, (space.id,))
    conn.execute("UPDATE core.embedding_space SET state = 'RETIRED', retired_at = now(), "
                 "retire_reason = 'test' WHERE id = %s", (space.id,))
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE core.embedding_space SET state = 'ACTIVE' WHERE id = %s",
                     (space.id,))
    conn.execute("UPDATE core.embedding_space SET rows_cleared_at = now() WHERE id = %s",
                 (space.id,))
    with pytest.raises(psycopg.errors.CheckViolation), conn.transaction():
        conn.execute("UPDATE core.embedding_space SET rows_cleared_at = now() - "
                     "interval '1 day' WHERE id = %s", (space.id,))


def test_one_active_and_one_building_per_role_and_a_slot_is_held(conn, v2):
    svc = _service(conn)
    first = svc.register_space("WORDING", state="ACTIVE",
                               embedder=E.HashedNgramEmbedder())
    assert svc.register_space("WORDING", state="ACTIVE") is None
    building = svc.register_space("WORDING")
    assert building.slot == 2 and svc.register_space("WORDING") is None
    with pytest.raises(psycopg.errors.UniqueViolation), conn.transaction():
        conn.execute(
            """INSERT INTO core.embedding_space (role, state, slot, provider, model,
                   fingerprint, fingerprint_sha256, dims_native, canary,
                   registered_endpoint)
               SELECT 'MEANING', 'BUILDING', 1, 'endpoint', 'x', '{}'::jsonb,
                      fingerprint_sha256, 768, canary, '127.0.0.1:9'
                 FROM core.embedding_space
                WHERE id = %s""", (first.id,))


def test_a_rebuild_fills_both_spaces_activates_itself_and_clears_the_old(conn, v2,
                                                                         monkeypatch):
    from noctornal_api import embeddings
    H.user(conn, PREFIX)
    src = H.source(conn, PREFIX)
    svc = _service(conn)
    old = svc.register_space("WORDING", state="ACTIVE", embedder=E.HashedNgramEmbedder())
    early = [H.document(conn, PREFIX, src=src, body=f"camera listing number {i} with "
                        f"light seals replaced and shutter checked") for i in range(5)]
    H.only_queue(conn, early)
    assert svc.run_pass("WORDING", max_seconds=0).embedded == 5
    notes = svc.ensure_spaces()
    new = svc.building("WORDING")
    assert new is not None and new.model == v2 and new.slot == 2, notes
    H.only_queue(conn, early)
    # A document stored mid-rebuild lands in BOTH the old and the new space.
    late = H.document(conn, PREFIX, src=src, body="a new listing stored during the "
                      "rebuild, rangefinder with case and strap")
    H.only_queue(conn, early + [late])
    queued = {r[0] for r in conn.execute(
        "SELECT slot FROM core.embedding_pending WHERE item_id = %s", (late,)).fetchall()}
    assert queued == {1, 2}
    monkeypatch.setattr(embeddings, "CLEAR_CHUNK", 2)
    result = svc.run_pass("WORDING", max_seconds=0)
    assert result.embedded == 7  # five into v2, the late one into both
    slots = {r[0] for r in conn.execute(
        "SELECT slot FROM collect.document_embedding WHERE document_id = %s",
        (late,)).fetchall()}
    assert slots == {1, 2}
    # Nothing left for v2: it activated itself; v1 retired, replaced by it.
    assert svc.active("WORDING").id == new.id
    retired = svc.space(old.id)
    assert retired.state == "RETIRED" and retired.retire_reason == f"replaced by {new.id}"
    assert ("EMBED_SPACE_RETIRED", "SYSTEM", None) in _audits(conn, old.id)
    # Clean-up in chunks of two, one chunk per kind per pass, then the slot frees.
    for _ in range(10):
        if svc.space(old.id).rows_cleared_at is not None:
            break
        svc.run_pass("WORDING", max_seconds=0)
    assert svc.space(old.id).rows_cleared_at is not None
    assert conn.execute("SELECT count(*) FROM collect.document_embedding "
                        "WHERE space_id = %s", (old.id,)).fetchone()[0] == 0
    assert svc._free_slot() == 1


def test_with_every_slot_held_a_rebuild_waits_and_says_so(conn, v2):
    from noctornal_api.readiness import _embedding_wording_current
    svc = _service(conn)
    old = svc.register_space("WORDING", state="ACTIVE", embedder=E.HashedNgramEmbedder())
    assert _meaning(svc, "ACTIVE") is not None
    assert _meaning(svc, "BUILDING") is not None
    notes = svc.ensure_spaces()
    assert notes == [{"role": "WORDING", "registered": False, "no_free_slot": True}]
    assert svc.run_pass("WORDING", max_seconds=0).no_free_slot == 1
    check = _embedding_wording_current(conn)
    assert check.ok and "no slot is free" in check.caveat
    assert old.model in check.evidence
