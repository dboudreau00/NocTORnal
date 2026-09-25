"""The embedding index administration sees every item (S1, 2026-09-25).

Registering an index queues every document, exhibit and claim; activating
one first sweeps the queue of entries whose item is gone, by an anti-join.
Both used to run on the administrator's request connection. Under row-level
security an administrator on no case sees no exhibit and no claim, so a
registration queued none of them, and an activation's sweep read every
exhibit and claim of every case as gone and deleted their queue entries.
Each test below runs the route in production's shape
(NOCTORNAL_TEST_ASSUME_ROLE: the request connection is the request role,
bound, and the system connection the system role) and fails on the
request-connection version.

Gated like the other row-security tests. Account prefix `rlsemb-`; the
similarity state is reset before and after, as the embeddings suites do.
"""
from __future__ import annotations

import os

import pytest

import embedding_pg as H
import rls_support as s

pytestmark = s.GATED

PREFIX = "rlsemb-"


@pytest.fixture(autouse=True)
def _development(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    for name in ("NOCTORNAL_ENV", "NOCTORNAL_EGRESS_PROXY_URL") + tuple(
            n for n in os.environ if n.startswith("NOCTORNAL_EMBED_")):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")


@pytest.fixture
def owner():
    c = s.owner_conn()
    H.reset(c)
    yield c
    H.reset(c)
    s.cleanup(c, PREFIX)
    c.close()


@pytest.fixture
def scene(owner):
    admin = s.user(owner, "RED", prefix=PREFIX)
    s.grant_global(owner, admin, "SYS_ADMIN")
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    exhibit = s.exhibit(owner, case_id, boss)
    _, raw = s.session(owner, admin)
    return {"exhibit": exhibit, "auth": {"Authorization": f"Bearer {raw}"},
            "client": H.app_client()}


def _queued(owner, slot: int, exhibit) -> bool:
    return bool(owner.execute(
        "SELECT 1 FROM core.embedding_pending WHERE slot = %s AND kind = 'evidence' "
        "AND item_id = %s", (slot, exhibit)).fetchone())


def test_registering_an_index_queues_exhibits_its_administrator_cannot_see(owner, scene):
    r = scene["client"].post("/api/v1/admin/embeddings/spaces", headers=scene["auth"],
                             json={"role": "WORDING", "reason": "the first index"})
    assert r.status_code == 201, r.text
    slot = r.json()["slot"]
    assert _queued(owner, slot, scene["exhibit"]), (
        "an exhibit on a case the administrator is not on was never queued")


def test_activating_an_index_keeps_the_queue_its_administrator_cannot_see(owner, scene):
    from noctornal_api.embeddings import EmbeddingService

    space = EmbeddingService(owner, blocking_failures=lambda _c: []).register_space(
        "WORDING", state="BUILDING")
    assert space is not None and _queued(owner, space.slot, scene["exhibit"])
    r = scene["client"].post(
        f"/api/v1/admin/embeddings/spaces/{space.id}/activate",
        headers=scene["auth"], json={"reason": "it looks finished"})
    assert r.status_code == 409, r.text
    assert _queued(owner, space.slot, scene["exhibit"]), (
        "the sweep read the exhibit as gone and deleted its queue entry")
