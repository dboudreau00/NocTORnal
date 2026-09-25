"""Row-level security on the rest of the case record (S1, 2026-09-25).

0123 puts selectors, the claim and exhibit vectors, a merge's record of
the ties it re-pointed, tombstones, tags and their assignments, and the
two-person requests under policy. Run as the request role, bound by a real
session's proof, with the fixtures seeded as the owner:

- a merge re-points every tie, a tie above the person merging included, and
  answers, and lists in the history, only the ties its reader can see
  (the conservative reading of a count of hidden ties: withheld, never
  announced);
- a tag assignment on an entity above the reader is hidden, and a case's
  tags and tombstones stay in their case, while the global taxonomy and a
  deployment-wide two-person request are read by every bound user;
- a write of a tombstone by the request role is refused (read only).

Gated like the other row-security tests. Account prefix `rlsleft-`.
"""
from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "rlsleft-"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    with c.transaction():
        c.execute(f"DELETE FROM core.tag_assignment WHERE tag_id IN "
                  f"(SELECT id FROM core.tag WHERE case_id IN {cases} "
                  f"OR name LIKE '{PREFIX}%')")
        c.execute(f"DELETE FROM core.tag WHERE case_id IN {cases} OR name LIKE '{PREFIX}%'")
        c.execute(f"DELETE FROM core.node_merge_edge WHERE merge_id IN "
                  f"(SELECT id FROM core.node_merge WHERE case_id IN {cases})")
        c.execute(f"UPDATE core.node SET merged_into_id = NULL WHERE case_id IN {cases}")
        c.execute(f"DELETE FROM core.node_merge WHERE case_id IN {cases}")
        c.execute(f"DELETE FROM core.approval_request WHERE requested_by IN {users}")
    s.cleanup(c, PREFIX)
    c.close()


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


def _ids(conn, sql: str, params=None) -> set:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


def test_a_merge_repoints_every_tie_and_counts_only_the_readers(owner, client):
    lead = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    case_id = s.case(owner, boss)
    s.assign(owner, case_id, lead, "CASE_OWNER")
    source = s.node(owner, case_id, boss, "rlsleft duplicate")
    target = s.node(owner, case_id, boss, "rlsleft keeper")
    other = s.node(owner, case_id, boss, "rlsleft contact")
    secret = s.node(owner, case_id, boss, "rlsleft secret", "RED")
    s.edge(owner, case_id, boss, source, other)
    hidden = s.edge(owner, case_id, boss, source, secret, "RED")
    r = client.post(f"/api/v1/cases/{case_id}/merges", headers=_auth(owner, lead),
                    json={"source_node_id": str(source), "target_node_id": str(target),
                          "reason": "the same persona under two handles"})
    assert r.status_code == 201, r.text
    assert r.json()["edges_repointed"] == 1, "the RED tie is not the reader's to count"
    moved = owner.execute("SELECT src_node_id FROM core.edge WHERE id = %s",
                          (hidden,)).fetchone()[0]
    assert moved == target, "the tie above the person merging was re-pointed all the same"
    listed = client.get(f"/api/v1/cases/{case_id}/merges", headers=_auth(owner, lead))
    assert listed.status_code == 200, listed.text
    assert [m["edges_repointed"] for m in listed.json()["merges"]] == [1]
    assert s.count(owner, "SELECT count(*) FROM core.node_merge_edge e "
                          "JOIN core.node_merge m ON m.id = e.merge_id "
                          "WHERE m.case_id = %s", (case_id,)) == 2


def test_tags_tombstones_and_requests_keep_to_their_case(owner):
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    mine, other = s.case(owner, boss), s.case(owner, boss)
    s.assign(owner, mine, analyst)
    seen = s.node(owner, mine, boss, "rlsleft seen")
    unseen = s.node(owner, mine, boss, "rlsleft unseen", "RED")

    def tag(case_id):
        return owner.execute(
            "INSERT INTO core.tag (case_id, namespace, name) VALUES (%s, 'rls', %s) "
            "RETURNING id", (case_id, f"{PREFIX}{uuid4().hex[:6]}")).fetchone()[0]

    local, foreign, shared = tag(mine), tag(other), tag(None)
    for node in (seen, unseen):
        owner.execute("INSERT INTO core.tag_assignment (tag_id, node_id, assigned_by) "
                      "VALUES (%s, %s, %s)", (local, node, boss))
    tombs = [owner.execute(
        """INSERT INTO core.purge_tombstone (case_id, object_type, object_count,
                                             authority, purged_by, storage_outcome)
           VALUES (%s, 'evidence', 1, 'rls test authority', %s, 'NOT_APPLICABLE')
           RETURNING id""", (case_id, boss)).fetchone()[0] for case_id in (mine, other)]
    requests = [owner.execute(
        """INSERT INTO core.approval_request (case_id, operation, payload, payload_hash,
                                              justification, requested_by, expires_at)
           VALUES (%s, 'node.merge', '{}', %s, 'rls test request', %s,
                   now() + interval '1 hour') RETURNING id""",
        (case_id, uuid4().bytes, boss)).fetchone()[0] for case_id in (mine, other, None)]
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        assert _ids(app, "SELECT id FROM core.tag WHERE id = ANY(%s)",
                    ([local, foreign, shared],)) == {local, shared}
        assert _ids(app, "SELECT node_id FROM core.tag_assignment WHERE tag_id = %s",
                    (local,)) == {seen}
        assert _ids(app, "SELECT id FROM core.purge_tombstone WHERE id = ANY(%s)",
                    (tombs,)) == {tombs[0]}
        assert _ids(app, "SELECT id FROM core.approval_request WHERE id = ANY(%s)",
                    (requests,)) == {requests[0], requests[2]}
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO core.purge_tombstone (case_id, object_type, object_count,
                                                     authority, purged_by, storage_outcome)
                   VALUES (%s, 'evidence', 1, 'forged', %s, 'NOT_APPLICABLE')""",
                (mine, analyst))
    finally:
        app.close()
    with owner.transaction():
        owner.execute("ALTER TABLE core.purge_tombstone DISABLE TRIGGER USER")
        owner.execute("DELETE FROM core.purge_tombstone WHERE id = ANY(%s)", (tombs,))
        owner.execute("ALTER TABLE core.purge_tombstone ENABLE TRIGGER USER")
