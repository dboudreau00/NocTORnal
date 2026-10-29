"""The answer to an out-of-schedule purge covers only what the caller may see.

A caller with the purge permission on a case can name, and have approved by
somebody else, an exhibit classified above their own clearance. When the
store refuses that exhibit under a retention lock, its warning names the
storage key, which carries the exhibit's SHA-256. The answer is drawn over
the exhibits the caller may know of, as the scheduled real run's is, so the
key, the counts and the tombstone id of the hidden exhibit stay out of it.
The tombstone itself still records the whole destruction.

Accounts `g44t-*`; the object store is `evidence_retention_support.VersionedStore`.
"""
from __future__ import annotations

from dataclasses import replace

import pytest

import evidence_retention_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

AUTHORITY = "out of schedule destruction review"


class _LockingStore(g.VersionedStore):
    """A store whose retention lock holds on the keys it is told of."""

    def __init__(self) -> None:
        super().__init__()
        self.locked_keys: set[str] = set()

    def delete_all_versions(self, key):
        from noctornal_api.evidence import VersionedDeleteResult
        if key in self.locked_keys:
            return VersionedDeleteResult(
                key=key, versions_seen=1, versions_removed=0, versions_locked=1)
        return super().delete_all_versions(key)


@pytest.fixture
def store(monkeypatch):
    st = _LockingStore()
    import noctornal_api.http.routers.governance as governance
    monkeypatch.setattr(governance, "EvidenceStorage", lambda: st)
    return st


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter

    limits = dict(LIMITS)
    limits["retention.destroy"] = replace(
        limits["retention.destroy"], quota=1000, burst=1000)
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(now=lambda: 1000.0),
                                    limits=limits)
    return TestClient(app, raise_server_exceptions=False)


def _approved(conn, case_id, requester, approver, evidence_ids):
    from noctornal_api.approvals import ApprovalService

    payload = {"case_id": str(case_id),
               "evidence_ids": [str(i) for i in evidence_ids],
               "authority": AUTHORITY}
    request = ApprovalService(conn).request(
        operation="evidence.purge", case_id=case_id, payload=payload,
        justification="a written order to destroy these exhibits early",
        requested_by=requester, element_classification="RED")
    ApprovalService(conn).decide(request.id, decided_by=approver, approve=True)
    return request.id


def _purge(client, conn, caller, request_id, case_id, evidence_ids):
    return client.post(
        "/api/v1/retention/purge/out-of-schedule",
        headers=g.token(conn, caller),
        json={"approval_request_id": str(request_id),
              "case_id": str(case_id),
              "evidence_ids": [str(i) for i in evidence_ids],
              "authority": AUTHORITY})


def test_a_locked_exhibit_above_the_caller_is_not_in_the_answer(
        conn, store, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, lead, "CASE_OWNER")
    hidden, _data = g.lodge(conn, store, case_id, boss,
                            classification="RED", title="dpto hidden")
    hidden_key = g.evidence_row(conn, hidden.evidence_id)[0]
    store.locked_keys.add(hidden_key)
    request_id = _approved(conn, case_id, lead, boss, [hidden.evidence_id])

    response = _purge(client, conn, lead, request_id, case_id,
                      [hidden.evidence_id])

    assert response.status_code == 200, response.text
    body = response.json()
    assert hidden_key not in response.text
    assert hidden_key.rsplit("/", 1)[-1] not in response.text
    assert body["evidence_purged"] == 0
    assert body["storage_locked"] == 0
    assert body["storage_failed"] == 0
    assert body["tombstones"] == []
    # The record of destruction still counts the exhibit.
    assert conn.execute(
        """SELECT count(*) FROM core.purge_tombstone
            WHERE approval_request_id = %s""", (request_id,)).fetchone()[0] == 1


def test_a_caller_cleared_for_the_exhibit_is_still_told_its_key(
        conn, store, client):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    other = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, other, "CASE_OWNER")
    seen, _data = g.lodge(conn, store, case_id, boss,
                          classification="RED", title="dpto seen")
    seen_key = g.evidence_row(conn, seen.evidence_id)[0]
    store.locked_keys.add(seen_key)
    request_id = _approved(conn, case_id, boss, other, [seen.evidence_id])

    response = _purge(client, conn, boss, request_id, case_id,
                      [seen.evidence_id])

    assert response.status_code == 200, response.text
    body = response.json()
    assert seen_key in response.text
    assert body["evidence_purged"] == 1
    assert body["storage_locked"] == 1
    assert len(body["tombstones"]) == 1
    assert any("NOT marked purged" in w and "1 of 1 exhibit" in w
               for w in body["warnings"])
