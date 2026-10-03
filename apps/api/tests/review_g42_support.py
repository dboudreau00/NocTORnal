"""Shared fixtures for the beta review's graph-visibility fixes (2026-10-03).

Every test of this unit runs through the real route as the REQUEST ROLE
(`NOCTORNAL_TEST_ASSUME_ROLE`, as `test_rls_http_pg` does) and seeds as the
owner, so what a reader is told is what production tells them. Accounts are
`g42t-`; no other suite's teardown pattern matches them.

Gated on NOCTORNAL_APP_DB_ROLE, as every row security test is.
"""
from __future__ import annotations

from uuid import UUID, uuid4

from fastapi.testclient import TestClient

import rls_support as s

PREFIX = "g42t-"
GATED = s.GATED

#: A claim every graph write is grounded in (invariant 1).
CLAIM = {"basis": "DIRECT_OBSERVATION", "reliability": "A", "credibility": "1",
         "confidence": "HIGH"}


def make_owner(monkeypatch):
    """The owner connection, with request connections assuming the request
    role and system connections the system role."""
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    return s.owner_conn()


def make_client() -> TestClient:
    """A client over a fresh app with its own in-process limiter, so the
    merge limit of one test never meets another's."""
    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app, raise_server_exceptions=False)


def auth(owner, uid: UUID) -> dict:
    _, raw = s.session(owner, uid)
    return {"Authorization": f"Bearer {raw}"}


class World:
    """One AMBER case: a RED owner (`boss`), an AMBER case owner (`lead`),
    an AMBER analyst and an AMBER read-only member."""

    def __init__(self, owner, withheld: str = "COUNT"):
        self.owner = owner
        self.boss = s.user(owner, "RED", prefix=PREFIX)
        self.lead = s.user(owner, "AMBER", prefix=PREFIX)
        self.analyst = s.user(owner, "AMBER", prefix=PREFIX)
        self.reader = s.user(owner, "AMBER", prefix=PREFIX)
        self.case_id = s.case(owner, self.boss)
        s.assign(owner, self.case_id, self.boss, "CASE_OWNER")
        s.assign(owner, self.case_id, self.lead, "CASE_OWNER")
        s.assign(owner, self.case_id, self.analyst, "ANALYST")
        s.assign(owner, self.case_id, self.reader, "READ_ONLY")
        self.disclose(withheld)

    def disclose(self, mode: str) -> None:
        self.owner.execute(
            'UPDATE core."case" SET withheld_disclosure = %s WHERE id = %s',
            (mode, self.case_id))

    def node(self, label: str, classification: str = "AMBER",
             actor: UUID | None = None) -> UUID:
        return s.node(self.owner, self.case_id, actor or self.boss, label,
                      classification)

    def edge(self, src: UUID, dst: UUID, classification: str = "AMBER") -> UUID:
        return s.edge(self.owner, self.case_id, self.boss, src, dst,
                      classification)

    def url(self, tail: str) -> str:
        return f"/api/v1/cases/{self.case_id}{tail}"

    def headers(self, uid: UUID) -> dict:
        return auth(self.owner, uid)


def cleanup(owner) -> None:
    """What `rls_support.cleanup` does not know about: merges and what they
    moved, selectors, approvals, tags, working sets, and the communications
    rows this unit seeds. Append-only rows (audit, custody) stay."""
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    for statement in (
        f"DELETE FROM core.node_merge_edge WHERE merge_id IN "
        f"(SELECT id FROM core.node_merge WHERE case_id IN {cases})",
        f"DELETE FROM core.node_merge WHERE case_id IN {cases}",
        f"DELETE FROM core.selector WHERE case_id IN {cases}",
        f"DELETE FROM core.approval_request WHERE case_id IN {cases}",
        f"DELETE FROM core.tag_assignment WHERE tag_id IN "
        f"(SELECT id FROM core.tag WHERE case_id IN {cases})",
        f"DELETE FROM core.tag WHERE case_id IN {cases}",
        f"DELETE FROM comms.channel_binding WHERE case_id IN {cases}",
        f"DELETE FROM comms.contact_block_entry WHERE block_id IN "
        f"(SELECT id FROM comms.contact_block WHERE case_id IN {cases})",
        f"DELETE FROM comms.contact_block WHERE case_id IN {cases}",
        f"DELETE FROM comms.participant WHERE conversation_id IN "
        f"(SELECT id FROM comms.conversation WHERE case_id IN {cases})",
        f"DELETE FROM comms.conversation WHERE case_id IN {cases}",
        f"DELETE FROM notify.notification WHERE case_id IN {cases}",
    ):
        try:
            with owner.transaction():
                owner.execute(statement)
        except Exception:  # noqa: BLE001
            pass
    s.cleanup(owner, prefix=PREFIX)


def random_id() -> UUID:
    return uuid4()


def answer(response) -> tuple[int, str | None]:
    """What a caller is told: the status and the sentence, nothing else, so
    two answers compare equal exactly when they cannot be told apart."""
    try:
        detail = response.json().get("detail")
    except Exception:  # noqa: BLE001
        detail = None
    return response.status_code, detail if isinstance(detail, str) else None
