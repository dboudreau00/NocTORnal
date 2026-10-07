"""Shared fixtures for the 2026-10-03 graph review tests.

The five findings this covers (claims mutable by the request role, a
retracted correction that stays in force, selector index drift, URL
credentials in selectors, and `valid_to` that could not be set) all need a
case with analysts at different clearances, a client over the real app, and
a cleanup that also lets go of what `rls_support.cleanup` does not know
about: the selector index, proposals and the documents a capture made.

Each test file passes its own e-mail prefix, so one file's teardown never
removes another's rows.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import UUID

import rls_support as s

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

#: The four grading fields every claim in a request body must carry.
GRADE = {"basis": "DIRECT_OBSERVATION", "reliability": "A", "credibility": "1",
         "confidence": "HIGH"}


def grade(rationale: str = "recorded by a test", **more) -> dict:
    return {**GRADE, "rationale": rationale, **more}


def make_client():
    from fastapi.testclient import TestClient

    from noctornal_api.http.app import create_app
    from noctornal_api.ratelimit import LIMITS, InProcessBackend, RateLimiter
    app = create_app()
    app.state.limiter = RateLimiter(InProcessBackend(), limits=dict(LIMITS))
    return TestClient(app)


def auth(conn, uid: UUID) -> dict:
    _, raw = s.session(conn, uid)
    return {"Authorization": f"Bearer {raw}"}


def bound(conn, uid: UUID):
    """A connection as the request role, bound to `uid`'s session."""
    _, raw = s.session(conn, uid)
    return s.app_conn(raw)


def worker():
    """A connection as the system role, from the owner's own login."""
    c = s.owner_conn()
    c.execute(f"SET ROLE {s.WORKER_ROLE}")
    return c


def now() -> datetime:
    return datetime.now(timezone.utc)


def cleanup(conn, prefix: str) -> None:
    """Everything a test of this group made. The selector index, the
    proposals and the documents of a capture go first: `s.cleanup` does not
    know them and a node cannot be deleted while a selector row names it."""
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{prefix}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    docs = [r[0] for r in conn.execute(
        f"SELECT DISTINCT document_id FROM collect.proposal "
        f"WHERE case_id IN {cases} AND document_id IS NOT NULL").fetchall()]
    with conn.transaction():
        conn.execute(f"DELETE FROM core.node_merge_edge WHERE merge_id IN "
                     f"(SELECT id FROM core.node_merge WHERE case_id IN {cases})")
        conn.execute(f"UPDATE core.node SET merged_into_id = NULL "
                     f"WHERE case_id IN {cases}")
        conn.execute(f"DELETE FROM core.node_merge WHERE case_id IN {cases}")
        conn.execute(f"DELETE FROM collect.proposal WHERE case_id IN {cases}")
        conn.execute(f"DELETE FROM core.selector WHERE case_id IN {cases}")
        conn.execute("DELETE FROM collect.extraction WHERE document_id = ANY(%s)",
                     (docs,))
    s.cleanup(conn, prefix)
    for doc in docs:
        try:
            with conn.transaction():
                conn.execute("DELETE FROM collect.document WHERE id = %s", (doc,))
        except Exception:  # noqa: BLE001
            pass   # another case's proposal still cites it


def selector_rows(conn, case_id: UUID, norm: str | None = None) -> list[tuple]:
    """(selector_type, norm_value, node_id, observation_cnt) of the case's
    index, optionally one value."""
    if norm is None:
        return conn.execute(
            "SELECT selector_type, norm_value, node_id, observation_cnt "
            "FROM core.selector WHERE case_id = %s ORDER BY norm_value",
            (case_id,)).fetchall()
    return conn.execute(
        "SELECT selector_type, norm_value, node_id, observation_cnt "
        "FROM core.selector WHERE case_id = %s AND norm_value = %s",
        (case_id, norm)).fetchall()


def one(conn, sql: str, params=None):
    row = conn.execute(sql, params).fetchone()
    return row[0] if row is not None and len(row) == 1 else row
