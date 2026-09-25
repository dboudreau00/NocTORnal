"""Row-level security on the deception records (S1, 2026-09-25).

0119 puts captures, BEC messages and calls under the ELEMENT policy and
their redirect chains, Received chains and attachment lists under their
record. Run as the request role, bound by a real session's proof, with the
fixtures seeded as the owner:

- a record is visible in a readable case within the reader's ceiling for
  that case: a RED capture in an AMBER case is hidden from an AMBER
  analyst, a grant on that case raises it, and a case they are not on
  shows nothing;
- the chain follows its capture;
- the service's own reads, which filter on the same composed labels,
  answer exactly as the owner's do for that reader;
- a write the author could not read back is refused;
- the policy is initplans only.

Gated like the other row-security tests. Account prefix `rlsdec-`.
"""
from __future__ import annotations

from uuid import UUID, uuid4

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "rlsdec-"


@pytest.fixture
def owner(monkeypatch):
    from noctornal_api.db import ASSUME_ROLE_ENV
    monkeypatch.setenv(ASSUME_ROLE_ENV, "1")
    c = s.owner_conn()
    yield c
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    with c.transaction():
        c.execute(f"DELETE FROM deception.capture WHERE case_id IN {cases}")
        c.execute(f"DELETE FROM deception.call_record WHERE case_id IN {cases}")
    s.cleanup(c, PREFIX)
    c.close()


def _capture(conn, case_id: UUID, actor: UUID, classification: str = "AMBER") -> UUID:
    from noctornal_api.deception import DeceptionService
    return DeceptionService(conn).record_capture(
        case_id=case_id, requested_url=f"https://{uuid4().hex[:8]}.rlsdec.test/login",
        capture_method="ANALYST_UPLOAD", captured_by=actor,
        hops=[{"url": "https://rlsdec.test/r", "hop_kind": "HTTP_30X"}],
        classification=classification)


def _ids(conn, sql: str, params=None) -> set[UUID]:
    return {r[0] for r in conn.execute(sql, params).fetchall()}


def test_a_record_is_held_to_its_case_and_the_ceiling_for_that_case(owner):
    from noctornal_api.deception import DeceptionService

    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    mine, other = s.case(owner, boss), s.case(owner, boss)
    s.assign(owner, mine, analyst)
    amber = _capture(owner, mine, boss)
    red = _capture(owner, mine, boss, "RED")
    elsewhere = _capture(owner, other, boss)
    _, raw = s.session(owner, analyst)
    everything = "SELECT id FROM deception.capture WHERE id = ANY(%s)"
    hops = "SELECT capture_id FROM deception.capture_hop WHERE capture_id = ANY(%s)"
    wanted = ([amber, red, elsewhere],)

    app = s.app_conn(raw)
    try:
        assert _ids(app, everything, wanted) == {amber}
        assert _ids(app, hops, wanted) == {amber}, "the chain follows its capture"
        listed = {UUID(r["id"]) for r in DeceptionService(app).captures(
            mine, clearance="AMBER", compartments=frozenset())}
        truth = {UUID(r["id"]) for r in DeceptionService(owner).captures(
            mine, clearance="AMBER", compartments=frozenset())}
        assert listed == truth == {amber}
        s.break_glass(owner, analyst, "RED", mine)
        assert _ids(app, everything, wanted) == {amber, red}, (
            "a grant on this case raises this case's records")
        s.break_glass(owner, analyst, "RED")
        assert elsewhere not in _ids(app, everything, wanted), (
            "no grant opens a case the analyst is not on")
    finally:
        app.close()


def test_a_record_the_author_could_not_read_back_is_refused(owner):
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    boss = s.user(owner, "RED", prefix=PREFIX)
    mine = s.case(owner, boss)
    s.assign(owner, mine, analyst)
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                """INSERT INTO deception.call_record
                       (case_id, started_at, direction, record_source,
                        recorded_by, classification)
                   VALUES (%s, now(), 'UNKNOWN', 'PBX_LOG', %s, 'RED')""",
                (mine, analyst))
    finally:
        app.close()


def _plan_nodes(plan) -> list[dict]:
    out, stack = [], [plan]
    while stack:
        node = stack.pop()
        out.append(node)
        stack.extend(node.get("Plans", []))
    return out


@pytest.mark.parametrize("table", ["capture", "email_message", "call_record"])
def test_the_policy_is_initplans_never_a_per_row_call(owner, table):
    analyst = s.user(owner, "AMBER", prefix=PREFIX)
    _, raw = s.session(owner, analyst)
    app = s.app_conn(raw)
    try:
        plan = app.execute(
            f"EXPLAIN (VERBOSE, FORMAT JSON) SELECT id FROM deception.{table} "
            f"WHERE case_id = %s", (uuid4(),)).fetchone()[0][0]["Plan"]
    finally:
        app.close()
    kinds = {n.get("Parent Relationship") for n in _plan_nodes(plan)}
    assert "InitPlan" in kinds and "SubPlan" not in kinds, plan
