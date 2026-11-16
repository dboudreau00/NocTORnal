"""The restore tool needs nothing the system role lacks (decision 240).

The tool connects as `noctornal_worker` (`connect_system(SystemPurpose.SCRIPT)`), never as the schema owner,
and the owner is what every other test connects as, so a missing grant would pass everywhere and fail on the
day an operator ran the tool. Here a whole run, exhibits and preserved samples, dry and real, goes through the
privileges of that role: the transaction is the test's own and is rolled back, and the role is taken with
`SET LOCAL ROLE` as the suite's other role tests take theirs.

It also holds the other half of the guard: the request role, which row security binds and which may not write a
RESTORED row, cannot be made to run the tool's statements either. Account prefix `rsrole-`.
"""
from __future__ import annotations

import os

import psycopg
import pytest

import rls_support as s
from restore_support import SampleWorld, World
from rolled_back import rolled_back

pytestmark = s.GATED

PREFIX = "rsrole-"
os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def worlds(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "preserved").mkdir()
    with rolled_back() as conn:
        boss = s.user(conn, "RED", prefix=PREFIX)
        s.grant_global(conn, boss, "SYS_ADMIN")
        case = s.case(conn, boss)
        yield (World(conn, boss, case, tmp_path / "evidence"),
               SampleWorld(conn, boss, case, tmp_path / "preserved"))


def test_a_dry_run_and_a_real_run_work_with_the_privileges_of_the_system_role(worlds):
    from noctornal_api.restore import Restore, resolve_actor
    ex_world, sample_world = worlds
    conn = ex_world.conn
    ex = ex_world.lodge()
    sm = sample_world.preserve()
    email = conn.execute("SELECT email FROM iam.app_user WHERE id = %s",
                         (ex_world.boss,)).fetchone()[0]

    def run(**kw):
        return Restore(conn, evidence=ex_world.fresh_storage, evidence_mirror=ex_world.mirror,
                       preserved=sample_world.fresh_storage, preserved_mirror=sample_world.mirror,
                       cases=[ex_world.case_id], where={"via": "test", "host": "h", "os_user": "u"},
                       **kw).run()

    conn.execute(f"SET LOCAL ROLE {s.WORKER_ROLE}")
    try:
        assert conn.execute("SELECT current_user").fetchone()[0] == s.WORKER_ROLE
        actor = resolve_actor(conn, email)
        assert actor == ex_world.boss
        dry = run(apply=False)
        assert dry.count("WOULD_RESTORE") == 2 and dry.left == 0
        real = run(apply=True, actor_id=actor, authority="TICKET-2026-1114")
        assert real.count("RESTORED") == 2 and real.left == 0, [o.as_dict() for o in real.outcomes]
        again = run(apply=True, actor_id=actor, authority="TICKET-2026-1114")
        assert again.count("ALREADY_PRESENT") == 2
    finally:
        conn.execute("RESET ROLE")
    assert len(ex_world.restored_rows(ex.id)) == 1 and len(sample_world.restored_rows(sm.id)) == 1
    assert ex_world.count("SELECT count(*) FROM audit.event WHERE action = 'RESTORE_RUN'") >= 2


def test_the_request_role_cannot_run_the_tools_statements(worlds):
    """A request-role connection is refused the custody row, the access row and the key: the tool is not
    something a request can be turned into."""
    ex_world, sample_world = worlds
    conn = ex_world.conn
    ex = ex_world.lodge()
    sm = sample_world.preserve()
    conn.execute(f"SET LOCAL ROLE {s.APP_ROLE}")
    try:
        for sql, params in (
                ("INSERT INTO core.evidence_custody (evidence_id, action, actor_id, detail) "
                 "VALUES (%s, 'RESTORED', %s, '{\"new_version_id\": \"v\"}')", (ex.id, ex_world.boss)),
                ("INSERT INTO lab.sample_access (sample_id, actor_id, actor_kind, action, detail) "
                 "VALUES (%s, %s, 'USER', 'RESTORED', "
                 "'{\"new_version_id\": \"v\", \"verified\": true, \"hold_confirmed\": true}')",
                 (sm.id, ex_world.boss))):
            conn.execute("SAVEPOINT attempt")
            with pytest.raises(psycopg.errors.Error):
                conn.execute(sql, params)
            conn.execute("ROLLBACK TO SAVEPOINT attempt")
        conn.execute("SAVEPOINT attempt")
        key = conn.execute("SELECT count(*) FROM lab.sample_data_key(%s)", (sm.id,)).fetchone()[0]
        conn.execute("ROLLBACK TO SAVEPOINT attempt")
    finally:
        conn.execute("RESET ROLE")
    assert key == 0, "an unbound request connection is answered no data key"
    assert ex_world.restored_rows(ex.id) == [] and sample_world.restored_rows(sm.id) == []


def test_a_request_role_bound_to_a_session_reads_the_version_a_restore_named(worlds):
    """The reads that follow a restore run as the request role under row security, not as the system role
    that wrote the row: the case's owner is answered the new version of each object, and a caller who may see
    neither is answered none."""
    from noctornal_api.db import bind_session
    ex_world, sample_world = worlds
    conn = ex_world.conn
    ex = ex_world.lodge()
    sm = sample_world.preserve()
    ex_world.restore()
    sample_world.restore()
    [(ex_detail, _a, _v)] = ex_world.restored_rows(ex.id)
    [(sm_detail, _b, _k)] = sample_world.restored_rows(sm.id)
    # Below the sample's label and outside the case: row security shows this caller neither object.
    stranger = s.user(conn, "GREEN", prefix=PREFIX)
    answers = {}
    for who in (ex_world.boss, stranger):
        _sid, raw = s.session(conn, who)
        conn.execute(f"SET LOCAL ROLE {s.APP_ROLE}")
        try:
            bind_session(conn, raw)
            answers[who] = (
                conn.execute("SELECT core.evidence_current_version(%s)", (ex.id,)).fetchone()[0],
                conn.execute("SELECT lab.sample_current_preserved_version(%s)",
                             (sm.id,)).fetchone()[0])
        finally:
            conn.execute("RESET ROLE")
    assert answers[ex_world.boss] == (ex_detail["new_version_id"], sm_detail["new_version_id"])
    assert answers[stranger] == (None, None)
