"""Row-level security on the persona act queue (0156, A collector process,
2026-10-02): the CUSTOM_ACT template.

The request role, bound to a user, sees an act only when that user asked for
it and its label is within their case-less ceiling; may enqueue only their
own PENDING act within that ceiling; and can claim, finish, forge or delete
nothing, because it has no UPDATE or DELETE policy. Gated as every row
security test is: the owner seeds, a SET ROLE connection is under test.
"""
from __future__ import annotations

from uuid import uuid4

import psycopg
import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "rlspa-"


@pytest.fixture
def conn():
    c = s.owner_conn()
    yield c
    c.execute("""UPDATE collect.persona_act SET status = 'CANCELLED',
                        finished_at = clock_timestamp()
                  WHERE status = 'PENDING' AND requested_by IN (
                        SELECT id FROM iam.app_user WHERE email LIKE %s)""",
              (f"{PREFIX}%",))
    s.cleanup(c, PREFIX)
    c.close()


def _act(conn, uid, classification="AMBER", status="PENDING"):
    from noctornal_api.persona_acts import dedupe_key

    return conn.execute(
        """INSERT INTO collect.persona_act
               (kind, classification, params, dedupe_key, requested_by, expires_at,
                status, finished_at)
           VALUES ('TELEGRAM_MEMBERSHIP', %s, '{}'::jsonb, %s, %s,
                   clock_timestamp() + interval '30 minutes', %s,
                   CASE WHEN %s IN ('PENDING', 'RUNNING') THEN NULL
                        ELSE clock_timestamp() END)
           RETURNING id""",
        (classification, dedupe_key("T", None, {"n": uuid4().hex}), uid, status,
         status)).fetchone()[0]


def test_the_request_role_sees_its_own_acts_within_its_ceiling_and_nothing_else(conn):
    me = s.user(conn, "AMBER", prefix=PREFIX)
    other = s.user(conn, "RED", prefix=PREFIX)
    mine = _act(conn, me)
    above = _act(conn, me, classification="RED")
    theirs = _act(conn, other)
    _sid, raw = s.session(conn, me)
    app = s.app_conn(raw)
    try:
        seen = {r[0] for r in app.execute(
            "SELECT id FROM collect.persona_act WHERE id = ANY(%s)",
            ([mine, above, theirs],)).fetchall()}
        assert seen == {mine}
    finally:
        app.close()
    unbound = s.app_conn()
    try:
        assert s.count(unbound, "SELECT count(*) FROM collect.persona_act "
                                "WHERE id = ANY(%s)", ([mine, above, theirs],)) == 0
    finally:
        unbound.close()


def test_the_request_role_enqueues_only_its_own_pending_act_within_its_ceiling(conn):
    from noctornal_api.persona_acts import dedupe_key

    me = s.user(conn, "AMBER", prefix=PREFIX)
    other = s.user(conn, "AMBER", prefix=PREFIX)
    _sid, raw = s.session(conn, me)
    app = s.app_conn(raw)
    insert = """INSERT INTO collect.persona_act
                    (kind, classification, params, dedupe_key, requested_by,
                     expires_at, status, finished_at)
                VALUES ('TELEGRAM_MEMBERSHIP', %s, '{}'::jsonb, %s, %s,
                        clock_timestamp() + interval '30 minutes', %s, %s)"""
    try:
        app.execute(insert, ("AMBER", dedupe_key("A", None, {"n": 1}), me, "PENDING", None))
        for classification, who, status, finished in (
                ("AMBER", other, "PENDING", None),      # somebody else's
                ("RED", me, "PENDING", None),           # above the ceiling
                ("AMBER", me, "DONE", s.now())):        # a forged outcome
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with app.transaction():
                    app.execute(insert, (classification,
                                         dedupe_key("B", None, {"n": uuid4().hex}),
                                         who, status, finished))
    finally:
        app.close()


def test_the_request_role_cannot_queue_an_act_that_never_expires(conn):
    """verify:g38 minor (2026-10-03): the INSERT policy pinned the requester,
    the label and PENDING, and left expires_at to the request role, so a
    compromised API could queue an act the collector would run in ten
    years. persona_act_window caps it at an hour from requested_at,
    whatever the inserting role writes."""
    from noctornal_api.persona_acts import MAX_TTL_S, dedupe_key

    me = s.user(conn, "AMBER", prefix=PREFIX)
    _sid, raw = s.session(conn, me)
    app = s.app_conn(raw)
    insert = """INSERT INTO collect.persona_act
                    (kind, classification, params, dedupe_key, requested_by,
                     requested_at, expires_at)
                SELECT 'TELEGRAM_MEMBERSHIP', 'AMBER', '{}'::jsonb, %s, %s, t,
                       t + make_interval(secs => %s)
                  FROM (SELECT clock_timestamp() AS t) AS now_"""
    try:
        for seconds in (10 * 365 * 86400, MAX_TTL_S + 1, 0, -60):
            with pytest.raises(psycopg.errors.CheckViolation, match="persona_act_window"):
                with app.transaction():
                    app.execute(insert, (dedupe_key("W", None, {"n": uuid4().hex}), me,
                                         seconds))
        # The longest the constant allows is admitted, so the CHECK and the
        # constant the collector and the route share cannot drift apart.
        app.execute(insert, (dedupe_key("W", None, {"n": uuid4().hex}), me, MAX_TTL_S))
    finally:
        app.close()


def test_the_request_role_queues_a_fresh_act_and_cannot_pre_fill_the_collectors_columns(conn):
    """verify:g38 minor (2026-10-03): the request role could also write
    attempts, claimed_by, claimed_at and result on its own PENDING row."""
    from psycopg.types.json import Jsonb

    from noctornal_api.persona_acts import dedupe_key

    me = s.user(conn, "AMBER", prefix=PREFIX)
    _sid, raw = s.session(conn, me)
    app = s.app_conn(raw)
    insert = """INSERT INTO collect.persona_act
                    (kind, classification, params, dedupe_key, requested_by,
                     expires_at, attempts, claimed_by, claimed_at, result)
                VALUES ('TELEGRAM_MEMBERSHIP', 'AMBER', '{}'::jsonb, %s, %s,
                        clock_timestamp() + interval '30 minutes', %s, %s, %s, %s)"""
    try:
        for attempts, claimed_by, claimed_at, result in (
                (3, None, None, None),
                (0, "collector:somebody", None, None),
                (0, None, s.now(), None),
                (0, None, None, Jsonb({"body": {"member": True}}))):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with app.transaction():
                    app.execute(insert, (dedupe_key("F", None, {"n": uuid4().hex}), me,
                                         attempts, claimed_by, claimed_at, result))
        app.execute(insert, (dedupe_key("F", None, {"n": uuid4().hex}), me,
                             0, None, None, None))
    finally:
        app.close()


def test_the_migrations_window_and_the_runners_ceiling_are_one_number():
    import importlib.util
    from pathlib import Path

    from noctornal_api.persona_acts import MAX_TTL_S

    path = (Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
            / "0156_persona_act_queue.py")
    spec = importlib.util.spec_from_file_location("m0155", path)
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert migration.MAX_ACT_WINDOW_S == MAX_TTL_S


def test_the_request_role_can_claim_finish_or_delete_nothing(conn):
    me = s.user(conn, "AMBER", prefix=PREFIX)
    mine = _act(conn, me)
    _sid, raw = s.session(conn, me)
    app = s.app_conn(raw)
    try:
        moved = app.execute(
            "UPDATE collect.persona_act SET status = 'RUNNING', "
            "claimed_at = clock_timestamp() WHERE id = %s", (mine,)).rowcount
        assert moved == 0
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with app.transaction():
                app.execute("DELETE FROM collect.persona_act WHERE id = %s", (mine,))
    finally:
        app.close()
    assert conn.execute("SELECT status FROM collect.persona_act WHERE id = %s",
                        (mine,)).fetchone()[0] == "PENDING"


def test_the_system_role_claims_and_finishes(conn):
    from noctornal_api.db import SystemPurpose, connect_system

    me = s.user(conn, "AMBER", prefix=PREFIX)
    mine = _act(conn, me)
    sysconn = connect_system(SystemPurpose.PERSONA_ACTS)
    try:
        claimed = sysconn.execute(
            "UPDATE collect.persona_act SET status = 'RUNNING', "
            "claimed_at = clock_timestamp() WHERE id = %s", (mine,)).rowcount
        assert claimed == 1
        done = sysconn.execute(
            "UPDATE collect.persona_act SET status = 'DONE', "
            "finished_at = clock_timestamp(), result = '{\"body\": {}}' "
            "WHERE id = %s", (mine,)).rowcount
        assert done == 1
    finally:
        sysconn.close()
