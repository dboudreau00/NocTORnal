"""Fixtures for the row-level security tests (S1, 2026-09-25).

The suite connects as the schema OWNER, which row security never filters.
These tests reach the runtime roles by SET ROLE from the owner's own
login, a superuser, so no runtime password ever enters the test
environment. The owner seeds; a second connection, SET ROLE noctornal_app
and bound with a real session's proof, is what is under test.

Gated on NOCTORNAL_APP_DB_ROLE (set in CI, where db/init/10-app-role.sh
creates both runtime roles before `alembic upgrade head`). On a developer
database, `python scripts/runtime_roles.py ensure` creates them.
"""
from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

APP_ROLE = os.environ.get("NOCTORNAL_APP_DB_ROLE", "").strip()
WORKER_ROLE = os.environ.get("NOCTORNAL_WORKER_DB_ROLE", "noctornal_worker").strip()
GATED = pytest.mark.skipif(
    not (os.environ.get("DATABASE_URL") and APP_ROLE),
    reason="DATABASE_URL and NOCTORNAL_APP_DB_ROLE required; run "
           "scripts/runtime_roles.py ensure on a development database")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

PREFIX = "rlsb-"
#: Registered before any row is filed under it (0059), never deleted: the
#: registry refuses to drop a key while any row still carries it.
COMPARTMENT = "RLS-TEST-X"


def owner_conn():
    from noctornal_api.db import connect
    return connect()


def register(conn, *keys: str) -> list[str]:
    for key in keys:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, f"{key} (row security test)"))
    return list(keys)


def user(conn, clearance: str = "AMBER", compartments: tuple[str, ...] = (),
         active: bool = True, prefix: str = PREFIX) -> UUID:
    # `prefix`: each test file names its own accounts, so one file's
    # teardown never removes another's (S1, 2026-09-25).
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{prefix}{uuid4().hex[:10]}@noctornal.test", "RLS analyst", "x" * 20)
    conn.execute(
        "UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s, "
        "is_active = %s WHERE id = %s",
        (clearance, register(conn, *compartments), active, uid))
    return uid


def grant_global(conn, uid: UUID, role: str) -> None:
    conn.execute("INSERT INTO iam.user_role (user_id, role_key) VALUES (%s, %s) "
                 "ON CONFLICT DO NOTHING", (uid, role))


def case(conn, owner: UUID, classification: str = "AMBER",
         compartments: tuple[str, ...] = ()) -> UUID:
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-RLS-{uuid4().hex[:8].upper()}", title="Row security",
        legal_basis="test authority", retention_until=date(2030, 1, 1),
        review_due=date(2029, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification, compartments=register(conn, *compartments))


def assign(conn, case_id: UUID, uid: UUID, role: str = "ANALYST",
           expires_at: datetime | None = None) -> None:
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by, expires_at)
           VALUES (%s, %s, %s, %s, %s)
           ON CONFLICT (case_id, user_id) DO UPDATE SET expires_at = EXCLUDED.expires_at""",
        (case_id, uid, role, uid, expires_at))


def node(conn, case_id: UUID, actor: UUID, label: str, classification: str = "AMBER",
         compartments: tuple[str, ...] = ()) -> UUID:
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_node(
        case_id=case_id, node_type="IDENTITY", label=label, created_by=actor,
        classification=classification, compartments=register(conn, *compartments),
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor))


def edge(conn, case_id: UUID, actor: UUID, src: UUID, dst: UUID,
         classification: str = "AMBER") -> UUID:
    from noctornal_api.graph import AssertionInput, GraphWriteService
    return GraphWriteService(conn).create_edge(
        case_id=case_id, edge_type="VOUCHED_FOR", src_node_id=src, dst_node_id=dst,
        created_by=actor, classification=classification,
        assertion=AssertionInput(basis="DIRECT_OBSERVATION", created_by=actor,
                                 rationale="vouched"))


def exhibit(conn, case_id: UUID, actor: UUID, classification: str = "AMBER") -> UUID:
    """A row only: no bytes, no custody, so it can be deleted afterwards."""
    return conn.execute(
        """INSERT INTO core.evidence
               (case_id, title, media_type, byte_size, sha256, blake3,
                storage_key, storage_bucket, acquired_by, acquired_at,
                acquisition_method, classification)
           VALUES (%s, 'rls exhibit', 'text/plain', 1, %s, %s, %s, 'b', %s, now(),
                   'MANUAL_UPLOAD', %s)
           RETURNING id""",
        (case_id, os.urandom(32), os.urandom(32), f"{case_id}/{uuid4().hex}",
         actor, classification)).fetchone()[0]


def session(conn, uid: UUID, *, mfa: bool = True) -> tuple[UUID, str]:
    """(session id, raw token), minted the way login mints one."""
    from noctornal_api.security.sessions import SessionService
    from noctornal_api.stores import PgSessionStore
    record, raw = SessionService(PgSessionStore(conn)).create(
        uuid4(), uid, mfa_satisfied=mfa)
    return record.id, raw


def app_conn(raw: str | None = None):
    """A connection as the request role, bound to `raw`'s session if given."""
    from noctornal_api.db import bind_session, connect
    c = connect()
    c.execute(f"SET ROLE {APP_ROLE}")
    if raw is not None:
        bind_session(c, raw)
    return c


def break_glass(conn, uid: UUID, level: str, case_id: UUID | None = None,
                hours: int = 1) -> UUID:
    return conn.execute(
        """INSERT INTO iam.break_glass
               (user_id, case_id, justification, expires_at, granted_classification)
           VALUES (%s, %s, 'row security test: an emergency of the test kind',
                   now() + %s, %s)
           RETURNING id""",
        (uid, case_id, timedelta(hours=hours), level)).fetchone()[0]


def count(conn, sql: str, params=None) -> int:
    return conn.execute(sql, params).fetchone()[0]


def cleanup(conn, prefix: str = PREFIX) -> None:
    """Everything the fixtures made that a table lets go of. Custody and
    audit rows are append-only by design and stay; so do the accounts'
    audit trail and any break-glass rows (reviewed history)."""
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{prefix}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    with conn.transaction():
        conn.execute(f"DELETE FROM core.hypothesis_evidence WHERE hypothesis_id IN "
                     f"(SELECT id FROM core.hypothesis WHERE case_id IN {cases})")
        conn.execute(f"DELETE FROM core.hypothesis WHERE case_id IN {cases}")
        conn.execute(f"DELETE FROM core.node_set_member WHERE set_id IN "
                     f"(SELECT id FROM core.node_set WHERE case_id IN {cases})")
        conn.execute(f"DELETE FROM core.node_set WHERE case_id IN {cases}")
        conn.execute(f"DELETE FROM core.evidence_link WHERE evidence_id IN "
                     f"(SELECT id FROM core.evidence WHERE case_id IN {cases})")
        conn.execute(f"DELETE FROM core.evidence e WHERE case_id IN {cases} "
                     f"AND NOT EXISTS (SELECT 1 FROM core.evidence_custody c "
                     f"WHERE c.evidence_id = e.id)")
        conn.execute("ALTER TABLE core.assertion DISABLE TRIGGER USER")
        try:
            conn.execute(f"DELETE FROM core.assertion WHERE case_id IN {cases}")
        finally:
            conn.execute("ALTER TABLE core.assertion ENABLE TRIGGER USER")
        conn.execute(f"DELETE FROM core.edge WHERE case_id IN {cases}")
        conn.execute(f"DELETE FROM core.node WHERE case_id IN {cases}")
        conn.execute(f"DELETE FROM iam.case_assignment WHERE user_id IN {users} "
                     f"OR case_id IN {cases}")
        conn.execute(f"DELETE FROM iam.session WHERE user_id IN {users}")
        conn.execute(f"DELETE FROM iam.user_role WHERE user_id IN {users}")
        conn.execute(f"DELETE FROM iam.break_glass WHERE user_id IN {users}")
    # The cases and accounts themselves, when nothing append-only names them
    # (a custody row or an audit trail can): each in its own savepoint.
    for statement in (f'DELETE FROM core."case" WHERE id IN {cases}',
                      f"DELETE FROM iam.app_user WHERE id IN {users}"):
        try:
            with conn.transaction():
                conn.execute(statement)
        except Exception:  # noqa: BLE001
            pass


def now() -> datetime:
    return datetime.now(timezone.utc)


def per_row_definer_calls(conn, sql: str, params=None) -> list[str]:
    """The plan nodes that call a row-security helper (`iam.rls_*`,
    `iam.case_*`, `iam.element_facts`) other than as an InitPlan, from
    EXPLAIN (VERBOSE) of `sql` on `conn` (S1, 2026-09-25). An InitPlan runs
    once per statement; any other node that calls one runs it per row, and
    a policy's per-row work must stay comparisons, containments and key
    probes. Empty is the pass."""
    import json
    plan = conn.execute("EXPLAIN (VERBOSE, FORMAT JSON) " + sql, params).fetchone()[0]
    if isinstance(plan, str):
        plan = json.loads(plan)
    out: list[str] = []
    stack = [(plan[0]["Plan"], False)]
    while stack:
        node, in_init = stack.pop()
        in_init = in_init or node.get("Parent Relationship") == "InitPlan"
        text = json.dumps({k: v for k, v in node.items() if k != "Plans"})
        if not in_init and ("iam.rls_" in text or "iam.case_" in text
                            or "iam.element_facts" in text):
            out.append(node.get("Node Type", "?"))
        stack.extend((child, in_init) for child in node.get("Plans", []))
    return out
