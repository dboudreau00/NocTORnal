"""The deployment's two-person policy against a database (F9, 2026-09-24;
migration dual_control_policy).

Which operations need a second signature and which permission pairs no role
may hold now live in `iam.dual_control_operation` and `iam.separated_duty`,
and the only way either moves is a row in `iam.dual_control_policy_change`
that a consumed `dual_control.policy` approval accounts for, proposed by an
administrator and countersigned by a Security officer who is not one.

## Isolation (the global policy is shared state)

(a) A test whose change SUCCEEDS runs inside `with pytest.raises(_RollBack),
    conn.transaction():`, so no mode or pair leaks. It asserts refusals
    only: an out-of-band audit row written from inside that transaction
    goes on the caller's connection (approvals.py, the chain-lock rule) and
    rolls back with it.
(b) "Consumed in an EARLIER transaction" runs on the autocommit fixture
    with two real transactions.
(c) The out-of-band rows themselves are proved on autocommit, where the
    caller holds no transaction that has audited.
(d) Teardown deletes notifications, then approvals the ledger does not hold,
    then accounts nothing holds; an account the append-only ledger names
    is DEACTIVATED, never deleted. No PENDING deployment-wide request
    survives a test, and node.merge ends PER_CASE or the teardown says so.

Email prefix `dcz-`, unique to this file (dcp- is test_deception_pg's); throwaway permissions `dcp.*`.
Env-gated on DATABASE_URL.
"""
from __future__ import annotations

import importlib.util
import os
import time
from datetime import date
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Json

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; the policy is gated")

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")

VERSIONS = Path(__file__).resolve().parents[3] / "db" / "migrations" / "versions"
PREFIX = "dcz-"


class _RollBack(Exception):
    pass


# ---------------------------------------------------------------------------
# Fixtures and helpers (the HTTP file imports these)
# ---------------------------------------------------------------------------

def force_mode(conn, mode: str = "PER_CASE") -> None:
    """The owner-level restore: the guard disabled BY NAME for one
    statement, in one transaction, as a migration would."""
    with conn.transaction():
        conn.execute("ALTER TABLE iam.dual_control_operation DISABLE TRIGGER "
                     "dual_control_operation_written_by_ledger")
        conn.execute("UPDATE iam.dual_control_operation SET mode = %s "
                     "WHERE operation = 'node.merge'", (mode,))
        conn.execute("ALTER TABLE iam.dual_control_operation ENABLE TRIGGER "
                     "dual_control_operation_written_by_ledger")


def merge_mode(conn) -> str:
    row = conn.execute("SELECT mode FROM iam.dual_control_operation "
                       "WHERE operation = 'node.merge'").fetchone()
    return row[0] if row else "missing"


def teardown(c, prefix: str) -> None:
    """Rule (d), for any prefix."""
    like = f"{prefix}%@noctornal.test"
    sub = f"(SELECT id FROM iam.app_user WHERE email LIKE '{like}')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    held = "(SELECT approval_request_id FROM iam.dual_control_policy_change)"
    named = ("(SELECT requested_by FROM iam.dual_control_policy_change "
             "UNION SELECT countersigned_by FROM iam.dual_control_policy_change)")
    pkey = f"{prefix.rstrip('-')}.%"
    with c.transaction():
        c.execute(f"""DELETE FROM notify.delivery WHERE notification_id IN
                        (SELECT id FROM notify.notification
                          WHERE recipient_id IN {sub} OR case_id IN {csub}
                             OR actor_id IN {sub})""")
        c.execute(f"""DELETE FROM notify.notification
                       WHERE recipient_id IN {sub} OR case_id IN {csub}
                          OR actor_id IN {sub}""")
        c.execute(f"""DELETE FROM core.approval_request
                       WHERE (requested_by IN {sub} OR case_id IN {csub})
                         AND id NOT IN {held}""")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub} "
                  f"OR user_id IN {sub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        # A policy pair a failed test left on its throwaway permissions.
        c.execute("ALTER TABLE iam.separated_duty DISABLE TRIGGER "
                  "separated_duty_written_by_ledger")
        c.execute("DELETE FROM iam.separated_duty WHERE permission_a LIKE %s "
                  "OR permission_b LIKE %s", (pkey, pkey))
        c.execute("ALTER TABLE iam.separated_duty ENABLE TRIGGER "
                  "separated_duty_written_by_ledger")
        c.execute("DELETE FROM iam.role_permission WHERE permission_key LIKE %s "
                  "OR role_key LIKE %s", (pkey, prefix.upper().rstrip('-') + "_%"))
        c.execute("DELETE FROM iam.permission WHERE key LIKE %s", (pkey,))
        c.execute(f"DELETE FROM iam.session WHERE user_id IN {sub}")
        c.execute(f"""UPDATE iam.app_user SET is_active = false
                       WHERE email LIKE '{like}'
                         AND (id IN {named} OR id IN
                              (SELECT requested_by FROM core.approval_request)
                           OR id IN (SELECT decided_by FROM core.approval_request
                                      WHERE decided_by IS NOT NULL))""")
        c.execute(f"""DELETE FROM iam.user_role WHERE user_id IN {sub}
                       AND user_id NOT IN {named}
                       AND user_id NOT IN (SELECT requested_by
                                             FROM core.approval_request)
                       AND user_id NOT IN (SELECT decided_by FROM
                             core.approval_request WHERE decided_by IS NOT NULL)""")
        c.execute(f"""DELETE FROM iam.app_user WHERE email LIKE '{like}'
                       AND id NOT IN {named}
                       AND id NOT IN (SELECT requested_by FROM core.approval_request)
                       AND id NOT IN (SELECT decided_by FROM core.approval_request
                                       WHERE decided_by IS NOT NULL)""")
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub} AND "
                  f"user_id IN (SELECT id FROM iam.app_user WHERE NOT is_active)")
    if merge_mode(c) != "PER_CASE":
        force_mode(c, "PER_CASE")
        raise AssertionError("a test left node.merge stricter than PER_CASE; "
                             "restored by the owner-level helper")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    teardown(c, PREFIX)
    c.close()


def user(conn, *roles, clearance="AMBER", name="Person", prefix=PREFIX,
         compartments=()):
    """An active account with global roles, written directly: no
    USER_CREATED or ROLE_GRANTED audit row, so the seven-day rule does not
    apply to it."""
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"{prefix}{uuid4().hex[:8]}@noctornal.test", name, "x" * 20)
    for key in compartments:
        conn.execute("INSERT INTO iam.compartment (key, label) VALUES (%s, %s) "
                     "ON CONFLICT (key) DO NOTHING", (key, f"{key} (test)"))
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s, compartments = %s "
                 "WHERE id = %s", (clearance, list(compartments), uid))
    for role in roles:
        conn.execute("INSERT INTO iam.user_role (user_id, role_key) "
                     "VALUES (%s, %s)", (uid, role))
    return uid


def throwaway_pair(conn, prefix=PREFIX) -> tuple[str, str]:
    """Two permissions no role holds, sorted as the ledger stores them."""
    tag = uuid4().hex[:8]
    root = prefix.rstrip("-")
    a, b = f"{root}.{tag}.a", f"{root}.{tag}.b"
    conn.execute("INSERT INTO iam.permission (key, description) VALUES "
                 "(%s, 'throwaway'), (%s, 'throwaway')", (a, b))
    return a, b


def _svc(conn):
    from noctornal_api.dual_control import DualControlPolicyService
    return DualControlPolicyService(conn)


def _approvals(conn):
    from noctornal_api.approvals import ApprovalService
    return ApprovalService(conn)


def _mode_change(to="ALWAYS"):
    return {"change": "OPERATION_MODE", "operation": "node.merge", "to": to}


def _flow(conn, change, admin, officer, *, apply=True):
    """Propose, countersign and (by default) apply one change."""
    req = _svc(conn).propose(change=change, justification="standing orders",
                             requested_by=admin)
    _approvals(conn).decide(req.id, decided_by=officer, approve=True)
    if apply:
        _svc(conn).apply(req.id, actor_id=admin)
    return req


def _case(conn, owner, classification="AMBER", compartments=()):
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-DCP-{uuid4().hex[:6]}", title="Two-person policy",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner,
        classification=classification, compartments=list(compartments))


# ---------------------------------------------------------------------------
# Where it starts, and what reads it
# ---------------------------------------------------------------------------

def test_the_policy_starts_where_decision_44_left_it(conn):
    assert merge_mode(conn) == "PER_CASE"
    rows = {tuple(sorted(r[:2])): r[2] for r in conn.execute(
        "SELECT permission_a, permission_b, origin FROM iam.separated_duty")}
    assert rows[("dual_control.countersign", "dual_control.manage")] == "migration"
    for pair in (("victim_pii.authorise", "victim_pii.reveal"),
                 ("break_glass.invoke", "break_glass.review"),
                 ("sample.preserved.authorise", "sample.preserved.retrieve")):
        assert rows[pair] == "migration", pair
    holders = {r[0] for r in conn.execute(
        "SELECT role_key FROM iam.role_permission WHERE permission_key = "
        "'dual_control.manage'")}
    signers = {r[0] for r in conn.execute(
        "SELECT role_key FROM iam.role_permission WHERE permission_key = "
        "'dual_control.countersign'")}
    assert holders == {"SYS_ADMIN"} and signers == {"SECURITY_OFFICER"}


def test_always_makes_every_case_require_a_second_signature_on_merges(conn):
    from noctornal_api.approvals import case_requires_dual_control, policy_mode
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    lead = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead)
    assert case_requires_dual_control(conn, case_id, "node.merge") is False
    with pytest.raises(_RollBack), conn.transaction():
        _flow(conn, _mode_change("ALWAYS"), admin, officer)
        assert policy_mode(conn, "node.merge") == "ALWAYS"
        assert case_requires_dual_control(conn, case_id, "node.merge") is True
        raise _RollBack
    assert merge_mode(conn) == "PER_CASE"


def test_a_mode_below_the_catalogue_floor_is_never_read(conn):
    from noctornal_api.approvals import case_requires_dual_control, policy_mode
    lead = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead)
    with pytest.raises(_RollBack), conn.transaction():
        conn.execute("ALTER TABLE iam.dual_control_operation DISABLE TRIGGER "
                     "dual_control_operation_written_by_ledger")
        conn.execute("INSERT INTO iam.dual_control_operation (operation, mode) "
                     "VALUES ('evidence.purge', 'PER_CASE')")
        assert policy_mode(conn, "evidence.purge") == "ALWAYS"
        assert case_requires_dual_control(conn, case_id, "evidence.purge") is True
        raise _RollBack


def test_a_missing_policy_row_fails_closed(conn):
    from noctornal_api.approvals import case_requires_dual_control, policy_mode
    lead = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead)
    with pytest.raises(_RollBack), conn.transaction():
        conn.execute("ALTER TABLE iam.dual_control_operation DISABLE TRIGGER "
                     "dual_control_operation_written_by_ledger")
        conn.execute("DELETE FROM iam.dual_control_operation "
                     "WHERE operation = 'node.merge'")
        assert policy_mode(conn, "node.merge") == "ALWAYS"
        assert case_requires_dual_control(conn, case_id, "node.merge") is True
        raise _RollBack


def test_an_unknown_mode_value_fails_closed(conn):
    from noctornal_api.approvals import policy_mode
    with pytest.raises(_RollBack), conn.transaction():
        conn.execute("ALTER TABLE iam.dual_control_operation DISABLE TRIGGER "
                     "dual_control_operation_written_by_ledger")
        conn.execute("ALTER TABLE iam.dual_control_operation DROP CONSTRAINT "
                     "dual_control_mode_known")
        conn.execute("UPDATE iam.dual_control_operation SET mode = 'NEVER' "
                     "WHERE operation = 'node.merge'")
        assert policy_mode(conn, "node.merge") == "ALWAYS"
        raise _RollBack


def test_the_policy_row_refuses_a_direct_write(conn):
    for sql in ("INSERT INTO iam.dual_control_operation (operation, mode) "
                "VALUES ('case.delete', 'ALWAYS')",
                "UPDATE iam.dual_control_operation SET mode = 'ALWAYS' "
                "WHERE operation = 'node.merge'",
                "DELETE FROM iam.dual_control_operation "
                "WHERE operation = 'node.merge'"):
        with pytest.raises(psycopg.errors.RaiseException,
                           match="only through a two-person policy change"):
            conn.execute(sql)
    with pytest.raises(psycopg.errors.RaiseException, match="never truncated"):
        conn.execute("TRUNCATE iam.dual_control_operation")
    assert merge_mode(conn) == "PER_CASE"


def test_separated_duty_refuses_a_direct_insert_update_and_delete(conn):
    a, b = throwaway_pair(conn)
    with pytest.raises(psycopg.errors.RaiseException,
                       match="disables trigger separated_duty_written_by_ledger"):
        conn.execute("INSERT INTO iam.separated_duty (permission_a, "
                     "permission_b, why) VALUES (%s, %s, 'a direct pair')", (a, b))
    for sql in ("UPDATE iam.separated_duty SET why = 'rewritten' "
                "WHERE permission_a = 'victim_pii.authorise'",
                "DELETE FROM iam.separated_duty "
                "WHERE permission_a = 'victim_pii.authorise'"):
        with pytest.raises(psycopg.errors.RaiseException,
                           match="only through a two-person policy change"):
            conn.execute(sql)
    with pytest.raises(psycopg.errors.RaiseException, match="never truncated"):
        conn.execute("TRUNCATE iam.separated_duty")


# ---------------------------------------------------------------------------
# A write from some other trigger (F9, 2026-09-24)
#
# The guard's depth test alone accepts a write from ANY trigger, and the
# runtime role can make one without owning anything: PUBLIC holds TEMP, so
# it can create a temporary table, a pg_temp function and a trigger that
# runs whatever it is handed. A probe moved node.merge and added a
# pair that way with no ledger row, no approval and no audit event. Every
# refusal below must be the binding's ("matches none"), which is only
# reached once the depth test has passed: that is what proves the probe
# really wrote from inside a trigger.
# ---------------------------------------------------------------------------

def _probe(conn) -> None:
    """The probe, inside the caller's transaction."""
    conn.execute("CREATE TEMP TABLE dcp_probe (sql text) ON COMMIT DROP")
    conn.execute("""CREATE FUNCTION pg_temp.dcp_probe_run() RETURNS trigger
                    LANGUAGE plpgsql AS $f$
                    BEGIN EXECUTE NEW.sql; RETURN NEW; END $f$""")
    conn.execute("CREATE TRIGGER dcp_probe_run BEFORE INSERT ON dcp_probe "
                 "FOR EACH ROW EXECUTE FUNCTION pg_temp.dcp_probe_run()")
    # The probe runs what it is handed: a harmless statement goes through.
    conn.execute("INSERT INTO dcp_probe VALUES "
                 "('SELECT set_config(''dcp.probe'', ''ran'', true)')")
    assert conn.execute("SELECT current_setting('dcp.probe')").fetchone()[0] == "ran"


def _probe_refused(conn, sql: str) -> None:
    with pytest.raises(psycopg.errors.RaiseException, match="matches none"), \
            conn.transaction():
        conn.execute("INSERT INTO dcp_probe VALUES (%s)", (sql,))


def _pair_rows(conn, a, b) -> list:
    return conn.execute(
        "SELECT origin FROM iam.separated_duty WHERE least(permission_a, "
        "permission_b) = %s AND greatest(permission_a, permission_b) = %s",
        (a, b)).fetchall()


def test_a_write_from_any_other_trigger_is_refused(conn):
    a, b = throwaway_pair(conn)
    with pytest.raises(_RollBack), conn.transaction():
        _probe(conn)
        for sql in (
                "UPDATE iam.dual_control_operation SET mode = 'ALWAYS' "
                "WHERE operation = 'node.merge'",
                "INSERT INTO iam.dual_control_operation (operation, mode) "
                "VALUES ('case.delete', 'ALWAYS')",
                "DELETE FROM iam.dual_control_operation "
                "WHERE operation = 'node.merge'",
                f"INSERT INTO iam.separated_duty (permission_a, permission_b, "
                f"why) VALUES ('{a}', '{b}', 'a pair nobody countersigned')",
                "UPDATE iam.separated_duty SET why = 'rewritten' "
                "WHERE permission_a = 'victim_pii.authorise'"):
            _probe_refused(conn, sql)
        assert merge_mode(conn) == "PER_CASE"
        assert _pair_rows(conn, a, b) == []
        raise _RollBack


def test_a_write_must_be_exactly_what_this_transactions_change_says(conn):
    """A legitimate change applied in the same transaction lends nothing
    to a write that differs from it."""
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    a, b = throwaway_pair(conn)
    c, d = throwaway_pair(conn)
    with pytest.raises(_RollBack), conn.transaction():
        _probe(conn)
        _flow(conn, _mode_change("ALWAYS"), admin, officer)
        _flow(conn, {"change": "SEPARATED_DUTY_ADD", "permission_a": a,
                     "permission_b": b, "why": "held apart for this test"},
              admin, officer)
        mode_change, add = (conn.execute(
            "SELECT id FROM iam.dual_control_policy_change WHERE change = %s "
            "AND applied_at = now() ORDER BY seq DESC LIMIT 1", (kind,)
        ).fetchone()[0] for kind in ("OPERATION_MODE", "SEPARATED_DUTY_ADD"))
        for sql in (
                # Back the other way, naming the change that went forward.
                f"UPDATE iam.dual_control_operation SET mode = 'PER_CASE', "
                f"change_id = '{mode_change}' WHERE operation = 'node.merge'",
                # Another pair, and another reason, under this pair's change.
                f"INSERT INTO iam.separated_duty (permission_a, permission_b, "
                f"why, origin, added_at, added_by_change) VALUES ('{c}', '{d}', "
                f"'held apart for this test', 'policy', now(), '{add}')",
                # The pair just added, with no change removing it.
                f"DELETE FROM iam.separated_duty WHERE permission_a = '{a}'"):
            _probe_refused(conn, sql)
        assert merge_mode(conn) == "ALWAYS"
        assert _pair_rows(conn, a, b) == [("policy",)]
        assert _pair_rows(conn, c, d) == []
        raise _RollBack


def test_a_write_naming_a_change_of_an_earlier_transaction_is_refused(conn):
    """Rule (b): real transactions. Each ledger row below matches the
    probe's write in every column but one, applied_at, which the ledger
    pins to the transaction that inserted it."""
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    a, b = throwaway_pair(conn)
    pair = {"permission_a": a, "permission_b": b}
    ids = []
    for change in ({"change": "SEPARATED_DUTY_ADD", **pair,
                    "why": "held apart for this test"},
                   {"change": "SEPARATED_DUTY_REMOVE", **pair},
                   {"change": "SEPARATED_DUTY_ADD", **pair,
                    "why": "held apart for this test"},
                   _mode_change("ALWAYS"), _mode_change("PER_CASE")):
        req = _flow(conn, change, admin, officer)
        ids.append(conn.execute(
            "SELECT id FROM iam.dual_control_policy_change "
            "WHERE approval_request_id = %s", (req.id,)).fetchone()[0])
    first_add, remove, _, tighten, _ = ids
    assert merge_mode(conn) == "PER_CASE"
    assert _pair_rows(conn, a, b) == [("policy",)]
    try:
        with pytest.raises(_RollBack), conn.transaction():
            _probe(conn)
            _probe_refused(
                conn, f"UPDATE iam.dual_control_operation SET mode = 'ALWAYS', "
                f"change_id = '{tighten}', changed_at = now() "
                f"WHERE operation = 'node.merge'")
            _probe_refused(
                conn, f"DELETE FROM iam.separated_duty WHERE permission_a = '{a}'")
            # Removed properly in this transaction, then put back naming the
            # first ADD, which went in two transactions ago.
            _flow(conn, {"change": "SEPARATED_DUTY_REMOVE", **pair},
                  admin, officer)
            assert _pair_rows(conn, a, b) == []
            _probe_refused(
                conn, f"INSERT INTO iam.separated_duty (permission_a, "
                f"permission_b, why, origin, added_at, added_by_change) VALUES "
                f"('{a}', '{b}', 'held apart for this test', 'policy', now(), "
                f"'{first_add}')")
            assert _pair_rows(conn, a, b) == []
            raise _RollBack
        assert remove != first_add
        assert merge_mode(conn) == "PER_CASE"
    finally:
        # Out through the flow it came in by, so no policy pair outlives
        # the test (the downgrade refuses while one exists).
        if _pair_rows(conn, a, b):
            _flow(conn, {"change": "SEPARATED_DUTY_REMOVE", **pair},
                  admin, officer)


def test_the_ledger_pins_applied_at_to_its_own_transaction(conn):
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        req = _flow(conn, _mode_change("ALWAYS"), admin, officer, apply=False)
        _approvals(conn).consume(req.id, actor_id=admin,
                                 operation="dual_control.policy", case_id=None,
                                 payload=req.payload)
        # A caller that names an applied_at of its choosing does not get it:
        # a row that claimed another transaction's start could otherwise be
        # matched by a write in that transaction.
        conn.execute(
            """INSERT INTO iam.dual_control_policy_change
                   (approval_request_id, change, operation, mode_from, mode_to,
                    based_on, requested_by, countersigned_by, applied_at)
               VALUES (%s, 'OPERATION_MODE', 'node.merge', 'PER_CASE',
                       'ALWAYS', %s, %s, %s, '2000-01-01T00:00:00Z')""",
            (req.id, req.payload["based_on"], admin, officer))
        pinned = conn.execute(
            "SELECT applied_at = now() FROM iam.dual_control_policy_change "
            "WHERE approval_request_id = %s", (req.id,)).fetchone()[0]
        assert pinned is True
        assert merge_mode(conn) == "ALWAYS"
        raise _RollBack


# ---------------------------------------------------------------------------
# The ledger's rules
# ---------------------------------------------------------------------------

def test_a_release_pair_cannot_be_removed_by_a_policy_change(conn):
    from noctornal_api.dual_control import PolicyError
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    with pytest.raises(PolicyError, match="installed with the software"):
        _svc(conn).propose(change={
            "change": "SEPARATED_DUTY_REMOVE",
            "permission_a": "victim_pii.reveal",
            "permission_b": "victim_pii.authorise"},
            justification="j", requested_by=admin)
    # Raised around propose's check, straight through the approvals service,
    # so the ledger's own refusal is what is tested.
    with pytest.raises(_RollBack), conn.transaction():
        req = _approvals(conn).request(
            operation="dual_control.policy", case_id=None,
            payload={"change": "SEPARATED_DUTY_REMOVE",
                     "permission_a": "victim_pii.authorise",
                     "permission_b": "victim_pii.reveal", "based_on": None},
            justification="j", requested_by=admin)
        _approvals(conn).decide(req.id, decided_by=officer, approve=True)
        with pytest.raises(PolicyError, match="not added by a two-person change"):
            _svc(conn).apply(req.id, actor_id=admin)
        assert _approvals(conn).get(req.id).state == "APPROVED"
        raise _RollBack


def _ledger_insert(conn, req, admin, officer, **over):
    row = {"change": "SEPARATED_DUTY_ADD", "permission_a": None,
           "permission_b": None, "why": None, "based_on": None}
    row.update(req.payload)
    row.update(over)
    conn.execute(
        """INSERT INTO iam.dual_control_policy_change
               (approval_request_id, change, operation, mode_from, mode_to,
                permission_a, permission_b, why, based_on, requested_by,
                countersigned_by)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (req.id, row["change"], row.get("operation"), row.get("from"),
         row.get("to"), row["permission_a"], row["permission_b"], row["why"],
         row["based_on"], admin, officer))


def _ledger_refuses(conn, req, admin, match):
    """The ledger trigger's own refusal, with the service's readable
    pre-check out of the way: the approval consumed and the row inserted in
    one savepoint, as `apply` does, and the database says no."""
    decided = _approvals(conn).get(req.id)
    with pytest.raises(psycopg.errors.RaiseException, match=match), \
            conn.transaction():
        _approvals(conn).consume(req.id, actor_id=admin,
                                 operation="dual_control.policy", case_id=None,
                                 payload=req.payload)
        _ledger_insert(conn, req, admin, decided.decided_by)


def test_a_change_applies_only_with_an_approval_consumed_in_the_same_transaction(conn):
    """Rule (b): two real transactions on the autocommit connection."""
    a, b = throwaway_pair(conn)
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    change = {"change": "SEPARATED_DUTY_ADD", "permission_a": a,
              "permission_b": b, "why": "held apart for this test"}
    # APPROVED but never consumed.
    req = _flow(conn, change, admin, officer, apply=False)
    with pytest.raises(psycopg.errors.RaiseException,
                       match="consumed in the same transaction"):
        with conn.transaction():
            _ledger_insert(conn, req, admin, officer)
    # Consumed in an EARLIER transaction, which committed.
    _approvals(conn).consume(req.id, actor_id=admin,
                             operation="dual_control.policy", case_id=None,
                             payload=req.payload)
    with pytest.raises(psycopg.errors.RaiseException,
                       match="consumed in the same transaction"):
        with conn.transaction():
            _ledger_insert(conn, req, admin, officer)
    # A payload that differs from the row, in the same transaction.
    other = _flow(conn, dict(change, why="another reason for the pair"),
                  admin, officer, apply=False)
    with pytest.raises(psycopg.errors.RaiseException,
                       match="exactly what was countersigned"):
        with conn.transaction():
            _approvals(conn).consume(other.id, actor_id=admin,
                                     operation="dual_control.policy",
                                     case_id=None, payload=other.payload)
            _ledger_insert(conn, other, admin, officer,
                           why="not what was countersigned")
    # An approval of another operation, and one raised in a case.
    lead = user(conn, "CASE_OWNER")
    case_id = _case(conn, lead)
    merge = _approvals(conn).request(
        operation="node.merge", case_id=case_id,
        payload={"source_node_id": str(uuid4())}, justification="j",
        requested_by=lead)
    with pytest.raises(psycopg.errors.RaiseException,
                       match="deployment-wide dual_control.policy approval"):
        with conn.transaction():
            _ledger_insert(conn, merge, admin, officer, permission_a=a,
                           permission_b=b, why="held apart for this test")
    assert conn.execute("SELECT count(*) FROM iam.separated_duty WHERE "
                        "permission_a = %s", (a,)).fetchone()[0] == 0


def test_the_proposer_cannot_countersign(conn):
    from noctornal_api.approvals import ApprovalError
    admin = user(conn, "SYS_ADMIN")
    user(conn, "SECURITY_OFFICER")
    a, b = throwaway_pair(conn)
    req = _svc(conn).propose(change={
        "change": "SEPARATED_DUTY_ADD", "permission_a": a, "permission_b": b,
        "why": "held apart for this test"}, justification="j",
        requested_by=admin)
    with pytest.raises(ApprovalError, match="two distinct humans"):
        _approvals(conn).decide(req.id, decided_by=admin, approve=True)
    with pytest.raises(_RollBack), conn.transaction():
        conn.execute("ALTER TABLE iam.dual_control_policy_change DISABLE "
                     "TRIGGER dual_control_change_checked")
        with pytest.raises(psycopg.errors.CheckViolation,
                           match="dual_control_change_two_people"):
            _ledger_insert(conn, req, admin, admin)
        raise _RollBack


def test_an_account_holding_both_roles_cannot_countersign_at_all(conn):
    """iam.separated_duty separates roles, not people (2026-09-24). An
    account holding SYS_ADMIN and SECURITY_OFFICER may refuse a
    change and never countersign one, and the ledger refuses it too."""
    from noctornal_api.approvals import ApprovalError
    from noctornal_api.dual_control import PolicyError
    admin = user(conn, "SYS_ADMIN")
    both = user(conn, "SYS_ADMIN", "SECURITY_OFFICER")
    user(conn, "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        req = _svc(conn).propose(change=_mode_change(), justification="j",
                                 requested_by=admin)
        with pytest.raises(ApprovalError, match="same person twice"):
            _approvals(conn).decide(req.id, decided_by=both, approve=True)
        # Forced past the service, the ledger says the same.
        conn.execute("""UPDATE core.approval_request
                           SET state = 'APPROVED', decided_by = %s,
                               decided_at = now()
                         WHERE id = %s""", (both, req.id))
        with pytest.raises(PolicyError, match="not a second person"):
            _svc(conn).apply(req.id, actor_id=admin)
        raise _RollBack
    with pytest.raises(_RollBack), conn.transaction():
        req = _svc(conn).propose(change=_mode_change(), justification="j",
                                 requested_by=admin)
        refused = _approvals(conn).decide(req.id, decided_by=both,
                                          approve=False)
        assert refused.state == "REJECTED"
        raise _RollBack


def test_the_first_run_shape_cannot_change_the_policy_alone(conn):
    """The first-run shape (2026-09-24). The first-run account
    holds SYS_ADMIN and SECURITY_OFFICER. It creates a second administrator,
    proposes from it and countersigns as itself: refused at decide and by
    the trigger at apply. With its own SYS_ADMIN then revoked it no longer
    holds dual_control.manage, and the reverse seven-day rule refuses it:
    it created the proposer's account with a role that proposes."""
    from noctornal_api.approvals import ApprovalError
    from noctornal_api.dual_control import PolicyError
    from noctornal_api.iam_admin import IamAdminService
    first = user(conn, "SYS_ADMIN", "SECURITY_OFFICER", "CASE_OWNER", "ANALYST",
                 clearance="RED", name="First run")
    with pytest.raises(_RollBack), conn.transaction():
        creds = IamAdminService(conn).create_analyst(
            email=f"{PREFIX}{uuid4().hex[:8]}@noctornal.test",
            display_name="Second admin", clearance="AMBER",
            roles=["SYS_ADMIN"], actor_id=first)
        second = creds.user_id
        # propose() refuses when nobody could countersign: an officer who is
        # not an administrator is what makes the proposal possible at all.
        user(conn, "SECURITY_OFFICER")
        req = _svc(conn).propose(change=_mode_change(), justification="j",
                                 requested_by=second)
        with pytest.raises(ApprovalError, match="same person twice"):
            _approvals(conn).decide(req.id, decided_by=first, approve=True)
        conn.execute("""UPDATE core.approval_request
                           SET state = 'APPROVED', decided_by = %s,
                               decided_at = now()
                         WHERE id = %s""", (first, req.id))
        _ledger_refuses(conn, req, second, "not a second person")
        with pytest.raises(PolicyError, match="cannot be used"):
            _svc(conn).apply(req.id, actor_id=second)

        IamAdminService(conn).revoke_role(first, role="SYS_ADMIN",
                                          actor_id=second)
        again = _svc(conn).propose(change=_mode_change(), justification="k",
                                   requested_by=second)
        with pytest.raises(ApprovalError, match="you created the account of"):
            _approvals(conn).decide(again.id, decided_by=first, approve=True)
        conn.execute("""UPDATE core.approval_request
                           SET state = 'APPROVED', decided_by = %s,
                               decided_at = now()
                         WHERE id = %s""", (first, again.id))
        _ledger_refuses(conn, again, second, "created the proposer's account")
        assert merge_mode(conn) == "PER_CASE"
        raise _RollBack


def test_one_approval_applies_once(conn):
    from noctornal_api.dual_control import PolicyError
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        req = _flow(conn, _mode_change(), admin, officer)
        with pytest.raises(PolicyError, match="cannot be used"):
            _svc(conn).apply(req.id, actor_id=admin)
        raise _RollBack


def test_a_stale_change_refuses_and_leaves_its_signature_unspent(conn):
    from noctornal_api.dual_control import PolicyError
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        first = _flow(conn, _mode_change(), admin, officer, apply=False)
        second = _flow(conn, _mode_change(), admin, officer, apply=False)
        assert first.payload == second.payload
        _svc(conn).apply(second.id, actor_id=admin)
        with pytest.raises(PolicyError, match="changed after this was countersigned"):
            _svc(conn).apply(first.id, actor_id=admin)
        assert _approvals(conn).get(first.id).state == "APPROVED"
        raise _RollBack


def test_an_approval_banked_across_later_changes_is_refused(conn):
    """The A-B-A case: a loosening approved and kept, the same
    loosening applied from a twin, a tightening after it, and the banked
    one spent last. `based_on` refuses it: it was countersigned against a
    version of the policy that no longer exists."""
    from noctornal_api.dual_control import PolicyError
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        _flow(conn, _mode_change("ALWAYS"), admin, officer)
        banked = _flow(conn, _mode_change("PER_CASE"), admin, officer,
                       apply=False)
        _flow(conn, _mode_change("PER_CASE"), admin, officer)
        _flow(conn, _mode_change("ALWAYS"), admin, officer)
        assert merge_mode(conn) == "ALWAYS"
        with pytest.raises(PolicyError, match="changed after this was countersigned"):
            _svc(conn).apply(banked.id, actor_id=admin)
        assert merge_mode(conn) == "ALWAYS"
        raise _RollBack


def test_a_pair_over_a_role_holding_both_is_refused_at_proposal_and_at_apply(conn):
    from noctornal_api.dual_control import PolicyError
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    a, b = throwaway_pair(conn)
    role = f"DCP_{uuid4().hex[:6].upper()}"
    conn.execute("INSERT INTO iam.role (key, display_name, description, "
                 "is_system) VALUES (%s, 'Holds both', 'dcp', false)", (role,))
    conn.execute("INSERT INTO iam.role_permission VALUES (%s, %s), (%s, %s)",
                 (role, a, role, b))
    change = {"change": "SEPARATED_DUTY_ADD", "permission_a": a,
              "permission_b": b, "why": "held apart for this test"}
    try:
        with pytest.raises(PolicyError, match=role):
            _svc(conn).propose(change=change, justification="j",
                               requested_by=admin)
        with pytest.raises(_RollBack), conn.transaction():
            req = _approvals(conn).request(
                operation="dual_control.policy", case_id=None,
                payload=dict(change, based_on=None), justification="j",
                requested_by=admin)
            _approvals(conn).decide(req.id, decided_by=officer, approve=True)
            with pytest.raises(PolicyError, match=role):
                _svc(conn).apply(req.id, actor_id=admin)
            assert _approvals(conn).get(req.id).state == "APPROVED"
            raise _RollBack
    finally:
        conn.execute("DELETE FROM iam.role_permission WHERE role_key = %s", (role,))
        conn.execute("DELETE FROM iam.role WHERE key = %s", (role,))


def test_a_pair_added_by_policy_holds_role_grants_apart(conn):
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    a, b = throwaway_pair(conn)
    with pytest.raises(_RollBack), conn.transaction():
        _flow(conn, {"change": "SEPARATED_DUTY_ADD", "permission_a": a,
                     "permission_b": b, "why": "held apart for this test"},
              admin, officer)
        row = conn.execute("SELECT origin, added_by_change FROM "
                           "iam.separated_duty WHERE permission_a = %s",
                           (a,)).fetchone()
        assert row[0] == "policy" and row[1] is not None
        conn.execute("INSERT INTO iam.role_permission VALUES ('ANALYST', %s)", (a,))
        with pytest.raises(psycopg.errors.RaiseException,
                           match="two-person control"), conn.transaction():
            conn.execute("INSERT INTO iam.role_permission VALUES ('ANALYST', %s)",
                         (b,))
        # And it comes out the same way it went in.
        _flow(conn, {"change": "SEPARATED_DUTY_REMOVE", "permission_a": b,
                     "permission_b": a}, admin, officer)
        assert conn.execute("SELECT count(*) FROM iam.separated_duty WHERE "
                            "permission_a = %s", (a,)).fetchone()[0] == 0
        raise _RollBack


def test_the_ledger_is_append_only(conn):
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        _flow(conn, _mode_change(), admin, officer)
        for sql in ("UPDATE iam.dual_control_policy_change SET why = 'x'",
                    "DELETE FROM iam.dual_control_policy_change"):
            with pytest.raises(psycopg.errors.RaiseException,
                               match="append-only"), conn.transaction():
                conn.execute(sql)
        # A plain TRUNCATE is refused before any trigger runs, because the
        # two policy tables reference the ledger; with CASCADE it reaches
        # the BEFORE TRUNCATE triggers, and one of the three refuses it.
        with pytest.raises(psycopg.errors.FeatureNotSupported), \
                conn.transaction():
            conn.execute("TRUNCATE iam.dual_control_policy_change")
        with pytest.raises(psycopg.errors.RaiseException,
                           match="append-only|is never truncated"), \
                conn.transaction():
            conn.execute("TRUNCATE iam.dual_control_policy_change CASCADE")
        assert conn.execute(
            "SELECT count(*) FROM pg_trigger WHERE tgname = "
            "'dual_control_change_no_truncate'").fetchone()[0] == 1
        raise _RollBack


def test_every_step_is_audited(conn):
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        req = _flow(conn, _mode_change(), admin, officer)
        actions = [r[0] for r in conn.execute(
            "SELECT action FROM audit.event WHERE object_id = %s AND case_id "
            "IS NULL ORDER BY seq", (req.id,))]
        assert actions == ["APPROVAL_REQUESTED", "APPROVAL_GRANTED",
                           "APPROVAL_CONSUMED"]
        change = conn.execute(
            "SELECT id FROM iam.dual_control_policy_change "
            "WHERE approval_request_id = %s", (req.id,)).fetchone()[0]
        row = conn.execute(
            "SELECT actor_id, case_id, detail FROM audit.event WHERE action = "
            "'DUAL_CONTROL_POLICY_CHANGED' AND object_id = %s", (change,)).fetchone()
        assert row[0] == admin and row[1] is None
        assert set(row[2]) == {"change", "operation", "from", "to",
                               "permission_a", "permission_b", "why",
                               "based_on", "approval_request_id",
                               "countersigned_by"}
        assert row[2]["countersigned_by"] == str(officer)
        assert _approvals(conn).get(req.id).result_ref == change
        raise _RollBack


# ---------------------------------------------------------------------------
# The seven-day rule
# ---------------------------------------------------------------------------

def _took_over(conn, action, officer_roles=("SECURITY_OFFICER",)):
    """An officer whose account a THIRD administrator touched, through the
    real IamAdminService method, so the rule is shown to cover any other
    account and not only the proposer's."""
    from noctornal_api.iam_admin import IamAdminService
    third = user(conn, "SYS_ADMIN", name="Third Admin")
    svc = IamAdminService(conn)
    if action == "USER_CREATED":
        return svc.create_analyst(
            email=f"{PREFIX}{uuid4().hex[:8]}@noctornal.test",
            display_name="New officer", clearance="AMBER",
            roles=["SECURITY_OFFICER"], actor_id=third).user_id, third
    if action == "ROLE_GRANTED":
        officer = user(conn, "ANALYST")
        svc.grant_role(officer, role="SECURITY_OFFICER", actor_id=third)
        return officer, third
    officer = user(conn, *officer_roles)
    if action == "PASSWORD_RESET":
        svc.reset_password(officer, actor_id=third)
    elif action == "TOTP_REENROLLED":
        svc.reenrol_totp(officer, actor_id=third)
    elif action == "USER_UNLOCKED":
        svc.unlock(officer, actor_id=third)
    elif action == "USER_REACTIVATED":
        # The load-bearing guard refuses deactivating the last active
        # officer, so a second one stands by.
        user(conn, "SECURITY_OFFICER")
        svc.set_active(officer, active=False, actor_id=third)
        svc.set_active(officer, active=True, actor_id=third)
    return officer, third


BLOCKING = ["PASSWORD_RESET", "TOTP_REENROLLED", "USER_REACTIVATED",
            "USER_UNLOCKED", "ROLE_GRANTED", "USER_CREATED"]


@pytest.mark.parametrize("action", BLOCKING)
def test_a_countersigner_someone_else_took_over_is_refused(conn, action):
    """Autocommit (rule c): the refusal row is written out of band, so it
    survives the caller's rollback, and the request stays PENDING."""
    from noctornal_api.approvals import ApprovalError
    admin = user(conn, "SYS_ADMIN")
    officer, third = _took_over(conn, action)
    a, b = throwaway_pair(conn)
    req = _svc(conn).propose(change={
        "change": "SEPARATED_DUTY_ADD", "permission_a": a, "permission_b": b,
        "why": "held apart for this test"}, justification="j",
        requested_by=admin)
    with pytest.raises(ApprovalError) as refused:
        with conn.transaction():
            _approvals(conn).decide(req.id, decided_by=officer, approve=True)
    said = str(refused.value)
    assert "You may countersign this from" in said and "Third Admin" in said
    assert said.count("UTC") == 2, said
    assert _approvals(conn).get(req.id).state == "PENDING"
    row = conn.execute(
        """SELECT actor_id, outcome, detail FROM audit.event
            WHERE action = 'DUAL_CONTROL_COUNTERSIGN_REFUSED'
              AND object_id = %s""", (req.id,)).fetchone()
    assert row is not None, "the refusal left no trace"
    assert row[0] == officer and row[1] == "DENIED"
    assert row[2]["reason"] == "countersigner_seasoning"
    assert row[2]["event_action"] == action
    assert row[2]["event_by"] == str(third)


def test_a_countersigner_may_still_refuse_while_blocked(conn):
    admin = user(conn, "SYS_ADMIN")
    officer, _ = _took_over(conn, "PASSWORD_RESET")
    a, b = throwaway_pair(conn)
    req = _svc(conn).propose(change={
        "change": "SEPARATED_DUTY_ADD", "permission_a": a, "permission_b": b,
        "why": "held apart for this test"}, justification="j",
        requested_by=admin)
    view = _svc(conn).countersign_view(_approvals(conn).get(req.id), officer)
    assert view["allowed"] is False and view["may_refuse"] is True
    assert "Third Admin" in view["reason"]
    done = _approvals(conn).decide(req.id, decided_by=officer, approve=False)
    assert done.state == "REJECTED"


def test_their_own_password_change_does_not_block_them(conn):
    from noctornal_api.approvals import countersign_block
    from noctornal_api.iam_admin import change_password
    officer = user(conn, "SECURITY_OFFICER")
    change_password(conn, officer, "a-long-new-password-of-their-own",
                    keep_session=None, via="account")
    # Even an action on the list is not counted when they did it themselves.
    conn.execute("""INSERT INTO audit.event (actor_id, actor_kind, action,
                        object_type, object_id, detail)
                    VALUES (%s, 'USER', 'PASSWORD_RESET', 'app_user', %s, '{}')""",
                 (officer, officer))
    assert countersign_block(conn, officer, "dual_control.countersign") is None


def test_after_the_window_they_may_countersign(conn):
    from noctornal_api.approvals import countersign_block, seasoning_days
    officer, _ = _took_over(conn, "PASSWORD_RESET")
    assert countersign_block(conn, officer, "dual_control.countersign") is not None
    assert conn.execute(
        "SELECT count(*) FROM iam.countersign_blocked_by(%s, "
        "'dual_control.countersign', now() + interval '8 days')",
        (officer,)).fetchone()[0] == 0
    assert seasoning_days(conn) == 7


def test_the_database_refuses_a_blocked_countersigner_at_apply(conn):
    """The decision written by direct UPDATE, which the approval guard
    allows for PENDING to APPROVED at now(), skipping the service's check:
    the ledger trigger refuses it anyway."""
    from noctornal_api.dual_control import PolicyError
    admin = user(conn, "SYS_ADMIN")
    with pytest.raises(_RollBack), conn.transaction():
        officer, _ = _took_over(conn, "TOTP_REENROLLED")
        req = _svc(conn).propose(change=_mode_change(), justification="j",
                                 requested_by=admin)
        conn.execute("""UPDATE core.approval_request
                           SET state = 'APPROVED', decided_by = %s,
                               decided_at = now()
                         WHERE id = %s""", (officer, req.id))
        _ledger_refuses(conn, req, admin,
                        "had its authenticator re-enrolled by someone else")
        with pytest.raises(PolicyError, match="cannot be used"):
            _svc(conn).apply(req.id, actor_id=admin)
        raise _RollBack


@pytest.mark.parametrize("how", ["officer_inactive", "officer_demoted",
                                 "proposer_demoted"])
def test_an_inactive_or_demoted_person_cannot_be_applied(conn, how):
    from noctornal_api.dual_control import PolicyError
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    user(conn, "SECURITY_OFFICER")   # so the change can still be proposed
    with pytest.raises(_RollBack), conn.transaction():
        req = _flow(conn, _mode_change(), admin, officer, apply=False)
        if how == "officer_inactive":
            conn.execute("UPDATE iam.app_user SET is_active = false "
                         "WHERE id = %s", (officer,))
            match = "countersigner is no longer"
        elif how == "officer_demoted":
            conn.execute("DELETE FROM iam.user_role WHERE user_id = %s",
                         (officer,))
            match = "countersigner is no longer"
        else:
            conn.execute("DELETE FROM iam.user_role WHERE user_id = %s",
                         (admin,))
            match = "proposer is no longer"
        with pytest.raises(PolicyError, match=match):
            _svc(conn).apply(req.id, actor_id=admin)
        assert merge_mode(conn) == "PER_CASE"
        raise _RollBack


def test_nobody_else_to_countersign_refuses_the_proposal(conn):
    from noctornal_api.dual_control import PolicyError
    admin = user(conn, "SYS_ADMIN", "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        conn.execute("""UPDATE iam.app_user u SET is_active = false
                         WHERE u.id <> %s AND EXISTS (
                           SELECT 1 FROM iam.user_role ur
                             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                            WHERE ur.user_id = u.id
                              AND rp.permission_key = 'dual_control.countersign')""",
                     (admin,))
        with pytest.raises(PolicyError, match="Nobody could countersign"):
            _svc(conn).propose(change=_mode_change(), justification="j",
                               requested_by=admin)
        raise _RollBack


# ---------------------------------------------------------------------------
# Who is told, and what the screen counts
# ---------------------------------------------------------------------------

def test_a_policy_request_notifies_countersigners_and_no_other_administrator(conn):
    admin, other_admin = user(conn, "SYS_ADMIN"), user(conn, "SYS_ADMIN")
    officer = user(conn, "SECURITY_OFFICER")
    both = user(conn, "SYS_ADMIN", "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        req = _svc(conn).propose(
            change=_mode_change(),
            justification="QUOTE-ME-NOT operation nightjar", requested_by=admin)
        assert req.approvers_notified >= 1
        rows = conn.execute(
            """SELECT recipient_id, classification, case_id, subject, summary,
                      body FROM notify.notification
                WHERE object_type = 'approval_request' AND object_id = %s""",
            (req.id,)).fetchall()
        recipients = {r[0] for r in rows}
        assert officer in recipients
        assert admin not in recipients and other_admin not in recipients
        assert both not in recipients
        for r in rows:
            assert r[1] == "GREEN" and r[2] is None
            assert "QUOTE-ME-NOT" not in (r[3] + r[4] + r[5])
        held = {r[0] for r in conn.execute(
            """SELECT DISTINCT ur.user_id FROM iam.user_role ur
                 JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                WHERE rp.permission_key = 'dual_control.countersign'""")}
        assert recipients <= held
        raise _RollBack


def test_awaiting_global_signature_counts_what_the_user_may_sign(conn):
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    both = user(conn, "SYS_ADMIN", "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        before = _approvals(conn).awaiting_global_signature(officer)
        _svc(conn).propose(change=_mode_change(), justification="j",
                           requested_by=admin)
        assert _approvals(conn).awaiting_global_signature(officer) == before + 1
        assert _approvals(conn).awaiting_global_signature(admin) == 0
        assert _approvals(conn).awaiting_global_signature(both) == 0
        raise _RollBack


def test_the_case_counts_are_bounded_by_the_viewers_labels(conn):
    """Counted over cases the viewer can OPEN, labels dominated and a
    live assignment (2026-09-24); nothing at all for an administrator
    with no case."""
    comp = "DCP-RED-COMP"
    lead = user(conn, "CASE_OWNER", clearance="RED", compartments=(comp,))
    red_viewer = user(conn, "SECURITY_OFFICER", clearance="RED",
                      compartments=(comp,))
    amber_viewer = user(conn, "SECURITY_OFFICER", clearance="AMBER")
    red_admin = user(conn, "SYS_ADMIN", clearance="RED", compartments=(comp,))
    case_id = _case(conn, lead, classification="RED", compartments=(comp,))
    conn.execute('UPDATE core."case" SET dual_control_merge = true WHERE id = %s',
                 (case_id,))
    for who in (red_viewer, amber_viewer):
        conn.execute("""INSERT INTO iam.case_assignment
                            (case_id, user_id, role_key, granted_by)
                        VALUES (%s, %s, 'READ_ONLY', %s)""", (case_id, who, lead))
    svc = _svc(conn)

    def counted(viewer, clearance, held):
        body = svc.overview(viewer, clearance=clearance, compartments=held)
        op = next(o for o in body["operations"] if o["key"] == "node.merge")
        assert "cases_total" not in op and "total" not in str(body.keys())
        return op["cases_requiring"]

    assert counted(red_viewer, "RED", frozenset({comp})) >= 1
    assert counted(amber_viewer, "AMBER", frozenset()) in (None, 0)
    assert counted(red_admin, "RED", frozenset({comp})) is None
    preview = svc.preview({"change": "OPERATION_MODE", "operation": "node.merge",
                           "from": "PER_CASE", "to": "ALWAYS", "based_on": None},
                          viewer_id=red_admin, clearance="RED",
                          compartments=frozenset({comp}))
    assert preview["cases_affected"] is None
    assert preview["effect"] == ("Every merge on this deployment will need a "
                                 "second signature.")


def test_the_readiness_row_says_whether_two_people_can_change_it(conn):
    from noctornal_api import readiness
    assert "dual_control_policy_changeable" in readiness.CHECK_NAMES
    assert "dual_control_policy_changeable" not in readiness.BLOCKING_CHECKS
    assert readiness.UI_TARGETS["dual_control_policy_changeable"] == "admin/accounts"
    with pytest.raises(_RollBack), conn.transaction():
        conn.execute("UPDATE iam.app_user SET is_active = false WHERE is_active")
        user(conn, "SYS_ADMIN")
        # The only countersigner also holds SYS_ADMIN: one person, no pair.
        user(conn, "SYS_ADMIN", "SECURITY_OFFICER")
        row = readiness._dual_control_policy_changeable(conn)
        assert not row.ok
        assert "0 may countersign" in row.evidence
        assert "first-run account" in row.action
        user(conn, "SECURITY_OFFICER")
        row = readiness._dual_control_policy_changeable(conn)
        assert row.ok and "two different people" in row.evidence
        raise _RollBack


# ---------------------------------------------------------------------------
# Out of band, and never waiting on itself
# ---------------------------------------------------------------------------

def test_a_refused_apply_leaves_no_open_transaction_and_its_record(conn):
    """Rule (c): the refusal is written after the apply's transaction has
    rolled back, on a second connection, and the audit chain is free the
    moment it returns: an unrelated audited action completes at once."""
    from noctornal_api.db import connect
    from noctornal_api.dual_control import PolicyError
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    a, b = throwaway_pair(conn)
    req = _flow(conn, {"change": "SEPARATED_DUTY_ADD", "permission_a": a,
                       "permission_b": b, "why": "held apart for this test"},
                admin, officer, apply=False)
    conn.execute("DELETE FROM iam.user_role WHERE user_id = %s", (admin,))
    with pytest.raises(PolicyError, match="proposer is no longer"):
        _svc(conn).apply(req.id, actor_id=admin)
    assert conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    assert _approvals(conn).get(req.id).state == "APPROVED"
    row = conn.execute(
        """SELECT outcome, detail->>'reason' FROM audit.event
            WHERE action = 'DUAL_CONTROL_APPLY_REFUSED' AND object_id = %s""",
        (req.id,)).fetchone()
    assert row is not None and row[0] == "DENIED"
    assert "proposer is no longer" in row[1]
    with connect() as other:
        other.execute("SELECT set_config('lock_timeout', '2s', false)")
        other.execute("""INSERT INTO audit.event (actor_id, actor_kind, action,
                             object_type, detail)
                         VALUES (%s, 'USER', 'DCP_UNRELATED', 'test', '{}')""",
                      (officer,))


def test_a_refusal_inside_an_audited_transaction_does_not_wait_on_itself(conn):
    """The deadlock this guards against: a caller whose transaction
    has audited holds the chain lock, and a second connection waiting for
    it would wait on the caller for ever. The helper sees the lock and
    writes on the caller's connection instead, at once."""
    from noctornal_api.approvals import holds_audit_chain_lock, record_out_of_band
    officer = user(conn, "SECURITY_OFFICER")
    target = uuid4()
    with pytest.raises(_RollBack), conn.transaction():
        assert holds_audit_chain_lock(conn) is False
        conn.execute("""INSERT INTO audit.event (actor_id, actor_kind, action,
                             object_type, detail)
                         VALUES (%s, 'USER', 'DCP_FIRST', 'test', '{}')""",
                     (officer,))
        assert holds_audit_chain_lock(conn) is True
        started = time.monotonic()
        record_out_of_band(conn, action="DCP_REFUSED", actor_id=officer,
                           object_type="test", object_id=target, case_id=None,
                           detail={"reason": "test"})
        assert time.monotonic() - started < 3
        assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id "
                            "= %s", (target,)).fetchone()[0] == 1
        raise _RollBack
    # Outside any transaction the row goes on a second connection and stays.
    record_out_of_band(conn, action="DCP_REFUSED", actor_id=officer,
                       object_type="test", object_id=target, case_id=None,
                       detail={"reason": "test"})
    assert conn.execute("SELECT count(*) FROM audit.event WHERE object_id = %s",
                        (target,)).fetchone()[0] == 1


# ---------------------------------------------------------------------------
# The migration's own directions, rolled back
# ---------------------------------------------------------------------------

def _migration(conn):
    path = next(VERSIONS.glob("*_dual_control_policy.py"))
    spec = importlib.util.spec_from_file_location("m_dcp", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.run = lambda sql: conn.execute(sql)
    return module


def test_the_migration_round_trips(conn):
    m = _migration(conn)
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        for name in ("iam.dual_control_operation", "iam.dual_control_policy_change"):
            assert conn.execute("SELECT to_regclass(%s)", (name,)).fetchone()[0] is None
        assert conn.execute("SELECT count(*) FROM iam.permission WHERE key LIKE "
                            "'dual_control.%'").fetchone()[0] == 0
        m.upgrade()
        assert merge_mode(conn) == "PER_CASE"
        raise _RollBack


def test_the_downgrade_refuses_while_the_policy_is_stricter_than_its_default(conn):
    m = _migration(conn)
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    with pytest.raises(_RollBack), conn.transaction():
        _flow(conn, _mode_change("ALWAYS"), admin, officer)
        with pytest.raises(psycopg.errors.RaiseException,
                           match=f"refusing to downgrade {m.revision}: "
                                 "node.merge is ALWAYS"), conn.transaction():
            m.downgrade()
        raise _RollBack


def test_the_downgrade_refuses_while_a_policy_pair_exists(conn):
    m = _migration(conn)
    admin, officer = user(conn, "SYS_ADMIN"), user(conn, "SECURITY_OFFICER")
    a, b = throwaway_pair(conn)
    with pytest.raises(_RollBack), conn.transaction():
        _flow(conn, {"change": "SEPARATED_DUTY_ADD", "permission_a": a,
                     "permission_b": b, "why": "held apart for this test"},
              admin, officer)
        with pytest.raises(psycopg.errors.RaiseException,
                           match=f"refusing to downgrade {m.revision}: 1 pair "
                                 f"was added by a two-person change \\({a} and {b}\\)"
                           ), conn.transaction():
            m.downgrade()
        raise _RollBack


def test_the_upgrade_refuses_a_pair_whose_record_was_lost(conn):
    m = _migration(conn)
    a, b = throwaway_pair(conn)
    with pytest.raises(_RollBack), conn.transaction():
        m.downgrade()
        conn.execute("INSERT INTO iam.separated_duty (permission_a, "
                     "permission_b, why) VALUES (%s, %s, 'lost record')", (a, b))
        conn.execute("""INSERT INTO audit.event (actor_kind, action, object_type,
                             detail)
                         VALUES ('SYSTEM', 'DUAL_CONTROL_POLICY_CHANGED',
                                 'dual_control_policy_change', %s)""",
                     (Json({"change": "SEPARATED_DUTY_ADD", "permission_a": b,
                            "permission_b": a}),))
        with pytest.raises(psycopg.errors.RaiseException,
                           match=f"refusing to upgrade {m.revision}: "
                                 f"iam.separated_duty holds {a} and {b}"
                           ), conn.transaction():
            m.upgrade()
        raise _RollBack


def test_a_later_migration_installs_a_pair_by_disabling_the_guard_by_name(conn):
    a, b = throwaway_pair(conn)
    with pytest.raises(_RollBack), conn.transaction():
        conn.execute("ALTER TABLE iam.separated_duty DISABLE TRIGGER "
                     "separated_duty_written_by_ledger")
        conn.execute("INSERT INTO iam.separated_duty (permission_a, "
                     "permission_b, why) VALUES (%s, %s, 'a release pair')", (a, b))
        conn.execute("ALTER TABLE iam.separated_duty ENABLE TRIGGER "
                     "separated_duty_written_by_ledger")
        assert conn.execute("SELECT origin FROM iam.separated_duty WHERE "
                            "permission_a = %s", (a,)).fetchone()[0] == "migration"
        raise _RollBack
