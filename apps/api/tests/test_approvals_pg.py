"""Four-eyes approval: the lifecycle, and the four properties that make it
a control rather than a form to fill in.

docs/05: "Dual control for the genuinely irreversible ... Two distinct
humans, enforced by constraint." The constraint is asserted here against a
real database, because that is where it lives -- a test of the Python guard
alone would pass on a service that had been refactored around it.

Env-gated on DATABASE_URL like every other _pg suite.
"""
from __future__ import annotations

import os
from datetime import date, timedelta
from uuid import uuid4

import pytest

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; approvals are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    from noctornal_api.db import connect
    c = connect()
    yield c
    sub = "(SELECT id FROM iam.app_user WHERE email LIKE 'appr-%@noctornal.test')"
    csub = f'(SELECT id FROM core."case" WHERE owner_user_id IN {sub})'
    with c.transaction():
        c.execute(f"DELETE FROM core.node_merge_edge WHERE merge_id IN "
                  f"(SELECT id FROM core.node_merge WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM core.node_merge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM notify.delivery WHERE notification_id IN "
                  f"(SELECT id FROM notify.notification WHERE case_id IN {csub})")
        c.execute(f"DELETE FROM notify.notification WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.approval_request WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.assertion WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.edge WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM core.node WHERE case_id IN {csub}")
        c.execute(f"DELETE FROM iam.case_assignment WHERE case_id IN {csub}")
        c.execute(f'DELETE FROM core."case" WHERE id IN {csub}')
        c.execute(f"DELETE FROM iam.user_role WHERE user_id IN {sub}")
        c.execute("DELETE FROM iam.app_user WHERE email LIKE 'appr-%@noctornal.test'")
    c.close()


def _user(conn, clearance="AMBER") -> "uuid4":
    from noctornal_api.stores import PgUserStore
    uid = PgUserStore(conn).create_user(
        f"appr-{uuid4().hex[:8]}@noctornal.test", "Approver", "x" * 20)
    # New users default to GREEN, and a case owner below their own case's
    # classification is refused (correctly) at creation.
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (clearance, uid))
    return uid


def _case(conn, owner) -> "uuid4":
    from noctornal_api.cases import CaseService
    return CaseService(conn).create(
        code=f"OP-APPR-{uuid4().hex[:6]}", title="Approvals",
        legal_basis="production order", retention_until=date(2028, 1, 1),
        review_due=date(2027, 1, 1), owner_user_id=owner, created_by=owner)


def _payload(a=None, b=None) -> dict:
    return {"source_node_id": str(a or uuid4()),
            "target_node_id": str(b or uuid4()),
            "reason": "same PGP fingerprint", "basis_selector_id": None}


@pytest.fixture
def svc(conn):
    from noctornal_api.approvals import ApprovalService
    return ApprovalService(conn)


# --- the lifecycle ------------------------------------------------------

def test_request_approve_consume(conn, svc):
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()

    req = svc.request(operation="node.merge", case_id=case_id, payload=payload,
                      justification="two handles, one fingerprint",
                      requested_by=alice)
    assert req.state == "PENDING" and req.is_actionable

    decided = svc.decide(req.id, decided_by=bob, approve=True, note="agreed")
    assert decided.state == "APPROVED" and decided.decided_by == bob

    consumed = svc.consume(req.id, actor_id=alice, operation="node.merge",
                           case_id=case_id, payload=payload)
    assert consumed.state == "CONSUMED" and consumed.consumed_at is not None


def test_two_distinct_humans_is_enforced_by_the_database(conn, svc):
    """docs/05 says "enforced by constraint" and means it. The service
    refuses self-approval with a readable message; this asserts that the
    guarantee survives the service being refactored around."""
    import psycopg

    alice = _user(conn)
    case_id = _case(conn, alice)
    req = svc.request(operation="node.merge", case_id=case_id,
                      payload=_payload(), justification="j", requested_by=alice)

    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """UPDATE core.approval_request
                  SET state = 'APPROVED', decided_by = %s, decided_at = now()
                WHERE id = %s""",
            (alice, req.id))


def test_the_service_refuses_self_approval_readably(conn, svc):
    from noctornal_api.approvals import ApprovalError
    alice = _user(conn)
    case_id = _case(conn, alice)
    req = svc.request(operation="node.merge", case_id=case_id,
                      payload=_payload(), justification="j", requested_by=alice)
    with pytest.raises(ApprovalError, match="two distinct humans"):
        svc.decide(req.id, decided_by=alice, approve=True)


# --- the four properties ------------------------------------------------

def test_an_approval_binds_to_the_exact_parameters(conn, svc):
    """The property the whole thing rests on.

    Without it, "Bob approved it" means Bob approved whatever Alice did
    next: get a nod for merging two obviously-identical spam bots, then
    execute a merge of the two nodes the case actually turns on.
    """
    from noctornal_api.approvals import ApprovalError
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    approved_payload = _payload()

    req = svc.request(operation="node.merge", case_id=case_id,
                      payload=approved_payload, justification="j",
                      requested_by=alice)
    svc.decide(req.id, decided_by=bob, approve=True)

    substituted = dict(approved_payload, target_node_id=str(uuid4()))
    with pytest.raises(ApprovalError):
        svc.consume(req.id, actor_id=alice, operation="node.merge",
                    case_id=case_id, payload=substituted)
    # And the approval is still live, so the legitimate action is not lost
    # as collateral from a rejected substitution.
    assert svc.get(req.id).state == "APPROVED"


def test_an_approval_is_single_use(conn, svc):
    from noctornal_api.approvals import ApprovalError
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()
    req = svc.request(operation="node.merge", case_id=case_id, payload=payload,
                      justification="j", requested_by=alice)
    svc.decide(req.id, decided_by=bob, approve=True)

    svc.consume(req.id, actor_id=alice, operation="node.merge",
                case_id=case_id, payload=payload)
    with pytest.raises(ApprovalError):
        svc.consume(req.id, actor_id=alice, operation="node.merge",
                    case_id=case_id, payload=payload)


def test_expiry_is_computed_never_swept(conn, svc):
    """There is no EXPIRED state and no job that sets one, so a dead
    scheduler cannot silently leave month-old approvals usable."""
    from noctornal_api.approvals import ApprovalError
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()
    req = svc.request(operation="node.merge", case_id=case_id, payload=payload,
                      justification="j", requested_by=alice)
    svc.decide(req.id, decided_by=bob, approve=True)

    # Both timestamps move: `approval_expiry_sane` refuses a row whose
    # expiry precedes its request, so an expiry cannot be back-dated on its
    # own -- which is the constraint doing its job, not an obstacle.
    conn.execute(
        """UPDATE core.approval_request
              SET requested_at = now() - interval '2 hours',
                  expires_at   = now() - interval '1 hour'
            WHERE id = %s""", (req.id,))
    with pytest.raises(ApprovalError):
        svc.consume(req.id, actor_id=alice, operation="node.merge",
                    case_id=case_id, payload=payload)
    # The row still says APPROVED — expiry is a comparison, not a state.
    assert svc.get(req.id).state == "APPROVED"
    assert svc.get(req.id).is_expired()


def test_an_expired_request_cannot_be_decided(conn, svc):
    """An approver looking at a week-old request is looking at week-old
    facts."""
    from noctornal_api.approvals import ApprovalError
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    req = svc.request(operation="node.merge", case_id=case_id,
                      payload=_payload(), justification="j", requested_by=alice)
    conn.execute(
        """UPDATE core.approval_request
              SET requested_at = now() - interval '2 hours',
                  expires_at   = now() - interval '1 hour'
            WHERE id = %s""", (req.id,))
    with pytest.raises(ApprovalError, match="expired"):
        svc.decide(req.id, decided_by=bob, approve=True)


def test_only_the_requester_may_consume(conn, svc):
    """The approval says "you may do the thing you asked to do". Letting the
    approver execute it instead splits one action across two names in the
    audit log, and "who did this" is the question the system exists to
    answer."""
    from noctornal_api.approvals import ApprovalError
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()
    req = svc.request(operation="node.merge", case_id=case_id, payload=payload,
                      justification="j", requested_by=alice)
    svc.decide(req.id, decided_by=bob, approve=True)
    with pytest.raises(ApprovalError):
        svc.consume(req.id, actor_id=bob, operation="node.merge",
                    case_id=case_id, payload=payload)


def test_a_rejection_is_terminal(conn, svc):
    """A single request must not be re-decided until somebody says yes.
    Asking again is allowed — it just has to be a NEW request, which leaves
    a trail."""
    from noctornal_api.approvals import ApprovalError
    alice, bob, carol = _user(conn), _user(conn), _user(conn)
    case_id = _case(conn, alice)
    req = svc.request(operation="node.merge", case_id=case_id,
                      payload=_payload(), justification="j", requested_by=alice)
    svc.decide(req.id, decided_by=bob, approve=False, note="different people")
    with pytest.raises(ApprovalError, match="already rejected"):
        svc.decide(req.id, decided_by=carol, approve=True)


def test_a_rejected_request_cannot_be_consumed(conn, svc):
    from noctornal_api.approvals import ApprovalError
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()
    req = svc.request(operation="node.merge", case_id=case_id, payload=payload,
                      justification="j", requested_by=alice)
    svc.decide(req.id, decided_by=bob, approve=False)
    with pytest.raises(ApprovalError):
        svc.consume(req.id, actor_id=alice, operation="node.merge",
                    case_id=case_id, payload=payload)


def test_an_approval_does_not_cross_cases(conn, svc):
    """The case is in the hash. The same two node ids could exist in two
    cases, and an approval granted in a training case must not consume in a
    live one."""
    from noctornal_api.approvals import ApprovalError
    alice, bob = _user(conn), _user(conn)
    case_a, case_b = _case(conn, alice), _case(conn, alice)
    payload = _payload()
    req = svc.request(operation="node.merge", case_id=case_a, payload=payload,
                      justification="j", requested_by=alice)
    svc.decide(req.id, decided_by=bob, approve=True)
    with pytest.raises(ApprovalError):
        svc.consume(req.id, actor_id=alice, operation="node.merge",
                    case_id=case_b, payload=payload)


def test_duplicate_pending_requests_are_refused(conn, svc):
    """Two live requests for the same action are two chances at a yes."""
    from noctornal_api.approvals import ApprovalError
    alice = _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()
    svc.request(operation="node.merge", case_id=case_id, payload=payload,
                justification="j", requested_by=alice)
    with pytest.raises(ApprovalError, match="already awaiting"):
        svc.request(operation="node.merge", case_id=case_id, payload=payload,
                    justification="j again", requested_by=alice)


def test_asking_again_after_a_rejection_is_allowed(conn, svc):
    """Approver shopping should leave a trail, not be impossible: a unit
    where a second opinion is unobtainable is a unit that stops asking."""
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()
    first = svc.request(operation="node.merge", case_id=case_id, payload=payload,
                        justification="j", requested_by=alice)
    svc.decide(first.id, decided_by=bob, approve=False)
    second = svc.request(operation="node.merge", case_id=case_id, payload=payload,
                         justification="new evidence: matching PGP", requested_by=alice)
    assert second.id != first.id
    # Both are visible. The history is the control on shopping.
    states = {r.id: r.state for r in svc.list_for_case(case_id)}
    assert states[first.id] == "REJECTED" and states[second.id] == "PENDING"


def test_withdrawal_is_not_a_decision(conn, svc):
    alice = _user(conn)
    case_id = _case(conn, alice)
    req = svc.request(operation="node.merge", case_id=case_id,
                      payload=_payload(), justification="j", requested_by=alice)
    withdrawn = svc.withdraw(req.id, actor_id=alice)
    assert withdrawn.state == "WITHDRAWN"
    assert withdrawn.decided_by is None, "a withdrawn request never had a decision"


def test_only_the_requester_may_withdraw(conn, svc):
    from noctornal_api.approvals import ApprovalError
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    req = svc.request(operation="node.merge", case_id=case_id,
                      payload=_payload(), justification="j", requested_by=alice)
    with pytest.raises(ApprovalError):
        svc.withdraw(req.id, actor_id=bob)


def test_a_justification_is_mandatory(conn, svc):
    from noctornal_api.approvals import ApprovalError
    alice = _user(conn)
    case_id = _case(conn, alice)
    with pytest.raises(ApprovalError):
        svc.request(operation="node.merge", case_id=case_id, payload=_payload(),
                    justification="   ", requested_by=alice)


def test_an_unregistered_operation_is_refused(conn, svc):
    from noctornal_api.approvals import ApprovalError
    alice = _user(conn)
    case_id = _case(conn, alice)
    with pytest.raises(ApprovalError, match="unknown operation"):
        svc.request(operation="graph.wipe", case_id=case_id, payload={},
                    justification="j", requested_by=alice)


# --- hashing ------------------------------------------------------------

def test_payload_hash_ignores_key_order_but_not_values():
    from noctornal_api.approvals import payload_hash
    case_id = uuid4()
    a = payload_hash("node.merge", case_id, {"x": 1, "y": 2})
    b = payload_hash("node.merge", case_id, {"y": 2, "x": 1})
    c = payload_hash("node.merge", case_id, {"x": 1, "y": 3})
    assert a == b
    assert a != c


def test_payload_hash_survives_a_json_round_trip():
    """The payload is stored as jsonb and read back before being re-hashed.
    If the round trip changed the hash, every consume would fail -- loudly,
    but only in production."""
    import json

    from noctornal_api.approvals import payload_hash
    case_id = uuid4()
    payload = {"source_node_id": str(uuid4()), "target_node_id": str(uuid4()),
               "reason": "same fingerprint", "basis_selector_id": None}
    assert payload_hash("node.merge", case_id, payload) == \
        payload_hash("node.merge", case_id, json.loads(json.dumps(payload)))


def test_the_operation_is_in_the_hash():
    """An approval to merge two nodes must not consume as an approval to
    purge the evidence they hang off."""
    from noctornal_api.approvals import payload_hash
    case_id = uuid4()
    payload = {"id": "x"}
    assert payload_hash("node.merge", case_id, payload) != \
        payload_hash("evidence.purge", case_id, payload)


# --- the per-case switch ------------------------------------------------

def test_merge_dual_control_is_off_by_default(conn):
    """docs/05 scopes dual control to the genuinely irreversible, and a
    merge here is a ledger with an exact restore. A second signature on
    every entity-resolution decision is a control that gets switched off."""
    from noctornal_api.approvals import case_requires_dual_control
    alice = _user(conn)
    case_id = _case(conn, alice)
    assert case_requires_dual_control(conn, case_id, "node.merge") is False


def test_the_switch_turns_it_on(conn):
    from noctornal_api.approvals import case_requires_dual_control
    alice = _user(conn)
    case_id = _case(conn, alice)
    conn.execute('UPDATE core."case" SET dual_control_merge = true WHERE id = %s',
                 (case_id,))
    assert case_requires_dual_control(conn, case_id, "node.merge") is True


def test_the_irreversible_operations_are_unconditional(conn):
    """There is no version of "delete the case" or "destroy the evidence"
    that is worth doing on one signature, so those are not switchable."""
    from noctornal_api.approvals import case_requires_dual_control
    alice = _user(conn)
    case_id = _case(conn, alice)
    for operation in ("case.delete", "evidence.purge",
                      "collection_account.reveal", "role.manage"):
        assert case_requires_dual_control(conn, case_id, operation) is True


# --- audit --------------------------------------------------------------

def test_every_step_leaves_an_audit_row(conn, svc):
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()
    req = svc.request(operation="node.merge", case_id=case_id, payload=payload,
                      justification="j", requested_by=alice)
    svc.decide(req.id, decided_by=bob, approve=True)
    svc.consume(req.id, actor_id=alice, operation="node.merge",
                case_id=case_id, payload=payload)
    actions = [r[0] for r in conn.execute(
        "SELECT action FROM audit.event WHERE object_id = %s ORDER BY seq",
        (req.id,)).fetchall()]
    assert actions == ["APPROVAL_REQUESTED", "APPROVAL_GRANTED", "APPROVAL_CONSUMED"]


def test_a_refused_consume_is_audited_with_the_reason(conn, svc):
    """The caller gets one uninformative message so a failed consume is not
    an oracle; the server-side row records WHICH condition failed, because
    "somebody replayed an approval" and "somebody's approval timed out" want
    different responses."""
    from noctornal_api.approvals import ApprovalError
    alice, bob = _user(conn), _user(conn)
    case_id = _case(conn, alice)
    payload = _payload()
    req = svc.request(operation="node.merge", case_id=case_id, payload=payload,
                      justification="j", requested_by=alice)
    svc.decide(req.id, decided_by=bob, approve=True)
    with pytest.raises(ApprovalError):
        svc.consume(req.id, actor_id=alice, operation="node.merge",
                    case_id=case_id, payload=dict(payload, reason="something else"))
    row = conn.execute(
        """SELECT detail->>'reason', outcome FROM audit.event
            WHERE object_id = %s AND action = 'APPROVAL_CONSUME_REFUSED'""",
        (req.id,)).fetchone()
    assert row is not None
    assert row[0] == "payload_mismatch"
    assert row[1] == "DENIED"


def test_the_ttl_is_taken_from_the_operation(conn, svc):
    from noctornal_api.approvals import OPERATIONS
    alice = _user(conn)
    case_id = _case(conn, alice)
    req = svc.request(operation="node.merge", case_id=case_id,
                      payload=_payload(), justification="j", requested_by=alice)
    expected = OPERATIONS["node.merge"].ttl
    actual = req.expires_at - req.requested_at
    assert abs(actual - expected) < timedelta(seconds=5)


def test_credential_reveal_has_the_shortest_ttl():
    """A persona credential approved this morning and used this evening is
    not the operation anybody agreed to (docs/04)."""
    from noctornal_api.approvals import OPERATIONS
    shortest = min(OPERATIONS.values(), key=lambda o: o.ttl)
    assert shortest.key == "collection_account.reveal"


def test_the_approver_permission_matches_the_operation():
    """An approver drawn from a wider pool than the actors is a rubber
    stamp with a job title, so every operation's approver permission is the
    permission the operation itself needs."""
    from noctornal_api.approvals import OPERATIONS
    assert OPERATIONS["node.merge"].permission == "graph.merge"
    assert OPERATIONS["evidence.purge"].permission == "evidence.purge"
    assert OPERATIONS["case.delete"].permission == "case.delete"
