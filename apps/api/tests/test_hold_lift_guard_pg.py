"""The database refuses a hold lift that no second person approved (decision 229).

Migration exhibit_hold_lift_two_people puts a guard on an exhibit's hold, as 0076 put one on a case's
merge switch: the hold comes off only in a transaction that consumed a `legal_hold.lift_exhibit`
approval for that exhibit and that epoch, whoever writes it, the schema owner and the system role
included, and the epoch moves only with the hold. Migration case_hold_lift_two_people does the same
for a case's hold with `legal_hold.lift_case`. The services and the routes over them are
`test_hold_lift_two_person_pg.py` and `test_hold_lift_two_person_http_pg.py`.

Accounts `g44t-*` (the prefix `evidence_retention_support` cleans up).
"""
from __future__ import annotations

import psycopg
import pytest

import evidence_retention_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

REFUSED = "takes a legal_hold.lift_exhibit approval for the hold as it stands"


def _held_exhibit(conn):
    """A case with two Lead investigators and an exhibit under a hold."""
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, second, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, "AMBER")
    conn.execute("UPDATE core.evidence SET legal_hold = true, legal_hold_reason = %s "
                 "WHERE id = %s", ("court order 2026-0042", exhibit))
    return boss, second, case_id, exhibit


def _held(conn, exhibit) -> bool:
    return conn.execute("SELECT legal_hold FROM core.evidence WHERE id = %s",
                        (exhibit,)).fetchone()[0]


def _lift(conn, exhibit) -> None:
    conn.execute("UPDATE core.evidence SET legal_hold = false, legal_hold_reason = NULL "
                 "WHERE id = %s", (exhibit,))


def _consume(conn, rid, *, actor, operation, case_id, payload) -> None:
    from noctornal_api.approvals import ApprovalService
    ApprovalService(conn).consume(rid, actor_id=actor, operation=operation,
                                  case_id=case_id, payload=payload)


def test_the_database_refuses_a_hold_lift_without_a_consumed_approval(conn):
    from noctornal_api.approvals import LIFT_EXHIBIT, lift_exhibit_payload

    boss, second, case_id, exhibit = _held_exhibit(conn)
    # Nobody is exempt: the system role is the one that lifts, and the owner is who a migration and an
    # operator's correction run as.
    for role in (None, s.WORKER_ROLE):
        with pytest.raises(psycopg.errors.CheckViolation, match=REFUSED):
            with conn.transaction():
                if role:
                    conn.execute(f"SET LOCAL ROLE {role}")
                _lift(conn, exhibit)
    assert _held(conn, exhibit)

    # The right approval, consumed in the lift's own transaction, is what lets it through, whoever
    # writes the row.
    _case, epoch = g.exhibit_epoch(conn, exhibit)
    rid = g.exhibit_lift_approval(conn, exhibit, requester=boss, approver=second)
    with conn.transaction():
        _consume(conn, rid, actor=boss, operation=LIFT_EXHIBIT, case_id=case_id,
                 payload=lift_exhibit_payload(exhibit, epoch))
        conn.execute(f"SET LOCAL ROLE {s.WORKER_ROLE}")
        _lift(conn, exhibit)
    assert not _held(conn, exhibit)


def test_an_approval_for_anything_else_does_not_lift_the_hold(conn):
    """Another exhibit's lift, another epoch's, another operation's, and one consumed in an earlier
    transaction: none of them lifts this hold."""
    from noctornal_api.approvals import (
        LIFT_EXHIBIT,
        ApprovalService,
        lift_exhibit_payload,
    )

    boss, second, case_id, exhibit = _held_exhibit(conn)
    other = s.exhibit(conn, case_id, boss, "AMBER")
    conn.execute("UPDATE core.evidence SET legal_hold = true, legal_hold_reason = %s "
                 "WHERE id = %s", ("court order 2026-0043", other))
    _case, epoch = g.exhibit_epoch(conn, exhibit)

    # Another exhibit's approval, spent in this transaction.
    rid = g.exhibit_lift_approval(conn, other, requester=boss, approver=second)
    with pytest.raises(psycopg.errors.CheckViolation, match=REFUSED):
        with conn.transaction():
            _consume(conn, rid, actor=boss, operation=LIFT_EXHIBIT, case_id=case_id,
                     payload=lift_exhibit_payload(other, g.exhibit_epoch(conn, other)[1]))
            _lift(conn, exhibit)

    # This exhibit's approval for an earlier epoch: the hold was placed again for another reason.
    stale = g.lift_approval(conn, operation=LIFT_EXHIBIT, case_id=case_id,
                            payload=lift_exhibit_payload(exhibit, epoch),
                            requester=boss, approver=second)
    conn.execute("UPDATE core.evidence SET legal_hold_reason = %s WHERE id = %s",
                 ("a second order, 2026-0050", exhibit))
    with pytest.raises(psycopg.errors.CheckViolation, match=REFUSED):
        with conn.transaction():
            _consume(conn, stale, actor=boss, operation=LIFT_EXHIBIT, case_id=case_id,
                     payload=lift_exhibit_payload(exhibit, epoch))
            _lift(conn, exhibit)

    # Another operation's approval, for this case.
    purge = {"case_id": str(case_id), "evidence_ids": [str(exhibit)],
             "authority": "g44 schedule"}
    svc = ApprovalService(conn)
    raised = svc.request(operation="evidence.purge", case_id=case_id, payload=purge,
                         justification="an early destruction", requested_by=boss)
    svc.decide(raised.id, decided_by=second, approve=True)
    with pytest.raises(psycopg.errors.CheckViolation, match=REFUSED):
        with conn.transaction():
            _consume(conn, raised.id, actor=boss, operation="evidence.purge",
                     case_id=case_id, payload=purge)
            _lift(conn, exhibit)

    # The right approval, but consumed in a transaction of its own that has committed.
    now_epoch = g.exhibit_epoch(conn, exhibit)[1]
    spent = g.lift_approval(conn, operation=LIFT_EXHIBIT, case_id=case_id,
                            payload=lift_exhibit_payload(exhibit, now_epoch),
                            requester=boss, approver=second)
    _consume(conn, spent, actor=boss, operation=LIFT_EXHIBIT, case_id=case_id,
             payload=lift_exhibit_payload(exhibit, now_epoch))
    with pytest.raises(psycopg.errors.CheckViolation, match=REFUSED):
        with conn.transaction():
            _lift(conn, exhibit)
    assert _held(conn, exhibit)


def test_legal_hold_epoch_moves_only_with_the_hold(conn):
    boss, second, case_id, exhibit = _held_exhibit(conn)
    start = g.exhibit_epoch(conn, exhibit)[1]
    assert start == 1, "placing the hold moved the epoch once"
    with pytest.raises(psycopg.errors.CheckViolation, match="moves only with the legal hold"):
        with conn.transaction():
            conn.execute("UPDATE core.evidence SET legal_hold_epoch = legal_hold_epoch + 5 "
                         "WHERE id = %s", (exhibit,))
    # Another column, and the hold placed again for the same reason, leave it where it is.
    conn.execute("UPDATE core.evidence SET title = 'renamed' WHERE id = %s", (exhibit,))
    conn.execute("UPDATE core.evidence SET legal_hold = true, legal_hold_reason = %s "
                 "WHERE id = %s", ("court order 2026-0042", exhibit))
    assert g.exhibit_epoch(conn, exhibit)[1] == start
    # The hold placed again for another reason is another hold.
    conn.execute("UPDATE core.evidence SET legal_hold_reason = %s WHERE id = %s",
                 ("a second order, 2026-0050", exhibit))
    assert g.exhibit_epoch(conn, exhibit)[1] == start + 1


def test_a_hold_placed_again_starts_a_new_epoch(conn):
    """A lift and a new hold leave the epoch two past the one the first lift was approved against, so
    no approval of the first hold describes the second (0076's A-B-A)."""
    boss, second, _case_id, exhibit = _held_exhibit(conn)
    first = g.exhibit_epoch(conn, exhibit)[1]
    g.lift_exhibit(conn, exhibit, requester=boss, approver_id=second)
    assert not _held(conn, exhibit)
    conn.execute("UPDATE core.evidence SET legal_hold = true, legal_hold_reason = %s "
                 "WHERE id = %s", ("a fresh order, 2026-0051", exhibit))
    assert g.exhibit_epoch(conn, exhibit)[1] == first + 2


# --- a case's hold (migration case_hold_lift_two_people) ----------------------------------

CASE_REFUSED = "takes a legal_hold.lift_case approval for the hold as it stands"


def _held_case(conn):
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    conn.execute('UPDATE core."case" SET legal_hold = true, legal_hold_reason = %s '
                 "WHERE id = %s", ("court order 2026-0042", case_id))
    return boss, second, case_id


def _case_held(conn, case_id) -> bool:
    return conn.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]


def _lift_case(conn, case_id) -> None:
    conn.execute('UPDATE core."case" SET legal_hold = false, legal_hold_reason = NULL '
                 "WHERE id = %s", (case_id,))


def test_the_database_refuses_a_case_hold_lift_without_a_consumed_approval(conn):
    from noctornal_api.approvals import LIFT_CASE, lift_case_payload

    boss, second, case_id = _held_case(conn)
    for role in (None, s.WORKER_ROLE):
        with pytest.raises(psycopg.errors.CheckViolation, match=CASE_REFUSED):
            with conn.transaction():
                if role:
                    conn.execute(f"SET LOCAL ROLE {role}")
                _lift_case(conn, case_id)
    assert _case_held(conn, case_id)

    # Another case's approval, and this case's for an earlier epoch, lift nothing.
    other = g.case(conn, boss)
    conn.execute('UPDATE core."case" SET legal_hold = true, legal_hold_reason = %s '
                 "WHERE id = %s", ("court order 2026-0043", other))
    elsewhere = g.case_lift_approval(conn, other, requester=boss, approver=second)
    stale = g.case_lift_approval(conn, case_id, requester=boss, approver=second)
    epoch = g.case_epoch(conn, case_id)
    conn.execute('UPDATE core."case" SET legal_hold_reason = %s WHERE id = %s',
                 ("a second order, 2026-0050", case_id))
    for rid, owner_case, payload_epoch in ((elsewhere, other, g.case_epoch(conn, other)),
                                           (stale, case_id, epoch)):
        with pytest.raises(psycopg.errors.CheckViolation, match=CASE_REFUSED):
            with conn.transaction():
                _consume(conn, rid, actor=boss, operation=LIFT_CASE, case_id=owner_case,
                         payload=lift_case_payload(payload_epoch))
                _lift_case(conn, case_id)
    assert _case_held(conn, case_id)

    # The right approval, consumed in the lift's own transaction, lets it through as the system
    # role.
    rid = g.case_lift_approval(conn, case_id, requester=boss, approver=second)
    with conn.transaction():
        _consume(conn, rid, actor=boss, operation=LIFT_CASE, case_id=case_id,
                 payload=lift_case_payload(g.case_epoch(conn, case_id)))
        conn.execute(f"SET LOCAL ROLE {s.WORKER_ROLE}")
        _lift_case(conn, case_id)
    assert not _case_held(conn, case_id)


def test_a_case_hold_epoch_moves_only_with_the_hold(conn):
    _boss, _second, case_id = _held_case(conn)
    start = g.case_epoch(conn, case_id)
    assert start == 1, "placing the hold moved the epoch once"
    with pytest.raises(psycopg.errors.CheckViolation, match="moves only with the legal hold"):
        with conn.transaction():
            conn.execute('UPDATE core."case" SET legal_hold_epoch = legal_hold_epoch + 1 '
                         "WHERE id = %s", (case_id,))
    conn.execute('UPDATE core."case" SET title = %s WHERE id = %s', ("renamed", case_id))
    assert g.case_epoch(conn, case_id) == start
    conn.execute('UPDATE core."case" SET legal_hold_reason = %s WHERE id = %s',
                 ("a second order, 2026-0050", case_id))
    assert g.case_epoch(conn, case_id) == start + 1


# --- a collected document's hold (migration document_hold_lift_two_people) ------------------

DOCUMENT_REFUSED = "takes a legal_hold.lift_document approval for the hold as it stands"


def _held_post(conn):
    """A post with two versions under a hold one RED Lead investigator placed, and a second one."""
    from noctornal_api.retention import RetentionService
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    v1, source = g.collected_document(conn, case_id, external_id="post:g229", cited=False)
    v2, _ = g.collected_document(conn, case_id, source=source, external_id="post:g229",
                                 version=2, supersedes=v1, cited=False)
    RetentionService(conn).set_document_legal_hold(
        v2, actor_id=boss, on=True, reason="court order 2026-0042", clearance="RED")
    return boss, second, v1, v2


def _document_held(conn, doc) -> bool:
    return conn.execute("SELECT legal_hold FROM collect.document WHERE id = %s",
                        (doc,)).fetchone()[0]


def _lift_versions(conn, *docs) -> None:
    conn.execute("UPDATE collect.document SET legal_hold = false, legal_hold_reason = NULL "
                 "WHERE id = ANY(%s::uuid[])", ([str(d) for d in docs],))


def test_the_database_refuses_a_document_hold_lift_without_a_consumed_approval(conn):
    from noctornal_api.approvals import LIFT_DOCUMENT, lift_document_payload

    boss, second, v1, v2 = _held_post(conn)
    for role in (None, s.WORKER_ROLE):
        with pytest.raises(psycopg.errors.CheckViolation, match=DOCUMENT_REFUSED):
            with conn.transaction():
                if role:
                    conn.execute(f"SET LOCAL ROLE {role}")
                _lift_versions(conn, v1)
    assert _document_held(conn, v1) and _document_held(conn, v2)

    # An approval that names the later version only does not release the earlier one.
    versions = g.held_versions(conn, v2)
    partial = {str(v2): versions[str(v2)]}
    rid = g.lift_approval(conn, operation=LIFT_DOCUMENT, case_id=None,
                          payload=lift_document_payload(v2, partial),
                          requester=boss, approver=second)
    with pytest.raises(psycopg.errors.CheckViolation, match=DOCUMENT_REFUSED):
        with conn.transaction():
            _consume(conn, rid, actor=boss, operation=LIFT_DOCUMENT, case_id=None,
                     payload=lift_document_payload(v2, partial))
            _lift_versions(conn, v1, v2)
    assert _document_held(conn, v1) and _document_held(conn, v2)

    # The approval that names every version, consumed in the lift's own transaction, releases them,
    # whoever writes the rows.
    rid = g.document_lift_approval(conn, v2, requester=boss, approver=second)
    with conn.transaction():
        _consume(conn, rid, actor=boss, operation=LIFT_DOCUMENT, case_id=None,
                 payload=lift_document_payload(v2, versions))
        conn.execute(f"SET LOCAL ROLE {s.WORKER_ROLE}")
        _lift_versions(conn, v1, v2)
    assert not _document_held(conn, v1) and not _document_held(conn, v2)


def test_a_document_hold_epoch_moves_only_with_the_hold(conn):
    _boss, _second, v1, _v2 = _held_post(conn)
    start = g.held_versions(conn, v1)[str(v1)]
    assert start == 1, "placing the hold moved the epoch once"
    with pytest.raises(psycopg.errors.CheckViolation, match="moves only with the legal hold"):
        with conn.transaction():
            conn.execute("UPDATE collect.document SET legal_hold_epoch = 7 WHERE id = %s",
                         (v1,))
    conn.execute("UPDATE collect.document SET triage_state = 'TRIAGED' WHERE id = %s", (v1,))
    assert g.held_versions(conn, v1)[str(v1)] == start


def test_placing_a_hold_is_never_refused_by_the_guard(conn):
    """Preservation never waits (decision 144): the guard reads nothing when a hold goes on."""
    boss, _second, case_id, _exhibit = _held_exhibit(conn)
    fresh = s.exhibit(conn, case_id, boss, "RED")
    with conn.transaction():
        conn.execute(f"SET LOCAL ROLE {s.WORKER_ROLE}")
        conn.execute("UPDATE core.evidence SET legal_hold = true, legal_hold_reason = %s "
                     "WHERE id = %s", ("preserve pending review", fresh))
    assert _held(conn, fresh)
