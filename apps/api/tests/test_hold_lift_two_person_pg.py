"""Lifting a legal hold takes two people (decision 229), at the service.

`RetentionService.set_legal_hold(on=False)` spends a `legal_hold.lift_exhibit` approval inside the lift's
own transaction: the requester asked for it, a different account approved it, it is bound to this exhibit,
this case and the hold as it stands, it lasts 72 hours and is spent once, and the colleague who approved
it is judged again at the spend. A refused lift writes one DENIED row that survives its rollback and leaves
the approval unspent. The database's own refusal is `test_hold_lift_guard_pg.py`; the routes are
`test_hold_lift_two_person_http_pg.py`.

Accounts `g44t-*`.
"""
from __future__ import annotations

from datetime import timedelta

import psycopg
import pytest

import evidence_retention_support as g
import rls_support as s

pytestmark = g.GATED

conn = g.conn

REASON = "Court order 2026-0042: preserve, informant identity at issue"


def _held_exhibit(conn, *, exhibit_class="AMBER", second_clearance="RED"):
    """A case with two Lead investigators, each holding retention.manage globally and on the case,
    and an exhibit under a hold the first placed."""
    from noctornal_api.retention import RetentionService
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, second_clearance, roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, second, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, exhibit_class)
    RetentionService(conn).set_legal_hold(exhibit, actor_id=boss, on=True, reason=REASON)
    return boss, second, case_id, exhibit


def _held(conn, exhibit) -> bool:
    return conn.execute("SELECT legal_hold FROM core.evidence WHERE id = %s",
                        (exhibit,)).fetchone()[0]


def _state(conn, rid) -> str:
    return conn.execute("SELECT state FROM core.approval_request WHERE id = %s",
                        (rid,)).fetchone()[0]


def _lift(conn, exhibit, *, actor, rid, case_id, approver=None):
    from noctornal_api.retention import RetentionService
    RetentionService(conn).set_legal_hold(
        exhibit, actor_id=actor, on=False, reason=g.LIFT_REASON,
        approval_request_id=rid,
        approver=approver if approver is not None else g.approver(conn, rid, case_id))


def test_a_hold_is_lifted_only_with_a_second_persons_approval(conn):
    from noctornal_api.retention import LIFT_TAKES_TWO, RetentionError, RetentionService

    boss, second, case_id, exhibit = _held_exhibit(conn)
    with pytest.raises(RetentionError) as refused:
        RetentionService(conn).set_legal_hold(exhibit, actor_id=boss, on=False,
                                              reason=g.LIFT_REASON)
    assert str(refused.value) == LIFT_TAKES_TWO
    assert _held(conn, exhibit), "one person lifted the hold"

    rid = g.exhibit_lift_approval(conn, exhibit, requester=boss, approver=second)
    _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id)
    assert not _held(conn, exhibit)
    assert _state(conn, rid) == "CONSUMED"


def test_one_person_cannot_request_and_approve_their_own_lift(conn):
    from noctornal_api.approvals import (
        LIFT_EXHIBIT,
        ApprovalError,
        ApprovalService,
        lift_exhibit_payload,
    )

    boss, _second, case_id, exhibit = _held_exhibit(conn)
    svc = ApprovalService(conn)
    raised = svc.request(operation=LIFT_EXHIBIT, case_id=case_id,
                         payload=lift_exhibit_payload(exhibit, g.exhibit_epoch(conn, exhibit)[1]),
                         justification=g.LIFT_JUSTIFICATION, requested_by=boss)
    with pytest.raises(ApprovalError, match="two distinct humans"):
        svc.decide(raised.id, decided_by=boss, approve=True)
    # And the database's own guarantee (0028), whatever the service says.
    with pytest.raises(psycopg.errors.CheckViolation, match="approval_two_distinct_humans"):
        with conn.transaction():
            conn.execute("""UPDATE core.approval_request
                               SET state = 'APPROVED', decided_by = requested_by,
                                   decided_at = now()
                             WHERE id = %s""", (raised.id,))
    assert _state(conn, raised.id) == "PENDING"


def test_a_lift_approval_is_for_this_exhibit_and_this_case_only(conn):
    from noctornal_api.retention import RetentionConflict, RetentionService

    boss, second, case_id, exhibit = _held_exhibit(conn)
    other = s.exhibit(conn, case_id, boss, "AMBER")
    RetentionService(conn).set_legal_hold(other, actor_id=boss, on=True, reason=REASON)
    rid = g.exhibit_lift_approval(conn, exhibit, requester=boss, approver=second)
    with pytest.raises(RetentionConflict, match="cannot be used for this operation"):
        _lift(conn, other, actor=boss, rid=rid, case_id=case_id)
    assert _held(conn, other) and _state(conn, rid) == "APPROVED"

    # The same exhibit id under another case is not this approval's either: an exhibit's case is fixed
    # (0140), so an approval's case is checked through its hash.
    elsewhere = g.case(conn, boss)
    s.assign(conn, elsewhere, boss, "CASE_OWNER")
    s.assign(conn, elsewhere, second, "CASE_OWNER")
    stray = s.exhibit(conn, elsewhere, boss, "AMBER")
    RetentionService(conn).set_legal_hold(stray, actor_id=boss, on=True, reason=REASON)
    with pytest.raises(RetentionConflict, match="cannot be used for this operation"):
        _lift(conn, stray, actor=boss, rid=rid, case_id=elsewhere)
    assert _held(conn, stray)

    _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id)
    assert not _held(conn, exhibit)


def test_a_lift_approval_is_spent_once(conn):
    from noctornal_api.retention import RetentionConflict, RetentionService

    boss, second, case_id, exhibit = _held_exhibit(conn)
    rid = g.exhibit_lift_approval(conn, exhibit, requester=boss, approver=second)
    _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id)
    RetentionService(conn).set_legal_hold(exhibit, actor_id=boss, on=True, reason=REASON)
    with pytest.raises(RetentionConflict, match="cannot be used for this operation"):
        _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id)
    assert _held(conn, exhibit)


def test_a_lift_approval_expires_after_the_catalogue_ttl(conn):
    """72 hours from the request, computed and never swept: an approval three days and a minute old
    lifts nothing, and its row still says APPROVED."""
    from noctornal_api.approvals import LIFT_TTL, OPERATIONS
    from noctornal_api.retention import RetentionConflict

    assert OPERATIONS["legal_hold.lift_exhibit"].ttl == LIFT_TTL == timedelta(hours=72)
    boss, second, case_id, exhibit = _held_exhibit(conn)
    rid = g.exhibit_lift_approval(conn, exhibit, requester=boss, approver=second)
    row = conn.execute("SELECT expires_at - requested_at FROM core.approval_request "
                       "WHERE id = %s", (rid,)).fetchone()
    assert row[0] == timedelta(hours=72)
    # Back-dated, the one direction 0074 allows: a request never gains time.
    conn.execute("""UPDATE core.approval_request
                       SET requested_at = requested_at - interval '72 hours 1 minute',
                           expires_at = expires_at - interval '72 hours 1 minute'
                     WHERE id = %s""", (rid,))
    with pytest.raises(RetentionConflict, match="cannot be used for this operation"):
        _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id)
    assert _held(conn, exhibit) and _state(conn, rid) == "APPROVED"


def test_a_lift_approval_is_void_after_the_hold_is_replaced(conn):
    """A-B-A: an approval for one hold is not spent on the next one, after a lift and a new hold."""
    from noctornal_api.retention import RetentionConflict, RetentionService

    boss, second, case_id, exhibit = _held_exhibit(conn)
    banked = g.exhibit_lift_approval(conn, exhibit, requester=boss, approver=second)
    g.lift_exhibit(conn, exhibit, requester=second, approver_id=boss)
    RetentionService(conn).set_legal_hold(exhibit, actor_id=boss, on=True,
                                          reason="a fresh preservation order, 2026-0051")
    with pytest.raises(RetentionConflict, match="cannot be used for this operation"):
        _lift(conn, exhibit, actor=boss, rid=banked, case_id=case_id)
    assert _held(conn, exhibit) and _state(conn, banked) == "APPROVED"


def test_a_failed_lift_leaves_the_approval_unspent(conn, monkeypatch):
    """A lift that fails after its approval was consumed rolls the spend back with it: the approval is
    APPROVED again, never CONSUMED with the hold still on."""
    from noctornal_api.retention import RetentionService

    boss, second, case_id, exhibit = _held_exhibit(conn)
    rid = g.exhibit_lift_approval(conn, exhibit, requester=boss, approver=second)
    real = RetentionService._audit

    def failing(self, case, actor, action, detail, **kw):
        if action == "LEGAL_HOLD_LIFTED":
            raise RuntimeError("the lift's audit write failed")
        return real(self, case, actor, action, detail, **kw)

    monkeypatch.setattr(RetentionService, "_audit", failing)
    with pytest.raises(RuntimeError, match="audit write failed"):
        _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id)
    monkeypatch.undo()
    assert _held(conn, exhibit) and _state(conn, rid) == "APPROVED"
    _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id)
    assert not _held(conn, exhibit) and _state(conn, rid) == "CONSUMED"


@pytest.mark.parametrize("change", ["clearance", "permission", "deactivated",
                                    "someone_else"])
def test_the_approver_who_changes_before_the_spend_voids_the_lift(conn, change):
    """The second person is judged at the spend, not only when they approved: one whose clearance fell
    below the exhibit, who no longer holds retention.manage on the case, or whose account was
    deactivated, approves nothing, and the approval stays unspent. Facts about anybody but the
    approval's own approver judge nobody."""
    from dataclasses import replace

    from noctornal_api.retention import RetentionConflict

    boss, second, case_id, exhibit = _held_exhibit(conn, exhibit_class="RED")
    rid = g.exhibit_lift_approval(conn, exhibit, requester=boss, approver=second)
    judged = None
    if change == "clearance":
        conn.execute("UPDATE iam.app_user SET tlp_clearance = 'AMBER' WHERE id = %s", (second,))
    elif change == "permission":
        conn.execute("UPDATE iam.case_assignment SET role_key = 'READ_ONLY' "
                     "WHERE case_id = %s AND user_id = %s", (case_id, second))
    elif change == "deactivated":
        conn.execute("UPDATE iam.app_user SET is_active = false WHERE id = %s", (second,))
    else:
        judged = replace(g.approver(conn, rid, case_id), user_id=boss)
    with pytest.raises(RetentionConflict, match="no longer"):
        _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id, approver=judged)
    assert _held(conn, exhibit) and _state(conn, rid) == "APPROVED"
    expected = {"clearance": "approver_below_material",
                "permission": "approver_no_longer_permitted",
                "deactivated": "approver_no_longer_permitted",
                "someone_else": "approver_not_judged"}[change]
    [(detail, outcome, object_id, _case)] = g.audit_rows(
        conn, "LEGAL_HOLD_LIFT_REFUSED", object_id=exhibit)
    assert (detail["refusal"], detail["stage"], outcome) == (expected, "spend", "DENIED")


def test_the_lift_audit_row_names_who_asked_and_who_approved(conn):
    boss, second, case_id, exhibit = _held_exhibit(conn)
    rid = g.exhibit_lift_approval(conn, exhibit, requester=boss, approver=second)
    _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id)
    [(detail, outcome, object_id, row_case)] = g.audit_rows(
        conn, "LEGAL_HOLD_LIFTED", object_id=exhibit)
    assert (outcome, object_id, row_case) == ("SUCCESS", exhibit, case_id)
    decided_at = conn.execute("SELECT decided_at FROM core.approval_request WHERE id = %s",
                              (rid,)).fetchone()[0]
    assert detail["approval_request_id"] == str(rid)
    assert detail["requested_by"] == str(boss)
    assert detail["approved_by"] == str(second)
    assert detail["approved_at"] == decided_at.isoformat()
    assert detail["prior_reason"] == REASON and detail["reason"] == g.LIFT_REASON
    # Ids and a time, never a name.
    assert "display_name" not in str(detail) and "RLS analyst" not in str(detail)
    [(consumed, *_rest)] = g.audit_rows(conn, "APPROVAL_CONSUMED", object_id=rid)
    assert consumed["approved_by"] == str(second)


def test_a_refused_lift_writes_one_denied_row_that_survives_the_rollback(conn):
    from noctornal_api.retention import RetentionError, RetentionService

    boss, _second, _case_id, exhibit = _held_exhibit(conn)
    with pytest.raises(RetentionError):
        RetentionService(conn).set_legal_hold(exhibit, actor_id=boss, on=False,
                                              reason=g.LIFT_REASON)
    rows = g.audit_rows(conn, "LEGAL_HOLD_LIFT_REFUSED", object_id=exhibit)
    assert len(rows) == 1
    detail, outcome, _object, _case = rows[0]
    assert outcome == "DENIED"
    assert detail == {"evidence_id": str(exhibit), "scope": "evidence",
                      "reason": g.LIFT_REASON, "refusal": "no_approval",
                      "stage": "spend"}
    assert not g.audit_rows(conn, "LEGAL_HOLD_LIFTED", object_id=exhibit)


def test_a_lift_of_an_exhibit_that_is_not_held_is_refused(conn):
    from noctornal_api.retention import RetentionConflict

    boss, second, case_id, exhibit = _held_exhibit(conn)
    rid = g.lift_exhibit(conn, exhibit, requester=boss, approver_id=second)
    with pytest.raises(RetentionConflict, match="not under a legal hold of its own"):
        _lift(conn, exhibit, actor=boss, rid=rid, case_id=case_id)


def test_a_hold_may_still_be_placed_by_one_person_below_the_material(conn):
    """Preservation never waits for a clearance (decision 144): placing stays one person's act."""
    from noctornal_api.retention import RetentionService

    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, lead, "CASE_OWNER")
    exhibit = s.exhibit(conn, case_id, boss, "RED")
    RetentionService(conn).set_legal_hold(exhibit, actor_id=lead, on=True, reason=REASON)
    assert _held(conn, exhibit)


# --- a case's hold ------------------------------------------------------------------------

def _held_case(conn, *, second_clearance="RED", exhibit_class="AMBER"):
    """A case under a hold the first of two Lead investigators placed, each holding retention.manage
    globally and on the case, with one exhibit in it."""
    from noctornal_api.retention import RetentionService
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, second_clearance, roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    s.assign(conn, case_id, boss, "CASE_OWNER")
    s.assign(conn, case_id, second, "CASE_OWNER")
    s.exhibit(conn, case_id, boss, exhibit_class)
    RetentionService(conn).set_case_legal_hold(case_id, actor_id=boss, on=True, reason=REASON)
    return boss, second, case_id


def _case_held(conn, case_id) -> bool:
    return conn.execute('SELECT legal_hold FROM core."case" WHERE id = %s',
                        (case_id,)).fetchone()[0]


def _lift_case(conn, case_id, *, actor, rid, approver=None, lifter=("RED", [])):
    from noctornal_api.retention import RetentionService
    return RetentionService(conn).set_case_legal_hold(
        case_id, actor_id=actor, on=False, reason=g.LIFT_REASON, lifter_ceiling=lifter,
        document_ceiling=lifter, approval_request_id=rid,
        approver=approver if approver is not None else g.approver(conn, rid, case_id))


def test_a_case_hold_is_lifted_only_with_a_second_persons_approval(conn):
    from noctornal_api.retention import LIFT_TAKES_TWO, RetentionError, RetentionService

    boss, second, case_id = _held_case(conn)
    with pytest.raises(RetentionError) as refused:
        RetentionService(conn).set_case_legal_hold(
            case_id, actor_id=boss, on=False, reason=g.LIFT_REASON,
            lifter_ceiling=("RED", []))
    assert str(refused.value) == LIFT_TAKES_TWO
    assert _case_held(conn, case_id), "one person lifted the case's hold"

    rid = g.case_lift_approval(conn, case_id, requester=boss, approver=second)
    out = _lift_case(conn, case_id, actor=boss, rid=rid)
    assert out["legal_hold"] is False and not _case_held(conn, case_id)
    assert _state(conn, rid) == "CONSUMED"
    [(detail, outcome, object_id, row_case)] = g.audit_rows(
        conn, "LEGAL_HOLD_LIFTED", object_id=case_id)
    assert (outcome, object_id, row_case) == ("SUCCESS", case_id, case_id)
    assert (detail["approval_request_id"], detail["requested_by"], detail["approved_by"]) == (
        str(rid), str(boss), str(second))
    assert detail["scope"] == "case" and detail["prior_reason"] == REASON


def test_a_case_lift_approval_is_for_this_case_and_this_hold_only(conn):
    from noctornal_api.retention import RetentionConflict, RetentionService

    boss, second, case_id = _held_case(conn)
    other = g.case(conn, boss)
    s.assign(conn, other, boss, "CASE_OWNER")
    s.assign(conn, other, second, "CASE_OWNER")
    RetentionService(conn).set_case_legal_hold(other, actor_id=boss, on=True, reason=REASON)
    rid = g.case_lift_approval(conn, case_id, requester=boss, approver=second)
    with pytest.raises(RetentionConflict, match="cannot be used for this operation"):
        _lift_case(conn, other, actor=boss, rid=rid)
    assert _case_held(conn, other) and _state(conn, rid) == "APPROVED"

    # A-B-A: an approval for one hold is not spent on the next one, after a lift and a new hold.
    banked = g.case_lift_approval(conn, case_id, requester=boss, approver=second)
    _lift_case(conn, case_id, actor=boss, rid=rid)
    RetentionService(conn).set_case_legal_hold(case_id, actor_id=boss, on=True,
                                               reason="a fresh preservation order, 2026-0051")
    with pytest.raises(RetentionConflict, match="cannot be used for this operation"):
        _lift_case(conn, case_id, actor=boss, rid=banked)
    assert _case_held(conn, case_id) and _state(conn, banked) == "APPROVED"


def test_the_case_lift_approver_is_judged_against_material_lodged_since_they_approved(conn):
    """An approver cleared to AMBER approves the lift of a case of AMBER material; a RED exhibit lodged
    before the spend is material they never reviewed and may not read, so the lift is refused, the
    approval stays unspent and the refusal is recorded."""
    from noctornal_api.retention import RetentionConflict

    boss, second, case_id = _held_case(conn, second_clearance="AMBER")
    rid = g.case_lift_approval(conn, case_id, requester=boss, approver=second)
    s.exhibit(conn, case_id, boss, "RED")
    with pytest.raises(RetentionConflict, match="no longer"):
        _lift_case(conn, case_id, actor=boss, rid=rid)
    assert _case_held(conn, case_id) and _state(conn, rid) == "APPROVED"
    [(detail, outcome, *_rest)] = g.audit_rows(conn, "LEGAL_HOLD_LIFT_REFUSED",
                                               object_id=case_id)
    assert (detail["refusal"], detail["stage"], outcome) == (
        "approver_below_material", "spend", "DENIED")


def test_a_case_lift_request_from_a_lifter_below_the_material_is_refused_and_recorded(conn):
    from noctornal_api.retention import RetentionError, RetentionService

    boss, _second, case_id = _held_case(conn, exhibit_class="RED")
    lead = g.user(conn, "AMBER", roles=("CASE_OWNER",))
    s.assign(conn, case_id, lead, "CASE_OWNER")
    svc = RetentionService(conn)
    with pytest.raises(RetentionError, match="cleared for everything"):
        svc.case_lift_request(case_id, actor_id=lead, justification=g.LIFT_JUSTIFICATION,
                              lifter_ceiling=("AMBER", []))
    [(detail, outcome, *_rest)] = g.audit_rows(conn, "LEGAL_HOLD_LIFT_REFUSED",
                                               object_id=case_id)
    assert (detail["refusal"], detail["stage"], outcome) == (
        "lifter_below_material", "request", "DENIED")
    assert svc.case_lift_request(case_id, actor_id=boss, justification=g.LIFT_JUSTIFICATION,
                                 lifter_ceiling=("RED", [])) == {
        "epoch": 1, "classification": "RED", "compartments": []}


# --- a collected document's hold ------------------------------------------------------------

def _held_post(conn, *, first_class="AMBER"):
    """A post with two versions under a hold the first of two RED Lead investigators placed; the
    first version at `first_class`."""
    from noctornal_api.retention import RetentionService
    boss = g.user(conn, "RED", roles=("CASE_OWNER",))
    second = g.user(conn, "RED", roles=("CASE_OWNER",))
    case_id = g.case(conn, boss)
    v1, source = g.collected_document(conn, case_id, classification=first_class,
                                      external_id="post:g229", cited=False)
    v2, _ = g.collected_document(conn, case_id, source=source, external_id="post:g229",
                                 version=2, supersedes=v1, cited=False)
    RetentionService(conn).set_document_legal_hold(
        v2, actor_id=boss, on=True, reason=REASON, clearance="RED")
    return boss, second, v1, v2


def _document_held(conn, doc) -> bool:
    return conn.execute("SELECT legal_hold FROM collect.document WHERE id = %s",
                        (doc,)).fetchone()[0]


def _lift_document(conn, doc, *, actor, rid, approver=None):
    from noctornal_api.retention import RetentionService
    return RetentionService(conn).set_document_legal_hold(
        doc, actor_id=actor, on=False, reason=g.LIFT_REASON, clearance="RED",
        approval_request_id=rid,
        approver=approver if approver is not None else g.approver(conn, rid, None))


def test_a_document_hold_is_lifted_only_with_a_second_persons_approval(conn):
    from noctornal_api.retention import LIFT_TAKES_TWO, RetentionError, RetentionService

    boss, second, v1, v2 = _held_post(conn)
    with pytest.raises(RetentionError) as refused:
        RetentionService(conn).set_document_legal_hold(
            v2, actor_id=boss, on=False, reason=g.LIFT_REASON, clearance="RED")
    assert str(refused.value) == LIFT_TAKES_TWO
    assert _document_held(conn, v1) and _document_held(conn, v2)

    rid = g.document_lift_approval(conn, v2, requester=boss, approver=second)
    out = _lift_document(conn, v2, actor=boss, rid=rid)
    assert out["legal_hold"] is False and out["versions"] == 2
    assert not _document_held(conn, v1) and not _document_held(conn, v2)
    assert _state(conn, rid) == "CONSUMED"
    [(detail, outcome, object_id, row_case)] = g.audit_rows(
        conn, "LEGAL_HOLD_LIFTED", object_id=v2)
    assert (outcome, object_id, row_case) == ("SUCCESS", v2, None)
    assert (detail["requested_by"], detail["approved_by"], detail["approval_request_id"]) == (
        str(boss), str(second), str(rid))


def test_a_document_lift_approval_is_void_once_what_it_releases_changes(conn):
    """Placed again for another reason, every version's epoch moves, so an approval for the hold as it
    was is not spent on the hold as it is."""
    from noctornal_api.retention import RetentionConflict, RetentionService

    boss, second, _v1, v2 = _held_post(conn)
    rid = g.document_lift_approval(conn, v2, requester=boss, approver=second)
    RetentionService(conn).set_document_legal_hold(
        v2, actor_id=boss, on=True, reason="a second order, 2026-0050", clearance="RED")
    with pytest.raises(RetentionConflict, match="cannot be used for this operation"):
        _lift_document(conn, v2, actor=boss, rid=rid)
    assert _document_held(conn, v2) and _state(conn, rid) == "APPROVED"


def test_the_document_lift_approver_must_be_cleared_for_every_version(conn):
    """A colleague whose own ceiling is below the earlier version approves nothing, though they may
    read the version the lift was asked for from."""
    from dataclasses import replace

    from noctornal_api.retention import RetentionConflict

    boss, second, v1, v2 = _held_post(conn, first_class="RED")
    rid = g.document_lift_approval(conn, v2, requester=boss, approver=second)
    below = replace(g.approver(conn, rid, None), ceiling=("AMBER", []),
                    document_ceiling=("AMBER", []))
    with pytest.raises(RetentionConflict, match="no longer"):
        _lift_document(conn, v2, actor=boss, rid=rid, approver=below)
    assert _document_held(conn, v1) and _state(conn, rid) == "APPROVED"
    [(detail, outcome, *_rest)] = g.audit_rows(conn, "LEGAL_HOLD_LIFT_REFUSED", object_id=v2)
    assert (detail["refusal"], detail["stage"], outcome) == (
        "approver_below_material", "spend", "DENIED")


def test_a_grant_scoped_to_the_case_raises_the_approver_as_it_raises_the_lifter_and_no_further(
        conn):
    """Break-glass: a grant scoped to the case raises the second person's ceiling for the case's own
    material, as `user_ceiling(case_id=)` raises the lifter's, and not for a collected document the
    case cites, which an account reads under its own clearance. The two people are judged alike."""
    from noctornal_api.retention import RetentionConflict

    boss, second, case_id = _held_case(conn, second_clearance="AMBER", exhibit_class="RED")
    s.break_glass(conn, second, "RED", case_id)
    rid = g.case_lift_approval(conn, case_id, requester=boss, approver=second)
    judged = g.approver(conn, rid, case_id)
    assert (judged.ceiling[0], judged.document_ceiling[0]) == ("RED", "AMBER")
    g.collected_document(conn, case_id, classification="RED")
    with pytest.raises(RetentionConflict, match="no longer"):
        _lift_case(conn, case_id, actor=boss, rid=rid)
    assert _case_held(conn, case_id) and _state(conn, rid) == "APPROVED"
    [(detail, *_rest)] = g.audit_rows(conn, "LEGAL_HOLD_LIFT_REFUSED", object_id=case_id)
    assert detail["refusal"] == "approver_below_material"
