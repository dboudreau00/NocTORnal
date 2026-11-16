"""The minimisation gap (decision 231): the conversations of a case that nobody assigned to it can
minimise, counted live and never named.

A conversation counts while it still holds a message body and no live assignee of an active account,
in a case role that carries `comms.minimise`, is cleared for it, cleared meaning what the gate
demands: the stricter of the conversation's and the case's classification, and both sets of
compartments. A break-glass grant makes nobody a minimiser, and flagging (`comms.bind`) is not
counted. Seeded as the owner; the count runs on an exempt connection, and the request role is
refused it.
"""
from __future__ import annotations

from dataclasses import fields
from datetime import timedelta
from uuid import uuid4

import pytest

import rls_support as s

pytestmark = s.GATED

PREFIX = "mg5s-"
LEVELS = ("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED")


@pytest.fixture
def owner():
    c = s.owner_conn()
    yield c
    cleanup(c)
    c.close()


def cleanup(c) -> None:
    users = f"(SELECT id FROM iam.app_user WHERE email LIKE '{PREFIX}%@noctornal.test')"
    cases = f'(SELECT id FROM core."case" WHERE owner_user_id IN {users})'
    with c.transaction():
        c.execute(f"DELETE FROM comms.conversation WHERE case_id IN {cases}")
    s.cleanup(c, prefix=PREFIX)


def _conversation(c, case_id, classification="RED", compartments=(), bodies=3):
    from noctornal_api.comms import CommsService
    svc = CommsService(c)
    conv = svc.open_conversation(
        case_id=case_id, platform_key="TELEGRAM", provenance_class="OPEN_GROUP",
        external_ref=f"gap-{uuid4().hex[:8]}", classification=classification,
        compartments=frozenset(s.register(c, *compartments)))
    for n in range(bodies):
        svc.add_message(conv, sender_handle=f"@member{n}", body=f"message {n}")
    return conv


def _gap(c, case_id):
    from noctornal_api.comms import CommsService
    return CommsService(c).minimisation_gap(case_id)


def _case_with_amber_lead(c, classification="AMBER", compartments=()):
    """A case whose owner, its one Lead investigator, is AMBER."""
    lead = s.user(c, "AMBER", compartments, prefix=PREFIX)
    return lead, s.case(c, lead, classification, compartments)


def test_a_conversation_above_everyone_assigned_is_counted_as_unminimisable(owner):
    from noctornal_api.comms import MinimisationGap
    _lead, case_id = _case_with_amber_lead(owner)
    _conversation(owner, case_id, "RED")
    _conversation(owner, case_id, "AMBER_STRICT")
    _conversation(owner, case_id, "AMBER")
    assert _gap(owner, case_id) == MinimisationGap(2, "RED")


def test_a_conversation_a_cleared_lead_can_reach_is_not_counted(owner):
    from noctornal_api.comms import MinimisationGap
    _lead, case_id = _case_with_amber_lead(owner)
    _conversation(owner, case_id, "RED")
    red_lead = s.user(owner, "RED", prefix=PREFIX)
    s.assign(owner, case_id, red_lead, "CASE_OWNER")
    assert _gap(owner, case_id) == MinimisationGap(0, None)


def test_an_expired_or_deactivated_assignee_does_not_make_a_conversation_reachable(owner):
    _lead, case_id = _case_with_amber_lead(owner)
    _conversation(owner, case_id, "RED")
    gone = s.user(owner, "RED", prefix=PREFIX)
    s.assign(owner, case_id, gone, "CASE_OWNER",
             expires_at=s.now() - timedelta(minutes=1))
    asleep = s.user(owner, "RED", active=False, prefix=PREFIX)
    s.assign(owner, case_id, asleep, "CASE_OWNER")
    assert _gap(owner, case_id).count == 1
    # The same grant with an end still to come makes it reachable.
    s.assign(owner, case_id, gone, "CASE_OWNER",
             expires_at=s.now() + timedelta(hours=1))
    assert _gap(owner, case_id).count == 0


def test_a_break_glass_grant_does_not_make_a_conversation_reachable(owner):
    lead, case_id = _case_with_amber_lead(owner)
    _conversation(owner, case_id, "RED")
    s.break_glass(owner, lead, "RED", case_id)
    s.break_glass(owner, lead, "RED")
    assert _gap(owner, case_id).count == 1


def test_a_lead_cleared_for_the_conversation_but_not_the_case_does_not_count(owner):
    """The gate composes the case's labels with the conversation's, so a Lead read into nothing
    the case needs cannot act on a conversation they would otherwise be cleared for."""
    _lead, case_id = _case_with_amber_lead(owner, compartments=("MG5-CASE",))
    _conversation(owner, case_id, "RED")
    red_lead = s.user(owner, "RED", prefix=PREFIX)
    s.assign(owner, case_id, red_lead, "CASE_OWNER")
    assert _gap(owner, case_id).count == 1
    s.register(owner, "MG5-CASE")
    owner.execute("UPDATE iam.app_user SET compartments = %s WHERE id = %s",
                  (["MG5-CASE"], red_lead))
    assert _gap(owner, case_id).count == 0


def _raised_case(c):
    """An AMBER case led by an AMBER Lead, holding an AMBER conversation, then raised to RED: a case
    may be raised after its conversations were written, and nothing re-labels them."""
    lead, case_id = _case_with_amber_lead(c)
    _conversation(c, case_id, "AMBER")
    c.execute('UPDATE core."case" SET classification = %s WHERE id = %s', ("RED", case_id))
    return lead, case_id


def test_a_lead_cleared_for_the_conversation_but_not_the_cases_classification_does_not_count(owner):
    """The case's classification, not only its compartments: the AMBER Lead is cleared for the AMBER
    conversation but not for the RED case it sits in, which the gate demands too."""
    from noctornal_api.comms import MinimisationGap
    lead, case_id = _raised_case(owner)
    assert _gap(owner, case_id) == MinimisationGap(1, "RED")
    owner.execute("UPDATE iam.app_user SET tlp_clearance = 'RED' WHERE id = %s", (lead,))
    assert _gap(owner, case_id) == MinimisationGap(0, None)


def test_a_lead_elsewhere_counts_as_eligible_only_when_cleared_for_the_case_too(owner):
    """`eligible_elsewhere` composes the labels as the count does: a Lead investigator elsewhere who
    is cleared for the conversation and not the case it sits in could not minimise it either."""
    from noctornal_api.comms import CommsService

    def listed():
        return {g.case_id: g for g in CommsService(owner).minimisation_gaps()}[case_id]

    _lead, case_id = _raised_case(owner)
    before = listed()
    assert (before.count, before.highest_tlp) == (1, "RED")
    amber = s.user(owner, "AMBER", prefix=PREFIX)
    s.grant_global(owner, amber, "CASE_OWNER")
    assert listed().eligible_elsewhere == before.eligible_elsewhere
    red = s.user(owner, "RED", prefix=PREFIX)
    s.grant_global(owner, red, "CASE_OWNER")
    assert listed().eligible_elsewhere == before.eligible_elsewhere + 1


def test_a_fully_minimised_conversation_is_not_counted(owner):
    from noctornal_api.comms import CommsService
    lead, case_id = _case_with_amber_lead(owner)
    conv = _conversation(owner, case_id, "RED")
    _conversation(owner, case_id, "RED", bodies=0)
    assert _gap(owner, case_id).count == 1
    CommsService(owner).minimise(conv, actor_id=lead, authority="closure order")
    assert _gap(owner, case_id).count == 0


def test_a_compartmented_conversation_needs_the_compartment_not_just_the_tlp(owner):
    _lead, case_id = _case_with_amber_lead(owner)
    _conversation(owner, case_id, "AMBER", ("MG5-WALL",))
    red_lead = s.user(owner, "RED", prefix=PREFIX)
    s.assign(owner, case_id, red_lead, "CASE_OWNER")
    gap = _gap(owner, case_id)
    assert (gap.count, gap.highest_tlp) == (1, "AMBER")
    walled = s.user(owner, "AMBER", ("MG5-WALL",), prefix=PREFIX)
    s.assign(owner, case_id, walled, "CASE_OWNER")
    assert _gap(owner, case_id).count == 0


def test_a_role_that_only_flags_does_not_make_a_conversation_reachable(owner):
    """`comms.bind` is held by roles that cannot minimise: a RED analyst who can flag the third
    parties still leaves the conversation in the gap."""
    _lead, case_id = _case_with_amber_lead(owner)
    _conversation(owner, case_id, "RED")
    for role in ("ANALYST", "REVIEWER", "CONTRIBUTOR", "READ_ONLY"):
        s.assign(owner, case_id, s.user(owner, "RED", prefix=PREFIX), role)
    assert _gap(owner, case_id).count == 1


def test_every_tlp_pair_compares_as_the_gate_does(owner):
    """`core.tlp` is an ordered enum; the comparison must be its order, not the text's."""
    from noctornal_api.comms import MinimisationGap
    for i, cleared in enumerate(LEVELS):
        lead = s.user(owner, cleared, prefix=PREFIX)
        case_id = s.case(owner, lead, "CLEAR")
        for level in LEVELS:
            _conversation(owner, case_id, level, bodies=1)
        above = LEVELS[i + 1:]
        assert _gap(owner, case_id) == MinimisationGap(
            len(above), above[-1] if above else None), cleared


def test_the_gap_carries_a_count_and_a_tier_and_nothing_that_names_a_conversation(owner):
    from noctornal_api.comms import CaseMinimisationGap, MinimisationGap
    assert [f.name for f in fields(MinimisationGap)] == ["count", "highest_tlp"]
    assert [f.name for f in fields(CaseMinimisationGap)] == [
        "case_id", "count", "highest_tlp", "leads_assigned", "eligible_elsewhere"]


def test_the_deployment_list_counts_each_case_and_who_could_close_it(owner):
    from noctornal_api.comms import CaseMinimisationGap, CommsService

    def listed():
        return {g.case_id: g for g in CommsService(owner).minimisation_gaps()}

    _lead, case_id = _case_with_amber_lead(owner)
    _conversation(owner, case_id, "RED")
    _conversation(owner, case_id, "AMBER", ("MG5-SIDE",))
    _clean_lead, clean = _case_with_amber_lead(owner)
    _conversation(owner, clean, "AMBER")
    # Other suites' accounts may hold the role, so what this test adds is read as a difference.
    before = listed()[case_id].eligible_elsewhere
    # Two Lead investigators could close part of it, one could not, and one is inactive.
    for clearance, comps, active in (("RED", (), True), ("AMBER", ("MG5-SIDE",), True),
                                     ("AMBER", (), True), ("RED", (), False)):
        uid = s.user(owner, clearance, comps, active=active, prefix=PREFIX)
        s.grant_global(owner, uid, "CASE_OWNER")
    mine = listed()
    assert clean not in mine
    assert mine[case_id] == CaseMinimisationGap(case_id, 2, "RED", 1, before + 2)


def test_the_oversight_permission_is_the_security_officers_alone_without_step_up(owner):
    """0196: a read and a notice, conferring nothing on a case, so no re-challenge, and held by
    the overseer who holds no case content."""
    rows = owner.execute(
        """SELECT p.requires_step_up,
                  array_agg(rp.role_key ORDER BY rp.role_key)
             FROM iam.permission p
             LEFT JOIN iam.role_permission rp ON rp.permission_key = p.key
            WHERE p.key = 'comms.minimise.oversee'
            GROUP BY p.requires_step_up""").fetchall()
    assert rows == [(False, ["SECURITY_OFFICER"])]
    # And the officer still holds nothing that acts on a conversation.
    assert not owner.execute(
        """SELECT 1 FROM iam.role_permission WHERE role_key = 'SECURITY_OFFICER'
              AND permission_key IN ('comms.minimise', 'comms.bind', 'comms.read')""").fetchone()


def test_the_request_role_is_refused_the_count(owner):
    from noctornal_api.comms import CommsService
    from noctornal_api.db import SystemContextUnavailable
    lead, case_id = _case_with_amber_lead(owner)
    _sid, raw = s.session(owner, lead)
    app = s.app_conn(raw)
    try:
        with pytest.raises(SystemContextUnavailable):
            CommsService(app).minimisation_gap(case_id)
        with pytest.raises(SystemContextUnavailable):
            CommsService(app).minimisation_gaps()
        with pytest.raises(SystemContextUnavailable):
            CommsService(app).minimisation_gap_states()
    finally:
        app.close()


def test_conversations_minimisable_fails_for_a_closed_case_with_a_gap_and_names_no_case():
    """The readiness row (decision 231): red while a closed case holds a conversation nobody assigned
    can minimise, a caveat while only an open one does, and never a case, an id or a count, because
    every holder of user.manage reads it. In one rolled-back transaction, so what other suites left
    is switched off for this test alone."""
    from noctornal_api import readiness
    from rolled_back import rolled_back

    name = "conversations_minimisable"
    assert name in readiness.CHECK_NAMES and name not in readiness.BLOCKING_CHECKS
    assert name not in readiness.UI_TARGETS and name not in readiness.CONSEQUENCES
    with rolled_back() as c:
        c.execute("UPDATE comms.message SET body = NULL WHERE body IS NOT NULL")
        clean = readiness.check(name, c)
        assert clean.ok and not clean.caveat, clean

        lead = s.user(c, "AMBER", prefix=PREFIX)
        case_id = s.case(c, lead)
        code = c.execute('SELECT code FROM core."case" WHERE id = %s', (case_id,)).fetchone()[0]
        conv = _conversation(c, case_id, "RED", ("MG5-READY",))
        c.execute('UPDATE core."case" SET status = %s WHERE id = %s', ("ACTIVE", case_id))
        still_open = readiness.check(name, c)
        assert still_open.ok and still_open.caveat, still_open
        assert "Oversight, Minimisation gaps" in still_open.caveat

        c.execute('UPDATE core."case" SET status = %s, closed_at = now() WHERE id = %s',
                  ("CLOSED", case_id))
        closed = readiness.check(name, c)
        assert not closed.ok and closed.action and not closed.blocking, closed
        assert (closed.consequence, closed.ui_target, closed.caveat) == ("", "", "")

        for text in (still_open.evidence, still_open.caveat, closed.evidence, closed.action):
            for secret in (code, str(case_id), str(conv), "MG5-READY", "RED"):
                assert secret not in text, (secret, text)
            assert not any(ch.isdigit() for ch in text), text

        # An archived case's duty is as unmet as a closed one's.
        c.execute('UPDATE core."case" SET status = %s WHERE id = %s', ("ARCHIVED", case_id))
        assert not readiness.check(name, c).ok
        # And a cleared Lead assigned to it makes the row green again.
        s.assign(c, case_id, s.user(c, "RED", ("MG5-READY",), prefix=PREFIX), "CASE_OWNER")
        assert readiness.check(name, c).ok


def test_conversations_minimisable_reads_the_states_and_not_the_oversight_counts(monkeypatch):
    """The row says whether a shut case has a gap, so it reads the statuses of the cases with one and
    never pays for the oversight list's per-case Lead and cleared-elsewhere counts."""
    from noctornal_api import readiness
    from noctornal_api.comms import CommsService
    from rolled_back import rolled_back

    def oversight(*_a, **_k):
        raise AssertionError("the readiness row read the oversight list")

    monkeypatch.setattr(CommsService, "minimisation_gaps", oversight)
    name = "conversations_minimisable"
    with rolled_back() as c:
        c.execute("UPDATE comms.message SET body = NULL WHERE body IS NOT NULL")
        assert CommsService(c).minimisation_gap_states() == frozenset()
        lead = s.user(c, "AMBER", prefix=PREFIX)
        case_id = s.case(c, lead)
        _conversation(c, case_id, "RED")
        c.execute('UPDATE core."case" SET status = %s WHERE id = %s', ("ACTIVE", case_id))
        assert CommsService(c).minimisation_gap_states() == {"ACTIVE"}
        still_open = readiness.check(name, c)
        assert still_open.ok and still_open.caveat, still_open
        c.execute('UPDATE core."case" SET status = %s, closed_at = now() WHERE id = %s',
                  ("CLOSED", case_id))
        assert CommsService(c).minimisation_gap_states() == {"CLOSED"}
        assert not readiness.check(name, c).ok
