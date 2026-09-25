"""The gate record behind egress.can_egress (2026-09-24).

Until this date `can_egress` returned "in_app" for any Destination member
that was not in the explicit `_CROSSES_BOUNDARY` set, so a member appended
without its line in that set failed OPEN, and a new destination is added
by appending exactly such a line. Each
destination now has one `GateRule`; a member without one is refused, IN_APP
is the only early return, and a crossing gate that drops invariant 8's
floor or allows compartments cannot be constructed at all.

Pure: the gate reads labels and returns a decision.
"""
from __future__ import annotations

import pytest
from test_egress import OUTBOUND

from noctornal_api import egress
from noctornal_api.egress import (
    _CROSSES_BOUNDARY,
    _GATES,
    DENY_ABOVE_DESTINATION_CEILING,
    DENY_ABOVE_PLATFORM_FLOOR,
    DENY_COMPARTMENTED,
    DENY_NO_CEILING,
    DENY_UNKNOWN_DESTINATION,
    Destination,
    EgressDecision,
    GateRule,
    can_egress,
)

LEVELS = ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"]


def test_every_destination_has_a_gate():
    assert set(Destination) == set(_GATES)


@pytest.mark.parametrize("classification", LEVELS)
def test_a_member_without_a_gate_is_refused_not_in_app(monkeypatch, classification):
    """The fail-open this item closes: WEBHOOK with its record removed is
    what a member appended without its line looks like."""
    gates = dict(_GATES)
    del gates[Destination.WEBHOOK]
    monkeypatch.setattr(egress, "_GATES", gates)
    decision = can_egress(classification, Destination.WEBHOOK)
    assert decision.denied
    assert decision.reason == DENY_UNKNOWN_DESTINATION
    assert can_egress(classification, "webhook").reason == DENY_UNKNOWN_DESTINATION


def test_only_in_app_returns_early(monkeypatch):
    """A destination that does not cross the boundary but has a ceiling
    (the shape the embeddings model host takes) is still gated: the early return
    is by identity, not by "does not cross"."""
    assert can_egress("RED", Destination.IN_APP).reason == "in_app"
    assert can_egress("RED", Destination.IN_APP,
                      compartments=frozenset({"alpha"})).allowed
    inside = dict(_GATES)
    inside[Destination.WEBHOOK] = GateRule(False, False, True)
    monkeypatch.setattr(egress, "_GATES", inside)
    decision = can_egress("GREEN", Destination.WEBHOOK)
    assert decision.denied and decision.reason == DENY_NO_CEILING
    compartmented = can_egress("GREEN", Destination.WEBHOOK, destination_ceiling="AMBER",
                               compartments=frozenset({"alpha"}))
    assert compartmented.reason == DENY_COMPARTMENTED
    assert can_egress("GREEN", Destination.WEBHOOK, destination_ceiling="AMBER").allowed
    above = can_egress("AMBER", Destination.WEBHOOK, destination_ceiling="GREEN")
    assert above.reason == DENY_ABOVE_DESTINATION_CEILING


@pytest.mark.parametrize("fields", [(True, False, True), (True, True, False, True),
                                    (True, False, False), (True, False, True, True)])
def test_a_crossing_gate_cannot_drop_the_floor_or_allow_compartments(fields):
    with pytest.raises(ValueError, match="invariant 8"):
        GateRule(*fields)


def test_a_gate_inside_the_boundary_may_do_without_the_floor():
    assert GateRule(False, False, True).compartments_allowed is False
    assert GateRule(False, False, False, True).compartments_allowed is True


@pytest.mark.parametrize("destination", sorted(_CROSSES_BOUNDARY, key=lambda d: d.value))
def test_every_crossing_gate_refuses_red_amber_strict_and_compartments(destination):
    for level in ("RED", "AMBER_STRICT"):
        decision = can_egress(level, destination, destination_ceiling="RED")
        assert decision.reason == DENY_ABOVE_PLATFORM_FLOOR, (destination, level)
    decision = can_egress("CLEAR", destination, destination_ceiling="AMBER",
                          compartments=frozenset({"alpha"}))
    assert decision.reason == DENY_COMPARTMENTED, destination


def test_the_outbound_hand_list_equals_the_derived_set():
    """test_egress.OUTBOUND is kept by hand and appended to by each feature
    that adds a destination: held equal to the set derived from the gates,
    a forgotten line on either side fails here at once."""
    assert set(OUTBOUND) == set(_CROSSES_BOUNDARY)
    assert len(OUTBOUND) == len(set(OUTBOUND))


def test_a_ceilinged_destination_with_no_ceiling_receives_nothing(monkeypatch):
    """An Enum cannot grow at run time, so a stand-in: WEBHOOK given the
    GateRule(True, True, True) every new crossing destination appends."""
    gates = dict(_GATES)
    gates[Destination.WEBHOOK] = GateRule(True, True, True)
    monkeypatch.setattr(egress, "_GATES", gates)
    decision = can_egress("CLEAR", Destination.WEBHOOK)
    assert decision.denied and decision.reason == DENY_NO_CEILING
    assert decision.explain() == "a destination with no declared ceiling may receive nothing"
    assert can_egress("CLEAR", Destination.WEBHOOK, destination_ceiling="GREEN").allowed


@pytest.mark.parametrize("destination", [Destination.EXPORT, Destination.SMTP,
                                         Destination.JIRA, Destination.WEBHOOK])
def test_the_floor_is_checked_before_compartments_and_compartments_before_the_ceiling(
        destination):
    alpha = frozenset({"alpha"})
    assert can_egress("RED", destination, compartments=alpha,
                      destination_ceiling="CLEAR").reason == DENY_ABOVE_PLATFORM_FLOOR
    assert can_egress("AMBER", destination, compartments=alpha,
                      destination_ceiling="CLEAR").reason == DENY_COMPARTMENTED
    assert can_egress("AMBER", destination,
                      destination_ceiling="CLEAR").reason == DENY_ABOVE_DESTINATION_CEILING
    # The older crossing destinations keep their earlier behaviour: no
    # ceiling given is not a refusal for them.
    assert can_egress("AMBER", destination).allowed


def test_crosses_boundary_is_derived_from_the_gates(monkeypatch):
    assert _CROSSES_BOUNDARY == frozenset(
        d for d, g in _GATES.items() if g.crosses_boundary)
    assert Destination.IN_APP not in _CROSSES_BOUNDARY
    assert _GATES[Destination.IN_APP] == GateRule(False, False, False, True)


def test_no_explanation_carries_a_dash_or_a_hedged_plural():
    reasons = [DENY_ABOVE_PLATFORM_FLOOR, DENY_ABOVE_DESTINATION_CEILING,
               DENY_COMPARTMENTED, egress.DENY_UNKNOWN_CLASSIFICATION,
               DENY_UNKNOWN_DESTINATION, DENY_NO_CEILING]
    for reason in reasons:
        text = EgressDecision(False, reason, "RED", "webhook").explain()
        assert text and "—" not in text and "–" not in text, reason
        assert " -- " not in text and "(s)" not in text, reason
