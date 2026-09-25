"""The two model-endpoint destinations of the egress gate (F6.2,
embeddings, 2026-09-24).

MODEL_HOST is a model server declared as this host's own and reached over
loopback on a DIRECT route outside production: inside the boundary like
IN_APP, so invariant 8's floor does not apply, but ceilinged, and closed
to compartmented material (egress.py's own rule that nothing outside the
platform models compartments, kept for a model server too). MODEL_REMOTE
is every other model endpoint and crosses the boundary: the floor, the
compartment refusal, a required ceiling. The four destinations that
existed decide exactly as before.

Pure.
"""
from __future__ import annotations

import pytest

from noctornal_api.egress import (
    _CROSSES_BOUNDARY,
    DENY_ABOVE_DESTINATION_CEILING,
    DENY_ABOVE_PLATFORM_FLOOR,
    DENY_COMPARTMENTED,
    DENY_NO_CEILING,
    DENY_UNKNOWN_CLASSIFICATION,
    Destination,
    can_egress,
)

LEVELS = ["CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"]


def test_model_host_honours_the_ceiling_and_not_the_floor():
    assert can_egress("RED", Destination.MODEL_HOST, destination_ceiling="RED").allowed
    decision = can_egress("RED", Destination.MODEL_HOST, destination_ceiling="AMBER")
    assert decision.denied and decision.reason == DENY_ABOVE_DESTINATION_CEILING
    assert can_egress("AMBER", Destination.MODEL_HOST, destination_ceiling="AMBER").allowed


@pytest.mark.parametrize("destination", [Destination.MODEL_HOST, Destination.MODEL_REMOTE])
def test_no_ceiling_or_an_unreadable_one_sends_nothing(destination):
    decision = can_egress("CLEAR", destination)
    assert decision.denied and decision.reason == DENY_NO_CEILING
    assert "no declared ceiling" in decision.explain()
    bad = can_egress("CLEAR", destination, destination_ceiling="TOP")
    assert bad.denied and bad.reason == DENY_UNKNOWN_CLASSIFICATION


@pytest.mark.parametrize("destination", [Destination.MODEL_HOST, Destination.MODEL_REMOTE])
def test_compartmented_material_goes_to_no_model_endpoint(destination):
    decision = can_egress("CLEAR", destination, compartments=frozenset({"K1"}),
                          destination_ceiling="RED")
    assert decision.denied and decision.reason == DENY_COMPARTMENTED


@pytest.mark.parametrize("classification", ["AMBER_STRICT", "RED"])
def test_model_remote_keeps_invariant_8_whatever_the_ceiling(classification):
    decision = can_egress(classification, Destination.MODEL_REMOTE,
                          destination_ceiling="RED")
    assert decision.denied and decision.reason == DENY_ABOVE_PLATFORM_FLOOR


def test_model_remote_honours_the_ceiling():
    assert can_egress("AMBER", Destination.MODEL_REMOTE, destination_ceiling="AMBER").allowed
    decision = can_egress("AMBER", Destination.MODEL_REMOTE, destination_ceiling="GREEN")
    assert decision.denied and decision.reason == DENY_ABOVE_DESTINATION_CEILING


def test_only_the_remote_endpoint_crosses_the_boundary():
    assert Destination.MODEL_REMOTE in _CROSSES_BOUNDARY
    assert Destination.MODEL_HOST not in _CROSSES_BOUNDARY


def test_no_explanation_names_the_content():
    for destination in (Destination.MODEL_HOST, Destination.MODEL_REMOTE):
        for level in LEVELS:
            text = can_egress(level, destination, compartments=frozenset({"SECRETKEY"}),
                              destination_ceiling="CLEAR").explain()
            assert "SECRETKEY" not in text


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("destination", [Destination.EXPORT, Destination.SMTP,
                                         Destination.JIRA, Destination.WEBHOOK,
                                         Destination.IN_APP])
def test_the_existing_destinations_decide_as_before(level, destination):
    """The lattice of the four outbound destinations and IN_APP, re-run:
    no ceiling needed, the floor for the outbound ones only."""
    decision = can_egress(level, destination)
    if destination is Destination.IN_APP:
        assert decision.allowed
    else:
        assert decision.allowed == (level not in ("AMBER_STRICT", "RED"))
