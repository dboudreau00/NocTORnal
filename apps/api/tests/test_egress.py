"""The classification egress gate (invariant 8, docs/07, Phase 5).

docs/07: "Every outbound path checks classification before it sends. One
function, `can_egress(object, destination)`, called by SMTP, Jira,
webhooks and export alike. AMBER_STRICT and RED never leave the platform
boundary, regardless of who clicked what."

The gate is pure, so it can be tested exhaustively — which matters more
here than almost anywhere else in the codebase, because this is the
function standing between a case file and a Jira project with a different
access model and a much wider audience.
"""
from __future__ import annotations

import pytest

from noctornal_api.egress import (
    DENY_ABOVE_DESTINATION_CEILING,
    DENY_ABOVE_PLATFORM_FLOOR,
    DENY_COMPARTMENTED,
    DENY_UNKNOWN_CLASSIFICATION,
    DENY_UNKNOWN_DESTINATION,
    Destination,
    EgressRefused,
    can_egress,
    enforce_egress,
)

OUTBOUND = [Destination.EXPORT, Destination.SMTP, Destination.JIRA,
            Destination.WEBHOOK]


# --- invariant 8, the hard floor ----------------------------------------

@pytest.mark.parametrize("destination", OUTBOUND)
@pytest.mark.parametrize("classification", ["AMBER_STRICT", "RED"])
def test_amber_strict_and_red_never_leave_the_boundary(classification, destination):
    """"regardless of who clicked what" — there is no argument, no role and
    no configuration that makes this sendable."""
    decision = can_egress(classification, destination)
    assert decision.denied
    assert decision.reason == DENY_ABOVE_PLATFORM_FLOOR


@pytest.mark.parametrize("classification", ["AMBER_STRICT", "RED"])
def test_a_permissive_destination_ceiling_cannot_raise_the_floor(classification):
    """A destination that claims it can hold RED does not get to hold RED.
    The floor is checked first precisely so a misconfigured — or
    maliciously configured — integration cannot argue its way past it."""
    decision = can_egress(classification, Destination.JIRA,
                          destination_ceiling="RED")
    assert decision.denied
    assert decision.reason == DENY_ABOVE_PLATFORM_FLOOR


def test_the_floor_does_not_apply_inside_the_platform():
    """IN_APP is not egress. A cleared analyst reading RED material in the
    interface has already passed the five-part gate; refusing here would
    make the product useless rather than safe."""
    assert can_egress("RED", Destination.IN_APP).allowed


# --- per-destination ceilings -------------------------------------------

def test_a_destination_ceiling_lowers_what_may_be_sent():
    """A Jira project configured for TLP:CLEAR is not a legitimate home for
    AMBER content just because the platform floor would permit it."""
    assert can_egress("AMBER", Destination.JIRA,
                      destination_ceiling="AMBER").allowed
    below = can_egress("AMBER", Destination.JIRA, destination_ceiling="CLEAR")
    assert below.denied
    assert below.reason == DENY_ABOVE_DESTINATION_CEILING


def test_no_ceiling_means_the_platform_floor_is_the_only_limit():
    assert can_egress("AMBER", Destination.WEBHOOK).allowed
    assert can_egress("GREEN", Destination.SMTP).allowed


def test_an_unparseable_ceiling_is_a_misconfigured_destination():
    """And a misconfigured destination is not a safe one, so it fails
    closed rather than falling back to the platform floor."""
    decision = can_egress("GREEN", Destination.JIRA,
                          destination_ceiling="TLP:MAUVE")
    assert decision.denied
    assert decision.reason == DENY_UNKNOWN_CLASSIFICATION


# --- compartments --------------------------------------------------------

@pytest.mark.parametrize("destination", OUTBOUND)
def test_compartmented_material_never_crosses_the_boundary(destination):
    """No external system models compartments, so egress would silently
    drop the need-to-know control rather than enforce it elsewhere."""
    decision = can_egress("GREEN", destination,
                          compartments=frozenset({"ALPHA"}))
    assert decision.denied
    assert decision.reason == DENY_COMPARTMENTED


def test_compartments_are_irrelevant_inside_the_platform():
    assert can_egress("AMBER", Destination.IN_APP,
                      compartments=frozenset({"ALPHA"})).allowed


def test_an_empty_compartment_set_does_not_block():
    assert can_egress("AMBER", Destination.SMTP,
                      compartments=frozenset()).allowed


# --- failing closed ------------------------------------------------------

def test_an_unknown_classification_is_refused_not_guessed():
    decision = can_egress("SECRET", Destination.SMTP)
    assert decision.denied
    assert decision.reason == DENY_UNKNOWN_CLASSIFICATION


def test_an_unknown_destination_is_refused_not_guessed():
    """A gate that fails open when it does not recognise where something is
    going is not a gate."""
    decision = can_egress("CLEAR", "carrier_pigeon")
    assert decision.denied
    assert decision.reason == DENY_UNKNOWN_DESTINATION


def test_destinations_may_be_named_as_strings():
    """Integration config comes from the database as text, so the gate
    accepts the string form without the caller hand-rolling a lookup."""
    assert can_egress("CLEAR", "smtp").allowed
    assert can_egress("RED", "smtp").denied


# --- the explanation -----------------------------------------------------

def test_a_denial_explains_itself_without_leaking_what_it_refused():
    """An explanation that restates the content or its compartments is not
    much of a refusal."""
    decision = can_egress("GREEN", Destination.WEBHOOK,
                          compartments=frozenset({"OPERATION_KESTREL"}))
    assert decision.denied
    assert "OPERATION_KESTREL" not in decision.explain()
    assert "compartment" in decision.explain()


def test_enforce_raises_with_the_decision_attached():
    with pytest.raises(EgressRefused) as excinfo:
        enforce_egress("RED", Destination.JIRA)
    assert excinfo.value.decision.reason == DENY_ABOVE_PLATFORM_FLOOR
    assert enforce_egress("CLEAR", Destination.JIRA).allowed


# --- there is only ONE copy of the rule ----------------------------------

def test_evidence_export_shares_the_gates_definition():
    """docs/07 wants one function. Evidence used to carry its own frozenset
    of non-egressable classifications; a second copy is how the copies
    drift, and the one that drifts is the leak."""
    from noctornal_api.egress import NEVER_EGRESS
    from noctornal_api.evidence import _NO_EGRESS
    assert _NO_EGRESS == frozenset(t.name for t in NEVER_EGRESS)
    assert _NO_EGRESS == {"AMBER_STRICT", "RED"}


@pytest.mark.parametrize("classification,destination,expected", [
    ("CLEAR", Destination.SMTP, True),
    ("GREEN", Destination.SMTP, True),
    ("AMBER", Destination.SMTP, True),
    ("AMBER_STRICT", Destination.SMTP, False),
    ("RED", Destination.SMTP, False),
])
def test_the_whole_lattice_at_a_glance(classification, destination, expected):
    assert can_egress(classification, destination).allowed is expected
