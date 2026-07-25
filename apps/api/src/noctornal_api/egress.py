"""The classification egress gate (invariant 8, docs/07, Phase 5).

docs/07 opens with the rule that governs every integration:

    Every outbound path checks classification before it sends. One
    function, `can_egress(object, destination)`, called by SMTP, Jira,
    webhooks and export alike. AMBER_STRICT and RED never leave the
    platform boundary, regardless of who clicked what.

And the reason, which is worth keeping in view because it is not a
hypothetical:

    Integrations are the leak path in every system of this kind. Not
    because anyone intends it, but because a Jira ticket auto-created from
    a watch hit quietly copies intelligence into a system with a completely
    different access model and a much wider audience.

This module is that one function. It is deliberately pure — it takes
labels and a destination and returns a decision — so it can be exhaustively
tested and so no caller can accidentally pass it a live connection and get
a different answer.

Three properties the implementation defends:

**Fail closed on anything unrecognised.** An unknown classification, an
unknown destination kind or a malformed ceiling is a DENY, never a
permit. A gate that fails open when it is confused is not a gate.

**The destination's ceiling and the platform floor are both binding.** A
Jira project configured for TLP:GREEN does not become a legitimate home for
AMBER content because someone raised the case's classification; and
nothing raises AMBER_STRICT or RED to sendable, ever, whatever a
destination claims it can hold.

**Compartments do not cross the boundary at all.** A compartment is
need-to-know inside the platform, and no external system models it. Sending
compartmented material anywhere outbound would silently discard the very
control that protects it, so it is refused outright rather than downgraded.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from noctornal_api.security.access import AccessResolutionError, Tlp, tlp_from_name

# Invariant 8, stated once. These never leave the boundary on ANY path.
NEVER_EGRESS = frozenset({Tlp.AMBER_STRICT, Tlp.RED})


class Destination(Enum):
    """Where something is going. Each is a different audience with a
    different access model, which is the whole reason the ceiling is
    per-destination rather than global."""

    # Stays inside the platform: the analyst is already authenticated and
    # cleared, and nothing is copied anywhere.
    IN_APP = "in_app"
    # Leaves the boundary. An analyst-initiated download of case material.
    EXPORT = "export"
    # Leaves the boundary into systems with their OWN access models, which
    # this platform does not control and cannot audit.
    SMTP = "smtp"
    JIRA = "jira"
    WEBHOOK = "webhook"


# Anything not IN_APP crosses the boundary. Kept as an explicit set rather
# than `!= IN_APP` so that adding a destination forces a decision about it.
_CROSSES_BOUNDARY = frozenset({
    Destination.EXPORT, Destination.SMTP, Destination.JIRA, Destination.WEBHOOK,
})

# Stable reason codes: these end up in audit rows and delivery logs, so they
# are matched on, not just read.
DENY_UNKNOWN_CLASSIFICATION = "unknown_classification"
DENY_UNKNOWN_DESTINATION = "unknown_destination"
DENY_ABOVE_PLATFORM_FLOOR = "above_platform_floor"
DENY_ABOVE_DESTINATION_CEILING = "above_destination_ceiling"
DENY_COMPARTMENTED = "compartmented_material"


@dataclass(frozen=True)
class EgressDecision:
    allowed: bool
    reason: str
    # Populated on a deny, for the audit row and the operator-facing message.
    classification: str | None = None
    destination: str | None = None

    @property
    def denied(self) -> bool:
        return not self.allowed

    def explain(self) -> str:
        """A sentence an operator can act on. Deliberately does NOT restate
        the content or its compartments — an explanation that leaks what it
        just refused to send is not much of a refusal."""
        if self.allowed:
            return "permitted"
        if self.reason == DENY_ABOVE_PLATFORM_FLOOR:
            # The "invariant 8" tag is deliberate and load-bearing: it ties
            # the runtime refusal to the documented rule, and existing tests
            # assert on it so the connection cannot be quietly broken.
            return (f"TLP:{self.classification} never leaves this platform, "
                    f"whatever the destination is configured to accept "
                    f"(invariant 8)")
        if self.reason == DENY_ABOVE_DESTINATION_CEILING:
            return (f"TLP:{self.classification} is above what the "
                    f"{self.destination} destination is cleared to hold")
        if self.reason == DENY_COMPARTMENTED:
            return ("compartmented material cannot leave the platform: no "
                    "external system models compartments, so sending it "
                    "would silently drop the control")
        if self.reason == DENY_UNKNOWN_CLASSIFICATION:
            return "unrecognised classification; refusing to guess"
        return "unrecognised destination; refusing to guess"


def can_egress(
    classification: str,
    destination: Destination | str,
    *,
    compartments: frozenset[str] = frozenset(),
    destination_ceiling: str | None = None,
) -> EgressDecision:
    """The one gate. Every outbound path calls this before it sends.

    `destination_ceiling` is the highest classification that specific
    destination is configured to accept — a Jira project, a webhook
    endpoint, a mailing list. It can only ever LOWER what is permitted; it
    can never raise anything past the platform floor.
    """
    try:
        level = tlp_from_name(classification)
    except AccessResolutionError:
        return EgressDecision(False, DENY_UNKNOWN_CLASSIFICATION,
                              classification, str(destination))

    if isinstance(destination, str):
        try:
            destination = Destination(destination)
        except ValueError:
            return EgressDecision(False, DENY_UNKNOWN_DESTINATION,
                                  level.name, str(destination))

    # Nothing crosses out of the app: the caller is already authenticated
    # and cleared, and the five-part gate has already run.
    if destination not in _CROSSES_BOUNDARY:
        return EgressDecision(True, "in_app", level.name, destination.value)

    # Invariant 8, the hard floor. Checked BEFORE the per-destination
    # ceiling so that no destination configuration can be mistaken for
    # authority to send this.
    if level in NEVER_EGRESS:
        return EgressDecision(False, DENY_ABOVE_PLATFORM_FLOOR,
                              level.name, destination.value)

    # Compartments are need-to-know inside the platform. Nothing outside
    # models them, so egress would drop the control silently.
    if compartments:
        return EgressDecision(False, DENY_COMPARTMENTED,
                              level.name, destination.value)

    if destination_ceiling is not None:
        try:
            ceiling = tlp_from_name(destination_ceiling)
        except AccessResolutionError:
            # A destination whose ceiling cannot be parsed is misconfigured,
            # and a misconfigured destination is not a safe one.
            return EgressDecision(False, DENY_UNKNOWN_CLASSIFICATION,
                                  level.name, destination.value)
        if level > ceiling:
            return EgressDecision(False, DENY_ABOVE_DESTINATION_CEILING,
                                  level.name, destination.value)

    return EgressDecision(True, "permitted", level.name, destination.value)


class EgressRefused(Exception):
    """Raised by `enforce_egress`. Carries the decision so the caller can
    audit the reason without re-deriving it."""

    def __init__(self, decision: EgressDecision):
        super().__init__(decision.explain())
        self.decision = decision


def enforce_egress(classification: str, destination: Destination | str, **kw):
    """`can_egress`, but raising — for the call sites where continuing past
    a denial would be a bug rather than a branch."""
    decision = can_egress(classification, destination, **kw)
    if decision.denied:
        raise EgressRefused(decision)
    return decision
