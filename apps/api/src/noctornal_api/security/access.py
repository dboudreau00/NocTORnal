"""The five-part access check — the single gate every endpoint calls.

docs/05: authorisation is RBAC for verbs, ABAC for rows, and access is
granted iff ALL FIVE hold:

    role grants the permission                     (verb)
  ∧ user is assigned to the case, unexpired        (relationship)
  ∧ user.tlp_clearance ≥ object.classification     (lattice)
  ∧ object.compartments ⊆ user.compartments        (need to know)
  ∧ session MFA fresh if the permission needs it    (assurance)

Scattering these across endpoints is how access bugs ship, so there is
exactly one evaluator. It is a pure function of a resolved AccessContext
(facts fetched by the caller / resolver), which makes it exhaustively
testable — including the invariant that removing ANY one of the five
checks changes a decision.

All five are evaluated with no short-circuit, so the audit trail can see
every reason a request failed, and `Decision.failed_checks` names them.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import IntEnum

from noctornal_api.security.sessions import STEP_UP_FRESHNESS


class AccessResolutionError(Exception):
    """The access context could not be resolved from trustworthy inputs
    (unknown permission, user, or classification value). The API layer must
    treat this as a hard DENY (403), never a 500 — resolution failures fail
    closed, they do not grant."""


class Tlp(IntEnum):
    """FIRST v2.0 TLP as an ordered lattice: a higher clearance dominates
    (may see) everything at or below it. Order MUST match the SQL enum."""
    CLEAR = 0
    GREEN = 1
    AMBER = 2
    AMBER_STRICT = 3
    RED = 4


def tlp_from_name(name: str) -> Tlp:
    """Parse a TLP label into the ordered enum, failing closed on anything
    unexpected rather than crashing with a bare KeyError."""
    try:
        return Tlp[name]
    except KeyError as exc:
        raise AccessResolutionError(f"unknown TLP classification: {name!r}") from exc


# Stable identifiers for the five checks — used in audit and tests.
CHECK_ROLE = "role_grants_permission"
CHECK_ASSIGNMENT = "case_assignment_unexpired"
CHECK_CLEARANCE = "tlp_clearance_dominates"
CHECK_COMPARTMENTS = "compartments_subset"
CHECK_STEP_UP = "step_up_freshness"

ALL_CHECKS = (CHECK_ROLE, CHECK_ASSIGNMENT, CHECK_CLEARANCE,
              CHECK_COMPARTMENTS, CHECK_STEP_UP)


@dataclass(frozen=True)
class AccessContext:
    permission_key: str
    permission_requires_step_up: bool
    # Permissions granted by the user's effective role ON this case.
    role_permissions: frozenset[str]
    # An assignment to this case exists AND is unexpired. (The role above is
    # read from the assignment even when expired, so the verb check and the
    # relationship check are independently necessary — an expired analyst
    # still "has" the verb but not the row.)
    has_unexpired_assignment: bool
    user_clearance: Tlp
    object_classification: Tlp
    user_compartments: frozenset[str]
    object_compartments: frozenset[str]
    # Session step-up clock; None if MFA never satisfied on this session.
    mfa_satisfied_at: datetime | None


@dataclass(frozen=True)
class Decision:
    allowed: bool
    failed_checks: tuple[str, ...]

    @property
    def denied(self) -> bool:
        return not self.allowed


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def evaluate(ctx: AccessContext, *, now=None) -> Decision:
    now = now or _utcnow()
    failed: list[str] = []

    # 1. Verb: the user's role grants this permission.
    if ctx.permission_key not in ctx.role_permissions:
        failed.append(CHECK_ROLE)

    # 2. Relationship: assigned to this case and not expired.
    if not ctx.has_unexpired_assignment:
        failed.append(CHECK_ASSIGNMENT)

    # 3. Lattice: clearance must dominate the object's classification.
    if not (ctx.user_clearance >= ctx.object_classification):
        failed.append(CHECK_CLEARANCE)

    # 4. Need to know: the object's compartments must be a subset of the
    #    user's. Empty object compartments are a subset of anything.
    if not (ctx.object_compartments <= ctx.user_compartments):
        failed.append(CHECK_COMPARTMENTS)

    # 5. Assurance: step-up permissions need a fresh MFA on the session.
    if ctx.permission_requires_step_up:
        fresh = (
            ctx.mfa_satisfied_at is not None
            and (now - ctx.mfa_satisfied_at) < STEP_UP_FRESHNESS
        )
        if not fresh:
            failed.append(CHECK_STEP_UP)

    return Decision(allowed=not failed, failed_checks=tuple(failed))
