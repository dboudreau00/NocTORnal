"""The five-part access gate (docs/05).

The load-bearing test is test_each_check_is_independently_necessary: for
every one of the five checks there is a request denied ONLY by that check,
so deleting any single check from evaluate() flips a decision to ALLOW and
this test fails. That is the invariant the session-4 rubric requires.
"""
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from noctornal_api.security.access import (
    ALL_CHECKS,
    CHECK_ASSIGNMENT,
    CHECK_CLEARANCE,
    CHECK_COMPARTMENTS,
    CHECK_ROLE,
    CHECK_STEP_UP,
    AccessContext,
    Tlp,
    evaluate,
)

NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc)


def _clock():
    return NOW


# A baseline where all five checks PASS. The permission requires step-up,
# so every one of the five is "active" and can be individually broken.
BASELINE = AccessContext(
    permission_key="graph.merge",
    permission_requires_step_up=True,
    role_permissions=frozenset({"graph.merge", "case.read"}),
    has_unexpired_assignment=True,
    user_clearance=Tlp.AMBER,
    object_classification=Tlp.AMBER,
    user_compartments=frozenset({"OP-KESTREL"}),
    object_compartments=frozenset({"OP-KESTREL"}),
    mfa_satisfied_at=NOW,  # fresh
)


def test_baseline_is_allowed():
    d = evaluate(BASELINE, now=_clock())
    assert d.allowed and d.failed_checks == ()


# Each entry: a one-field mutation of BASELINE that must fail ONLY the
# named check. If evaluate() dropped that check, the decision would flip to
# allowed and this test would catch it.
_BREAKERS = {
    CHECK_ROLE: replace(BASELINE, role_permissions=frozenset({"case.read"})),
    CHECK_ASSIGNMENT: replace(BASELINE, has_unexpired_assignment=False),
    CHECK_CLEARANCE: replace(BASELINE, object_classification=Tlp.RED),
    CHECK_COMPARTMENTS: replace(
        BASELINE, object_compartments=frozenset({"OP-KESTREL", "OP-SECRET"})
    ),
    CHECK_STEP_UP: replace(BASELINE, mfa_satisfied_at=NOW - timedelta(minutes=20)),
}


@pytest.mark.parametrize("check", ALL_CHECKS)
def test_each_check_is_independently_necessary(check):
    ctx = _BREAKERS[check]
    d = evaluate(ctx, now=_clock())
    assert d.denied, f"{check}: expected denial"
    assert d.failed_checks == (check,), (
        f"{check}: exactly this check must fail (got {d.failed_checks}); "
        "otherwise removing it would not be detected"
    )


def test_all_five_checks_have_a_breaker():
    # Guards against a check being added to evaluate() with no coverage.
    assert set(_BREAKERS) == set(ALL_CHECKS)


# --- semantic edge cases ------------------------------------------------

def test_clearance_equal_is_allowed_one_below_denied():
    ok = replace(BASELINE, user_clearance=Tlp.AMBER, object_classification=Tlp.AMBER)
    assert evaluate(ok, now=_clock()).allowed
    higher = replace(BASELINE, user_clearance=Tlp.RED, object_classification=Tlp.AMBER)
    assert evaluate(higher, now=_clock()).allowed
    below = replace(BASELINE, user_clearance=Tlp.GREEN, object_classification=Tlp.AMBER)
    assert CHECK_CLEARANCE in evaluate(below, now=_clock()).failed_checks


def test_empty_object_compartments_always_subset():
    ctx = replace(
        BASELINE,
        object_compartments=frozenset(),
        user_compartments=frozenset(),
    )
    assert evaluate(ctx, now=_clock()).allowed


def test_step_up_ignored_when_permission_does_not_require_it():
    # A non-step-up permission is unaffected by a stale / absent MFA clock.
    ctx = replace(
        BASELINE,
        permission_key="case.read",
        permission_requires_step_up=False,
        role_permissions=frozenset({"case.read"}),
        mfa_satisfied_at=None,
    )
    assert evaluate(ctx, now=_clock()).allowed


def test_step_up_boundary_exactly_at_freshness_window():
    from noctornal_api.security.sessions import STEP_UP_FRESHNESS
    # Exactly at the window is NOT fresh (strict <).
    at_edge = replace(BASELINE, mfa_satisfied_at=NOW - STEP_UP_FRESHNESS)
    assert CHECK_STEP_UP in evaluate(at_edge, now=_clock()).failed_checks
    just_inside = replace(
        BASELINE, mfa_satisfied_at=NOW - STEP_UP_FRESHNESS + timedelta(seconds=1)
    )
    assert evaluate(just_inside, now=_clock()).allowed


def test_multiple_failures_all_reported():
    ctx = replace(
        BASELINE,
        role_permissions=frozenset(),
        has_unexpired_assignment=False,
    )
    failed = evaluate(ctx, now=_clock()).failed_checks
    assert CHECK_ROLE in failed and CHECK_ASSIGNMENT in failed


def test_tlp_order_matches_first_v2():
    assert (Tlp.CLEAR < Tlp.GREEN < Tlp.AMBER < Tlp.AMBER_STRICT < Tlp.RED)


def test_tlp_from_name_parses_and_fails_closed():
    from noctornal_api.security.access import AccessResolutionError, tlp_from_name
    assert tlp_from_name("AMBER_STRICT") is Tlp.AMBER_STRICT
    for bad in ("amber", "SECRET", "", "AMBER "):
        with pytest.raises(AccessResolutionError):
            tlp_from_name(bad)
