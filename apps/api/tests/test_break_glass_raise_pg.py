"""Break-glass raises effective clearance -- the guarantee, finally held.

From 2026-08-10 to 2026-09-01 break_glass.py's own docstring said "AND IT
DOES NOT CURRENTLY RAISE ANYTHING": invoke() wrote a grant and no access
decision read it, so an analyst who invoked break-glass at 3am got a loud,
audited, reviewable record and exactly the access they already had. The
roadmap called it the most serious open finding: a stated emergency
control with no implementation.

These tests are written against `PgAccessResolver.resolve()` and
`evaluate()` directly -- the single construction site of the five-part
gate's context, which is where the raise now lives -- rather than through
HTTP, so that what is asserted is the decision and nothing else.

Every one of them FAILS on the commit before the raise was wired. The
last one asserts the thing the module has always promised and must keep
promising: a grant does not cross a compartment.

Env-gated on DATABASE_URL, like every other *_pg.py file.
"""
from __future__ import annotations

import os
from uuid import uuid4

import pytest

from test_governance_pg import _case, _user  # noqa: E402

DATABASE_URL = os.environ.get("DATABASE_URL", "")
pytestmark = pytest.mark.skipif(
    not DATABASE_URL, reason="DATABASE_URL not set; break-glass tests are gated"
)

os.environ.setdefault("NOCTORNAL_TOTP_KEK", "A" * 43 + "=")


@pytest.fixture
def conn():
    """Own connection and teardown. `iam.break_glass` and `audit.event` are
    append-only ledgers that carry foreign keys to the user, so the user
    and the case CANNOT be deleted once a grant or an audit row names them
    (the roadmap's "an append-only ledger outlives its subject" trap).
    Rows are left with a recognisable prefix instead; this is the same
    posture test_governance_pg takes."""
    from noctornal_api.db import connect
    c = connect()
    yield c
    c.close()


def _read_role(conn) -> str:
    """Whichever seeded case role carries `case.read`. Looked up rather
    than hard-coded so a reseed cannot silently turn this file into a test
    of the wrong permission."""
    row = conn.execute(
        "SELECT role_key FROM iam.role_permission WHERE permission_key = 'case.read' "
        "ORDER BY role_key LIMIT 1").fetchone()
    assert row, "no seeded role grants case.read"
    return row[0]


def _assign(conn, case_id, user_id, granted_by):
    conn.execute(
        """INSERT INTO iam.case_assignment (case_id, user_id, role_key, granted_by)
           VALUES (%s, %s, %s, %s)""",
        (case_id, user_id, _read_role(conn), granted_by))


def _set_clearance(conn, user_id, level):
    conn.execute("UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                 (level, user_id))


def _set_case_classification(conn, case_id, level):
    conn.execute('UPDATE core."case" SET classification = %s WHERE id = %s',
                 (level, case_id))


def _decide(conn, *, user_id, case_id, object_classification="AMBER",
            compartments=frozenset()):
    from noctornal_api.security.access import evaluate
    from noctornal_api.stores import PgAccessResolver
    ctx = PgAccessResolver(conn).resolve(
        user_id=user_id, case_id=case_id, permission_key="case.read",
        object_classification=object_classification,
        object_compartments=frozenset(compartments),
        mfa_satisfied_at=None)
    return evaluate(ctx)


def _green_analyst_on_an_amber_case(conn):
    """The shape of the emergency: an analyst cleared to GREEN, assigned to
    a case that has been raised to AMBER above them."""
    officer = _user(conn, "SECURITY_OFFICER")          # RED; can review
    analyst = _user(conn)                              # RED by fixture...
    _set_clearance(conn, analyst, "GREEN")             # ...GREEN for real
    case_id = _case(conn, officer)
    _set_case_classification(conn, case_id, "AMBER")
    _assign(conn, case_id, analyst, granted_by=officer)
    return officer, analyst, case_id


def test_without_a_grant_the_lattice_refuses_and_nothing_is_counted(conn):
    from noctornal_api.security.access import CHECK_CLEARANCE
    _, analyst, case_id = _green_analyst_on_an_amber_case(conn)
    d = _decide(conn, user_id=analyst, case_id=case_id)
    assert not d.allowed
    assert CHECK_CLEARANCE in d.failed_checks


def test_a_live_grant_raises_clearance_for_the_case_it_names(conn):
    """The guarantee. GREEN cannot read AMBER; invoke break-glass naming
    AMBER for this case; GREEN can now read AMBER on this case."""
    from noctornal_api.break_glass import BreakGlassService
    from noctornal_api.security.access import CHECK_CLEARANCE
    _, analyst, case_id = _green_analyst_on_an_amber_case(conn)
    svc = BreakGlassService(conn)

    assert CHECK_CLEARANCE in _decide(conn, user_id=analyst, case_id=case_id).failed_checks

    grant = svc.invoke(user_id=analyst, case_id=case_id, classification="AMBER",
                       justification="owner unreachable, live extortion deadline in 40 min")
    d = _decide(conn, user_id=analyst, case_id=case_id)
    assert d.allowed, d.failed_checks

    after = svc.get(grant.id)
    assert after.used_at is not None
    assert after.action_count == 1


def test_a_use_is_counted_only_when_the_grant_made_the_difference(conn):
    """An analyst reading a CLEAR node under an AMBER grant has not USED the
    grant. Counting it would tell the reviewing officer the emergency was
    busier than it was -- and the interesting review case is the grant
    that was barely used."""
    from noctornal_api.break_glass import BreakGlassService
    _, analyst, case_id = _green_analyst_on_an_amber_case(conn)
    svc = BreakGlassService(conn)
    grant = svc.invoke(user_id=analyst, case_id=case_id, classification="AMBER",
                       justification="owner unreachable, live extortion deadline in 40 min")

    # Below the analyst's own clearance: allowed on their own account, and
    # therefore NOT a use of the grant.
    d = _decide(conn, user_id=analyst, case_id=case_id, object_classification="GREEN")
    assert d.allowed
    assert svc.get(grant.id).action_count == 0

    # At the granted level: the grant is what made it possible. Twice.
    _decide(conn, user_id=analyst, case_id=case_id, object_classification="AMBER")
    _decide(conn, user_id=analyst, case_id=case_id, object_classification="AMBER")
    assert svc.get(grant.id).action_count == 2

    # ABOVE the granted level: still refused, and still not counted --
    # the grant did not make it possible.
    d = _decide(conn, user_id=analyst, case_id=case_id, object_classification="RED")
    assert not d.allowed
    assert svc.get(grant.id).action_count == 2


def test_a_grant_for_one_case_does_not_open_another(conn):
    """Scope. The emergency is on case A; case B is still refused."""
    from noctornal_api.break_glass import BreakGlassService
    officer, analyst, case_a = _green_analyst_on_an_amber_case(conn)
    case_b = _case(conn, officer)
    _set_case_classification(conn, case_b, "AMBER")
    _assign(conn, case_b, analyst, granted_by=officer)

    BreakGlassService(conn).invoke(
        user_id=analyst, case_id=case_a, classification="AMBER",
        justification="owner unreachable, live extortion deadline in 40 min")
    assert _decide(conn, user_id=analyst, case_id=case_a).allowed
    assert not _decide(conn, user_id=analyst, case_id=case_b).allowed


def test_a_global_grant_opens_every_case_and_the_search_ceiling(conn):
    """A grant with no case is global. It raises the gate on every case AND
    the case-agnostic ceiling search filters by -- the one place a
    case-scoped grant deliberately does not reach."""
    from noctornal_api.break_glass import BreakGlassService
    from noctornal_api.http.deps import user_ceiling
    from noctornal_api.security.access import Tlp
    officer, analyst, case_a = _green_analyst_on_an_amber_case(conn)
    case_b = _case(conn, officer)
    _set_case_classification(conn, case_b, "AMBER")
    _assign(conn, case_b, analyst, granted_by=officer)

    assert user_ceiling(conn, analyst)[0] == Tlp.GREEN
    BreakGlassService(conn).invoke(
        user_id=analyst, case_id=None, classification="AMBER",
        justification="owner unreachable, live extortion deadline in 40 min")
    assert _decide(conn, user_id=analyst, case_id=case_a).allowed
    assert _decide(conn, user_id=analyst, case_id=case_b).allowed
    assert user_ceiling(conn, analyst)[0] == Tlp.AMBER


def test_a_case_scoped_grant_leaves_the_search_ceiling_alone(conn):
    """The honest limit, asserted so it cannot drift: a grant on ONE case
    must not widen the caller's view of every other case, so the
    case-agnostic ceiling stays at the analyst's own clearance."""
    from noctornal_api.break_glass import BreakGlassService
    from noctornal_api.http.deps import user_ceiling
    from noctornal_api.security.access import Tlp
    _, analyst, case_id = _green_analyst_on_an_amber_case(conn)
    BreakGlassService(conn).invoke(
        user_id=analyst, case_id=case_id, classification="AMBER",
        justification="owner unreachable, live extortion deadline in 40 min")
    assert _decide(conn, user_id=analyst, case_id=case_id).allowed
    assert user_ceiling(conn, analyst)[0] == Tlp.GREEN


def test_revocation_closes_the_door_at_once(conn):
    from noctornal_api.break_glass import BreakGlassService
    officer, analyst, case_id = _green_analyst_on_an_amber_case(conn)
    svc = BreakGlassService(conn)
    grant = svc.invoke(user_id=analyst, case_id=case_id, classification="AMBER",
                       justification="owner unreachable, live extortion deadline in 40 min")
    assert _decide(conn, user_id=analyst, case_id=case_id).allowed
    svc.revoke(grant.id, actor_id=officer)
    assert not _decide(conn, user_id=analyst, case_id=case_id).allowed


def test_an_expired_grant_no_longer_raises(conn):
    """Aged in place: `expires_at` is tied to `started_at` by a CHECK, so
    both move together (the roadmap's "age the pair" trap)."""
    from noctornal_api.break_glass import BreakGlassService
    _, analyst, case_id = _green_analyst_on_an_amber_case(conn)
    grant = BreakGlassService(conn).invoke(
        user_id=analyst, case_id=case_id, classification="AMBER",
        justification="owner unreachable, live extortion deadline in 40 min")
    assert _decide(conn, user_id=analyst, case_id=case_id).allowed
    conn.execute(
        """UPDATE iam.break_glass
              SET started_at = now() - interval '9 hours',
                  expires_at = now() - interval '1 hour'
            WHERE id = %s""", (grant.id,))
    assert not _decide(conn, user_id=analyst, case_id=case_id).allowed


def test_a_grant_without_a_classification_raises_nothing(conn):
    """A grant is allowed to name no classification (a pure "I was here"
    record). It must not be read as a raise to anything."""
    from noctornal_api.break_glass import BreakGlassService
    _, analyst, case_id = _green_analyst_on_an_amber_case(conn)
    BreakGlassService(conn).invoke(
        user_id=analyst, case_id=case_id,
        justification="owner unreachable, live extortion deadline in 40 min")
    assert not _decide(conn, user_id=analyst, case_id=case_id).allowed


def test_a_grant_never_crosses_a_compartment(conn):
    """The promise the module has made since it was written, now asserted
    at the gate rather than only at the service: an emergency is not
    knowledge of the need. AMBER is raised; the compartment still refuses."""
    from noctornal_api.break_glass import BreakGlassService
    from noctornal_api.security.access import CHECK_CLEARANCE, CHECK_COMPARTMENTS
    _, analyst, case_id = _green_analyst_on_an_amber_case(conn)
    BreakGlassService(conn).invoke(
        user_id=analyst, case_id=case_id, classification="AMBER",
        justification="owner unreachable, live extortion deadline in 40 min")
    d = _decide(conn, user_id=analyst, case_id=case_id,
                compartments={f"OP-{uuid4().hex[:6].upper()}"})
    assert not d.allowed
    assert CHECK_COMPARTMENTS in d.failed_checks
    assert CHECK_CLEARANCE not in d.failed_checks     # the raise DID apply
