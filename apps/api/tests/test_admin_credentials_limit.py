"""The admin credential routes have their own rate-limit meter (pure).

Final review U18 (2026-09-23). `POST /admin/users` and
`POST /admin/users/{id}/totp` were metered on `auth.recovery_codes`, the
administrator's OWN recovery-code bucket: three at once, then one every
twelve minutes. The console spends one of the three issuing the first
administrator's codes at their first sign-in, so a fresh install's
operator could add two colleagues before a 429. The HTTP proof is
`test_admin_credentials_limit_pg.py`; these pin the catalogue and the
wiring without a database.
"""
from __future__ import annotations

from pathlib import Path

from noctornal_api.ratelimit import LIMITS, OnBackendFailure, Scope

_SRC = Path(__file__).resolve().parents[1] / "src" / "noctornal_api"


def _dep_limit_name(route) -> set[str]:
    """The limit names a route's rate-limit dependencies were built with,
    read off the closure `rate_limit()` returns (its `name` cell)."""
    names = set()
    for dep in route.dependant.dependencies:
        fn = dep.call
        if getattr(fn, "__name__", "") not in ("_user_dep", "_ip_dep",
                                                "_credential_dep"):
            continue
        for var, cell in zip(fn.__code__.co_freevars, fn.__closure__ or (),
                             strict=True):
            if var == "name":
                names.add(cell.cell_contents)
    return names


def _routes():
    """The two routers' own routes. Not `create_app()`, which builds a
    limiter and would reach for whatever Redis the environment names."""
    from noctornal_api.http.routers import admin, auth
    return {(tuple(sorted(r.methods)), r.path): r
            for router in (admin.router, auth.router) for r in router.routes
            if hasattr(r, "dependant")}


def test_admin_credential_routes_do_not_spend_the_recovery_code_bucket():
    routes = _routes()
    for path in ("/admin/users", "/admin/users/{user_id}/totp"):
        names = _dep_limit_name(routes[(("POST",), path)])
        assert names == {"admin.credentials"}, (path, names)
    # ...and the recovery-code route still has its own, unchanged.
    assert _dep_limit_name(
        routes[(("POST",), "/auth/recovery-codes")]) == {"auth.recovery_codes"}


def test_the_admin_meter_lets_a_unit_be_stood_up_in_one_sitting():
    """Sized for onboarding: well above the three the old shared bucket
    allowed, still per administrator, and closed when it cannot measure."""
    limit = LIMITS["admin.credentials"]
    assert limit.scope is Scope.USER
    assert limit.on_backend_failure is OnBackendFailure.DENY
    assert limit.effective_burst >= 10
    assert limit.effective_burst > LIMITS["auth.recovery_codes"].effective_burst
    # The recovery-code meter itself is not loosened by this change.
    assert LIMITS["auth.recovery_codes"].effective_burst == 3
    assert LIMITS["auth.recovery_codes"].quota == 5


def test_admin_router_names_no_recovery_code_meter():
    source = (_SRC / "http" / "routers" / "admin.py").read_text(encoding="utf-8")
    assert 'rate_limit("auth.recovery_codes")' not in source
