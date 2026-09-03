"""A missing account costs exactly one Argon2id verify, the same as a wrong
password on a real one.

`AuthService.authenticate` has equalised this since the service was
written: an unknown email verifies the submitted password against a fixed
dummy hash so that existence never leaks through response time. Until
2026-09-02 that property was described in two docstrings and asserted by
no test -- the pure auth suite covered outcomes and lockout, so the
equaliser could have been short-circuited out of the code (`user and
verify(...)`) and every test would still have passed. A defence nobody
tests is a defence that survives until the first refactor.

Wall-clock is deliberately NOT measured. Argon2id at 64 MiB varies by
tens of milliseconds between runs on a shared CI runner, and a timing
assertion loose enough not to flake would also be loose enough to miss a
real regression. What can be pinned exactly is the WORK: the hasher is
called once on every path, and the hash it is handed on the unknown-user
path is a real Argon2id hash with the production parameters -- not an
empty string, which `verify_password` rejects in microseconds and which
would make the equaliser decorative.

Pure: uses the in-memory store from conftest, no database.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from noctornal_api.security import auth as auth_mod
from noctornal_api.security.auth import AuthOutcome, AuthService, AuthUser

NOW = datetime(2026, 9, 2, 12, 0, 0, tzinfo=timezone.utc)

# The PHC prefix the production hasher emits (docs/05: Argon2id, t=3,
# m=64 MiB, p=4). A dummy hash with weaker parameters would verify faster
# than a real one and reintroduce the very oracle the dummy exists to close.
PRODUCTION_PHC_PREFIX = "$argon2id$v=19$m=65536,t=3,p=4$"


@pytest.fixture
def hasher_calls(monkeypatch):
    """Count calls to the hasher instead of timing them.

    Every call reports a mismatch, so no path can authenticate; what this
    file pins is that every path pays for exactly one verify.
    """
    calls: list[str] = []

    def counting_verify(stored_hash: str, password: str) -> bool:
        calls.append(stored_hash)
        return False

    monkeypatch.setattr(auth_mod.passwords, "verify_password", counting_verify)
    return calls


def _real_user(**overrides) -> AuthUser:
    fields = dict(
        id=uuid4(), is_active=True,
        password_hash=PRODUCTION_PHC_PREFIX + "c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA",
        totp_enrolled=True, totp_last_counter=None,
        failed_logins=0, locked_until=None,
    )
    fields.update(overrides)
    return AuthUser(**fields)


def _svc(user_store) -> AuthService:
    return AuthService(user_store, now=lambda: NOW)


def test_a_missing_account_runs_the_hasher_exactly_once(user_store, hasher_calls):
    result = _svc(user_store).authenticate("nobody@noctornal.test", "guess", "000000")
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert len(hasher_calls) == 1, (
        f"an unknown email must cost one verify, like a wrong password; "
        f"it cost {len(hasher_calls)}")


def test_the_missing_account_path_verifies_a_real_argon2id_hash(user_store, hasher_calls):
    """The dummy has to be a REAL hash with the production parameters.
    `verify_password('', ...)` returns in microseconds -- an equaliser
    that hands the hasher a placeholder does no work and equalises
    nothing."""
    _svc(user_store).authenticate("nobody@noctornal.test", "guess", "000000")
    (handed,) = hasher_calls
    assert handed.startswith(PRODUCTION_PHC_PREFIX), handed
    assert handed == auth_mod._DUMMY_HASH


def test_a_wrong_password_on_a_real_account_runs_the_hasher_exactly_once(
        user_store, hasher_calls):
    user = _real_user()
    user_store.add("real@noctornal.test", user, secret="JBSWY3DPEHPK3PXP")
    result = _svc(user_store).authenticate("real@noctornal.test", "wrong", "000000")
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert hasher_calls == [user.password_hash]


def test_unknown_and_wrong_password_cost_the_same_number_of_verifies(
        user_store, hasher_calls):
    """The property in one assertion: the two responses an attacker is
    trying to tell apart do identical work."""
    user_store.add("real@noctornal.test", _real_user(), secret="JBSWY3DPEHPK3PXP")
    svc = _svc(user_store)
    svc.authenticate("real@noctornal.test", "wrong", "000000")
    on_real = len(hasher_calls)
    del hasher_calls[:]
    svc.authenticate("nobody@noctornal.test", "wrong", "000000")
    on_missing = len(hasher_calls)
    assert on_real == on_missing == 1


@pytest.mark.parametrize("state", [
    pytest.param(dict(is_active=False), id="inactive"),
    pytest.param(dict(locked_until=NOW + timedelta(minutes=10)), id="locked"),
    pytest.param(dict(totp_enrolled=False), id="not-enrolled"),
])
def test_account_state_does_not_change_the_work_done(user_store, hasher_calls, state):
    """The module docstring claims state (active/locked) never leaks via
    timing either. Pinned the same way: one verify, whatever the state."""
    user_store.add("real@noctornal.test", _real_user(**state), secret="JBSWY3DPEHPK3PXP")
    result = _svc(user_store).authenticate("real@noctornal.test", "wrong", "000000")
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert len(hasher_calls) == 1
