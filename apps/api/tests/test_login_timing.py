"""A missing account costs exactly one Argon2id verify, the same as a wrong password on a real one.

`AuthService.authenticate` equalises this: an unknown email verifies the submitted password against a fixed
dummy hash so that existence never leaks through response time. Without a test the equaliser could be
short-circuited out of the code (`user and verify(...)`) and every outcome and lockout test would still
pass.

Wall-clock is deliberately not measured. Argon2id at 64 MiB varies by tens of milliseconds between runs on a
shared CI runner, and a timing assertion loose enough not to flake would be loose enough to miss a real
regression. What can be pinned exactly is the work: the hasher is called once on every path, and the hash it
is handed on the unknown-user path is a real Argon2id hash with the production parameters, not an empty
string, which `verify_password` rejects in microseconds and which would make the equaliser decorative.

A recovery-shaped second factor adds recovery verifies, and those are pinned the same way: exactly
`recovery.CODE_COUNT` of them on every path, whatever the account holds, because a count that depended on
the account would let the wait say the password was right. They go through a binding of their own
(`passwords.verify_recovery_code`), which the first fixture below never sees, so `recovery_hasher` counts both.

Pure: uses the in-memory store from conftest, no database.
"""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from noctornal_api.security import auth as auth_mod
from noctornal_api.security import recovery
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


# --- a recovery-shaped second factor ------------------------------------------------------------------

PASSWORD = "the-right-password"
HELD_PREFIX = "$argon2id$v=19$m=65536,t=3,p=4$held-"
RECOVERY_SHAPED = "abcde-fghjk-mnpqr"
WRONG_RECOVERY_SHAPED = "zzzzz-zzzzz-zzzzz"
SIX_DIGITS = "123456"


def held(code: str) -> str:
    """What the stand-in below stores for a recovery code: its normalised form after a recognisable prefix."""
    return HELD_PREFIX + recovery.normalise(code)


class _Hasher:
    """Both verify bindings, counted. Their answers are stood in for, so the paths that need a right password
    or a right code can be taken without hashing: a password verifies when it is PASSWORD against the
    account's own hash, a recovery code when the stored value is the one `held` makes for it. Everything
    else, the dummy hash included, mismatches."""

    def __init__(self, user: AuthUser):
        self.user = user
        self.password: list[str] = []
        self.recovery: list[str] = []

    def verify_password(self, stored_hash: str, password: str) -> bool:
        self.password.append(stored_hash)
        return stored_hash == self.user.password_hash and password == PASSWORD

    def verify_recovery_code(self, stored_hash: str, code: str) -> bool:
        self.recovery.append(stored_hash)
        return stored_hash == held(code)

    def work(self) -> tuple[int, int]:
        return len(self.password), len(self.recovery)


@pytest.fixture
def recovery_hasher(monkeypatch):
    hasher = _Hasher(_real_user())
    monkeypatch.setattr(auth_mod.passwords, "verify_password", hasher.verify_password)
    monkeypatch.setattr(auth_mod.passwords, "verify_recovery_code", hasher.verify_recovery_code)
    return hasher


def _hold(user_store, hasher, codes: int, **account) -> AuthUser:
    """The real account, holding `codes` recovery codes, the first of which is RECOVERY_SHAPED."""
    user = replace(hasher.user, **account)
    hasher.user = user
    user_store.add("real@noctornal.test", user, secret="JBSWY3DPEHPK3PXP")
    first = [held(RECOVERY_SHAPED)] if codes else []
    user_store.recovery[user.id] = first + [held(c) for c in recovery.generate_set(max(codes - 1, 0))]
    return user


#: Every way a sign-in with a recovery-shaped code can end: the account's state (None for no account), how
#: many codes it holds, the email, password and code sent, and whether it signs in. Each must cost one password
#: verify and CODE_COUNT recovery verifies.
_PATHS = [
    pytest.param(None, 0, "nobody@noctornal.test", PASSWORD, RECOVERY_SHAPED, False, id="unknown-account"),
    pytest.param({}, 10, "real@noctornal.test", "wrong", RECOVERY_SHAPED, False, id="wrong-password"),
    pytest.param(dict(is_active=False), 10, "real@noctornal.test", PASSWORD, RECOVERY_SHAPED, False,
                 id="inactive"),
    pytest.param(dict(locked_until=NOW + timedelta(minutes=10)), 10, "real@noctornal.test", PASSWORD,
                 RECOVERY_SHAPED, False, id="locked"),
    pytest.param(dict(totp_enrolled=False), 10, "real@noctornal.test", PASSWORD, RECOVERY_SHAPED, False,
                 id="not-enrolled"),
    pytest.param({}, 10, "real@noctornal.test", PASSWORD, WRONG_RECOVERY_SHAPED, False,
                 id="right-password-wrong-code-ten-held"),
    pytest.param({}, 3, "real@noctornal.test", PASSWORD, WRONG_RECOVERY_SHAPED, False,
                 id="right-password-wrong-code-three-held"),
    pytest.param({}, 0, "real@noctornal.test", PASSWORD, WRONG_RECOVERY_SHAPED, False,
                 id="right-password-wrong-code-none-held"),
    pytest.param({}, 10, "real@noctornal.test", PASSWORD, RECOVERY_SHAPED, True,
                 id="right-password-right-code-ten-held"),
    pytest.param({}, 1, "real@noctornal.test", PASSWORD, RECOVERY_SHAPED, True,
                 id="right-password-right-code-one-held"),
]


@pytest.mark.parametrize("account, codes, email, password, code, signs_in", _PATHS)
def test_a_recovery_shaped_code_costs_the_same_work_on_every_path(
        user_store, recovery_hasher, account, codes, email, password, code, signs_in):
    """SIGNIN-01. A correct password with a recovery-shaped code used to cost one verify per stored recovery
    hash on top of the password's, and a wrong password one: the wait said which password was right. The
    work is fixed at what an account can hold, padded with the dummy hash, on EVERY path."""
    if account is not None:
        _hold(user_store, recovery_hasher, codes, **account)
    result = _svc(user_store).authenticate(email, password, code)
    assert result.ok is signs_in
    assert recovery_hasher.work() == (1, recovery.CODE_COUNT), (
        f"(password verifies, recovery verifies) was {recovery_hasher.work()}; a recovery-shaped "
        f"code must cost (1, {recovery.CODE_COUNT}) however the account stands")


def test_a_set_the_database_somehow_holds_beyond_ten_still_costs_ten(user_store, recovery_hasher):
    """Issuing never makes more than CODE_COUNT, but the column is an unbounded array, and a count that
    followed its length would be the oracle again for the one account that held more."""
    _hold(user_store, recovery_hasher, recovery.CODE_COUNT + 5)
    result = _svc(user_store).authenticate("real@noctornal.test", PASSWORD, WRONG_RECOVERY_SHAPED)
    assert not result.ok
    assert recovery_hasher.work() == (1, recovery.CODE_COUNT)


def test_the_padding_is_the_dummy_hash_and_a_failed_password_reads_no_stored_hash(
        user_store, recovery_hasher):
    """A sign-in that failed before its second factor counted (a wrong password here) verifies the dummy
    hash alone: it never reads, let alone verifies, the account's stored hashes."""
    _hold(user_store, recovery_hasher, 10)
    _svc(user_store).authenticate("real@noctornal.test", "wrong", RECOVERY_SHAPED)
    assert recovery_hasher.recovery == [auth_mod._DUMMY_HASH] * recovery.CODE_COUNT


def test_a_short_set_is_checked_in_full_and_padded_with_the_dummy_hash(user_store, recovery_hasher):
    user = _hold(user_store, recovery_hasher, 3)
    _svc(user_store).authenticate("real@noctornal.test", PASSWORD, WRONG_RECOVERY_SHAPED)
    stored = user_store.recovery[user.id]
    assert sorted(recovery_hasher.recovery) == sorted(stored + [auth_mod._DUMMY_HASH] * (10 - 3))


@pytest.mark.parametrize("account, codes, email, password, code", [
    pytest.param(None, 0, "nobody@noctornal.test", PASSWORD, SIX_DIGITS, id="unknown-account"),
    pytest.param({}, 10, "real@noctornal.test", "wrong", SIX_DIGITS, id="wrong-password"),
    pytest.param(dict(is_active=False), 10, "real@noctornal.test", PASSWORD, SIX_DIGITS, id="inactive"),
    pytest.param({}, 10, "real@noctornal.test", PASSWORD, SIX_DIGITS, id="right-password-wrong-code"),
    pytest.param({}, 10, "real@noctornal.test", PASSWORD, None, id="right-password-no-code"),
    pytest.param({}, 10, "real@noctornal.test", PASSWORD, "", id="right-password-empty-code"),
])
def test_a_six_digit_code_still_costs_one_verify_and_no_recovery_work(
        user_store, recovery_hasher, account, codes, email, password, code):
    """The recovery padding belongs to the recovery shape alone: an authenticator code is still one password
    verify, so the common sign-in does not pay ten more."""
    if account is not None:
        _hold(user_store, recovery_hasher, codes, **account)
    _svc(user_store).authenticate(email, password, code)
    assert recovery_hasher.work() == (1, 0)
