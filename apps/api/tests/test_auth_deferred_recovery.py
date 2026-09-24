"""A recovery code checked at sign-in and spent only when the sign-in goes
ahead (final review u4, 2026-09-24). Unit tests, no database.

Sign-in's must-change and no-change-pending refusals answer after the
credentials are checked, and `authenticate` used to spend a recovery code
on the way, so a refusal cost the person a single-use code for nothing.
`authenticate(spend_recovery=False)` now checks the code and hands its hash
back, and `AuthService.spend` removes it atomically when the session is
about to be minted. What must still hold: a code works once, the loser of
a race is a failure that counts, and the hash never reaches a repr.
`routers/auth.py` login is exercised end to end in
test_issued_password_signin_pg.py.
"""
from __future__ import annotations

from uuid import uuid4

from noctornal_api.security import recovery
from noctornal_api.security.auth import AuthOutcome, AuthService, AuthUser
from noctornal_api.security.passwords import hash_password
from noctornal_api.security.totp import code_at, generate_secret

PASSWORD = "correct horse battery"


def _enrolled(store, codes):
    user = AuthUser(
        id=uuid4(), is_active=True, password_hash=hash_password(PASSWORD),
        totp_enrolled=True, totp_last_counter=None, failed_logins=0,
        locked_until=None,
    )
    store.add("a@b.test", user, generate_secret())
    store.set_recovery_codes(user.id, codes)
    return user


def test_a_checked_code_is_not_spent_until_the_sign_in_goes_ahead(
        user_store, clock):
    codes = recovery.generate_set(2)
    user = _enrolled(user_store, codes)
    svc = AuthService(user_store, now=clock)

    checked = svc.authenticate("a@b.test", PASSWORD, codes[0],
                               spend_recovery=False)
    assert checked.outcome is AuthOutcome.OK
    assert checked.audit_reason == "ok_recovery_code"
    assert checked.recovery_hash
    assert checked.recovery_hash not in repr(checked)
    assert len(user_store.get_recovery_hashes(user.id)) == 2, (
        "checking a code spent it")

    # A refusal after the check leaves it usable: check it again.
    again = svc.authenticate("a@b.test", PASSWORD, codes[0],
                             spend_recovery=False)
    assert again.ok

    assert svc.spend(again) is True
    assert len(user_store.get_recovery_hashes(user.id)) == 1
    later = svc.authenticate("a@b.test", PASSWORD, codes[0],
                             spend_recovery=False)
    assert later.outcome is AuthOutcome.INVALID_CREDENTIALS, (
        "a spent code checked out again")


def test_the_loser_of_a_race_for_one_code_fails_and_counts(user_store, clock):
    codes = recovery.generate_set(1)
    user = _enrolled(user_store, codes)
    svc = AuthService(user_store, now=clock)
    first = svc.authenticate("a@b.test", PASSWORD, codes[0], spend_recovery=False)
    second = svc.authenticate("a@b.test", PASSWORD, codes[0], spend_recovery=False)
    assert first.ok and second.ok
    assert svc.spend(first) is True
    assert svc.spend(second) is False, "one code opened two sessions"
    assert user_store.users["a@b.test"].failed_logins == 1
    assert user_store.get_recovery_hashes(user.id) == []


def test_every_other_caller_still_spends_at_once(user_store, clock):
    codes = recovery.generate_set(2)
    user = _enrolled(user_store, codes)
    svc = AuthService(user_store, now=clock)
    result = svc.authenticate("a@b.test", PASSWORD, codes[0])
    assert result.ok and result.recovery_hash is None
    assert len(user_store.get_recovery_hashes(user.id)) == 1
    assert svc.spend(result) is True, "nothing left to spend is not a failure"


def test_a_totp_sign_in_has_nothing_to_spend_and_a_failure_spends_nothing(
        user_store, clock):
    user = _enrolled(user_store, recovery.generate_set(1))
    svc = AuthService(user_store, now=clock)
    secret = user_store.get_totp_secret(user.id)
    ok = svc.authenticate("a@b.test", PASSWORD,
                          code_at(secret, int(clock().timestamp())),
                          spend_recovery=False)
    assert ok.ok and ok.recovery_hash is None and svc.spend(ok) is True
    bad = svc.authenticate("a@b.test", "wrong", "zzzzz-zzzzz-zzzzz",
                           spend_recovery=False)
    assert svc.spend(bad) is False
    assert len(user_store.get_recovery_hashes(user.id)) == 1
