"""Recovery codes (docs/05, enhancement E4) — unit tests, no database.

docs/05 asked for "10, single-use, Argon2id-hashed, regenerated as a set"
and it was specified but never built, which left the TOTP lockout with no
proper escape hatch on a host whose clock cannot agree with a phone.

The properties worth testing are the ones that make it a second factor
rather than a second password: a code works exactly once, a set replaces
rather than tops up, and the login path accepts one without becoming an
oracle for anything.
"""
from __future__ import annotations

from datetime import timedelta


from noctornal_api.security import recovery
from noctornal_api.security.auth import AuthOutcome, AuthService, AuthUser
from noctornal_api.security.passwords import hash_password
from noctornal_api.security.totp import generate_secret, code_at


def _enrolled(store, clock, email="a@b.test", password="correct horse battery"):
    """A real, active, TOTP-enrolled user with a known password."""
    from uuid import uuid4
    secret = generate_secret()
    user = AuthUser(
        id=uuid4(), is_active=True, password_hash=hash_password(password),
        totp_enrolled=True, totp_last_counter=None, failed_logins=0,
        locked_until=None,
    )
    store.add(email, user, secret)
    return user, secret, password


# --- shape and formatting ------------------------------------------------

def test_a_set_is_ten_distinct_codes():
    codes = recovery.generate_set()
    assert len(codes) == recovery.CODE_COUNT == 10
    assert len(set(codes)) == 10


def test_codes_avoid_characters_that_are_misread_off_paper():
    """These get printed, then typed back by someone already locked out."""
    joined = "".join(recovery.generate_set())
    for ambiguous in "01lIO":
        assert ambiguous not in joined


def test_normalise_accepts_what_a_human_actually_types():
    canonical = recovery.normalise("abcde-fghjk-mnpqr")
    for variant in ("ABCDE-FGHJK-MNPQR", "abcde fghjk mnpqr",
                    "abcdefghjkmnpqr", "  abcde--fghjk--mnpqr  "):
        assert recovery.normalise(variant) == canonical


def test_a_recovery_code_is_told_apart_from_a_totp_code_by_shape():
    """One login field takes either. A separate "use a recovery code"
    endpoint would have to answer before the password was checked, which is
    the oracle docs/00's open question D warns about."""
    assert recovery.looks_like_code(recovery.generate_code())
    assert not recovery.looks_like_code("123456")
    assert not recovery.looks_like_code("000000")
    assert not recovery.looks_like_code("")


# --- the login path ------------------------------------------------------

def test_a_recovery_code_authenticates_in_place_of_totp(user_store, clock):
    user, _secret, password = _enrolled(user_store, clock)
    codes = recovery.generate_set()
    user_store.set_recovery_codes(user.id, codes)
    result = AuthService(user_store, now=clock).authenticate(
        "a@b.test", password, codes[0])
    assert result.outcome is AuthOutcome.OK
    assert result.audit_reason == "ok_recovery_code"


def test_a_code_works_exactly_once(user_store, clock):
    """Single use is the whole point. A reusable code is a second password
    that bypasses the second factor forever."""
    user, _secret, password = _enrolled(user_store, clock)
    codes = recovery.generate_set()
    user_store.set_recovery_codes(user.id, codes)
    svc = AuthService(user_store, now=clock)
    assert svc.authenticate("a@b.test", password, codes[0]).ok
    second = svc.authenticate("a@b.test", password, codes[0])
    assert second.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert second.audit_reason == "bad_recovery_code"
    # The other nine are untouched.
    assert svc.authenticate("a@b.test", password, codes[1]).ok


def test_spending_a_code_leaves_the_rest_of_the_set(user_store, clock):
    user, _secret, password = _enrolled(user_store, clock)
    codes = recovery.generate_set()
    user_store.set_recovery_codes(user.id, codes)
    AuthService(user_store, now=clock).authenticate("a@b.test", password, codes[3])
    assert len(user_store.get_recovery_hashes(user.id)) == 9


def test_a_wrong_password_is_never_rescued_by_a_valid_code(user_store, clock):
    """The recovery code replaces the SECOND factor, not the first."""
    user, _secret, _password = _enrolled(user_store, clock)
    codes = recovery.generate_set()
    user_store.set_recovery_codes(user.id, codes)
    result = AuthService(user_store, now=clock).authenticate(
        "a@b.test", "wrong password", codes[0])
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.audit_reason == "bad_password"
    # And the code was NOT consumed by a failed password attempt.
    assert len(user_store.get_recovery_hashes(user.id)) == 10


def test_a_locked_account_cannot_be_opened_with_a_recovery_code(user_store, clock):
    """Lockout is about the account, not the factor. A recovery code that
    skipped it would make brute-forcing the password free again."""
    from uuid import uuid4
    password = "correct horse battery"
    codes = recovery.generate_set()
    user = AuthUser(
        id=uuid4(), is_active=True, password_hash=hash_password(password),
        totp_enrolled=True, totp_last_counter=None, failed_logins=5,
        locked_until=clock() + timedelta(minutes=10),
    )
    user_store.add("a@b.test", user, generate_secret())
    user_store.set_recovery_codes(user.id, codes)
    result = AuthService(user_store, now=clock).authenticate(
        "a@b.test", password, codes[0])
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.audit_reason == "locked"
    assert len(user_store.get_recovery_hashes(user.id)) == 10


def test_an_unknown_code_burns_a_lockout_attempt(user_store, clock):
    """Otherwise the recovery field is an unlimited guessing surface for
    anyone who already has the password."""
    user, _secret, password = _enrolled(user_store, clock)
    user_store.set_recovery_codes(user.id, recovery.generate_set())
    AuthService(user_store, now=clock).authenticate(
        "a@b.test", password, "zzzzz-zzzzz-zzzzz")
    assert user_store.users["a@b.test"].failed_logins == 1


def test_totp_still_works_when_recovery_codes_exist(user_store, clock):
    user, secret, password = _enrolled(user_store, clock)
    user_store.set_recovery_codes(user.id, recovery.generate_set())
    code = code_at(secret, int(clock().timestamp()))
    assert AuthService(user_store, now=clock).authenticate(
        "a@b.test", password, code).ok


def test_a_user_with_no_codes_is_not_broken_by_the_recovery_path(user_store, clock):
    user, _secret, password = _enrolled(user_store, clock)
    result = AuthService(user_store, now=clock).authenticate(
        "a@b.test", password, recovery.generate_code())
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.audit_reason == "bad_recovery_code"


def test_the_failure_reason_never_reaches_the_caller(user_store, clock):
    """audit_reason distinguishes bad_recovery_code from bad_totp for the
    audit trail; the OUTCOME the client sees is the same either way."""
    user, _secret, password = _enrolled(user_store, clock)
    user_store.set_recovery_codes(user.id, recovery.generate_set())
    svc = AuthService(user_store, now=clock)
    bad_code = svc.authenticate("a@b.test", password, "zzzzz-zzzzz-zzzzz")
    bad_totp = svc.authenticate("a@b.test", password, "000000")
    assert bad_code.outcome is bad_totp.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert bad_code.audit_reason != bad_totp.audit_reason
