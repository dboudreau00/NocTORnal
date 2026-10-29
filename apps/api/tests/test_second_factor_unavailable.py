"""A stored TOTP secret that cannot be opened is never looked at for a wrong
password, and is not needed for a recovery code. How it is answered is in
test_unopenable_totp_counts_as_a_failed_login.py. No database: the store is a
fake.
"""
from __future__ import annotations

from uuid import uuid4

from noctornal_api.security import passwords
from noctornal_api.security.auth import AuthOutcome, AuthService, AuthUser

PASSWORD = "right-password"


class _Store:
    """Just enough of the protocol: one enrolled, active, unlocked user
    whose secret does not open."""

    def __init__(self, raises: Exception):
        self.user = AuthUser(id=uuid4(), is_active=True,
                             password_hash=passwords.hash_password(PASSWORD),
                             totp_enrolled=True, totp_last_counter=None,
                             failed_logins=0, locked_until=None)
        self.raises = raises
        self.failed: list = []
        self.cleared: list = []

    def get_for_auth(self, email):
        return self.user if email == "a@x" else None

    def get_totp_secret(self, user_id):
        raise self.raises

    def advance_totp_counter(self, user_id, new_counter):
        raise AssertionError("never reached: there was no secret to verify")

    def record_failed_login(self, user_id, threshold, lock_until):
        self.failed.append(user_id)

    def clear_failed_logins(self, user_id, at):
        self.cleared.append(user_id)

    def get_recovery_hashes(self, user_id):
        return []

    def consume_recovery_hash(self, user_id, code_hash):
        return False


def test_a_wrong_password_never_reaches_the_secret():
    """The secret is opened only after the password verified."""
    store = _Store(AssertionError("get_totp_secret must not be called"))
    result = AuthService(store).authenticate("a@x", "wrong", "123456")
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert store.failed == [store.user.id]


def test_a_recovery_code_does_not_need_the_secret_at_all():
    """The documented fallback for a lost authenticator is also the
    fallback for a lost KEY: a recovery code is checked against Argon2id
    hashes, never against the sealed secret, so an analyst holding one
    can still sign in while the ring is being repaired."""
    from noctornal_api.security import recovery
    store = _Store(AssertionError("get_totp_secret must not be called"))
    code = recovery.generate_set(1)[0]
    store.consume_recovery_hash = lambda user_id, code_hash: True
    store.get_recovery_hashes = lambda user_id: [passwords.hash_recovery_code(code)]
    result = AuthService(store).authenticate("a@x", PASSWORD, code)
    assert result.ok and result.audit_reason == "ok_recovery_code"
