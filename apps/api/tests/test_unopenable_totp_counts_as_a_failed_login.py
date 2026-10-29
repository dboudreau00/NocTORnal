"""A stored TOTP secret that cannot be opened is answered as an invalid
credential, and it burns a lockout attempt.

An answer of its own would be reachable only with the right password, so it
would confirm the password to a guesser for as long as the secret stays
unopenable, with no lockout to stop the guessing. No database: the store is a
fake that raises what the envelope raises.
"""
from __future__ import annotations

from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from cryptography.exceptions import InvalidTag

from noctornal_api.security import envelope, passwords
from noctornal_api.security.auth import AuthOutcome, AuthService, AuthUser

EMAIL = "analyst@noctornal.test"
PASSWORD = "right-password"


class _UnopenableSecretStore:
    """One enrolled, active, unlocked account whose secret does not open."""

    def __init__(self, raises: Exception) -> None:
        self.raises = raises
        self.user = AuthUser(id=uuid4(), is_active=True,
                             password_hash=passwords.hash_password(PASSWORD),
                             totp_enrolled=True, totp_last_counter=None,
                             failed_logins=0, locked_until=None)
        self.cleared: list = []

    def get_for_auth(self, email: str) -> AuthUser | None:
        return self.user if email.lower() == EMAIL else None

    def get_totp_secret(self, user_id: UUID) -> str | None:
        raise self.raises

    def advance_totp_counter(self, user_id: UUID, new_counter: int) -> bool:
        raise AssertionError("never reached: there was no secret to verify")

    def record_failed_login(self, user_id: UUID, threshold: int, lock_until) -> None:
        self.user = replace(self.user, failed_logins=self.user.failed_logins + 1)

    def clear_failed_logins(self, user_id: UUID, at) -> None:
        self.cleared.append(user_id)

    def get_recovery_hashes(self, user_id: UUID) -> list[str]:
        return []

    def consume_recovery_hash(self, user_id: UUID, code_hash: str) -> bool:
        return False


@pytest.mark.parametrize("raises", [
    InvalidTag(),                          # a key of that id that does not open it
    envelope.KeyUnavailable("env:v0"),     # no key of that id in the ring
])
def test_an_unopenable_second_factor_is_an_invalid_credential(raises):
    """The right password gets the same outcome as a wrong one, and one
    lockout attempt is spent. The cause is kept for the audit trail only."""
    store = _UnopenableSecretStore(raises)
    result = AuthService(store).authenticate(EMAIL, PASSWORD, "123456")
    assert result.outcome is AuthOutcome.INVALID_CREDENTIALS
    assert result.user_id is None
    assert result.audit_reason == "totp_secret_unopenable"
    assert store.user.failed_logins == 1
    assert store.cleared == []


def test_it_matches_what_a_wrong_password_gets():
    store = _UnopenableSecretStore(envelope.KeyUnavailable("env:v0"))
    right = AuthService(store).authenticate(EMAIL, PASSWORD, "123456")
    wrong = AuthService(store).authenticate(EMAIL, "wrong-password", "123456")
    assert (right.outcome, right.user_id) == (wrong.outcome, wrong.user_id)
    assert store.user.failed_logins == 2
