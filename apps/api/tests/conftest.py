"""Shared test fixtures: in-memory stores and a controllable clock.

These let the auth/session POLICY be tested without a database; the
Postgres-backed stores are exercised separately by the env-gated
integration test.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest

# A deterministic KEK so envelope-encryption tests never touch a real key.
os.environ.setdefault(
    "NOCTORNAL_TOTP_KEK", "A" * 43 + "="  # 32 zero-ish bytes, valid base64
)

from noctornal_api.security.auth import AuthUser, UserStore
from noctornal_api.security.sessions import SessionRecord, SessionStore


class Clock:
    """A movable clock injected as `now` into the services under test."""

    def __init__(self, start: datetime):
        self._t = start

    def __call__(self) -> datetime:
        return self._t

    def advance(self, delta) -> None:
        self._t = self._t + delta

    def set(self, t: datetime) -> None:
        self._t = t


@pytest.fixture
def clock() -> Clock:
    return Clock(datetime(2026, 7, 24, 12, 0, 0, tzinfo=timezone.utc))


class InMemoryUserStore(UserStore):
    """Mirrors the Postgres store's atomic semantics (compare-and-set
    counter advance, post-increment lockout) in a single-threaded dict."""

    def __init__(self) -> None:
        self.users: dict[str, AuthUser] = {}
        self.secrets: dict[UUID, str] = {}
        self.counters: dict[UUID, int] = {}
        self.cleared: list[UUID] = []
        self.recovery: dict[UUID, list[str]] = {}

    def add(self, email: str, user: AuthUser, secret: str | None = None) -> None:
        self.users[email.lower()] = user
        if secret is not None:
            self.secrets[user.id] = secret

    def _email_of(self, user_id: UUID) -> str | None:
        for email, u in self.users.items():
            if u.id == user_id:
                return email
        return None

    def get_for_auth(self, email: str) -> AuthUser | None:
        return self.users.get(email.lower())

    def get_totp_secret(self, user_id: UUID) -> str | None:
        return self.secrets.get(user_id)

    def advance_totp_counter(self, user_id: UUID, new_counter: int) -> bool:
        from dataclasses import replace
        email = self._email_of(user_id)
        if email is None:
            return False
        current = self.users[email].totp_last_counter
        if current is not None and new_counter <= current:
            return False  # compare-and-set: already consumed → replay
        self.counters[user_id] = new_counter
        self.users[email] = replace(self.users[email], totp_last_counter=new_counter)
        return True

    def record_failed_login(self, user_id: UUID, threshold: int, lock_until) -> None:
        from dataclasses import replace
        email = self._email_of(user_id)
        if email is None:
            return
        u = self.users[email]
        new_count = u.failed_logins + 1
        # Post-increment lockout; never clear an existing lock.
        locked_until = u.locked_until
        if new_count >= threshold:
            locked_until = max(locked_until, lock_until) if locked_until else lock_until
        self.users[email] = replace(u, failed_logins=new_count, locked_until=locked_until)

    def set_recovery_codes(self, user_id: UUID, codes: list[str]) -> None:
        from noctornal_api.security import passwords
        self.recovery[user_id] = [passwords.hash_recovery_code(c) for c in codes]

    def get_recovery_hashes(self, user_id: UUID) -> list[str]:
        return list(self.recovery.get(user_id, []))

    def consume_recovery_hash(self, user_id: UUID, code_hash: str) -> bool:
        """Mirrors the Postgres store's atomic remove-if-present."""
        held = self.recovery.get(user_id, [])
        if code_hash not in held:
            return False
        self.recovery[user_id] = [h for h in held if h != code_hash]
        return True

    def clear_failed_logins(self, user_id: UUID, at: datetime) -> None:
        from dataclasses import replace
        email = self._email_of(user_id)
        if email is None:
            return
        self.cleared.append(user_id)
        self.users[email] = replace(self.users[email], failed_logins=0, locked_until=None)


class InMemorySessionStore(SessionStore):
    def __init__(self) -> None:
        self.by_hash: dict[bytes, SessionRecord] = {}

    def insert(self, record: SessionRecord) -> None:
        self.by_hash[record.token_hash] = record

    def get_by_token_hash(self, token_hash: bytes) -> SessionRecord | None:
        return self.by_hash.get(token_hash)

    def update(self, record: SessionRecord) -> None:
        self.by_hash[record.token_hash] = record

    def revoke(self, session_id: UUID, reason: str, at: datetime) -> bool:
        from dataclasses import replace
        for h, rec in list(self.by_hash.items()):
            if rec.id == session_id and rec.revoked_at is None:
                self.by_hash[h] = replace(rec, revoked_at=at, revoke_reason=reason)
                return True
        return False

    def revoke_all_for_user(self, user_id: UUID, reason: str, at: datetime) -> int:
        from dataclasses import replace
        n = 0
        for h, rec in list(self.by_hash.items()):
            if rec.user_id == user_id and rec.revoked_at is None:
                self.by_hash[h] = replace(rec, revoked_at=at, revoke_reason=reason)
                n += 1
        return n


@pytest.fixture
def user_store() -> InMemoryUserStore:
    return InMemoryUserStore()


@pytest.fixture
def session_store() -> InMemorySessionStore:
    return InMemorySessionStore()


@pytest.fixture
def new_uuid():
    return uuid4
