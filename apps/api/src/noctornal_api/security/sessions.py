"""Server-side opaque sessions with absolute and idle expiry.

docs/05: absolute expiry 12 h, idle expiry 30 min, both enforced
server-side; only the token hash is stored; global revocation; step-up
freshness clock (mfa_satisfied_at). The store is a protocol so the policy
here is testable in-memory and backed by iam.session in production.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import UUID

from noctornal_api.security.tokens import hash_token, new_session_token

ABSOLUTE_LIFETIME = timedelta(hours=12)
IDLE_TIMEOUT = timedelta(minutes=30)
STEP_UP_FRESHNESS = timedelta(minutes=15)  # docs/05 sensitive-op re-challenge


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class SessionRecord:
    id: UUID
    user_id: UUID
    token_hash: bytes
    issued_at: datetime
    expires_at: datetime            # absolute deadline
    last_seen_at: datetime
    mfa_satisfied_at: datetime | None
    revoked_at: datetime | None = None
    revoke_reason: str | None = None


class SessionStore(Protocol):
    def insert(self, record: SessionRecord) -> None: ...
    def get_by_token_hash(self, token_hash: bytes) -> SessionRecord | None: ...
    def update(self, record: SessionRecord) -> None: ...
    def revoke(self, session_id: UUID, reason: str, at: datetime) -> bool: ...
    def revoke_all_for_user(self, user_id: UUID, reason: str, at: datetime) -> int: ...


@dataclass(frozen=True)
class ValidationResult:
    session: SessionRecord | None
    reason: str | None = None  # 'revoked' | 'absolute_expired' | 'idle_expired' | 'not_found'

    @property
    def ok(self) -> bool:
        return self.session is not None


class SessionService:
    def __init__(self, store: SessionStore, *, now=_utcnow):
        self._store = store
        self._now = now

    def create(
        self,
        session_id: UUID,
        user_id: UUID,
        *,
        mfa_satisfied: bool,
    ) -> tuple[SessionRecord, str]:
        """Create a session and return (record, raw_token). The raw token
        is shown to the client once; only its hash is persisted."""
        now = self._now()
        token = new_session_token()
        record = SessionRecord(
            id=session_id,
            user_id=user_id,
            token_hash=token.hash,
            issued_at=now,
            expires_at=now + ABSOLUTE_LIFETIME,
            last_seen_at=now,
            mfa_satisfied_at=now if mfa_satisfied else None,
        )
        self._store.insert(record)
        return record, token.raw

    def validate(self, raw_token: str, *, touch: bool = True) -> ValidationResult:
        """Resolve a raw token to a live session, enforcing revocation and
        both expiries server-side. On success, slides the idle window
        (unless touch=False, e.g. for a read-only freshness probe)."""
        record = self._store.get_by_token_hash(hash_token(raw_token))
        if record is None:
            return ValidationResult(None, "not_found")
        now = self._now()
        if record.revoked_at is not None:
            return ValidationResult(None, "revoked")
        if now >= record.expires_at:
            return ValidationResult(None, "absolute_expired")
        if now - record.last_seen_at >= IDLE_TIMEOUT:
            return ValidationResult(None, "idle_expired")
        if touch:
            record = replace(record, last_seen_at=now)
            self._store.update(record)
        return ValidationResult(record)

    def is_step_up_fresh(self, record: SessionRecord) -> bool:
        """True if MFA was satisfied recently enough for a step-up
        permission (docs/05: within 15 minutes)."""
        if record.mfa_satisfied_at is None:
            return False
        return self._now() - record.mfa_satisfied_at < STEP_UP_FRESHNESS

    def mark_mfa_satisfied(self, record: SessionRecord) -> SessionRecord:
        updated = replace(record, mfa_satisfied_at=self._now())
        self._store.update(updated)
        return updated

    def revoke(self, session_id: UUID, reason: str) -> bool:
        """Revoke ONE session — an ordinary logout. Killing every session
        for the user would evict their other devices (docs/05 lists global
        revocation as a separate, deliberate capability)."""
        return self._store.revoke(session_id, reason, self._now())

    def revoke_all_for_user(self, user_id: UUID, reason: str) -> int:
        """Global revocation: password change, admin kill-all, security
        officer action, or account deactivation."""
        return self._store.revoke_all_for_user(user_id, reason, self._now())
