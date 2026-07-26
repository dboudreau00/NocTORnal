"""Authentication service: password + mandatory TOTP.

Single-step: the caller submits password AND TOTP code together and gets
back exactly one of OK or INVALID_CREDENTIALS. The specific reason (wrong
password, wrong code, locked, inactive, not enrolled, replay, unknown
user) is carried in `audit_reason` for the server-side audit trail ONLY
and must never reach the client — otherwise the response becomes a
password/enumeration oracle (a correct-password-without-code that returned
a distinct "now enter your code" would confirm the password for free).

Defences, all exercised by tests:
- Constant work: every attempt runs one Argon2id verify (the real hash if
  the user exists, a fixed dummy hash otherwise) BEFORE any state branch,
  so timing and outcome do not reveal whether an account exists or its
  state (active/locked). Enumeration-resistant.
- Mandatory MFA: a correct password alone never authenticates, and a
  correct-password/no-code probe still consumes a lockout attempt, so it
  is not a free password oracle.
- Replay protection is atomic at the store: the TOTP counter advance is a
  compare-and-set; if a concurrent login already consumed the code the
  advance reports failure and authentication fails.
- Lockout is computed from the post-increment value in the store, never a
  stale read, and never clears an existing lock.

A two-step "password first, then code" UX would need a short-lived opaque
MFA ticket issued indistinguishably whether or not the password was
correct; that is deferred (see docs/00 backlog).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol
from uuid import UUID

from noctornal_api.security import passwords, recovery, totp

MAX_FAILED_LOGINS = 5
LOCKOUT_DURATION = timedelta(minutes=15)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthOutcome(Enum):
    OK = "ok"
    INVALID_CREDENTIALS = "invalid_credentials"  # the ONLY failure the caller sees


@dataclass(frozen=True)
class AuthUser:
    id: UUID
    is_active: bool
    password_hash: str | None
    totp_enrolled: bool                # whether a TOTP secret exists (no secret here)
    totp_last_counter: int | None
    failed_logins: int
    locked_until: datetime | None


class UserStore(Protocol):
    def get_for_auth(self, email: str) -> AuthUser | None: ...
    def get_totp_secret(self, user_id: UUID) -> str | None: ...
    # Atomic compare-and-set: advance only if new_counter is strictly
    # greater than the stored one (NULL treated as -inf). Returns False if
    # a concurrent login already consumed this or a later step (replay).
    def advance_totp_counter(self, user_id: UUID, new_counter: int) -> bool: ...
    # Atomic: increment failed_logins and set locked_until iff the
    # post-increment count reaches `threshold`; never clears an existing lock.
    def record_failed_login(
        self, user_id: UUID, threshold: int, lock_until: datetime
    ) -> None: ...
    def clear_failed_logins(self, user_id: UUID, at: datetime) -> None: ...
    # Recovery codes (docs/05). The stored Argon2id hashes, and an ATOMIC
    # single-use consume: remove exactly this hash and report whether the
    # row was still there. Verifying then deleting would let two concurrent
    # logins spend the same code.
    def get_recovery_hashes(self, user_id: UUID) -> list[str]: ...
    def consume_recovery_hash(self, user_id: UUID, code_hash: str) -> bool: ...


@dataclass(frozen=True)
class AuthResult:
    outcome: AuthOutcome
    user_id: UUID | None = None
    audit_reason: str | None = None  # server-side audit only; never sent to a client

    @property
    def ok(self) -> bool:
        return self.outcome is AuthOutcome.OK


class AuthService:
    def __init__(self, users: UserStore, *, now=_utcnow):
        self._users = users
        self._now = now

    def authenticate(self, email: str, password: str, totp_code: str | None) -> AuthResult:
        now = self._now()
        user = self._users.get_for_auth(email)

        # 1. Constant work on EVERY path: verify a real or dummy hash before
        #    any state branch, so existence/state never leaks via timing.
        stored_hash = user.password_hash if (user and user.password_hash) else _DUMMY_HASH
        password_ok = passwords.verify_password(stored_hash, password) and bool(
            user and user.password_hash
        )

        locked = bool(user and user.locked_until and now < user.locked_until)
        active = bool(user and user.is_active)

        # 2. Single decision point. Reason is internal (audit) only.
        success = False
        reason: str
        if user is None:
            reason = "unknown_user"
        elif not password_ok:
            reason = "bad_password"
        elif not active:
            reason = "inactive"
        elif locked:
            reason = "locked"
        elif not user.totp_enrolled:
            reason = "not_enrolled"
        elif not totp_code:
            reason = "no_totp"
        elif recovery.looks_like_code(totp_code):
            # A recovery code, told apart from a TOTP code by SHAPE. This
            # branch is only reachable once the password has already been
            # verified on a real, active, unlocked account, so the extra
            # Argon2id work it does is not an enumeration oracle -- a caller
            # who reaches it already knows the password.
            if self._consume_recovery(user.id, totp_code):
                success = True
                reason = "ok_recovery_code"
            else:
                reason = "bad_recovery_code"
        else:
            secret = self._users.get_totp_secret(user.id)  # decrypt only when needed
            result = (
                totp.verify(secret, totp_code, int(now.timestamp()), user.totp_last_counter)
                if secret is not None
                else totp.TotpResult(False)
            )
            if not result.ok:
                reason = "bad_totp"
            elif not self._users.advance_totp_counter(user.id, result.new_last_counter):
                reason = "replay"  # a concurrent login already consumed this code
            else:
                success = True
                reason = "ok"

        if success:
            self._users.clear_failed_logins(user.id, now)
            # Carry the reason rather than a flat "ok": a login that spent a
            # RECOVERY CODE is a notable event -- it means someone could not
            # complete their normal second factor -- and the audit trail is
            # the only place that distinction survives.
            return AuthResult(AuthOutcome.OK, user.id, reason)

        # 3. Burn a lockout attempt for a real, active, not-already-locked
        #    account — this is what stops a correct-password/no-code probe
        #    from being a free, unlimited password oracle. Unknown users
        #    (no row), inactive and already-locked accounts are left alone.
        if user is not None and active and not locked:
            self._users.record_failed_login(user.id, MAX_FAILED_LOGINS, now + LOCKOUT_DURATION)
        return AuthResult(AuthOutcome.INVALID_CREDENTIALS, None, reason)

    def _consume_recovery(self, user_id: UUID, submitted: str) -> bool:
        """Verify a recovery code and spend it, atomically.

        Every stored hash is checked rather than stopping at the first
        match, so the work done does not depend on WHICH code was
        submitted -- the position of a code in the set is not something a
        caller should be able to time.

        The consume is what actually decides the outcome: if the atomic
        removal reports the hash was already gone, a concurrent login spent
        it first and this attempt fails. Single-use is enforced by the
        database, not by the order of statements here.
        """
        normalised = recovery.normalise(submitted)
        if not normalised:
            return False
        matched: str | None = None
        for stored in self._users.get_recovery_hashes(user_id):
            if passwords.verify_recovery_code(stored, normalised) and matched is None:
                matched = stored
        if matched is None:
            return False
        return self._users.consume_recovery_hash(user_id, matched)


# A fixed valid Argon2id hash so unknown-user verification does real work
# and takes comparable time to a real check (timing-oracle resistance).
_DUMMY_HASH = passwords.hash_password("noctornal-timing-equaliser")
