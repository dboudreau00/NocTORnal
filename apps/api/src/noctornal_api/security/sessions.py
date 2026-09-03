"""Server-side opaque sessions with absolute and idle expiry.

docs/05: absolute expiry 12 h, idle expiry 30 min, both enforced
server-side; only the token hash is stored; global revocation; step-up
freshness clock (mfa_satisfied_at). The store is a protocol so the policy
here is testable in-memory and backed by iam.session in production.

## Binding (0058)

A token is a bearer credential, so until 2026-09-02 a stolen one was
perfectly portable: nothing on record said where a session was minted,
and validation had nothing to compare a replay against. `create` now
takes the address and User-Agent it was minted with and records them, and
`binding_mismatch` says whether a presentation matches them. Whether a
mismatch is REFUSED is `NOCTORNAL_SESSION_STRICT_BINDING`, off by default:
a browser update changes the User-Agent mid-session and a laptop moving
between networks changes the address, so refusing is a deliberate posture
for a deployment that would rather re-authenticate than risk it. The
values are recorded either way, for the audit trail.

WHICH sessions actually carry them is a shorter list than "a session
now carries" suggested, and saying it that way was a claim this module
could not keep. There are exactly two create sites:

- `http/routers/auth.py` (the login handler) passes both, so every
  session a person signs in for is bound;
- `scripts/bootstrap.py session` passes NEITHER, and cannot: it mints
  from a shell for a browser it has never met, and a guessed address
  would be a fact on record that nobody established. Under strict
  binding that session is refused on first use -- deliberately, since
  "cannot verify" is not "verified" -- and the command says so before it
  prints the URL.

A session minted before 0058 is in the same position and is refused for
the same reason. `deps.refuse_unbound_session` records `unbound` in the
audit row so the security officer can tell that case from a replay.

Both validation call sites -- `deps.current_user` for HTTP and the
websocket handshake in `http/routers/live.py` -- run the check in the
same order: validate with `touch=False`, refuse, and only then slide the
idle window. `live.py` did not until 2026-09-02, which made the socket a
way to both use and keep alive a session HTTP had already refused.
"""
from __future__ import annotations

import ipaddress
import os
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


def normalise_ip(value: str | None) -> str | None:
    """The canonical text of an address, or None for anything that is not
    one. Starlette's test client reports its peer as the string
    "testclient" and a Unix-socket peer has no address at all; neither
    may become a session that 500s at login, and neither is an address
    strict mode can verify. "2001:0DB8::0001" and "2001:db8::1" are one
    address and compare equal here, because the comparison is of
    addresses and not of the strings a kernel or a proxy formatted them
    as."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def strict_binding_enabled() -> bool:
    """Read at call time, not import time, so a deployment can turn the
    control on without restarting and a test can turn it on per case."""
    return os.environ.get("NOCTORNAL_SESSION_STRICT_BINDING", "").strip().lower() in {
        "1", "true"}


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
    #: Where the session was minted (0058). None for a session created
    #: before binding existed, or from a transport with no address -- and
    #: a None here is a fact strict mode compares, not a wildcard.
    ip: str | None = None
    user_agent: str | None = None


def binding_mismatch(record: SessionRecord, *, ip: str | None,
                     user_agent: str | None) -> list[str]:
    """Which of the recorded bindings the presentation fails: a subset of
    ["ip", "user_agent"], empty when it matches. Pure.

    None is compared as a value, never skipped. A session minted before
    0058 has no recorded address, and strict mode REFUSES it rather than
    waving it through: "cannot verify" and "verified" are different facts,
    and the deployment that turned strict mode on asked for the second."""
    mismatched: list[str] = []
    if normalise_ip(record.ip) != normalise_ip(ip):
        mismatched.append("ip")
    if (record.user_agent or None) != (user_agent or None):
        mismatched.append("user_agent")
    return mismatched


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
        ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[SessionRecord, str]:
        """Create a session and return (record, raw_token). The raw token
        is shown to the client once; only its hash is persisted. `ip` and
        `user_agent` are where it was minted (0058); the address is
        canonicalised here so the record and the row agree with what
        `binding_mismatch` will later compare."""
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
            ip=normalise_ip(ip),
            user_agent=(user_agent or None),
        )
        self._store.insert(record)
        return record, token.raw

    def validate(self, raw_token: str, *, touch: bool = True) -> ValidationResult:
        """Resolve a raw token to a live session, enforcing revocation and
        both expiries server-side. On success, slides the idle window
        (unless touch=False -- a read-only freshness probe, or a caller
        with a further check to make before the request counts as
        activity; see `touch`)."""
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
            record = self.touch(record)
        return ValidationResult(record)

    def touch(self, record: SessionRecord) -> SessionRecord:
        """Slide the idle window. Separate from `validate` so a caller can
        validate first, apply its own refusal (`deps.refuse_unbound_session`,
        from `deps.current_user` over HTTP and from the websocket handshake
        in `routers/live.py`), and count the request as activity only if it
        passed -- a refused replay must not keep the session alive. Any new
        validation call site owes the same order; `live.py` used the
        touching default until 2026-09-02 and every refused reconnect kept
        the victim's session from ever timing out."""
        updated = replace(record, last_seen_at=self._now())
        self._store.update(updated)
        return updated

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
