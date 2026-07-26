"""Postgres-backed implementations of the auth/session store protocols.

These are the production stores behind AuthService and SessionService.
Every query is parameterised (docs/05: no string-built SQL). The TOTP
secret is decrypted only when totp.verify actually needs it, in the API
process, and never returned to a client or logged.

Connections are expected to be autocommit (see db.connect): the two
security-critical mutations — the TOTP counter advance and the lockout
increment — are single-statement compare-and-set UPDATEs, so their
atomicity comes from the statement itself, not a surrounding transaction.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg

from noctornal_api.security import envelope, passwords
from noctornal_api.security.access import (
    AccessContext,
    AccessResolutionError,
    tlp_from_name,
)
from noctornal_api.security.auth import AuthUser, UserStore
from noctornal_api.security.sessions import SessionRecord, SessionStore


class PgUserStore(UserStore):
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # --- provisioning helpers (used by admin flows / tests) -------------
    def create_user(self, email: str, display_name: str, password: str) -> UUID:
        row = self._c.execute(
            """INSERT INTO iam.app_user (email, display_name, password_hash)
               VALUES (%s, %s, %s) RETURNING id""",
            (email, display_name, passwords.hash_password(password)),
        ).fetchone()
        return row[0]

    def enroll_totp(self, user_id: UUID, secret: str) -> None:
        blob, key_id = envelope.encrypt(secret)
        self._c.execute(
            """UPDATE iam.app_user
                  SET totp_secret_ciphertext = %s,
                      totp_key_id = %s,
                      totp_enrolled_at = now()
                WHERE id = %s""",
            (blob, key_id, user_id),
        )

    # --- UserStore protocol ---------------------------------------------
    def get_for_auth(self, email: str) -> AuthUser | None:
        # Does NOT decrypt the secret — only reports whether one exists — so
        # a password-guessing / enumeration attacker never triggers an
        # AES-GCM decrypt or materialises the plaintext secret in memory.
        row = self._c.execute(
            """SELECT id, is_active, password_hash,
                      (totp_secret_ciphertext IS NOT NULL) AS totp_enrolled,
                      totp_last_counter, failed_logins, locked_until
                 FROM iam.app_user WHERE email = %s""",
            (email,),
        ).fetchone()
        if row is None:
            return None
        return AuthUser(
            id=row[0], is_active=row[1], password_hash=row[2],
            totp_enrolled=row[3], totp_last_counter=row[4],
            failed_logins=row[5], locked_until=row[6],
        )

    # --- recovery codes (docs/05) ---------------------------------------
    def issue_recovery_codes(self, user_id: UUID, count: int | None = None) -> list[str]:
        """Generate a fresh SET, replacing any existing one, and return the
        plaintexts. They are never recoverable again — only Argon2id hashes
        are stored, so there is no "show me my codes" path to abuse.

        Replacing rather than topping up is deliberate: an analyst told they
        have ten fresh codes must not still be carrying a valid one they
        printed last year.
        """
        from noctornal_api.security import recovery
        codes = recovery.generate_set(count or recovery.CODE_COUNT)
        hashes = [passwords.hash_recovery_code(c) for c in codes]
        self._c.execute(
            "UPDATE iam.app_user SET recovery_codes_hash = %s WHERE id = %s",
            (hashes, user_id),
        )
        return codes

    def get_recovery_hashes(self, user_id: UUID) -> list[str]:
        row = self._c.execute(
            "SELECT recovery_codes_hash FROM iam.app_user WHERE id = %s",
            (user_id,),
        ).fetchone()
        return list(row[0]) if row and row[0] else []

    def consume_recovery_hash(self, user_id: UUID, code_hash: str) -> bool:
        """Spend one code, atomically. The guard is `@>` (the array still
        contains this hash), so two concurrent logins presenting the same
        code cannot both succeed — the loser updates 0 rows.

        `array_remove` drops every copy, but a duplicate hash would mean two
        identical codes, which generation makes vanishingly unlikely and
        which would be a bug worth failing closed on anyway.
        """
        cur = self._c.execute(
            """UPDATE iam.app_user
                  SET recovery_codes_hash = array_remove(recovery_codes_hash, %s)
                WHERE id = %s AND recovery_codes_hash @> ARRAY[%s]
              RETURNING id""",
            (code_hash, user_id, code_hash),
        )
        return cur.fetchone() is not None

    def count_recovery_codes(self, user_id: UUID) -> int:
        return len(self.get_recovery_hashes(user_id))

    def get_totp_secret(self, user_id: UUID) -> str | None:
        row = self._c.execute(
            "SELECT totp_secret_ciphertext, totp_key_id FROM iam.app_user WHERE id = %s",
            (user_id,),
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return envelope.decrypt(bytes(row[0]), key_id=row[1] or "env:v1")

    def advance_totp_counter(self, user_id: UUID, new_counter: int) -> bool:
        # Compare-and-set: only advances if strictly greater than the stored
        # counter. A concurrent login that already consumed this (or a later)
        # step leaves 0 rows updated → replay rejected at the database, not
        # just in app memory.
        cur = self._c.execute(
            """UPDATE iam.app_user
                  SET totp_last_counter = %s
                WHERE id = %s
                  AND (totp_last_counter IS NULL OR totp_last_counter < %s)
              RETURNING id""",
            (new_counter, user_id, new_counter),
        )
        return cur.fetchone() is not None

    def record_failed_login(
        self, user_id: UUID, threshold: int, lock_until: datetime
    ) -> None:
        """Increment and lock in one statement, deciding lockout from the
        POST-increment value so parallel failures cannot each read a stale
        count and skip the lock, and never shortening an existing lock.

        The counter DECAYS: once a previous lock has elapsed the window
        restarts at 1. Without that reset the count stayed at the threshold
        forever, so a single bad login every 15 minutes re-locked the account
        indefinitely — a one-request-per-quarter-hour denial of service
        against any analyst whose email address is known.
        """
        self._c.execute(
            """UPDATE iam.app_user
                  SET failed_logins = CASE
                          WHEN locked_until IS NOT NULL AND locked_until <= now()
                          THEN 1                      -- expired lock: new window
                          ELSE failed_logins + 1
                      END,
                      locked_until = CASE
                          WHEN locked_until IS NOT NULL AND locked_until <= now()
                          THEN NULL                   -- 1 < threshold, so unlocked
                          WHEN failed_logins + 1 >= %s
                          THEN GREATEST(COALESCE(locked_until, %s), %s)
                          ELSE locked_until
                      END
                WHERE id = %s""",
            (threshold, lock_until, lock_until, user_id),
        )

    def clear_failed_logins(self, user_id: UUID, at: datetime) -> None:
        self._c.execute(
            """UPDATE iam.app_user
                  SET failed_logins = 0, locked_until = NULL, last_login_at = %s
                WHERE id = %s""",
            (at, user_id),
        )


class PgAccessResolver:
    """Builds the AccessContext for the five-part gate from the database.

    The role is read from the case assignment even when it has expired, so
    the verb check (does the role grant this permission?) and the
    relationship check (is the assignment unexpired?) stay independently
    necessary. All queries parameterised.
    """
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def resolve(
        self,
        *,
        user_id: UUID,
        case_id: UUID,
        permission_key: str,
        object_classification: str,
        object_compartments: frozenset[str],
        mfa_satisfied_at: datetime | None,
    ) -> AccessContext:
        # Every lookup fails CLOSED: an unknown permission/user or an
        # out-of-range TLP value raises AccessResolutionError (→ 403), never
        # a 500 that could mask a bad caller.
        perm_row = self._c.execute(
            "SELECT requires_step_up FROM iam.permission WHERE key = %s",
            (permission_key,),
        ).fetchone()
        if perm_row is None:
            raise AccessResolutionError(f"unknown permission: {permission_key!r}")
        requires_step_up = bool(perm_row[0])

        # `is_active` belongs HERE, not only on the global path (CR2,
        # 2026-07-26).
        #
        # `SessionService.validate` resolves a token against `iam.session`
        # alone and never joins `app_user`, and `revoke_all_for_user` has
        # zero production callers — so deactivating an account severed
        # nothing. A deactivated analyst holding a live `__Host-session`
        # cookie kept full read AND write on every case they were assigned
        # to, for the remaining twelve hours of the session's absolute
        # lifetime. Login already refuses them (`auth.py`) and
        # `require_global` already checks it; the case-scoped path — which
        # is every graph, evidence and comms mutation in the product — did
        # not.
        #
        # An inactive account resolves to "unknown user" deliberately: the
        # caller learns their session is no good, not whether a particular
        # account exists or what state it is in.
        user = self._c.execute(
            "SELECT tlp_clearance, compartments FROM iam.app_user "
            "WHERE id = %s AND is_active",
            (user_id,),
        ).fetchone()
        if user is None:
            raise AccessResolutionError(f"unknown or inactive user: {user_id}")
        user_clearance = tlp_from_name(user[0])
        user_compartments = frozenset(user[1] or [])

        assignment = self._c.execute(
            """SELECT role_key, (expires_at IS NULL OR expires_at > now()) AS unexpired
                 FROM iam.case_assignment WHERE case_id = %s AND user_id = %s""",
            (case_id, user_id),
        ).fetchone()

        role_permissions: frozenset[str] = frozenset()
        has_unexpired = False
        if assignment is not None:
            role_key, has_unexpired = assignment[0], bool(assignment[1])
            perms = self._c.execute(
                "SELECT permission_key FROM iam.role_permission WHERE role_key = %s",
                (role_key,),
            ).fetchall()
            role_permissions = frozenset(p[0] for p in perms)

        return AccessContext(
            permission_key=permission_key,
            permission_requires_step_up=requires_step_up,
            role_permissions=role_permissions,
            has_unexpired_assignment=has_unexpired,
            user_clearance=user_clearance,
            object_classification=tlp_from_name(object_classification),
            user_compartments=user_compartments,
            object_compartments=object_compartments,
            mfa_satisfied_at=mfa_satisfied_at,
        )


class PgSessionStore(SessionStore):
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    def insert(self, record: SessionRecord) -> None:
        self._c.execute(
            """INSERT INTO iam.session
                   (id, user_id, token_hash, issued_at, expires_at,
                    last_seen_at, mfa_satisfied_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (record.id, record.user_id, record.token_hash, record.issued_at,
             record.expires_at, record.last_seen_at, record.mfa_satisfied_at),
        )

    def get_by_token_hash(self, token_hash: bytes) -> SessionRecord | None:
        row = self._c.execute(
            """SELECT id, user_id, token_hash, issued_at, expires_at,
                      last_seen_at, mfa_satisfied_at, revoked_at, revoke_reason
                 FROM iam.session WHERE token_hash = %s""",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        return SessionRecord(
            id=row[0], user_id=row[1], token_hash=bytes(row[2]),
            issued_at=row[3], expires_at=row[4], last_seen_at=row[5],
            mfa_satisfied_at=row[6], revoked_at=row[7], revoke_reason=row[8],
        )

    def update(self, record: SessionRecord) -> None:
        self._c.execute(
            """UPDATE iam.session
                  SET last_seen_at = %s, mfa_satisfied_at = %s,
                      revoked_at = %s, revoke_reason = %s
                WHERE id = %s""",
            (record.last_seen_at, record.mfa_satisfied_at, record.revoked_at,
             record.revoke_reason, record.id),
        )

    def revoke(self, session_id: UUID, reason: str, at: datetime) -> bool:
        cur = self._c.execute(
            """UPDATE iam.session SET revoked_at = %s, revoke_reason = %s
                WHERE id = %s AND revoked_at IS NULL""",
            (at, reason, session_id),
        )
        return cur.rowcount > 0

    def revoke_all_for_user(self, user_id: UUID, reason: str, at: datetime) -> int:
        cur = self._c.execute(
            """UPDATE iam.session
                  SET revoked_at = %s, revoke_reason = %s
                WHERE user_id = %s AND revoked_at IS NULL""",
            (at, reason, user_id),
        )
        return cur.rowcount
