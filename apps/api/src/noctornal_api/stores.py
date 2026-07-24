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
        # Increment and lock in one statement, deciding lockout from the
        # POST-increment value (failed_logins + 1) so parallel failures
        # cannot each read a stale count and skip the lock; and never
        # overwrite an existing lock with a shorter/null one.
        self._c.execute(
            """UPDATE iam.app_user
                  SET failed_logins = failed_logins + 1,
                      locked_until = CASE
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

    def revoke_all_for_user(self, user_id: UUID, reason: str, at: datetime) -> int:
        cur = self._c.execute(
            """UPDATE iam.session
                  SET revoked_at = %s, revoke_reason = %s
                WHERE user_id = %s AND revoked_at IS NULL""",
            (at, reason, user_id),
        )
        return cur.rowcount
