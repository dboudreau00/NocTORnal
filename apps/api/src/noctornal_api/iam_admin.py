"""Analyst account administration (docs/05, `user.manage`).

Until now the ONLY way to create, unlock, or re-enrol an analyst was
`scripts/bootstrap.py` on the server's own shell, with `DATABASE_URL` and
the TOTP KEK exported by hand. That is a reasonable floor for the very
first account and an unreasonable ceiling for every account after it: an
administrator who has to shell into the box to add a colleague is an
administrator who shares accounts instead.

## What this deliberately is NOT

- It is not a password reader. Passwords and TOTP secrets are returned
  exactly once, in the response to the call that generated them, and are
  not retrievable afterwards — there is no endpoint that returns an
  existing credential. (`collection_account.reveal` exists for personas;
  nothing equivalent exists for analysts, on purpose.)
- It is not a role editor. Granting and revoking GLOBAL roles is here;
  changing what a role MEANS is `role.manage`, registered as a four-eyes
  operation in the approvals catalogue, and has no endpoint at all yet.
- It is not self-service. Every route is gated on `user.manage`, which
  the seed marks step-up and grants to SYS_ADMIN alone.

## The three refusals that keep an admin from locking the building

1. You cannot deactivate yourself. The session doing the deactivating is
   proof the account is in use.
2. You cannot deactivate — or revoke the last role from — the last active
   SYS_ADMIN. A deployment with zero user-managers can only be repaired
   from the database shell, which is the situation this module exists to
   end.
3. The same for the last active SECURITY_OFFICER: break-glass REFUSES to
   grant when nobody can review it, so removing the last officer quietly
   disables emergency access everywhere.

Lowering a user's clearance below a case they OWN is refused for the same
reason `cases.py` refuses to raise a case above its owner: both create an
owner who cannot read their own case, and there is no route back.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.security import totp
from noctornal_api.security.envelope import _load_kek
from noctornal_api.stores import PgSessionStore, PgUserStore


class AdminError(Exception):
    pass


#: Roles this surface may grant. Read from iam.role at call time as well —
#: this is the ALLOWLIST, and the DB check is the existence check. A role
#: the seed does not know is a typo, and a typo in an authz grant is
#: silent no-access (the compartment-registry lesson, docs/16).
GRANTABLE_ROLES = frozenset({
    "SYS_ADMIN", "SECURITY_OFFICER", "CASE_OWNER", "ANALYST",
    "MALWARE_ANALYST", "READ_ONLY",
    # The seed carries eleven roles and this list carried six, so a
    # deployment could not staff its own collection surface from the
    # panel: provisioning a working COLLECTOR still meant a shell on the
    # server, which is the hurdle this module exists to remove.
    "COLLECTOR", "CONTRIBUTOR", "LIAISON", "REVIEWER",
})

#: Seeded, and deliberately NOT grantable here. SERVICE is a machine
#: identity: handing it to a human through an account panel is how a
#: person ends up holding a role whose audit rows read as a system action.
_NOT_GRANTABLE = frozenset({"SERVICE"})

#: Roles whose LAST active holder may not be removed. See module docstring.
_LOAD_BEARING = ("SYS_ADMIN", "SECURITY_OFFICER")

_TLP = ("CLEAR", "GREEN", "AMBER", "RED")


@dataclass(frozen=True)
class OneTimeCredentials:
    """Returned once, never stored, never retrievable."""
    user_id: UUID
    email: str
    password: str
    totp_secret: str
    otpauth_uri: str


def _otpauth_uri(email: str, secret: str) -> str:
    label = f"NocTORnal:{email}"
    return (f"otpauth://totp/{label}"
            f"?secret={secret}&issuer=NocTORnal&algorithm=SHA1"
            f"&digits=6&period=30")


def require_kek() -> None:
    """Fail BEFORE any row is written, with the operator's actual problem.

    Creating a user and then failing to seal their TOTP secret leaves an
    email address taken by an account that cannot log in — the exact
    half-provisioned state bootstrap wraps a transaction around.
    """
    try:
        _load_kek()
    except Exception as exc:
        raise AdminError(
            "the TOTP key-encryption key is not available to the API "
            "process, so no account secret can be sealed. Set "
            "NOCTORNAL_TOTP_KEK in the API's environment (the installer "
            "writes it to .env.local) and restart."
        ) from exc


class IamAdminService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- read --------------------------------------------------------------

    def list_users(self) -> list[dict]:
        rows = self._c.execute(
            """SELECT u.id, u.email, u.display_name, u.tlp_clearance::text,
                      u.is_active, u.totp_enrolled_at IS NOT NULL,
                      u.failed_logins, u.locked_until, u.last_login_at,
                      u.created_at,
                      coalesce(array_agg(ur.role_key ORDER BY ur.role_key)
                               FILTER (WHERE ur.role_key IS NOT NULL), '{}')
                 FROM iam.app_user u
                 LEFT JOIN iam.user_role ur ON ur.user_id = u.id
                GROUP BY u.id
                ORDER BY u.is_active DESC, u.email""").fetchall()
        return [{
            "id": str(r[0]), "email": r[1], "display_name": r[2],
            "tlp_clearance": r[3], "is_active": r[4], "totp_enrolled": r[5],
            "failed_logins": r[6],
            "locked_until": r[7].isoformat() if r[7] else None,
            "last_login_at": r[8].isoformat() if r[8] else None,
            "created_at": r[9].isoformat() if r[9] else None,
            "roles": list(r[10]),
        } for r in rows]

    # -- create ------------------------------------------------------------

    def create_analyst(self, *, email: str, display_name: str,
                       clearance: str, roles: list[str],
                       actor_id: UUID | None) -> OneTimeCredentials:
        email = (email or "").strip()
        display_name = (display_name or "").strip()
        if not email or "@" not in email:
            raise AdminError("a work email is required")
        if not display_name:
            raise AdminError("a display name is required")
        self._check_clearance(clearance)
        roles = list(dict.fromkeys(r.strip().upper() for r in roles if r.strip()))
        if not roles:
            raise AdminError("at least one global role is required: a user "
                             "with no role can see nothing and fix nothing")
        self._check_roles(roles)
        require_kek()

        password = secrets.token_urlsafe(24)
        secret = totp.generate_secret()
        store = PgUserStore(self._c)
        try:
            # One transaction, exactly as bootstrap: a user who exists but
            # has no role, or no TOTP secret while mfa_required is true,
            # cannot log in and cannot be fixed by re-running (the email is
            # taken).
            with self._c.transaction():
                user_id = store.create_user(email, display_name, password)
                self._c.execute(
                    "UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                    (clearance, user_id))
                for role in roles:
                    self._c.execute(
                        """INSERT INTO iam.user_role (user_id, role_key)
                           VALUES (%s, %s) ON CONFLICT DO NOTHING""",
                        (user_id, role))
                store.enroll_totp(user_id, secret)
                self._audit(actor_id, "USER_CREATED", user_id, {
                    "email": email, "roles": roles,
                    "tlp_clearance": clearance})
        except psycopg.errors.UniqueViolation as exc:
            raise AdminError(
                f"a user with email {email} already exists — nothing was "
                f"changed") from exc
        return OneTimeCredentials(
            user_id=user_id, email=email, password=password,
            totp_secret=secret, otpauth_uri=_otpauth_uri(email, secret))

    # -- lifecycle ---------------------------------------------------------

    def set_active(self, user_id: UUID, *, active: bool,
                   actor_id: UUID) -> None:
        row = self._c.execute(
            "SELECT is_active, email FROM iam.app_user WHERE id = %s",
            (user_id,)).fetchone()
        if row is None:
            raise AdminError("no such user")
        if row[0] == active:
            return  # idempotent; re-running an admin action is not an error
        if not active and user_id == actor_id:
            raise AdminError(
                "you cannot deactivate your own account: the session "
                "performing this action is proof it is in use")
        with self._c.transaction():
            # Inside the transaction so the census lock is still held when
            # the write lands; the guard below now runs under it.
            if not active:
                self._lock_role_census()
                self._refuse_if_load_bearing(user_id, "deactivate")
            self._c.execute(
                """UPDATE iam.app_user
                      SET is_active = %s,
                          deactivated_at = CASE WHEN %s THEN NULL
                                                ELSE now() END
                    WHERE id = %s""",
                (active, active, user_id))
            if not active:
                # A deactivated account with a live session is not
                # deactivated. `revoke_all_for_user` exists for exactly
                # this.
                from datetime import datetime, timezone
                PgSessionStore(self._c).revoke_all_for_user(
                    user_id, "account deactivated",
                    datetime.now(timezone.utc))
            self._audit(actor_id,
                        "USER_REACTIVATED" if active else "USER_DEACTIVATED",
                        user_id, {"email": row[1]})

    def set_clearance(self, user_id: UUID, *, clearance: str,
                      actor_id: UUID) -> None:
        self._check_clearance(clearance)
        row = self._c.execute(
            "SELECT tlp_clearance::text, email FROM iam.app_user WHERE id = %s",
            (user_id,)).fetchone()
        if row is None:
            raise AdminError("no such user")
        if row[0] == clearance:
            return
        # Lowering below a case they OWN **or DEPUTISE** strands them — the
        # mirror of the raise `cases.py` refuses, and just as one-way once
        # done. The deputy half was missed on the first pass, and
        # `cases.py:88` checks a deputy's clearance at creation for exactly
        # the same reason: a deputy exists to act when the owner cannot,
        # so a deputy who cannot open the case is a succession plan that
        # fails on the day it is needed, silently.
        stranded = self._c.execute(
            """SELECT code,
                      CASE WHEN owner_user_id = %s THEN 'owner'
                           ELSE 'deputy' END
                 FROM core."case"
                WHERE (owner_user_id = %s OR deputy_user_id = %s)
                  AND status <> 'CLOSED'
                  AND classification > %s::core.tlp
                ORDER BY code LIMIT 5""",
            (user_id, user_id, user_id, clearance)).fetchall()
        if stranded:
            names = ", ".join(f"{r[0]} ({r[1]})" for r in stranded)
            raise AdminError(
                f"lowering this user to {clearance} would strand them below "
                f"cases they hold ({names}). Transfer, reassign or close "
                f"those cases first.")
        with self._c.transaction():
            self._c.execute(
                "UPDATE iam.app_user SET tlp_clearance = %s WHERE id = %s",
                (clearance, user_id))
            self._audit(actor_id, "USER_CLEARANCE_CHANGED", user_id, {
                "email": row[1], "from": row[0], "to": clearance})

    # -- roles -------------------------------------------------------------

    def grant_role(self, user_id: UUID, *, role: str, actor_id: UUID) -> None:
        role = role.strip().upper()
        self._check_roles([role])
        # Checked, because the alternative is a raw ForeignKeyViolation
        # reaching the catch-all handler as "Internal error: unexpected
        # failure" — a 500 for a caller who simply named a user that is
        # not there. Its sibling `revoke_role` had the mirror defect:
        # DELETE matched nothing and answered 200 "revoked", reporting a
        # no-op as a completed authz change.
        self._require_user(user_id)
        with self._c.transaction():
            inserted = self._c.execute(
                """INSERT INTO iam.user_role (user_id, role_key)
                   VALUES (%s, %s) ON CONFLICT DO NOTHING
                   RETURNING user_id""",
                (user_id, role)).fetchone()
            if inserted:
                self._audit(actor_id, "ROLE_GRANTED", user_id, {"role": role})

    def revoke_role(self, user_id: UUID, *, role: str, actor_id: UUID) -> None:
        role = role.strip().upper()
        self._require_user(user_id)
        with self._c.transaction():
            if role in _LOAD_BEARING:
                self._lock_role_census()
                self._refuse_if_load_bearing(user_id, f"revoke {role} from",
                                             only_role=role)
            deleted = self._c.execute(
                """DELETE FROM iam.user_role
                    WHERE user_id = %s AND role_key = %s
                    RETURNING user_id""",
                (user_id, role)).fetchone()
            if deleted:
                self._audit(actor_id, "ROLE_REVOKED", user_id, {"role": role})

    # -- credentials -------------------------------------------------------

    def reenrol_totp(self, user_id: UUID, *,
                     actor_id: UUID) -> OneTimeCredentials:
        """A NEW secret. The old one stops working in the same transaction.

        For the analyst whose phone is gone — and the reason it is an admin
        action rather than self-service is that the person asking has, by
        definition, lost their second factor and cannot prove who they are
        to the software. They prove it to a human instead, and the human's
        id goes in the audit row.
        """
        require_kek()
        row = self._c.execute(
            "SELECT email FROM iam.app_user WHERE id = %s",
            (user_id,)).fetchone()
        if row is None:
            raise AdminError("no such user")
        secret = totp.generate_secret()
        with self._c.transaction():
            PgUserStore(self._c).enroll_totp(user_id, secret)
            # The scenario IS a stolen or lost phone, and a new secret
            # alone does not evict whoever holds the device: an existing
            # session carries its own token and never re-presents TOTP.
            # Rotating the factor while leaving the sessions it authorised
            # standing is a lockout that does not lock anybody out — and
            # the panel's own copy promises the old authenticator "stops
            # working immediately".
            from datetime import datetime, timezone
            revoked = PgSessionStore(self._c).revoke_all_for_user(
                user_id, "TOTP re-enrolled", datetime.now(timezone.utc))
            self._audit(actor_id, "TOTP_REENROLLED", user_id,
                        {"email": row[0], "sessions_revoked": revoked})
        return OneTimeCredentials(
            user_id=user_id, email=row[0], password="",
            totp_secret=secret, otpauth_uri=_otpauth_uri(row[0], secret))

    def unlock(self, user_id: UUID, *, actor_id: UUID) -> None:
        row = self._c.execute(
            """SELECT failed_logins, locked_until, email
                 FROM iam.app_user WHERE id = %s""",
            (user_id,)).fetchone()
        if row is None:
            raise AdminError("no such user")
        with self._c.transaction():
            self._c.execute(
                """UPDATE iam.app_user
                      SET failed_logins = 0, locked_until = NULL
                    WHERE id = %s""", (user_id,))
            self._audit(actor_id, "USER_UNLOCKED", user_id, {
                "email": row[2], "failed_logins": row[0],
                "was_locked_until": row[1].isoformat() if row[1] else None})

    # -- internals ---------------------------------------------------------

    def _require_user(self, user_id: UUID) -> None:
        if self._c.execute(
                "SELECT 1 FROM iam.app_user WHERE id = %s",
                (user_id,)).fetchone() is None:
            raise AdminError("no such user")

    def _check_clearance(self, clearance: str) -> None:
        if clearance not in _TLP:
            raise AdminError(
                f"unknown clearance {clearance!r}; one of {', '.join(_TLP)}")

    def _check_roles(self, roles: list[str]) -> None:
        bad = [r for r in roles if r not in GRANTABLE_ROLES]
        if bad:
            raise AdminError(
                f"role(s) not grantable from this surface: {', '.join(bad)}")
        known = {r[0] for r in self._c.execute(
            "SELECT key FROM iam.role WHERE key = ANY(%s)",
            (roles,)).fetchall()}
        missing = [r for r in roles if r not in known]
        if missing:
            raise AdminError(
                f"role(s) not present in this deployment's seed: "
                f"{', '.join(missing)}")

    def _lock_role_census(self) -> None:
        """Serialise every read-then-write over the role census.

        `_refuse_if_load_bearing` counts other active holders and the
        caller then writes — an unlocked check-then-write. Two admins
        deactivating the last two SYS_ADMINs at the same instant each see
        the other still active, each pass, and the deployment lands with
        zero user-managers: the exact state the guard exists to prevent,
        reachable by two clicks a second apart.

        `pg_advisory_xact_lock` releases at commit, and every caller here
        wraps its write in a transaction, so the lock spans the check and
        the write. Same technique as the first-run door and 0013's chain.
        """
        self._c.execute(
            "SELECT pg_advisory_xact_lock("
            "  hashtextextended('iam.role_census', 0))")

    def _refuse_if_load_bearing(self, user_id: UUID, verb: str,
                                only_role: str | None = None) -> None:
        for role in _LOAD_BEARING:
            if only_role is not None and role != only_role:
                continue
            holds = self._c.execute(
                """SELECT 1 FROM iam.user_role
                    WHERE user_id = %s AND role_key = %s""",
                (user_id, role)).fetchone()
            if not holds:
                continue
            others = self._c.execute(
                """SELECT count(*) FROM iam.user_role ur
                     JOIN iam.app_user u ON u.id = ur.user_id
                    WHERE ur.role_key = %s AND u.is_active
                      AND ur.user_id <> %s""",
                (role, user_id)).fetchone()[0]
            if others == 0:
                raise AdminError(
                    f"refusing to {verb} the last active {role}: "
                    + ("a deployment with no user-manager can only be "
                       "repaired from the database shell"
                       if role == "SYS_ADMIN" else
                       "break-glass refuses to grant when nobody can "
                       "review it, so this would quietly disable "
                       "emergency access"))

    def _audit(self, actor_id: UUID | None, action: str, subject: UUID,
               detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    detail)
               VALUES (%s, %s, %s, 'app_user', %s, %s)""",
            (actor_id, "USER" if actor_id else "SYSTEM", action, subject,
             Json(detail)))


# ---------------------------------------------------------------------------
# First-run setup
# ---------------------------------------------------------------------------

def needs_setup(conn: psycopg.Connection) -> bool:
    """True while the deployment has no user at all.

    Counts EVERY row, active or not: a deployment with one deactivated
    account is not fresh, it is locked out — and re-opening the first-run
    door on it would let anyone on the network become its administrator.
    That state is repaired from the database shell, deliberately.
    """
    return conn.execute(
        "SELECT count(*) FROM iam.app_user").fetchone()[0] == 0


def create_first_admin(conn: psycopg.Connection, *, email: str,
                       display_name: str) -> OneTimeCredentials:
    """The one unauthenticated write in the system, and the gate is the
    emptiness of `iam.app_user` itself.

    The advisory lock makes the check-then-insert atomic against a
    concurrent first-run: without it, two browsers on a fresh install could
    both pass the count and the loser's "first admin" would be a second
    admin nobody created on purpose.
    """
    require_kek()
    with conn.transaction():
        conn.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended('iam.first_run', 0))")
        if not needs_setup(conn):
            raise AdminError(
                "this deployment already has accounts; first-run setup is "
                "closed. Sign in, or use bootstrap.py on the server.")
        svc = IamAdminService(conn)
        # SECURITY_OFFICER included: break-glass cannot grant until one
        # exists, and a fresh single-operator install IS that operator.
        return svc.create_analyst(
            email=email, display_name=display_name, clearance="RED",
            roles=["SYS_ADMIN", "SECURITY_OFFICER", "CASE_OWNER", "ANALYST"],
            actor_id=None)
