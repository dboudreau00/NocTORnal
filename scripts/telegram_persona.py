"""Enrol, import and log out a Telegram persona's session, on the server.

    python scripts/telegram_persona.py enrol  --persona <uuid> [--replace]
    python scripts/telegram_persona.py import --persona <uuid> [--replace] < session.json
    python scripts/telegram_persona.py logout --persona <uuid> --reason "..." [--local-only]

## Why a script and not the console

An enrolment carries the account's login code and, when it has one, its
two-step password. Neither may pass through a browser or the API, so the
console creates the persona with no credential and an operator with a
shell on the server enrols it here (roadmap F5.2, telegram,
2026-09-24).

## Who runs it

The operator signs in exactly as the console's login would verify them:
email, password and a CURRENT authenticator code. A recovery code is
refused here (it would sign the script in and stay usable for ever: the
login route spends it, this script never does), an administrator-issued
password that was never replaced is refused as the login route refuses it,
and the account must hold collection_account.manage. A failure is audited
as the login route audits one, with `via` naming this script. Every row the
script writes names the signed-in person.

## What it does, and what it never does

Everything runs through the persona gate with the operator's clearance: the
persona must be visible, in its active hours, and covered by a live
authority a second person confirmed; its connections leave only through
its route on the egress proxy (an `act` context, and a `stop` context for a
logout). A platform's answer during an act (a flood wait, a revoked
session) is on the persona before its lock is released.

It writes no file (the library is only ever given a session held in
memory), prints no secret, reads a session to import from stdin and never
from the command line, and stores neither the phone number nor the
two-step password. It prints exactly one line.

Exit 0 on success, 1 on a refusal, 2 when the environment is unusable.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import platform
import socket
import sys
from uuid import UUID

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "apps", "api", "src"))

from _env import load_env_local  # noqa: E402

VIA = "scripts/telegram_persona.py"

#: Replaced by the tests with a fake transport factory; None is Telethon.
TRANSPORT_FACTORY = None

NOT_VERIFIED = "The sign-in did not verify."
RECOVERY_REFUSED = "A recovery code does not sign in this script: use the authenticator."
CHANGE_FIRST = "Sign in to the console and replace the issued password first."
NOT_MANAGER = "This account does not hold collection_account.manage."


class Refused(Exception):
    """A refusal with the one line the script prints."""


def _audit(conn, actor_id, action: str, object_type: str, object_id,
           detail: dict) -> None:
    from psycopg.types.json import Json

    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id, detail)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (actor_id, "USER" if actor_id else "SYSTEM", action, object_type,
         object_id, Json(detail)))


def _where() -> dict:
    """Where the act ran, for the audit rows: the script, the host and the
    operating-system account (never a credential)."""
    try:
        os_user = getpass.getuser()
    except Exception:  # noqa: BLE001 - the name is a courtesy
        os_user = None
    return {"via": VIA, "host": socket.gethostname() or platform.node(),
            "os_user": os_user}


def sign_in(conn):
    """The operator's user id, or Refused. authenticate(spend_recovery=False)
    verifies a recovery code WITHOUT spending it, so the script refuses it
    after the fact and never spends it; must_change_password is read only
    after both factors verified, so an unauthenticated shell user learns
    nothing about an account's reset state."""
    from noctornal_api.security.auth import AuthOutcome, AuthService
    from noctornal_api.stores import PgUserStore

    email = input("Email: ").strip()
    password = getpass.getpass("Password: ")
    code = getpass.getpass("Authenticator code: ").strip()
    result = AuthService(PgUserStore(conn)).authenticate(
        email, password, code, spend_recovery=False)
    if result.outcome is AuthOutcome.SECOND_FACTOR_UNAVAILABLE or not result.ok:
        _audit(conn, result.user_id if result.outcome is
               AuthOutcome.SECOND_FACTOR_UNAVAILABLE else None, "AUTH_FAILED",
               "auth", None, {"reason": result.audit_reason, "email": email,
                              "via": VIA})
        raise Refused(NOT_VERIFIED)
    if result.audit_reason == "ok_recovery_code":
        _audit(conn, None, "AUTH_FAILED", "auth", None,
               {"reason": "recovery_code_refused", "email": email, "via": VIA})
        raise Refused(RECOVERY_REFUSED)
    must_change = conn.execute(
        "SELECT must_change_password FROM iam.app_user WHERE id = %s",
        (result.user_id,)).fetchone()
    if must_change is not None and must_change[0]:
        _audit(conn, None, "AUTH_FAILED", "auth", None,
               {"reason": "password_change_required", "email": email, "via": VIA})
        raise Refused(CHANGE_FIRST)
    holds = conn.execute(
        """SELECT EXISTS (
               SELECT 1 FROM iam.user_role ur
                 JOIN iam.role_permission rp ON rp.role_key = ur.role_key
                 JOIN iam.app_user u ON u.id = ur.user_id
                WHERE ur.user_id = %s AND u.is_active
                  AND rp.permission_key = 'collection_account.manage')""",
        (result.user_id,)).fetchone()[0]
    if not holds:
        _audit(conn, result.user_id, "AUTHZ_DENIED", "auth", None,
               {"permission": "collection_account.manage", "via": VIA})
        raise Refused(NOT_MANAGER)
    _audit(conn, result.user_id, "AUTH_SUCCEEDED", "auth", None, {"via": VIA})
    return result.user_id


def _persona(conn, persona_id: UUID) -> dict:
    row = conn.execute(
        """SELECT handle, platform::text, status, platform_uid,
                  coalesce(octet_length(secret_ciphertext), 0) > 0,
                  session_enrolled_at, fingerprint_profile
             FROM collect.collection_account WHERE id = %s""",
        (persona_id,)).fetchone()
    if row is None or row[1] != "TELEGRAM":
        raise Refused("No Telegram persona has that id.")
    return {"handle": row[0], "status": row[2], "platform_uid": row[3],
            "credential": bool(row[4]), "enrolled_at": row[5],
            "fingerprint": dict(row[6] or {})}


def _ready(conn) -> None:
    """The deployment and the build, before anything is asked of anyone."""
    from noctornal_api import egress, telegram
    from noctornal_api.collection_authority import source_ceiling
    from noctornal_api.http.errors import Problem
    from noctornal_api.http.routers.collection import refuse_unready

    try:
        refuse_unready(conn)
    except Problem as problem:
        raise Refused(problem.detail or "This deployment is not ready to collect.") from None
    available, sentence = telegram.client_available()
    if not available:
        raise Refused(sentence)
    ceiling, why = source_ceiling("TELEGRAM")
    if ceiling is None:
        raise Refused(why)
    if not egress.boundary().in_force:
        raise Refused(telegram.NO_PROXY_SENTENCE)


def _factory():
    from noctornal_api import telegram_wire

    return TRANSPORT_FACTORY or telegram_wire.TelethonTransport


def _transport(secret, route, fingerprint):
    from noctornal_api import telegram_wire

    return _factory()(secret, route, fingerprint,
                      proxy=telegram_wire.proxy_for(route))


def _session(transport, work):
    """One short connection: `work`, then close, off this thread."""
    from noctornal_api.telegram import TELEGRAM_ACT_SECONDS, run_blocking

    async def run():
        try:
            return await work(transport)
        finally:
            try:
                await transport.close()
            except Exception:  # noqa: BLE001 - closing never masks the answer
                pass

    return run_blocking(run, TELEGRAM_ACT_SECONDS)


def _store(conn, persona_id: UUID, persona: dict, secret, uid: str, *,
           actor_id: UUID, action: str, replaced: bool) -> str:
    """Seal the session and record the enrolment, in one transaction. The
    account id is set once; a different account is a different persona."""
    from noctornal_api.collection import PersonaVault
    from noctornal_api.telegram import session_address

    if persona["platform_uid"] and persona["platform_uid"] != uid:
        raise Refused(f"This persona is Telegram account {persona['platform_uid']}. "
                      f"Enrol {uid} as a new persona.")
    taken = conn.execute(
        """SELECT 1 FROM collect.collection_account
            WHERE platform = 'TELEGRAM' AND platform_uid = %s AND id <> %s""",
        (uid, persona_id)).fetchone()
    if taken is not None:
        raise Refused(f"Another persona is already Telegram account {uid}.")
    where = _where()
    with conn.transaction():
        PersonaVault(conn).store(persona_id, secret.dump(), actor_id=actor_id,
                                 detail={**where, "kind": "telegram-mtproto"})
        conn.execute(
            """UPDATE collect.collection_account
                  SET platform_uid = coalesce(platform_uid, %s),
                      session_enrolled_at = now()
                WHERE id = %s""", (uid, persona_id))
        key_id = conn.execute(
            "SELECT secret_key_id FROM collect.collection_account WHERE id = %s",
            (persona_id,)).fetchone()[0]
        if replaced:
            _audit(conn, actor_id, "PERSONA_SECRET_REPLACED", "collection_account",
                   persona_id, where)
        _audit(conn, actor_id, action, "collection_account", persona_id,
               {**where, "platform_uid": uid,
                "dc_id": session_address(secret.session).dc_id,
                "key_id": key_id})
    return key_id


def _clearance(conn, user_id) -> str:
    from noctornal_api.http.deps import user_ceiling

    return user_ceiling(conn, user_id)[0].name


def enrol(conn, persona_id: UUID, *, actor_id: UUID, replace: bool) -> str:
    from noctornal_api.telegram import (
        TelegramPasswordNeeded,
        TelegramRefused,
        TelegramSecret,
        device_problems,
    )
    from noctornal_api.telegram_service import enrolment_session

    _ready(conn)
    persona = _persona(conn, persona_id)
    if persona["status"] == "BURNED":
        raise Refused("This persona is burnt and must not be used again.")
    if persona["credential"] and not replace:
        raise Refused("This persona has a session already. Log it out first, or "
                      "run enrol with --replace.")
    problems = device_problems(persona["fingerprint"])
    if problems:
        raise Refused(" ".join(problems))
    with enrolment_session(conn, persona_id, actor_id=actor_id,
                           clearance=_clearance(conn, actor_id),
                           purpose="enrol") as ctx:
        api_id_text = input("api_id: ").strip()
        phone = input("Phone number: ").strip()
        api_hash = getpass.getpass("api_hash: ").strip()
        if not api_id_text.isdigit():
            raise Refused("An api_id is a positive whole number.")
        fresh = TelegramSecret.fresh(int(api_id_text), api_hash)

        # Two short connections, so no tunnel outlives the proxy's act
        # limit while a person types: the code is sent on the first; the
        # second starts from the first's session (a PHONE_MIGRATE moves
        # it) and its phone_code_hash.
        async def first(transport):
            await transport.connect()
            sent = await transport.send_code(phone)
            return sent, transport.session_string()

        phone_code_hash, moved = _session(
            _transport(fresh, ctx.route, ctx.fingerprint), first)
        code = getpass.getpass("Login code Telegram sent: ").strip()
        password = getpass.getpass(
            "Two-step password (leave empty if the account has none): ")
        second_secret = fresh.with_session(moved) if moved else fresh

        async def second(transport):
            await transport.connect()
            try:
                await transport.sign_in(phone, code, phone_code_hash)
            except TelegramPasswordNeeded:
                if not password:
                    raise TelegramRefused(
                        "This account has a two-step password. Run enrol again "
                        "and give it.") from None
                await transport.sign_in_password(password)
            me = await transport.me()
            return me.uid, transport.session_string()

        uid, session = _session(
            _transport(second_secret, ctx.route, ctx.fingerprint), second)
        secret = fresh.with_session(session)
        key_id = _store(conn, persona_id, persona, secret, uid,
                        actor_id=actor_id, action="PERSONA_SESSION_ENROLLED",
                        replaced=persona["credential"])
    return (f"Enrolled persona {persona['handle']} as Telegram account {uid}. "
            f"The session is sealed under key {key_id}. Nothing secret was printed.")


def import_session(conn, persona_id: UUID, *, actor_id: UUID, replace: bool,
                   stdin=None) -> str:
    from noctornal_api.egress_policy import is_blocked
    from noctornal_api.telegram import (
        TELEGRAM_DC_PORTS,
        TelegramSecret,
        TelegramSecretInvalid,
        TelegramWrongAccount,
        device_problems,
        in_dc_networks,
        session_address,
    )
    from noctornal_api.telegram_service import enrolment_session

    _ready(conn)
    persona = _persona(conn, persona_id)
    if persona["status"] == "BURNED":
        raise Refused("This persona is burnt and must not be used again.")
    if persona["credential"] and not replace:
        raise Refused("This persona has a session already. Log it out first, or "
                      "run import with --replace.")
    problems = device_problems(persona["fingerprint"])
    if problems:
        raise Refused(" ".join(problems))
    raw = (stdin or sys.stdin).read(64 * 1024)
    try:
        given = json.loads(raw)
        secret = TelegramSecret.fresh(given.get("api_id"), given.get("api_hash")) \
            .with_session(given.get("session"))
    except (ValueError, AttributeError, TypeError, TelegramSecretInvalid):
        raise Refused("Standard input is one JSON object with api_id, api_hash "
                      "and session.") from None
    where = session_address(secret.session)
    if (is_blocked(ipaddress.ip_address(where.ip)) or not in_dc_networks(where.ip)
            or where.port not in TELEGRAM_DC_PORTS):
        raise Refused("That session points outside Telegram's published "
                      "data-centre networks, so it is not imported.")
    with enrolment_session(conn, persona_id, actor_id=actor_id,
                           clearance=_clearance(conn, actor_id),
                           purpose="import") as ctx:
        async def check(transport):
            me = await transport.open()
            return me.uid, transport.session_string()

        uid, session = _session(_transport(secret, ctx.route, ctx.fingerprint), check)
        if not uid:
            raise TelegramWrongAccount()
        stored = secret.with_session(session) if session else secret
        key_id = _store(conn, persona_id, persona, stored, uid, actor_id=actor_id,
                        action="PERSONA_SESSION_IMPORTED",
                        replaced=persona["credential"])
    return (f"Imported a session for persona {persona['handle']} as Telegram "
            f"account {uid}. The session is sealed under key {key_id}. Nothing "
            f"secret was printed.")


def logout(conn, persona_id: UUID, *, actor_id: UUID, reason: str,
           local_only: bool) -> str:
    """Log the session out at Telegram through a STOP route (no window, no
    authority: stopping is always allowed), then clear the enrolment and
    destroy the credential, in that order, in one transaction."""
    from noctornal_api.collection import CollectionError, PersonaVault, persona_session
    from noctornal_api.telegram import TelegramSecret

    reason = (reason or "").strip()
    if len(reason) < 5:
        raise Refused("A logout says why, in at least 5 characters.")
    persona = _persona(conn, persona_id)
    if not persona["credential"]:
        raise Refused("This persona has no session to log out.")
    remote = False
    try:
        with persona_session(conn, persona_id, actor_id=actor_id,
                             clearance=_clearance(conn, actor_id),
                             purpose="logout", source_id=None,
                             need="PUBLIC_READ", platform="TELEGRAM",
                             stopping=True, needs_secret=True) as ctx:
            secret = TelegramSecret.parse(ctx.lease.value)
            try:
                async def out(transport):
                    return await transport.log_out()

                remote = bool(_session(_transport(secret, ctx.route,
                                                  ctx.fingerprint), out))
            except CollectionError:
                remote = False
            if not remote and not local_only:
                raise Refused(
                    "Telegram did not confirm the logout, so nothing was "
                    "destroyed. Run it again, or with --local-only, which "
                    "destroys the copy here and leaves the key working for "
                    "whoever holds another copy.")
            where = _where()
            with conn.transaction():
                conn.execute(
                    "UPDATE collect.collection_account SET session_enrolled_at = NULL "
                    "WHERE id = %s", (persona_id,))
                PersonaVault(conn).destroy_secret(
                    persona_id, actor_id=actor_id, reason=reason,
                    detail={**where, "remote": remote})
                _audit(conn, actor_id, "PERSONA_LOGGED_OUT", "collection_account",
                       persona_id, {**where, "reason": reason, "remote": remote})
    except CollectionError as exc:
        raise Refused(_sentence(exc)) from None
    return (f"Logged out persona {persona['handle']}"
            + ("" if remote else " here only: Telegram did not confirm it")
            + ". Its credential is destroyed. Nothing secret was printed.")


def _sentence(exc: BaseException) -> str:
    """The fixed sentence of an outcome, never a library's text."""
    from noctornal_api.collection import attended_answer

    answer = attended_answer(exc)
    if answer is not None:
        return answer[1]
    from noctornal_api.telegram import TelegramTransportFailed

    if isinstance(exc, TelegramTransportFailed):
        return "Telegram could not be reached. Nothing was changed."
    return str(exc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Enrol, import or log out a Telegram persona's session.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("enrol", "import"):
        p = sub.add_parser(name)
        p.add_argument("--persona", required=True)
        p.add_argument("--replace", action="store_true",
                       help="replace a stored session (audited)")
    p = sub.add_parser("logout")
    p.add_argument("--persona", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--local-only", action="store_true",
                   help=("destroy the copy here even when Telegram does not "
                         "confirm the logout; the key then still works for "
                         "whoever holds another copy"))
    args = parser.parse_args(argv)
    try:
        persona_id = UUID(args.persona)
    except ValueError:
        print("--persona takes a persona's id.", file=sys.stderr)
        return 1
    load_env_local()
    from noctornal_api.collection import CollectionError
    from noctornal_api.db import SystemPurpose, connect_system

    try:
        # S1 (2026-09-25): a script binds no user, so on the request role it
        # would see nothing under row-level security.
        conn = connect_system(SystemPurpose.COLLECTION)
    except Exception as exc:  # noqa: BLE001 - the environment, said once
        print(f"The database could not be reached ({type(exc).__name__}).",
              file=sys.stderr)
        return 2
    try:
        actor = sign_in(conn)
        if args.command == "enrol":
            line = enrol(conn, persona_id, actor_id=actor, replace=args.replace)
        elif args.command == "import":
            line = import_session(conn, persona_id, actor_id=actor,
                                  replace=args.replace)
        else:
            line = logout(conn, persona_id, actor_id=actor, reason=args.reason,
                          local_only=args.local_only)
    except Refused as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except CollectionError as exc:
        print(_sentence(exc), file=sys.stderr)
        return 1
    finally:
        conn.close()
    print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
