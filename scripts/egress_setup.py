"""Set up and change the egress configuration without the console
(S2, the egress proxy, 2026-09-24; docs/00 decision 68).

    python scripts/egress_setup.py keygen            new keys, printed once
    python scripts/egress_setup.py dev-env           .env.local lines for a proxy on this host
    python scripts/egress_setup.py role-sql          the proxy role's grants, for an older cluster
    python scripts/egress_setup.py preflight [--dir infra/production]
    python scripts/egress_setup.py adopt             propose, confirm and create what an upgrade needs
    python scripts/egress_setup.py list
    python scripts/egress_setup.py profile-create --name N --kind K --ceiling C [policy options]
    python scripts/egress_setup.py profile-policy --profile ID [policy options]
    python scripts/egress_setup.py profile-exit --profile ID --exit-kind KIND < endpoint.json
    python scripts/egress_setup.py profile-passive-default --profile ID
    python scripts/egress_setup.py profile-activate --profile ID
    python scripts/egress_setup.py profile-deactivate --profile ID
    python scripts/egress_setup.py profile-retire --profile ID --reason TEXT
    python scripts/egress_setup.py route-create --name NAME --description TEXT
    python scripts/egress_setup.py route-allow --route ID --entry ENTRY --note TEXT
    python scripts/egress_setup.py route-disallow --route ID --destination ID
    python scripts/egress_setup.py route-retire --route ID --reason TEXT
    python scripts/egress_setup.py dev-smtp          the development Mailpit relay route

## Every write signs its operator in

A claimed email is not an identity. Every command that writes asks for the
email, the password and a CURRENT authenticator code, verifies them as the
console's sign-in does (a recovery code is not a fresh second factor here,
and an issued password nobody has replaced yet is refused), requires
egress.manage, and records that person with the host and the operating
system user in each audit row. A failed sign-in writes AUTH_FAILED exactly
as the console's does. `list` needs egress.log.read. keygen, dev-env,
role-sql and preflight read no database and need no sign-in.

## An exit's credentials never touch the command line

profile-exit reads the endpoint as JSON on STDIN ({"host", "port",
"username", "password"}) and refuses one on argv, where it would sit in the
shell history and the process list. Nothing prints it back.

Output is one line per change naming its audit action; any refusal exits 1
with the service's sentence.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import json
import os
import re
import socket
import subprocess
import sys
from pathlib import Path
from uuid import UUID

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402
from psycopg.types.json import Json  # noqa: E402
from noctornal_api import egress, egress_ledger  # noqa: E402
from noctornal_api.egress_admin import EgressAdminError, EgressAdminService  # noqa: E402
from noctornal_api.security import egress_seal  # noqa: E402

VIA = "scripts/egress_setup.py"
PROD_DIR = Path(__file__).resolve().parent.parent / "infra" / "production"

#: What each egress env file must carry, and how each value must look.
REQUIRED = {
    "egress-client.env": ("NOCTORNAL_EGRESS_CLIENT_KEY", "NOCTORNAL_EGRESS_FINGERPRINT_KEY",
                          "NOCTORNAL_EGRESS_SEAL_PUBLIC"),
    "egress-proxy.env": ("NOCTORNAL_EGRESS_DATABASE_URL", "NOCTORNAL_EGRESS_CLIENT_KEY",
                         "NOCTORNAL_EGRESS_SEAL_KEY", "NOCTORNAL_EGRESS_FINGERPRINT_KEY"),
    "postgres-init.env": ("NOCTORNAL_EGRESS_DB_PASSWORD",),
}
#: Compose 2.24 is the first to take env_file entries with `required: false`.
COMPOSE_FLOOR = (2, 24)


class SetupError(Exception):
    """A refusal: printed as one sentence, exit status 1."""


# ---------------------------------------------------------------------------
# Signing in
# ---------------------------------------------------------------------------

def _via() -> dict:
    try:
        os_user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no user name is still an answer
        os_user = "unknown"
    return {"via": VIA, "os_user": os_user, "host": socket.gethostname()}


def _auth_failed(conn, user_id, reason: str, email: str) -> None:
    conn.execute(
        """INSERT INTO audit.event (actor_id, actor_kind, action, object_type, detail)
           VALUES (%s, %s, 'AUTH_FAILED', 'auth', %s)""",
        (user_id, "USER" if user_id else "SYSTEM",
         Json({"reason": reason, "email": email, **_via()})))


def sign_in(conn, *, need: str, ask=input, secret=getpass.getpass) -> tuple[UUID, dict]:
    """(the operator's user id, the audit detail naming where the change
    came from), or SetupError. The console's sign-in, minus the session."""
    from noctornal_api.security.auth import AuthService
    from noctornal_api.stores import PgUserStore

    email = ask("Email: ").strip()
    password = secret("Password: ")
    code = secret("Current authenticator code: ").strip()
    result = AuthService(PgUserStore(conn)).authenticate(
        email, password, code, spend_recovery=False)
    if result.ok and result.audit_reason == "ok_recovery_code":
        # Verified and left unspent: a recovery code proves a lost device,
        # not a fresh second factor, and this is a configuration change.
        _auth_failed(conn, result.user_id, "recovery_code_refused", email)
        raise SetupError("Sign in with your authenticator's current code: a recovery "
                         "code is not accepted here.")
    if not result.ok:
        _auth_failed(conn, result.user_id, result.audit_reason or "failed", email)
        raise SetupError("Sign-in failed.")
    row = conn.execute(
        "SELECT must_change_password, is_active FROM iam.app_user WHERE id = %s",
        (result.user_id,)).fetchone()
    if row is None or not row[1]:
        _auth_failed(conn, result.user_id, "inactive", email)
        raise SetupError("Sign-in failed.")
    if row[0]:
        _auth_failed(conn, result.user_id, "password_change_due", email)
        raise SetupError("Sign in to the console and replace the issued password first.")
    held = conn.execute(
        """SELECT EXISTS (SELECT 1 FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
            WHERE ur.user_id = %s AND rp.permission_key = %s)""",
        (result.user_id, need)).fetchone()[0]
    if not held:
        conn.execute(
            """INSERT INTO audit.event (actor_id, actor_kind, action, object_type, detail)
               VALUES (%s, 'USER', 'AUTHZ_DENIED', 'auth', %s)""",
            (result.user_id, Json({"permission": need, "scope": "global", **_via()})))
        raise SetupError(f"This account does not hold {need}.")
    return result.user_id, _via()


# ---------------------------------------------------------------------------
# Commands that read no database
# ---------------------------------------------------------------------------

def keygen() -> str:
    keys = egress_seal.keygen()
    return "\n".join([
        "# Shown once. Nothing here is stored anywhere else.",
        "# infra/production/egress-proxy.env (the egress proxy alone):",
        f"NOCTORNAL_EGRESS_SEAL_KEY={keys[egress_seal.SEAL_KEY_ENV]}",
        f"NOCTORNAL_EGRESS_CLIENT_KEY={keys['NOCTORNAL_EGRESS_CLIENT_KEY']}",
        f"NOCTORNAL_EGRESS_FINGERPRINT_KEY={keys[egress_seal.FINGERPRINT_KEY_ENV]}",
        "# infra/production/egress-client.env (api and cron):",
        f"NOCTORNAL_EGRESS_CLIENT_KEY={keys['NOCTORNAL_EGRESS_CLIENT_KEY']}",
        f"NOCTORNAL_EGRESS_FINGERPRINT_KEY={keys[egress_seal.FINGERPRINT_KEY_ENV]}",
        f"NOCTORNAL_EGRESS_SEAL_PUBLIC={keys[egress_seal.SEAL_PUBLIC_ENV]}",
        f"# The seal key's id is {keys['key_id']}.",
    ])


def dev_env() -> str:
    return "\n".join([
        "# For a development egress proxy on this host: add to .env.local, then run",
        "# python -m noctornal_api.egress_proxy in its own terminal.",
        "NOCTORNAL_EGRESS_LISTEN=127.0.0.1:3128",
        "NOCTORNAL_EGRESS_PROXY_URL=http://127.0.0.1:3128",
        "# and the client and fingerprint keys from: python scripts/egress_setup.py keygen",
    ])


def role_sql() -> str:
    return "\n".join([
        "/* Run in psql as a superuser on a cluster that predates the egress",
        "   proxy's role. \\password prompts for the password, so it never sits in",
        "   a statement or a log; put the same one in NOCTORNAL_EGRESS_DATABASE_URL. */",
        f"CREATE ROLE {egress_ledger.EGRESS_ROLE} LOGIN NOSUPERUSER NOCREATEDB "
        f"NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;",
        f"\\password {egress_ledger.EGRESS_ROLE}",
        f"GRANT CONNECT ON DATABASE noctornal TO {egress_ledger.EGRESS_ROLE};",
        egress_ledger.EGRESS_ROLE_SQL,
    ])


def read_env_file(path: Path) -> dict[str, str]:
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _b64_len(value: str) -> int | None:
    try:
        return len(base64.b64decode(value, validate=True))
    except (binascii.Error, ValueError):
        return None


def compose_version() -> tuple[int, int] | None:
    """The installed `docker compose` version, or None when it cannot be
    asked. Runs one local command and sends nothing anywhere."""
    try:
        out = subprocess.run(["docker", "compose", "version", "--short"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"(\d+)\.(\d+)", out or "")
    return (int(match.group(1)), int(match.group(2))) if match else None


def preflight(directory: Path, *, compose=compose_version) -> list[str]:
    """Every problem with the three egress env files, and the Compose floor,
    before `compose up` on an upgrade. Writes nothing; names no value."""
    problems: list[str] = []
    files: dict[str, dict[str, str]] = {}
    for name, keys in REQUIRED.items():
        path = directory / name
        if not path.is_file():
            problems.append(f"{name} is missing (copy {name}.example and fill it in).")
            continue
        values = read_env_file(path)
        files[name] = values
        for key in keys:
            if not values.get(key):
                problems.append(f"{name} has no {key}.")
    for name, values in files.items():
        for key, want in (("NOCTORNAL_EGRESS_CLIENT_KEY", 32),
                          ("NOCTORNAL_EGRESS_FINGERPRINT_KEY", 32),
                          ("NOCTORNAL_EGRESS_SEAL_KEY", 32),
                          ("NOCTORNAL_EGRESS_SEAL_PUBLIC", 32)):
            if values.get(key):
                size = _b64_len(values[key])
                if size is None or (size < want if key == "NOCTORNAL_EGRESS_CLIENT_KEY"
                                    else size != want):
                    problems.append(f"{name}: {key} is not a well formed key.")
    client, proxy = files.get("egress-client.env", {}), files.get("egress-proxy.env", {})
    for key in ("NOCTORNAL_EGRESS_CLIENT_KEY", "NOCTORNAL_EGRESS_FINGERPRINT_KEY"):
        if client.get(key) and proxy.get(key) and client[key] != proxy[key]:
            problems.append(f"{key} differs between egress-client.env and "
                            f"egress-proxy.env; both must hold the same key.")
    if client.get("NOCTORNAL_EGRESS_SEAL_PUBLIC") and proxy.get("NOCTORNAL_EGRESS_SEAL_KEY"):
        try:
            private = egress_seal.load_private(proxy["NOCTORNAL_EGRESS_SEAL_KEY"])
            public = egress_seal.load_public(client["NOCTORNAL_EGRESS_SEAL_PUBLIC"])
            if egress_seal.key_id(private.public_key()) != egress_seal.key_id(public):
                problems.append("NOCTORNAL_EGRESS_SEAL_PUBLIC is not the public half of "
                                "NOCTORNAL_EGRESS_SEAL_KEY.")
        except egress_seal.SealError:
            pass
    db_password = files.get("postgres-init.env", {}).get("NOCTORNAL_EGRESS_DB_PASSWORD")
    dsn = proxy.get("NOCTORNAL_EGRESS_DATABASE_URL", "")
    if db_password and dsn and f":{db_password}@" not in dsn:
        problems.append("NOCTORNAL_EGRESS_DATABASE_URL does not carry the password "
                        "postgres-init.env gives noctornal_egress.")
    version = compose()
    if version is None:
        problems.append("The docker compose version could not be read; Compose 2.24 or "
                        "later is needed for the optional env files.")
    elif version < COMPOSE_FLOOR:
        problems.append("Docker Compose is older than 2.24, which cannot read the "
                        "optional env files the production compose file uses.")
    return problems


# ---------------------------------------------------------------------------
# Commands that write (each signs its operator in)
# ---------------------------------------------------------------------------

def _connect():
    from noctornal_api.db import SystemPurpose, connect_system
    return connect_system(SystemPurpose.SCRIPT)


def _policy_from(args) -> dict:
    policy = {}
    if args.ports:
        policy["allowed_ports"] = [int(p) for p in args.ports.split(",") if p.strip()]
    if args.suffix is not None:
        policy["allowed_host_suffixes"] = args.suffix
    if args.cidr is not None:
        policy["allowed_cidrs"] = args.cidr
    for flag in ("any_public_host", "allow_onion", "resolve_at_proxy"):
        value = getattr(args, flag)
        if value is not None:
            policy[flag] = value
    for name in ("idle_timeout_s", "max_session_s", "max_concurrent"):
        value = getattr(args, name)
        if value is not None:
            policy[name] = value
    return policy


def read_endpoint(stream) -> egress_seal.ExitEndpoint:
    try:
        data = json.loads(stream.read())
        return egress_seal.ExitEndpoint(str(data["host"]), int(data["port"]),
                                        str(data.get("username") or ""),
                                        str(data.get("password") or ""))
    except (ValueError, KeyError, TypeError):
        raise SetupError('The endpoint on standard input is not JSON with "host" and '
                         '"port" (and optionally "username" and "password").') from None


def adopt(conn, user_id, via, *, ask=input, out=print) -> list[str]:
    svc = EgressAdminService(conn)
    proposal = svc.adopt_proposal()
    passive = proposal.get("passive_default")
    if not passive and not proposal["routes"]:
        out("Nothing to adopt: the passive default and the configured routes exist.")
        return []
    out("This deployment needs, to keep working through the egress proxy:")
    if passive:
        out(f"  a passive default profile 'passive' (DATACENTRE, leaving from this "
            f"deployment's own address), any public host on ports "
            f"{', '.join(str(p) for p in passive['allowed_ports'])}, carrying feeds "
            f"labelled up to {passive['ceiling']}")
    for route in proposal["routes"]:
        out(f"  the {route['name']} route allowing {route['entry']}")
        if route.get("confirm_network"):
            answer = ask(f"    The relay answers inside {route['network']}. Allow that "
                         f"network (Enter), or type another: ").strip()
            if answer:
                host_port = route["entry"].split("@", 1)
                port = route["entry"].rsplit(":", 1)[1]
                route["entry"] = f"{host_port[0]}@{answer}:{port}"
                route["network"] = answer
    if ask("Create these? Type yes to create them: ").strip().lower() != "yes":
        out("Nothing was created.")
        return []
    result = svc.adopt(actor_id=user_id, proposal=proposal, via=via)
    for item in result["created"]:
        out(f"EGRESS_ADOPTED {item}")
    return result["created"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python scripts/egress_setup.py",
        description="Set up and change the egress configuration without the console.")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("keygen", "dev-env", "role-sql", "adopt", "list", "dev-smtp"):
        sub.add_parser(name)
    pre = sub.add_parser("preflight")
    pre.add_argument("--dir", default=str(PROD_DIR))

    def policy_options(p):
        p.add_argument("--ports")
        p.add_argument("--suffix", action="append")
        p.add_argument("--cidr", action="append")
        for flag in ("any-public-host", "allow-onion", "resolve-at-proxy"):
            dest = flag.replace("-", "_")
            p.add_argument(f"--{flag}", dest=dest, action="store_true", default=None)
            p.add_argument(f"--no-{flag}", dest=dest, action="store_false")
        p.add_argument("--idle-timeout-s", dest="idle_timeout_s", type=int)
        p.add_argument("--max-session-s", dest="max_session_s", type=int)
        p.add_argument("--max-concurrent", dest="max_concurrent", type=int)

    create = sub.add_parser("profile-create")
    create.add_argument("--name", required=True)
    create.add_argument("--kind", required=True, choices=("RESIDENTIAL", "DATACENTRE",
                                                           "TOR", "VPN"))
    create.add_argument("--region")
    create.add_argument("--ceiling", required=True,
                        choices=("CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"))
    policy_options(create)
    change = sub.add_parser("profile-policy")
    change.add_argument("--profile", required=True, type=UUID)
    change.add_argument("--ceiling", choices=("CLEAR", "GREEN", "AMBER", "AMBER_STRICT",
                                              "RED"))
    policy_options(change)
    exit_ = sub.add_parser("profile-exit")
    exit_.add_argument("--profile", required=True, type=UUID)
    exit_.add_argument("--exit-kind", dest="exit_kind", required=True,
                       choices=("DIRECT", "HTTP", "HTTPS", "SOCKS5"))
    exit_.add_argument("--acknowledge-cleartext", dest="cleartext_ack",
                       action="store_true")
    for name in ("profile-passive-default", "profile-activate", "profile-deactivate"):
        sub.add_parser(name).add_argument("--profile", required=True, type=UUID)
    retire = sub.add_parser("profile-retire")
    retire.add_argument("--profile", required=True, type=UUID)
    retire.add_argument("--reason", required=True)
    route = sub.add_parser("route-create")
    route.add_argument("--name", required=True)
    route.add_argument("--description", required=True)
    allow = sub.add_parser("route-allow")
    allow.add_argument("--route", required=True, type=UUID)
    allow.add_argument("--entry", required=True)
    allow.add_argument("--note", required=True)
    disallow = sub.add_parser("route-disallow")
    disallow.add_argument("--route", required=True, type=UUID)
    disallow.add_argument("--destination", required=True, type=UUID)
    rretire = sub.add_parser("route-retire")
    rretire.add_argument("--route", required=True, type=UUID)
    rretire.add_argument("--reason", required=True)
    return parser


_ENDPOINT_FLAGS = ("--host", "--port", "--username", "--password", "--endpoint")


def run(argv: list[str], *, ask=input, secret=getpass.getpass, stdin=None,
        out=print, compose=compose_version) -> int:
    """The command line, with its prompts and streams injectable for tests."""
    if argv and argv[0] == "profile-exit" and any(
            a.split("=", 1)[0] in _ENDPOINT_FLAGS for a in argv[1:]):
        raise SetupError("An exit's endpoint is read from standard input as JSON, never "
                         "from the command line, where it would stay in the shell "
                         "history and the process list.")
    args = _parser().parse_args(argv)
    if args.command == "keygen":
        out(keygen())
        return 0
    if args.command == "dev-env":
        out(dev_env())
        return 0
    if args.command == "role-sql":
        out(role_sql())
        return 0
    if args.command == "preflight":
        problems = preflight(Path(args.dir), compose=compose)
        for problem in problems:
            out(problem)
        if problems:
            return 1
        out("The egress env files are in place and well formed.")
        return 0
    if args.command == "dev-smtp" and egress._production():
        raise SetupError("dev-smtp is for development: in production the relay is another "
                         "service, reached through an smtp route an administrator "
                         "creates.")
    conn = _connect()
    try:
        need = "egress.log.read" if args.command == "list" else "egress.manage"
        user_id, via = sign_in(conn, need=need, ask=ask, secret=secret)
        svc = EgressAdminService(conn)
        if args.command == "list":
            from noctornal_api.http.deps import user_ceiling
            level, held = user_ceiling(conn, user_id)
            body = svc.overview(clearance=level.name, compartments=held)
            for p in body["profiles"]:
                state = "retired" if p["retired"] else ("on" if p["is_active"] else "off")
                out(f"profile {p['id']} {p['name']} {p['kind']} exit "
                    f"{p['exit_kind'] or 'none'} {state}"
                    + (" passive default" if p["is_passive_default"] else ""))
            for r in body["routes"]:
                state = "retired" if r["retired"] else ("on" if r["is_active"] else "off")
                entries = ", ".join(d["entry"] for d in r["destinations"] if not d["retired"])
                out(f"route {r['id']} {r['name']} {state}: {entries or 'no destination'}")
            if body["withheld"]:
                out(f"and {body['withheld']} profiles above your clearance")
            return 0
        if args.command == "adopt":
            adopt(conn, user_id, via, ask=ask, out=out)
            return 0
        if args.command == "dev-smtp":
            made = svc.create_route(actor_id=user_id, name="smtp",
                                    description="The development Mailpit relay", via=via)
            out("EGRESS_ROUTE_CREATED smtp")
            svc.add_destination(actor_id=user_id, route_id=UUID(made["id"]),
                                entry="localhost:1025",
                                note="The development Mailpit relay on this host.", via=via)
            out("EGRESS_DESTINATION_ADDED localhost:1025")
            return 0
        if args.command == "profile-create":
            made = svc.create_profile(actor_id=user_id, name=args.name, kind=args.kind,
                                      region=args.region, ceiling=args.ceiling,
                                      policy=_policy_from(args), via=via)
            out(f"EGRESS_PROFILE_CREATED {made['id']}")
        elif args.command == "profile-policy":
            policy = _policy_from(args)
            if args.ceiling:
                policy["ceiling"] = args.ceiling
            level = conn.execute("SELECT tlp_clearance::text FROM iam.app_user WHERE id = %s",
                                 (user_id,)).fetchone()[0]
            result = svc.set_policy(actor_id=user_id, profile_id=args.profile,
                                    clearance=level, policy=policy, via=via)
            out("EGRESS_PROFILE_POLICY_CHANGED"
                + (" (widened: authorities recorded before now no longer pass)"
                   if result["widened"] else ""))
        elif args.command == "profile-exit":
            endpoint = None if args.exit_kind == "DIRECT" else read_endpoint(
                stdin if stdin is not None else sys.stdin)
            result = svc.seal_exit(actor_id=user_id, profile_id=args.profile,
                                   exit_kind=args.exit_kind, endpoint=endpoint,
                                   cleartext_ack=args.cleartext_ack, via=via)
            out(f"EGRESS_EXIT_SEALED {result['exit_kind']} "
                f"{result['key_id'] or ''}".rstrip())
        elif args.command == "profile-passive-default":
            svc.set_passive_default(actor_id=user_id, profile_id=args.profile, via=via)
            out("EGRESS_PASSIVE_DEFAULT_SET")
        elif args.command in ("profile-activate", "profile-deactivate"):
            active = args.command == "profile-activate"
            svc.set_active(actor_id=user_id, profile_id=args.profile, active=active, via=via)
            out("EGRESS_PROFILE_ACTIVATED" if active else "EGRESS_PROFILE_DEACTIVATED")
        elif args.command == "profile-retire":
            svc.retire(actor_id=user_id, profile_id=args.profile, reason=args.reason,
                       via=via)
            out("EGRESS_PROFILE_RETIRED")
        elif args.command == "route-create":
            made = svc.create_route(actor_id=user_id, name=args.name,
                                    description=args.description, via=via)
            out(f"EGRESS_ROUTE_CREATED {made['id']}")
        elif args.command == "route-allow":
            made = svc.add_destination(actor_id=user_id, route_id=args.route,
                                       entry=args.entry, note=args.note, via=via)
            out(f"EGRESS_DESTINATION_ADDED {made['entry']}")
        elif args.command == "route-disallow":
            svc.retire_destination(actor_id=user_id, route_id=args.route,
                                   destination_id=args.destination, via=via)
            out("EGRESS_DESTINATION_RETIRED")
        elif args.command == "route-retire":
            svc.retire_route(actor_id=user_id, route_id=args.route, reason=args.reason,
                             via=via)
            out("EGRESS_ROUTE_RETIRED")
        return 0
    except EgressAdminError as exc:
        raise SetupError(str(exc)) from None
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    load_env_local()
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except SetupError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
