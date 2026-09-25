"""Create and grant the two runtime roles on an existing cluster (S1).

    python scripts/runtime_roles.py ensure     create both roles if missing, grant them here
    python scripts/runtime_roles.py check      print each role's attributes and privileges

## Why this exists

The runtime roles are born at initdb (`db/init/10-app-role.sh`), which runs
once, on an empty data directory, and only when the passwords are set. A
cluster initialised before `noctornal_worker` existed, or without either
password (every development stack), has no such roles, and the migrations
that grant them are no-ops there by design (0060, 0108, 0109: a GRANT to a
missing role would break every developer's `alembic upgrade head`).
Alembic never re-runs a revision it has recorded, so creating a role
afterwards leaves it holding nothing. `ensure` is the repair, and it
replays exactly the migrations' own SQL, so the two cannot disagree.

## What ensure does, in order

1. Refuses under NOCTORNAL_ENV=production unless `--production` is given:
   in production the roles are an initdb decision, and this is the repair
   an operator runs deliberately.
2. When the connected role is a superuser: creates `noctornal_app`
   (NOBYPASSRLS) and `noctornal_worker` (BYPASSRLS) with exactly the
   attributes 10-app-role.sh gives them and NO password (nothing in the
   test suite logs in as them: it reaches them with SET ROLE from the
   owner), and pins the log and message settings 10-app-role.sh pins.
   Not a superuser: prints the statements for one to run, and stops.
3. On THIS database: the runtime grants for both roles (0108's
   `grants_sql`, the shape 0060 set plus every later revoke), then 0109's
   IAM-plane lockdown for the request role when the database is at or past
   0109.

It never drops or alters any other role, and it touches only the database
DATABASE_URL names.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(_HERE), "apps", "api", "src"))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from _env import load_env_local  # noqa: E402

load_env_local()

VERSIONS = Path(_HERE).parent / "db" / "migrations" / "versions"
APP_ROLE = "noctornal_app"
WORKER_ROLE = "noctornal_worker"

#: The attributes db/init/10-app-role.sh creates each role with.
ROLE_ATTRIBUTES = {
    APP_ROLE: "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS",
    WORKER_ROLE: "LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS",
}

#: Role-level settings for the request role. log_parameter_max_length keeps
#: the row-security binding proof, which travels as a bind parameter, out
#: of the server log; lc_messages makes a row-security refusal's text the
#: one the API recognises (http/errors.py).
APP_ROLE_SETTINGS = (
    ("log_parameter_max_length", "0"),
    ("log_parameter_max_length_on_error", "0"),
    ("lc_messages", "C"),
)


def _migration(prefix: str):
    path = next(VERSIONS.glob(f"{prefix}_*.py"))
    spec = importlib.util.spec_from_file_location(f"m{prefix}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def create_statements() -> list[str]:
    out = []
    for role, attributes in ROLE_ATTRIBUTES.items():
        out.append(
            f"DO $noc$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = "
            f"'{role}') THEN CREATE ROLE {role} {attributes}; END IF; END $noc$;")
    for name, value in APP_ROLE_SETTINGS:
        out.append(f"ALTER ROLE {APP_ROLE} SET {name} = '{value}';")
    return out


def _at_or_past(conn, revision: str) -> bool:
    row = conn.execute("SELECT version_num FROM alembic_version").fetchone()
    return bool(row and row[0] >= revision)


def ensure(conn) -> int:
    superuser = conn.execute(
        "SELECT rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()[0]
    if not superuser:
        print("The connected role is not a superuser, so it cannot create a role "
              "with BYPASSRLS. Ask one to run:")
        for statement in create_statements():
            print(f"  {statement}")
        print("then run this command again.")
        return 1
    for statement in create_statements():
        conn.execute(statement)
    grants = _migration("0108")
    conn.execute(grants.grants_sql(APP_ROLE))
    conn.execute(grants.grants_sql(WORKER_ROLE))
    if _at_or_past(conn, "0109"):
        conn.execute(_migration("0109").UPGRADE_SQL)
    print(f"{APP_ROLE} and {WORKER_ROLE} exist and are granted on this database.")
    print(f"NOCTORNAL_APP_DB_ROLE={APP_ROLE}")
    print(f"NOCTORNAL_WORKER_DB_ROLE={WORKER_ROLE}")
    return 0


def check(conn) -> int:
    for role in (APP_ROLE, WORKER_ROLE):
        row = conn.execute(
            """SELECT rolcanlogin, rolsuper, rolbypassrls, rolinherit
                 FROM pg_roles WHERE rolname = %s""", (role,)).fetchone()
        if row is None:
            print(f"{role}: does not exist")
            continue
        owns = conn.execute(
            """SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner
                WHERE r.rolname = %s""", (role,)).fetchone()[0]
        writes_iam = conn.execute(
            "SELECT has_table_privilege(%s, 'iam.session', 'INSERT')",
            (role,)).fetchone()[0]
        print(f"{role}: login {row[0]}, superuser {row[1]}, bypassrls {row[2]}, "
              f"inherit {row[3]}, owns {owns} relations, "
              f"may insert sessions {writes_iam}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("ensure", "check"))
    parser.add_argument("--production", action="store_true",
                        help="allow ensure under NOCTORNAL_ENV=production")
    args = parser.parse_args(argv)
    production = os.environ.get("NOCTORNAL_ENV", "").strip().lower() == "production"
    if args.command == "ensure" and production and not args.production:
        print("NOCTORNAL_ENV is production: in production the runtime roles are "
              "created at initdb. Pass --production to repair a cluster on purpose.")
        return 1
    from noctornal_api.db import connect
    conn = connect()
    try:
        return ensure(conn) if args.command == "ensure" else check(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
