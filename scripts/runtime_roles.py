"""Create and grant the two runtime roles on an existing cluster.

    python scripts/runtime_roles.py ensure     create both roles if missing, grant them here
    python scripts/runtime_roles.py check      print each role's attributes and privileges

The runtime roles are born at initdb (`db/init/10-app-role.sh`), which runs once, on an empty data
directory, and only when the passwords are set. A cluster initialised without them (every
development stack, or one older than `noctornal_worker`) has no such roles, and the migrations that
grant them are no-ops there by design, because a GRANT to a missing role would break every
developer's `alembic upgrade head`. Alembic never re-runs a recorded revision, so a role created
afterwards holds nothing. `ensure` is the repair, and it replays the migrations' own SQL, so the
two cannot disagree:

1. Refuses under NOCTORNAL_ENV=production unless `--production` is given: in production the roles
   are an initdb decision, and this is a repair an operator runs deliberately.
2. As a superuser, creates `noctornal_app` (NOBYPASSRLS) and `noctornal_worker` (BYPASSRLS) with
   exactly the attributes and pinned log and message settings 10-app-role.sh gives them and no
   password (the tests reach them with SET ROLE from the owner). Otherwise it prints the
   statements for a superuser to run, and stops.
3. On this database, replays 0108's runtime grants for both roles and 0109's IAM-plane lockdown
   for the request role, then every later revision that takes back what 0108's blanket grant
   hands out, each only when the database is at or past it.

It never drops or alters any other role, and it touches only the database DATABASE_URL names.
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


def _migration_named(stem: str):
    path = next(VERSIONS.glob(f"*_{stem}.py"))
    spec = importlib.util.spec_from_file_location(f"m_{stem}", path)
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


def grant(conn) -> None:
    """Step 3: replay the migrations' runtime grants on this database, in
    chain order, each only once the database has reached it."""
    grants = _migration("0108")
    conn.execute(grants.grants_sql(APP_ROLE))
    conn.execute(grants.grants_sql(WORKER_ROLE))
    if _at_or_past(conn, "0109"):
        conn.execute(_migration("0109").UPGRADE_SQL)
    # 0108's blanket grant hands back UPDATE and DELETE on core.assertion; the claims guard takes
    # them off again. Found by name and read for its own revision id, so renumbering it cannot
    # break this replay.
    guard = _migration_named("assertion_marked_once")
    if _at_or_past(conn, guard.revision):
        conn.execute(guard.GRANTS_SQL)

    # 0108's grants hand table SELECT back on iam.app_user and 0109's the mfa_satisfied_at UPDATE,
    # so the two revisions that take them away are replayed after them.
    for revision in ("0143", "0144"):
        if _at_or_past(conn, revision):
            conn.execute(_migration(revision).PRIVILEGES_SQL)
    # 0155's GRANTS_SQL only: its guards are created once, by the migration.
    if _at_or_past(conn, "0155"):
        conn.execute(_migration("0155").GRANTS_SQL)
    # 0156's too: no DELETE on the persona act queue, which 0108's blanket grant hands back to a new
    # role.
    if _at_or_past(conn, "0156"):
        conn.execute(_migration("0156").GRANTS_SQL)
    # The chain triggers draw the ledger sequences as the owner, so neither runtime role holds them;
    # 0108's blanket grant hands every sequence back, so the revoke is replayed. Found by name.
    sequences = _migration_named("ledger_sequences_trigger_drawn")
    if _at_or_past(conn, sequences.revision):
        conn.execute(sequences.REVOKE_SQL)
    # What else 0108's blanket grant hands back: the Lab custody ledger's sequence, the session,
    # break-glass and other sealed columns, the case material's UPDATE and DELETE and the
    # configuration tables' writes. Each found by name.
    for stem, attribute in (("sample_access_sequence_trigger_drawn", "REVOKE_SQL"),
                            ("iam_session_break_glass_columns_sealed", "PRIVILEGES_SQL"),
                            ("case_material_request_writes", "GRANTS_SQL"),
                            ("configuration_read_only", "PRIVILEGES_SQL"),
                            ("sealed_columns_outside_accounts", "PRIVILEGES_SQL"),
                            ("notify_preference_read_only", "PRIVILEGES_SQL")):
        later = _migration_named(stem)
        if _at_or_past(conn, later.revision):
            conn.execute(getattr(later, attribute))


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
    grant(conn)
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
    from noctornal_api.config import is_production
    production = is_production()
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
