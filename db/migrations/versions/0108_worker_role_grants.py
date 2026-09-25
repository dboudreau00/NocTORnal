"""The system role's privileges: the runtime role's, and not row security.

## Why a second runtime role

Row-level security (S1, 2026-09-25) puts `noctornal_app`, the role
every request connects as, under policies that show it only what the bound
user may read. Some work must see EVERY row or it silently does part of a
legal obligation and reports it done: a retention purge, a lock extension,
a legal hold on an exhibit above the officer's clearance, a guard that
permits a node's retirement when it finds no hidden tie, the withheld
counts docs/14 U2 exists for, a merge that re-points every edge. And every
write to the IAM plane (sessions, accounts, roles, assignments, grants)
moves off the request role altogether (0109), because the IAM plane is the
policies' own input and a request role that could write it could rebind
itself as anyone.

That work runs on `db.connect_system(purpose)`, which connects as
`noctornal_worker`: LOGIN, BYPASSRLS, owns nothing, member of nothing.
`db/init/10-app-role.sh` creates it at initdb (BYPASSRLS needs a
superuser, which initdb is and the migration role must never be);
`scripts/runtime_roles.py ensure` creates it on an existing cluster. This
revision GRANTS it.

## What it holds

Exactly what `noctornal_app` held before 0109 took the IAM-plane writes
away: 0060's grants (USAGE on the ten schemas, DML on every table, USAGE
and SELECT on sequences, EXECUTE on functions, SELECT on the version
table, the same default privileges for later tables), then UPDATE and
DELETE off the four ledgers, then `RUNTIME_REVOKES`: every privilege a
migration after 0060 took from the runtime role. BYPASSRLS lifts row
filtering; it does not lift a missing GRANT, so the append-only ledgers
and the insert-only records stay exactly as closed to this role as to the
request role. `test_worker_role_privileges_pg.py` holds the two roles
equal but for the IAM-plane writes, and `test_runtime_revokes_contract.py`
fails when a migration before this one revokes something from the
runtime role that `RUNTIME_REVOKES` does not repeat.

## It is a complete no-op where the role does not exist

As 0060: every statement is inside one DO block guarded on `pg_roles`, so
CI without the role, every developer database and the dev compose migrate
and round-trip exactly as before. The ordering rule is 0060's too: a role
created after this revision ran holds nothing until `scripts/runtime_roles.py
ensure` (or this file's UPGRADE_SQL, run by hand as the owner) grants it.
"""
from alembic import op

revision = "0108"
down_revision = "0107"
branch_labels = None
depends_on = None

#: The system role. Created by db/init/10-app-role.sh or
#: scripts/runtime_roles.py, never here: CREATE ROLE ... BYPASSRLS needs a
#: superuser.
WORKER_ROLE = "noctornal_worker"

#: 0060's list, frozen here (a migration never imports another's constants).
SCHEMAS = ("analytics", "audit", "collect", "comms", "core", "deception",
           "iam", "ingest", "lab", "notify")

#: 0060's append-only ledgers: UPDATE and DELETE come off.
LEDGERS = ("audit.event", "core.evidence_custody", "core.purge_tombstone",
           "lab.sample_access")

#: Every privilege a migration between 0060 and this one revoked from the
#: runtime role, so the system role holds no more than it on those tables.
#: (object, privileges, kind). Frozen: a later revision that revokes from
#: the runtime role revokes from BOTH roles itself.
RUNTIME_REVOKES: tuple[tuple[str, str, str], ...] = (
    ("lab.preservation_authorisation", "DELETE", "TABLE"),            # 0063
    ("iam.dual_control_policy_change", "UPDATE, DELETE", "TABLE"),    # 0075
    ("lab.yara_ruleset", "DELETE", "TABLE"),                          # 0080
    ("lab.yara_ruleset_version", "DELETE", "TABLE"),                  # 0080
    ("lab.yara_activation", "DELETE", "TABLE"),                       # 0080
    ("lab.yara_compiled", "UPDATE, DELETE", "TABLE"),                 # 0080
    ("lab.yara_compiled_rejected", "UPDATE, DELETE", "TABLE"),        # 0080
    ("collect.collection_authority", "DELETE", "TABLE"),              # 0083
    ("collect.collection_authority_target", "DELETE", "TABLE"),       # 0083
    ("collect.egress_binding", "INSERT, UPDATE, DELETE", "TABLE"),    # 0085
    ("collect.egress_connection", "INSERT, UPDATE, DELETE", "TABLE"),  # 0086
    ("collect.egress_connection_seq", "USAGE, UPDATE", "SEQUENCE"),   # 0086
    ("comms.pgp_key_acquisition", "DELETE", "TABLE"),                 # 0088
    ("comms.pgp_key", "DELETE", "TABLE"),                             # 0088
    ("comms.pgp_verification", "UPDATE, DELETE", "TABLE"),            # 0089
    ("comms.pgp_key_lookup", "DELETE", "TABLE"),                      # 0090
    ("notify.jira_link", "DELETE", "TABLE"),                          # 0097
    ("notify.jira_event", "DELETE", "TABLE"),                         # 0097
    ("ingest.provider", "DELETE", "TABLE"),                           # 0098
    ("ingest.provider_exposure_change", "DELETE", "TABLE"),           # 0098
    ("ingest.lookup", "DELETE", "TABLE"),                             # 0099
    ("ingest.lookup_result", "DELETE", "TABLE"),                      # 0099
    ("ingest.lookup_attempt", "UPDATE, DELETE", "TABLE"),             # 0099
    ("ingest.lookup_batch", "DELETE", "TABLE"),                       # 0101
    ("lab.screening_list", "DELETE", "TABLE"),                        # 0102
    ("lab.screening_hash", "UPDATE", "TABLE"),                        # 0102
    ("lab.screening_result", "UPDATE, DELETE", "TABLE"),              # 0102
    ("lab.screening_review", "UPDATE, DELETE", "TABLE"),              # 0102
    ("lab.detonation", "DELETE", "TABLE"),                            # 0103
    ("collect.telegram_chat", "DELETE", "TABLE"),                     # 0106
    ("collect.telegram_message", "DELETE", "TABLE"),                  # 0106
)

VERSION_TABLE = "public.alembic_version"


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _array(values: tuple[str, ...]) -> str:
    """A `text[]` literal of module constants matching `[a-z_.]+`."""
    return "ARRAY[" + ", ".join(f"'{v}'" for v in values) + "]"


def _revokes(role_expr: str) -> str:
    """One guarded REVOKE per RUNTIME_REVOKES entry, skipped where the
    object does not exist (a database built from db/schema.sql, a partial
    chain in a test)."""
    lines = []
    for obj, privileges, kind in RUNTIME_REVOKES:
        target = "SEQUENCE " if kind == "SEQUENCE" else ""
        lines.append(
            f"    IF to_regclass('{obj}') IS NOT NULL THEN\n"
            f"      EXECUTE format('REVOKE {privileges} ON {target}{obj} FROM %I', {role_expr});\n"
            f"    END IF;")
    return "\n".join(lines)


def grants_sql(role: str) -> str:
    """0060's grant shape for `role`, then the ledger and later revokes.
    A function of the role so `scripts/runtime_roles.py ensure` replays the
    same text for either runtime role on a cluster where one was created
    after its migration ran."""
    return f"""
DO $noc$
DECLARE
  r    text := '{role}';
  ownr text := current_user;
  s    text;
  t    text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
    FOREACH s IN ARRAY {_array(SCHEMAS)} LOOP
      EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', s, r);
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE'
                     || ' ON ALL TABLES IN SCHEMA %I TO %I', s, r);
      EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', s, r);
      EXECUTE format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %I TO %I', s, r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO %I',
                     ownr, s, r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' GRANT USAGE, SELECT ON SEQUENCES TO %I', ownr, s, r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' GRANT EXECUTE ON FUNCTIONS TO %I', ownr, s, r);
    END LOOP;
    FOREACH t IN ARRAY {_array(LEDGERS)} LOOP
      EXECUTE format('REVOKE UPDATE, DELETE ON %s FROM %I', t::regclass, r);
    END LOOP;
{_revokes('r')}
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
    IF to_regclass('{VERSION_TABLE}') IS NOT NULL THEN
      EXECUTE format('GRANT SELECT ON {VERSION_TABLE} TO %I', r);
    END IF;
  END IF;
END
$noc$;
"""


def revoke_all_sql(role: str) -> str:
    """0060's DOWNGRADE_SQL shape: default privileges first, because they
    are catalog rows of their own and survive a REVOKE on the tables."""
    return f"""
DO $noc$
DECLARE
  r    text := '{role}';
  ownr text := current_user;
  s    text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
    FOREACH s IN ARRAY {_array(SCHEMAS)} LOOP
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' REVOKE ALL ON TABLES FROM %I', ownr, s, r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' REVOKE ALL ON SEQUENCES FROM %I', ownr, s, r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA %I'
                     || ' REVOKE ALL ON FUNCTIONS FROM %I', ownr, s, r);
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I', s, r);
      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I', s, r);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM %I', s, r);
      EXECUTE format('REVOKE ALL ON SCHEMA %I FROM %I', s, r);
    END LOOP;
    IF to_regclass('{VERSION_TABLE}') IS NOT NULL THEN
      EXECUTE format('REVOKE ALL ON {VERSION_TABLE} FROM %I', r);
    END IF;
    EXECUTE format('REVOKE USAGE ON SCHEMA public FROM %I', r);
  END IF;
END
$noc$;
"""


UPGRADE_SQL = grants_sql(WORKER_ROLE)
DOWNGRADE_SQL = revoke_all_sql(WORKER_ROLE)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
