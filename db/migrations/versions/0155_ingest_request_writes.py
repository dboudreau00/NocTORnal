"""The request role writes only what a request writes on the ingest
records, the victims' credentials and the reveal authorisations (F51,
2026-10-02).

## Why

0154's UPDATE policies say WHICH ROWS the request role may update. They
say nothing about which columns or which values, and the verification of
2026-10-02 showed what that left an injected statement:

- the grantee of a live authorisation could move its window (the 30-day
  CHECK is counted from `granted_at`, which they could move too, so it
  bounded nothing), re-attribute it to another officer and retarget it to
  another of their cases;
- an `ingest.manage` holder assigned to a case could detach its record
  into quarantine, out of the case and out of the case's legal hold, which
  reaches a record only through its case (`retention.due`), and a reader
  of two cases could move a record between them; any reader could lower a
  record's classification, drop its compartments, empty its payload or
  bring its expiry forward to the next purge;
- any reader of a record could clear a credential's value together with
  its key (the encrypted-or-absent CHECK is satisfied by both NULL), move
  it to another record, or reset its reveal count.

## What the request role keeps

`RUNTIME_COLUMN_UPDATES`, which is every column a request writes on these
tables (every UPDATE of them in apps/api/src and scripts):

- `ingest.record`: `case_id` (`IngestService.attach_record`) and
  `category`, `category_source`, `category_confidence`, `retain_until`
  (`correct_category`);
- `ingest.victim_credential`: `reveal_count`, `last_revealed_at`, and
  `ingest.pii_authorisation`: `query_count` (`reveal_credential`).

Table-level UPDATE comes off the request role on all three. A column grant
says which columns, not which values (0112's reasoning), so three BEFORE
UPDATE guards hold the values to what those verbs write, for a caller that
row security does not exempt (the owner and the system role are trusted,
as in 0112, so every fixture and system path is unchanged):

- a record's case is set once, from quarantine, and is never moved or
  cleared; its expiry only ever moves later (a correction keeps or extends
  it): it is never brought forward or cleared, a record with NO expiry is
  given none, and no date goes past 1 December 9999, the furthest the
  application can read back (2026-10-03);
- a credential's reveal count rises by one, stamped now;
- an authorisation's query count rises by one.

## The system role

0108 holds `noctornal_worker` to the request role's privileges. On
`ingest.pii_authorisation` it loses table UPDATE too and keeps
`query_count`: no system connection writes that table. On `ingest.record`
and `ingest.victim_credential` it keeps table UPDATE (`SYSTEM_KEEPS_UPDATE`),
as it keeps the IAM-plane writes 0109 took from the request role: the
retention purge empties a record, a compartment rename rewrites
`compartments`, scoring writes `priority` and `priority_detail`, and the
KEK re-wrap re-seals `value_ciphertext` and `value_key_id`.
`test_worker_role_privileges_pg.py` reads both constants.

`scripts/runtime_roles.py ensure` replays `GRANTS_SQL` after 0108's and
0109's own, so a runtime role created after this revision ran is narrowed
the same way. It never replays `GUARDS_SQL`, which is not repeatable.

## What holds, and what does not

Holds against any statement the request role sends: an authorisation's
window is the one it was granted with (0154 dates a grant when it is made),
its officer, grantee and case never change, a revoked one stays revoked,
and its count only rises, by one; a record is never detached, moved
between cases, relabelled, emptied or unfolded, and its expiry is never
brought forward, cleared, given to a record that has none (retention reads
none as never due) or set past what the application can read back, so a
request cannot make the next purge destroy a record or poison its listing;
a credential's value, key, kind and record never change, and its count only
rises, by one.

Does not, because a verb writes the same columns: any reader of a record
can make the category correction's write (category, its source and
confidence, an expiry only later) without the verb's reason, its audit row
or its refusal on a closed case; an `ingest.manage` holder who reads a case
can attach a quarantined record to it the same way; a reader of a
credential can count a reveal nobody made, on the credential and, for the
grantee, on their own live authorisation. None of these hides, moves or
destroys anything, and every real reveal has its PII_REVEALED row in the
append-only audit log.

One of them does defeat something, and it is said plainly (2026-10-03): "an expiry only
later" lets any reader of a
record push its expiry out, as far as 1 December 9999, so a record outlives
the retention rule it was filed under. That is a retention failure, the
opposite of a destruction: nothing is lost, and the audit log records no
such write, because only the verb audits and a raw statement is not the
verb. There is no tighter bound here, because `core.retention_rule` bounds
`retain_days` only from below and a guard that reads no table cannot know
the rule; closing it means the extension going through a definer function
that reads the rule. Recorded in docs/17.

A record with NO expiry (NULL) is left alone by a request and by the
correction, which used to give it the new category's clock from arrival.
The application always stamps an expiry, so only a legacy or hand-made row
has none, and giving it one is a destruction decision that belongs to
retention (`retention.py` leaves a clockless document alone for the same
reason), not to a relabel.

## No-op without the roles; downgrade

The grants are guarded on `pg_roles` as 0060 and 0109 are. The downgrade
drops the guards, takes the column grants back and gives both roles table
UPDATE on the three tables again, as 0060 and 0108 left them.
"""
from alembic import op

revision = "0155"
down_revision = "0154"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"
WORKER_ROLE = "noctornal_worker"

#: Every column a request writes on these tables, and so all the request
#: role may UPDATE there. `test_app_role_privileges_pg.py` reads it, with
#: 0109's constant of the same name.
RUNTIME_COLUMN_UPDATES: dict[str, tuple[str, ...]] = {
    "ingest.record": ("case_id", "category", "category_source",
                      "category_confidence", "retain_until"),
    "ingest.victim_credential": ("reveal_count", "last_revealed_at"),
    "ingest.pii_authorisation": ("query_count",),
}

#: Where the system role keeps table-level UPDATE, because a system path
#: writes columns no request does (the docstring names them).
SYSTEM_KEEPS_UPDATE: tuple[str, ...] = ("ingest.record", "ingest.victim_credential")

#: (trigger, table, columns it fires on, function).
GUARDS: tuple[tuple[str, str, str, str], ...] = (
    ("record_request_guard", "ingest.record", "case_id, retain_until",
     "ingest.record_request_guard()"),
    ("victim_credential_request_guard", "ingest.victim_credential",
     "reveal_count, last_revealed_at", "ingest.victim_credential_request_guard()"),
    ("pii_authorisation_request_guard", "ingest.pii_authorisation",
     "query_count", "ingest.pii_authorisation_request_guard()"),
)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _grants(verb: str, preposition: str, role: str, tables) -> str:
    lines = []
    for table in tables:
        cols = ", ".join(RUNTIME_COLUMN_UPDATES[table])
        lines.append(f"    EXECUTE format('{verb} UPDATE ({cols}) ON {table} "
                     f"{preposition} %I', {role});")
    return "\n".join(lines)


def _whole(verb: str, preposition: str, role: str, tables) -> str:
    return "\n".join(f"    EXECUTE format('{verb} UPDATE ON {table} {preposition} %I', "
                     f"{role});" for table in tables)


_SYSTEM_NARROWED = tuple(t for t in RUNTIME_COLUMN_UPDATES if t not in SYSTEM_KEEPS_UPDATE)

#: Repeatable: `scripts/runtime_roles.py ensure` replays it.
GRANTS_SQL = f"""
DO $noc$
DECLARE
  app text := '{APP_ROLE}';
  wrk text := '{WORKER_ROLE}';
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
{_whole('REVOKE', 'FROM', 'app', RUNTIME_COLUMN_UPDATES)}
{_grants('GRANT', 'TO', 'app', RUNTIME_COLUMN_UPDATES)}
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = wrk) THEN
{_whole('REVOKE', 'FROM', 'wrk', _SYSTEM_NARROWED)}
{_grants('GRANT', 'TO', 'wrk', _SYSTEM_NARROWED)}
  END IF;
END
$noc$;
"""

#: The values those columns may take from a caller row security binds.
#: SECURITY INVOKER and reading no table, as 0112's guards; the messages
#: name no table, so no policied table appears in a trigger body.
GUARDS_SQL = """
CREATE FUNCTION ingest.record_request_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF OLD.case_id IS NOT NULL AND NEW.case_id IS DISTINCT FROM OLD.case_id THEN
    RAISE EXCEPTION 'a record is attached to a case once, from quarantine, and is never moved or detached'
      USING ERRCODE = '42501';
  END IF;
  /* An expiry only ever moves later (g31 verification 2, 2026-10-03). NULL is
     the latest there is: retention.due never selects a record with none, so
     a request neither clears an expiry nor gives a record one, since a date
     on an unclocked record is a destruction decision and retention's, not a
     relabel's. Nothing past 1 December 9999 either: psycopg cannot read
     infinity, or a date past the year 9999 in any time zone, so one such
     value would poison every listing that reads the record. */
  IF NEW.retain_until IS DISTINCT FROM OLD.retain_until
     AND (OLD.retain_until IS NULL
          OR NEW.retain_until IS NULL
          OR NEW.retain_until < OLD.retain_until
          OR NEW.retain_until > timestamptz '9999-12-01 00:00:00+00') THEN
    RAISE EXCEPTION 'a record''s expiry only moves later, within what can be read back: a request never brings it forward, clears it or gives a record one'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION ingest.victim_credential_request_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF NEW.reveal_count IS DISTINCT FROM OLD.reveal_count + 1
     OR NEW.last_revealed_at IS DISTINCT FROM pg_catalog.now() THEN
    RAISE EXCEPTION 'a reveal is counted one at a time, stamped with the time it was made'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

CREATE FUNCTION ingest.pii_authorisation_request_guard() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF iam.rls_caller_exempt() THEN
    RETURN NEW;
  END IF;
  IF NEW.query_count IS DISTINCT FROM OLD.query_count + 1 THEN
    RAISE EXCEPTION 'an authorisation counts its reveals one at a time'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
""" + "".join(
    f"\nCREATE TRIGGER {name}\n  BEFORE UPDATE OF {columns} ON {table}\n"
    f"  FOR EACH ROW EXECUTE FUNCTION {function};\n"
    for name, table, columns, function in GUARDS)

DOWNGRADE_SQL = "".join(
    f"DROP TRIGGER {name} ON {table};\nDROP FUNCTION {function};\n"
    for name, table, _columns, function in reversed(GUARDS)) + f"""
DO $noc$
DECLARE
  app text := '{APP_ROLE}';
  wrk text := '{WORKER_ROLE}';
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN
{_grants('REVOKE', 'FROM', 'app', RUNTIME_COLUMN_UPDATES)}
{_whole('GRANT', 'TO', 'app', RUNTIME_COLUMN_UPDATES)}
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = wrk) THEN
{_grants('REVOKE', 'FROM', 'wrk', _SYSTEM_NARROWED)}
{_whole('GRANT', 'TO', 'wrk', _SYSTEM_NARROWED)}
  END IF;
END
$noc$;
"""


def upgrade() -> None:
    run(GRANTS_SQL)
    run(GUARDS_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
