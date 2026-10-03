"""A recorded claim is never rewritten or deleted by the runtime roles
(graph-assertion-claims-mutable-by-request-role, review 2026-10-03).

## Why

Invariant 5 says a claim's own columns are never written again, and that a
retraction (and, since 0131, a supersession) stamps its marks once, from
NULL. Until this revision that was a convention of `graph.py` alone. 0060
handed `noctornal_app` UPDATE and DELETE on every table but four ledgers,
and 0108 handed `noctornal_worker` the same, so one statement on the
request role's connection could re-grade a claim, rewrite its rationale or
value, un-retract a withdrawn source, or delete a claim that was not an
element's last, with no audit row. The review proved each as `SET ROLE
noctornal_app` bound to an AMBER analyst.

## What this does

- **Both runtime roles lose UPDATE and DELETE on `core.assertion`** and
  keep UPDATE on exactly the five columns of the marked row:
  `retracted_at`, `retracted_by`, `retraction_reason`, `superseded_at`,
  `superseded_by`. Every claim column is then refused by the privilege
  check itself, whatever the statement. INSERT stays: recording a claim is
  the product's main write.
- **The marks are stamped once, from NULL, for every role** (the trigger
  `assertion_marked_once`). A retraction or a supersession, once recorded,
  is never changed or withdrawn, and a retraction's author and reason do
  not arrive without its time. The schema owner is held to it too; an
  owner who must repair a row disables the trigger by name, as the table
  comments say of the other guards.
- **A mark a runtime role stamps must be coherent** (the verifier's round,
  2026-10-03; the schema owner and a superuser are exempt). A
  retraction needs its author and a reason with its time, the author must
  be an existing user and, when a session is bound to the connection, the
  person signed in (`iam.rls_actor()`); a supersession must name the claim
  that replaces it (`supersedes_id` pointing back at it, which 0131 already
  holds to the same element and case). Without these a statement injected
  into a request could hide a live claim with no author, no reason and no
  replacement, and no audit row. The function is SECURITY DEFINER with a
  pinned search path, as 0131's is, so an invisible row never reads as
  absent.
- **TRUNCATE is refused** (`assertion_never_truncated`), the statement
  that would empty the table without firing a row trigger. It needs the
  owner, so this guards against an accident, not the runtime roles.
- `GUARDED_TABLES` declares what the request role keeps, the way 0063
  declared the first guarded table; `test_app_role_privileges_pg.py` and
  `test_worker_role_privileges_pg.py` hold the catalog to it.

The owner keeps UPDATE and DELETE: migrations and maintenance run as the
owner, and the test suite's teardown releases documents from claims as
the owner. Not being the owner is the control, as 0060 says.

Every legitimate write still works: `create_*` and `add_assertion`
insert, `retract_assertion` stamps the three retraction columns from
NULL, `supersede_assertion` (0131) inserts the copy and stamps the two
supersession columns from NULL, and merges never touch a claim.

`GRANTS_SQL` is idempotent and separate, so `scripts/runtime_roles.py
ensure` replays it for a role created after this revision ran.

## Downgrade

Drops both triggers and their functions, takes the column grants back and
gives both roles UPDATE and DELETE again, which is what 0060 and 0108 left
them holding. Nothing is lost: no row is written by this revision.
"""
from alembic import op

revision = "0135"
down_revision = "0134"
branch_labels = None
depends_on = None

#: The two runtime roles, spelled as 0060 and 0108 spell them. A migration
#: does not import another's constants, so the names are repeated.
APP_ROLE = "noctornal_app"
WORKER_ROLE = "noctornal_worker"

#: Guarded without being append-only: the table and the privileges the
#: runtime role KEEPS on it at table level. Its UPDATE is column-level
#: only (`MARK_COLUMNS`), which `has_table_privilege` does not count.
GUARDED_TABLES = {
    "core.assertion": ("SELECT", "INSERT"),
}

#: The columns of the marked row: the only ones the runtime roles may write
#: after a claim is recorded, and each only once, from NULL.
MARK_COLUMNS = ("retracted_at", "retracted_by", "retraction_reason",
                "superseded_at", "superseded_by")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _for_each_role(body: str) -> str:
    roles = ", ".join(f"'{r}'" for r in (APP_ROLE, WORKER_ROLE))
    return f"""
DO $noc$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY[{roles}]::text[] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
{body}
    END IF;
  END LOOP;
END
$noc$;
"""


_COLS = ", ".join(MARK_COLUMNS)

#: Frozen text, and idempotent: replayed by scripts/runtime_roles.py ensure.
GRANTS_SQL = _for_each_role(f"""\
      EXECUTE format('REVOKE UPDATE, DELETE ON core.assertion FROM %I', r);
      EXECUTE format('GRANT UPDATE ({_COLS}) ON core.assertion TO %I', r);""")

UNGRANTS_SQL = _for_each_role(f"""\
      EXECUTE format('REVOKE UPDATE ({_COLS}) ON core.assertion FROM %I', r);
      EXECUTE format('GRANT UPDATE, DELETE ON core.assertion TO %I', r);""")

#: Frozen text: a later revision that changes it restates it.
TRIGGERS_SQL = """
CREATE FUNCTION core.assertion_marked_once() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
AS $f$
DECLARE
  actor uuid;
  caller text := CASE WHEN pg_catalog.current_setting('role') = 'none'
                      THEN session_user::text
                      ELSE pg_catalog.current_setting('role') END;
BEGIN
  IF OLD.retracted_at IS NOT NULL THEN
    IF NEW.retracted_at IS DISTINCT FROM OLD.retracted_at
       OR NEW.retracted_by IS DISTINCT FROM OLD.retracted_by
       OR NEW.retraction_reason IS DISTINCT FROM OLD.retraction_reason THEN
      RAISE EXCEPTION 'a retraction is recorded once and is never changed or withdrawn';
    END IF;
  ELSIF NEW.retracted_at IS NULL
        AND (NEW.retracted_by IS DISTINCT FROM OLD.retracted_by
             OR NEW.retraction_reason IS DISTINCT FROM OLD.retraction_reason) THEN
    RAISE EXCEPTION 'a retraction is stamped with its time, its author and its reason together';
  END IF;
  IF OLD.superseded_at IS NOT NULL THEN
    IF NEW.superseded_at IS DISTINCT FROM OLD.superseded_at
       OR NEW.superseded_by IS DISTINCT FROM OLD.superseded_by THEN
      RAISE EXCEPTION 'a supersession is recorded once and is never changed or withdrawn';
    END IF;
  ELSIF NEW.superseded_at IS NULL
        AND NEW.superseded_by IS DISTINCT FROM OLD.superseded_by THEN
    RAISE EXCEPTION 'a supersession is stamped with its time';
  END IF;
  /* What a statement injected into a request may NOT do with a mark (verify
     round, 2026-10-03). The schema owner (and a superuser) is exempt, as
     for every guard, and repairs by disabling this trigger by name; both
     runtime roles are held, whatever else they may bypass. The caller is the
     role in effect, as `iam.rls_caller_exempt` reads it, because this
     function runs as its owner. */
  IF NOT pg_catalog.pg_has_role(
           caller,
           (SELECT c.relowner FROM pg_catalog.pg_class c WHERE c.oid = TG_RELID),
           'USAGE') THEN
    IF NEW.retracted_at IS NOT NULL AND OLD.retracted_at IS NULL THEN
      IF NEW.retracted_by IS NULL OR NEW.retraction_reason IS NULL
         OR pg_catalog.btrim(NEW.retraction_reason) = '' THEN
        RAISE EXCEPTION 'a retraction is stamped with its time, its author and its reason together';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM iam.app_user u WHERE u.id = NEW.retracted_by) THEN
        RAISE EXCEPTION 'a retraction names the person who made it';
      END IF;
      actor := iam.rls_actor();
      IF actor IS NOT NULL AND NEW.retracted_by IS DISTINCT FROM actor THEN
        RAISE EXCEPTION 'a retraction names the person signed in, and nobody else';
      END IF;
    END IF;
    IF NEW.superseded_at IS NOT NULL AND OLD.superseded_at IS NULL THEN
      IF NEW.superseded_by IS NULL OR NOT EXISTS (
           SELECT 1 FROM core.assertion r
            WHERE r.id = NEW.superseded_by AND r.supersedes_id = OLD.id) THEN
        RAISE EXCEPTION 'a supersession names the claim that replaces this one';
      END IF;
    END IF;
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER assertion_marked_once
  BEFORE UPDATE OF retracted_at, retracted_by, retraction_reason,
                   superseded_at, superseded_by ON core.assertion
  FOR EACH ROW EXECUTE FUNCTION core.assertion_marked_once();

CREATE FUNCTION core.assertion_kept() RETURNS trigger
  LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp
AS $f$
BEGIN
  RAISE EXCEPTION 'claims are never deleted: a claim is retracted or superseded and its row is kept';
END
$f$;

CREATE TRIGGER assertion_never_truncated
  BEFORE TRUNCATE ON core.assertion
  FOR EACH STATEMENT EXECUTE FUNCTION core.assertion_kept();

COMMENT ON FUNCTION core.assertion_marked_once() IS
  'Invariant 5 at the database (review 2026-10-03): a retraction and a '
  'supersession are stamped once, from NULL, and never changed; for a '
  'runtime role a retraction carries its author (the signed-in person) and '
  'its reason, and a supersession names its replacement. An owner who must '
  'repair a row disables trigger assertion_marked_once by name.';
"""

DROP_TRIGGERS_SQL = """
DROP TRIGGER IF EXISTS assertion_never_truncated ON core.assertion;
DROP FUNCTION IF EXISTS core.assertion_kept();
DROP TRIGGER IF EXISTS assertion_marked_once ON core.assertion;
DROP FUNCTION IF EXISTS core.assertion_marked_once();
"""


def upgrade() -> None:
    run(TRIGGERS_SQL)
    run(GRANTS_SQL)


def downgrade() -> None:
    run(UNGRANTS_SQL)
    run(DROP_TRIGGERS_SQL)
