"""A YARA compile is queued through a definer, and the compile queue is
read-only to the request role
(the heartbeat and the queues, 2026-11-15).

## Why

0179 left `lab.yara_compile_job` writable by the request role because it is
not configuration. One statement injected into a request could delete a
version's job, mark it failed or running, or move its attempts, so the
version would wait uncompiled, or read as rules that do not compile, until
something queued it again, with no audit row.

## What

The request role loses INSERT, UPDATE and DELETE on the queue and keeps
SELECT, which a rule set's build status reads. A request queues a compile
through `lab.yara_compile_enqueue(version, engine, platform, fingerprint)`,
a definer that does what `RulesetService._queue` did as the writer: it
inserts the job, or sets an existing one back to QUEUED (one that is
RUNNING stays RUNNING) with its attempts reset after a failure. It queues
nothing for a version that does not exist, or for a key part outside 1 to
200 characters. A forged call can only queue a compile of a version that
exists, and the queue's key holds that to one job per version and build:
an extra compile, never a lost one.

The request paths are a version's upload, its activation and a build's
rejection (`RulesetService.add_version`, `queue_compile` and
`reject_build`, from `routers/lab_yara.py`). The static triage worker
claims, fails and deletes jobs on its system connection, unchanged, and
queues through the same function. `lab.yara_compiled_rejected`, which a
rejection also writes as the request role, keeps its INSERT: it is the next
residual (docs/17).

`RUNTIME_READ_ONLY_TABLES` declares the queue for
`test_app_role_privileges_pg.py` and `test_worker_role_privileges_pg.py`.
`PRIVILEGES_SQL` is repeatable and `scripts/runtime_roles.py ensure`
replays it after 0108's blanket grant. `FUNCTION_SQL` is frozen.

## No-op without the role; downgrade

The grants are guarded on `pg_roles` as 0179's are. The downgrade drops the
function and gives the three writes back.
"""
from alembic import op

revision = "0189"
down_revision = "0188"
branch_labels = None
depends_on = None

#: Read-only to the request role; `test_app_role_privileges_pg.py` reads
#: this constant from every migration after 0060.
RUNTIME_READ_ONLY_TABLES: tuple[str, ...] = ("lab.yara_compile_job",)

#: Frozen text.
FUNCTION_SQL = """
CREATE FUNCTION lab.yara_compile_enqueue(p_version uuid, p_engine text, p_platform text,
                                         p_fingerprint text) RETURNS void
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  INSERT INTO lab.yara_compile_job AS j (version_id, engine, platform, fingerprint)
  SELECT v.id, p_engine, p_platform, p_fingerprint
    FROM lab.yara_ruleset_version v
   WHERE v.id = p_version
     AND pg_catalog.length(p_engine) BETWEEN 1 AND 200
     AND pg_catalog.length(p_platform) BETWEEN 1 AND 200
     AND pg_catalog.length(p_fingerprint) BETWEEN 1 AND 200
  ON CONFLICT (version_id, engine, platform, fingerprint)
  DO UPDATE SET status = CASE WHEN j.status = 'RUNNING' THEN 'RUNNING' ELSE 'QUEUED' END,
                attempts = CASE WHEN j.status = 'FAILED' THEN 0 ELSE j.attempts END,
                updated_at = pg_catalog.now()
$$;

COMMENT ON FUNCTION lab.yara_compile_enqueue(uuid, text, text, text) IS
  'Queues a compile of an existing YARA rule set version for one build key, or sets its job '
  'back to QUEUED (0189): the compile queue is read-only to the request role.';

REVOKE ALL ON FUNCTION lab.yara_compile_enqueue(uuid, text, text, text) FROM PUBLIC;

DO $noc$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['noctornal_app', 'noctornal_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION '
                     'lab.yara_compile_enqueue(uuid, text, text, text) TO %I', r);
    END IF;
  END LOOP;
END
$noc$;
"""


def _block(verb: str, preposition: str) -> str:
    return f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'noctornal_app') THEN
    {verb} INSERT, UPDATE, DELETE ON lab.yara_compile_job {preposition} noctornal_app;
  END IF;
END
$noc$;
"""


#: Repeatable: `scripts/runtime_roles.py ensure` replays it.
PRIVILEGES_SQL = _block("REVOKE", "FROM")

DOWNGRADE_SQL = ("DROP FUNCTION lab.yara_compile_enqueue(uuid, text, text, text);\n"
                 + _block("GRANT", "TO"))


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(FUNCTION_SQL)
    run(PRIVILEGES_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
