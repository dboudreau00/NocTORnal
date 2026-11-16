"""An ingest batch is created only by a caller that holds its key's secret,
and the batches are read-only to the request role
(the heartbeat and the queues, 2026-11-15).

## Why

0179 left `ingest.batch` writable by the request role: the unauthenticated
submit inserts a batch as that role after the key authenticates. One
statement injected into a request could therefore create a batch under any
key, so a partner would be named as the source of a payload it never sent,
or rewrite a batch's `raw_key` and `raw_sha256` so a re-parse read another
object as that partner's submission, or move a batch's state.

## What

The request role loses INSERT, UPDATE and DELETE on the batches and keeps
SELECT, which the ingest routes read. The submit creates its batch through
`ingest.batch_accept(key, hmac, idempotency, raw_key, raw_bytes,
raw_sha256, content_type, detected_format)`, a definer that inserts it only
when `hmac` is that key's stored HMAC (compared as sha256 of each side, as
`ingest.api_key_used` compares it, 0179), the key is neither revoked nor
expired, the length is within the key's `max_bytes_per_request`, and
`raw_key` is the content address of `raw_sha256`. It returns the batch's id,
or NULL when it refuses. A statement that does not hold a key's secret
cannot create a batch on it: the request role reads no key's HMAC (0180),
and an HMAC under a pepper the caller does not hold cannot be guessed.

`IngestService.authenticate` already computes the HMAC to check the secret;
it now keeps it on the authenticated key as an attribute that no
serialisation or copy of the key's settings carries, and `accept` hands it
to the function. A batch's parse, its state and a re-parse already run on
the INGEST system connection. `collect.collection_run`, the poll runs, keeps
the request role's writes: it is the next residual (docs/17).

`RUNTIME_READ_ONLY_TABLES` declares the table for
`test_app_role_privileges_pg.py` and `test_worker_role_privileges_pg.py`.
`PRIVILEGES_SQL` is repeatable and `scripts/runtime_roles.py ensure`
replays it after 0108's blanket grant. `FUNCTION_SQL` is frozen.

## No-op without the role; downgrade

The grants are guarded on `pg_roles` as 0179's are. The downgrade drops the
function and gives the three writes back.
"""
from alembic import op

revision = "0190"
down_revision = "0189"
branch_labels = None
depends_on = None

#: Read-only to the request role; `test_app_role_privileges_pg.py` reads
#: this constant from every migration after 0060.
RUNTIME_READ_ONLY_TABLES: tuple[str, ...] = ("ingest.batch",)

SIGNATURE = "ingest.batch_accept(uuid, bytea, text, text, bigint, bytea, text, text)"

#: Frozen text.
FUNCTION_SQL = f"""
CREATE FUNCTION ingest.batch_accept(p_key uuid, p_hmac bytea, p_idempotency text,
                                    p_raw_key text, p_raw_bytes bigint, p_raw_sha256 bytea,
                                    p_content_type text, p_detected_format text)
  RETURNS uuid
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  INSERT INTO ingest.batch (api_key_id, idempotency_key, raw_key, raw_bytes, raw_sha256,
                            content_type, detected_format)
  SELECT k.id, p_idempotency, p_raw_key, p_raw_bytes, p_raw_sha256, p_content_type,
         p_detected_format
    FROM ingest.api_key k
   WHERE k.id = p_key
     AND p_hmac IS NOT NULL
     AND pg_catalog.sha256(k.secret_hmac) = pg_catalog.sha256(p_hmac)
     AND k.revoked_at IS NULL
     AND k.expires_at > pg_catalog.now()
     AND p_raw_bytes BETWEEN 1 AND k.max_bytes_per_request
     AND pg_catalog.length(p_raw_sha256) = 32
     AND p_raw_key = 'ingest/'
                     || pg_catalog.substr(pg_catalog.encode(p_raw_sha256, 'hex'), 1, 2)
                     || '/' || pg_catalog.encode(p_raw_sha256, 'hex')
  RETURNING id
$$;

COMMENT ON FUNCTION {SIGNATURE} IS
  'Creates an ingest batch for a caller that presents its key''s secret''s HMAC, on a live key, '
  'within the key''s size and at the content address of its digest, and answers its id or NULL '
  '(0190): the batches are read-only to the request role.';

REVOKE ALL ON FUNCTION {SIGNATURE} FROM PUBLIC;

DO $noc$
DECLARE
  r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['noctornal_app', 'noctornal_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION {SIGNATURE} TO %I', r);
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
    {verb} INSERT, UPDATE, DELETE ON ingest.batch {preposition} noctornal_app;
  END IF;
END
$noc$;
"""


#: Repeatable: `scripts/runtime_roles.py ensure` replays it.
PRIVILEGES_SQL = _block("REVOKE", "FROM")

DOWNGRADE_SQL = f"DROP FUNCTION {SIGNATURE};\n" + _block("GRANT", "TO")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(FUNCTION_SQL)
    run(PRIVILEGES_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
