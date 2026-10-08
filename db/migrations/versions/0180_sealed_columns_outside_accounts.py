"""The request role reads no sealed column outside the accounts table
(sealed columns outside the accounts table, Beta 1.1, 2026-10-08).

## Why

0143 closed an account's credential columns to `noctornal_app`. The same
role, bound or not, could still read as ciphertext or as a keyed hash: a
persona's sealed credential and forum session
(`collect.collection_account.secret_ciphertext`, `session_ciphertext`), an
ingest key's HMAC (`ingest.api_key.secret_hmac`), a lookup provider's
sealed key (`ingest.provider.secret_ciphertext`), a download ticket's hash
(`lab.download_ticket.token_hash`) and, for any Lab reader, a sample's
sealed data key (`lab.sample.data_key_ciphertext`). No plaintext follows
without the key encryption keys or the pepper, which live in the process
environment, but a statement injected into a request had no business with
any of them.

## What

Each of those tables is read by column: every column it has when this
revision runs but the sealed ones (`SEALED`), discovered from the catalog
as 0143 does it. The API's own reads of them become:

- the length checks, as generated columns the request role may read:
  `collect.collection_account.secret_stored` (a credential is held: the
  persona list, the gate before a persona is used) and
  `lab.sample.data_key_destroyed` (a rejected sample's key was destroyed:
  every sample list, the download's and the retrieval's refusals, the
  sandbox card). A generated column, not a function, because a sample's
  answer is read in the `RETURNING` of the very statement that destroys the
  key, where a function would read the row as it was.
- `ingest.provider_secret(p_provider)`: the sealed key for an exempt caller
  (the lookups drain and the provider test on LOOKUPS, the readiness
  register on READINESS), NULL to the request role, which reads whether a
  key is held from `secret_key_id` (0098's `provider_secret_complete`
  pairs the two).
- `lab.spend_sample_ticket`, `lab.spend_production_ticket` and
  `lab.ticket_by_hash`: the two one-statement spends and the refusal's
  read, as the definer, keyed on the hash the caller computes from the
  ticket it presents. The request role's UPDATE of `redeemed_at` (0109)
  goes with them: nothing a request runs writes the table any more.
- `lab.sample_data_key(p_sample)`: the data key for an exempt caller (the
  static triage runner, the sandbox dispatch), for the sample origin on the
  sample its spent ticket names (within the ticket's five minutes, while
  `iam.rls_actor` binds its holder, an active account), and for a holder
  of `sample.download` or `sample.analyse` through a global role on a
  sample within their reach (`lab.sample`'s own policy, restated): the
  people who may handle the bytes, a session's download and a rejection's
  check of a held copy included. Every other Lab reader reads no key.
- An ingest key's HMAC is compared by `ingest.api_key_used` (0179).

EXECUTE on each function is taken from PUBLIC and given to the two runtime
roles. `PRIVILEGES_SQL` is idempotent; `scripts/runtime_roles.py ensure`
replays it after 0108's blanket grant.

## No-op without the role; downgrade

Guarded on `pg_roles` as 0143 is. The downgrade drops the functions and
the two generated columns, and gives table SELECT and 0109's UPDATE of
`redeemed_at` back.
"""
from alembic import op

revision = "0180"
down_revision = "0179"
branch_labels = None
depends_on = None

#: Never readable by the request role. `test_sealed_columns_pg.py` reads
#: this and asserts each is refused.
SEALED: dict[str, tuple[str, ...]] = {
    "collect.collection_account": ("secret_ciphertext", "session_ciphertext"),
    "ingest.api_key": ("secret_hmac",),
    "ingest.provider": ("secret_ciphertext",),
    "lab.download_ticket": ("token_hash",),
    "lab.sample": ("data_key_ciphertext",),
}

#: The tables whose request-role SELECT is by column. Read by
#: `test_app_role_privileges_pg.py` and `test_worker_role_privileges_pg.py`.
RUNTIME_COLUMN_SELECTS: dict[str, tuple[str, ...]] = {table: () for table in SEALED}

#: 0109 left the request role UPDATE of `redeemed_at`; the spends are
#: definers now, so it keeps none (`test_app_role_privileges_pg.py`).
RUNTIME_COLUMN_UPDATES: dict[str, tuple[str, ...]] = {"lab.download_ticket": ()}

FUNCTIONS = (
    "ingest.provider_secret(uuid)",
    "lab.spend_sample_ticket(bytea, uuid)",
    "lab.spend_production_ticket(bytea, uuid, text, uuid)",
    "lab.ticket_by_hash(bytea)",
    "lab.sample_data_key(uuid)",
)

#: Frozen text.
COLUMNS_SQL = """
ALTER TABLE collect.collection_account
  ADD COLUMN secret_stored boolean
  GENERATED ALWAYS AS (coalesce(octet_length(secret_ciphertext), 0) > 0) STORED;
COMMENT ON COLUMN collect.collection_account.secret_stored IS
  'Whether a credential is sealed for this persona, for the readers that may not see it (0180).';

ALTER TABLE lab.sample
  ADD COLUMN data_key_destroyed boolean
  GENERATED ALWAYS AS (octet_length(data_key_ciphertext) = 0) STORED;
COMMENT ON COLUMN lab.sample.data_key_destroyed IS
  'Whether the sample''s data key was destroyed with its bytes, for the readers that may not see it (0180).';
"""


def _by_column(table: str, sealed: tuple[str, ...]) -> str:
    names = ", ".join(f"'{c}'" for c in sealed)
    cols = ", ".join(sealed)
    return f"""
    SELECT string_agg(pg_catalog.quote_ident(a.attname), ', ' ORDER BY a.attnum)
      INTO readable
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = '{table}'::pg_catalog.regclass
       AND a.attnum > 0 AND NOT a.attisdropped
       AND a.attname NOT IN ({names});
    EXECUTE format('REVOKE SELECT ON {table} FROM %I', app);
    EXECUTE format('REVOKE SELECT ({cols}) ON {table} FROM %I', app);
    EXECUTE format('GRANT SELECT (%s) ON {table} TO %I', readable, app);"""


PRIVILEGES_SQL = """
DO $noc$
DECLARE
  app text := 'noctornal_app';
  readable text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN""" + "".join(
    _by_column(t, c) for t, c in SEALED.items()) + """
    EXECUTE format('REVOKE UPDATE (redeemed_at) ON lab.download_ticket FROM %I', app);
  END IF;
END
$noc$;
"""

#: Frozen text.
FUNCTION_SQL = """
CREATE FUNCTION ingest.provider_secret(p_provider uuid) RETURNS bytea
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT p.secret_ciphertext FROM ingest.provider p
   WHERE p.id = p_provider AND iam.rls_caller_exempt()
$$;

COMMENT ON FUNCTION ingest.provider_secret(uuid) IS
  'A lookup provider''s sealed key for an exempt caller (the drain, the provider test, the '
  'readiness register); NULL to the request role (0180).';

CREATE FUNCTION lab.spend_sample_ticket(p_token_hash bytea, p_sample uuid)
  RETURNS TABLE (id uuid, user_id uuid, session_id uuid, token_hash bytea, purpose text)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE lab.download_ticket t
     SET redeemed_at = pg_catalog.now()
   WHERE t.token_hash = p_token_hash
     AND t.sample_id = p_sample
     AND t.redeemed_at IS NULL
     AND t.expires_at > pg_catalog.now()
  RETURNING t.id, t.user_id, t.session_id, t.token_hash, t.purpose
$$;

COMMENT ON FUNCTION lab.spend_sample_ticket(bytea, uuid) IS
  'Spends a sample ticket in one statement, for the sample origin, which may not read a '
  'ticket''s hash (0180): samples.redeem_download_ticket.';

CREATE FUNCTION lab.spend_production_ticket(p_token_hash bytea, p_evidence uuid,
                                            p_purpose text, p_case uuid)
  RETURNS TABLE (id uuid, user_id uuid, session_id uuid, token_hash bytea,
                 issued_at timestamptz)
  LANGUAGE sql VOLATILE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  UPDATE lab.download_ticket t
     SET redeemed_at = pg_catalog.now()
   WHERE t.token_hash = p_token_hash
     AND t.evidence_id = p_evidence
     AND t.purpose = p_purpose
     AND t.redeemed_at IS NULL
     AND t.expires_at > pg_catalog.now()
     AND (SELECT f.case_id FROM iam.element_facts('evidence', p_evidence) f) = p_case
  RETURNING t.id, t.user_id, t.session_id, t.token_hash, t.issued_at
$$;

COMMENT ON FUNCTION lab.spend_production_ticket(bytea, uuid, text, uuid) IS
  'Spends an exhibit production ticket in one statement (0180): '
  'evidence.redeem_production_ticket.';

CREATE FUNCTION lab.ticket_by_hash(p_token_hash bytea)
  RETURNS TABLE (user_id uuid, sample_id uuid, evidence_id uuid,
                 redeemed_at timestamptz, expired boolean, evidence_case uuid)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT t.user_id, t.sample_id, t.evidence_id, t.redeemed_at,
         t.expires_at <= pg_catalog.now(),
         (SELECT f.case_id FROM iam.element_facts('evidence', t.evidence_id) f)
    FROM lab.download_ticket t
   WHERE t.token_hash = p_token_hash
$$;

COMMENT ON FUNCTION lab.ticket_by_hash(bytea) IS
  'Why a presented ticket matched no spend, for the refusal''s audit row (0180).';

CREATE FUNCTION lab.sample_data_key(p_sample uuid)
  RETURNS TABLE (data_key_ciphertext bytea, data_key_id text)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT s.data_key_ciphertext, s.data_key_id
    FROM lab.sample s
   WHERE s.id = p_sample
     AND (iam.rls_caller_exempt()
          OR EXISTS (
               SELECT 1 FROM lab.download_ticket t
                WHERE t.sample_id = s.id
                  AND t.token_hash = pg_catalog.sha256(pg_catalog.convert_to(
                        nullif(pg_catalog.current_setting('noctornal.rls_ticket', true), ''),
                        'UTF8'))
                  AND t.redeemed_at IS NOT NULL
                  AND t.redeemed_at > pg_catalog.now() - interval '5 minutes'
                  AND t.user_id = iam.rls_actor())
          OR ((iam.rls_holds_global('sample.download')
               OR iam.rls_holds_global('sample.analyse'))
              AND s.classification <= iam.rls_clearance()
              AND s.compartments OPERATOR(pg_catalog.<@) iam.rls_compartments()
              AND (s.case_id IS NULL
                   OR iam.rls_cases_in_reach() OPERATOR(pg_catalog.?) s.case_id::text)))
$$;

COMMENT ON FUNCTION lab.sample_data_key(uuid) IS
  'A sample''s sealed data key: for an exempt caller, for the sample origin on the sample '
  'its spent ticket names, and for a holder of sample.download or sample.analyse on a '
  'sample within their reach (0180).';
""" + "".join(
    f"\nREVOKE ALL ON FUNCTION {fn} FROM PUBLIC;" for fn in FUNCTIONS) + """

DO $noc$
DECLARE
  r text;
  fn text;
BEGIN
  FOREACH r IN ARRAY ARRAY['noctornal_app', 'noctornal_worker'] LOOP
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      FOREACH fn IN ARRAY ARRAY[""" + ", ".join(f"'{fn}'" for fn in FUNCTIONS) + """] LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I', fn, r);
      END LOOP;
    END IF;
  END LOOP;
END
$noc$;
"""


def _every_column(table: str) -> str:
    return f"""
    SELECT string_agg(pg_catalog.quote_ident(a.attname), ', ' ORDER BY a.attnum)
      INTO every
      FROM pg_catalog.pg_attribute a
     WHERE a.attrelid = '{table}'::pg_catalog.regclass
       AND a.attnum > 0 AND NOT a.attisdropped;
    EXECUTE format('REVOKE SELECT (%s) ON {table} FROM %I', every, app);
    EXECUTE format('GRANT SELECT ON {table} TO %I', app);"""


DOWNGRADE_SQL = "\n".join(f"DROP FUNCTION {fn};" for fn in reversed(FUNCTIONS)) + """

ALTER TABLE lab.sample DROP COLUMN data_key_destroyed;
ALTER TABLE collect.collection_account DROP COLUMN secret_stored;

DO $noc$
DECLARE
  app text := 'noctornal_app';
  every text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = app) THEN""" + "".join(
    _every_column(t) for t in SEALED) + """
    EXECUTE format('GRANT UPDATE (redeemed_at) ON lab.download_ticket TO %I', app);
  END IF;
END
$noc$;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(COLUMNS_SQL)
    run(PRIVILEGES_SQL)
    run(FUNCTION_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
