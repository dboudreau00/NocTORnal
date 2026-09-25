"""Similarity spaces and their work queue (F6.1, embeddings, 2026-09-24).

## What this adds

1. `core.embedding_space`: one row per embedder fingerprint. Vectors are
   compared only inside one space, so a space is the unit a similarity
   index is built, activated, rebuilt and retired in. Two roles:
   WORDING (the built-in embedder in `embedders.py`, which runs in this
   process and sends nothing anywhere) and MEANING (an operator's model
   server, reached only through the `embeddings` integration route and
   off unless configured). Per role at most one ACTIVE and one BUILDING
   space, and three storage SLOTS, so an active WORDING space, an active
   MEANING space and one rebuild can coexist. A slot is held until the
   retired space's rows are cleared (`rows_cleared_at`).

   The identity of a space (role, slot, provider, model, fingerprint,
   canary, dimensions) never changes after registration: a new model is
   a new space, and the transition trigger refuses anything else, because
   a space whose fingerprint was edited in place would compare vectors
   from two models as if they were one. The state moves BUILDING to
   ACTIVE, BUILDING to RETIRED or ACTIVE to RETIRED, and RETIRED is final
   except for stamping `rows_cleared_at` once.

   The bookkeeping columns the pass writes: `model_mismatch_at` (MEANING:
   the model behind the endpoint no longer reproduces the canary),
   `gate_key` (MEANING: the gate configuration the WITHHELD rows were last
   judged under, so a raised ceiling or a new declaration re-judges them
   without scanning every row each pass), `enqueued_at` (every existing
   item has been queued for this space) and `canary_checked_at`,
   `canary_ok`, `canary_problem`
   (the last canary result, which readiness reads instead of sending one
   each time the register renders).

2. `core.embedding_pending`: the work queue, one row per (slot, kind,
   item) that has no vector row in that slot yet. It is filled by the
   triggers the next two migrations add (a new document, exhibit or
   claim; a relabel, edit or purge that deleted a vector row) and in bulk
   when a space registers, and the pass drains it. Before this, the pass
   found work by walking every document with a NOT EXISTS probe on every
   pass, which in steady state is a scan of the corpus every five minutes
   for nothing.

3. `embedding.manage` (global, step-up), granted to SYS_ADMIN: rebuild,
   activate or retire a similarity index, and run a pass from the
   console. Reading similarity needs nothing new.

## Downgrade

Deletes the grant and the permission and drops the queue, the trigger and
the table. Nothing here is primary material: vectors are derived from the
text they index, and the next pass after a re-upgrade registers a space
and embeds again (for a MEANING space that sends the eligible text to the
model endpoint again, audited as the first time).
"""
from __future__ import annotations

from alembic import op

revision = "0091"
down_revision = "0090"
branch_labels = None
depends_on = None


UPGRADE_SQL = """
CREATE TABLE core.embedding_space (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role text NOT NULL CHECK (role IN ('WORDING', 'MEANING')),
  state text NOT NULL CHECK (state IN ('BUILDING', 'ACTIVE', 'RETIRED')),
  slot smallint NOT NULL CHECK (slot BETWEEN 1 AND 3),
  provider text NOT NULL CHECK (provider IN ('builtin', 'endpoint')),
  model text NOT NULL CHECK (btrim(model) <> ''),
  fingerprint jsonb NOT NULL,
  fingerprint_sha256 bytea NOT NULL CHECK (length(fingerprint_sha256) = 32),
  dims_native integer NOT NULL CHECK (dims_native BETWEEN 1 AND 768),
  canary vector(768) NOT NULL,
  unicode_version text,
  registered_endpoint text,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid REFERENCES iam.app_user (id),
  activated_at timestamptz,
  activated_by uuid REFERENCES iam.app_user (id),
  retired_at timestamptz,
  retired_by uuid REFERENCES iam.app_user (id),
  retire_reason text,
  model_mismatch_at timestamptz,
  gate_key bytea,
  enqueued_at timestamptz,
  canary_checked_at timestamptz,
  canary_ok boolean,
  canary_problem text,
  rows_cleared_at timestamptz,
  UNIQUE (id, slot),
  CONSTRAINT embedding_space_active_dated
    CHECK (state <> 'ACTIVE' OR activated_at IS NOT NULL),
  CONSTRAINT embedding_space_retired_dated
    CHECK (state <> 'RETIRED' OR (retired_at IS NOT NULL AND retire_reason IS NOT NULL)),
  CONSTRAINT embedding_space_cleared_when_retired
    CHECK (rows_cleared_at IS NULL OR state = 'RETIRED'),
  CONSTRAINT embedding_space_endpoint_recorded
    CHECK ((provider = 'endpoint') = (registered_endpoint IS NOT NULL)),
  CONSTRAINT embedding_space_role_provider
    CHECK ((provider = 'endpoint') = (role = 'MEANING')),
  CONSTRAINT embedding_space_mismatch_endpoint_only
    CHECK (model_mismatch_at IS NULL OR provider = 'endpoint'),
  CONSTRAINT embedding_space_gate_endpoint_only
    CHECK (gate_key IS NULL OR provider = 'endpoint')
);

COMMENT ON TABLE core.embedding_space IS
  'One similarity space per embedder fingerprint (F6.1). Vectors are '
  'compared only inside one space. registered_endpoint is host:port at '
  'registration, history only: the live endpoint, ceiling and declarations '
  'are read from the environment, never from this row.';

CREATE UNIQUE INDEX embedding_space_one_active ON core.embedding_space (role)
  WHERE state = 'ACTIVE';
CREATE UNIQUE INDEX embedding_space_one_building ON core.embedding_space (role)
  WHERE state = 'BUILDING';
CREATE UNIQUE INDEX embedding_space_slot_held ON core.embedding_space (slot)
  WHERE rows_cleared_at IS NULL;

CREATE FUNCTION core.embedding_space_transition() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.id, NEW.role, NEW.slot, NEW.provider, NEW.model, NEW.fingerprint,
      NEW.fingerprint_sha256, NEW.dims_native, NEW.canary::text,
      NEW.unicode_version, NEW.registered_endpoint, NEW.created_at,
      NEW.created_by)
     IS DISTINCT FROM
     (OLD.id, OLD.role, OLD.slot, OLD.provider, OLD.model, OLD.fingerprint,
      OLD.fingerprint_sha256, OLD.dims_native, OLD.canary::text,
      OLD.unicode_version, OLD.registered_endpoint, OLD.created_at,
      OLD.created_by) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'an embedding space never changes what it is: register a new space '
      'for another model or setting';
  END IF;
  IF OLD.state = 'RETIRED' THEN
    IF (to_jsonb(NEW) - 'rows_cleared_at') IS DISTINCT FROM
       (to_jsonb(OLD) - 'rows_cleared_at')
       OR (OLD.rows_cleared_at IS NOT NULL
           AND NEW.rows_cleared_at IS DISTINCT FROM OLD.rows_cleared_at) THEN
      RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
        'a retired embedding space is final: only the moment its rows were '
        'cleared is recorded, once';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'BUILDING' AND NEW.state IN ('ACTIVE', 'RETIRED'))
    OR (OLD.state = 'ACTIVE' AND NEW.state = 'RETIRED')) THEN
    RAISE EXCEPTION USING ERRCODE = 'check_violation', MESSAGE =
      'an embedding space moves from building to active or retired, or from '
      'active to retired, and never back';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER embedding_space_transition
  BEFORE UPDATE ON core.embedding_space
  FOR EACH ROW EXECUTE FUNCTION core.embedding_space_transition();

CREATE TABLE core.embedding_pending (
  slot smallint NOT NULL CHECK (slot BETWEEN 1 AND 3),
  kind text NOT NULL CHECK (kind IN ('document', 'evidence', 'assertion')),
  item_id uuid NOT NULL,
  queued_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (slot, kind, item_id)
);

COMMENT ON TABLE core.embedding_pending IS
  'Items that have no vector row yet in a slot (F6.1). Filled by triggers '
  'on new and changed items and in bulk when a space registers; drained by '
  'scripts/embed_pass.py. No foreign key: one queue serves three kinds, and '
  'the pass drops an entry whose item is gone or purged.';

-- Queue an item for every space that is building or active. Called by the
-- item tables' triggers (the next two migrations); a slot with no space
-- queues nothing, so a deployment that never embeds pays one empty probe.
CREATE FUNCTION core.embedding_enqueue(p_kind text, p_item uuid) RETURNS void
LANGUAGE sql AS $$
  INSERT INTO core.embedding_pending (slot, kind, item_id)
  SELECT s.slot, p_kind, p_item FROM core.embedding_space s
   WHERE s.state IN ('BUILDING', 'ACTIVE')
  ON CONFLICT DO NOTHING;
$$;

INSERT INTO iam.permission (key, description, requires_step_up) VALUES
  ('embedding.manage',
   'Rebuild, activate or retire a similarity index, and run an embedding pass',
   true)
ON CONFLICT (key) DO NOTHING;

INSERT INTO iam.role_permission (role_key, permission_key) VALUES
  ('SYS_ADMIN', 'embedding.manage')
ON CONFLICT (role_key, permission_key) DO NOTHING;
"""

DOWNGRADE_SQL = """
DELETE FROM iam.role_permission WHERE permission_key = 'embedding.manage';
DELETE FROM iam.permission WHERE key = 'embedding.manage';
DROP FUNCTION core.embedding_enqueue(text, uuid);
DROP TABLE core.embedding_pending;
DROP TRIGGER embedding_space_transition ON core.embedding_space;
DROP FUNCTION core.embedding_space_transition();
DROP TABLE core.embedding_space;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
