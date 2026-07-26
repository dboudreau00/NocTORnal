"""Phase 3 analytics: make metric_run able to hold a whole SNA run, and
make a cached run provably safe to serve.

0015 shipped projection / metric_run / node_metric / community_assignment
and nothing ever wrote them. Implementing the metric suite exposed four
gaps.

1. **Graph-level results have nowhere to live.** node_metric is per node,
   community_assignment is per node. Structural balance, unbalanced
   triads, cut vertices, bridges, component counts and the key-player
   removal set with its fragmentation preview are properties of the graph,
   not of a node. metric_run.result (jsonb) holds them.

2. **A failed run had nowhere to record why.** status defaulted to
   'RUNNING' and there was no error column, so a crashed run stayed
   'RUNNING' forever and read as "still working". Invariant 12 says
   nothing is silently dropped; metric_run.error plus a CHECKed status
   vocabulary means a failure is a fact you can query.

3. **Cache safety.** This is the important one. GraphService.project()
   filters by the CALLER's clearance and compartments, so the projected
   graph -- and therefore every metric computed from it -- differs between
   analysts. Serving an AMBER analyst a betweenness score computed over a
   graph that included RED nodes would leak the structure of nodes they
   may not see: a high betweenness with no visible explanation is exactly
   the inference the clearance model exists to prevent.

   The graph_hash is computed over the caller-VISIBLE edge list, so
   different visibility already yields a different hash and therefore a
   different cache entry. visibility_clearance / visibility_compartments
   record that scoping explicitly so the lookup can filter on it directly
   as well. Defence in depth: a hash collision, or a future change to how
   the hash is derived, still cannot cross a clearance boundary.

4. **Projections were not reusable.** metric_run references projection(id),
   but nothing identified the row for a given parameter set, so every run
   would have created another projection row. preset + params pin the
   remaining parameters (notably the trust-decay half-life, which changes
   every weight and therefore every number), and a unique (case_id, name)
   lets a run upsert its projection.
"""
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = analytics, core, public;

-- 4. Reusable, fully-parameterised projections ---------------------------
ALTER TABLE projection ADD COLUMN preset text;
ALTER TABLE projection ADD COLUMN params jsonb NOT NULL DEFAULT '{}'::jsonb;

-- A name identifies a parameter set within a case, so a run can upsert its
-- projection instead of accumulating a row per request. Deduplicate first:
-- nothing enforced this before, and the '__layout__' row is written by a
-- read-modify-write that could race.
DELETE FROM layout_position lp
 WHERE EXISTS (
   SELECT 1 FROM projection p
    WHERE p.id = lp.projection_id
      AND p.id <> (SELECT min(p2.id::text)::uuid FROM projection p2
                    WHERE p2.case_id = p.case_id AND p2.name = p.name));
DELETE FROM projection p
 WHERE p.id <> (SELECT min(p2.id::text)::uuid FROM projection p2
                 WHERE p2.case_id = p.case_id AND p2.name = p.name);
CREATE UNIQUE INDEX projection_case_name_uk ON projection (case_id, name);

-- 1 + 2. A run can carry graph-level results, and can fail out loud ------
ALTER TABLE metric_run ADD COLUMN result jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE metric_run ADD COLUMN error text;
ALTER TABLE metric_run ADD COLUMN created_by uuid;

-- status was free text defaulting to 'RUNNING'. Pin the vocabulary, and
-- require that a terminal state is self-consistent: FAILED explains
-- itself, COMPLETE does not carry an error.
ALTER TABLE metric_run ADD CONSTRAINT metric_run_status_ck
  CHECK (status IN ('RUNNING', 'COMPLETE', 'FAILED'));
ALTER TABLE metric_run ADD CONSTRAINT metric_run_failed_explains_itself_ck
  CHECK ((status = 'FAILED') = (error IS NOT NULL));

-- 3. Cache safety: a run is scoped to the visibility it was computed under.
--
-- BOTH columns end up NOT NULL with NO DEFAULT, and that is the whole
-- point. A default would fail OPEN: '{}' is exactly the value an analyst
-- holding no compartments searches for, so a run computed by someone read
-- into compartment ALPHA but persisted without setting this column would
-- become a cache hit for an analyst with no compartments -- serving them
-- metrics derived from ALPHA nodes they cannot see. That is precisely the
-- leak this column exists to close, reopened by its own default.
-- With no default, a writer that forgets is a loud insert failure.
--
-- Added nullable, then constrained, so this migration also applies to a
-- database where Phase 3 has already run. Any pre-existing run predates
-- the visibility columns and so has no recoverable visibility class --
-- and a cached metric whose visibility is UNKNOWN is exactly the thing
-- that must never be served. They are deleted rather than backfilled with
-- a guess: metric runs are a cache, every one of them is recomputable
-- from the graph, and inventing '{}' here would recreate the leak.
-- node_metric and community_assignment cascade.
ALTER TABLE metric_run ADD COLUMN visibility_clearance core.tlp;
ALTER TABLE metric_run ADD COLUMN visibility_compartments text[];

DELETE FROM metric_run WHERE visibility_clearance IS NULL;

ALTER TABLE metric_run ALTER COLUMN visibility_clearance SET NOT NULL;
ALTER TABLE metric_run ALTER COLUMN visibility_compartments SET NOT NULL;

-- The cache lookup: newest COMPLETE run for this projection + algorithm +
-- graph hash + visibility. Partial, because only COMPLETE runs are ever
-- served from cache.
CREATE INDEX metric_run_cache_idx
    ON metric_run (projection_id, algorithm, graph_hash,
                   visibility_clearance, started_at DESC)
 WHERE status = 'COMPLETE';
""")


def downgrade() -> None:
    run("""
SET search_path = analytics, core, public;

DROP INDEX IF EXISTS analytics.metric_run_cache_idx;
ALTER TABLE metric_run DROP COLUMN visibility_compartments;
ALTER TABLE metric_run DROP COLUMN visibility_clearance;
ALTER TABLE metric_run DROP CONSTRAINT metric_run_failed_explains_itself_ck;
ALTER TABLE metric_run DROP CONSTRAINT metric_run_status_ck;
ALTER TABLE metric_run DROP COLUMN created_by;
ALTER TABLE metric_run DROP COLUMN error;
ALTER TABLE metric_run DROP COLUMN result;

DROP INDEX IF EXISTS analytics.projection_case_name_uk;
ALTER TABLE projection DROP COLUMN params;
ALTER TABLE projection DROP COLUMN preset;
""")
