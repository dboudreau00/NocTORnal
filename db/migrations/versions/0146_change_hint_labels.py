"""The change hint names the labels of what changed, for the server only (http_ui-012, 2026-10-03).

## Why

0045's statement triggers announce every write to `core.node` and
`core.edge` as `{"case_id", "kind", "op"}`, and the live socket passed it
to every subscriber who may read the case. No content travels, but a RED
or compartmented node written in an AMBER case still woke the AMBER
analyst's console: a timing channel that says restricted activity happened
in this case, and when.

## What

`core.announce_change()` adds `labels` to the payload: the distinct
(classification, compartments) pairs a reader would have to hold to see
what the statement wrote, so `routers/live.py` can ask the access gate, per
delivery, whether the subscriber may read at least one of them, and drop
the hint otherwise. The labels never reach the client; the message the
socket sends is unchanged.

What a reader has to hold is not always the row's own labels:

- A tie is visible only when BOTH its endpoints are (`routers/read.py`
  `list_edges`), so a tie's pair is the join of its own labels and its two
  endpoints': the highest classification, the union of the compartments. An
  AMBER tie attached to a RED entity is a RED event.
- An UPDATE is announced under the labels the rows had AND the labels they
  now have, so a reclassification reaches the people who could see the
  element before (their view must change) and the people who can now.
  The two UPDATE triggers are recreated to reference both transition
  tables; 0045 gave them the new rows only.

The function is SECURITY DEFINER with a pinned search path, as 0113 does for
every trigger function that reads a policied table (`test_rls_registry_pg`
holds the rule): reading the endpoints as the writer would show an AMBER
writer no RED endpoint and the pair would be wrong exactly when it matters.
It reads labels only, and only for the rows the statement itself wrote.

A statement writing more than `MAX_LABEL_SETS` distinct pairs, or one whose
payload would pass `MAX_PAYLOAD_BYTES` (pg_notify refuses 8000 bytes and a
refusal would abort the write), announces `labels: null`, and the socket
drops a hint it cannot place: under-delivering a refetch is the safe
failure, an over-delivered one is the leak.

## Downgrade

Restores 0045's function text (as the invoker it was) and its UPDATE
triggers.
"""
from alembic import op

revision = "0146"
down_revision = "0145"
branch_labels = None
depends_on = None

MAX_LABEL_SETS = 32
MAX_PAYLOAD_BYTES = 7900

#: Frozen text.
UPGRADE_SQL = """
CREATE OR REPLACE FUNCTION core.announce_change() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  affected uuid;
  label_sets json;
  label_count integer := 0;
  unplaced boolean := false;
  payload text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    SELECT case_id INTO affected FROM oldrows LIMIT 1;
  ELSE
    SELECT case_id INTO affected FROM newrows LIMIT 1;
  END IF;
  IF affected IS NULL THEN
    RETURN NULL;
  END IF;

  IF TG_ARGV[0] = 'edge' THEN
    -- A tie is read only where both ends are: its pair is the join of its
    -- own labels and its endpoints'. The endpoints are read as the definer
    -- (this function runs as the owner), because a writer that cannot see an
    -- endpoint would otherwise leave the pair unknowable; a node row that is
    -- not there at all is not guessed at.
    IF TG_OP = 'DELETE' THEN
      SELECT coalesce(bool_or(s.id IS NULL OR t.id IS NULL), false) INTO unplaced
        FROM oldrows r
        LEFT JOIN core.node s ON s.id = r.src_node_id
        LEFT JOIN core.node t ON t.id = r.dst_node_id;
      SELECT count(*), json_agg(json_build_array(d.cls, d.comps))
        INTO label_count, label_sets
        FROM (SELECT DISTINCT
                     greatest(r.classification, s.classification, t.classification) AS cls,
                     ARRAY(SELECT DISTINCT c
                             FROM unnest(coalesce(r.compartments, '{}')
                                         || coalesce(s.compartments, '{}')
                                         || coalesce(t.compartments, '{}')) AS c
                            ORDER BY c) AS comps
                FROM oldrows r
                JOIN core.node s ON s.id = r.src_node_id
                JOIN core.node t ON t.id = r.dst_node_id
               LIMIT 33) d;
    ELSIF TG_OP = 'UPDATE' THEN
      SELECT coalesce(bool_or(s.id IS NULL OR t.id IS NULL), false) INTO unplaced
        FROM (SELECT src_node_id, dst_node_id FROM newrows
              UNION ALL SELECT src_node_id, dst_node_id FROM oldrows) r
        LEFT JOIN core.node s ON s.id = r.src_node_id
        LEFT JOIN core.node t ON t.id = r.dst_node_id;
      SELECT count(*), json_agg(json_build_array(d.cls, d.comps))
        INTO label_count, label_sets
        FROM (SELECT DISTINCT
                     greatest(r.classification, s.classification, t.classification) AS cls,
                     ARRAY(SELECT DISTINCT c
                             FROM unnest(coalesce(r.compartments, '{}')
                                         || coalesce(s.compartments, '{}')
                                         || coalesce(t.compartments, '{}')) AS c
                            ORDER BY c) AS comps
                FROM (SELECT classification, compartments, src_node_id, dst_node_id
                        FROM newrows
                      UNION ALL
                      SELECT classification, compartments, src_node_id, dst_node_id
                        FROM oldrows) r
                JOIN core.node s ON s.id = r.src_node_id
                JOIN core.node t ON t.id = r.dst_node_id
               LIMIT 33) d;
    ELSE
      SELECT coalesce(bool_or(s.id IS NULL OR t.id IS NULL), false) INTO unplaced
        FROM newrows r
        LEFT JOIN core.node s ON s.id = r.src_node_id
        LEFT JOIN core.node t ON t.id = r.dst_node_id;
      SELECT count(*), json_agg(json_build_array(d.cls, d.comps))
        INTO label_count, label_sets
        FROM (SELECT DISTINCT
                     greatest(r.classification, s.classification, t.classification) AS cls,
                     ARRAY(SELECT DISTINCT c
                             FROM unnest(coalesce(r.compartments, '{}')
                                         || coalesce(s.compartments, '{}')
                                         || coalesce(t.compartments, '{}')) AS c
                            ORDER BY c) AS comps
                FROM newrows r
                JOIN core.node s ON s.id = r.src_node_id
                JOIN core.node t ON t.id = r.dst_node_id
               LIMIT 33) d;
    END IF;
  ELSE
    IF TG_OP = 'DELETE' THEN
      SELECT count(*), json_agg(json_build_array(d.classification, d.compartments))
        INTO label_count, label_sets
        FROM (SELECT DISTINCT classification, compartments FROM oldrows LIMIT 33) d;
    ELSIF TG_OP = 'UPDATE' THEN
      SELECT count(*), json_agg(json_build_array(d.classification, d.compartments))
        INTO label_count, label_sets
        FROM (SELECT classification, compartments FROM newrows
              UNION SELECT classification, compartments FROM oldrows LIMIT 33) d;
    ELSE
      SELECT count(*), json_agg(json_build_array(d.classification, d.compartments))
        INTO label_count, label_sets
        FROM (SELECT DISTINCT classification, compartments FROM newrows LIMIT 33) d;
    END IF;
  END IF;

  IF unplaced OR label_count > 32 THEN
    label_sets := NULL;
  END IF;
  payload := json_build_object('case_id', affected, 'kind', TG_ARGV[0],
                               'op', TG_OP, 'labels', label_sets)::text;
  IF octet_length(payload) > 7900 THEN
    payload := json_build_object('case_id', affected, 'kind', TG_ARGV[0],
                                 'op', TG_OP, 'labels', NULL)::text;
  END IF;
  PERFORM pg_notify('noctornal_change', payload);
  RETURN NULL;
END
$$;

DROP TRIGGER node_announce_upd ON core.node;
CREATE TRIGGER node_announce_upd
  AFTER UPDATE ON core.node
  REFERENCING OLD TABLE AS oldrows NEW TABLE AS newrows
  FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('node');

DROP TRIGGER edge_announce_upd ON core.edge;
CREATE TRIGGER edge_announce_upd
  AFTER UPDATE ON core.edge
  REFERENCING OLD TABLE AS oldrows NEW TABLE AS newrows
  FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('edge');
"""

DOWNGRADE_SQL = """
DROP TRIGGER node_announce_upd ON core.node;
CREATE TRIGGER node_announce_upd
  AFTER UPDATE ON core.node
  REFERENCING NEW TABLE AS newrows
  FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('node');

DROP TRIGGER edge_announce_upd ON core.edge;
CREATE TRIGGER edge_announce_upd
  AFTER UPDATE ON core.edge
  REFERENCING NEW TABLE AS newrows
  FOR EACH STATEMENT EXECUTE FUNCTION core.announce_change('edge');

CREATE OR REPLACE FUNCTION core.announce_change() RETURNS trigger AS $$
DECLARE
  affected uuid;
BEGIN
  -- DELETE has no NEW TABLE, and an INSERT has no OLD TABLE, so
  -- each branch reads the one that exists. A statement that
  -- touched nothing announces nothing.
  IF TG_OP = 'DELETE' THEN
    SELECT case_id INTO affected FROM oldrows LIMIT 1;
  ELSE
    SELECT case_id INTO affected FROM newrows LIMIT 1;
  END IF;
  IF affected IS NULL THEN
    RETURN NULL;
  END IF;
  PERFORM pg_notify(
    'noctornal_change',
    json_build_object('case_id', affected,
                      'kind', TG_ARGV[0],
                      'op', TG_OP)::text);
  RETURN NULL;
END $$ LANGUAGE plpgsql;
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
