"""Invariant 1 enforcement: no graph element without an assertion — at all
times, not just at creation.

CONVENTIONS.md invariant 1 / docs/01: "Nothing is a fact. Every node and edge
traces to at least one row in core.assertion." Enforced as a symmetric
pair of DEFERRABLE INITIALLY DEFERRED constraint triggers:

  1. AFTER INSERT on node/edge — the element must have >=1 assertion row
     by commit. Deferral lets the assertion (which FKs to the element) be
     written after it in the same transaction.
  2. AFTER DELETE OR UPDATE OF node_id/edge_id on assertion — removing or
     repointing the LAST assertion of a still-existing element is rejected.

Trigger 2 is what makes the guarantee steady-state and closes two paths
trigger 1 alone missed: `SET CONSTRAINTS ALL IMMEDIATE` (fire the insert
trigger early, then delete the assertion before commit) and a later
transaction deleting the assertion. Both now generate their own deferred
event on core.assertion that cannot be dodged.

WHAT IS ENFORCED: >=1 assertion ROW per node/edge, always. RETRACTION and
SUPERSEDE are row-preserving UPDATEs (of retracted_at / superseded_at, NOT
node_id/edge_id), so they do not fire trigger 2 — an element may lose all
its LIVE support and correctly dissolve from the live projection while its
row + history persist for temporal replay (docs/01 retraction
propagation). "At least one LIVE assertion" is therefore a projection
property, deliberately NOT write-enforced. A purge that hard-deletes an
element and its assertions in one transaction is fine: trigger 2 skips
when the referenced element no longer exists.

Out of scope (same threat model as the audit chain): a table owner can
ALTER TABLE ... DISABLE TRIGGER.
"""
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

-- Trigger 1: an inserted node/edge must have a supporting assertion.
CREATE OR REPLACE FUNCTION core.require_node_assertion() RETURNS trigger AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM core.node WHERE id = NEW.id) THEN
    RETURN NULL;                      -- removed within this same transaction
  END IF;
  IF NOT EXISTS (SELECT 1 FROM core.assertion WHERE node_id = NEW.id) THEN
    RAISE EXCEPTION
      'invariant 1: node % committed without a supporting assertion', NEW.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$ LANGUAGE plpgsql SET search_path = core, public;

CREATE OR REPLACE FUNCTION core.require_edge_assertion() RETURNS trigger AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM core.edge WHERE id = NEW.id) THEN
    RETURN NULL;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM core.assertion WHERE edge_id = NEW.id) THEN
    RAISE EXCEPTION
      'invariant 1: edge % committed without a supporting assertion', NEW.id
      USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$ LANGUAGE plpgsql SET search_path = core, public;

CREATE CONSTRAINT TRIGGER node_requires_assertion
  AFTER INSERT ON core.node
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION core.require_node_assertion();

CREATE CONSTRAINT TRIGGER edge_requires_assertion
  AFTER INSERT ON core.edge
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION core.require_edge_assertion();

-- Trigger 2: the last assertion of a still-existing element may not be
-- deleted or repointed away (retract/supersede instead). Fires only on
-- node_id/edge_id change or DELETE, so row-preserving retraction is free.
CREATE OR REPLACE FUNCTION core.assertion_protects_element() RETURNS trigger AS $$
BEGIN
  IF OLD.node_id IS NOT NULL
     AND EXISTS (SELECT 1 FROM core.node WHERE id = OLD.node_id)
     AND NOT EXISTS (SELECT 1 FROM core.assertion WHERE node_id = OLD.node_id) THEN
    RAISE EXCEPTION
      'invariant 1: last assertion for node % may not be removed (retract or supersede instead)',
      OLD.node_id USING ERRCODE = 'check_violation';
  END IF;
  IF OLD.edge_id IS NOT NULL
     AND EXISTS (SELECT 1 FROM core.edge WHERE id = OLD.edge_id)
     AND NOT EXISTS (SELECT 1 FROM core.assertion WHERE edge_id = OLD.edge_id) THEN
    RAISE EXCEPTION
      'invariant 1: last assertion for edge % may not be removed (retract or supersede instead)',
      OLD.edge_id USING ERRCODE = 'check_violation';
  END IF;
  RETURN NULL;
END $$ LANGUAGE plpgsql SET search_path = core, public;

CREATE CONSTRAINT TRIGGER assertion_protects_element
  AFTER DELETE OR UPDATE OF node_id, edge_id ON core.assertion
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION core.assertion_protects_element();
""")


def downgrade() -> None:
    run("""
DROP TRIGGER IF EXISTS assertion_protects_element ON core.assertion;
DROP FUNCTION IF EXISTS core.assertion_protects_element();
DROP TRIGGER IF EXISTS edge_requires_assertion ON core.edge;
DROP TRIGGER IF EXISTS node_requires_assertion ON core.node;
DROP FUNCTION IF EXISTS core.require_edge_assertion();
DROP FUNCTION IF EXISTS core.require_node_assertion();
""")
