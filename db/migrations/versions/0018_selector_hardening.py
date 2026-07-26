"""Selector and edge-flag hardening from the ontology adversarial review.

Wrong-merge / missed-merge fixes (packages/ontology mirrors these):
- Normalisers: Telegram IDs keep their chat/user namespace, JIDs drop the
  per-session resourcepart, Session IDs case-fold as hex, MXID localparts
  stay case-sensitive, TLSH loses the T1 prefix, onions lose URL wrappers,
  IBAN-style accounts lose grouping, case-sensitive base58-ish values
  trim instead of byte-exact.
- Strength: FORUM_UID (unscoped, per-venue), PDB_PATH and CODESIGN_CN
  (attacker-controlled free text) must never auto-merge.
- is_social_tie: PARTICIPANT_IN, SAME_DEVICE_AS, CO_POSTED_IN and
  SHARED_INFRA are structural/bipartite plumbing; counting them as social
  ties double-counts or fabricates alliances in every centrality run.
- Validator: SAME_AS may no longer cross the IDENTITY/PERSON layer —
  attribution is exclusively ATTRIBUTED_TO (invariant 2).
"""
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

UPDATE selector_type SET normaliser = 'telegram_id_norm' WHERE key = 'TELEGRAM_ID';
UPDATE selector_type SET normaliser = 'jid_norm'          WHERE key = 'JABBER';
UPDATE selector_type SET normaliser = 'lower_hex'         WHERE key = 'SESSION_ID';
UPDATE selector_type SET normaliser = 'mxid_norm'         WHERE key = 'MATRIX_MXID';
UPDATE selector_type SET normaliser = 'tlsh_norm'         WHERE key = 'TLSH';
UPDATE selector_type SET normaliser = 'onion_norm'        WHERE key = 'ONION';
UPDATE selector_type SET normaliser = 'upper_nospace'     WHERE key = 'BANK_ACCT';
UPDATE selector_type SET normaliser = 'trim'
  WHERE key IN ('XMR_ADDR','TRON_ADDR','MATRIX_DEVKEY','BRIAR_LINK','SSDEEP');
UPDATE selector_type SET normaliser = 'trim', is_strong = false WHERE key = 'FORUM_UID';
UPDATE selector_type SET is_strong = false WHERE key IN ('PDB_PATH','CODESIGN_CN');

UPDATE edge_type SET is_social_tie = false
  WHERE key IN ('PARTICIPANT_IN','SAME_DEVICE_AS','CO_POSTED_IN');
UPDATE edge_type SET is_social_tie = false, default_sign = 0 WHERE key = 'SHARED_INFRA';

CREATE OR REPLACE FUNCTION core.validate_edge_endpoints() RETURNS trigger AS $$
DECLARE
  et      RECORD;
  src_ty  text;
  dst_ty  text;
BEGIN
  NEW.updated_at := now();
  -- Endpoints unchanged → nothing to re-validate. Without this, narrowing
  -- an edge_type's allowed endpoints later makes existing nonconforming
  -- edges un-updatable — including the soft delete that removes them.
  IF TG_OP = 'UPDATE' AND NEW.edge_type = OLD.edge_type
     AND NEW.src_node_id = OLD.src_node_id AND NEW.dst_node_id = OLD.dst_node_id
     AND NEW.case_id = OLD.case_id THEN
    RETURN NEW;
  END IF;
  SELECT * INTO et FROM core.edge_type WHERE key = NEW.edge_type;
  SELECT node_type INTO src_ty FROM core.node WHERE id = NEW.src_node_id;
  SELECT node_type INTO dst_ty FROM core.node WHERE id = NEW.dst_node_id;

  IF NOT (src_ty = ANY(et.src_node_types)) THEN
    RAISE EXCEPTION 'edge %: source node type % not permitted (allowed: %)',
      NEW.edge_type, src_ty, et.src_node_types;
  END IF;
  IF NOT (dst_ty = ANY(et.dst_node_types)) THEN
    RAISE EXCEPTION 'edge %: target node type % not permitted (allowed: %)',
      NEW.edge_type, dst_ty, et.dst_node_types;
  END IF;

  -- SAME_AS is unconfidenced identity-equivalence plumbing; letting it
  -- cross the IDENTITY/PERSON layer hard-codes an attribution as a fact.
  -- The cross-layer join is exclusively ATTRIBUTED_TO (invariant 2).
  IF NEW.edge_type = 'SAME_AS' AND src_ty <> dst_ty THEN
    RAISE EXCEPTION 'SAME_AS may not cross the IDENTITY/PERSON layer (attribution is ATTRIBUTED_TO)';
  END IF;

  -- Cross-case edges are never legitimate. Cross-case *pivoting* happens
  -- through selector matching and an access request, not by drawing an
  -- edge that would leak one case's structure into another.
  IF (SELECT case_id FROM core.node WHERE id = NEW.src_node_id) <> NEW.case_id
     OR (SELECT case_id FROM core.node WHERE id = NEW.dst_node_id) <> NEW.case_id THEN
    RAISE EXCEPTION 'edge % spans cases', NEW.edge_type;
  END IF;

  RETURN NEW;
END $$ LANGUAGE plpgsql;
""")


def downgrade() -> None:
    run("""
SET search_path = core, public;

UPDATE selector_type SET normaliser = 'digits'        WHERE key = 'TELEGRAM_ID';
UPDATE selector_type SET normaliser = 'lower_trim'    WHERE key = 'JABBER';
UPDATE selector_type SET normaliser = 'exact'         WHERE key = 'SESSION_ID';
UPDATE selector_type SET normaliser = 'lower_trim'    WHERE key = 'MATRIX_MXID';
UPDATE selector_type SET normaliser = 'upper_nospace' WHERE key = 'TLSH';
UPDATE selector_type SET normaliser = 'lower_trim'    WHERE key = 'ONION';
UPDATE selector_type SET normaliser = 'exact'
  WHERE key IN ('BANK_ACCT','XMR_ADDR','TRON_ADDR','MATRIX_DEVKEY','BRIAR_LINK','SSDEEP');
UPDATE selector_type SET normaliser = 'exact', is_strong = true WHERE key = 'FORUM_UID';
UPDATE selector_type SET is_strong = true WHERE key IN ('PDB_PATH','CODESIGN_CN');

UPDATE edge_type SET is_social_tie = true
  WHERE key IN ('PARTICIPANT_IN','SAME_DEVICE_AS','CO_POSTED_IN');
UPDATE edge_type SET is_social_tie = true, default_sign = 1 WHERE key = 'SHARED_INFRA';

CREATE OR REPLACE FUNCTION core.validate_edge_endpoints() RETURNS trigger AS $$
DECLARE
  et      RECORD;
  src_ty  text;
  dst_ty  text;
BEGIN
  NEW.updated_at := now();
  IF TG_OP = 'UPDATE' AND NEW.edge_type = OLD.edge_type
     AND NEW.src_node_id = OLD.src_node_id AND NEW.dst_node_id = OLD.dst_node_id
     AND NEW.case_id = OLD.case_id THEN
    RETURN NEW;
  END IF;
  SELECT * INTO et FROM core.edge_type WHERE key = NEW.edge_type;
  SELECT node_type INTO src_ty FROM core.node WHERE id = NEW.src_node_id;
  SELECT node_type INTO dst_ty FROM core.node WHERE id = NEW.dst_node_id;

  IF NOT (src_ty = ANY(et.src_node_types)) THEN
    RAISE EXCEPTION 'edge %: source node type % not permitted (allowed: %)',
      NEW.edge_type, src_ty, et.src_node_types;
  END IF;
  IF NOT (dst_ty = ANY(et.dst_node_types)) THEN
    RAISE EXCEPTION 'edge %: target node type % not permitted (allowed: %)',
      NEW.edge_type, dst_ty, et.dst_node_types;
  END IF;

  IF (SELECT case_id FROM core.node WHERE id = NEW.src_node_id) <> NEW.case_id
     OR (SELECT case_id FROM core.node WHERE id = NEW.dst_node_id) <> NEW.case_id THEN
    RAISE EXCEPTION 'edge % spans cases', NEW.edge_type;
  END IF;

  RETURN NEW;
END $$ LANGUAGE plpgsql;
""")
