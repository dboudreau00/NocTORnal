"""Wire the three orphan node types into the edge vocabulary.

TRANSACTION, DATASET and CREDENTIAL_SET were decided node types that no
edge could connect to (ontology review open question B). Resolved:
- TRANSACTION is a specific proven on-chain event (decision 22): wallets
  are its inputs/outputs (TX_INPUT / TX_OUTPUT), keeping the money graph
  two-mode. PAID stays the actor-level summary edge; the two coexist.
- DATASET / CREDENTIAL_SET can be held by an actor (CONTROLS) and carry
  breach provenance to a victim (EXFILTRATED_FROM).

All three new edges are structural (is_social_tie = false, sign 0): they
are two-mode / provenance plumbing, projected at analysis time, never a
direct social tie. Mirrored in packages/ontology and the reference seed.
"""
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

UPDATE edge_type
   SET dst_node_types = '{SELECTOR,WALLET,INFRA,SERVICE,CHANNEL,DATASET,CREDENTIAL_SET}'
 WHERE key = 'CONTROLS';

INSERT INTO edge_type (key, display_name, inverse_name, is_directed, default_sign, src_node_types, dst_node_types, is_social_tie) VALUES
('TX_INPUT',         'is an input to',      'has input',  true, 0, '{WALLET}','{TRANSACTION}',         false),
('TX_OUTPUT',        'is an output of',     'has output', true, 0, '{TRANSACTION}','{WALLET}',         false),
('EXFILTRATED_FROM', 'was exfiltrated from','source of',  true, 0, '{DATASET,CREDENTIAL_SET}','{VICTIM,ORGANISATION}', false)
ON CONFLICT (key) DO NOTHING;
""")


def downgrade() -> None:
    run("""
SET search_path = core, public;

DELETE FROM edge_type WHERE key IN ('TX_INPUT','TX_OUTPUT','EXFILTRATED_FROM');
UPDATE edge_type
   SET dst_node_types = '{SELECTOR,WALLET,INFRA,SERVICE,CHANNEL}'
 WHERE key = 'CONTROLS';
""")
