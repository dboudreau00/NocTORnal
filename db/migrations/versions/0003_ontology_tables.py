"""Ontology reference tables: node_type, edge_type, selector_type.

Extensible vocabularies are tables, not enums, so new types ship as rows
(design commitment 5 / decision 6).
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE TABLE node_type (
  key           text PRIMARY KEY,          -- 'IDENTITY','PERSON','GROUP',...
  display_name  text NOT NULL,
  category      text NOT NULL,             -- ACTOR | ARTEFACT | CONTEXT
  icon          text,
  colour_token  text,                      -- resolves against UI palette
  schema_json   jsonb NOT NULL DEFAULT '{}'::jsonb,  -- JSON Schema for attrs
  is_active     boolean NOT NULL DEFAULT true,
  sort_order    int NOT NULL DEFAULT 100
);

CREATE TABLE edge_type (
  key             text PRIMARY KEY,        -- 'MEMBER_OF','VOUCHED_FOR',...
  display_name    text NOT NULL,
  inverse_name    text,                    -- label when traversed backwards
  is_directed     boolean NOT NULL DEFAULT true,
  -- Signed-network semantics. +1 trust/affiliation, -1 distrust/conflict,
  -- 0 neutral/structural. Drives balance-theory analytics.
  default_sign    smallint NOT NULL DEFAULT 1 CHECK (default_sign IN (-1,0,1)),
  -- Which node types this edge may legally connect. Enforced in app +
  -- validated by a trigger; keeps the graph from turning to soup.
  src_node_types  text[] NOT NULL,
  dst_node_types  text[] NOT NULL,
  -- Whether this edge counts toward SNA metrics by default. Some edges
  -- (SAME_AS, ALIAS_OF) are identity plumbing, not social ties, and will
  -- wreck centrality if included.
  is_social_tie   boolean NOT NULL DEFAULT true,
  schema_json     jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_active       boolean NOT NULL DEFAULT true
);

-- Selector kinds are their own vocabulary because normalisation and
-- validation differ wildly per kind (see collect.selector_norm_rule).
CREATE TABLE selector_type (
  key             text PRIMARY KEY,        -- 'TELEGRAM_ID','BTC_ADDR',...
  display_name    text NOT NULL,
  -- Whether this selector is strong enough to merge identities on its own.
  -- PGP fingerprint: yes. Nickname: absolutely not.
  is_strong       boolean NOT NULL DEFAULT false,
  is_pii          boolean NOT NULL DEFAULT false,
  validator_regex text,
  normaliser      text,                    -- name of app-side normaliser fn
  is_active       boolean NOT NULL DEFAULT true
);
""")


def downgrade() -> None:
    run("""
DROP TABLE core.selector_type;
DROP TABLE core.edge_type;
DROP TABLE core.node_type;
""")
