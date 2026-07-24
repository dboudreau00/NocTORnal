"""The provenance spine: assertion, hypothesis, hypothesis_evidence.

Every node attribute and every edge traces to >=1 assertion (invariant 1).
Cross-schema FKs (source/document) arrive in 0014.
"""
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE TABLE assertion (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES "case"(id),
  -- Subject of the claim: exactly one of these.
  node_id         uuid REFERENCES node(id),
  edge_id         uuid REFERENCES edge(id),
  claim_path      text,                     -- e.g. 'attrs.role' when node-scoped
  claim_value     jsonb,
  basis           assertion_basis NOT NULL,
  reliability     source_reliability NOT NULL DEFAULT 'F',
  credibility     info_credibility  NOT NULL DEFAULT '6',
  confidence      analytic_confidence NOT NULL DEFAULT 'LOW',
  -- Provenance chain
  source_id       uuid,                     -- collect.source
  document_id     uuid,                     -- collect.document
  evidence_id     uuid,                     -- core.evidence
  external_ref    text,                     -- vendor report id, court ref
  -- Analyst rationale is mandatory for inference-based claims — this is
  -- what makes the graph defensible later.
  rationale       text,
  -- Bitemporal
  observed_at     timestamptz,              -- when the fact was true
  recorded_at     timestamptz NOT NULL DEFAULT now(),
  superseded_at   timestamptz,
  superseded_by   uuid REFERENCES assertion(id),
  retracted_at    timestamptz,
  retracted_by    uuid,
  retraction_reason text,
  created_by      uuid NOT NULL,
  CONSTRAINT assertion_one_subject CHECK (num_nonnulls(node_id, edge_id) = 1),
  CONSTRAINT assertion_inference_needs_rationale
    CHECK (basis NOT IN ('ANALYST_INFERENCE','AUTOMATED_INFERENCE') OR rationale IS NOT NULL)
);

CREATE INDEX ON assertion (node_id) WHERE retracted_at IS NULL AND superseded_at IS NULL;
CREATE INDEX ON assertion (edge_id) WHERE retracted_at IS NULL AND superseded_at IS NULL;
CREATE INDEX ON assertion (source_id);
CREATE INDEX ON assertion (document_id);

-- Competing hypotheses. ACH is how you stop the graph becoming a
-- monument to the first theory someone had.
CREATE TABLE hypothesis (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id      uuid NOT NULL REFERENCES "case"(id),
  statement    text NOT NULL,
  confidence   analytic_confidence NOT NULL DEFAULT 'LOW',
  status       review_state NOT NULL DEFAULT 'PROPOSED',
  created_by   uuid NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hypothesis_evidence (
  hypothesis_id uuid NOT NULL REFERENCES hypothesis(id) ON DELETE CASCADE,
  assertion_id  uuid NOT NULL REFERENCES assertion(id),
  -- Diagnosticity: does this evidence discriminate between hypotheses?
  stance        smallint NOT NULL CHECK (stance IN (-2,-1,0,1,2)),
  note          text,
  PRIMARY KEY (hypothesis_id, assertion_id)
);
""")


def downgrade() -> None:
    run("""
DROP TABLE core.hypothesis_evidence;
DROP TABLE core.hypothesis;
DROP TABLE core.assertion;
""")
