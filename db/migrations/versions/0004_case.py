"""core."case" — the unit of access control and governance."""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE TABLE "case" (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code            text UNIQUE NOT NULL,     -- OP-KESTREL-24
  title           text NOT NULL,
  summary         text,
  status          case_status NOT NULL DEFAULT 'DRAFT',
  classification  tlp NOT NULL DEFAULT 'AMBER',
  -- Compartments are additive need-to-know locks on top of case access.
  compartments    text[] NOT NULL DEFAULT '{}',
  owner_user_id   uuid NOT NULL,
  deputy_user_id  uuid,
  -- Governance. Non-negotiable: a case with no lawful basis and no
  -- review date is a liability, so these are NOT NULL from day one.
  legal_basis     text NOT NULL,
  authority_ref   text,                     -- warrant / tasking / RIPA ref
  retention_until date NOT NULL,
  review_due      date NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  closed_at       timestamptz,
  -- AT TIME ZONE 'UTC' fixes the cast: a bare ::date follows the session
  -- TimeZone GUC and the constraint would mean different things per session.
  CONSTRAINT case_retention_sane CHECK (retention_until > (created_at AT TIME ZONE 'UTC')::date)
);

CREATE INDEX ON "case" (status) WHERE status IN ('ACTIVE','DORMANT');
CREATE INDEX ON "case" (review_due) WHERE status = 'ACTIVE';
""")


def downgrade() -> None:
    run("""
DROP TABLE core."case";
""")
