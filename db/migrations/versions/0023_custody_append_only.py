"""Evidence custody ledger is append-only.

The custody ledger (core.evidence_custody) is where "who acquired, viewed,
exported, or hash-verified this exhibit, and when" lives. For the evidence
to survive a challenge (US FRE 902(13)-(14); Canada Evidence Act
ss. 31.1-31.8), that record must be tamper-evident: no code path, admin
tool or migration may UPDATE or DELETE a custody row. Same posture as the
audit chain (invariant 6). A superuser can still drop the trigger — that
is the out-of-scope threat model, identical to audit.event.
"""
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE FUNCTION core.block_custody_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'evidence_custody is append-only (chain of custody)';
END $$ LANGUAGE plpgsql;

CREATE TRIGGER evidence_custody_append_only
  BEFORE UPDATE OR DELETE ON core.evidence_custody
  FOR EACH ROW EXECUTE FUNCTION core.block_custody_mutation();
CREATE TRIGGER evidence_custody_no_truncate
  BEFORE TRUNCATE ON core.evidence_custody
  FOR EACH STATEMENT EXECUTE FUNCTION core.block_custody_mutation();
""")


def downgrade() -> None:
    run("""
DROP TRIGGER IF EXISTS evidence_custody_no_truncate ON core.evidence_custody;
DROP TRIGGER IF EXISTS evidence_custody_append_only ON core.evidence_custody;
DROP FUNCTION IF EXISTS core.block_custody_mutation();
""")
