"""Cross-schema foreign keys, added after all referenced tables exist.

User FKs are deliberately NOT ON DELETE CASCADE anywhere: users are
deactivated, never deleted, because their name is on the audit trail and
on the custody record.
"""
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

ALTER TABLE core.assertion
  ADD CONSTRAINT assertion_source_fk   FOREIGN KEY (source_id)   REFERENCES collect.source(id),
  ADD CONSTRAINT assertion_document_fk FOREIGN KEY (document_id) REFERENCES collect.document(id),
  ADD CONSTRAINT assertion_evidence_fk FOREIGN KEY (evidence_id) REFERENCES core.evidence(id);

ALTER TABLE core.evidence
  ADD CONSTRAINT evidence_collection_account_fk FOREIGN KEY (collection_account_id)
      REFERENCES collect.collection_account(id),
  ADD CONSTRAINT evidence_collection_run_fk FOREIGN KEY (collection_run_id)
      REFERENCES collect.collection_run(id);

ALTER TABLE core.tag_assignment
  ADD CONSTRAINT tag_assignment_document_fk FOREIGN KEY (document_id)
      REFERENCES collect.document(id) ON DELETE CASCADE;

ALTER TABLE collect.collection_account
  ADD CONSTRAINT collection_account_egress_fk FOREIGN KEY (egress_profile_id)
      REFERENCES collect.egress_profile(id);

-- User FKs. Deliberately NOT ON DELETE CASCADE anywhere: users are
-- deactivated, never deleted, because their name is on the audit trail
-- and on the custody record.
ALTER TABLE core."case"
  ADD CONSTRAINT case_owner_fk  FOREIGN KEY (owner_user_id)  REFERENCES iam.app_user(id),
  ADD CONSTRAINT case_deputy_fk FOREIGN KEY (deputy_user_id) REFERENCES iam.app_user(id);

ALTER TABLE core.node
  ADD CONSTRAINT node_created_by_fk FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

ALTER TABLE core.edge
  ADD CONSTRAINT edge_created_by_fk FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

ALTER TABLE core.assertion
  ADD CONSTRAINT assertion_created_by_fk FOREIGN KEY (created_by) REFERENCES iam.app_user(id);

ALTER TABLE core.evidence
  ADD CONSTRAINT evidence_acquired_by_fk FOREIGN KEY (acquired_by) REFERENCES iam.app_user(id);
""")


def downgrade() -> None:
    run("""
ALTER TABLE core.evidence DROP CONSTRAINT evidence_acquired_by_fk;
ALTER TABLE core.assertion DROP CONSTRAINT assertion_created_by_fk;
ALTER TABLE core.edge DROP CONSTRAINT edge_created_by_fk;
ALTER TABLE core.node DROP CONSTRAINT node_created_by_fk;
ALTER TABLE core."case" DROP CONSTRAINT case_deputy_fk, DROP CONSTRAINT case_owner_fk;
ALTER TABLE collect.collection_account DROP CONSTRAINT collection_account_egress_fk;
ALTER TABLE core.tag_assignment DROP CONSTRAINT tag_assignment_document_fk;
ALTER TABLE core.evidence
  DROP CONSTRAINT evidence_collection_run_fk,
  DROP CONSTRAINT evidence_collection_account_fk;
ALTER TABLE core.assertion
  DROP CONSTRAINT assertion_evidence_fk,
  DROP CONSTRAINT assertion_document_fk,
  DROP CONSTRAINT assertion_source_fk;
""")
