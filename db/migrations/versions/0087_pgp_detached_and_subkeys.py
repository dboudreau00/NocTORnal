"""What a verification row records about the signature it checked (F10a,
comms, 2026-09-24).

## What was wrong

- Only clearsigned messages could be checked, so a vendor who publishes a
  detached signature beside a file could not be verified at all, and the
  row had nowhere to say which form was checked.
- `pgp.py` compared the claimed fingerprint with VALIDSIG's FIRST field,
  which is the key that made the signature: a subkey whenever the vendor
  signs with one. Vendors publish the PRIMARY fingerprint, so every
  genuine subkey signature was recorded as KEY_MISMATCH. It failed safe,
  and the reading was false. `pgp_verification_verified_matches_claim`
  encoded the same assumption (claimed = signing).

## What this adds

1. `signature_form` (CLEARSIGNED or DETACHED, default CLEARSIGNED, so every
   existing row reads as what it was).
2. `signing_primary_fingerprint`: VALIDSIG's last field, the primary the
   signing key is bound under. Shaped like every other fingerprint.
3. `signature_class`: the two hex digits of the signature class (00 over
   bytes, 01 over canonical text).
4. `pgp_verification_verified_matches_claim` re-stated so a VERIFIED row's
   claimed fingerprint may be the signing key OR its primary. `IS NOT
   DISTINCT FROM` is load-bearing: written as `IN (signing, primary)`, a
   NULL primary makes the whole expression NULL, a CHECK passes on NULL,
   and a mismatch would go through. test_pgp_detached_pg.py holds that
   case by name.

Existing rows satisfy every new constraint; nothing is backfilled from
the stored status output (a KEY_MISMATCH recorded before this for a
genuine subkey signature is re-verified, never edited: docs/17).

## Downgrade

Refuses while any row is DETACHED, or VERIFIED on its primary (claimed is
not the signing fingerprint): 0035's CHECK would reject those rows, and
dropping the column would lose which form was checked. The refusal names
the count and the query that finds them. Otherwise it drops the new
objects and restores 0035's CHECK.
"""
from alembic import op

revision = "0087"
down_revision = "0086"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


UPGRADE_SQL = """
ALTER TABLE comms.pgp_verification
  ADD COLUMN signature_form text NOT NULL DEFAULT 'CLEARSIGNED',
  ADD COLUMN signing_primary_fingerprint text,
  ADD COLUMN signature_class text,
  ADD CONSTRAINT pgp_verification_form_known
    CHECK (signature_form IN ('CLEARSIGNED', 'DETACHED')),
  ADD CONSTRAINT pgp_verification_primary_fp_shape
    CHECK (signing_primary_fingerprint IS NULL
        OR signing_primary_fingerprint ~ '^[0-9A-F]{40}$'
        OR signing_primary_fingerprint ~ '^[0-9A-F]{64}$'),
  ADD CONSTRAINT pgp_verification_sig_class_shape
    CHECK (signature_class IS NULL OR signature_class ~ '^[0-9a-f]{2}$');

ALTER TABLE comms.pgp_verification
  DROP CONSTRAINT pgp_verification_verified_matches_claim;
ALTER TABLE comms.pgp_verification
  ADD CONSTRAINT pgp_verification_verified_matches_claim
    CHECK (outcome <> 'VERIFIED'
        OR (signing_fingerprint IS NOT NULL
            AND (claimed_fingerprint = signing_fingerprint
                 OR claimed_fingerprint IS NOT DISTINCT FROM
                    signing_primary_fingerprint)));

COMMENT ON COLUMN comms.pgp_verification.signing_primary_fingerprint IS
  'The primary key the signing key is bound under (gpg VALIDSIG, last '
  'field). A claim may name the signing key or this primary (F10a).';
COMMENT ON COLUMN comms.pgp_verification.signature_form IS
  'CLEARSIGNED or DETACHED: which form of signature was checked (F10a).';
"""

DOWNGRADE_SQL = """
DO $$
DECLARE
  n bigint;
BEGIN
  SELECT count(*) INTO n FROM comms.pgp_verification
   WHERE signature_form = 'DETACHED'
      OR (outcome = 'VERIFIED' AND claimed_fingerprint <> signing_fingerprint);
  IF n > 0 THEN
    RAISE EXCEPTION 'refusing to downgrade 0087: % verification rows are DETACHED or were verified on the signing key''s primary, which the older schema cannot hold. Find them with SELECT id FROM comms.pgp_verification WHERE signature_form = ''DETACHED'' OR (outcome = ''VERIFIED'' AND claimed_fingerprint <> signing_fingerprint)', n;
  END IF;
END $$;

ALTER TABLE comms.pgp_verification
  DROP CONSTRAINT pgp_verification_verified_matches_claim;
ALTER TABLE comms.pgp_verification
  ADD CONSTRAINT pgp_verification_verified_matches_claim
    CHECK (outcome <> 'VERIFIED'
        OR (signing_fingerprint IS NOT NULL
            AND signing_fingerprint = claimed_fingerprint));

ALTER TABLE comms.pgp_verification
  DROP CONSTRAINT pgp_verification_sig_class_shape,
  DROP CONSTRAINT pgp_verification_primary_fp_shape,
  DROP CONSTRAINT pgp_verification_form_known,
  DROP COLUMN signature_class,
  DROP COLUMN signing_primary_fingerprint,
  DROP COLUMN signature_form;
"""


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
