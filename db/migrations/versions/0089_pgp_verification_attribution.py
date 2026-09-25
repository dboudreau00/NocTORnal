"""What a verification row must show when it stands behind a confirmation:
the key it cites, the link from that key to the binding's holder, and a
ledger nobody rewrites (F10b, 2026-09-24).

One concern: the verification row as the record that justifies a
CONFIRMED binding. A key citation, attribution and the ledger's own guard
are one rule seen from three sides, so they land together.

## What was wrong

- A guarantor's signed vouch ("vendor X's Tox is ABC"), checked with the
  GUARANTOR's key and naming X's binding, was VERIFIED and upgraded X's
  binding: nothing tied the claimed key to the binding's holder. That is
  the escrow error with a signature on it.
- A verification could not say it was made with a registry key whose
  fingerprint a person had confirmed against a publication (0088).
- The ledger that justifies a CONFIRMED binding kept full UPDATE and
  DELETE for the runtime role and had no guard: deleting a row left a
  CONFIRMED binding whose note cites a verification that no longer exists,
  and an UPDATE could rewrite the outcome or the attribution.

## What this adds

1. `pgp_key_id` (a registry key, same case by composite key),
   `claimed_fingerprint_basis` (STATED, typed at the check; or
   CONFIRMED_KEY, exactly when a key is cited) and
   `claimed_fingerprint_source_ref` (where a STATED fingerprint was
   published; never with a key, which carries its own provenance). A
   trigger holds that a cited key is confirmed, not retired when the row
   is written, and that the claim is its confirmed fingerprint.
2. `attribution` (SAME_BLOCK or SAME_IDENTITY), set only on a VERIFIED row
   naming a binding, and the outcome UNATTRIBUTED: a good signature by the
   claimed key over text naming the identifier, with no link from the key
   to the binding's holder. Its CHECK requires everything a VERIFIED row
   requires except that link.
3. `comms.pgp_verification_is_attributed()`: a VERIFIED row naming a
   binding cites a contact block within the binding's labels (and a cited
   key within them too), whose SELF PGP_FPR line lists the claimed or
   primary fingerprint, whose publisher is not a different entity from the
   binding's identity, and which ties the holder the way `attribution`
   says. The service applies the same rule (pgp.py), and this refuses a
   writer that skips it. Each refusal is one authored line (0059's reason:
   safe_detail forwards it).
4. The ledger's guard: UPDATE, DELETE and TRUNCATE are refused, and
   UPDATE and DELETE are revoked from the runtime role (`GUARDED_TABLES`).

Rows written before this revision stay valid: the new checks are one
directional (attribution NULL is allowed on an old VERIFIED row), and
docs/17 lists how to find the CONFIRMED bindings upgraded before it.

## Downgrade

Refuses while any row cites a key or is UNATTRIBUTED: the older schema
cannot hold either. Otherwise restores 0037's outcome list and drops the
new columns, constraints, triggers and functions, and gives the runtime
role back UPDATE and DELETE where it exists.
"""
from alembic import op

revision = "0089"
down_revision = "0088"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

#: The ledger keeps SELECT and INSERT for the runtime role.
GUARDED_TABLES = {
    "comms.pgp_verification": ("SELECT", "INSERT"),
}

#: 0037's list, restored by the downgrade.
OUTCOMES_0037 = ("VERIFIED", "BAD_SIGNATURE", "KEY_MISMATCH",
                 "VALUE_NOT_IN_PAYLOAD", "KEY_UNAVAILABLE", "EXPIRED_KEY",
                 "REVOKED_KEY", "EXPIRED_SIGNATURE", "MALFORMED",
                 "NO_VERIFIER")
OUTCOMES = OUTCOMES_0037 + ("UNATTRIBUTED",)


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def _outcome_check(outcomes: tuple[str, ...]) -> str:
    listed = ", ".join(f"'{o}'" for o in outcomes)
    return f"""
ALTER TABLE comms.pgp_verification DROP CONSTRAINT pgp_verification_outcome_known;
ALTER TABLE comms.pgp_verification ADD CONSTRAINT pgp_verification_outcome_known
  CHECK (outcome IN ({listed}));
"""


UPGRADE_SQL = """
ALTER TABLE comms.pgp_verification
  ADD COLUMN pgp_key_id uuid,
  ADD COLUMN claimed_fingerprint_basis text NOT NULL DEFAULT 'STATED',
  ADD COLUMN claimed_fingerprint_source_ref text,
  ADD COLUMN attribution text,
  ADD CONSTRAINT pgp_verification_basis_known
    CHECK (claimed_fingerprint_basis IN ('STATED', 'CONFIRMED_KEY')),
  ADD CONSTRAINT pgp_verification_basis_is_the_key
    CHECK ((claimed_fingerprint_basis = 'CONFIRMED_KEY') = (pgp_key_id IS NOT NULL)),
  ADD CONSTRAINT pgp_verification_source_ref_size
    CHECK (claimed_fingerprint_source_ref IS NULL
        OR length(claimed_fingerprint_source_ref) <= 2000),
  ADD CONSTRAINT pgp_verification_key_carries_its_provenance
    CHECK (pgp_key_id IS NULL OR claimed_fingerprint_source_ref IS NULL),
  ADD CONSTRAINT pgp_verification_key_same_case
    FOREIGN KEY (pgp_key_id, case_id) REFERENCES comms.pgp_key(id, case_id),
  ADD CONSTRAINT pgp_verification_attribution_known
    CHECK (attribution IS NULL OR attribution IN ('SAME_BLOCK', 'SAME_IDENTITY')),
  ADD CONSTRAINT pgp_verification_attribution_confirms_a_binding
    CHECK (attribution IS NULL
        OR (outcome = 'VERIFIED' AND channel_binding_id IS NOT NULL)),
  ADD CONSTRAINT pgp_verification_unattributed_is_otherwise_verified
    CHECK (outcome <> 'UNATTRIBUTED'
        OR (channel_binding_id IS NOT NULL
            AND confirms_value IS NOT NULL
            AND value_in_payload
            AND signed_payload_sha256 IS NOT NULL
            AND status_output IS NOT NULL
            AND signing_fingerprint IS NOT NULL
            AND (claimed_fingerprint = signing_fingerprint
                 OR claimed_fingerprint IS NOT DISTINCT FROM
                    signing_primary_fingerprint)));

CREATE INDEX pgp_verification_key_idx ON comms.pgp_verification (pgp_key_id)
  WHERE pgp_key_id IS NOT NULL;

CREATE FUNCTION comms.pgp_verification_cites_a_confirmed_key() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  confirmed text;
  retired timestamptz;
BEGIN
  IF NEW.pgp_key_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT confirmed_fingerprint, retired_at INTO confirmed, retired
    FROM comms.pgp_key WHERE id = NEW.pgp_key_id;
  IF confirmed IS NULL THEN
    RAISE EXCEPTION 'a check made with a registry key cites a key whose fingerprint was confirmed';
  END IF;
  IF retired IS NOT NULL THEN
    RAISE EXCEPTION 'a retired key is not used for a check';
  END IF;
  IF NEW.claimed_fingerprint <> confirmed THEN
    RAISE EXCEPTION 'a check made with a registry key claims that key''s confirmed fingerprint';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER pgp_verification_cites_a_confirmed_key
  BEFORE INSERT ON comms.pgp_verification
  FOR EACH ROW EXECUTE FUNCTION comms.pgp_verification_cites_a_confirmed_key();

CREATE FUNCTION comms.pgp_verification_is_attributed() RETURNS trigger
  LANGUAGE plpgsql AS $$
DECLARE
  cb_cls core.tlp;
  cb_comp text[];
  cb_identity uuid;
  cb_platform text;
  cb_durable text;
  b_cls core.tlp;
  b_comp text[];
  b_publisher uuid;
  a_cls core.tlp;
  a_comp text[];
BEGIN
  IF NEW.outcome <> 'VERIFIED' OR NEW.channel_binding_id IS NULL THEN
    RETURN NEW;
  END IF;
  IF NEW.contact_block_id IS NULL OR NEW.attribution IS NULL THEN
    RAISE EXCEPTION 'a check that confirms a binding cites the contact block that ties the key to the binding''s holder, and says how';
  END IF;
  SELECT classification, compartments, identity_node_id, platform_key,
         durable_value
    INTO cb_cls, cb_comp, cb_identity, cb_platform, cb_durable
    FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
  SELECT classification, compartments, publisher_identity_node_id
    INTO b_cls, b_comp, b_publisher
    FROM comms.contact_block WHERE id = NEW.contact_block_id;
  IF b_cls > cb_cls OR NOT (b_comp <@ cb_comp) THEN
    RAISE EXCEPTION 'the cited contact block is filed above the binding it would confirm';
  END IF;
  IF NEW.pgp_key_id IS NOT NULL THEN
    SELECT a.classification, a.compartments INTO a_cls, a_comp
      FROM comms.pgp_key k
      JOIN comms.pgp_key_acquisition a ON a.id = k.acquisition_id
     WHERE k.id = NEW.pgp_key_id;
    IF a_cls > cb_cls OR NOT (a_comp <@ cb_comp) THEN
      RAISE EXCEPTION 'the key is filed above the binding it would confirm';
    END IF;
  END IF;
  IF NOT EXISTS (
       SELECT 1 FROM comms.contact_block_entry e
        WHERE e.block_id = NEW.contact_block_id
          AND e.role = 'SELF' AND e.selector_type = 'PGP_FPR'
          AND comms.pgp_fingerprint_norm(e.durable_value)
              IN (NEW.claimed_fingerprint,
                  coalesce(NEW.signing_primary_fingerprint,
                           NEW.claimed_fingerprint))) THEN
    RAISE EXCEPTION 'the cited contact block does not list the claimed fingerprint as its publisher''s own';
  END IF;
  IF b_publisher IS NOT NULL AND cb_identity IS NOT NULL
     AND b_publisher <> cb_identity THEN
    RAISE EXCEPTION 'the cited contact block''s publisher and the binding''s identity are different entities';
  END IF;
  IF NEW.attribution = 'SAME_IDENTITY' THEN
    IF b_publisher IS NULL OR cb_identity IS NULL OR b_publisher <> cb_identity THEN
      RAISE EXCEPTION 'SAME_IDENTITY needs the block''s publisher to be the binding''s identity';
    END IF;
  ELSIF NOT EXISTS (
       SELECT 1 FROM comms.contact_block_entry e
        WHERE e.block_id = NEW.contact_block_id AND e.role = 'SELF'
          AND e.platform_key = cb_platform
          AND lower(e.durable_value) = lower(cb_durable)) THEN
    RAISE EXCEPTION 'SAME_BLOCK needs the cited contact block to list the binding''s identifier as its publisher''s own';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER pgp_verification_is_attributed
  BEFORE INSERT ON comms.pgp_verification
  FOR EACH ROW EXECUTE FUNCTION comms.pgp_verification_is_attributed();

CREATE FUNCTION comms.guard_pgp_verification() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'a verification is the record behind a confirmation; it is never rewritten or deleted';
END $$;

CREATE TRIGGER pgp_verification_guarded
  BEFORE UPDATE OR DELETE ON comms.pgp_verification
  FOR EACH ROW EXECUTE FUNCTION comms.guard_pgp_verification();
CREATE TRIGGER pgp_verification_no_truncate
  BEFORE TRUNCATE ON comms.pgp_verification
  FOR EACH STATEMENT EXECUTE FUNCTION comms.guard_pgp_verification();
"""

REVOKE_SQL = f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE UPDATE, DELETE ON comms.pgp_verification FROM %I',
                   '{APP_ROLE}');
  END IF;
END
$noc$;
"""

GRANT_BACK_SQL = f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('GRANT UPDATE, DELETE ON comms.pgp_verification TO %I',
                   '{APP_ROLE}');
  END IF;
END
$noc$;
"""

DOWNGRADE_SQL = """
DO $$
DECLARE
  n bigint;
BEGIN
  SELECT count(*) INTO n FROM comms.pgp_verification
   WHERE pgp_key_id IS NOT NULL OR outcome = 'UNATTRIBUTED';
  IF n > 0 THEN
    RAISE EXCEPTION 'refusing to downgrade 0089: % verification rows cite a registry key or are UNATTRIBUTED, which the older schema cannot hold. Find them with SELECT id FROM comms.pgp_verification WHERE pgp_key_id IS NOT NULL OR outcome = ''UNATTRIBUTED''', n;
  END IF;
END $$;

DROP TRIGGER pgp_verification_no_truncate ON comms.pgp_verification;
DROP TRIGGER pgp_verification_guarded ON comms.pgp_verification;
DROP FUNCTION comms.guard_pgp_verification();
DROP TRIGGER pgp_verification_is_attributed ON comms.pgp_verification;
DROP FUNCTION comms.pgp_verification_is_attributed();
DROP TRIGGER pgp_verification_cites_a_confirmed_key ON comms.pgp_verification;
DROP FUNCTION comms.pgp_verification_cites_a_confirmed_key();
DROP INDEX comms.pgp_verification_key_idx;
ALTER TABLE comms.pgp_verification
  DROP CONSTRAINT pgp_verification_unattributed_is_otherwise_verified,
  DROP CONSTRAINT pgp_verification_attribution_confirms_a_binding,
  DROP CONSTRAINT pgp_verification_attribution_known,
  DROP CONSTRAINT pgp_verification_key_same_case,
  DROP CONSTRAINT pgp_verification_key_carries_its_provenance,
  DROP CONSTRAINT pgp_verification_source_ref_size,
  DROP CONSTRAINT pgp_verification_basis_is_the_key,
  DROP CONSTRAINT pgp_verification_basis_known,
  DROP COLUMN attribution,
  DROP COLUMN claimed_fingerprint_source_ref,
  DROP COLUMN claimed_fingerprint_basis,
  DROP COLUMN pgp_key_id;
"""


def upgrade() -> None:
    run(UPGRADE_SQL + _outcome_check(OUTCOMES))
    run(REVOKE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL + _outcome_check(OUTCOMES_0037))
    run(GRANT_BACK_SQL)
