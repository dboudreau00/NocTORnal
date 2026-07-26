"""Close what 0035's CHECK constraints could not, and one they missed.

An adversarial review broke `pgp.py` and it is worth being precise about
how, because it says what a constraint can and cannot do.

0035's docstring claimed its CHECKs made the two attribution traps
"unrepresentable". They did not, and could not. The attack forged a
`[GNUPG:] VALIDSIG <victim fingerprint>` line into the status stream by
hiding it in a crafted OpenPGP user ID: gpg does not escape bytes at or
above 0x80, and Python's `str.splitlines()` breaks on U+0085, U+2028 and
U+2029. The parser then read the forged line first and wrote BOTH
`signing_fingerprint` and `claimed_fingerprint` from the same lied-to
parse -- so they agreed, and
`pgp_verification_verified_matches_claim` passed.

**A constraint defends against the application forgetting to check. It
cannot defend against the application checking a forged input.** The real
fix is in `pgp.py` (parse bytes, split on b"\\n" only). What this migration
does is narrow what a row may claim, so the next parser defect has fewer
places to land.

## What is added

1. **`EXPIRED_SIGNATURE`.** gpg emits `EXPSIG` instead of `GOODSIG` when
   the SIGNATURE (not the key) has expired. Without its own outcome that
   fell through to "gpg did not report a good signature" -- failing
   closed, but labelling stale evidence as forged. 0035 already gave
   expired KEYS their own outcome for this exact reason.

2. **A VERIFIED row must carry its status output.** The column exists so a
   disputed verification can be re-read rather than re-argued; a VERIFIED
   row with nothing to re-read is the case where that matters most.

3. **A digest must be 32 bytes.** `signed_payload_sha256` accepted one
   byte. A column whose whole purpose is to let a later reader confirm
   which bytes verified should not accept something that cannot be a
   SHA-256.

4. **Composite foreign keys carry the case.** A verification could cite a
   `channel_binding` or `contact_block` belonging to a DIFFERENT case. The
   application checked the binding and (after this review) the block, but
   that is application logic again. `(id, case_id)` uniques let the FK
   itself carry the correlation, so the cross-case citation stops being
   representable.

5. **A VERIFIED row must confirm the binding's OWN identifier.** This is
   the check that actually ties a signature to the thing it upgrades, and
   it lived only in `verify_and_record` -- exactly the placement 0035's
   own docstring rejects. It is cross-row, so it needs a trigger rather
   than a CHECK. Without it a valid signature over selector A could be
   recorded as confirming a binding holding selector B.

The trigger is deliberately narrow: it fires only for `VERIFIED`, only
when a binding is named, and compares case-insensitively because durable
values are canonicalised but an actor's own rendering is not.
"""
from alembic import op

revision = "0037"
down_revision = "0036"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = comms, core, public;

-- 1. EXPIRED_SIGNATURE ------------------------------------------------
ALTER TABLE pgp_verification DROP CONSTRAINT pgp_verification_outcome_known;
ALTER TABLE pgp_verification ADD CONSTRAINT pgp_verification_outcome_known
  CHECK (outcome IN (
    'VERIFIED',
    'BAD_SIGNATURE',
    'KEY_MISMATCH',
    'VALUE_NOT_IN_PAYLOAD',
    'KEY_UNAVAILABLE',
    'EXPIRED_KEY',
    'REVOKED_KEY',
    -- The SIGNATURE expired, not the key. Distinct because "stale" and
    -- "forged" are different findings and only one of them is an
    -- accusation.
    'EXPIRED_SIGNATURE',
    'MALFORMED',
    'NO_VERIFIER'));

-- 2. A confirmation has to be re-readable -----------------------------
ALTER TABLE pgp_verification
  ADD CONSTRAINT pgp_verification_verified_is_re_readable
  CHECK (outcome <> 'VERIFIED' OR status_output IS NOT NULL);

-- 3. A digest is 32 bytes ---------------------------------------------
ALTER TABLE pgp_verification
  ADD CONSTRAINT pgp_verification_digest_is_sha256
  CHECK (signed_payload_sha256 IS NULL
         OR octet_length(signed_payload_sha256) = 32);

-- 4. Composite FKs, so the CASE travels with the reference -------------
ALTER TABLE channel_binding
  ADD CONSTRAINT channel_binding_id_case_key UNIQUE (id, case_id);
ALTER TABLE contact_block
  ADD CONSTRAINT contact_block_id_case_key UNIQUE (id, case_id);

ALTER TABLE pgp_verification
  ADD CONSTRAINT pgp_verification_binding_same_case
  FOREIGN KEY (channel_binding_id, case_id)
  REFERENCES channel_binding (id, case_id);
ALTER TABLE pgp_verification
  ADD CONSTRAINT pgp_verification_block_same_case
  FOREIGN KEY (contact_block_id, case_id)
  REFERENCES contact_block (id, case_id);
""")

    # 5. A VERIFIED row must confirm the binding's OWN identifier.
    run("""
CREATE FUNCTION comms.pgp_verification_confirms_its_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
  bound text;
BEGIN
  IF NEW.outcome <> 'VERIFIED' OR NEW.channel_binding_id IS NULL THEN
    RETURN NEW;
  END IF;
  SELECT durable_value INTO bound
    FROM comms.channel_binding WHERE id = NEW.channel_binding_id;
  -- A binding with no durable value has nothing a signature could
  -- confirm; upgrading it would assert control of an identifier this
  -- system has declined to index.
  IF bound IS NULL THEN
    RAISE EXCEPTION 'invariant: cannot confirm a binding that has no '
                    'durable value (verification %)', NEW.id;
  END IF;
  IF NEW.confirms_value IS NULL OR lower(NEW.confirms_value) <> lower(bound) THEN
    RAISE EXCEPTION 'invariant: a VERIFIED row must confirm the binding''s '
                    'own identifier -- signature covers %, binding holds %',
                    coalesce(NEW.confirms_value, '(null)'), bound;
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER pgp_verification_confirms_its_binding
  BEFORE INSERT OR UPDATE ON comms.pgp_verification
  FOR EACH ROW EXECUTE FUNCTION comms.pgp_verification_confirms_its_binding();
""")


def downgrade() -> None:
    run("""
DROP TRIGGER pgp_verification_confirms_its_binding ON comms.pgp_verification;
DROP FUNCTION comms.pgp_verification_confirms_its_binding();

ALTER TABLE comms.pgp_verification
  DROP CONSTRAINT pgp_verification_block_same_case;
ALTER TABLE comms.pgp_verification
  DROP CONSTRAINT pgp_verification_binding_same_case;
ALTER TABLE comms.contact_block DROP CONSTRAINT contact_block_id_case_key;
ALTER TABLE comms.channel_binding DROP CONSTRAINT channel_binding_id_case_key;

ALTER TABLE comms.pgp_verification
  DROP CONSTRAINT pgp_verification_digest_is_sha256;
ALTER TABLE comms.pgp_verification
  DROP CONSTRAINT pgp_verification_verified_is_re_readable;

ALTER TABLE comms.pgp_verification DROP CONSTRAINT pgp_verification_outcome_known;
ALTER TABLE comms.pgp_verification ADD CONSTRAINT pgp_verification_outcome_known
  CHECK (outcome IN (
    'VERIFIED', 'BAD_SIGNATURE', 'KEY_MISMATCH', 'VALUE_NOT_IN_PAYLOAD',
    'KEY_UNAVAILABLE', 'EXPIRED_KEY', 'REVOKED_KEY', 'MALFORMED',
    'NO_VERIFIER'));
""")
