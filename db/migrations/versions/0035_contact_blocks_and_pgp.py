"""Phase 7 -- contact blocks, the service stoplist, and PGP verification.

docs/10 calls contact blocks "the highest-value extraction target" and then
immediately says why naive extraction of them is dangerous:

    Naive extraction across the whole post produces false links, because
    contact blocks routinely include third-party identifiers -- the forum's
    escrow agent, a guarantor, a partner shop. Attributing the escrow's
    Jabber to the vendor is a serious, and easy, error.

Three tables, each answering one half of that.

## `service_selector` -- the stoplist, and why it is GLOBAL by default

A forum's escrow agent is a property of the FORUM, not of a case. Scoping
the stoplist per case would mean every case rediscovers the same escrow
identifier by attributing it to a vendor first, which is precisely the
error the list exists to prevent -- so `scope = 'GLOBAL'` is the default
and `'CASE'` is the exception.

Entries are RETIRED, never deleted. A stoplist entry that turns out to be
wrong has already influenced parses that cite it, and deleting the row
would leave those citations dangling with no way to see what changed.

The stoplist matches on the DURABLE value, not the observed one. Matching
on the observed form would miss an escrow agent who rotated their Tox
nospam -- which is the same failure the normalisers exist to prevent,
arriving from the other direction.

## `contact_block` / `contact_block_entry` -- structure, not a bag of hits

docs/10's requirements list is four items and each is a column here:

- "Parse blocks as structured units with role labels where present" ->
  `entry.label` keeps the label EXACTLY as written, and `role` is the
  parser's reading of it.
- "Score selectors by their position and label within the block" ->
  `score` plus `score_reason`, because a bare 0.4 is exactly the "bare 0.87
  similarity" docs/03 says will be over-trusted or ignored.
- "Maintain a stoplist" -> `stoplist_id`.
- "Flag when a selector appears in many unrelated vendors' blocks" ->
  `shared_service_blocks`, counted at parse time and stamped with
  `shared_service_counted_at` because the count is a moving number and a
  stale one read as current is a wrong answer with a timestamp.

An entry the parser rejects is stored with its role and reason and is NOT
dropped (invariant 12). A silently-dropped line is how you find out six
months later that every block from one forum parsed to nothing.

## `pgp_verification` -- where the schema refuses the two classic traps

docs/10: "A message signed by a key whose fingerprint appears in the
contact block is real cryptographic evidence of control, not a claim."

Both halves of that sentence are load-bearing, and each has a trap:

**Trap 1 -- the wrong key.** A signature that verifies proves control of
whatever key signed it, which is only interesting if that key is the one
the actor CLAIMED. `verification_verified_matches_claim` makes a VERIFIED
row with `signing_fingerprint <> claimed_fingerprint` unrepresentable.

**Trap 2 -- the replayed message.** A valid signature over some other text
proves nothing about an identifier the submitter attached afterwards. Any
signed message from the real vendor could be replayed with an attacker's
Tox ID pasted below it. `verification_verified_covers_value` requires that
the identifier being confirmed appeared INSIDE the signed payload.

Neither is left to application code, because both are the kind of check
that survives review and then gets refactored away.

There is deliberately no `TRUSTED` outcome. GnuPG's web-of-trust model
answers "do I trust this key's owner", which is a different question from
"did this key sign this text", and only the second is evidence here.
"""
from alembic import op

revision = "0035"
down_revision = "0034"
branch_labels = None
depends_on = None

_NEW_PERMISSIONS = [
    ("comms.read", False, "See channels, conversations and contact blocks"),
    ("comms.bind", False, "Record a channel binding or parse a contact block"),
    # Minimisation destroys message bodies irreversibly. It is a
    # privacy-PROTECTIVE act and still needs step-up, because irreversible
    # is irreversible whichever direction it protects in.
    ("comms.minimise", True, "Drop message bodies, keeping the metadata graph"),
    # A stoplist entry changes attribution in every case that parses a block
    # afterwards. That reach is why it is a separate permission from
    # comms.bind rather than implied by it.
    ("comms.stoplist.manage", False,
     "Add or retire a known escrow/guarantor/admin identifier"),
]

# comms.read and comms.bind go to the case-side roles; the stoplist and
# minimisation do not. READ_ONLY gets read and nothing else.
_ROLE_GRANTS = [
    ("CASE_OWNER", "comms.read"), ("CASE_OWNER", "comms.bind"),
    ("CASE_OWNER", "comms.minimise"), ("CASE_OWNER", "comms.stoplist.manage"),
    ("ANALYST", "comms.read"), ("ANALYST", "comms.bind"),
    ("REVIEWER", "comms.read"), ("REVIEWER", "comms.bind"),
    ("REVIEWER", "comms.stoplist.manage"),
    ("CONTRIBUTOR", "comms.read"), ("CONTRIBUTOR", "comms.bind"),
    ("COLLECTOR", "comms.read"), ("COLLECTOR", "comms.bind"),
    ("READ_ONLY", "comms.read"),
    ("LIAISON", "comms.read"),
]


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = comms, core, public;

-- ------------------------------------------------------------------
-- The stoplist. docs/10: "Maintain a stoplist of known escrow, guarantor
-- and admin identifiers."
-- ------------------------------------------------------------------
CREATE TABLE service_selector (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- GLOBAL because a forum's escrow agent belongs to the forum. A per-case
  -- list would make every case rediscover it by getting the attribution
  -- wrong first.
  scope           text NOT NULL DEFAULT 'GLOBAL',
  case_id         uuid REFERENCES core."case"(id),
  -- Nullable, and mirroring contact_block_entry for the same reason: a
  -- forum's escrow agent is as likely to be listed by PGP fingerprint or
  -- BTC address as by chat platform, and neither of those has a
  -- comms.platform row. A stoplist that can only hold chat identifiers
  -- cannot stop the escrow's wallet being attributed to a vendor.
  platform_key    text REFERENCES platform(key),
  selector_type   text,
  -- Matched on the DURABLE value: an escrow agent who rotates their Tox
  -- nospam must not fall off the list.
  durable_value   text NOT NULL,
  observed_value  text NOT NULL,
  role            text NOT NULL,
  -- Which service. "Escrow" alone does not tell a later analyst whose.
  service_name    text,
  note            text NOT NULL DEFAULT '',
  added_by        uuid NOT NULL REFERENCES iam.app_user(id),
  added_at        timestamptz NOT NULL DEFAULT now(),
  -- Retired, never deleted: parses already cite this row, and a deleted
  -- row leaves them citing nothing.
  retired_at      timestamptz,
  retired_by      uuid REFERENCES iam.app_user(id),
  retired_reason  text,

  CONSTRAINT service_selector_scope_known CHECK (scope IN ('GLOBAL', 'CASE')),
  -- The two must agree in both directions: a GLOBAL entry with a case is a
  -- case entry nobody scoped, and a CASE entry without one is global by
  -- accident.
  CONSTRAINT service_selector_scope_matches_case
    CHECK ((scope = 'CASE') = (case_id IS NOT NULL)),
  CONSTRAINT service_selector_role_known CHECK (role IN (
    'ESCROW', 'GUARANTOR', 'ADMIN', 'MODERATOR', 'SUPPORT',
    'MARKET_STAFF', 'EXCHANGER', 'SHARED_SERVICE', 'OTHER')),
  -- An entry that names neither a platform nor a selector type cannot be
  -- matched against anything, so it would sit on the list looking like
  -- protection and provide none.
  CONSTRAINT service_selector_has_a_kind
    CHECK (platform_key IS NOT NULL OR selector_type IS NOT NULL),
  -- Retiring is a decision and decisions are attributable.
  CONSTRAINT service_selector_retirement_attributed
    CHECK (retired_at IS NULL OR (retired_by IS NOT NULL
                                  AND retired_reason IS NOT NULL))
);
-- PARTIAL indexes: a retired entry must not block re-adding the same
-- identifier, and the two scopes are independent lists.
--
-- coalesce, not the bare columns: now that platform_key and selector_type
-- are nullable, a plain unique index would let the SAME identifier be
-- added twice, because two NULLs never conflict in a unique index. The
-- duplicate would look like protection and provide it twice over.
CREATE UNIQUE INDEX service_selector_global_idx
  ON service_selector (coalesce(platform_key, ''), coalesce(selector_type, ''),
                       durable_value)
  WHERE scope = 'GLOBAL' AND retired_at IS NULL;
CREATE UNIQUE INDEX service_selector_case_idx
  ON service_selector (case_id, coalesce(platform_key, ''),
                       coalesce(selector_type, ''), durable_value)
  WHERE scope = 'CASE' AND retired_at IS NULL;
CREATE INDEX service_selector_lookup_idx
  ON service_selector (durable_value) WHERE retired_at IS NULL;

-- ------------------------------------------------------------------
-- A contact block as published, and its parse.
-- ------------------------------------------------------------------
CREATE TABLE contact_block (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  -- Who published it. An IDENTITY, never a PERSON (invariant 2). Nullable
  -- because a block is usually found before its publisher is resolved, and
  -- forcing a resolution here would manufacture identities.
  publisher_identity_node_id uuid REFERENCES core.node(id),
  publisher_handle text,
  -- Where it was seen. A block with no provenance is an unattributable
  -- claim, so this is NOT NULL.
  source_ref      text NOT NULL,
  document_id     uuid REFERENCES collect.document(id),
  evidence_id     uuid REFERENCES core.evidence(id),
  raw_text        text NOT NULL,
  raw_sha256      bytea NOT NULL,
  -- The IMPERSONATION detector. docs/10: "Scammers copy legitimate
  -- vendors' contact blocks wholesale. The same block under two handles
  -- means EITHER one operator OR one impersonating the other." This is a
  -- digest over the normalised SELECTOR SET, so it survives reformatting,
  -- reordering and cosmetic edits -- which is what a copier changes.
  block_fingerprint text NOT NULL,
  parser_version  text NOT NULL,
  classification  core.tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{}',
  created_by      uuid NOT NULL REFERENCES iam.app_user(id),
  created_at      timestamptz NOT NULL DEFAULT now(),

  -- The same artefact parsed twice is one row. Re-parsing under a new
  -- parser version is a deliberate act, not an accident of double-submit.
  UNIQUE (case_id, raw_sha256)
);
CREATE INDEX contact_block_case_idx ON contact_block (case_id, created_at DESC);
CREATE INDEX contact_block_publisher_idx ON contact_block (publisher_identity_node_id)
  WHERE publisher_identity_node_id IS NOT NULL;
-- The impersonation query: same fingerprint, different publisher.
CREATE INDEX contact_block_fingerprint_idx
  ON contact_block (block_fingerprint);

CREATE TABLE contact_block_entry (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  block_id        uuid NOT NULL REFERENCES contact_block(id) ON DELETE CASCADE,
  -- Position IS evidence: docs/10 says to score by position within the
  -- block, and a trailing "Escrow:" line reads differently from the first
  -- line.
  line_no         integer NOT NULL,
  -- EXACTLY as written. The parser's reading of it goes in `role`; keeping
  -- both means a wrong reading is visible rather than baked in.
  label           text,
  platform_key    text REFERENCES platform(key),
  -- The ontology selector type. A contact block is not only chat
  -- platforms: the PGP fingerprint, the BTC address and the onion mirror
  -- are the other half of it and have no comms.platform row. Recording
  -- the ontology type is what lets those reach core.selector, which is
  -- where cross-artefact correlation actually happens.
  selector_type   text,
  observed_value  text NOT NULL,
  durable_value   text,
  -- SELF: the parser reads this as the publisher's own.
  -- THIRD_PARTY: a label or the stoplist says it is somebody else's.
  -- UNPARSED: recognised as a line, not resolved to a platform. Kept
  --   rather than dropped -- invariant 12.
  role            text NOT NULL,
  -- Why. A score with no reason is the "bare 0.87" docs/03 warns about.
  role_reason     text NOT NULL,
  score           numeric(4, 3) NOT NULL,
  score_reason    text NOT NULL,
  stoplist_id     uuid REFERENCES service_selector(id),
  -- docs/10: "Flag when a selector appears in many unrelated vendors'
  -- blocks -- that is a shared service, not a shared identity."
  --
  -- PUBLISHERS, not blocks: one vendor who reposts their block in eight
  -- threads is one publisher, and counting blocks would call them a
  -- shared service. Distinct publishers is the number the threshold means.
  shared_service_publishers integer,
  -- The count moves. A stale one read as current is a wrong answer with a
  -- timestamp on it, so the timestamp is recorded too.
  shared_service_counted_at timestamptz,
  -- The proposal this entry raised, when it raised one. Machines propose
  -- (invariant 3): the parser NEVER writes comms.channel_binding.
  proposal_id     uuid REFERENCES collect.proposal(id),
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT contact_block_entry_role_known
    CHECK (role IN ('SELF', 'THIRD_PARTY', 'UNPARSED')),
  CONSTRAINT contact_block_entry_score_range
    CHECK (score >= 0 AND score <= 1),
  -- An UNPARSED entry does not pretend to know what it is.
  CONSTRAINT contact_block_entry_unparsed_has_no_kind
    CHECK (role <> 'UNPARSED'
           OR (platform_key IS NULL AND selector_type IS NULL)),
  -- ...and a SELF entry has to know at least one of the two: claiming a
  -- line is the publisher's own while being unable to say what kind of
  -- thing it is would be an attribution with no subject.
  --
  -- THIRD_PARTY is deliberately NOT held to this. `role` answers WHOSE
  -- and the kind columns answer WHAT, and they are independent questions:
  -- "Escrow: @forum_escrow" is a line whose owner is known exactly and
  -- whose type is genuinely ambiguous (@handle could be Telegram, Discord
  -- or a forum account). Forcing a kind there would make the parser guess
  -- at precisely the point it has decided not to.
  --
  -- SimpleX needs both halves of the OR: a real platform with no selector
  -- type at all. A PGP fingerprint is the mirror image.
  CONSTRAINT contact_block_entry_self_has_a_kind
    CHECK (role <> 'SELF'
           OR platform_key IS NOT NULL OR selector_type IS NOT NULL),
  -- If the stoplist is what made this third-party, it cannot be SELF.
  CONSTRAINT contact_block_entry_stoplisted_is_third_party
    CHECK (stoplist_id IS NULL OR role = 'THIRD_PARTY'),
  -- The count and its timestamp travel together or not at all.
  CONSTRAINT contact_block_entry_shared_count_dated
    CHECK ((shared_service_publishers IS NULL)
           = (shared_service_counted_at IS NULL)),
  UNIQUE (block_id, line_no)
);
CREATE INDEX contact_block_entry_block_idx ON contact_block_entry (block_id, line_no);
CREATE INDEX contact_block_entry_durable_idx
  ON contact_block_entry (platform_key, durable_value)
  WHERE durable_value IS NOT NULL;

-- ------------------------------------------------------------------
-- PGP verification. The CHECKs here are the point of the table.
-- ------------------------------------------------------------------
CREATE TABLE pgp_verification (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  -- What this verification is offered as evidence FOR. Nullable because a
  -- verification can be recorded before the binding it supports exists.
  channel_binding_id uuid REFERENCES channel_binding(id),
  contact_block_id uuid REFERENCES contact_block(id),
  -- The fingerprint the ACTOR published. Uppercase hex, no spaces.
  claimed_fingerprint text NOT NULL,
  -- The fingerprint that actually signed. NULL when nothing verified.
  signing_fingerprint text,
  -- The identifier this verification is asserted to confirm -- a Tox
  -- pubkey, a JID. Trap 2 below is about this value.
  confirms_value  text,
  -- Digest of the exact bytes that were signed, so a later reader can tell
  -- whether the payload they are looking at is the one that verified.
  signed_payload_sha256 bytea,
  -- Did `confirms_value` appear INSIDE the signed text?
  value_in_payload boolean NOT NULL DEFAULT false,
  outcome         text NOT NULL,
  verifier        text NOT NULL,
  verifier_version text,
  -- GnuPG's --status-fd output verbatim. The machine-readable lines are
  -- what was actually parsed, and keeping them means a disputed
  -- verification can be re-read rather than re-argued.
  status_output   text,
  note            text,
  verified_at     timestamptz NOT NULL DEFAULT now(),
  created_by      uuid NOT NULL REFERENCES iam.app_user(id),

  CONSTRAINT pgp_verification_outcome_known CHECK (outcome IN (
    'VERIFIED',              -- signed by the claimed key, over the value
    'BAD_SIGNATURE',         -- the signature did not verify
    'KEY_MISMATCH',          -- verified, but NOT by the claimed key
    'VALUE_NOT_IN_PAYLOAD',  -- verified, but the value was pasted outside
    'KEY_UNAVAILABLE',       -- no public key to check against
    'EXPIRED_KEY',
    'REVOKED_KEY',
    'MALFORMED',
    -- Not a failure of the evidence: a failure to look. Distinct so a
    -- queue of "nobody has checked these" is a query and not a guess.
    'NO_VERIFIER')),
  CONSTRAINT pgp_verification_verifier_known
    CHECK (verifier IN ('GPG', 'EXTERNAL', 'NONE')),
  -- TRAP 1: a signature proves control of whatever key signed it. If that
  -- is not the key the actor claimed, it is evidence about a stranger.
  CONSTRAINT pgp_verification_verified_matches_claim CHECK (
    outcome <> 'VERIFIED'
    OR (signing_fingerprint IS NOT NULL
        AND signing_fingerprint = claimed_fingerprint)),
  -- TRAP 2: any signed message from the real vendor can be replayed with
  -- somebody else's identifier pasted below it. A VERIFIED row asserts
  -- that the identifier was INSIDE the signed bytes.
  CONSTRAINT pgp_verification_verified_covers_value CHECK (
    outcome <> 'VERIFIED'
    OR (confirms_value IS NOT NULL AND value_in_payload
        AND signed_payload_sha256 IS NOT NULL)),
  -- Nothing verifies without a verifier. This closes the path where an
  -- absent gpg silently becomes a confirmation.
  CONSTRAINT pgp_verification_no_verifier_verifies_nothing CHECK (
    verifier <> 'NONE' OR outcome = 'NO_VERIFIER'),
  -- Uppercase hex, 40 (v4) or 64 (v5/v6) characters. A fingerprint with
  -- spaces left in would not match one without.
  CONSTRAINT pgp_verification_claimed_fp_shape
    CHECK (claimed_fingerprint ~ '^[0-9A-F]{40}$'
           OR claimed_fingerprint ~ '^[0-9A-F]{64}$'),
  CONSTRAINT pgp_verification_signing_fp_shape
    CHECK (signing_fingerprint IS NULL
           OR signing_fingerprint ~ '^[0-9A-F]{40}$'
           OR signing_fingerprint ~ '^[0-9A-F]{64}$')
);
CREATE INDEX pgp_verification_case_idx ON pgp_verification (case_id, verified_at DESC);
CREATE INDEX pgp_verification_binding_idx ON pgp_verification (channel_binding_id)
  WHERE channel_binding_id IS NOT NULL;
CREATE INDEX pgp_verification_claimed_idx ON pgp_verification (claimed_fingerprint);
""")

    perms = ",\n".join(
        f"('{k}', {str(s).lower()}, '{d}')" for k, s, d in _NEW_PERMISSIONS)
    grants = ",\n".join(f"('{r}', '{p}')" for r, p in _ROLE_GRANTS)
    run(f"""
SET search_path = iam, core, public;
INSERT INTO permission (key, requires_step_up, description) VALUES
{perms}
ON CONFLICT (key) DO NOTHING;

INSERT INTO role_permission (role_key, permission_key) VALUES
{grants}
ON CONFLICT (role_key, permission_key) DO NOTHING;
""")


def downgrade() -> None:
    keys = ",".join(f"'{k}'" for k, _, _ in _NEW_PERMISSIONS)
    run(f"""
DELETE FROM iam.role_permission WHERE permission_key IN ({keys});
DELETE FROM iam.permission WHERE key IN ({keys});

DROP TABLE comms.pgp_verification;
DROP TABLE comms.contact_block_entry;
DROP TABLE comms.contact_block;
DROP TABLE comms.service_selector;
""")
