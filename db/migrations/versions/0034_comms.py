"""Phase 7 -- communication channels, message-level capture (docs/10).

Decision 35 chose message-level capture over metadata-only. Metadata would
have been cheaper, but content is what a disclosure obligation and a
prosecution turn on, and a channel that has since been deleted cannot be
re-captured. The accepted costs are that storage scales with traffic rather
than with the number of parties, that every captured message is personal
data inside the retention and minimisation regime, and that the Phase 5
egress gate stops being advisory.

**docs/16 L4 is the BLOCKING entry this phase creates**: interception law,
one-party vs two-party consent, and the retention of uninvolved third
parties' content in a group channel. `conversation.provenance_class` is NOT
NULL so the distinction between "our persona was a party to this" and "we
obtained it another way" is always recorded -- but recording it is not the
same as having the authority.

## The durable-selector column is the point of this migration

docs/10:

    Read the "durable selector" column carefully. Getting this wrong is the
    single biggest source of false attribution in this domain.

`comms.platform.durable_selector_type` encodes, per platform, which
identifier is stable. Three of them are traps:

- **Tox.** A Tox ID is 76 hex: a 32-byte public key, 4 bytes of nospam and a
  2-byte checksum. The nospam is user-changeable at will, and actors change
  it specifically to shed unwanted contacts. Index the first 64 hex -- the
  public key. A tool that keys on the whole ID silently fails to correlate
  the same actor afterwards, and silently is the problem.
- **Telegram.** The numeric user ID, never `@username`: usernames are
  recycled, so a match on one can attribute a new person's traffic to an
  old investigation.
- **SimpleX.** No persistent identifier exists at all. Modelled as a channel
  with no selector rather than pretended otherwise, because an absence of
  data must not read as an absence of activity.

## OMEMO fingerprints are DEVICE selectors, not account ones

docs/10: two different JIDs publishing the same device fingerprint is the
same physical device -- "a far stronger link than a shared nickname and it
is almost never collected". They are modelled against a `DEVICE` node so one
device can link several personas WITHOUT collapsing them, which is exactly
the IDENTITY-vs-PERSON distinction (invariant 2) applied one level down.

## CLAIMED is not CONFIRMED

An identifier an actor advertises in a signature block is a claim. An
identifier observed in use, or verified by a PGP signature over it, is
something else. `channel_binding.verification` keeps them apart, because
treating a claim as a confirmation is how a rival's Jabber ID ends up
attributed to the person who posted it as an insult.
"""
from alembic import op

revision = "0034"
down_revision = "0033"
branch_labels = None
depends_on = None

# (key, display, durable_selector_type, displayed_id, note)
# The `note` is not decoration: it is what an analyst reads when deciding
# whether an identifier means what they think it means.
_PLATFORMS = [
    ("SESSION", "Session", "SESSION_ID", "66-hex Session ID (05...)",
     "The Session ID IS an X25519 public key. No central history; local "
     "SQLCipher DB on seized devices, and open-group servers hold room "
     "history."),
    ("TOX", "Tox / qTox", "TOX_PUBKEY", "76-hex Tox ID",
     "INDEX THE FIRST 64 HEX ONLY -- the public key. The trailing nospam is "
     "user-rotatable and actors change it to shed contacts; keying on the "
     "full 76 silently fails to correlate the same actor afterwards."),
    ("XMPP", "XMPP / Jabber", "JID", "local@domain/resource",
     "The resourcepart is dropped: it is per-connection. OMEMO device "
     "fingerprints are a SEPARATE, stronger selector against a DEVICE node."),
    ("MATRIX", "Matrix", "MXID", "@user:server.tld",
     "MXID plus device keys plus the cross-signing master key. Federated, so "
     "the homeserver operator matters and room state is widely replicated."),
    ("SIGNAL", "Signal", "SIGNAL_ACI", "phone number or username",
     "The ACI (account identifier UUID) is durable; the phone number is not. "
     "Service returns essentially nothing: registration date, last connect."),
    ("SIMPLEX", "SimpleX", None, "none by design",
     "NO PERSISTENT IDENTIFIER EXISTS. Connections are one-time queue links. "
     "Coverage against a SimpleX user is inherently poor and the interface "
     "must say so -- an absence of data is not an absence of activity."),
    ("THREEMA", "Threema", "THREEMA_ID", "8-character Threema ID",
     "Swiss, minimal retention."),
    ("BRIAR", "Briar", "BRIAR_PUBKEY", "contact link",
     "P2P over Tor, no server at all."),
    ("WIRE", "Wire", "WIRE_UUID", "@handle",
     "Account UUID is durable; the handle is not. MLS protocol; on-prem "
     "deployments exist."),
    ("TELEGRAM", "Telegram", "TELEGRAM_UID", "@username",
     "THE NUMERIC USER ID, NEVER @username. Usernames are recycled, so a "
     "match on one can attribute a new person's traffic to an old case."),
    ("DISCORD", "Discord", "DISCORD_SNOWFLAKE", "handle",
     "Snowflake ID. Common in lower-tier and marketplace activity."),
    ("ICQ", "ICQ", "ICQ_UIN", "UIN",
     "Service closed June 2024. Historical value only, but old threads are "
     "full of them."),
    ("WICKR", "Wickr", "WICKR_ID", "Wickr ID",
     "Consumer service shut down 2023. Historical."),
    ("SKYPE", "Skype", "SKYPE_NAME", "live:...",
     "Legacy; appears in old artefacts."),
    ("FORUM_PM", "Forum private message", "FORUM_UID", "forum handle",
     "On-site messaging. The forum UID is durable; the display name is not."),
]


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE SCHEMA IF NOT EXISTS comms;
SET search_path = comms, core, public;

CREATE TABLE platform (
  key             text PRIMARY KEY,
  display_name    text NOT NULL,
  -- WHICH identifier is stable. NULL means the platform genuinely has none
  -- (SimpleX), which is a fact worth modelling rather than a gap to fill.
  durable_selector_type text,
  displayed_id    text NOT NULL,
  -- What an analyst reads when deciding whether an identifier means what
  -- they think it means. docs/10: getting this wrong is the single biggest
  -- source of false attribution in this domain.
  note            text NOT NULL,
  is_active       boolean NOT NULL DEFAULT true
);

-- An identifier observed for a platform, bound to an identity.
CREATE TABLE channel_binding (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  platform_key    text NOT NULL REFERENCES platform(key),
  -- The identity this identifier belongs to. An IDENTITY, never a PERSON:
  -- a handle is not a person (invariant 2), and a channel is a handle's
  -- property.
  identity_node_id uuid REFERENCES core.node(id),
  -- Exactly as observed, including the parts that are not durable. Kept
  -- because what the actor published is itself evidence.
  observed_value  text NOT NULL,
  -- Normalised to the durable part. For Tox this is the 64-hex public key
  -- and NOT the 76-hex ID; for Telegram the numeric id and NOT @username.
  durable_value   text,
  -- CLAIMED: advertised in a signature block or profile.
  -- OBSERVED: seen in actual use.
  -- CONFIRMED: cryptographically verified, e.g. a PGP signature over it.
  -- Treating a claim as a confirmation is how a rival's Jabber ID gets
  -- attributed to the person who posted it as an insult.
  verification    text NOT NULL DEFAULT 'CLAIMED',
  verification_note text,
  -- The artefact these identifiers were published TOGETHER in. docs/10:
  -- the co-declaration structure is itself diagnostic -- which identifiers
  -- an actor publishes in one place says more than any one of them.
  co_declaration_ref text,
  first_seen      timestamptz,
  last_seen       timestamptz,
  classification  core.tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{}',
  created_by      uuid NOT NULL REFERENCES iam.app_user(id),
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT channel_binding_verification_known
    CHECK (verification IN ('CLAIMED', 'OBSERVED', 'CONFIRMED')),
  -- A CONFIRMED binding has to say what confirmed it. "Confirmed" with no
  -- stated method is a claim that somebody felt strongly about.
  CONSTRAINT channel_binding_confirmation_has_method
    CHECK (verification <> 'CONFIRMED' OR verification_note IS NOT NULL)
);
CREATE INDEX channel_binding_case_idx ON channel_binding (case_id);
CREATE INDEX channel_binding_identity_idx ON channel_binding (identity_node_id);
-- THE index that matters: correlation is on the DURABLE value.
CREATE INDEX channel_binding_durable_idx
  ON channel_binding (platform_key, durable_value)
  WHERE durable_value IS NOT NULL;
CREATE INDEX channel_binding_codecl_idx ON channel_binding (co_declaration_ref)
  WHERE co_declaration_ref IS NOT NULL;

-- OMEMO and equivalent per-device identity keys. docs/10: two different
-- JIDs publishing the same fingerprint is the SAME PHYSICAL DEVICE, which
-- is a far stronger link than a shared nickname and is almost never
-- collected. Modelled against a DEVICE node so one device links several
-- personas WITHOUT collapsing them -- invariant 2, one level down.
CREATE TABLE device_fingerprint (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  platform_key    text NOT NULL REFERENCES platform(key),
  device_node_id  uuid REFERENCES core.node(id),
  fingerprint     text NOT NULL,
  algorithm       text NOT NULL DEFAULT 'OMEMO',
  first_seen      timestamptz,
  last_seen       timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),

  UNIQUE (case_id, platform_key, fingerprint)
);
CREATE INDEX device_fingerprint_value_idx
  ON device_fingerprint (platform_key, fingerprint);

CREATE TABLE conversation (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id         uuid NOT NULL REFERENCES core."case"(id),
  platform_key    text NOT NULL REFERENCES platform(key),
  conversation_node_id uuid REFERENCES core.node(id),
  external_ref    text,
  title           text,
  is_group        boolean NOT NULL DEFAULT false,
  -- MANDATORY, and the reason this column exists at all. docs/16 L4:
  -- capturing a conversation a persona is a PARTY to is legally distinct
  -- from capturing one it is not, and both differ by jurisdiction. The
  -- distinction is always recorded even though the authority is external.
  provenance_class text NOT NULL,
  -- The persona that was a party, when one was. NULL for everything else,
  -- and the check below makes that consistent.
  collection_account_id uuid REFERENCES collect.collection_account(id),
  legal_authority text,
  started_at      timestamptz,
  last_message_at timestamptz,
  message_count   integer NOT NULL DEFAULT 0,
  classification  core.tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{}',
  created_at      timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT conversation_provenance_known CHECK (provenance_class IN (
    'PERSONA_PARTY',      -- our persona was a participant
    'SEIZED_DEVICE',      -- recovered from a device under warrant
    'PLATFORM_DISCLOSURE',-- provided by the platform operator
    'OPEN_GROUP',         -- a public or open-join room
    'THIRD_PARTY_REPORT', -- given to us by somebody else
    'UNKNOWN')),
  -- PERSONA_PARTY has to name the persona. Without it, "we were a party"
  -- is unverifiable, and that claim is exactly the one interception law
  -- turns on.
  CONSTRAINT conversation_persona_party_named CHECK (
    provenance_class <> 'PERSONA_PARTY' OR collection_account_id IS NOT NULL
  ),
  -- Anything not obtained by being a party or from an open room needs an
  -- authority written down.
  CONSTRAINT conversation_needs_authority CHECK (
    provenance_class IN ('PERSONA_PARTY', 'OPEN_GROUP', 'UNKNOWN')
    OR legal_authority IS NOT NULL
  )
);
CREATE INDEX conversation_case_idx ON conversation (case_id, last_message_at DESC);
CREATE UNIQUE INDEX conversation_external_idx
  ON conversation (case_id, platform_key, external_ref)
  WHERE external_ref IS NOT NULL;

CREATE TABLE participant (
  conversation_id uuid NOT NULL REFERENCES conversation(id) ON DELETE CASCADE,
  channel_binding_id uuid REFERENCES channel_binding(id),
  -- The raw handle as it appeared, for the common case where a participant
  -- is never resolved to an identity at all. Most group members never are,
  -- and pretending otherwise creates identities out of nothing.
  observed_handle text NOT NULL,
  identity_node_id uuid REFERENCES core.node(id),
  -- docs/08 and docs/16 L4: a third party in a group channel is not a
  -- subject, and minimisation has to be able to find them.
  is_incidental   boolean NOT NULL DEFAULT false,
  first_seen      timestamptz,
  last_seen       timestamptz,
  message_count   integer NOT NULL DEFAULT 0,

  PRIMARY KEY (conversation_id, observed_handle)
);
CREATE INDEX participant_identity_idx ON participant (identity_node_id)
  WHERE identity_node_id IS NOT NULL;
CREATE INDEX participant_incidental_idx ON participant (conversation_id)
  WHERE is_incidental;

CREATE TABLE message (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  conversation_id uuid NOT NULL REFERENCES conversation(id) ON DELETE CASCADE,
  external_ref    text,
  sender_handle   text NOT NULL,
  sent_at         timestamptz,
  captured_at     timestamptz NOT NULL DEFAULT now(),
  body            text,
  -- Deduplication, and the answer to "did we already have this".
  content_sha256  bytea NOT NULL,
  has_attachment  boolean NOT NULL DEFAULT false,
  -- Set when the body has been minimised away but the metadata is kept.
  -- docs/10: most captured chat is operationally worthless, and the value
  -- is in the identifiers, the co-declaration structure and the graph of
  -- who talks to whom -- all of which survive minimisation.
  body_minimised_at timestamptz,
  classification  core.tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{}',

  UNIQUE (conversation_id, content_sha256)
);
CREATE INDEX message_conversation_idx ON message (conversation_id, sent_at);
CREATE INDEX message_sender_idx ON message (conversation_id, sender_handle);
""")

    values = ",\n".join(
        "('{}', '{}', {}, '{}', '{}')".format(
            key, display.replace("'", "''"),
            f"'{selector}'" if selector else "NULL",
            displayed.replace("'", "''"), note.replace("'", "''"))
        for key, display, selector, displayed, note in _PLATFORMS)
    run(f"""
INSERT INTO comms.platform
    (key, display_name, durable_selector_type, displayed_id, note)
VALUES
{values}
ON CONFLICT (key) DO NOTHING;
""")


def downgrade() -> None:
    run("""
DROP TABLE comms.message;
DROP TABLE comms.participant;
DROP TABLE comms.conversation;
DROP TABLE comms.device_fingerprint;
DROP TABLE comms.channel_binding;
DROP TABLE comms.platform;
DROP SCHEMA comms;
""")
