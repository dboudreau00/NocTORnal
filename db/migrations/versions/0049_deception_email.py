"""BEC email: the headers that are allowed to disagree, and a Received
chain that knows which end of itself to trust.

docs/19 §2 and §3.2. `core.evidence` already stores a `.eml` perfectly
well as opaque bytes. What it cannot do is answer the only questions that
matter in a business-email-compromise case:

    Does From: disagree with Reply-To:?   <- the classic BEC tell
    Did DKIM actually PASS, and for which domain?
    Where does the Received chain stop being evidence?

So the headers get columns. Not a jsonb blob: a report has to cite
`from_replyto_divergent`, an index has to find every message claiming to
be the CFO, and a `->>'reply-to'` that silently returns NULL because the
parser used a different case is a finding that quietly disappears.

## The Received chain is only trustworthy inwards

THE thing to get right here, and the reason `seq` is numbered the way it
is. Each MTA PREPENDS its own `Received` header, so the raw chain reads
newest-first — and every hop above the first one your own infrastructure
added is **attacker-writable**. A BEC sender forges as many plausible
upstream hops as they like.

    seq 0  = the recipient's own MTA          <- trustworthy
    seq 1  = the hop before that              <- trustworthy iff still ours
    ...
    is_trusted_boundary marks the last hop under the recipient's control.
    ABOVE IT NOTHING IS EVIDENCE OF ANYTHING.

An analyst reading the chain the other way attributes the mail to
whatever originating IP the attacker typed into a header. That is not a
subtle error; it is the difference between an investigation and a
libel. The column exists so the UI can draw the line and so the
extractor can refuse to propose an `INFRA` node from above it.

`seq` is stored in RECEIVED ORDER (0 = closest to the recipient), which
is the reverse of the order the headers appear in the file. The parser
does that flip once, here, rather than leaving every consumer to
remember it.

## Attachments go to lab.sample, not to a second weaker home

A BEC attachment is malware. `lab.sample` already has encryption at
rest, a separate download origin, a policy gate and a custody ledger.
`email_attachment.sample_id` points there. Giving attachments their own
bytes column would have created a second, unguarded copy of exactly the
thing invariant 10 exists to contain.
"""
from alembic import op

revision = "0049"
down_revision = "0048"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE TABLE deception.email_message (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id        uuid NOT NULL REFERENCES core."case"(id),
  -- The exhibit: the raw .eml, hostile (HTML body + remote images).
  evidence_id    uuid NOT NULL REFERENCES core.evidence(id),
  message_id      text,
  message_id_norm text,

  -- THE BEC CLUSTER. Separate columns because they are ALLOWED to
  -- disagree, and the disagreement is the evidence.
  header_from          text,   -- From:            spoofable
  header_from_display  text,   -- the display name -- the actual lure
  header_reply_to      text,   -- Reply-To:        where a reply really goes
  header_return_path   text,   -- Return-Path
  envelope_from        text,   -- SMTP MAIL FROM, if the MTA recorded it
  header_to            text[],
  header_cc            text[],
  subject              text,
  date_header          timestamptz,
  in_reply_to          text,
  thread_topic         text,

  -- What the RECEIVING MTA decided. A passing DKIM d= is the only
  -- durable sender identity in an email (invariant 9).
  spf_result     text,
  spf_domain     text,
  dkim_result    text,
  dkim_domain    text,
  dmarc_result   text,
  dmarc_domain   text,
  auth_results_raw text,

  -- Derived, but STORED, because it is the finding and a report cites
  -- it. Recomputing on read would make a historical report change when
  -- the parser changes.
  from_replyto_divergent   boolean NOT NULL DEFAULT false,
  from_returnpath_divergent boolean NOT NULL DEFAULT false,
  display_name_impersonates text,
  reply_to_is_freemail     boolean NOT NULL DEFAULT false,

  -- Body, extracted only. The HTML body is NEVER rendered: it loads
  -- remote images, and doing so fires the actor's tracking pixel from
  -- the investigating organisation's IP (docs/19 §5).
  body_text       text,
  has_html_body   boolean NOT NULL DEFAULT false,
  extracted_urls  text[] NOT NULL DEFAULT '{}',

  direction       text NOT NULL DEFAULT 'INBOUND_TO_VICTIM',
  victim_node_id  uuid REFERENCES core.node(id),
  recorded_by     uuid NOT NULL REFERENCES iam.app_user(id),
  recorded_at     timestamptz NOT NULL DEFAULT now(),
  parse_gaps      jsonb NOT NULL DEFAULT '[]'::jsonb,
  classification  core.tlp NOT NULL DEFAULT 'AMBER',
  compartments    text[] NOT NULL DEFAULT '{}',
  legal_hold      boolean NOT NULL DEFAULT false,

  CONSTRAINT email_direction_known CHECK (direction IN
    ('INBOUND_TO_VICTIM','OUTBOUND_FROM_VICTIM','INTERNAL','UNKNOWN')),
  CONSTRAINT email_auth_result_known CHECK (
    (spf_result   IS NULL OR spf_result   IN ('PASS','FAIL','SOFTFAIL','NEUTRAL','NONE','TEMPERROR','PERMERROR')) AND
    (dkim_result  IS NULL OR dkim_result  IN ('PASS','FAIL','NONE','TEMPERROR','PERMERROR')) AND
    (dmarc_result IS NULL OR dmarc_result IN ('PASS','FAIL','NONE','TEMPERROR','PERMERROR'))),
  -- A dkim_domain without a PASS is not an identity; recording one would
  -- invite a downstream reader to treat it as authenticated.
  CONSTRAINT email_dkim_domain_needs_pass CHECK (
    dkim_domain IS NULL OR dkim_result = 'PASS')
);
CREATE INDEX email_case_idx ON deception.email_message (case_id, recorded_at DESC);
CREATE INDEX email_msgid_idx ON deception.email_message (message_id_norm)
  WHERE message_id_norm IS NOT NULL;
CREATE INDEX email_from_idx ON deception.email_message (lower(header_from))
  WHERE header_from IS NOT NULL;
CREATE INDEX email_replyto_idx ON deception.email_message (lower(header_reply_to))
  WHERE header_reply_to IS NOT NULL;
-- The triage query: show me every divergent message in this case.
CREATE INDEX email_divergent_idx ON deception.email_message (case_id)
  WHERE from_replyto_divergent;

CREATE TRIGGER email_message_tlp BEFORE INSERT OR UPDATE
  ON deception.email_message
  FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

-- The Received chain, RECIPIENT-FIRST. seq 0 is the receiving MTA.
CREATE TABLE deception.email_hop (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id   uuid NOT NULL REFERENCES deception.email_message(id) ON DELETE CASCADE,
  seq          int NOT NULL,
  received_raw text NOT NULL,
  from_host    text,
  from_ip      inet,
  by_host      text,
  protocol     text,
  tls_used     boolean,
  received_at  timestamptz,
  -- The last hop under the recipient's control. Above it the chain is
  -- attacker-writable and is not evidence.
  is_trusted_boundary boolean NOT NULL DEFAULT false,
  UNIQUE (message_id, seq),
  CONSTRAINT email_hop_seq_nonneg CHECK (seq >= 0)
);
CREATE INDEX email_hop_ip_idx ON deception.email_hop (from_ip)
  WHERE from_ip IS NOT NULL;

-- At most one boundary per message: two would make "is this hop
-- trustworthy" unanswerable, which is the one question the table exists
-- to answer.
CREATE UNIQUE INDEX email_hop_one_boundary_idx
  ON deception.email_hop (message_id) WHERE is_trusted_boundary;

CREATE TABLE deception.email_attachment (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  message_id   uuid NOT NULL REFERENCES deception.email_message(id) ON DELETE CASCADE,
  filename     text,
  media_type   text,
  byte_size    bigint,
  sha256       bytea,
  -- Malware goes to the lab, under the gate that already exists.
  sample_id    uuid REFERENCES lab.sample(id),
  is_inline    boolean NOT NULL DEFAULT false,
  content_id   text,
  CONSTRAINT email_attachment_sha_is_sha256 CHECK (
    sha256 IS NULL OR octet_length(sha256) = 32)
);
CREATE INDEX email_attachment_msg_idx ON deception.email_attachment (message_id);
CREATE INDEX email_attachment_sha_idx ON deception.email_attachment (sha256)
  WHERE sha256 IS NOT NULL;
""")


def downgrade() -> None:
    run("DROP TABLE IF EXISTS deception.email_attachment")
    run("DROP TABLE IF EXISTS deception.email_hop")
    run("DROP TABLE IF EXISTS deception.email_message")
