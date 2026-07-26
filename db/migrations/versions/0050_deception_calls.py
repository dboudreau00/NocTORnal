"""Vishing: the number the victim saw and the number the network vouched
for are two columns, and they are never the same column.

docs/19 §1.2 and §3.3. Invariant 9 says index the durable identifier, not
the displayed one. It was written about Tox nospam and recycled Telegram
usernames. In telephony it is sharper, because the displayed identifier is
**chosen by the attacker as the attack**: caller ID spoofing is the
technique, not an incidental detail.

    presented_number      what the victim's handset showed.   WEAK.
    presented_name        CNAM. Also attacker-influenced.     WEAK.
    p_asserted_identity   set by the trusted network.         DURABLE.
    originating_trunk     which trunk actually offered it.    DURABLE.
    stir_shaken_attestation  A/B/C -- the telephony DKIM.      DURABLE.

Collapsing these into one "caller" column is how a spoofed number ends up
as a strong `PHONE` selector on a real person's `PERSON` node — which
attributes a crime to whoever's number the attacker picked out of the
air. That is the fund-losing bug of this subsystem, and it is a schema
decision, not a UI one.

**No selector is minted from a presented value.** The service layer
enforces it; the schema makes the two fields impossible to confuse.

STIR/SHAKEN attestation A means the originating carrier vouches the
caller is entitled to that number. It is the only field on the row that
authenticates anything, which is why `stir_shaken_verified` is separate
from the attestation letter: an unverified claim of attestation A is
worth nothing, and one boolean column would have let it read as verified.

## Recordings are interception; metadata is not

`recording_evidence_id` is NULL unless `recording_lawful_basis` says
under what authority the content was obtained — a `CHECK`, the same shape
as `lab.detonation`'s exposure constraints. That is legal item L4
(docs/16, docs/19 §6). The platform can HOLD a recording someone else
lawfully obtained. It contains no code that obtains one: no SIP capture,
no RTP, no transcription. That is deliberate and is listed under "what is
deliberately not built".

`record_source` grades the provenance of the record itself. A victim's
recollection of a call and a carrier CDR are both admissible and are not
the same grade of evidence; a schema that could not tell them apart would
launder one into the other.
"""
from alembic import op

revision = "0050"
down_revision = "0049"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE TABLE deception.call_record (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id        uuid NOT NULL REFERENCES core."case"(id),

  -- WHAT THE VICTIM SAW. Attacker-chosen. Never a strong selector.
  presented_number      text,
  presented_number_e164 text,
  presented_name        text,

  -- WHAT THE NETWORK SAW. Durable.
  originating_trunk     text,
  p_asserted_identity   text,
  carrier_name          text,
  stir_shaken_attestation text,
  stir_shaken_verified  boolean NOT NULL DEFAULT false,

  called_number_e164 text,
  direction      text NOT NULL,
  started_at     timestamptz NOT NULL,
  ended_at       timestamptz,
  duration_seconds int,
  disposition    text,

  -- SIP, when the record came from a trunk rather than a bill.
  sip_call_id    text,
  sip_from_uri   text,
  sip_to_uri     text,
  source_ip      inet,
  user_agent     text,

  -- Provenance OF THE RECORD. A CDR and a victim's recollection are not
  -- the same grade of evidence.
  record_source  text NOT NULL,
  evidence_id    uuid REFERENCES core.evidence(id),

  -- L4. Content, not metadata.
  recording_evidence_id  uuid REFERENCES core.evidence(id),
  recording_lawful_basis text,

  victim_node_id uuid REFERENCES core.node(id),
  lure_node_id   uuid REFERENCES core.node(id),
  note           text,
  recorded_by    uuid NOT NULL REFERENCES iam.app_user(id),
  recorded_at    timestamptz NOT NULL DEFAULT now(),
  classification core.tlp NOT NULL DEFAULT 'AMBER',
  compartments   text[] NOT NULL DEFAULT '{}',
  legal_hold     boolean NOT NULL DEFAULT false,

  CONSTRAINT call_direction_known CHECK (direction IN
    ('INBOUND_TO_VICTIM','OUTBOUND_FROM_VICTIM','UNKNOWN')),
  CONSTRAINT call_record_source_known CHECK (record_source IN
    ('CARRIER_CDR','PBX_LOG','SIP_CAPTURE','VICTIM_STATEMENT',
     'HANDSET_LOG','THIRD_PARTY_REPORT')),
  CONSTRAINT call_disposition_known CHECK (disposition IS NULL OR disposition IN
    ('ANSWERED','NO_ANSWER','BUSY','VOICEMAIL','REJECTED','FAILED')),
  CONSTRAINT call_attestation_known CHECK (
    stir_shaken_attestation IS NULL OR stir_shaken_attestation IN ('A','B','C')),
  -- "Verified" is a claim about a check that ran, so it needs something
  -- to have been checked.
  CONSTRAINT call_verified_needs_attestation CHECK (
    NOT stir_shaken_verified OR stir_shaken_attestation IS NOT NULL),
  -- L4: no lawful basis, no recording. The metadata is unaffected.
  CONSTRAINT call_recording_needs_basis CHECK (
    recording_evidence_id IS NULL OR recording_lawful_basis IS NOT NULL),
  CONSTRAINT call_duration_nonneg CHECK (
    duration_seconds IS NULL OR duration_seconds >= 0),
  CONSTRAINT call_ends_after_it_starts CHECK (
    ended_at IS NULL OR ended_at >= started_at)
);
CREATE INDEX call_case_idx ON deception.call_record (case_id, started_at DESC);
CREATE INDEX call_presented_idx ON deception.call_record (presented_number_e164)
  WHERE presented_number_e164 IS NOT NULL;
CREATE INDEX call_called_idx ON deception.call_record (called_number_e164)
  WHERE called_number_e164 IS NOT NULL;
CREATE INDEX call_trunk_idx ON deception.call_record (originating_trunk)
  WHERE originating_trunk IS NOT NULL;
CREATE INDEX call_pai_idx ON deception.call_record (p_asserted_identity)
  WHERE p_asserted_identity IS NOT NULL;
-- The triage query: calls with a recording, which are the L4-sensitive
-- ones and the ones an audit will ask about.
CREATE INDEX call_recorded_idx ON deception.call_record (case_id)
  WHERE recording_evidence_id IS NOT NULL;

CREATE TRIGGER call_record_tlp BEFORE INSERT OR UPDATE
  ON deception.call_record
  FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();
""")


def downgrade() -> None:
    # The schema itself is dropped by 0048's downgrade, which runs LAST in
    # the unwind (0050 -> 0049 -> 0048) and is also the migration that
    # created it. Dropping it here would mean DROP SCHEMA RESTRICT against
    # a schema still holding capture and email_message.
    run("DROP TABLE IF EXISTS deception.call_record")
