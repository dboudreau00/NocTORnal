"""Web capture: the evidential unit is the tuple, not the screenshot.

docs/19 §3.1. A screenshot on its own proves that somebody had a
screenshot. What proves a phishing page is the whole fetch:

    requested URL -> redirect chain -> final URL -> TLS certificate
                  -> screenshot -> DOM,  all at one timestamp

`deception.capture` holds that tuple on ONE row, with the screenshot, DOM
and HAR as three FKs into `core.evidence`. The single row is the point: a
screenshot that can be re-paired with a different page's DOM is not
evidence of anything, and a schema that stores them as independent
exhibits invites exactly that. `capture_hop` carries the chain, because
kits route shortener -> compromised host -> kit and each hop is
separately attributable infrastructure.

## Why the TLS public-key hash is a first-class column

Phishing infrastructure rotates domains constantly and certificates
rarely — reissuing costs effort, and kit operators reuse a key across
dozens of hostnames. `tls_spki_sha256` is therefore the durable web
identifier in the way the domain is not (invariant 9, and the new
TLS_SPKI selector in 0047).

## Two CHECKs that encode a legal position, not a data rule

`capture_active_needs_egress_profile` — an active fetch from the office
egress IP tells the actor they are being watched. docs/19 §5. Passive
methods (an analyst upload, a victim-supplied screenshot) never touched
the attacker, so they are exempt; anything that made a request is not.

> **This is a record-keeping control, not a routing one, and the
> difference matters.** NocTORnal does not perform web captures — there
> is no code path in this platform that fetches a phishing URL, by
> design (docs/19 §7). `collect.egress_profile.endpoint_ciphertext` is
> read by zero lines of Python; the table is referenced only by
> `collection.py`'s persona-collision report. So this column records
> which egress the operator DECLARES their external tool used. It does
> not and cannot prove it. Stated plainly because a constraint that
> looks like a technical control while being an attestation is exactly
> the shape of defect this codebase has found in itself repeatedly — a
> defence written, exported, and never called.
>
> Its value is real but narrow: a capture with no declared egress is a
> capture nobody can account for afterwards, and the constraint makes
> that impossible to leave blank by accident.

`capture_submission_needs_authority` — entering credentials into a
phishing page, INCLUDING canary or fabricated ones, may constitute
unauthorised access under computer-misuse statutes in several
jurisdictions. That is legal item L5 (docs/19 §6) and it is not a
decision software can make. The column records that a human did it under
a written authority; there is no code in this platform that does it.
This is the same shape as `lab.detonation`'s exposure constraints, and
for the same reason: the row that has to survive is the authorisation.

## Re-capture inserts, never updates

Invariant 5. Phishing pages change hourly and go dark within days; the
sequence of captures IS the timeline that proves the page was live when
the victim hit it. There is deliberately no unique constraint on
(case_id, requested_url).
"""
from alembic import op

revision = "0048"
down_revision = "0047"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE SCHEMA IF NOT EXISTS deception;

CREATE TABLE deception.capture (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  case_id            uuid NOT NULL REFERENCES core."case"(id),
  -- What was asked for, and where it ended up. Both, always: the
  -- difference between them IS the redirect finding.
  requested_url      text NOT NULL,
  requested_url_norm text NOT NULL,
  final_url          text,
  final_url_norm     text,
  captured_at        timestamptz NOT NULL DEFAULT now(),
  capture_method     text NOT NULL,
  capture_tool       text,
  -- The egress the operator DECLARES their external tool used. An
  -- attestation, not a routing control: nothing in this platform
  -- performs the fetch. See the module docstring.
  egress_profile_id  uuid REFERENCES collect.egress_profile(id),
  user_agent         text,
  viewport           text,
  http_status        int,
  -- Did it serve content at capture time? A dead page is a finding, not
  -- a failed capture, and the row must be able to say so.
  is_live            boolean,
  page_title         text,
  -- Extracted, defanged in the UI, never rendered as markup.
  visible_text       text,
  favicon_hash       text,
  -- The three exhibits. DOM and HAR are attacker-authored (invariant 10,
  -- migration 0046); the screenshot is raster and may render.
  screenshot_evidence_id uuid REFERENCES core.evidence(id),
  dom_evidence_id        uuid REFERENCES core.evidence(id),
  har_evidence_id        uuid REFERENCES core.evidence(id),
  -- TLS identity. The SPKI hash outlives the domain.
  tls_subject        text,
  tls_issuer         text,
  tls_not_before     timestamptz,
  tls_not_after      timestamptz,
  tls_spki_sha256    bytea,
  -- L5 (docs/19 §6).
  submitted_input    boolean NOT NULL DEFAULT false,
  submission_authority_ref text,
  captured_by        uuid NOT NULL REFERENCES iam.app_user(id),
  note               text,
  classification     core.tlp NOT NULL DEFAULT 'AMBER',
  compartments       text[] NOT NULL DEFAULT '{}',
  legal_hold         boolean NOT NULL DEFAULT false,
  created_at         timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT capture_method_known CHECK (capture_method IN
    ('MANUAL_BROWSER','HEADLESS','VENDOR_API','ANALYST_UPLOAD',
     'VICTIM_SUPPLIED','PASSIVE_FEED')),
  -- Active methods reached out and touched attacker infrastructure.
  CONSTRAINT capture_active_needs_egress_profile CHECK (
    capture_method IN ('ANALYST_UPLOAD','VICTIM_SUPPLIED','PASSIVE_FEED')
    OR egress_profile_id IS NOT NULL),
  -- L5. No authority reference, no row.
  CONSTRAINT capture_submission_needs_authority CHECK (
    NOT submitted_input OR submission_authority_ref IS NOT NULL),
  CONSTRAINT capture_spki_is_a_sha256 CHECK (
    tls_spki_sha256 IS NULL OR octet_length(tls_spki_sha256) = 32)
);
CREATE INDEX capture_case_idx ON deception.capture (case_id, captured_at DESC);
CREATE INDEX capture_url_idx  ON deception.capture (requested_url_norm);
CREATE INDEX capture_final_idx ON deception.capture (final_url_norm)
  WHERE final_url_norm IS NOT NULL;
-- The cross-case infrastructure pivot: same key, different domains.
CREATE INDEX capture_spki_idx ON deception.capture (tls_spki_sha256)
  WHERE tls_spki_sha256 IS NOT NULL;
CREATE INDEX capture_favicon_idx ON deception.capture (favicon_hash)
  WHERE favicon_hash IS NOT NULL;

CREATE TRIGGER capture_tlp BEFORE INSERT OR UPDATE ON deception.capture
  FOR EACH ROW EXECUTE FUNCTION core.enforce_tlp_floor();

-- The redirect chain. seq 0 is the URL that was requested; each
-- subsequent row is one hop the client actually followed.
CREATE TABLE deception.capture_hop (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  capture_id  uuid NOT NULL REFERENCES deception.capture(id) ON DELETE CASCADE,
  seq         int NOT NULL,
  url         text NOT NULL,
  url_norm    text NOT NULL,
  http_status int,
  resolved_ip inet,
  asn         int,
  server_header text,
  hop_kind    text NOT NULL,
  UNIQUE (capture_id, seq),
  CONSTRAINT capture_hop_seq_nonneg CHECK (seq >= 0),
  CONSTRAINT capture_hop_kind_known CHECK (hop_kind IN
    ('REQUESTED','HTTP_30X','META_REFRESH','JS','FRAME','DNS_CNAME'))
);
CREATE INDEX capture_hop_url_idx ON deception.capture_hop (url_norm);
""")


def downgrade() -> None:
    run("DROP TABLE IF EXISTS deception.capture_hop")
    run("DROP TABLE IF EXISTS deception.capture")
    # This migration created the schema, and it is the LAST to unwind
    # (0050 -> 0049 -> 0048), so by now it is empty. RESTRICT rather than
    # CASCADE is deliberate: if something else has since put a table here,
    # fail loudly rather than quietly take it with us.
    run("DROP SCHEMA IF EXISTS deception RESTRICT")
