"""The delivery ledger's causes, exposure, queue time and event identity
(F8, 2026-09-24).

## What was wrong

`notify.delivery` said WHAT happened to a delivery (its state) and left
WHY to be inferred: a SUPPRESSED row was the recipient's own choice when
`last_attempt_at` was NULL and a revoked clearance when it was set, and the
ledger route parsed that from free text. Jira (F7) adds four more kinds of
absence (no case, no destination, a kind nobody routed, a case its owner
keeps out), so the inference stops holding. Nothing recorded what left the
building either: whether a summary, a subject line or a content-free stub
reached the far end was reconstructed from the classification.

## What this adds

- `notify.delivery.cause`: one stable code per decided row, from
  transports.CAUSES. Code matches on the cause, never on `detail`, which
  stays the human sentence.
- `notify.delivery.exposure`: STUB, SUBJECT or SUMMARY, what actually
  left on an outbound channel. NULL while nothing left, and always NULL on
  IN_APP (a CHECK), because the in-app row never crosses the boundary.
- `notify.delivery.queued_at`: when the row was queued, so the ledger can
  order and page on a column of its own table instead of a join.
- `notify.notification.event_id`: shared by every row one event fanned out
  to (one approval request to three signers is one event). Jira posts one
  event once however many recipients it reached. New rows get a random id
  by default; rows written before this revision stay NULL and readers use
  coalesce(event_id, id), so each is its own event.
- `delivery_ledger_idx`, the ledger's order and cursor.

## The backfill is derived, not invented

0044 left `sent_to` NULL on history because where a message went was not
recorded anywhere. Cause and exposure are different: the SUPPRESSED detail
strings are the stable sentences their writers have always promised
(notifications._queue_deliveries, transports._REVOKE_SQL), and
render_email and webhook_payload have only ever sent the subject and
summary, or the stub, so exposure is determined by the code that ran. A
SUPPRESSED row whose detail matches none of those is LEGACY.

## Locking (2026-09-24)

Every revision runs inside one transaction (db/migrations/env.py,
transaction_per_migration). The first ALTER TABLE takes ACCESS EXCLUSIVE
on notify.delivery and holds it until commit, so the backfill, the
constraints and the index all run under it, and every merge and approval
(which write notify.delivery in their own transaction) waits for the
whole revision. Stop the api and the cron before migrating. The standard
upgrade already starts them only after migrate completes.

## Downgrade

Drops the index, the constraints and the four columns. Lossless: every
backfilled value is derived, and event_id before this revision was
implicit.
"""
from alembic import op

revision = "0095"
down_revision = "0094"
branch_labels = None
depends_on = None

#: transports.CAUSES, spelled here because a migration never imports the
#: application; test_notify_ledger_migration_pg.py holds the two equal.
CAUSES = ("RECIPIENT_DISABLED", "BELOW_THRESHOLD", "CASELESS",
          "DESTINATION_OFF", "KIND_NOT_ROUTED", "CASE_NOT_ROUTED", "WITHDRAWN",
          "REVOKED", "EGRESS_REFUSED", "TRANSPORT_ERROR", "RATE_LIMITED",
          "GAVE_UP", "REQUEUED", "ALREADY_ON_ISSUE", "LEGACY")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    causes = ", ".join(f"'{c}'" for c in CAUSES)
    run(f"""
ALTER TABLE notify.delivery
  ADD COLUMN cause text,
  ADD COLUMN exposure text,
  ADD COLUMN queued_at timestamptz;
ALTER TABLE notify.notification ADD COLUMN event_id uuid;
ALTER TABLE notify.notification ALTER COLUMN event_id SET DEFAULT gen_random_uuid();

UPDATE notify.delivery d SET
  queued_at = n.created_at,
  cause = CASE
    WHEN d.state = 'SUPPRESSED' AND d.detail = 'channel disabled by the recipient'
      THEN 'RECIPIENT_DISABLED'
    WHEN d.state = 'SUPPRESSED'
         AND d.detail LIKE 'priority % is below the recipient''s threshold for %'
      THEN 'BELOW_THRESHOLD'
    WHEN d.state = 'SUPPRESSED'
         AND d.detail LIKE 'the recipient may no longer read this notification%'
      THEN 'REVOKED'
    WHEN d.state = 'SUPPRESSED' THEN 'LEGACY'
    WHEN d.state = 'REFUSED' THEN 'EGRESS_REFUSED'
    WHEN d.state = 'FAILED' THEN 'GAVE_UP'
    WHEN d.state = 'PENDING' AND d.attempts > 0 THEN 'TRANSPORT_ERROR'
  END,
  exposure = CASE
    WHEN d.channel IN ('SMTP', 'WEBHOOK') AND d.state = 'SENT' THEN 'SUMMARY'
    WHEN d.channel IN ('SMTP', 'WEBHOOK') AND d.state = 'REFUSED' AND d.redacted
      THEN 'STUB'
  END
  FROM notify.notification n
 WHERE n.id = d.notification_id;

ALTER TABLE notify.delivery
  ALTER COLUMN queued_at SET DEFAULT now(),
  ALTER COLUMN queued_at SET NOT NULL,
  ADD CONSTRAINT delivery_cause_known
    CHECK (cause IS NULL OR cause IN ({causes})),
  ADD CONSTRAINT delivery_decided_has_cause
    CHECK (state NOT IN ('SUPPRESSED', 'REFUSED', 'FAILED') OR cause IS NOT NULL),
  ADD CONSTRAINT delivery_exposure_known
    CHECK (exposure IS NULL OR exposure IN ('STUB', 'SUBJECT', 'SUMMARY')),
  ADD CONSTRAINT delivery_in_app_never_leaves
    CHECK (channel <> 'IN_APP' OR exposure IS NULL),
  ADD CONSTRAINT delivery_on_issue_is_jira
    CHECK (cause IS DISTINCT FROM 'ALREADY_ON_ISSUE'
           OR (channel = 'JIRA' AND state = 'SENT'));

CREATE INDEX delivery_ledger_idx ON notify.delivery
  ((coalesce(last_attempt_at, sent_at, queued_at)) DESC, id DESC);

COMMENT ON COLUMN notify.delivery.cause IS
  'Why the row is in its state: one stable code (transports.CAUSES). Code '
  'matches on this, never on detail, which is the human sentence.';
COMMENT ON COLUMN notify.delivery.exposure IS
  'What left the building on this channel: STUB, SUBJECT or SUMMARY. NULL '
  'while nothing left, and always NULL on IN_APP. Backfilled from the code '
  'that ran (render_email and webhook_payload only ever sent those).';
COMMENT ON COLUMN notify.delivery.queued_at IS
  'When the delivery was queued: the notification''s time for rows written '
  'before 0095.';
COMMENT ON COLUMN notify.notification.event_id IS
  'Shared by every row one event fanned out to. NULL before 0095, where '
  'readers take the row''s own id.';
""")


def downgrade() -> None:
    run("""
DROP INDEX IF EXISTS notify.delivery_ledger_idx;
ALTER TABLE notify.delivery
  DROP CONSTRAINT IF EXISTS delivery_on_issue_is_jira,
  DROP CONSTRAINT IF EXISTS delivery_in_app_never_leaves,
  DROP CONSTRAINT IF EXISTS delivery_exposure_known,
  DROP CONSTRAINT IF EXISTS delivery_decided_has_cause,
  DROP CONSTRAINT IF EXISTS delivery_cause_known,
  DROP COLUMN IF EXISTS queued_at,
  DROP COLUMN IF EXISTS exposure,
  DROP COLUMN IF EXISTS cause;
ALTER TABLE notify.notification DROP COLUMN IF EXISTS event_id;
""")
