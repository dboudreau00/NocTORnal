"""Notification: the in-app centre, per-channel delivery, and preferences.

Phase 5. docs/07 opens with the reason this is hygiene rather than plumbing:

    A system that cries wolf gets muted, and then the one alert that
    mattered is also muted.

and with the rule that shapes the whole table:

    Email is the least trustworthy channel you have. It sits in inboxes,
    gets forwarded, is often synced to phones. Subject line carries no
    intelligence. Body carries a summary and a deep link, not the content.

## Three text fields, three different safety contracts

That rule is unenforceable if a notification is one blob of text, because
whoever writes the email transport then has to remember which parts are
safe. So the content is split by where it is allowed to appear, and the
contract is part of the column:

- `subject` — **never contains intelligence.** The case CODE and what kind
  of thing happened. Safe for an email subject line, which is the most
  exposed string in the system: it renders on a lock screen.
- `summary` — one line, **no entity names, no handles, no selectors.** Safe
  for an email body alongside a link and a TLP marking.
- `body` — the full in-app text. May name entities, because in-app the
  reader has already passed the five-part gate. **Never leaves the
  platform.** `notifications.py` has a test asserting the SMTP transport
  cannot read this column.

## A notification is classified data

"Merge performed on OP-KESTREL between shadowbroker and A. Petrov" is case
content sitting in an inbox. So each row carries its own classification and
compartments, and reading it is filtered by the caller's CURRENT clearance
rather than the clearance they had when it was written — a revoked clearance
has to hide old notifications too, or the centre becomes a retention loophole
for everything the analyst used to be able to see.

## Delivery is a ledger, not a flag

`notify.delivery` is one row per channel per notification, including the
ones that were REFUSED by the egress gate. Invariant 12: nothing is silently
dropped. "The email was suppressed because the case is AMBER_STRICT" is an
answer; a missing row is not.
"""
from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE SCHEMA IF NOT EXISTS notify;
SET search_path = notify, core, public;

CREATE TABLE notification (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recipient_id  uuid NOT NULL REFERENCES iam.app_user(id),
  case_id       uuid REFERENCES core."case"(id),
  kind          text NOT NULL,
  -- 1 is highest. Priority 1 overrides quiet hours and is never digested;
  -- docs/07 calls for exactly that override, because the reason quiet hours
  -- are acceptable at all is that something can still get through.
  priority      smallint NOT NULL DEFAULT 2,

  -- See the module docstring. Three fields, three contracts.
  subject       text NOT NULL,
  summary       text NOT NULL,
  body          text NOT NULL,

  -- The labels of the CONTENT, not of the case: an AMBER case can raise a
  -- notification about a RED element, and the stricter of the two is what
  -- governs both the read filter and the egress gate.
  classification core.tlp NOT NULL,
  compartments  text[] NOT NULL,

  object_type   text,
  object_id     uuid,
  -- The actor whose action caused this. Kept so the dispatcher can refuse
  -- to tell somebody what they just did themselves -- self-notification is
  -- the single commonest reason people mute a notification system.
  actor_id      uuid REFERENCES iam.app_user(id),

  created_at    timestamptz NOT NULL DEFAULT now(),
  read_at       timestamptz,
  -- Acknowledgement is distinct from reading (docs/07): a hit someone has
  -- looked at stops nagging everyone else only once it is ACKNOWLEDGED.
  acknowledged_at timestamptz,

  CONSTRAINT notification_priority_range CHECK (priority BETWEEN 1 AND 3),
  CONSTRAINT notification_subject_present CHECK (length(btrim(subject)) > 0),
  -- Acknowledging implies reading. Without this the counters disagree.
  CONSTRAINT notification_ack_implies_read
    CHECK (acknowledged_at IS NULL OR read_at IS NOT NULL)
);

-- The unread badge, which is polled: this is the hottest read in the app.
CREATE INDEX notification_unread_idx
    ON notification (recipient_id, created_at DESC) WHERE read_at IS NULL;
CREATE INDEX notification_recipient_idx
    ON notification (recipient_id, created_at DESC);
CREATE INDEX notification_case_idx ON notification (case_id, created_at DESC);
CREATE INDEX notification_object_idx ON notification (object_id)
    WHERE object_id IS NOT NULL;

-- One row per channel per notification, INCLUDING refusals and
-- suppressions. Invariant 12: a delivery that did not happen has a reason,
-- not an absence.
CREATE TABLE delivery (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  notification_id uuid NOT NULL REFERENCES notification(id) ON DELETE CASCADE,
  channel         text NOT NULL,          -- IN_APP | SMTP | WEBHOOK | JIRA
  state           text NOT NULL,          -- PENDING|SENT|FAILED|REFUSED|SUPPRESSED
  -- Quiet hours and digest both work by pushing this into the future
  -- rather than by dropping the row, so a deferred notification is visibly
  -- deferred instead of invisibly gone.
  deliver_after   timestamptz NOT NULL DEFAULT now(),
  attempts        smallint NOT NULL DEFAULT 0,
  last_attempt_at timestamptz,
  sent_at         timestamptz,
  -- The egress gate's reason code on a REFUSED row, or the transport error
  -- on a FAILED one. Matched on, not just read, so it is a stable string.
  detail          text,
  -- Whether the full summary went out or only the content-free stub. An
  -- auditor asking "what did this email actually say" needs this.
  redacted        boolean NOT NULL DEFAULT false,

  CONSTRAINT delivery_state_known
    CHECK (state IN ('PENDING', 'SENT', 'FAILED', 'REFUSED', 'SUPPRESSED')),
  CONSTRAINT delivery_channel_known
    CHECK (channel IN ('IN_APP', 'SMTP', 'WEBHOOK', 'JIRA')),
  CONSTRAINT delivery_sent_has_timestamp
    CHECK ((state = 'SENT') = (sent_at IS NOT NULL))
);

CREATE UNIQUE INDEX delivery_one_per_channel
    ON delivery (notification_id, channel);
-- The outbox drain: everything due, oldest first.
CREATE INDEX delivery_due_idx ON delivery (deliver_after)
    WHERE state = 'PENDING';

-- Per-user, per-channel. A missing row means the built-in default, so a new
-- user is not silently un-notified and an admin does not have to seed rows.
CREATE TABLE preference (
  user_id       uuid NOT NULL REFERENCES iam.app_user(id),
  channel       text NOT NULL,
  enabled       boolean NOT NULL DEFAULT true,
  -- Only notifications at or above this priority use this channel.
  -- 3 = everything, 1 = only the urgent.
  min_priority  smallint NOT NULL DEFAULT 3,
  digest        boolean NOT NULL DEFAULT false,
  -- Local wall-clock times, interpreted in `timezone`. Stored as time
  -- rather than as an offset because "not after 22:00 my time" is what a
  -- person means, and it has to survive a daylight-saving change.
  quiet_from    time,
  quiet_to      time,
  timezone      text NOT NULL DEFAULT 'UTC',
  address       text,                     -- overrides the account email

  PRIMARY KEY (user_id, channel),
  CONSTRAINT preference_channel_known
    CHECK (channel IN ('IN_APP', 'SMTP', 'WEBHOOK', 'JIRA')),
  CONSTRAINT preference_priority_range CHECK (min_priority BETWEEN 1 AND 3),
  -- Half a quiet window is a bug that reads as a working one.
  CONSTRAINT preference_quiet_window_complete
    CHECK ((quiet_from IS NULL) = (quiet_to IS NULL))
);
""")


def downgrade() -> None:
    run("""
DROP TABLE notify.preference;
DROP TABLE notify.delivery;
DROP TABLE notify.notification;
DROP SCHEMA notify;
""")
