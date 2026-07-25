"""Four-eyes approval, and the per-case switch that turns it on for merges.

docs/05 asks for **dual control** "for the genuinely irreversible: case
deletion, evidence purge, role definition changes, persona credential
reveal. Two distinct humans, enforced by constraint." docs/08 adds
out-of-schedule purge. docs/04 adds `collection_account.reveal`.

None of those operations is built yet. This table is built first anyway,
because the shape of the control is the part worth getting right, and
retrofitting a second approver onto an operation that already ships is how
you end up with dual control that is really single control with a form to
fill in.

## The four things that make it a control rather than a ceremony

**1. The approval binds to the exact parameters.** `payload_hash` is taken
over the operation, the case and the canonicalised payload. Consuming an
approval re-computes that hash against what is about to be executed and
refuses on any difference. Without it, "approved" means "approved of this
analyst's next idea": request a merge of two obviously-identical bots, get
a nod, then execute a merge of the two nodes the case actually turns on.

**2. It is single use, enforced by the state machine, not by discipline.**
`consume` is one atomic `UPDATE ... WHERE state = 'APPROVED'`, so two
concurrent attempts cannot both win. An approval that can be replayed is a
standing permission with extra steps.

**3. Expiry is COMPUTED, never swept.** There is no `EXPIRED` state and no
job that sets one. `expires_at` is compared at decision and consumption
time, so a dead cron job cannot silently leave month-old approvals live.
A control whose correctness depends on a scheduled task is a control that
fails quietly the first time the scheduler does.

**4. Two distinct humans, in the database.** `approval_two_distinct_humans`
is the constraint docs/05 asks for by name. Application code can be
refactored around; a CHECK cannot. It cannot stop one person with two
accounts, which is a joiner/leaver problem rather than a schema one -- what
it does stop is the far commoner accident of a UI that lets the requester
click their own Approve button.

## Why merge is OPT-IN and defaults to off

`case.dual_control_merge` exists because docs/09's roadmap and the Phase 3
handoff both flag that a merge can be performed by one analyst alone. But
docs/05 scopes dual control to "the genuinely irreversible", and a merge
here is a ledger with an exact restore (0027) -- it is the most reversible
destructive-looking operation in the system.

Entity resolution is also the daily work of this tool. A second human on
every merge in a case with three hundred personas is a control that gets
switched off in week two and never switched back on. So it is a per-case
switch, default off, for the unit whose standing orders require it or the
case whose subject makes it worth the friction.
"""
from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = core, public;

CREATE TABLE approval_request (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- NULL for a globally-scoped operation (role.manage, user.manage). The
  -- case-scoped ones carry it so the pending queue can be shown in the
  -- case where the work is happening.
  case_id        uuid REFERENCES "case"(id),
  operation      text NOT NULL,
  -- The exact parameters. Stored as well as hashed so an approver can SEE
  -- what they are approving -- a hash alone would make the second human a
  -- rubber stamp by construction.
  payload        jsonb NOT NULL,
  payload_hash   bytea NOT NULL,
  justification  text NOT NULL,
  requested_by   uuid NOT NULL REFERENCES iam.app_user(id),
  requested_at   timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL,
  state          text NOT NULL DEFAULT 'PENDING',
  decided_by     uuid REFERENCES iam.app_user(id),
  decided_at     timestamptz,
  decision_note  text,
  consumed_at    timestamptz,
  -- What the approved operation produced (a merge id, a purge run id), so
  -- the approval and its consequence are joinable after the fact.
  result_ref     uuid,

  CONSTRAINT approval_state_known
    CHECK (state IN ('PENDING', 'APPROVED', 'REJECTED', 'WITHDRAWN', 'CONSUMED')),
  -- docs/05, word for word: "Two distinct humans, enforced by constraint."
  CONSTRAINT approval_two_distinct_humans
    CHECK (decided_by IS NULL OR decided_by <> requested_by),
  CONSTRAINT approval_decision_complete
    CHECK ((decided_at IS NULL) = (decided_by IS NULL)),
  -- A decided state must actually carry a decision, and a pending one must
  -- not. Without this a row could read PENDING while naming an approver.
  CONSTRAINT approval_state_matches_decision
    CHECK ((state IN ('APPROVED', 'REJECTED', 'CONSUMED')) = (decided_by IS NOT NULL)),
  CONSTRAINT approval_consumed_has_timestamp
    CHECK ((state = 'CONSUMED') = (consumed_at IS NOT NULL)),
  -- "Because I was asked to" is not a justification, and an empty string
  -- is how a mandatory field becomes optional.
  CONSTRAINT approval_justification_present
    CHECK (length(btrim(justification)) > 0),
  CONSTRAINT approval_expiry_sane CHECK (expires_at > requested_at)
);

-- Two analysts requesting the same operation at the same time would give
-- two chances at a yes for one action. Scoped to PENDING, so re-requesting
-- after a rejection is still possible -- and visible in the history, which
-- is the point: shopping for an approver should leave a trail, not be
-- impossible.
CREATE UNIQUE INDEX approval_one_pending_per_payload
    ON approval_request (operation, payload_hash) WHERE state = 'PENDING';
CREATE INDEX approval_case_idx
    ON approval_request (case_id, state, requested_at DESC);
CREATE INDEX approval_requester_idx
    ON approval_request (requested_by, requested_at DESC);
-- The approver's queue: everything awaiting a decision, newest first.
CREATE INDEX approval_pending_idx
    ON approval_request (requested_at DESC) WHERE state = 'PENDING';

-- Per-case policy. Default false: a merge here is a reversible ledger
-- (0027), docs/05 reserves dual control for the genuinely irreversible,
-- and a second human on every entity-resolution decision is a control that
-- gets switched off. On, it is one switch for the case whose subject
-- warrants the friction.
ALTER TABLE "case" ADD COLUMN dual_control_merge boolean NOT NULL DEFAULT false;
""")


def downgrade() -> None:
    run("""
ALTER TABLE core."case" DROP COLUMN dual_control_merge;
DROP TABLE core.approval_request;
""")
