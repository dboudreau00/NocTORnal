"""An approval request is fixed once it is raised, decided once, and spent
once (F9, 2026-09-24).

## What was wrong

`core.approval_request` (0028) carries CHECK constraints and nothing else.
A CHECK sees one row at a time, so it can say a decided row names its
decider; it cannot say the decider was not changed afterwards. Nothing in
the database stopped the runtime role rewriting `payload`, `decided_by` or
`state` on a row that had already been decided, or putting an APPROVED row
back to APPROVED after it was CONSUMED. The code never does any of that;
the point is that the two-person policy (the next revision) reads these
rows from a trigger, and a trigger that trusts a row anybody could rewrite
is a check on nothing.

## What this adds

`core.guard_approval_request()`, BEFORE INSERT OR UPDATE, row level:

- a request is INSERTED pending and undecided;
- what it asks for (operation, case, payload and its hash, justification,
  requester) never changes;
- `requested_at` and `expires_at` only stay or move EARLIER: a request
  never gains time (the expiry tests back-date both, which is the one
  direction that cannot extend a signature);
- the state moves PENDING to APPROVED, REJECTED or WITHDRAWN, or APPROVED
  to CONSUMED, and nowhere else;
- the decision (`decided_by`, `decided_at`, `decision_note`) is written
  once, on PENDING to APPROVED or REJECTED, and `decided_at` is the
  database's `now()` (2026-09-24: the next revision
  measures the countersigner's seven-day window back from `decided_at`,
  so that end of the window has to be a time the database witnessed, not
  one the API process chose);
- `consumed_at` is written once, on APPROVED to CONSUMED, and equals
  `now()`, so "consumed in this transaction" is a question the database
  can answer;
- `result_ref` is written once, from NULL, and only on a CONSUMED row.

Every RAISE is one line: `safe_detail` forwards only the first line of a
P0001 to the client.

DELETE is not guarded. Test teardowns delete approval rows in eleven
suites, deleting a pending request is a denial of service rather than a
forgery, and every approval a two-person policy change spends is held by
that ledger's foreign key.

## Downgrade

Drops the trigger and its function; the rows are untouched.
"""
from alembic import op

revision = "0074"
down_revision = "0073"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
CREATE FUNCTION core.guard_approval_request() RETURNS trigger
LANGUAGE plpgsql AS $f$
DECLARE
  deciding boolean;
  consuming boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.state IS DISTINCT FROM 'PENDING'
       OR NEW.decided_by IS NOT NULL OR NEW.decided_at IS NOT NULL
       OR NEW.decision_note IS NOT NULL OR NEW.consumed_at IS NOT NULL
       OR NEW.result_ref IS NOT NULL THEN
      RAISE EXCEPTION 'an approval request is created pending and undecided';
    END IF;
    RETURN NEW;
  END IF;

  IF (NEW.operation, NEW.case_id, NEW.payload, NEW.payload_hash,
      NEW.justification, NEW.requested_by)
     IS DISTINCT FROM
     (OLD.operation, OLD.case_id, OLD.payload, OLD.payload_hash,
      OLD.justification, OLD.requested_by) THEN
    RAISE EXCEPTION 'what an approval request asks for is fixed when it is raised: raise a new one';
  END IF;

  IF NEW.requested_at > OLD.requested_at OR NEW.expires_at > OLD.expires_at THEN
    RAISE EXCEPTION 'an approval request never gains time: raise a new one';
  END IF;

  IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
       (OLD.state = 'PENDING' AND NEW.state IN ('APPROVED', 'REJECTED', 'WITHDRAWN'))
    OR (OLD.state = 'APPROVED' AND NEW.state = 'CONSUMED')) THEN
    RAISE EXCEPTION 'an approval request moves from pending to decided or withdrawn, and from approved to consumed, and never back';
  END IF;

  deciding := OLD.state = 'PENDING' AND NEW.state IN ('APPROVED', 'REJECTED');
  IF (NEW.decided_by, NEW.decided_at, NEW.decision_note)
     IS DISTINCT FROM (OLD.decided_by, OLD.decided_at, OLD.decision_note)
     AND NOT deciding THEN
    RAISE EXCEPTION 'a decision on an approval request is made once';
  END IF;
  IF deciding AND NEW.decided_at IS DISTINCT FROM now() THEN
    RAISE EXCEPTION 'a decision on an approval request is recorded at the time it is made';
  END IF;

  consuming := OLD.state = 'APPROVED' AND NEW.state = 'CONSUMED';
  IF NEW.consumed_at IS DISTINCT FROM OLD.consumed_at AND NOT consuming THEN
    RAISE EXCEPTION 'an approval is spent once';
  END IF;
  IF consuming AND NEW.consumed_at IS DISTINCT FROM now() THEN
    RAISE EXCEPTION 'an approval is spent at the time it is used';
  END IF;

  IF NEW.result_ref IS DISTINCT FROM OLD.result_ref
     AND (OLD.result_ref IS NOT NULL OR NEW.state IS DISTINCT FROM 'CONSUMED') THEN
    RAISE EXCEPTION 'what an approval produced is recorded once, after it is spent';
  END IF;
  RETURN NEW;
END
$f$;

CREATE TRIGGER approval_request_frozen
  BEFORE INSERT OR UPDATE ON core.approval_request
  FOR EACH ROW EXECUTE FUNCTION core.guard_approval_request();

COMMENT ON FUNCTION core.guard_approval_request() IS
  'An approval request is inserted pending, what it asks for never changes, '
  'it is decided once at now(), spent once at now(), and never gains time '
  '(migration approval_request_frozen, F9 2026-09-24).';
""")


def downgrade() -> None:
    run("""
DROP TRIGGER IF EXISTS approval_request_frozen ON core.approval_request;
DROP FUNCTION IF EXISTS core.guard_approval_request();
""")
