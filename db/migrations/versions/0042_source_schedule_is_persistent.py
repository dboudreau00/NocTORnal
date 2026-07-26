"""The polling schedule stops being a per-process guess.

docs/17 F15(i). Two defects with one cause: the collector's timing lived
in memory, and the process it lived in is created per request.

## Jitter that was not jitter

`due_sources()` computed `next_due_at(last_ok, interval, jitter)` freshly
on every call, so the "next" time was re-rolled every time anybody looked.
The realised interval therefore depended on how often the scheduler polls
rather than on the interval, and frequent polling collapses the variance
toward the floor -- a regular cadence, which is the exact signature jitter
exists to avoid. docs/04 is blunt about the cost: "a collector that polls
exactly every 300 seconds is one a competent forum admin picks out of an
access log in an afternoon, and a burnt persona is expensive and slow to
replace."

Rolling once and STORING it is the whole fix. `next_due_at` also becomes
answerable, which the module docstring already claimed: "why did this poll
at 04:12" should have an answer, and it did not.

## A rate limit that never fired

`RateLimiter` kept `{source_id: last_request_time}` on the instance, and
`CollectionService` is constructed per request, so the dict was always
empty and `max_rps` never spaced anything. docs/04 ties `max_rps` directly
to not burning personas.

docs/04 asks for this globally through Redis and that is still the right
end state -- this makes the state durable and shared, which is the part
that matters, and leaves the Redis token bucket as an optimisation rather
than a correctness fix.
"""
from alembic import op

revision = "0042"
down_revision = "0041"
branch_labels = None
depends_on = None


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run("""
SET search_path = collect, core, public;

-- Rolled ONCE, when a run finishes, and read as-is thereafter.
ALTER TABLE source ADD COLUMN next_due_at timestamptz;
COMMENT ON COLUMN source.next_due_at IS
  'When this source is next due. Rolled once with jitter after each run; '
  're-rolling on read is what made the cadence regular -- docs/17 F15(i).';

-- Every attempt, not every success: the rate limit exists to space
-- REQUESTS, and a failed request cost a request.
ALTER TABLE source ADD COLUMN last_request_at timestamptz;
COMMENT ON COLUMN source.last_request_at IS
  'Last outbound attempt, successful or not. The per-source max_rps gap '
  'is measured from here so it survives the process.';

-- A source that has never been polled is due NOW rather than one interval
-- from now: waiting the interval first means a newly-added source sits
-- idle for its whole period and somebody concludes the collector is
-- broken, which is how a working system gets "fixed".
UPDATE source
   SET next_due_at = CASE
         WHEN last_ok_at IS NULL THEN now()
         ELSE last_ok_at + (poll_interval_s || ' seconds')::interval
       END;

CREATE INDEX source_due_idx ON source (next_due_at) WHERE is_active;
""")


def downgrade() -> None:
    run("""
DROP INDEX collect.source_due_idx;
ALTER TABLE collect.source DROP COLUMN last_request_at;
ALTER TABLE collect.source DROP COLUMN next_due_at;
""")
