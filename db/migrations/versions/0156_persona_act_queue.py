"""The persona act queue: what the API asks the collector to do (ROADMAP-
REMAINING "A collector process", 2026-10-02).

## Why a queue, and why Postgres

Until 2026-10-02 every attended persona act (looking a Telegram chat up,
joining it, checking or marking membership, rebinding it, a Poll now of a
source a persona reads) ran inside the API process on the request thread,
and the API held the key that opens every persona credential. The owner
decided to move everything that needs a persona credential into a
collector process that alone holds the persona key, which reverses decision
30's "no worker process and no queue" for this one purpose, on purpose. The
API now writes the act here and the collector runs it. Postgres is the
queue: no broker, no new service beyond the collector itself; a claim is
`FOR UPDATE SKIP LOCKED`, and `pg_notify` wakes the collector.

## collect.persona_act

One row per act asked for. It carries NO secret: the kind, the source when
there is one, the request's own parameters (a chat reference, a note, a
reason), who asked, from which session, when their second factor was last
satisfied (the collector re-asks the global gate with it), and the label
the act is held at: the source's classification, or for a new chat the
label asked for. `dedupe_key` (a sha256 of the kind, the source and the parameters; the
source since 2026-10-03)
makes a double click one act: one live (PENDING or RUNNING) act per
requester, kind and key. `expires_at` bounds how long an attended act may
wait to start, and `persona_act_window` caps it at an hour after
`requested_at` (2026-10-03), whatever the inserting role wrote. The
request role's INSERT policy also pins the columns the collector owns
(`attempts` zero, no claimant, no claim time, no result), so what it
queues is a fresh act and nothing else. `status` moves PENDING to RUNNING (a claim) and on to DONE,
REFUSED or FAILED, or back to PENDING when the persona was busy; PENDING
may instead end EXPIRED or CANCELLED. A finished row never changes again
(`collect.guard_persona_act`), and its `result` is the answer the route
would have given: the body, or the problem's status, title and sentence,
never a credential.

## Row-level security (decided 2026-10-02, the CUSTOM_ACT template)

Under policy, because a row names a source and carries a request's own
words at that source's label. The request role sees an act only when it
asked for it and the act's label is within its case-less ceiling (an act
belongs to no case, as a source does not), and may INSERT only such a row,
PENDING. It has no UPDATE or DELETE policy, so it can neither claim, finish
nor forge an outcome: the collector and the inline runner write status as
the PERSONA_ACTS system purpose. `noctornal_egress` holds no privilege
here; the proxy reads the persona's own state, as before.

## Privileges

Both runtime roles keep SELECT, INSERT and UPDATE and lose the DELETE the
default privileges handed them (`GUARDED_TABLES`): an act asked for is a
record of who asked for what, and is never deleted. The guard refuses a
DELETE and a TRUNCATE from any role, the owner's included.

## Downgrade

Refuses while any act is PENDING or RUNNING (work in flight would vanish
without an outcome). Otherwise drops the table and its guard: the acts'
outcomes are also in the audit log (PERSONA_ACT_QUEUED and
PERSONA_ACT_FINISHED, and each act's own events), which outlives it.
"""
from alembic import op

revision = "0156"
down_revision = "0155"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"
WORKER_ROLE = "noctornal_worker"

#: The privileges each runtime role keeps (test_app_role_privileges_pg).
GUARDED_TABLES = {
    "collect.persona_act": ("SELECT", "INSERT", "UPDATE"),
}

#: The longest an act may wait to start, in seconds: persona_acts.MAX_TTL_S,
#: which test_persona_act_queue_pg holds equal. The window CHECK caps
#: expires_at by it from requested_at, because the request role writes both
#: (verify:g38, 2026-10-03: an INSERT could otherwise ask for an act that
#: never expires; the collector's claim caps requested_at by it too).
MAX_ACT_WINDOW_S = 3600

_CLR = "(SELECT iam.rls_clearance())"
_ACTOR = "(SELECT iam.rls_actor())"

#: The read and enqueue policies, frozen text.
POLICY_SELECT = f"requested_by = {_ACTOR} AND classification <= {_CLR}"
#: A fresh act only (verify:g38, 2026-10-03): PENDING, never claimed, never
#: attempted, no outcome. The request role writes the row, so the columns
#: the collector owns are pinned to what an unclaimed act holds.
POLICY_INSERT = (f"requested_by = {_ACTOR} AND classification <= {_CLR} "
                 f"AND status = 'PENDING' AND attempts = 0 "
                 f"AND claimed_by IS NULL AND claimed_at IS NULL "
                 f"AND result IS NULL")

UPGRADE_SQL = f"""
CREATE TABLE collect.persona_act (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind            text NOT NULL CONSTRAINT persona_act_kind CHECK (kind IN (
                    'TELEGRAM_RESOLVE', 'TELEGRAM_JOIN', 'TELEGRAM_MEMBERSHIP',
                    'TELEGRAM_MARK_MEMBER', 'TELEGRAM_REBIND', 'SOURCE_POLL')),
  source_id       uuid REFERENCES collect.source(id),
  classification  core.tlp NOT NULL,
  params          jsonb NOT NULL DEFAULT '{{}}'::jsonb
                    CONSTRAINT persona_act_params CHECK (
                      jsonb_typeof(params) = 'object'
                      AND octet_length(params::text) <= 8192),
  dedupe_key      text NOT NULL
                    CONSTRAINT persona_act_dedupe CHECK (dedupe_key ~ '^[0-9a-f]{{64}}$'),
  requested_by    uuid NOT NULL REFERENCES iam.app_user(id),
  session_id      uuid,
  mfa_satisfied_at timestamptz,
  requested_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  not_before      timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at      timestamptz NOT NULL,
  status          text NOT NULL DEFAULT 'PENDING'
                    CONSTRAINT persona_act_status CHECK (status IN (
                      'PENDING', 'RUNNING', 'DONE', 'REFUSED', 'FAILED',
                      'EXPIRED', 'CANCELLED')),
  attempts        integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  claimed_by      text CHECK (claimed_by IS NULL OR length(claimed_by) <= 120),
  claimed_at      timestamptz,
  finished_at     timestamptz,
  result          jsonb,
  CONSTRAINT persona_act_finished CHECK (
    (status IN ('PENDING', 'RUNNING')) = (finished_at IS NULL)),
  CONSTRAINT persona_act_claimed CHECK (status <> 'RUNNING' OR claimed_at IS NOT NULL),
  CONSTRAINT persona_act_window CHECK (
    expires_at > requested_at
    AND expires_at <= requested_at + interval '{MAX_ACT_WINDOW_S} seconds')
);

COMMENT ON TABLE collect.persona_act IS
  'Attended persona acts the API asked the collector to run (A collector process, 2026-10-02). No secret.';

CREATE UNIQUE INDEX persona_act_one_live
  ON collect.persona_act (requested_by, kind, dedupe_key)
  WHERE status IN ('PENDING', 'RUNNING');
CREATE INDEX persona_act_queue
  ON collect.persona_act (not_before) WHERE status = 'PENDING';
CREATE INDEX persona_act_running
  ON collect.persona_act (claimed_at) WHERE status = 'RUNNING';
CREATE INDEX persona_act_requester
  ON collect.persona_act (requested_by, requested_at DESC);

-- Compares the row with itself and reads no table.
CREATE FUNCTION collect.guard_persona_act() RETURNS trigger
  LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION USING MESSAGE =
      'a persona act is a record of who asked for what, and is never deleted',
      ERRCODE = '42501';
  END IF;
  IF OLD.status NOT IN ('PENDING', 'RUNNING') THEN
    RAISE EXCEPTION USING MESSAGE =
      'a finished persona act is a record and never changes', ERRCODE = '42501';
  END IF;
  IF NEW.id <> OLD.id OR NEW.kind <> OLD.kind
     OR NEW.source_id IS DISTINCT FROM OLD.source_id
     OR NEW.classification <> OLD.classification
     OR NEW.params <> OLD.params OR NEW.dedupe_key <> OLD.dedupe_key
     OR NEW.requested_by <> OLD.requested_by
     OR NEW.session_id IS DISTINCT FROM OLD.session_id
     OR NEW.mfa_satisfied_at IS DISTINCT FROM OLD.mfa_satisfied_at
     OR NEW.requested_at <> OLD.requested_at OR NEW.expires_at <> OLD.expires_at THEN
    RAISE EXCEPTION USING MESSAGE =
      'what a persona act asked for never changes once it is asked', ERRCODE = '42501';
  END IF;
  IF NOT ((OLD.status = 'PENDING' AND NEW.status IN ('PENDING', 'RUNNING', 'EXPIRED', 'CANCELLED'))
       OR (OLD.status = 'RUNNING' AND NEW.status IN ('PENDING', 'RUNNING', 'DONE', 'REFUSED', 'FAILED'))) THEN
    RAISE EXCEPTION USING MESSAGE =
      'a persona act moves ' || OLD.status || ' to ' || NEW.status || ', which is not a step it takes',
      ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER guard_persona_act BEFORE UPDATE OR DELETE ON collect.persona_act
  FOR EACH ROW EXECUTE FUNCTION collect.guard_persona_act();
CREATE TRIGGER persona_act_no_truncate BEFORE TRUNCATE ON collect.persona_act
  FOR EACH STATEMENT EXECUTE FUNCTION collect.guard_persona_act();

ALTER TABLE collect.persona_act ENABLE ROW LEVEL SECURITY;
CREATE POLICY rls_read ON collect.persona_act FOR SELECT USING ({POLICY_SELECT});
CREATE POLICY rls_enqueue ON collect.persona_act FOR INSERT WITH CHECK ({POLICY_INSERT});

DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON collect.persona_act FROM %I', '{APP_ROLE}');
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{WORKER_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON collect.persona_act FROM %I', '{WORKER_ROLE}');
  END IF;
END
$noc$;
"""

DOWNGRADE_SQL = """
DO $noc$
DECLARE n bigint;
BEGIN
  SELECT count(*) INTO n FROM collect.persona_act
   WHERE status IN ('PENDING', 'RUNNING');
  IF n > 0 THEN
    RAISE EXCEPTION USING MESSAGE =
      'refusing to downgrade 0156: ' || n
      || CASE WHEN n = 1 THEN ' persona act is' ELSE ' persona acts are' END
      || ' still pending or running, and dropping the queue would lose '
      || CASE WHEN n = 1 THEN 'it' ELSE 'them' END || ' without an '
      || 'outcome; stop the API, let the collector finish what is pending or '
      || 'cancel it, '
      || 'then downgrade';
  END IF;
END
$noc$;
DROP POLICY rls_enqueue ON collect.persona_act;
DROP POLICY rls_read ON collect.persona_act;
DROP TABLE collect.persona_act;
DROP FUNCTION collect.guard_persona_act();
"""


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def upgrade() -> None:
    run(UPGRADE_SQL)


def downgrade() -> None:
    run(DOWNGRADE_SQL)
