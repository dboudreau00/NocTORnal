"""A detonation that is actually sent to the self-hosted CAPEv2 sandbox,
its second person's sign-off, and the link to its machine result (F14,
2026-09-24).

## What was wrong

`lab.detonation` recorded requests and nothing was ever sent: the route
answered "Recorded only. No sandbox integration exists", and
`submitted_at`, `external_ref` and `report` were never written. The runtime
role held full DML on it, so the record of an overt act could be rewritten
or deleted by the application's own credentials.

## What this adds

1. `mode`: every existing row becomes RECORD_ONLY and is never dispatched
   or changed; SUBMIT rows are the ones the sandbox worker sends.
2. The target a SUBMIT row names, as it stood at the request (provider,
   the configured target key and host, its declared ceiling, the egress
   route, the CAPE network route and its class, the analysis machine and
   its class, the options), so the worker can refuse a send whose target
   changed since.
3. The sign-off in the product: required when the target's exposure is not
   NONE, the network route is LIVE or the machine is LIVE; given by the
   named authoriser, never the requester (CHECKs), within a 72 hour window.
4. The send and its outcome: when it was committed as sent, the archive's
   SHA-256, what the sandbox answered (CONFIRMED, NOT_SENT,
   REJECTED_BY_TARGET, UNCONFIRMED), CAPE's task id and status, the report's
   digest and size, and the machine analysis it produced.
5. A guard: DELETE and TRUNCATE refused, a RECORD_ONLY row never updated,
   the request's fields never changed, set-once columns set once, and the
   status moves only along AWAITING_SIGNOFF to QUEUED, DECLINED, CANCELLED
   or REFUSED; QUEUED to SUBMITTED, REFUSED or CANCELLED; SUBMITTED to
   REPORTED or FAILED. Every other status is terminal.

The five legacy statuses stay legal for RECORD_ONLY rows (a row an
operator set by hand must not fail the upgrade). `GUARDED_TABLES`
declares what the runtime role keeps, and the REVOKE takes DELETE back
(the table predates 0060 and holds it through its GRANT ON ALL TABLES).

## Downgrade

Refuses while any SUBMIT row exists, naming the count: dropping the columns
would erase the record of what left the building. Otherwise it drops what
this added and restores `detonation_status_known` exactly as 0031 wrote it.
"""
from __future__ import annotations

from alembic import op

revision = "0103"
down_revision = "0102"
branch_labels = None
depends_on = None

APP_ROLE = "noctornal_app"

GUARDED_TABLES = {
    "lab.detonation": ("SELECT", "INSERT", "UPDATE"),
}

LEGACY_STATUSES = ("PENDING", "AUTHORISED", "SUBMITTED", "REPORTED", "REFUSED")
SUBMIT_STATUSES = ("AWAITING_SIGNOFF", "QUEUED", "SUBMITTED", "REPORTED",
                   "FAILED", "REFUSED", "DECLINED", "CANCELLED")
IN_FLIGHT = ("AWAITING_SIGNOFF", "QUEUED", "SUBMITTED")
OUTCOMES = ("CONFIRMED", "NOT_SENT", "REJECTED_BY_TARGET", "UNCONFIRMED")

#: The fields a request fixes. The guard refuses any change to them.
REQUEST_FIELDS = (
    "id", "sample_id", "target", "exposure_level", "authorised_by",
    "authorisation_note", "requested_by", "requested_at", "mode", "provider",
    "target_key", "target_host", "target_ceiling", "egress_route",
    "network_route", "route_class", "machine", "machine_class", "options",
    "signoff_required", "signoff_expires_at")

#: Set once, from NULL, and never changed after.
SET_ONCE = (
    "signed_off_by", "signed_off_at", "signoff_decision", "signoff_note",
    "external_ref", "classification_sent", "submitted_sha256",
    "submit_outcome", "report_sha256", "report_bytes", "analysis_id",
    "cancelled_by", "submitted_at", "completed_at", "report")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _tuple(prefix: str, names: tuple[str, ...]) -> str:
    return "(" + ", ".join(f"{prefix}.{n}" for n in names) + ")"


_SET_ONCE_CHECKS = "\n".join(
    f"  IF OLD.{c} IS NOT NULL AND NEW.{c} IS DISTINCT FROM OLD.{c} THEN\n"
    f"    RAISE EXCEPTION 'detonation.{c} is set once';\n"
    f"  END IF;" for c in SET_ONCE)

UPGRADE_SQL = f"""
SET search_path = lab, core, public;

ALTER TABLE detonation
  ADD COLUMN mode text NOT NULL DEFAULT 'RECORD_ONLY',
  ADD COLUMN provider text,
  ADD COLUMN target_key text,
  ADD COLUMN target_host text,
  ADD COLUMN target_ceiling core.tlp,
  ADD COLUMN egress_route text,
  ADD COLUMN network_route text,
  ADD COLUMN route_class text,
  ADD COLUMN machine text,
  ADD COLUMN machine_class text,
  ADD COLUMN options jsonb NOT NULL DEFAULT '{{}}',
  ADD COLUMN signoff_required boolean NOT NULL DEFAULT false,
  ADD COLUMN signoff_expires_at timestamptz,
  ADD COLUMN signed_off_by uuid REFERENCES iam.app_user(id),
  ADD COLUMN signed_off_at timestamptz,
  ADD COLUMN signoff_decision text,
  ADD COLUMN signoff_note text,
  ADD COLUMN classification_sent core.tlp,
  ADD COLUMN egress_reason text,
  ADD COLUMN submitted_sha256 bytea,
  ADD COLUMN submit_outcome text,
  ADD COLUMN external_status text,
  ADD COLUMN attempts integer NOT NULL DEFAULT 0,
  ADD COLUMN last_polled_at timestamptz,
  ADD COLUMN last_error text,
  ADD COLUMN completed_at timestamptz,
  ADD COLUMN report_sha256 bytea,
  ADD COLUMN report_bytes bigint,
  ADD COLUMN analysis_id uuid REFERENCES lab.sample_analysis(id),
  ADD COLUMN cancelled_by uuid REFERENCES iam.app_user(id),
  DROP CONSTRAINT detonation_status_known,
  ADD CONSTRAINT detonation_mode_known CHECK (mode IN ('RECORD_ONLY', 'SUBMIT')),
  ADD CONSTRAINT detonation_status_by_mode
    CHECK ((mode = 'RECORD_ONLY' AND status IN ({_in(LEGACY_STATUSES)}))
        OR (mode = 'SUBMIT' AND status IN ({_in(SUBMIT_STATUSES)}))),
  ADD CONSTRAINT detonation_submit_names_target
    CHECK (mode = 'RECORD_ONLY'
           OR num_nulls(provider, target_key, target_host, target_ceiling,
                        egress_route, network_route, route_class) = 0),
  ADD CONSTRAINT detonation_route_class_known
    CHECK (route_class IS NULL OR route_class IN ('ISOLATED', 'LIVE')),
  ADD CONSTRAINT detonation_machine_classed
    CHECK ((machine IS NULL) = (machine_class IS NULL)
           AND (machine_class IS NULL OR machine_class IN ('ISOLATED', 'LIVE'))),
  ADD CONSTRAINT detonation_ceiling_leaves
    CHECK (target_ceiling IS NULL OR target_ceiling IN ('CLEAR', 'GREEN', 'AMBER')),
  ADD CONSTRAINT detonation_signoff_when_exposed
    CHECK (mode = 'RECORD_ONLY'
           OR signoff_required = (exposure_level <> 'NONE'
                                  OR route_class = 'LIVE'
                                  OR coalesce(machine_class = 'LIVE', false))),
  ADD CONSTRAINT detonation_signoff_names_an_authoriser
    CHECK (NOT signoff_required
           OR (authorised_by IS NOT NULL AND authorisation_note IS NOT NULL)),
  ADD CONSTRAINT detonation_signoff_window
    CHECK (signoff_required = (signoff_expires_at IS NOT NULL)),
  ADD CONSTRAINT detonation_signoff_complete
    CHECK ((signed_off_at IS NULL) = (signed_off_by IS NULL)
           AND (signed_off_at IS NULL) = (signoff_decision IS NULL)),
  ADD CONSTRAINT detonation_signoff_decision_known
    CHECK (signoff_decision IS NULL OR signoff_decision IN ('APPROVED', 'DECLINED')),
  ADD CONSTRAINT detonation_signoff_by_the_named_authoriser
    CHECK (signed_off_by IS NULL OR signed_off_by = authorised_by),
  ADD CONSTRAINT detonation_two_people
    CHECK (mode = 'RECORD_ONLY' OR authorised_by IS DISTINCT FROM requested_by),
  ADD CONSTRAINT detonation_queued_only_when_signed
    CHECK (status NOT IN ('QUEUED', 'SUBMITTED', 'REPORTED', 'FAILED')
           OR mode = 'RECORD_ONLY' OR NOT signoff_required
           OR signoff_decision = 'APPROVED'),
  ADD CONSTRAINT detonation_declined_is_signed
    CHECK (status <> 'DECLINED' OR signoff_decision = 'DECLINED'),
  ADD CONSTRAINT detonation_sent_is_dated
    CHECK (mode = 'RECORD_ONLY'
           OR status NOT IN ('SUBMITTED', 'REPORTED', 'FAILED')
           OR submitted_at IS NOT NULL),
  ADD CONSTRAINT detonation_submit_outcome_known
    CHECK (submit_outcome IS NULL OR submit_outcome IN ({_in(OUTCOMES)})),
  ADD CONSTRAINT detonation_confirmed_has_ref
    CHECK (mode = 'RECORD_ONLY'
           OR (submit_outcome IS NOT DISTINCT FROM 'CONFIRMED')
              = (external_ref IS NOT NULL)),
  ADD CONSTRAINT detonation_reported_is_complete
    CHECK (status <> 'REPORTED' OR mode = 'RECORD_ONLY'
           OR (submit_outcome = 'CONFIRMED' AND report_sha256 IS NOT NULL
               AND completed_at IS NOT NULL AND analysis_id IS NOT NULL)),
  ADD CONSTRAINT detonation_attempts_non_negative CHECK (attempts >= 0);

COMMENT ON COLUMN detonation.mode IS
  'RECORD_ONLY: a request recorded and never sent (every row before 0103). '
  'SUBMIT: sent by scripts/sandbox_dispatch.py to the configured sandbox.';

-- One request per sample and target in flight. The service inserts plainly
-- and catches the unique violation.
CREATE UNIQUE INDEX detonation_one_in_flight ON detonation (sample_id, target_key)
  WHERE mode = 'SUBMIT' AND status IN ({_in(IN_FLIGHT)});
CREATE INDEX detonation_due_idx ON detonation (status, requested_at)
  WHERE mode = 'SUBMIT' AND status IN ({_in(IN_FLIGHT)});
CREATE INDEX detonation_signoff_idx ON detonation (authorised_by)
  WHERE status = 'AWAITING_SIGNOFF';
CREATE INDEX detonation_analysis_idx ON detonation (analysis_id)
  WHERE analysis_id IS NOT NULL;

CREATE FUNCTION lab.guard_detonation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
    RAISE EXCEPTION 'a detonation is the record of an overt act and is never deleted';
  END IF;
  IF OLD.mode = 'RECORD_ONLY' THEN
    RAISE EXCEPTION 'a record-only detonation request is never changed';
  END IF;
  IF {_tuple("NEW", REQUEST_FIELDS)} IS DISTINCT FROM {_tuple("OLD", REQUEST_FIELDS)} THEN
    RAISE EXCEPTION 'what a detonation request asked for never changes';
  END IF;
  IF OLD.status NOT IN ({_in(IN_FLIGHT)}) THEN
    RAISE EXCEPTION 'a detonation that is % is finished and never changes', OLD.status;
  END IF;
  IF NEW.status IS DISTINCT FROM OLD.status AND NOT (
       (OLD.status = 'AWAITING_SIGNOFF'
          AND NEW.status IN ('QUEUED', 'DECLINED', 'CANCELLED', 'REFUSED'))
    OR (OLD.status = 'QUEUED'
          AND NEW.status IN ('SUBMITTED', 'REFUSED', 'CANCELLED'))
    OR (OLD.status = 'SUBMITTED' AND NEW.status IN ('REPORTED', 'FAILED'))) THEN
    RAISE EXCEPTION 'a detonation cannot move from % to %', OLD.status, NEW.status;
  END IF;
{_SET_ONCE_CHECKS}
  RETURN NEW;
END $$;
CREATE TRIGGER detonation_guard BEFORE UPDATE OR DELETE ON detonation
  FOR EACH ROW EXECUTE FUNCTION lab.guard_detonation();
CREATE TRIGGER detonation_no_truncate BEFORE TRUNCATE ON detonation
  FOR EACH STATEMENT EXECUTE FUNCTION lab.guard_detonation();
"""

REVOKE_SQL = f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('REVOKE DELETE ON lab.detonation FROM %I', '{APP_ROLE}');
  END IF;
END
$noc$;
"""

#: Given back on the way down, so the role is left as 0060 made it.
GRANT_BACK_SQL = f"""
DO $noc$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN
    EXECUTE format('GRANT DELETE ON lab.detonation TO %I', '{APP_ROLE}');
  END IF;
END
$noc$;
"""

COUNT_SQL = "SELECT count(*) FROM lab.detonation WHERE mode = 'SUBMIT'"


def downgrade_refusal(n: int) -> str:
    return (f"refusing to downgrade 0103: {n} "
            f"{'detonation was' if n == 1 else 'detonations were'} requested "
            f"for sending to a sandbox. Dropping the columns would erase the "
            f"record of what left the building. Stay at this revision.")


def run(sql: str) -> None:
    op.get_bind().connection.driver_connection.execute(sql)


def query(sql: str) -> list:
    return op.get_bind().connection.driver_connection.execute(sql).fetchall()


def upgrade() -> None:
    run(UPGRADE_SQL)
    run(REVOKE_SQL)


def downgrade() -> None:
    n = query(COUNT_SQL)[0][0]
    if n:
        raise RuntimeError(downgrade_refusal(n))
    run(GRANT_BACK_SQL)
    run(f"""
SET search_path = lab, core, public;
DROP TRIGGER detonation_no_truncate ON detonation;
DROP TRIGGER detonation_guard ON detonation;
DROP FUNCTION lab.guard_detonation();
DROP INDEX detonation_analysis_idx;
DROP INDEX detonation_signoff_idx;
DROP INDEX detonation_due_idx;
DROP INDEX detonation_one_in_flight;
ALTER TABLE detonation
  DROP CONSTRAINT detonation_attempts_non_negative,
  DROP CONSTRAINT detonation_reported_is_complete,
  DROP CONSTRAINT detonation_confirmed_has_ref,
  DROP CONSTRAINT detonation_submit_outcome_known,
  DROP CONSTRAINT detonation_sent_is_dated,
  DROP CONSTRAINT detonation_declined_is_signed,
  DROP CONSTRAINT detonation_queued_only_when_signed,
  DROP CONSTRAINT detonation_two_people,
  DROP CONSTRAINT detonation_signoff_by_the_named_authoriser,
  DROP CONSTRAINT detonation_signoff_decision_known,
  DROP CONSTRAINT detonation_signoff_complete,
  DROP CONSTRAINT detonation_signoff_window,
  DROP CONSTRAINT detonation_signoff_names_an_authoriser,
  DROP CONSTRAINT detonation_signoff_when_exposed,
  DROP CONSTRAINT detonation_ceiling_leaves,
  DROP CONSTRAINT detonation_machine_classed,
  DROP CONSTRAINT detonation_route_class_known,
  DROP CONSTRAINT detonation_submit_names_target,
  DROP CONSTRAINT detonation_status_by_mode,
  DROP CONSTRAINT detonation_mode_known,
  DROP COLUMN cancelled_by,
  DROP COLUMN analysis_id,
  DROP COLUMN report_bytes,
  DROP COLUMN report_sha256,
  DROP COLUMN completed_at,
  DROP COLUMN last_error,
  DROP COLUMN last_polled_at,
  DROP COLUMN attempts,
  DROP COLUMN external_status,
  DROP COLUMN submit_outcome,
  DROP COLUMN submitted_sha256,
  DROP COLUMN egress_reason,
  DROP COLUMN classification_sent,
  DROP COLUMN signoff_note,
  DROP COLUMN signoff_decision,
  DROP COLUMN signed_off_at,
  DROP COLUMN signed_off_by,
  DROP COLUMN signoff_expires_at,
  DROP COLUMN signoff_required,
  DROP COLUMN options,
  DROP COLUMN machine_class,
  DROP COLUMN machine,
  DROP COLUMN route_class,
  DROP COLUMN network_route,
  DROP COLUMN egress_route,
  DROP COLUMN target_ceiling,
  DROP COLUMN target_host,
  DROP COLUMN target_key,
  DROP COLUMN provider,
  DROP COLUMN mode,
  ADD CONSTRAINT detonation_status_known
    CHECK (status IN ({_in(LEGACY_STATUSES)}));
""")
