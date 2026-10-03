"""The deployment-wide sweep of collected documents (docs/17 F30, 2026-10-02).

A Telegram group's messages and a forum's posts are collected documents. They
carry a retention clock (CHAT_EXPORT and the other rules), the purge honours
every legal hold on a document and on every case that cites it, and until now
nothing ran that purge over them: the governance purge route is case-scoped
and a collected document belongs to no case, and no script called
`RetentionService.purge_due(case_id=None)`. So a group chat's third-party
messages outlived their clock for as long as nobody decided how a sweep is
run, by whom and under which authority (docs/16 L4).

## What this module decides (docs/00 decisions 157 to 159)

**It is run by an operator, never by the cron loop.** `scripts/
retention_sweep.py` is dry by default, and a real run needs an explicit flag
AND an authority reference declared in the environment. That is the L1
pattern (`samples.policy_declared`): recorded, refused when missing or a
placeholder, never verified, because the software cannot check that the
document the reference names exists or says what the operator believes. The
retention module's own rule stands: "a purge job that runs itself on a timer
nobody watches is how data disappears on a Sunday". The operator documentation
(infra/production/README.md) says how to schedule it, and a test holds the
production cron loop to not containing it.

**It sweeps collected documents and nothing else.** `purge_due(case_id=None)`
also reaches every case's exhibits, ingest records, lookups and dead letters,
and writes their tombstones under no case: the cross-case destruction
`test_a_purge_cannot_be_run_without_naming_a_case` was written against.
Exhibits are behind a COMPLIANCE object lock and the case-scoped route's
preview digest and step-up; a document is the one family with no other way in.
The family set is `SWEPT_KINDS`, one line, so widening it is a decision with a
diff. Dead letters are the other family with no case and no sweep; they are
not covered here (see integration notes).

**It does not fork the purge.** The act is `RetentionService.purge_due`, with
its hold predicate, its locks, its markup deletion and its tombstone, called
with `kinds=SWEPT_KINDS`. This module adds the declaration, the named actor,
the loop over a backlog bigger than one pass, and one audit row of counts.

**A named account answers for it.** `core.purge_tombstone.purged_by` is a
real user, so the run names an active account that holds `retention.purge`.
That is a declaration too, not an authentication: the script runs on the
server with the system role, where a signed-in session has no meaning, and
step-up (a property of a session) is replaced by the three things a script
can enforce: the flag, the declared authority and a named account, all
recorded in the tombstones and in the one `RETENTION_SWEEP` event.
"""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api.retention import RetentionError, RetentionService
from noctornal_api.wording import agree, count_of

#: The declaration a real run needs: a reference an auditor can follow (a
#: retention schedule, counsel's instruction, a ticket). Read from the
#: environment of the one run and deliberately NOT a line of secrets.env,
#: which every container receives: a standing authority in a file every
#: service reads is an authority nobody declared for this run.
AUTHORITY_ENV = "NOCTORNAL_RETENTION_SWEEP_AUTHORITY"
#: The account that answers for a run, when `--actor` is not given.
ACTOR_ENV = "NOCTORNAL_RETENTION_SWEEP_ACTOR"
#: The audit action of one real run's summary: counts and the reference, no
#: content. The per-pass destruction is `PURGE_EXECUTED` and its tombstone.
EVENT = "RETENTION_SWEEP"
PERMISSION = "retention.purge"

#: The `DueItem.object_type` values this sweep may destroy. Collected
#: documents only; see the module docstring for why that is the decision.
SWEPT_KINDS = frozenset({"document"})

#: One pass destroys at most what `RetentionService.due` lists (500), so a
#: group chat with tens of thousands of expired messages needs many passes.
#: The cap is a backstop against a loop that cannot make progress, not a
#: budget: a run that meets it says so and exits 1, and the next run
#: continues.
DEFAULT_MAX_PASSES = 100

#: How long an unheld document may sit past its clock before the readiness
#: row fails. Weekly is the longest schedule the operator documentation
#: suggests, so a document a day or six past its clock under a weekly sweep
#: is the schedule working, not a gap.
OVERDUE_AFTER = timedelta(days=7)

#: Written into `purge_due`'s dry run, which needs an actor argument and
#: writes none of it (the only write that reads it is the Jira note, and a
#: dry run records nothing).
_NO_ACTOR = UUID(int=0)

#: A value of this shape was typed to make the refusal go away, not read off
#: a document (docs/16 L1: "true is what somebody types to make an error go
#: away and a reference is what somebody has to actually possess").
_PLACEHOLDER_MARKERS = ("replace-me", "changeme", "change-me", "placeholder")
_NOT_A_REFERENCE = frozenset({
    "true", "false", "yes", "no", "y", "n", "1", "0", "on", "off", "ok",
    "none", "null", "n/a", "na", "tbd", "todo", "xxx"})
_MIN_REFERENCE = 5


class SweepRefused(Exception):
    """The sweep will not run as asked, said in one sentence for the
    operator. Nothing was destroyed."""


def validate_reference(value: str | None) -> str:
    """The authority reference, or a refusal. Refuses blank, a placeholder
    (infra/production/secrets.env.example's `replace-me` shape), a word that
    is an answer rather than a reference, and anything too short to be one.
    It cannot refuse a false reference, and says so in the refusal's
    neighbour, the operator documentation."""
    text = (value or "").strip()
    if not text:
        raise SweepRefused(
            f"{AUTHORITY_ENV} is not set. A real sweep destroys collected "
            f"documents and records the authority it ran under: set it to a "
            f"reference an auditor can follow (a retention schedule, counsel's "
            f"instruction, a ticket) and run again. Nothing was destroyed.")
    lowered = text.lower()
    if any(mark in lowered for mark in _PLACEHOLDER_MARKERS):
        raise SweepRefused(
            f"{AUTHORITY_ENV} still carries a placeholder, which is not a "
            f"reference an auditor can follow. Nothing was destroyed.")
    if lowered in _NOT_A_REFERENCE or len(text) < _MIN_REFERENCE:
        raise SweepRefused(
            f"{AUTHORITY_ENV} is not a reference an auditor can follow: name "
            f"the schedule, instruction or ticket itself, not an answer. "
            f"Nothing was destroyed.")
    return text


def declared_authority(env: Mapping[str, str] | None = None) -> str:
    """The reference declared in the environment of this run, or a refusal.
    A DECLARATION the software records and cannot verify (docs/16 L1)."""
    env = os.environ if env is None else env
    return validate_reference(env.get(AUTHORITY_ENV))


def resolve_actor(conn: psycopg.Connection, email: str | None) -> UUID:
    """The active account that answers for this run, or a refusal. One
    sentence for every way it can fail, so the script is not a way to learn
    which addresses are accounts."""
    email = (email or "").strip()
    if not email:
        raise SweepRefused(
            f"a real sweep names the account that answers for it: pass --actor "
            f"EMAIL or set {ACTOR_ENV}. The tombstones record who destroyed "
            f"what. Nothing was destroyed.")
    row = conn.execute(
        """SELECT u.id FROM iam.app_user u
            WHERE u.email = %s AND u.is_active
              AND EXISTS (SELECT 1 FROM iam.user_role ur
                            JOIN iam.role_permission rp
                              ON rp.role_key = ur.role_key
                           WHERE ur.user_id = u.id
                             AND rp.permission_key = %s)""",
        (email, PERMISSION)).fetchone()
    if row is None:
        raise SweepRefused(
            f"no active account with that email holds {PERMISSION}. Name the "
            f"account that answers for the destruction. Nothing was destroyed.")
    return row[0]


@dataclass
class SweepReport:
    """What a run found and did, counts only."""
    apply: bool
    #: Collected documents past their clock when the run began, and how many
    #: of those no hold kept: what a dry run would destroy.
    past_clock: int = 0
    sweepable: int = 0
    passes: int = 0
    documents_purged: int = 0
    tombstones: int = 0
    #: After a real run: documents past their clock that a hold keeps, and
    #: documents past their clock that nothing kept and the run did not
    #: destroy (a store that refused its markup, or the pass cap).
    held: int = 0
    remaining: int = 0
    #: Why the run stopped before it was done, and whether that was the
    #: purge refusing (no store for the markup) rather than the pass cap.
    stopped: str | None = None
    refused: bool = False
    warnings: list[str] = field(default_factory=list)

    def counters(self) -> str:
        """One line of `key=value`, the shape every drain prints."""
        if not self.apply:
            pairs = [("mode", "dry-run"), ("past_clock", self.past_clock),
                     ("sweepable", self.sweepable),
                     ("held", self.past_clock - self.sweepable)]
        else:
            pairs = [("mode", "apply"), ("passes", self.passes),
                     ("documents_purged", self.documents_purged),
                     ("tombstones", self.tombstones), ("held", self.held),
                     ("remaining", self.remaining)]
        return " ".join(f"{key}={value}" for key, value in pairs)


def sweep(conn: psycopg.Connection, *, apply: bool,
          actor_id: UUID | None = None, authority: str | None = None,
          document_raw=None, as_of: datetime | None = None,
          max_passes: int = DEFAULT_MAX_PASSES,
          where: Mapping[str, object] | None = None) -> SweepReport:
    """Count what is past its clock, and with `apply` destroy what no hold
    keeps. `conn` must be a system connection: under row-level security a
    sweep on the request role would see only some documents and report
    success.

    A dry run writes nothing at all, not even an audit row: it is a read.
    A real run needs a named actor and a valid authority reference (checked
    here as well as by the script, so no caller can skip the refusal), loops
    `purge_due` until a pass destroys nothing, and writes ONE
    `RETENTION_SWEEP` event of counts at the end, also when it stopped early
    and also when nothing was due, so the log shows that a sweep ran."""
    # Refused before anything is read: a real run without a valid declaration
    # or a named account does not start, so no caller can skip either.
    reference = actor = None
    if apply:
        reference = validate_reference(authority)
        if actor_id is None:
            raise SweepRefused(
                "a real sweep names the account that answers for it. Nothing "
                "was destroyed.")
        actor = actor_id
    now = as_of or datetime.now(timezone.utc)
    service = RetentionService(conn, document_raw=document_raw)
    past, sweepable, _oldest = service.document_backlog(now)
    report = SweepReport(apply=apply, past_clock=past, sweepable=sweepable)

    if not apply:
        # The purge's own dry run, for its warnings (a placeholder rule, the
        # documents with no clock); its counts stop at one pass's limit and
        # are not the ones reported.
        preview = service.purge_due(
            actor_id=_NO_ACTOR, authority="dry run", as_of=now, dry_run=True,
            kinds=SWEPT_KINDS)
        report.warnings = list(dict.fromkeys(preview.warnings))
        return report

    recorded = f"retention sweep under {reference}"
    capped = False
    try:
        while report.passes < max_passes:
            result = service.purge_due(
                actor_id=actor, authority=recorded, as_of=now,
                kinds=SWEPT_KINDS)
            report.passes += 1
            report.documents_purged += result.documents_purged
            report.tombstones += len(result.tombstones)
            report.warnings = list(dict.fromkeys(
                [*report.warnings, *result.warnings]))
            # A pass that destroyed nothing has nothing left it can: the
            # rest is held, or a store refused it and the next run retries.
            if result.documents_purged == 0:
                break
        else:
            capped = True
    except RetentionError as exc:
        # The purge's own refusal (no store for collected markup is
        # configured): said, recorded, and not retried.
        report.stopped = str(exc)
        report.refused = True
    except BaseException:
        # The counts after the failure are unknown, and the row says so by
        # leaving them out rather than recording zeros.
        _record(conn, actor, reference, report, where, finished=False,
                counted=False)
        raise
    past_after, sweepable_after, _ = service.document_backlog(now)
    report.held = past_after - sweepable_after
    report.remaining = sweepable_after
    if capped and report.remaining:
        report.stopped = (
            f"stopped at the limit of {max_passes} passes with documents "
            f"still due; run it again")
    _record(conn, actor, reference, report, where,
            finished=report.stopped is None, counted=True)
    return report


def _record(conn: psycopg.Connection, actor_id: UUID, reference: str,
            report: SweepReport, where: Mapping[str, object] | None, *,
            finished: bool, counted: bool) -> None:
    """The run's one audit row. Counts, the declared reference and where it
    ran (script, host, operating-system account): never a document, an id, a
    key or a line of what was destroyed, which the tombstones count and the
    audit log must not copy."""
    detail = {
        "authority": reference,
        "passes": report.passes,
        "documents_purged": report.documents_purged,
        "finished": finished,
        **(dict(where) if where else {}),
    }
    if counted:
        detail["held"] = report.held
        detail["remaining"] = report.remaining
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id,
                case_id, detail)
           VALUES (%s, 'USER', %s, 'retention', NULL, NULL, %s)""",
        (actor_id, EVENT, Json(detail)))


# ---------------------------------------------------------------------------
# The readiness row
# ---------------------------------------------------------------------------

def _documents(n: int) -> str:
    return count_of(n, "collected document", "collected documents")


def _age_words(age: timedelta) -> str:
    days = max(int(age.total_seconds() // 86400), 0)
    return count_of(days, "day", "days") if days else "under a day"


def readiness_verdict(conn: psycopg.Connection, *,
                      now: datetime | None = None) -> tuple[bool, str, str]:
    """(ok, evidence, action) for the `retention_sweep_current` row: how many
    collected documents are past their clock and unswept. Counts and an age,
    never a document, a source or a case.

    Passes with nothing past its clock, with only held documents past it (a
    hold is the purge refusing correctly, and the evidence says how many),
    and with unheld ones inside `OVERDUE_AFTER`. Fails once an unheld
    document has waited longer than that: somebody's third-party content is
    being held past its clock, which is the gap F30 recorded. Not blocking:
    it names a duty that is late, not a decision that cannot wait."""
    now = now or datetime.now(timezone.utc)
    past, sweepable, oldest = RetentionService(conn).document_backlog(now)
    if not past:
        return True, "No collected document is past its retention clock.", ""
    held = past - sweepable
    kept = ""
    if held:
        kept = (f" {held} more {agree(held, 'is', 'are')} kept by a legal hold "
                f"and {agree(held, 'stays', 'stay')}.")
    if not sweepable:
        return (True,
                f"{_documents(past)} {agree(past, 'is', 'are')} past "
                f"{agree(past, 'its', 'their')} retention clock and "
                f"{agree(past, 'is', 'every one is')} kept by a legal hold, so "
                f"a sweep keeps {agree(past, 'it', 'them')}.", "")
    age = now - oldest
    lead = (f"{_documents(sweepable)} {agree(sweepable, 'is', 'are')} past "
            f"{agree(sweepable, 'its', 'their')} retention clock and "
            f"unswept, the oldest by {_age_words(age)}.")
    if age <= OVERDUE_AFTER:
        return (True, lead + f" That is inside the {OVERDUE_AFTER.days} days a "
                f"weekly sweep allows." + kept, "")
    return (False,
            lead + " No sweep of collected documents is scheduled, or the "
            "last one could not finish." + kept,
            "run python scripts/retention_sweep.py to see what a sweep would "
            "destroy, then run it with --apply under a declared authority, and "
            "schedule it (infra/production/README.md, Retention sweep)")
