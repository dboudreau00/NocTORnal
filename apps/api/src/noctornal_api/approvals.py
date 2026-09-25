"""Four-eyes approval: request, decide, consume.

docs/05: "Dual control for the genuinely irreversible: case deletion,
evidence purge, role definition changes, persona credential reveal. Two
distinct humans, enforced by constraint."

The constraint lives in migration 0028. This module is the lifecycle around
it, and the two rules it exists to hold:

**An approval is for a specific action, not for a person.** Everything is
bound to `payload_hash` -- a hash over the operation, the case and the
canonicalised payload. `consume()` recomputes it against what is about to
run and refuses on any difference. Without that binding, "Bob approved it"
means Bob approved whatever the requester did next.

**An approval is spent, not held.** `consume()` is one atomic UPDATE
guarded on `state = 'APPROVED'`, so it succeeds exactly once even under
concurrency. An approval that can be replayed is a standing grant.

## What the caller still has to do

This module does NOT decide whether the approver was allowed to approve.
That is an authorization question and there is exactly one place that
answers those -- `security/access.evaluate()` via `http/deps`. The HTTP
layer checks that the approver independently holds the operation's
permission and has a fresh second factor BEFORE calling `decide()`, for the
obvious reason: a second human who could not have performed the operation
themselves is a witness, not a control.

## Consuming is the requester's job

Only `requested_by` may consume an approval. The approval says "you may do
the thing you asked to do"; letting the approver execute it instead splits
one action across two people's names in the audit log and makes "who did
this" ambiguous, which is the question this whole system exists to answer.
An approver who wants to perform it can raise their own request.

## Case-scoped and deployment-wide (F9, 2026-09-24)

Every operation says whether it is raised in a case or for the whole
deployment (`Operation.scope`). A deployment-wide request has no case, so
nobody is assigned to it: it is raised and decided through the global
`/approvals` routes and told to everybody who could sign it. The first of
them is `dual_control.policy`, a change to the two-person policy itself,
which an administrator proposes and a DIFFERENT kind of person, a Security
officer, countersigns (`Operation.approver_permission`).

## Out-of-band audit rows, and the one rule they follow

A refusal the caller's transaction must not roll back is written on a
second connection (`_record_out_of_band`). `audit.chain_hash` takes an
advisory lock on every audit insert and holds it to the end of the
inserting transaction, so a caller whose open transaction has ALREADY
written an audit row holds that lock, and a second connection waiting for
it waits on a caller that is waiting for the second connection. Postgres
cannot see that cycle: it runs through this Python thread. So the rule
(2026-09-24): out of band only while the caller holds no
open transaction that has audited. `_record_out_of_band` checks the
caller's locks and, when it does hold the chain lock, writes on the
caller's own connection instead and logs that it did; the side
connection also carries a five-second lock timeout, so a future mistake
fails one request instead of freezing every audited action in the
deployment. The callers keep the rule by shape: `consume()` is the first
write in every transaction that spends an approval, and a refused policy
change is recorded after its transaction has rolled back.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api import notify_events

log = logging.getLogger(__name__)

PENDING = "PENDING"
APPROVED = "APPROVED"
REJECTED = "REJECTED"
WITHDRAWN = "WITHDRAWN"
CONSUMED = "CONSUMED"

#: The deployment modes of a configurable operation, least strict first
#: (F9, 2026-09-24). PER_CASE: a case asks for the second signature with
#: its own switch. ALWAYS: every case needs it. There is no NEVER: a
#: deployment should not forbid a case from being stricter.
MODES = ("PER_CASE", "ALWAYS")

#: Where an operation is raised: in a case, or for the whole deployment.
SCOPES = ("case", "global")


class ApprovalError(Exception):
    pass


@dataclass(frozen=True)
class Operation:
    """One four-eyeable operation.

    `permission` is what the REQUESTER holds. `signer_permission` is what
    the APPROVER must independently hold, and it is the SAME permission
    unless `approver_permission` names another one, deliberately: an
    approver drawn from a wider pool than the actors is a rubber stamp
    with a job title. The one exception is a pair declared in
    `iam.separated_duty`, where the second person is by design a different
    kind of person (an administrator proposes, a Security officer
    countersigns); then nobody holding the requester's permission may sign
    at all, or one person holding both roles would be both people.

    `scope` and `enforced_at` have no default (F9, 2026-09-24), so an entry
    that does not say whether it is raised in a case, and which function
    spends it, does not construct. `enforced_at` is
    "relative/path.py::Qualname" of the function that calls `consume` for
    this key, or None with `not_enforced_because` saying why; the
    Two-person controls screen shows that sentence rather than a control
    the code does not have, and `test_approvals_catalogue.py` holds both
    halves to the source.

    `modes[0]` is the operation's floor. An operation is configurable, and
    gets a row in `iam.dual_control_operation`, only when it lists more than
    one mode; the database can then make it stricter and never looser.

    `countersigner_seasoned`: the approver may not sign within the seven
    days after someone else took over their credentials or gave them the
    role that signs (`iam.countersign_blocked_by`).
    """

    key: str
    permission: str
    ttl: timedelta
    description: str
    scope: str
    enforced_at: str | None
    approver_permission: str | None = None
    modes: tuple[str, ...] = ("ALWAYS",)
    not_enforced_because: str = ""
    countersigner_seasoned: bool = False

    @property
    def signer_permission(self) -> str:
        return self.approver_permission or self.permission

    @property
    def configurable(self) -> bool:
        return len(self.modes) > 1


# The catalogue. docs/05 names four; docs/08 adds out-of-schedule purge;
# docs/04 adds credential reveal; F9 (2026-09-24) adds the two-person
# policy itself and the case switch's relaxation. The ones not wired yet
# are registered so that when those operations are built the control
# already exists and does not have to be retrofitted onto something that
# already shipped without it; each says why it is not wired, and the
# Two-person controls screen shows that sentence.
OPERATIONS: dict[str, Operation] = {
    "node.merge": Operation(
        key="node.merge", permission="graph.merge", ttl=timedelta(hours=8),
        description="Fold one entity into another",
        scope="case",
        enforced_at="http/routers/merges.py::_merge_under_dual_control",
        modes=("PER_CASE", "ALWAYS"),
    ),
    "case.delete": Operation(
        key="case.delete", permission="case.delete", ttl=timedelta(hours=24),
        description="Delete a case",
        scope="case", enforced_at=None,
        not_enforced_because=(
            "Marking a case PURGED takes one signature today, and destroying "
            "a case is not built."),
    ),
    "evidence.purge": Operation(
        key="evidence.purge", permission="evidence.purge",
        ttl=timedelta(hours=24),
        description="Destroy evidence outside the retention schedule",
        scope="case",
        enforced_at="retention.py::RetentionService.purge_out_of_schedule",
    ),
    "role.manage": Operation(
        key="role.manage", permission="role.manage", ttl=timedelta(hours=24),
        description="Change a role definition",
        scope="global", enforced_at=None,
        not_enforced_because=(
            "Nothing changes a role definition yet: roles change only with "
            "a release."),
    ),
    "collection_account.reveal": Operation(
        key="collection_account.reveal",
        permission="collection_account.reveal",
        # Short: a credential reveal approved this morning and used this
        # evening is not the operation anybody agreed to.
        ttl=timedelta(minutes=30),
        description="Reveal a persona credential",
        scope="global", enforced_at=None,
        not_enforced_because=(
            "Deliberately not reachable over HTTP: a persona credential never "
            "leaves the vault, and revealing a Telegram session would hand "
            "over the whole account."),
    ),
    # F9 (2026-09-24). A change to the two-person policy: which operations
    # need a second signature, and which permission pairs no role may hold.
    # Proposed by an administrator and countersigned by a Security officer,
    # a declared separated pair (migration dual_control_policy).
    "dual_control.policy": Operation(
        key="dual_control.policy", permission="dual_control.manage",
        approver_permission="dual_control.countersign",
        ttl=timedelta(hours=24),
        description="Change which operations need two people",
        scope="global",
        enforced_at="dual_control.py::DualControlPolicyService.apply",
        countersigner_seasoned=True,
    ),
    # F9b (2026-09-24). Turning a case's merge requirement OFF. The second
    # person is another holder of case.update on the case: a deputy or a
    # second Lead investigator (0028's same-permission rule). Turning it on
    # takes no approval at all.
    "case.policy.relax": Operation(
        key="case.policy.relax", permission="case.update",
        ttl=timedelta(hours=24),
        description="Stop requiring a second signature on a case's merges",
        scope="case",
        enforced_at="http/routers/approvals.py::set_policy",
    ),
}

# A merge TTL of eight hours is one shift. Long enough that an approval
# obtained at handover survives to the end of the day; short enough that it
# cannot be banked.

#: The case column that says whether a PER_CASE operation is required in a
#: case. Read through one literal statement each (`_PER_CASE_READ`), never
#: an interpolated column name.
PER_CASE_COLUMN = {"node.merge": "dual_control_merge"}

_PER_CASE_READ = {
    "node.merge": 'SELECT dual_control_merge FROM core."case" WHERE id = %s',
}

#: The gate of the global approvals router: every permission either side of
#: a deployment-wide operation that something actually spends. An account
#: holding none of them is refused there instead of being handed a list
#: that can only ever be empty.
GLOBAL_GATE_PERMISSIONS: tuple[str, ...] = tuple(sorted(
    {p for op in OPERATIONS.values()
     if op.scope == "global" and op.enforced_at is not None
     for p in (op.permission, op.signer_permission)}))


def relax_payload(epoch: int) -> dict:
    """The one payload a `case.policy.relax` approval may carry: the switch
    as it stands (its epoch, migration case_merge_relax_two_people), so the
    approval applies to one state of the switch and cannot be banked across
    an off and on again."""
    return {"setting": "dual_control_merge", "from": True, "to": False,
            "epoch": epoch}


def policy_mode(conn: psycopg.Connection, operation: str) -> str:
    """The deployment's mode for `operation`.

    An operation with one mode is that mode (its floor) and is never read
    from the database. A configurable one reads `iam.dual_control_operation`
    and takes the value only when it is one of the operation's own modes:
    a missing row, an unknown value and a value below the code's floor all
    answer ALWAYS. Failing closed is the point: a row the code does not
    recognise must never be the way a control goes off."""
    op = OPERATIONS.get(operation)
    if op is None:
        return "ALWAYS"
    if not op.configurable:
        return op.modes[0]
    row = conn.execute(
        "SELECT mode FROM iam.dual_control_operation WHERE operation = %s",
        (operation,)).fetchone()
    if row is None or row[0] not in op.modes:
        return "ALWAYS"
    return row[0]


def countersign_block(conn: psycopg.Connection, signer_id: UUID,
                      permission: str, *, as_of: datetime | None = None,
                      proposer_id: UUID | None = None,
                      proposer_permission: str | None = None,
                      lookback_days: int | None = None) -> dict | None:
    """Why `signer_id` may not countersign now, or None.

    The one reader of the seven-day rule (F9, 2026-09-24): decide, the
    listing, the overview and the ledger trigger all call
    `iam.countersign_blocked_by`. With a proposer named, it also answers
    for the reverse direction: the signer took over the proposer's account
    (2026-09-24). `lookback_days` widens the window for
    the change card's provenance line, and only for that."""
    row = conn.execute(
        """SELECT b.action, b.occurred_at, b.actor_id, b.subject_id,
                  b.occurred_at + iam.countersigner_seasoning(),
                  u.display_name, s.display_name, r.display_name
             FROM iam.countersign_blocked_by(
                    %s, %s, coalesce(%s::timestamptz, now()), %s, %s,
                    make_interval(days => %s::int)) b
             LEFT JOIN iam.app_user u ON u.id = b.actor_id
             LEFT JOIN iam.app_user s ON s.id = b.subject_id
             LEFT JOIN iam.role r ON r.key = b.role_key""",
        (signer_id, permission, as_of, proposer_id,
         proposer_permission, lookback_days)).fetchone()
    if row is None:
        return None
    return {"action": row[0], "at": row[1], "by": row[2], "subject": row[3],
            "may_sign_after": row[4], "by_name": row[5],
            "subject_name": row[6], "role_name": row[7],
            "own": row[3] == signer_id}


def seasoning_days(conn: psycopg.Connection) -> int:
    """The window, in days, as the database holds it."""
    return int(conn.execute(
        "SELECT extract(day FROM iam.countersigner_seasoning())").fetchone()[0])


def utc_text(moment: datetime) -> str:
    """The console's form of an instant, which a reader sees verbatim."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


#: What happened, said to the countersigner, who is its subject.
_OWN_WORDS = {
    "PASSWORD_RESET": "reset your password",
    "TOTP_REENROLLED": "re-enrolled your authenticator",
    "USER_REACTIVATED": "reactivated your account",
    "USER_UNLOCKED": "unlocked your account",
    "USER_CREATED": "created your account",
}

#: What the countersigner did to the proposer's account.
_PROPOSER_WORDS = {
    "PASSWORD_RESET": "you reset the password of {name}, who proposed this",
    "TOTP_REENROLLED": "you re-enrolled the authenticator of {name}, who "
                       "proposed this",
    "USER_REACTIVATED": "you reactivated the account of {name}, who proposed "
                        "this",
    "USER_UNLOCKED": "you unlocked the account of {name}, who proposed this",
    "ROLE_GRANTED": "you gave {name}, who proposed this, a role that proposes",
    "USER_CREATED": "you created the account of {name}, who proposed this",
}


def countersign_block_sentence(block: dict, *, days: int = 7) -> str:
    """The refusal a blocked countersigner reads: when they may sign, and
    who did what when. Times in UTC, and said so."""
    when = utc_text(block["may_sign_after"])
    at = utc_text(block["at"])
    if block["own"]:
        if block["action"] == "ROLE_GRANTED":
            what = ("gave you the role " + block["role_name"]
                    if block.get("role_name") else
                    "gave you a role that countersigns")
        else:
            what = _OWN_WORDS.get(block["action"], "changed your account")
        return (f"You may countersign this from {when}: "
                f"{block['by_name'] or 'another account'} {what} on {at}. For "
                f"{days} days after someone else issues, resets or re-enrols "
                f"an account's credentials, reactivates or unlocks it, or "
                f"gives it a role that countersigns, that account may not "
                f"countersign.")
    what = _PROPOSER_WORDS.get(
        block["action"], "you changed the account of {name}, who proposed this")
    return (f"You may countersign this from {when}: "
            f"{what.format(name=block['subject_name'] or 'the proposer')} on "
            f"{at}. For {days} days after you issue, reset or re-enrol an "
            f"account's credentials, reactivate or unlock it, or give it a "
            f"role that proposes, you may not countersign what that account "
            f"proposes.")


def holds_global_permission(conn: psycopg.Connection, user_id: UUID,
                            permission: str) -> bool:
    """Whether any of the account's global roles carries `permission`,
    active or not: the question is who the person IS, not whether they
    may act today."""
    return conn.execute(
        """SELECT EXISTS (
             SELECT 1 FROM iam.user_role ur
               JOIN iam.role_permission rp ON rp.role_key = ur.role_key
              WHERE ur.user_id = %s AND rp.permission_key = %s)""",
        (user_id, permission)).fetchone()[0]


def eligible_signers_sql(alias: str = "u") -> str:
    """SQL true when `alias` (an iam.app_user row) could sign a
    deployment-wide request whose signer permission is `%(signer)s` and
    whose requester permission is `%(requester)s`: active, holding the
    signer's permission, and, where the two differ, NOT holding the
    requester's (2026-09-24: `iam.separated_duty` keeps
    the halves in different roles, and this keeps them in different
    people). Shared by the notification, the waiting count and
    `dual_control.signers`, so the three agree about who could sign."""
    return f"""
        {alias}.is_active
        AND EXISTS (SELECT 1 FROM iam.user_role sur
                      JOIN iam.role_permission srp ON srp.role_key = sur.role_key
                     WHERE sur.user_id = {alias}.id
                       AND srp.permission_key = %(signer)s)
        AND (%(signer)s = %(requester)s OR NOT EXISTS (
               SELECT 1 FROM iam.user_role rur
                 JOIN iam.role_permission rrp ON rrp.role_key = rur.role_key
                WHERE rur.user_id = {alias}.id
                  AND rrp.permission_key = %(requester)s))
    """


@dataclass(frozen=True)
class ApprovalRequest:
    id: UUID
    case_id: UUID | None
    operation: str
    payload: dict
    justification: str
    requested_by: UUID
    requested_at: datetime
    expires_at: datetime
    state: str
    decided_by: UUID | None
    decided_at: datetime | None
    decision_note: str | None
    consumed_at: datetime | None
    result_ref: UUID | None
    #: N1 (2026-09-02). Whether the notification that a request or a
    #: decision raises actually reached anyone, on the record returned by
    #: `request()` / `decide()` ONLY.
    #:
    #: `approvers_notified`: 0 means nobody else on the case both holds the
    #: operation's permission and may read the request (or the request has
    #: no case); None means the notify write itself failed after the row
    #: committed. `requester_notified`: False means suppressed, None means
    #: failed. Reach is not stored, so a record read back from the table
    #: carries None for both -- which is "not recorded", not "failed". The
    #: router renders them only on the two writes, so a listing never
    #: claims a failure it cannot know about. (A listing does carry a
    #: separate count of the APPROVAL_REQUESTED notifications a request
    #: raised, which IS stored; see the router, 2026-09-23.)
    approvers_notified: int | None = None
    requester_notified: bool | None = None

    def is_expired(self, now: datetime | None = None) -> bool:
        return self.expires_at <= (now or datetime.now(timezone.utc))

    @property
    def is_actionable(self) -> bool:
        """Still awaiting a decision, and still in time to receive one."""
        return self.state == PENDING and not self.is_expired()


def canonical_payload(payload: dict) -> str:
    """The exact bytes the hash is taken over.

    Sorted keys and no whitespace, so two dicts that mean the same thing
    hash the same regardless of how the client serialised them. UUIDs and
    datetimes are stringified because a payload that round-trips through
    JSON must hash identically before and after -- otherwise every approval
    would fail to consume, which is at least a loud failure, or worse, a
    later change to the serialiser would silently start letting mismatched
    payloads through.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str)


def payload_hash(operation: str, case_id: UUID | None, payload: dict) -> bytes:
    """Bind the approval to the operation AND the case AND the parameters.

    The case is in the hash because the same two node ids could exist in
    two cases; without it an approval granted in a training case would
    consume in a live one.
    """
    material = f"{operation}\x1f{case_id or '-'}\x1f{canonical_payload(payload)}"
    return hashlib.sha256(material.encode("utf-8")).digest()


class ApprovalService:
    def __init__(self, conn: psycopg.Connection):
        self._c = conn

    # -- lifecycle --------------------------------------------------------

    def request(self, *, operation: str, case_id: UUID | None, payload: dict,
                justification: str, requested_by: UUID) -> ApprovalRequest:
        op = self._operation(operation)
        # F9 (2026-09-24): a case operation raised with no case would be
        # told to nobody and decided by nobody, and a deployment-wide one
        # raised in a case would be hidden behind that case's assignments.
        if op.scope == "case" and case_id is None:
            raise ApprovalError(f"{op.description} is raised in a case")
        if op.scope == "global" and case_id is not None:
            raise ApprovalError(
                f"{op.description} is deployment-wide and takes no case")
        if not justification or not justification.strip():
            raise ApprovalError(
                "a request for a second signature has to say what it is for: "
                "the justification is the only thing the approver has to "
                "work from")
        now = datetime.now(timezone.utc)
        digest = payload_hash(operation, case_id, payload)
        try:
            row = self._c.execute(
                """INSERT INTO core.approval_request
                       (case_id, operation, payload, payload_hash,
                        justification, requested_by, requested_at, expires_at)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING """ + _COLUMNS,
                (case_id, operation, Json(payload), digest,
                 justification.strip(), requested_by, now, now + op.ttl),
            ).fetchone()
        except psycopg.errors.UniqueViolation as exc:
            # The partial unique index on PENDING. Two requests for the same
            # action are two chances at a yes.
            raise ApprovalError(
                "an identical request is already awaiting a decision") from exc
        record = _record(row)
        self._audit(record, "APPROVAL_REQUESTED", requested_by, {
            "operation": operation, "justification": record.justification,
            "expires_at": record.expires_at.isoformat(),
        })
        # An approval nobody is told about is an approval nobody gives, and
        # then dual control is just a merge button that does not work. So
        # the reach is COUNTED and returned, not discarded: until N1
        # (2026-09-02) this was a bare statement, `approval_requested`
        # returned a count nothing read, and a request that reached nobody
        # was a 201 like any other.
        #
        # It runs on an autocommit connection AFTER the row above committed,
        # so a failure here is logged and reported as `None`, never raised.
        # Raising turned a request that EXISTS into a 500; the analyst
        # re-submitted, and the retry was a 409 for an identical pending
        # request they had just been told was never made.
        reach: int | None = 0
        try:
            if case_id is not None:
                # The SIGNER's permission (F9, 2026-09-24): the people told
                # are the people the decide route will accept.
                reach = notify_events.approval_requested(
                    self._c, case_id=case_id, request_id=record.id,
                    operation=operation, permission=op.signer_permission,
                    justification=record.justification, actor_id=requested_by)
            else:
                reach = notify_events.global_approval_requested(
                    self._c, request_id=record.id, operation=operation,
                    description=op.description,
                    permission=op.signer_permission,
                    requester_permission=op.permission,
                    actor_id=requested_by)
        except Exception:  # noqa: BLE001 - reported on the record, not raised
            log.exception("approval request %s was recorded but its "
                          "notification failed", record.id)
            reach = None
        return replace(record, approvers_notified=reach)

    def decide(self, request_id: UUID, *, decided_by: UUID, approve: bool,
               note: str | None = None) -> ApprovalRequest:
        """Approve or reject. The caller must ALREADY have checked that
        `decided_by` holds the operation's permission and has a fresh second
        factor -- see the module docstring.

        Self-approval is refused here as well as by the CHECK constraint.
        The constraint is the guarantee; this is the readable error.

        Two refusals are about the PERSON rather than the request, and both
        apply to approving only: a refusal is the safe direction and is
        never blocked (F9, 2026-09-24).

        - Where the signer's permission is a different kind of person's
          (`approver_permission`), an account that also holds the
          requester's permission is not a second person, whichever two
          accounts are involved (the first-run account
          holds both roles and could otherwise countersign what a second
          account it created proposed).
        - `countersigner_seasoned`: the seven-day rule, in either
          direction, with the sentence that says who and when.

        Each refusal is written out of band: the refusal is the detection
        signal, and a caller's rollback must not take it.

        `decided_at` is the database's `now()`: the approval guard insists
        on it, because the ledger measures the seven-day window back from
        it and the API's clock is not the database's.
        """
        current = self.get(request_id)
        if current is None:
            raise ApprovalError("no such approval request")
        if current.state != PENDING:
            raise ApprovalError(
                f"this request is already {current.state.lower()}; a decision "
                "cannot be revisited, raise a new request")
        if current.is_expired():
            raise ApprovalError(
                "this request has expired; raise a new one so the approver is "
                "looking at current facts")
        if decided_by == current.requested_by:
            raise ApprovalError(
                "dual control means two distinct humans: you cannot approve "
                "your own request")
        op = OPERATIONS.get(current.operation)
        if approve and op is not None:
            self._refuse_unless_second_person(current, op, decided_by)

        # Guarded on the state we read, so a concurrent decision loses
        # rather than overwrites.
        row = self._c.execute(
            """UPDATE core.approval_request
                  SET state = %s, decided_by = %s, decided_at = now(),
                      decision_note = %s
                WHERE id = %s AND state = 'PENDING'
            RETURNING """ + _COLUMNS,
            (APPROVED if approve else REJECTED, decided_by,
             (note or "").strip() or None, request_id),
        ).fetchone()
        if row is None:
            raise ApprovalError("this request was decided by someone else first")
        record = _record(row)
        self._audit(record, "APPROVAL_GRANTED" if approve else "APPROVAL_REFUSED",
                    decided_by, {
                        "operation": record.operation,
                        "requested_by": str(record.requested_by),
                        "note": record.decision_note,
                    })
        # Same shape as `request()` (N1, 2026-09-02): the decision is
        # committed, so a failure to tell the requester is a fact on the
        # record, not a 500 that says the decision was not made.
        told: bool | None = False
        try:
            if record.case_id is not None:
                told = notify_events.approval_decided(
                    self._c, case_id=record.case_id, request_id=record.id,
                    operation=record.operation, requested_by=record.requested_by,
                    approved=approve, note=record.decision_note,
                    actor_id=decided_by) is not None
            else:
                told = notify_events.global_approval_decided(
                    self._c, request_id=record.id,
                    description=op.description if op else record.operation,
                    requested_by=record.requested_by, approved=approve,
                    actor_id=decided_by) is not None
        except Exception:  # noqa: BLE001 - reported on the record, not raised
            log.exception("approval decision on %s was recorded but its "
                          "notification failed", record.id)
            told = None
        return replace(record, requester_notified=told)

    def _refuse_unless_second_person(self, current: ApprovalRequest,
                                     op: Operation, decided_by: UUID) -> None:
        """The two person-level refusals of `decide`, each audited out of
        band as DUAL_CONTROL_COUNTERSIGN_REFUSED (DENIED)."""
        if (op.approver_permission is not None
                and holds_global_permission(self._c, decided_by, op.permission)):
            self._record_out_of_band(
                "DUAL_CONTROL_COUNTERSIGN_REFUSED", decided_by, current.id,
                current.case_id,
                {"reason": "countersigner_can_propose",
                 "operation": op.key, "holds": op.permission})
            raise ApprovalError(
                f"You can also propose this ({op.description.lower()}), so "
                f"your countersignature would be the same person twice. It "
                f"has to come from someone who holds {op.signer_permission} "
                f"and not {op.permission}.")
        if not op.countersigner_seasoned:
            return
        block = countersign_block(
            self._c, decided_by, op.signer_permission,
            proposer_id=current.requested_by,
            proposer_permission=op.permission)
        if block is None:
            return
        self._record_out_of_band(
            "DUAL_CONTROL_COUNTERSIGN_REFUSED", decided_by, current.id,
            current.case_id,
            {"reason": "countersigner_seasoning", "operation": op.key,
             "event_action": block["action"],
             "event_at": block["at"].isoformat(),
             "event_by": str(block["by"]),
             "event_subject": str(block["subject"]),
             "may_sign_after": block["may_sign_after"].isoformat()})
        raise ApprovalError(countersign_block_sentence(
            block, days=seasoning_days(self._c)))

    def withdraw(self, request_id: UUID, *, actor_id: UUID,
                 scope: str | None = None,
                 case_id: UUID | None = None) -> ApprovalRequest:
        """The requester changing their mind. Not a decision -- a withdrawn
        request never had one, and the distinction matters when reading the
        history back.

        `scope` binds the withdrawal to the route it came through (F9,
        2026-09-24): "global" matches only a deployment-wide request, and
        "case" only a request raised in `case_id`, so a requester who has
        lost access to one case cannot withdraw its request through a case
        they still hold. None keeps the unscoped form
        for callers inside the service layer."""
        where = ""
        params: list = [WITHDRAWN, request_id, actor_id]
        if scope == "global":
            where = " AND case_id IS NULL"
        elif scope == "case":
            where = " AND case_id IS NOT NULL AND case_id = %s"
            params.append(case_id)
        elif scope is not None:
            raise ApprovalError(f"unknown scope {scope!r}")
        row = self._c.execute(
            """UPDATE core.approval_request
                  SET state = %s
                WHERE id = %s AND state = 'PENDING' AND requested_by = %s"""
            + where + " RETURNING " + _COLUMNS,
            tuple(params),
        ).fetchone()
        if row is None:
            raise ApprovalError(
                "no pending request of yours with that id")
        record = _record(row)
        self._audit(record, "APPROVAL_WITHDRAWN", actor_id,
                    {"operation": record.operation})
        return record

    def consume(self, request_id: UUID, *, actor_id: UUID, operation: str,
                case_id: UUID | None, payload: dict) -> ApprovalRequest:
        """Spend an approval on the operation it was granted for.

        Call this INSIDE the transaction that performs the operation. If the
        two are not atomic, a failure between them either burns an approval
        without doing the work (annoying) or does the work without burning
        the approval (the control is now reusable, which is the bad one).

        Every condition is in the WHERE clause rather than checked first,
        so the whole thing is one atomic compare-and-set: two concurrent
        attempts cannot both find the request APPROVED.
        """
        digest = payload_hash(operation, case_id, payload)
        row = self._c.execute(
            """UPDATE core.approval_request
                  SET state = %s, consumed_at = now()
                WHERE id = %s
                  AND state = 'APPROVED'
                  AND expires_at > now()
                  AND requested_by = %s
                  AND operation = %s
                  AND case_id IS NOT DISTINCT FROM %s
                  AND payload_hash = %s
            RETURNING """ + _COLUMNS,
            (CONSUMED, request_id, actor_id, operation, case_id, digest),
        ).fetchone()
        if row is None:
            # Deliberately one message for every failure mode. Which
            # condition failed would tell a caller whether a given request
            # id exists, who raised it, and whether an approval is
            # outstanding -- and the legitimate caller can see all of that
            # in the approvals list anyway.
            raise self._explain_consume_failure(request_id, actor_id, operation,
                                                case_id, digest)
        record = _record(row)
        self._audit(record, "APPROVAL_CONSUMED", actor_id, {
            "operation": record.operation,
            "approved_by": str(record.decided_by),
        })
        return record

    def attach_result(self, request_id: UUID, result_ref: UUID) -> None:
        """Join the approval to what it produced. Best effort and separate
        from `consume` so a failure to record the link can never roll back
        the operation itself.

        Caught and logged since 2026-09-24: the approval guard refuses a
        second `result_ref`, and a refused convenience join raised after
        the operation had succeeded would have answered 500 for an
        operation that was done."""
        try:
            self._c.execute(
                "UPDATE core.approval_request SET result_ref = %s WHERE id = %s",
                (result_ref, request_id))
        except psycopg.Error:
            log.exception("could not record the result of approval %s",
                          request_id)

    # -- reads ------------------------------------------------------------

    def get(self, request_id: UUID) -> ApprovalRequest | None:
        row = self._c.execute(
            f"SELECT {_COLUMNS} FROM core.approval_request WHERE id = %s",
            (request_id,)).fetchone()
        return _record(row) if row else None

    def list_for_case(self, case_id: UUID, *, state: str | None = None,
                      limit: int = 100) -> list[ApprovalRequest]:
        if state is None:
            rows = self._c.execute(
                f"""SELECT {_COLUMNS} FROM core.approval_request
                     WHERE case_id = %s ORDER BY requested_at DESC LIMIT %s""",
                (case_id, limit)).fetchall()
        else:
            rows = self._c.execute(
                f"""SELECT {_COLUMNS} FROM core.approval_request
                     WHERE case_id = %s AND state = %s
                     ORDER BY requested_at DESC LIMIT %s""",
                (case_id, state, limit)).fetchall()
        return [_record(r) for r in rows]

    def awaiting_signature(self, user_id: UUID, *, clearance: str,
                           compartments: frozenset[str]) -> dict[str, int]:
        """Undecided, unexpired requests this person could sign, per case.

        ux08-triage:no-work-waiting-at-sign-in (2026-09-23). A request
        whose notification had been read left no trace anywhere on the
        rail: the Triage badge counted proposals only. This is the set the
        decide route would accept a signature from, as far as roles go:
        not the requester, and a live assignment on the case whose role
        carries the operation's own permission (the same join
        `notify_events.approval_requested` uses to choose whom to tell).
        Only over cases whose labels the person dominates; the step-up
        half is checked when they sign. Case operations only, with the
        signer's permission (F9, 2026-09-24); the deployment-wide ones are
        `awaiting_global_signature`."""
        pairs = [(k, op.signer_permission) for k, op in OPERATIONS.items()
                 if op.scope == "case"]
        rows = self._c.execute(
            """SELECT r.case_id, count(DISTINCT r.id)
                 FROM core.approval_request r
                 JOIN core."case" c ON c.id = r.case_id
                  AND c.classification <= %s::core.tlp
                  AND c.compartments <@ %s::text[]
                 JOIN unnest(%s::text[], %s::text[]) AS o(operation, permission)
                   ON o.operation = r.operation
                 JOIN iam.case_assignment ca
                   ON ca.case_id = r.case_id AND ca.user_id = %s
                  AND (ca.expires_at IS NULL OR ca.expires_at > now())
                 JOIN iam.role_permission rp
                   ON rp.role_key = ca.role_key
                  AND rp.permission_key = o.permission
                WHERE r.state = 'PENDING' AND r.expires_at > now()
                  AND r.requested_by <> %s
                GROUP BY r.case_id""",
            (clearance, sorted(compartments),
             [p[0] for p in pairs], [p[1] for p in pairs], user_id, user_id),
        ).fetchall()
        return {str(r[0]): r[1] for r in rows}

    # -- deployment-wide requests (F9, 2026-09-24) --------------------------
    #
    # Explicit about `case_id IS NULL` in every statement, and kept apart
    # from the case reads above, so the row-level security that comes
    # last (docs/00 decision 76) can see exactly which reads need a
    # pending global request visible to its would-be signer.

    def awaiting_global_signature(self, user_id: UUID) -> int:
        """Undecided, unexpired deployment-wide requests this person could
        sign: not the requester, and an eligible signer of that operation
        (`eligible_signers_sql`). A request they are blocked from
        countersigning by the seven-day rule still counts: they may refuse
        it."""
        ops = [op for op in OPERATIONS.values() if op.scope == "global"]
        total = 0
        for op in ops:
            total += self._c.execute(
                """SELECT count(*) FROM core.approval_request r
                     JOIN iam.app_user u ON u.id = %(user)s
                    WHERE r.case_id IS NULL AND r.operation = %(operation)s
                      AND r.state = 'PENDING' AND r.expires_at > now()
                      AND r.requested_by <> %(user)s
                      AND """ + eligible_signers_sql("u"),
                {"user": user_id, "operation": op.key,
                 "signer": op.signer_permission,
                 "requester": op.permission}).fetchone()[0]
        return total

    def list_global(self, operations: list[str], *, state: str | None = None,
                    limit: int = 100) -> list[ApprovalRequest]:
        """Deployment-wide requests for `operations`, newest first. `state`
        None is every state; "OPEN" is what can still move: PENDING, or
        APPROVED and not yet spent."""
        if not operations:
            return []
        if state is None:
            rows = self._c.execute(
                f"""SELECT {_COLUMNS} FROM core.approval_request
                     WHERE case_id IS NULL AND operation = ANY(%s)
                     ORDER BY requested_at DESC LIMIT %s""",
                (operations, limit)).fetchall()
        elif state == "OPEN":
            rows = self._c.execute(
                f"""SELECT {_COLUMNS} FROM core.approval_request
                     WHERE case_id IS NULL AND operation = ANY(%s)
                       AND (state = 'PENDING'
                            OR (state = 'APPROVED' AND consumed_at IS NULL))
                     ORDER BY requested_at DESC LIMIT %s""",
                (operations, limit)).fetchall()
        else:
            rows = self._c.execute(
                f"""SELECT {_COLUMNS} FROM core.approval_request
                     WHERE case_id IS NULL AND operation = ANY(%s)
                       AND state = %s
                     ORDER BY requested_at DESC LIMIT %s""",
                (operations, state, limit)).fetchall()
        return [_record(r) for r in rows]

    # -- internals --------------------------------------------------------

    def _operation(self, key: str) -> Operation:
        try:
            return OPERATIONS[key]
        except KeyError:
            raise ApprovalError(
                f"unknown operation {key!r}; four-eyes operations are "
                f"registered in approvals.OPERATIONS") from None

    def _explain_consume_failure(self, request_id, actor_id, operation,
                                 case_id, digest) -> ApprovalError:
        """One message out, a specific reason in the log.

        The caller gets a single uninformative refusal so a failed consume
        is not an oracle for whether an approval exists. The server-side
        audit row says which condition failed, because that is the
        difference between "somebody tried to replay an approval" and
        "somebody's approval timed out".

        ## The row is written on its OWN connection, and has to be

        Both production callers invoke `consume()` inside
        `with conn.transaction():` and catch `ApprovalError` OUTSIDE that
        block -- the dual-control merge endpoint and the out-of-schedule
        evidence purge, and both are structured that way deliberately, so
        a refused consume destroys nothing.

        The consequence was that this INSERT went in on the same
        connection and was rolled back by the very exception it was
        written to explain. `audit.event` contained ZERO
        APPROVAL_CONSUME_REFUSED rows in production no matter how many
        replay or payload-substitution attempts occurred: the single
        detection signal for the attack this module exists to stop --
        get a signature for merging two obvious spam bots, then execute
        the two nodes the case turns on -- was generated and immediately
        destroyed.

        The suite could not see it. `test_approvals_pg.py` calls
        `consume()` directly on the autocommit fixture connection with no
        enclosing transaction, so the row survives there and only there.

        A second connection is the same technique `collection.py` uses to
        keep a RUNNING row alive across an unwind. If it cannot be opened,
        the refusal still stands: failing to record an attempt must never
        become a way to make the attempt succeed.
        """
        row = self._c.execute(
            """SELECT state, requested_by, operation, case_id, payload_hash,
                      expires_at <= now()
                 FROM core.approval_request WHERE id = %s""",
            (request_id,)).fetchone()
        if row is None:
            reason = "no_such_request"
        elif row[0] != APPROVED:
            reason = f"state_{row[0].lower()}"
        elif row[5]:
            reason = "expired"
        elif row[1] != actor_id:
            reason = "not_the_requester"
        elif row[2] != operation or row[3] != case_id:
            reason = "wrong_operation_or_case"
        elif bytes(row[4]) != digest:
            # The interesting one: an approval granted for parameters that
            # are not the parameters now being executed.
            reason = "payload_mismatch"
        else:
            reason = "unknown"
        self._audit_refusal_out_of_band(request_id, actor_id, operation,
                                        case_id, reason)
        return ApprovalError(
            "this approval cannot be used for this operation: it may have "
            "expired, already been used, belong to someone else, or have "
            "been granted for different parameters")

    def _audit_refusal_out_of_band(self, request_id, actor_id, operation,
                                   case_id, reason: str) -> None:
        """Record the refusal on a connection the caller cannot roll back.

        See `_explain_consume_failure` for why. The chaining trigger owns
        `prev_hash`/`row_hash`, so a row written here links into the same
        chain as every other event -- there is no second ledger.
        """
        self._record_out_of_band(
            "APPROVAL_CONSUME_REFUSED", actor_id, request_id, case_id,
            {"reason": reason, "operation": operation})

    def _record_out_of_band(self, action: str, actor_id, request_id,
                            case_id, detail: dict) -> None:
        """A DENIED audit row about an approval request, written where the
        caller's rollback cannot take it (F9, 2026-09-24)."""
        record_out_of_band(self._c, action=action, actor_id=actor_id,
                           object_type="approval_request",
                           object_id=request_id, case_id=case_id,
                           detail=detail)

    def _audit(self, record: ApprovalRequest, action: str, actor_id: UUID,
               detail: dict) -> None:
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, detail)
               VALUES (%s, 'USER', %s, 'approval_request', %s, %s, %s)""",
            (actor_id, action, record.id, record.case_id, Json(detail)))


_COLUMNS = ("id, case_id, operation, payload, justification, requested_by, "
            "requested_at, expires_at, state, decided_by, decided_at, "
            "decision_note, consumed_at, result_ref")


def _record(r) -> ApprovalRequest:
    return ApprovalRequest(
        id=r[0], case_id=r[1], operation=r[2], payload=r[3],
        justification=r[4], requested_by=r[5], requested_at=r[6],
        expires_at=r[7], state=r[8], decided_by=r[9], decided_at=r[10],
        decision_note=r[11], consumed_at=r[12], result_ref=r[13],
    )


def case_requires_dual_control(conn: psycopg.Connection, case_id: UUID,
                               operation: str) -> bool:
    """Whether `operation` needs a second signature in this case.

    The deployment's mode first (F9, 2026-09-24): ALWAYS answers True for
    every case. Under PER_CASE the case's own switch answers, read through
    one literal statement per operation. The irreversible operations
    docs/05 names have one mode, ALWAYS, because there is no version of
    "delete the case" that is worth doing with one signature."""
    if policy_mode(conn, operation) == "ALWAYS":
        return True
    statement = _PER_CASE_READ.get(operation)
    if statement is None:
        return True
    row = conn.execute(statement, (case_id,)).fetchone()
    # A case the read cannot find REQUIRES the second signature (S1,
    # 2026-09-25). The gate runs first and 404s a case that does not exist,
    # so this branch was unreachable; under row-level security it is
    # reachable whenever the gate and the policy disagree, and a two-person
    # control must fail closed then, not switch itself off.
    if row is None:
        return True
    return bool(row[0])


#: The advisory lock `audit.chain_hash` takes on every audit insert, as
#: pg_locks shows a bigint key: the high half in classid, the low half in
#: objid, objsubid 1.
_HOLDS_CHAIN_LOCK = """
    WITH k AS (SELECT hashtextextended('audit.event.chain', 0) AS v)
    SELECT EXISTS (
      SELECT 1 FROM pg_locks l, k
       WHERE l.locktype = 'advisory' AND l.pid = pg_backend_pid()
         AND l.granted AND l.objsubid = 1
         AND l.classid = ((k.v >> 32) & 4294967295)::oid
         AND l.objid = (k.v & 4294967295)::oid)"""

#: How long the side connection waits for the audit chain before giving
#: up and logging: a future caller that breaks the rule fails one request
#: instead of freezing every audited action in the deployment.
_SIDE_LOCK_TIMEOUT = "5s"


def holds_audit_chain_lock(conn: psycopg.Connection) -> bool:
    """Whether `conn` has an open transaction that has already written an
    audit row, and so holds the chain lock until it ends."""
    if conn.info.transaction_status != psycopg.pq.TransactionStatus.INTRANS:
        return False
    return bool(conn.execute(_HOLDS_CHAIN_LOCK).fetchone()[0])


def record_out_of_band(conn: psycopg.Connection, *, action: str, actor_id,
                       object_type: str, object_id, case_id,
                       detail: dict) -> None:
    """Write one DENIED audit row that the caller's rollback cannot take.

    On a second connection, unless `conn` holds the audit chain lock (see
    the module docstring): then a second connection would wait on this
    very caller, so the row goes on `conn` and a warning says it will not
    survive that caller's rollback. Never raises: the refusal the row
    records stands whether or not it was recorded, and losing the record
    of an attempt must never become a way to make the attempt succeed."""
    params = (actor_id, action, object_type, object_id, case_id, Json(detail))
    statement = """INSERT INTO audit.event
                       (actor_id, actor_kind, action, object_type, object_id,
                        case_id, outcome, detail)
                   VALUES (%s, 'USER', %s, %s, %s, %s, 'DENIED', %s)"""
    try:
        if holds_audit_chain_lock(conn):
            log.warning(
                "%s for %s written on the caller's connection: it already "
                "holds the audit chain, so the row goes with its transaction",
                action, object_id)
            conn.execute(statement, params)
            return
    except psycopg.Error:
        log.exception("could not inspect the caller's locks before %s",
                      action)
    # The request role, as the request's own connection is (S1): an
    # audit append needs nothing more.
    from noctornal_api.db import connect_request as connect

    try:
        with connect() as side:
            side.execute("SELECT set_config('lock_timeout', %s, false)",
                         (_SIDE_LOCK_TIMEOUT,))
            side.execute(statement, params)
    except psycopg.errors.LockNotAvailable:
        log.exception("%s for %s was not recorded: the audit chain stayed "
                      "locked for %s", action, object_id, _SIDE_LOCK_TIMEOUT)
    except Exception:  # noqa: BLE001 - see the docstring
        log.exception("could not record %s for %s", action, object_id)
