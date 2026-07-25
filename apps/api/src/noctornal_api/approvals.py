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
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import psycopg
from psycopg.types.json import Json

from noctornal_api import notify_events

PENDING = "PENDING"
APPROVED = "APPROVED"
REJECTED = "REJECTED"
WITHDRAWN = "WITHDRAWN"
CONSUMED = "CONSUMED"


class ApprovalError(Exception):
    pass


@dataclass(frozen=True)
class Operation:
    """One four-eyeable operation.

    `permission` is what the APPROVER must independently hold. It is the
    same permission the requester needed, deliberately: an approver drawn
    from a wider pool than the actors is a rubber stamp with a job title.
    """

    key: str
    permission: str
    ttl: timedelta
    description: str


# The catalogue. docs/05 names four; docs/08 adds out-of-schedule purge;
# docs/04 adds credential reveal. Only `node.merge` has an implementation
# behind it today -- the rest are registered so that when those operations
# are built the control already exists and does not have to be retrofitted
# onto something that already shipped without it.
OPERATIONS: dict[str, Operation] = {
    "node.merge": Operation(
        "node.merge", permission="graph.merge", ttl=timedelta(hours=8),
        description="Fold one entity into another",
    ),
    "case.delete": Operation(
        "case.delete", permission="case.delete", ttl=timedelta(hours=24),
        description="Delete a case",
    ),
    "evidence.purge": Operation(
        "evidence.purge", permission="evidence.purge", ttl=timedelta(hours=24),
        description="Destroy evidence outside the retention schedule",
    ),
    "role.manage": Operation(
        "role.manage", permission="role.manage", ttl=timedelta(hours=24),
        description="Change a role definition",
    ),
    "collection_account.reveal": Operation(
        "collection_account.reveal", permission="collection_account.reveal",
        # Short: a credential reveal approved this morning and used this
        # evening is not the operation anybody agreed to.
        ttl=timedelta(minutes=30),
        description="Reveal a persona credential",
    ),
}

# A merge TTL of eight hours is one shift. Long enough that an approval
# obtained at handover survives to the end of the day; short enough that it
# cannot be banked.


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
        # then dual control is just a merge button that does not work.
        if case_id is not None:
            notify_events.approval_requested(
                self._c, case_id=case_id, request_id=record.id,
                operation=operation, permission=op.permission,
                justification=record.justification, actor_id=requested_by)
        return record

    def decide(self, request_id: UUID, *, decided_by: UUID, approve: bool,
               note: str | None = None) -> ApprovalRequest:
        """Approve or reject. The caller must ALREADY have checked that
        `decided_by` holds the operation's permission and has a fresh second
        factor -- see the module docstring.

        Self-approval is refused here as well as by the CHECK constraint.
        The constraint is the guarantee; this is the readable error.
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

        now = datetime.now(timezone.utc)
        # Guarded on the state we read, so a concurrent decision loses
        # rather than overwrites.
        row = self._c.execute(
            """UPDATE core.approval_request
                  SET state = %s, decided_by = %s, decided_at = %s,
                      decision_note = %s
                WHERE id = %s AND state = 'PENDING'
            RETURNING """ + _COLUMNS,
            (APPROVED if approve else REJECTED, decided_by, now,
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
        if record.case_id is not None:
            notify_events.approval_decided(
                self._c, case_id=record.case_id, request_id=record.id,
                operation=record.operation, requested_by=record.requested_by,
                approved=approve, note=record.decision_note,
                actor_id=decided_by)
        return record

    def withdraw(self, request_id: UUID, *, actor_id: UUID) -> ApprovalRequest:
        """The requester changing their mind. Not a decision -- a withdrawn
        request never had one, and the distinction matters when reading the
        history back."""
        row = self._c.execute(
            """UPDATE core.approval_request
                  SET state = %s
                WHERE id = %s AND state = 'PENDING' AND requested_by = %s
            RETURNING """ + _COLUMNS,
            (WITHDRAWN, request_id, actor_id),
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
        the operation itself."""
        self._c.execute(
            "UPDATE core.approval_request SET result_ref = %s WHERE id = %s",
            (result_ref, request_id))

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
        self._c.execute(
            """INSERT INTO audit.event
                   (actor_id, actor_kind, action, object_type, object_id,
                    case_id, outcome, detail)
               VALUES (%s, 'USER', 'APPROVAL_CONSUME_REFUSED', 'approval_request',
                       %s, %s, 'DENIED', %s)""",
            (actor_id, request_id, case_id,
             Json({"reason": reason, "operation": operation})))
        return ApprovalError(
            "this approval cannot be used for this operation: it may have "
            "expired, already been used, belong to someone else, or have "
            "been granted for different parameters")

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
    """Per-case policy. Today only merges have a switch; the irreversible
    operations docs/05 names will be unconditional when they are built,
    because there is no version of "delete the case" that is worth doing
    with one signature."""
    if operation != "node.merge":
        return True
    row = conn.execute(
        'SELECT dual_control_merge FROM core."case" WHERE id = %s',
        (case_id,)).fetchone()
    return bool(row and row[0])
