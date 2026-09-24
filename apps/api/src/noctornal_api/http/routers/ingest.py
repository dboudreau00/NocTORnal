"""Phase 9 over HTTP: the 202 endpoint, key management, and victim PII.

## Two different authentication models, deliberately

`POST /ingest` authenticates with an **ingest API key**, not a session.
Everything else on this router authenticates with a session and is gated
by the five-part check. They are separated because the key model is
write-only by construction:

> **Invariant 11.** Ingest keys are write-only. A `case:read` scope on an
> `ingest.api_key` is a bug, and there is a check constraint saying so. A
> leaked ingest key means junk data, never the case file.

So the key path can reach exactly one endpoint, and that endpoint returns
a batch id and nothing else. There is no route where a key reads anything.

## 202, and why nothing is parsed in the request

docs/12: respond immediately, parse asynchronously, never block the
caller on parsing. `accept()` persists the raw bytes and returns; parsing
happens later through `POST /batches/{id}/parse`. That seam is what makes
a malformed 50MB dump somebody else's problem rather than a request
timeout, and it is what lets `ingest.dead_letter` capture the unparseable
fragment instead of losing it (invariant 12).

## Victim credentials are masked, and the reveal is a two-person act

`credentials_masked` is the default view. Revealing one requires a live
`ingest.pii_authorisation` granted by somebody holding
`victim_pii.authorise` -- a permission SECURITY_OFFICER holds and case
roles do not -- and the reveal itself is step-up gated and audited per
credential. docs/16 L2 is BLOCKING and unresolved: the lawful basis for
holding this data about thousands of uninvolved people is an external
determination, and none of the controls here substitute for it.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import NamedTuple
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, Field

from noctornal_api.http.deps import (
    CurrentUser,
    audit_auth_event,
    authorize_object,
    counted_at_case_gate,
    current_user,
    effective_labels,
    get_conn,
    refuse_if_case_read_only,
    require_global,
    require_step_up,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit, read_body_capped
from noctornal_api.ingest import (
    CATEGORIES,
    HIGH_RISK_CATEGORIES,
    TRIAGE_STATES,
    AuthorisationRequired,
    CaseMismatch,
    IngestError,
    IngestService,
    RepairInvalid,
    redact_structure,
)
from noctornal_api.rawstore import MissingObject, RawBatchStorage, RawStoreError
from noctornal_api.security.access import (
    CHECK_ROLE,
    CHECK_STEP_UP,
    AccessResolutionError,
    Decision,
    evaluate,
    tlp_from_name,
)
from noctornal_api.security.sessions import STEP_UP_FRESHNESS
from noctornal_api.stores import PgAccessResolver


def _with_raw(conn: psycopg.Connection, **kw) -> IngestService:
    """An `IngestService` that can actually persist and re-read raw bytes.

    Built per request like every other service here. `RawBatchStorage`
    raises when MinIO is not configured rather than degrading to a no-op:
    an accept path that acknowledges bytes and drops them is worse than one
    that refuses, because the partner is told it worked.
    """
    try:
        storage = RawBatchStorage()
    except RawStoreError as exc:
        raise Problem(
            503, "Storage unavailable",
            "raw ingest storage is not configured, and the raw payload "
            "must be persisted before parsing. Set MINIO_ENDPOINT / "
            "MINIO_ACCESS_KEY / MINIO_SECRET_KEY and INGEST_BUCKET.") from exc
    return IngestService(conn, storage, **kw)

router = APIRouter(prefix="/ingest", tags=["ingest"])

#: The console prints this when a key is issued. It names the legal-review
#: item by its register number, which counsel uses, and not a design
#: document's path, which the reader cannot open (ux19-copy
#: developer-speak-in-copy, 2026-09-23; L4's notice changed the same way).
L2_NOTICE = (
    "Legal review item L2 is still open: the lawful basis for holding "
    "stealer-log data about thousands of uninvolved people, victim "
    "notification obligations, and the real retention period are for "
    "counsel to determine. The 90-day default is a placeholder."
)


def _key_from_header(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise Problem(401, "Unauthenticated", "no ingest key presented")
    return authorization[7:].strip()

def _own_record(conn: psycopg.Connection, record_id: UUID) -> tuple:
    """(case_id, classification, compartments) for a record, or a 404.

    `ingest.record` carries its own classification and compartments --
    migration 0033 calls the compartment "STEALER LOG CONTROL 1" -- and
    `IngestService` writes both and reads neither. So the router has to,
    or a record's victims are visible to anyone holding the global
    `ingest.read` verb. Reproduced live: a GREEN, unassigned analyst
    listed the credential inventory of an AMBER_STRICT compartmented
    record.
    """
    row = conn.execute(
        """SELECT case_id, classification, compartments
             FROM ingest.record WHERE id = %s""", (record_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such record")
    return row[0], row[1], frozenset(row[2] or [])


def _operator_may_see_quarantine(conn: psycopg.Connection, user: CurrentUser,
                                 classification: str,
                                 compartments: frozenset[str]) -> None:
    """The gate for a record attached to NO case. Raises 404 or returns.

    Written out rather than reusing `require_global` because that is a
    FastAPI dependency: it runs before the handler, and whether a record is
    unattached is only known after it has been read. The three checks are
    the same ones `deps.require_global` makes — verb through a global role,
    the account active, and step-up freshness where the permission demands
    it — plus the label check, which `require_global` never makes because
    it knows nothing about an object.

    Ordering: 404 for every failure. "This record exists but is not yours"
    is itself a disclosure about a compartmented feed, and a status code
    that distinguishes the two is an existence oracle (deps.py rule 2).
    """
    row = conn.execute(
        """SELECT bool_or(p.requires_step_up)
             FROM iam.user_role ur
             JOIN iam.role_permission rp ON rp.role_key = ur.role_key
             JOIN iam.permission p ON p.key = rp.permission_key
             JOIN iam.app_user u ON u.id = ur.user_id
            WHERE ur.user_id = %s AND rp.permission_key = 'ingest.manage'
              AND u.is_active""", (user.user_id,)).fetchone()
    if row is None or row[0] is None:
        raise Problem(404, "Not found", "no such record")
    if row[0]:
        fresh = (
            user.session_mfa_at is not None
            and (datetime.now(user.session_mfa_at.tzinfo) - user.session_mfa_at)
            < STEP_UP_FRESHNESS)
        if not fresh:
            raise Problem(403, "Forbidden", "re-authentication required")
    clearance, held = user_ceiling(conn, user.user_id)
    # Unattached is not unclassified: the record carries the issuing key's
    # ceiling, and `/quarantine` applies exactly this predicate in SQL.
    # `Tlp` is an IntEnum ordered to match the SQL enum, so `>` here means
    # the same thing as `<=` does in the query.
    if tlp_from_name(classification) > clearance \
            or not frozenset(compartments).issubset(held):
        raise Problem(404, "Not found", "no such record")


def _authorise_record(conn: psycopg.Connection, user: CurrentUser,
                      record_id: UUID, permission: str) -> UUID | None:
    """Gate a record by its OWN case and its OWN labels.

    Answered as 404 either way: a status code must not be an existence
    oracle (deps.py rule 2), and "this record exists but is not yours" is
    itself a disclosure about a compartmented case.
    """
    case_id, classification, compartments = _own_record(conn, record_id)
    if case_id is None:
        # Quarantine: no case assignment can reach it, so the OPERATOR verb
        # is the gate -- the same one `/quarantine` uses -- and the labels
        # still apply.
        #
        # This branch used to `return case_id` and check nothing at all. It
        # was safe for `credentials`, whose service layer re-applies the
        # labels and refuses a null case outright; it was a hole for
        # `rescore`, which reaches `score_record` -- a method with no label
        # predicate that WRITES `priority`. A GREEN analyst with no case
        # assignment could confirm a compartmented quarantine record
        # existed, read its watched-selector hit count out of the returned
        # score, and reorder the operator's triage queue.
        _operator_may_see_quarantine(conn, user, classification, compartments)
        return None
    try:
        authorize_object(conn, user, case_id=case_id,
                         permission_key=permission,
                         classification=classification,
                         compartments=compartments)
    except Problem:
        raise Problem(404, "Not found", "no such record") from None
    return case_id


def _decision_global(conn: psycopg.Connection, user: CurrentUser,
                     permission_key: str, *, classification: str = "CLEAR",
                     compartments: frozenset[str] = frozenset()) -> Decision | None:
    """The five-part gate on a GLOBAL verb, as a question.

    `PgAccessResolver.resolve_global` gathers the facts -- the verb through
    a global role, the account active, step-up, and the caller's labels
    against the object's -- and `evaluate()` decides, so a decision about
    an object with no case is the same evaluator's decision as every
    other. None when the context cannot be resolved (an inactive account,
    an unknown permission), which every caller treats as denied.
    """
    try:
        ctx = PgAccessResolver(conn).resolve_global(
            user_id=user.user_id, permission_key=permission_key,
            object_classification=classification,
            object_compartments=compartments,
            mfa_satisfied_at=user.session_mfa_at)
    except AccessResolutionError:
        return None
    return evaluate(ctx)


def _holds_global(conn: psycopg.Connection, user: CurrentUser,
                  permission_key: str) -> tuple[bool, bool]:
    """(held, fresh): `require_global`'s facts, read off the one gate.

    Until 2026-09-11 this was its own three-way SQL -- a second copy of a
    rule `evaluate()` owns, in the router whose every shipped authz defect
    was a query that never called the gate. It now asks the gate with no
    object (CLEAR, no compartments) and reads two named checks off the
    decision: the verb, and step-up freshness. `fresh` is True whenever
    the permission does not require step-up, exactly as before.
    """
    decision = _decision_global(conn, user, permission_key)
    if decision is None:
        return False, False
    return (CHECK_ROLE not in decision.failed_checks,
            CHECK_STEP_UP not in decision.failed_checks)


def _case_allows(conn: psycopg.Connection, user: CurrentUser, case_id: UUID,
                 permission_key: str, *, classification: str | None = None,
                 compartments: frozenset[str] = frozenset()) -> bool:
    """The five-part gate on one case, as a question: `authorize_object`
    without the refusal and the audit row, for a listing that answers
    what the caller may see rather than refusing the whole request.
    Element labels compose with the case's exactly as `authorize_object`
    composes them (`effective_labels`). A resolution failure -- or a case
    that no longer exists -- is False: it fails closed."""
    try:
        eff_cls, eff_comp = effective_labels(conn, case_id, classification, compartments)
        ctx = PgAccessResolver(conn).resolve(
            user_id=user.user_id, case_id=case_id, permission_key=permission_key,
            object_classification=eff_cls, object_compartments=eff_comp,
            mfa_satisfied_at=user.session_mfa_at,
            # A question, so no audit row of any kind: one queue load asked
            # it per case and per label set, and each answer counted as a
            # break-glass use (final review U19 fix round, 2026-09-23, g02).
            count_use=False)
    except (AccessResolutionError, Problem):
        return False
    return evaluate(ctx).allowed


def _authorised_cases_for_ingest(conn: psycopg.Connection,
                                 user: CurrentUser) -> list[UUID]:
    """Cases where the five-part gate allows `ingest.read` -- asked of the
    gate, one case at a time (2026-09-11). Until then this was a SQL
    restatement of four of the five checks, which was correct on the day
    it was written and had no way to stay so: a check added to
    `evaluate()` would not have been added here."""
    candidates = conn.execute(
        "SELECT case_id FROM iam.case_assignment WHERE user_id = %s ORDER BY case_id",
        (user.user_id,)).fetchall()
    return [row[0] for row in candidates
            if _case_allows(conn, user, row[0], "ingest.read")]


# ---------------------------------------------------------------------------
# The write path. Key-authenticated, and the ONLY endpoint a key can reach.
# ---------------------------------------------------------------------------

@router.post("", status_code=202, response_model=dict,
             # NOT a USER-scoped limit: this endpoint's caller presents an
             # ingest key, not a session, and a USER-scoped subject would
             # resolve `current_user` and reject every legitimate
             # submission. See the catalogue entry for why CREDENTIAL
             # scope is sound here and was not for the blanket ceiling.
             dependencies=[Depends(rate_limit("ingest.submit"))])
async def submit(
    request: Request,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None,
                                         alias="Idempotency-Key"),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Accept a batch and return 202. **Nothing is parsed here.**

    Authenticated by an ingest API key, which is write-only by
    construction (invariant 11) -- so a leaked key means junk data in a
    quarantine bucket, never the case file.

    The peer address is taken from the server's own view of the
    connection, never from a header, because the key's IP allowlist is
    only a control if the caller cannot choose the address it is compared
    against.

    The body is read through `read_body_capped` against the key's own
    `max_bytes_per_request` (a column on `ingest.api_key`, 32 MiB by
    default, set per key at issue), and a body over it is a 413 with the
    cap in the message. Until 2026-09-09 this line was `await
    request.body()`: the whole body was accumulated in memory FIRST and
    `accept()` compared its length with the cap afterwards, so a partner
    -- or anyone holding a leaked key -- could hand the API gigabytes and
    the refusal arrived only once they had been buffered. The cap was
    documented and enforced and useless against the thing a cap is for.
    Now a declared length over the cap is refused before a byte is read,
    and a chunked body is refused on the chunk that crosses it. The key is
    authenticated BEFORE the body is read, so an unauthenticated caller's
    body is never read at all. `accept()` keeps its own length check for
    callers that are not this route.
    """
    svc = _with_raw(conn)
    # From the server's own view of the connection, never from a header:
    # an allowlist is only a control if the caller cannot choose the
    # address it is compared against.
    peer = request.client.host if request.client else None
    token = _key_from_header(authorization)
    key = svc.authenticate(token, peer_ip=peer)
    if key is not None and key.get("ip_allowlist") and not peer:
        # Defence in depth, and as of CR6 (2026-07-26) it is UNREACHABLE
        # by design rather than by accident. Saying so, because the
        # previous comment here described service behaviour that has since
        # changed and would mislead the next reader.
        #
        # `authenticate()` used to read `if allowlist and peer_ip:`, which
        # SKIPPED the check whenever the peer address was unknown -- a unix
        # socket, some proxy setups -- so a key restricted to a partner
        # CIDR was accepted from anywhere. This guard was written to catch
        # that, and could not: the dict `authenticate()` returned omitted
        # `ip_allowlist` entirely, so the condition was always false. A
        # defence written twice and connected zero times.
        #
        # The service now returns None in that case, so `key is None`
        # short-circuits before this line. `ip_allowlist` is nevertheless
        # in the dict and this check nevertheless runs, so that if the
        # service is ever relaxed the router still fails closed.
        raise Problem(401, "Unauthenticated", "invalid ingest key")
    if key is None:
        # One message for every failure mode -- unknown, revoked, expired,
        # wrong address. Distinguishing them tells a probing caller which
        # half of their guess was right.
        raise Problem(401, "Unauthenticated", "invalid ingest key")

    raw = await read_body_capped(
        request, int(key["max_bytes_per_request"]),
        what="a submission on this ingest key")
    try:
        result = svc.accept(
            key, raw, content_type=request.headers.get("content-type"),
            idempotency_key=idempotency_key)
    except IngestError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {
        "batch_id": str(result.batch_id),
        "accepted": result.accepted,
        "duplicate": result.duplicate,
        "detail": result.detail,
        "notice": ("Accepted for later parsing. Nothing has been parsed, "
                   "categorised or written to a case yet. Unparseable "
                   "fragments go to the dead-letter queue with the raw "
                   "bytes rather than being dropped."),
    }


# ---------------------------------------------------------------------------
# Key management. Session-authenticated.
# ---------------------------------------------------------------------------

class IssueKeyBody(BaseModel):
    name: str = Field(min_length=3)
    declared_category: str = "UNKNOWN"
    environment: str = "live"
    source_id: UUID | None = None
    forced_compartment: str | None = None
    classification_ceiling: str = "AMBER"
    default_reliability: str = "F"
    ip_allowlist: list[str] = Field(default_factory=list)
    #: Mandatory expiry. docs/12 treats a key with no expiry as one nobody
    #: will ever notice is still live. The ceiling is the service's
    #: MAX_KEY_TTL (365 days): this said 730, so a request for 400 passed
    #: validation and came back as the service's refusal, and the Keys
    #: form (2026-09-23) needs one number to offer.
    ttl_days: int = Field(default=90, ge=1, le=365)


@router.post("/keys", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("evidence.export"))])
def issue_key(
    body: IssueKeyBody,
    user: CurrentUser = Depends(require_global("ingest.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Issue a key. **The secret is returned exactly once, here.**

    It is never stored in plaintext and cannot be recovered -- a lost key
    is reissued, not looked up. Expiry is mandatory: docs/12 treats a key
    with no expiry as one nobody will ever notice is still live.
    """
    try:
        issued = IngestService(conn).issue_key(
            name=body.name, owner_user_id=user.user_id,
            declared_category=body.declared_category,
            environment=body.environment, source_id=body.source_id,
            forced_compartment=body.forced_compartment,
            classification_ceiling=body.classification_ceiling,
            default_reliability=body.default_reliability,
            ip_allowlist=body.ip_allowlist or None,
            ttl=timedelta(days=body.ttl_days))
    except IngestError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {
        "id": str(issued.id), "key_id": issued.key_id,
        "secret": issued.token,
        "expires_at": issued.expires_at.isoformat(),
        "notice": ("This secret is shown ONCE and is not stored in "
                   "recoverable form. The key is write-only: it can submit "
                   "batches and read nothing."),
    }


class RevokeKeyBody(BaseModel):
    reason: str = Field(min_length=5)


@router.post("/keys/{key_row_id}/revoke", response_model=dict)
def revoke_key(
    key_row_id: UUID, body: RevokeKeyBody,
    user: CurrentUser = Depends(require_global("ingest.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Revoke a key. Step-up gated through `ingest.manage`, audited with
    the reason, and 404 for a key that is unknown or already revoked (it
    answered "revoked": true for both until 2026-09-23)."""
    try:
        IngestService(conn).revoke_key(
            key_row_id, actor_id=user.user_id, reason=body.reason)
    except IngestError as exc:
        if "no such live key" in str(exc):
            raise Problem(404, "Not found", safe_detail(exc)) from exc
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"id": str(key_row_id), "revoked": True}


@router.get("/keys/stale", response_model=dict)
def stale_keys(
    days: int = Query(30, ge=1, le=365),
    user: CurrentUser = Depends(require_global("ingest.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Keys nobody has used lately.

    docs/12 is blunt about what these are: either dead integrations or
    somebody else's. Both are reasons to revoke.
    """
    rows = IngestService(conn).stale_keys(days=days)
    return {"keys": rows, "count": len(rows), "unused_for_days": days}



# ---------------------------------------------------------------------------
# Parsing, and what failed to parse
# ---------------------------------------------------------------------------

class ParseBody(BaseModel):
    #: Where the parsed records land. Optional, because a batch may be
    #: triaged before anyone decides which case it belongs to.
    case_id: UUID | None = None
    parser_version: str = "1"


@router.post("/batches/{batch_id}/parse", response_model=dict,
             dependencies=[Depends(rate_limit("capture"))])
def parse_batch(
    batch_id: UUID, body: ParseBody,
    user: CurrentUser = Depends(require_global("ingest.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Parse an accepted batch.

    Separate from acceptance so a malformed 50MB dump is a background
    problem rather than a request timeout, and so the dead-letter queue
    can hold what did not parse.
    """
    if body.case_id is not None:
        # Parsing INTO a case writes records there, so it needs the case
        # gate and not just the global ingest verb.
        authorize_object(conn, user, case_id=body.case_id,
                         permission_key="ingest.manage")
    if conn.execute("SELECT 1 FROM ingest.batch WHERE id = %s",
                    (batch_id,)).fetchone() is None:
        raise Problem(404, "Not found", "no such batch")
    # `raw_for` reads the object and verifies it against `raw_sha256`
    # before returning. Note what is NOT here any more: this used to read
    # `ingest.batch.raw_bytes`, which is a bigint -- the byte COUNT --
    # so `bytes(<int>)` allocated that many NULs and every parse shredded
    # a run of zeros into the dead-letter queue without touching the
    # batch. Re-parsing something that is not what arrived attributes
    # records to a submission that never happened.
    svc = _with_raw(conn)
    try:
        raw = svc.raw_for(batch_id)
    except MissingObject as exc:
        raise Problem(
            409, "Conflict",
            "the raw payload for this batch is not in object storage. A "
            "batch accepted before storage was configured cannot be "
            "re-parsed; the partner has to resend. Parsing an empty payload "
            "would mark the batch PARSED with zero records, which is a "
            "silent loss.") from exc
    except IngestError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    try:
        result = svc.parse_batch(
            batch_id, raw=raw, case_id=body.case_id,
            parser_version=body.parser_version)
    except IngestError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return {
        "batch_id": str(batch_id), "records": result.records,
        "dead_letters": result.dead, "duplicates": result.duplicates,
        "warnings": result.warnings,
        "notice": ("Fragments that failed to parse are in the dead-letter "
                   "queue, structurally redacted: keys, types and lengths, "
                   "never values. The verbatim bytes stay in the batch's raw "
                   "object under its own retention. Silent drops are how you "
                   "find out six months later that a feed has been "
                   "half-failing."),
    }


@router.get("/dead-letters", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def dead_letters(
    api_key_id: UUID | None = Query(None),
    case_id: UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What did not parse, and why -- scoped to what the caller may read.

    A rising dead-letter rate on one key is the signal that a provider
    changed their format -- and it is invisible unless somebody looks,
    which is what this endpoint is for.

    **Every decision here is `evaluate()`'s, since 2026-09-11.** The verb
    (`_holds_global`), the caller's cases (`_authorised_cases_for_ingest`)
    and each returned row against its own labels (`visible`, below) are
    the one gate's answers; the SQL predicates only bound the fetch.

    **Scope, since 2026-09-09.** Until then this listed EVERY case's dead
    letters to any holder of the global `ingest.read` verb, filtered only
    by the caller's clearance ceiling. An ANALYST on one case read the
    partner key, error class, classification and failure rate of every
    other case's feeds: the same over-broad grant `/records` and
    `/quarantine` were split apart to avoid, reachable through the queue
    next to them. `ingest.dead_letter` carries no `case_id` -- the batch
    is parsed INTO a case and the case lands on `ingest.record` -- so a
    dead letter's case is the case its batch's records went to, and the
    listing is the union of two scopes, each behind its own verb:

    - rows whose batch fed a case the caller is assigned to with
      `ingest.read` (the five-part gate's assignment, expiry, verb and
      labels, via `_authorised_cases_for_ingest`), for holders of the
      global `ingest.read` verb;
    - rows whose batch fed NO case -- wholly dead-lettered, or parsed into
      quarantine -- for holders of the operator verb `ingest.manage`,
      which is the verb `/quarantine` requires and the one the console
      probes to decide whether to show the quarantine section at all.

    A batch re-parsed into a second case belongs to both; each case's
    readers see the row, and `case_ids` names only the cases the CALLER
    may read. The caller's own clearance and compartments still bound
    every row, as before. `ingest.manage` requires step-up: an operator
    whose step-up has lapsed keeps the case rows they can read and is told
    in `scope.unattached_withheld` that the unattached rows were not
    listed, rather than being handed a listing that looks complete.

    No `require_global` on the route, deliberately (the same reasoning as
    `rescore`): which verb applies depends on what the row IS. A caller
    holding neither verb is refused 403 with the same AUTHZ_DENIED audit
    `require_global` would have written.

    **`case_id` narrows to one case (2026-09-23).** The Feeds pane is
    opened inside a case, and it showed the same deployment-wide list in
    every case under "N unparsed fragments", which read as that case's
    failures when none of them were (ux12-feeds:dead-letters-no-feed-no-
    scope). With `case_id` the listing is the dead letters of batches that
    fed THAT case, unattached ones left out; a case the caller may not
    read is the same 404 `/records` gives. Each row also carries its
    `api_key_id`, which is what the `api_key_id` filter takes, so the pane
    can filter by the feed it names.
    """
    reads, _ = _holds_global(conn, user, "ingest.read")
    manages, fresh = _holds_global(conn, user, "ingest.manage")
    if not (reads or manages):
        audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, None,
                         {"permission": "ingest.read", "scope": "global"})
        raise Problem(403, "Forbidden", "missing global permission ingest.read")
    if manages and not fresh and not reads:
        audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, None,
                         {"permission": "ingest.manage", "scope": "global",
                          "failed_checks": ["step_up_freshness"]})
        raise Problem(403, "Forbidden", "re-authentication required")
    allowed = _authorised_cases_for_ingest(conn, user) if reads else []
    unattached = manages and fresh
    withheld = "re-authentication required" if manages and not fresh else None
    # The cases whose batches bound the fetch, and whether unattached rows
    # join them. `allowed` stays whole for naming a row's cases.
    fed_scope = allowed
    with_unattached = unattached
    if case_id is not None:
        if case_id not in allowed:
            raise Problem(404, "Not found", "no such case")
        fed_scope = [case_id]
        with_unattached = False
        # Nothing unattached was asked for, so nothing was withheld.
        withheld = None

    if api_key_id is not None and not unattached:
        # A key is visible to a case reader only if it fed one of their
        # cases. 404 either way: "that key exists but fed nobody you read"
        # is a disclosure about the deployment's feeds (deps.py rule 2),
        # and it is the answer `/records` gives for a case off-scope.
        fed = conn.execute(
            """SELECT 1 FROM ingest.batch b
                 JOIN ingest.record r ON r.batch_id = b.id
                WHERE b.api_key_id = %s AND r.case_id = ANY(%s::uuid[])
                LIMIT 1""", (api_key_id, allowed)).fetchone()
        if fed is None:
            raise Problem(404, "Not found", "no such key")

    # The fragment IS returned, and only because migration 0040 made that
    # safe: it is redacted structurally before it is stored, so what comes
    # back is keys, types and lengths and never a value. A queue you cannot
    # see the shape of is a queue nobody can diagnose, which is how a feed
    # half-fails for six months.
    #
    # Rows recorded before 0040 are verbatim and are withheld: `redacted`
    # says which is which, and `scripts/redact_dead_letters.py` is the
    # repair. Never render `raw_fragment` as HTML -- invariant 10's
    # reasoning applies to any attacker-controlled bytes, not only samples.
    clearance, compartments = user_ceiling(conn, user.user_id)
    rows = conn.execute(
        """SELECT dl.id, dl.batch_id, dl.error_class, dl.error_detail,
                  dl.occurred_at, dl.replayed_at, dl.resolution,
                  dl.raw_fragment, dl.redacted, dl.classification,
                  dl.retain_until, k.name, k.key_id,
                  ARRAY(SELECT DISTINCT r.case_id FROM ingest.record r
                         WHERE r.batch_id = dl.batch_id
                           AND r.case_id = ANY(%s::uuid[])),
                  dl.compartments, dl.api_key_id
             FROM ingest.dead_letter dl
             LEFT JOIN ingest.api_key k ON k.id = dl.api_key_id
            WHERE (%s::uuid IS NULL OR dl.api_key_id = %s)
              AND dl.purged_at IS NULL
              AND dl.classification <= %s::core.tlp
              AND dl.compartments <@ %s
              AND (EXISTS (SELECT 1 FROM ingest.record r
                            WHERE r.batch_id = dl.batch_id
                              AND r.case_id = ANY(%s::uuid[]))
                   OR (%s AND NOT EXISTS (SELECT 1 FROM ingest.record r
                                           WHERE r.batch_id = dl.batch_id
                                             AND r.case_id IS NOT NULL)))
            ORDER BY dl.occurred_at DESC LIMIT %s""",
        (allowed, api_key_id, api_key_id, clearance.name, list(compartments),
         fed_scope, with_unattached, limit)).fetchall()

    # The decision on each ROW is the gate's, not the query's (2026-09-11).
    # The predicates above bound the fetch and the LIMIT; what is returned
    # is what `evaluate()` allows against the row's own labels -- through
    # its case for a row whose batch fed one, and through the global verb
    # for an unattached row. So a predicate left off this SELECT, which is
    # the shape of every authz defect this router has shipped, is a row
    # the gate still refuses. Decided once per (case, labels): a feed's
    # dead letters share both, so this is a handful of resolutions, not
    # one per row.
    decided: dict[tuple, bool] = {}

    def visible(row) -> bool:
        labels = (row[9], frozenset(row[14] or []))
        for case in (row[13] or []):
            key = (case, labels)
            if key not in decided:
                decided[key] = _case_allows(
                    conn, user, case, "ingest.read",
                    classification=labels[0], compartments=labels[1])
            if decided[key]:
                return True
        if row[13]:
            return False
        key = (None, labels)
        if key not in decided:
            decision = _decision_global(conn, user, "ingest.manage",
                                        classification=labels[0],
                                        compartments=labels[1])
            decided[key] = bool(unattached and decision is not None
                                and decision.allowed)
        return decided[key]

    rows = [row for row in rows if visible(row)]
    # Who may repair and replay what, so the pane offers the action only
    # where the replay route would take it: `ingest.replay` for any row it
    # lists, and the operator for an unattached row into quarantine
    # (`replay`'s docstring). Every reader was offered it and a REVIEWER
    # met a 403 inside the form (fix round, 2026-09-23). Asked of the gate
    # with no audit row: a listing asks, it does not refuse.
    replays, _ = _holds_global(conn, user, "ingest.replay")
    out = {"dead_letters": [
        {"id": str(r[0]), "batch_id": str(r[1]) if r[1] else None,
         "error_class": r[2], "error_detail": r[3],
         "occurred_at": r[4].isoformat() if r[4] else None,
         "replayed_at": r[5].isoformat() if r[5] else None,
         "resolution": r[6],
         "fragment": r[7] if r[8] else None,
         "fragment_withheld": not r[8],
         "classification": r[9],
         "retain_until": r[10].isoformat() if r[10] else None,
         # The feed, named -- this endpoint's docstring has always said a
         # rising rate on ONE KEY is the signal, and until 2026-09-09 the
         # rows never said which key. `/records` already shows both to
         # the same readers.
         "feed": r[11], "key_id": r[12],
         "api_key_id": str(r[15]) if r[15] else None,
         "case_ids": [str(c) for c in (r[13] or [])],
         "unattached": not (r[13] or []),
         "can_replay": bool(replays or not (r[13] or []))}
        for r in rows],
        "count": len(rows),
        "scope": {"cases": [str(c) for c in allowed],
                  "unattached": with_unattached,
                  "unattached_withheld": withheld,
                  # Whether a replay may name a case at all; the case's
                  # own gate still answers for that case.
                  "replay_into_case": replays,
                  **({"case": str(case_id)} if case_id else {})},
        "notice": ("Fragments are structurally redacted: keys, types and "
                   "lengths only, never values. Rows recorded before "
                   "2026-07-25 are withheld until the repair script runs. "
                   "Listed: dead letters of feeds into cases you are "
                   "assigned to, plus unattached ones if you hold "
                   "ingest.manage (`scope` says which applied).")}
    if api_key_id is not None:
        out["dead_letter_rate_24h"] = IngestService(conn).dead_letter_rate(
            api_key_id)
    return out


class ReplayBody(BaseModel):
    #: The corrected fragment. The ORIGINAL is never overwritten -- what
    #: arrived is evidence of what the provider sent, and a repair that
    #: destroys it makes the next format change unattributable.
    repaired: str = Field(min_length=1)
    case_id: UUID | None = None


class _Reach(NamedTuple):
    """How the caller sees one dead letter (`_dead_letter_reach`), and
    what a replay needs to gate on: the fragment's own labels, which are
    the labels of the record a replay makes (the issuing key's ceiling and
    forced compartment, on both), and the cases its batch fed."""
    #: "case", "operator", or None when the listing would not show it.
    how: str | None
    classification: str | None = None
    compartments: frozenset[str] = frozenset()
    #: Every case a record of its batch went to: the dead letter's own.
    fed: tuple[UUID, ...] = ()
    #: Those of `fed` the caller reads it through (`how == "case"`).
    seen: tuple[UUID, ...] = ()


def _dead_letter_reach(conn: psycopg.Connection, user: CurrentUser,
                       dead_letter_id: UUID) -> _Reach:
    """How the caller sees this dead letter, if at all: the listing's rule
    for one row. "case" through a case its batch fed (`ingest.read` on
    that case against the row's own labels); "operator" for a row whose
    batch fed no case (the operator verb, fresh, against the same labels);
    None when the listing would not show it.

    Asked as questions (`_case_allows`), so nothing here counts a
    break-glass use: `replay` counts once, at the gate that lets the
    replay through (r2 c5, 2026-09-24)."""
    row = conn.execute(
        """SELECT dl.classification, dl.compartments,
                  ARRAY(SELECT DISTINCT r.case_id FROM ingest.record r
                         WHERE r.batch_id = dl.batch_id
                           AND r.case_id IS NOT NULL)
             FROM ingest.dead_letter dl
            WHERE dl.id = %s AND dl.purged_at IS NULL""",
        (dead_letter_id,)).fetchone()
    if row is None:
        return _Reach(None)
    labels = (row[0], frozenset(row[1] or []))
    fed = tuple(row[2] or ())
    if fed:
        seen = tuple(case for case in fed
                     if _case_allows(conn, user, case, "ingest.read",
                                     classification=labels[0],
                                     compartments=labels[1]))
        return _Reach("case" if seen else None, *labels, fed, seen)
    decision = _decision_global(conn, user, "ingest.manage",
                                classification=labels[0],
                                compartments=labels[1])
    return _Reach("operator" if decision is not None and decision.allowed
                  else None, *labels)


# A read-only case (CLOSED, ARCHIVED or PURGED) refuses a record put into
# it or triaged in it: that is content, not governance (the owner's
# decision in force for Alpha 6). The refusal is g13's one gate,
# `deps.refuse_if_case_read_only`: the states `cases.CONTENT_READ_ONLY_STATES`,
# the 409 titled `CASE_READ_ONLY_TITLE` the console turns read-only on,
# and a CASE_READ_ONLY_REFUSED audit row. Replay, attach and category
# correction gate on `ingest.replay`, a content verb, so `authorize_object`
# refuses them itself; record triage gates on `ingest.read`, a reader's
# verb, and calls the gate by hand. (A second copy of the check here
# refused only CLOSED and ARCHIVED, titled its 409 "Conflict" and wrote no
# audit row: merged away 2026-09-24.)


@router.post("/dead-letters/{dead_letter_id}/replay", response_model=dict,
             dependencies=[Depends(rate_limit("capture"))])
def replay(
    dead_letter_id: UUID, body: ReplayBody,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Re-parse a repaired fragment after fixing the parser.

    **The dead letter is gated by what it IS (2026-09-23).** The route
    checked the global verb and, when a case was named, that case, and
    never the dead letter: any `ingest.replay` holder could replay a RED
    or compartmented fragment from a feed into a case they did not read,
    by id, and make a record of it. The console offers Replay since the
    same date, so the dead letter now has to be one the caller's listing
    would show them (`_dead_letter_reach`), and a row they may not see
    gets the same 404 an unknown id gets.

    **The operator replays an unattached one into quarantine.** A dead
    letter whose batch fed no case is listed only to the operator
    (`ingest.manage`, fresh), and `ingest.replay` belongs to the analyst
    and lead investigator roles, so on a deployment that keeps those
    duties apart nobody could replay it at all (fix round, 2026-09-23).
    Re-parsing into quarantine is the job the operator verb already does
    for a whole batch (`/batches/{id}/parse` with no case), so that one
    path is theirs; putting the record into a case still needs
    `ingest.replay` on that case, exactly as attaching one does.

    **The target is gated at the fragment's labels, and counted (r2 c5,
    2026-09-24).** The only gate at the dead letter's own labels was the
    reach question, which counts nothing, and the case named was gated at
    its own labels. So a RED fragment on an AMBER case, visible only
    under a grant, was replayed into a RED record with the grant unused on
    the officer's card, and a grant on one case let a RED record into
    another case the caller is not cleared for there. Now the case named
    is asked `ingest.replay` with the fragment's labels, as attach asks
    with the record's; a replay into quarantine of a row seen through a
    case is counted at that case (`ingest.read`, the fragment's labels),
    preferring a case the caller reads without a grant, so the grant is
    counted only where it is what let the replay through.

    **Never between cases (r2 c19, 2026-09-24).** A dead letter's case is
    any case its batch fed, and the record a replay makes keeps the
    batch. A replay into some other case the caller works therefore made
    the whole batch's dead letters that case's too: its readers listed
    them, feed and key included, and could replay them. Attach refuses a
    move between cases, and so does this. A row that belongs to no case
    has none to leave, and goes into a case as a quarantined record is
    attached to one.
    """
    reach = _dead_letter_reach(conn, user, dead_letter_id)
    if not (reach.how == "operator" and body.case_id is None):
        # Every other replay needs the verb the route has always required,
        # refused and audited exactly as the dependency refused it.
        require_global("ingest.replay")(user=user, conn=conn)
    if reach.how is None:
        raise Problem(404, "Not found", "no such dead letter")
    labels = {"classification": reach.classification,
              "compartments": reach.compartments}
    if body.case_id is not None:
        # Refuses a read-only case too: `ingest.replay` is a content verb.
        # Before the move check, so whether this batch fed a case is told
        # only to a caller that case's gate has let through.
        authorize_object(conn, user, case_id=body.case_id,
                         permission_key="ingest.replay", **labels)
        if reach.how == "case" and body.case_id not in reach.fed:
            raise Problem(
                409, "Conflict",
                "this dead letter's feed went to another case. Replay puts "
                "it back into its own case or into quarantine, never into "
                "a different one.")
    elif reach.how == "case":
        # False sorts first: a case the caller reads without the grant.
        via = min(reach.seen,
                  key=lambda case: counted_at_case_gate(conn, user, case))
        authorize_object(conn, user, case_id=via,
                         permission_key="ingest.read", **labels)
    try:
        record_id = IngestService(conn).replay(
            dead_letter_id, actor_id=user.user_id, repaired=body.repaired,
            case_id=body.case_id)
    except RepairInvalid as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    except IngestError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return {"dead_letter_id": str(dead_letter_id),
            "record_id": str(record_id),
            "notice": ("The original fragment is retained. A repair that "
                       "overwrote it would make the next format change "
                       "unattributable.")}


# ---------------------------------------------------------------------------
# The triage queue itself
# ---------------------------------------------------------------------------

#: Shared by `/records`, `/quarantine` and `/records/{id}`. One
#: projection, so the endpoints cannot drift into returning different
#: shapes for the same row -- and so a column added for one is never
#: accidentally exposed by another under a different permission.
#:
#: Named parameters since 2026-09-23, because the projection itself now
#: takes the caller's scope: `vis` (the cases the caller reads the queue
#: of), `qok` (whether unattached rows are theirs, the operator's), and
#: their ceiling (`clearance`, `comps`). Those bound three things a row
#: used to say about records the caller could not see:
#:
#: - `duplicate_feeds`, `duplicate_visible`, `duplicate_sources`: which
#:   FEEDS sent the folded copies, over the copies the caller may read.
#:   "ALSO SENT BY 1 other" read as a second feed corroborating a leak
#:   post when the same partner had resent it through a mirror
#:   (ux12-feeds:also-sent-by-false-corroboration). `duplicate_count`
#:   stays the total, as before. `duplicate_sources` counts the readable
#:   copies PER FEED and marks the row's own feed, because the fix round
#:   (2026-09-23) found the console calling copies "all from this feed:
#:   a resend, not a second source" when only the readable ones were: a
#:   copy the caller cannot see may be the second source, and near-
#:   duplicate matching runs across the whole deployment, so such copies
#:   are the ordinary case. Resends and other feeds are counted apart,
#:   and whatever is left of the total is said to be unseen.
#: - `duplicate_of*`: what a folded row is a duplicate OF, when the caller
#:   may read that record, so the console can put it under its primary.
#: - `triage_*` and `category_was`: the latest triage decision and the
#:   classifier's original category, read back from the audit chain
#:   (IngestService, "the queue's verbs").
#:
#: **One page, then the projection (fix round, 2026-09-23).** The first
#: version joined the per-row lookups (the folded copies, the primary,
#: the triage and correction events) to EVERY record in scope before the
#: sort and the LIMIT, and `ingest.record` has no index on
#: `duplicate_of`, so the copies of each record were a scan of the whole
#: table: quadratic, and a queue read over a case of 50,000 records had
#: not answered after 212 seconds. Now the page is chosen first (`page`,
#: the filters, the order and the limit, over `ingest.record` alone), the
#: copies of the whole page are counted in ONE pass (`dup`), and the
#: lookups run for the page's rows only: the same read takes tens of
#: milliseconds. The total count comes from the same pass, where it used
#: to be one scan per returned row. An index on `duplicate_of` would make
#: that pass a lookup; it needs a migration, and the chain is closed for
#: this release.
def _queue_sql(where: str, tail: str = "") -> str:
    """The queue projection over the records `where` selects.

    `where` is appended to `r.purged_at IS NULL` and `tail` is the page's
    ORDER BY and LIMIT; both are fixed strings from this module with named
    parameters, never caller text.
    """
    return f"""
        WITH page AS MATERIALIZED (
             SELECT r.id FROM ingest.record r
              WHERE r.purged_at IS NULL{where}
              {tail}),
        dup AS MATERIALIZED (
             SELECT d.duplicate_of AS primary_id, dk.name,
                    count(*) AS total,
                    count(*) FILTER (
                        WHERE d.purged_at IS NULL
                          AND d.classification <= %(clearance)s::core.tlp
                          AND d.compartments <@ %(comps)s
                          AND (d.case_id = ANY(%(vis)s::uuid[])
                               OR (%(qok)s AND d.case_id IS NULL))) AS seen
               FROM ingest.record d
               JOIN ingest.batch db ON db.id = d.batch_id
               JOIN ingest.api_key dk ON dk.id = db.api_key_id
              WHERE d.duplicate_of IN (SELECT id FROM page)
              GROUP BY d.duplicate_of, dk.name)
        SELECT r.id, r.case_id, r.category, r.category_confidence,
               r.category_source, r.priority, r.priority_detail,
               r.created_at, r.duplicate_of, r.classification,
               r.compartments, r.retain_until, b.received_at,
               k.name, k.key_id,
               (SELECT count(*) FROM ingest.victim_credential vc
                 WHERE vc.record_id = r.id),
               coalesce(dupx.total, 0)::bigint,
               dupx.feeds, dupx.seen::bigint,
               prim.received_at, prim.feed, prim.visible,
               tri.detail, tri.occurred_at, tri.actor,
               cor.detail, dupx.sources
          FROM page
          JOIN ingest.record r ON r.id = page.id
          JOIN ingest.batch b ON b.id = r.batch_id
          JOIN ingest.api_key k ON k.id = b.api_key_id
          LEFT JOIN LATERAL (
                SELECT sum(x.total) AS total,
                       array_agg(x.name ORDER BY x.name)
                           FILTER (WHERE x.seen > 0) AS feeds,
                       coalesce(sum(x.seen), 0) AS seen,
                       coalesce(jsonb_agg(jsonb_build_object(
                                    'feed', x.name, 'copies', x.seen,
                                    'this_feed', x.name = k.name)
                                ORDER BY x.name = k.name DESC, x.name)
                                    FILTER (WHERE x.seen > 0),
                                '[]'::jsonb) AS sources
                  FROM dup x WHERE x.primary_id = r.id) dupx ON true
          LEFT JOIN LATERAL (
                SELECT pb.received_at, pk.name AS feed, true AS visible
                  FROM ingest.record p
                  JOIN ingest.batch pb ON pb.id = p.batch_id
                  JOIN ingest.api_key pk ON pk.id = pb.api_key_id
                 WHERE p.id = r.duplicate_of AND p.purged_at IS NULL
                   AND p.classification <= %(clearance)s::core.tlp
                   AND p.compartments <@ %(comps)s
                   AND (p.case_id = ANY(%(vis)s::uuid[])
                        OR (%(qok)s AND p.case_id IS NULL))) prim ON true
          LEFT JOIN LATERAL (
                SELECT e.detail, e.occurred_at, u.display_name AS actor
                  FROM audit.event e
                  LEFT JOIN iam.app_user u ON u.id = e.actor_id
                 WHERE e.object_id = r.id
                   AND e.action = 'INGEST_RECORD_TRIAGED'
                 ORDER BY e.seq DESC LIMIT 1) tri ON true
          LEFT JOIN LATERAL (
                SELECT e.detail FROM audit.event e
                 WHERE e.object_id = r.id
                   AND e.action = 'INGEST_CATEGORY_CORRECTED'
                 ORDER BY e.seq ASC LIMIT 1) cor ON true
         ORDER BY r.priority DESC, r.created_at DESC"""


#: The queue's order, and the page's.
_PAGE_TAIL = "ORDER BY r.priority DESC, r.created_at DESC LIMIT %(limit)s"

#: The latest triage state of `r`, for the page's filter: the same lookup
#: the projection's `tri` makes, asked only when a triage filter is on.
_TRIAGE_STATE = """coalesce((SELECT e.detail ->> 'state' FROM audit.event e
                         WHERE e.object_id = r.id
                           AND e.action = 'INGEST_RECORD_TRIAGED'
                         ORDER BY e.seq DESC LIMIT 1), 'NEW')"""


def _visible_detail(detail: dict | None, record_case: UUID | None,
                    allowed: set[str]) -> dict | None:
    """The score's reasons, with every watch the caller may not read taken
    out.

    A record in a case is scored against that case's watches and the
    case-less ones, which its readers may see. A record in QUARANTINE is
    scored against every watch, because routing it is the operator's job,
    and a watch on a case the operator is not on is that case's content:
    its name and the selector it watches are withheld and the term says
    only that such a watch exists. The score itself already said as much.

    A record never scored keeps the null it always had: `{}` in its place
    was an API shape change nobody had asked for (fix round, 2026-09-23).
    """
    if detail is None:
        return None
    detail = dict(detail)
    terms = []
    for term in detail.get("terms") or []:
        if term.get("term") != "selector":
            terms.append(term)
            continue
        watches = [w for w in term.get("watches") or []
                   if w.get("case_id") is None
                   or (record_case is not None
                       and w.get("case_id") == str(record_case))
                   or w.get("case_id") in allowed]
        if watches:
            terms.append({**term, "watches": watches})
        else:
            terms.append({"term": "selector", "points": term.get("points"),
                          "hidden": True, "watches": []})
    if "terms" in detail:
        detail["terms"] = terms
    return detail


def _queue_row(r, allowed: set[str] | None = None) -> dict:
    triage = r[22] or {}
    corrected = r[25] or None
    return {
        "id": str(r[0]),
        "case_id": str(r[1]) if r[1] else None,
        "quarantined": r[1] is None,
        "category": r[2],
        "category_confidence": float(r[3]),
        "category_source": r[4],
        "priority": float(r[5]),
        "priority_detail": _visible_detail(r[6], r[1], allowed or set()),
        "created_at": r[7].isoformat(),
        "is_duplicate": r[8] is not None,
        "classification": r[9],
        "compartments": list(r[10] or []),
        "retain_until": r[11].isoformat() if r[11] else None,
        "received_at": r[12].isoformat() if r[12] else None,
        "feed": r[13], "key_id": r[14],
        "credential_count": r[15],
        "duplicate_count": r[16],
        # Which feeds sent the folded copies the caller may read, and how
        # many of the copies that is. A copy from the row's own feed is a
        # resend, not a second source.
        "duplicate_feeds": list(r[17] or []),
        "duplicate_visible": int(r[18] or 0),
        # The same copies per feed, {feed, copies, this_feed}: resends
        # from the row's own feed apart from copies another feed sent.
        "duplicate_sources": [
            {"feed": s.get("feed"), "copies": int(s.get("copies") or 0),
             "this_feed": bool(s.get("this_feed"))}
            for s in (r[26] or [])],
        # What a folded row folds INTO. Null when the caller may not read
        # the primary: an id from another case or compartment is itself a
        # disclosure.
        "duplicate_of": (str(r[8]) if r[8] is not None and r[21] else None),
        "duplicate_of_received_at": r[19].isoformat() if r[19] else None,
        "duplicate_of_feed": r[20],
        "triage_state": triage.get("state") or "NEW",
        "triage_reason": triage.get("reason"),
        "triage_linked_to": triage.get("linked_to"),
        "triage_at": r[23].isoformat() if r[23] else None,
        "triage_by": r[24],
        # The classifier's own output, when an analyst has corrected it.
        "category_was": corrected.get("from") if corrected else None,
    }


def _queue_params(allowed, quarantine_ok: bool, clearance, compartments,
                  **extra) -> dict:
    return {"vis": [UUID(str(c)) for c in allowed], "qok": quarantine_ok,
            "clearance": clearance.name, "comps": list(compartments),
            **extra}


def _facets(conn: psycopg.Connection, scope: list, clearance,
            compartments) -> dict:
    """Counts over the WHOLE of a case queue, whatever filter is on.

    ux12-feeds:category-filter-collapses-and-sticks (2026-09-23). The
    Category select was rebuilt from the page it had just filtered, so
    choosing STEALER_LOG left STEALER_LOG as the only choice; and a filter
    carried into another case answered "Nothing in the queue for this
    case." for a queue holding other categories. The select is built from
    these counts instead, which the filter does not narrow.

    `watched_untriaged` is the Feeds rail badge: records that match a
    watched selector and nobody has triaged yet (ux12-feeds:feeds-badge-
    never-set). Folded duplicates are not counted: the badge is a count
    of things to look at, and a copy of one is not a second one.

    Two statements, not one, since the fix round (2026-09-23): the badge
    is read on every case open, and asking the audit chain for the triage
    state of EVERY record in the case to count the few that matched a
    watch made a large stealer-log case pay per record on each open. The
    category counts touch no audit row; the triage state is looked up only
    for the records that matched a watched selector.
    """
    bound = (scope, clearance.name, list(compartments))
    rows = conn.execute(
        """SELECT r.category, count(*)
             FROM ingest.record r
            WHERE r.purged_at IS NULL AND r.duplicate_of IS NULL
              AND r.case_id = ANY(%s)
              AND r.classification <= %s::core.tlp
              AND r.compartments <@ %s
            GROUP BY r.category ORDER BY r.category""", bound).fetchall()
    watched = conn.execute(
        """WITH hit AS MATERIALIZED (
               SELECT r.id FROM ingest.record r
                WHERE r.purged_at IS NULL AND r.duplicate_of IS NULL
                  AND r.case_id = ANY(%s)
                  AND r.classification <= %s::core.tlp
                  AND r.compartments <@ %s
                  AND coalesce((r.priority_detail
                                ->> 'watched_selector_hits')::int, 0) > 0)
           SELECT count(*) FROM hit
            WHERE coalesce((SELECT e.detail ->> 'state' FROM audit.event e
                             WHERE e.object_id = hit.id
                               AND e.action = 'INGEST_RECORD_TRIAGED'
                             ORDER BY e.seq DESC LIMIT 1), 'NEW') = 'NEW'""",
        bound).fetchone()[0]
    return {"categories": {row[0]: row[1] for row in rows},
            "total": sum(row[1] for row in rows),
            "watched_untriaged": int(watched),
            # Every category the database accepts, for the row's Correct
            # category control: the list the CHECK enforces, not a copy.
            "known": list(CATEGORIES)}


@router.get("/records", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def records(
    case_id: UUID | None = Query(None),
    category: str | None = Query(None),
    include_duplicates: bool = Query(False),
    triage_state: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(require_global("ingest.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The queue, highest priority first.

    docs/12: "A record containing a selector on somebody's watchlist should
    surface in seconds, and a generic combo list should sink silently to the
    bottom. Volume is the enemy, and a queue nobody can prioritise is a
    queue nobody reads."

    Near-duplicates are hidden by default and counted rather than dropped:
    "the same leak post from nine sources" is the failure this exists to
    prevent, and silently discarding the other eight is a different failure
    (invariant 12). `duplicate_count` says how many were folded away, and
    `duplicate_feeds` which feeds sent the ones the caller may read.

    **The payload is not returned.** A record can hold a whole stealer log;
    this is a queue, and the fields here are the ones an analyst triages on.

    Records attached to no case are NOT here — see `/quarantine`. They are
    a different job with a different verb, and a hidden branch inside one
    endpoint that widens what it returns based on a second permission is
    exactly the shape that becomes a hole.

    `triage_state` filters on the latest triage decision (NEW is "none
    yet"); `facets` counts the whole scope by category whatever the
    filters say, and carries the watched-and-untriaged count the rail
    badge shows.
    """
    if triage_state is not None:
        triage_state = triage_state.strip().upper()
        if triage_state not in TRIAGE_STATES:
            raise Problem(400, "Invalid request",
                          "triage_state must be one of "
                          + ", ".join(TRIAGE_STATES))
    clearance, compartments = user_ceiling(conn, user.user_id)
    allowed = _authorised_cases_for_ingest(conn, user)
    if case_id is not None and case_id not in allowed:
        raise Problem(404, "Not found", "no such case")
    scope = [case_id] if case_id is not None else allowed

    rows = conn.execute(
        _queue_sql(
            """
              AND r.case_id = ANY(%(scope)s)
              AND r.classification <= %(clearance)s::core.tlp
              AND r.compartments <@ %(comps)s"""
            + ("" if category is None else " AND r.category = %(category)s")
            + ("" if include_duplicates else " AND r.duplicate_of IS NULL")
            + ("" if triage_state is None
               else f" AND {_TRIAGE_STATE} = %(triage)s"),
            _PAGE_TAIL),
        _queue_params(allowed, False, clearance, compartments,
                      scope=scope, category=category,
                      dupes=include_duplicates, triage=triage_state,
                      limit=limit)).fetchall()
    seen = {str(c) for c in allowed}
    return {"records": [_queue_row(r, seen) for r in rows], "count": len(rows),
            "facets": _facets(conn, scope, clearance, compartments),
            "notice": (
                "Near-duplicates are folded, not dropped, and duplicate_count "
                "says how many. Payloads are not returned here: a record can "
                "hold a whole stealer log, and this is a queue.")}


@router.get("/quarantine", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def quarantine(
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(require_global("ingest.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Records that belong to no case yet.

    Its own endpoint and its own verb. A record with no case cannot be
    granted by a case assignment, so the ordinary five-part gate hides it
    from everybody — and if nobody can see it, nothing is ever attached and
    the material sits there until its retention clock destroys it.
    `POST /records/{id}/attach` is how the operator attaches one
    (2026-09-23).

    `ingest.manage` is the operator verb: it already covers issuing keys
    and parsing batches, which is the same job. It is deliberately NOT
    `ingest.read` — SYS_ADMIN holding that would mean the operator reads
    every case's records, which is the over-broad grant this system exists
    to avoid.

    The classification predicate still applies. Unattached is not
    unclassified: the record carries the issuing key's ceiling.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    allowed = _authorised_cases_for_ingest(conn, user)
    rows = conn.execute(
        _queue_sql("""
              AND r.case_id IS NULL
              AND r.classification <= %(clearance)s::core.tlp
              AND r.compartments <@ %(comps)s""", _PAGE_TAIL),
        _queue_params(allowed, True, clearance, compartments,
                      limit=limit)).fetchall()
    seen = {str(c) for c in allowed}
    return {"records": [_queue_row(r, seen) for r in rows], "count": len(rows),
            "notice": ("Unattached material. Attaching it to a case is what "
                       "puts it under that case's authority and review "
                       "clock; until then it expires on the category's.")}


@router.get("/records/{record_id}", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def record_detail(
    record_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One queue record's METADATA: never its payload.

    ux12-feeds:queue-is-a-dead-end (2026-09-23): a row could not be opened.
    This is what Open shows: the score's reasons, the feed and key, the
    batch it arrived in and that batch's digest (the custody of the raw
    object), the SHAPE of the payload (its keys and each value's type and
    length, through the same `redact_structure` the dead letters use,
    never a value), the folded copies the caller may read, and the
    record's own history (triage, attachment, category corrections)
    from the audit chain.

    Gated like `rescore`, by what the record is: `ingest.read` on its case
    with its labels, or the operator verb for a quarantined one, and a 404
    either way for a record the caller may not read.
    """
    _authorise_record(conn, user, record_id, "ingest.read")
    clearance, compartments = user_ceiling(conn, user.user_id)
    allowed = _authorised_cases_for_ingest(conn, user)
    # Quarantined copies and primaries are the operator's, fresh: a case
    # reader opening a case record does not see quarantine through it.
    manages, fresh = _holds_global(conn, user, "ingest.manage")
    qok = manages and fresh
    row = conn.execute(
        _queue_sql(" AND r.id = %(rid)s"),
        _queue_params(allowed, qok, clearance, compartments,
                      rid=record_id)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such record")
    seen = {str(c) for c in allowed}
    out = _queue_row(row, seen)
    batch = conn.execute(
        """SELECT b.id, b.received_at, b.raw_bytes, b.raw_sha256,
                  b.detected_format, b.content_type, b.parsed_at,
                  b.parser_version, b.state, k.environment,
                  k.declared_category, r.payload
             FROM ingest.record r
             JOIN ingest.batch b ON b.id = r.batch_id
             JOIN ingest.api_key k ON k.id = b.api_key_id
            WHERE r.id = %s""", (record_id,)).fetchone()
    out["batch"] = {
        "id": str(batch[0]),
        "received_at": batch[1].isoformat() if batch[1] else None,
        "raw_bytes": batch[2],
        "raw_sha256": bytes(batch[3]).hex() if batch[3] else None,
        "detected_format": batch[4], "content_type": batch[5],
        "parsed_at": batch[6].isoformat() if batch[6] else None,
        "parser_version": batch[7], "state": batch[8],
        "key_environment": batch[9], "key_declared_category": batch[10],
    }
    out["payload_shape"] = redact_structure(batch[11])
    copies = conn.execute(
        """SELECT d.id, b.received_at, k.name
             FROM ingest.record d
             JOIN ingest.batch b ON b.id = d.batch_id
             JOIN ingest.api_key k ON k.id = b.api_key_id
            WHERE d.duplicate_of = %s AND d.purged_at IS NULL
              AND d.classification <= %s::core.tlp
              AND d.compartments <@ %s
              AND (d.case_id = ANY(%s::uuid[]) OR (%s AND d.case_id IS NULL))
            ORDER BY b.received_at""",
        (record_id, clearance.name, list(compartments),
         [UUID(str(c)) for c in allowed], qok)).fetchall()
    out["copies"] = [{"id": str(c[0]),
                      "received_at": c[1].isoformat() if c[1] else None,
                      "feed": c[2]} for c in copies]
    history = conn.execute(
        """SELECT e.action, e.occurred_at, u.display_name, e.detail
             FROM audit.event e
             LEFT JOIN iam.app_user u ON u.id = e.actor_id
            WHERE e.object_id = %s
              AND e.action IN ('INGEST_RECORD_TRIAGED',
                               'INGEST_RECORD_ATTACHED',
                               'INGEST_CATEGORY_CORRECTED')
            ORDER BY e.seq""", (record_id,)).fetchall()
    out["history"] = [{"action": h[0], "at": h[1].isoformat(), "by": h[2],
                       "detail": h[3]} for h in history]
    out["notice"] = ("Metadata only. The payload is never shown here: its "
                     "shape is, with every value replaced by its type and "
                     "length.")
    return out


class TriageRecordBody(BaseModel):
    state: str
    reason: str | None = None
    linked_to: str | None = None


@router.post("/records/{record_id}/triage", response_model=dict)
def triage_record(
    record_id: UUID, body: TriageRecordBody,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Mark a queue record Triaged, Linked (to what) or Discarded (why),
    or put it back to New. Audited, and the latest decision is the
    record's state.

    The reader's verb, like triage of a collected document: the analyst
    working the queue is the one who decides a hit is noise, so a case
    record needs `ingest.read` on its case with its labels, and a
    quarantined one the operator verb. 404 for a record the caller may
    not read.
    """
    case_id = _authorise_record(conn, user, record_id, "ingest.read")
    if case_id is not None:
        # After the access decision, never before (deps.py): a caller the
        # record gate refused has had its 404 and learns nothing here.
        refuse_if_case_read_only(conn, user, case_id, "ingest.read")
    try:
        return IngestService(conn).triage_record(
            record_id, actor_id=user.user_id, state=body.state,
            reason=body.reason, linked_to=body.linked_to)
    except IngestError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


class AttachRecordBody(BaseModel):
    case_id: UUID
    reason: str


@router.post("/records/{record_id}/attach", response_model=dict)
def attach_record(
    record_id: UUID, body: AttachRecordBody,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Attach a quarantined record to a case.

    Two gates, one per side. The RECORD needs the operator verb, fresh (it
    is in quarantine, so nothing else reaches it). The TARGET case needs
    `ingest.replay` on it with the record's labels: the verb that already
    puts a repaired dead letter into a case, which is the same act, and
    one the case's own team holds. Not `ingest.manage` on the case, which
    is what parsing a batch into a case asks for: that permission lives
    only in the SYS_ADMIN role, and a case assignment carries a case role,
    so no real assignment ever grants it and the verb could never be used.
    The upshot is the right one: material goes into a case on the word of
    somebody who works that case. A record already in a case is refused;
    a read-only case (CLOSED, ARCHIVED or PURGED) is refused by the gate.
    """
    current = _authorise_record(conn, user, record_id, "ingest.read")
    if current is not None:
        raise Problem(409, "Conflict",
                      "this record is already attached to a case. Attach "
                      "moves material out of quarantine, never between "
                      "cases.")
    _cid, classification, compartments = _own_record(conn, record_id)
    # Refuses a read-only case too: `ingest.replay` is a content verb.
    authorize_object(conn, user, case_id=body.case_id,
                     permission_key="ingest.replay",
                     classification=classification,
                     compartments=compartments)
    try:
        return IngestService(conn).attach_record(
            record_id, case_id=body.case_id, actor_id=user.user_id,
            reason=body.reason)
    except IngestError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


class CategoryBody(BaseModel):
    category: str
    reason: str


@router.post("/records/{record_id}/category", response_model=dict)
def correct_category(
    record_id: UUID, body: CategoryBody,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Correct the classifier's category (ux12-feeds:confidence-label-
    ambiguous, 2026-09-23). docs/12: "Keep the confidence and let analysts
    correct it; corrections are training data."

    `ingest.replay` on the record's case, the repair verb: a category
    decides the record's retention, its handling rules and its score, so
    changing it is a repair of what the machine made, which REVIEWER, who
    reads the queue, does not do. A quarantined record needs the operator
    verb. The classifier's output is kept in the audit event and returned
    on the row as `category_was`.
    """
    # Read first, 404 for a record the caller may not see; then the repair
    # verb, which refuses 403 like any other missing verb on a case the
    # caller is on, because they already know the record is there.
    case_id = _authorise_record(conn, user, record_id, "ingest.read")
    if case_id is not None:
        _cid, classification, compartments = _own_record(conn, record_id)
        # Refuses a read-only case too: `ingest.replay` is a content verb.
        # Not counted: the read gate above resolved these same labels and
        # counted this request if a grant was what let it through, and a
        # correction read as two uses on the officer's card (r2 u1,
        # 2026-09-24). The verb, the lifecycle and the refusal are asked
        # all the same.
        authorize_object(conn, user, case_id=case_id,
                         permission_key="ingest.replay", count_use=False,
                         classification=classification,
                         compartments=compartments)
    try:
        return IngestService(conn).correct_category(
            record_id, actor_id=user.user_id, category=body.category,
            reason=body.reason)
    except IngestError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc


@router.post("/records/{record_id}/score", response_model=dict)
def rescore(
    record_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Recompute one record's triage score.

    Worth having by hand because the score depends on `collect.watch`
    selectors, which change: a record ingested before a selector was added
    scored zero against it and will keep scoring zero until something asks.

    **No `require_global` on the route, deliberately.** Which verb applies
    depends on what the record IS: a record in a case needs `ingest.read`
    plus that case's five-part gate; a quarantined record belongs to no
    case and needs the operator verb `ingest.manage`, because no case
    assignment can reach it. `_authorise_record` picks, and refuses with a
    404 either way.

    Gating the route on `ingest.read` — which is what it did — made the
    operator unable to sort the one queue nobody else works, while leaving
    the quarantine branch checking nothing at all. Both halves were wrong
    in the same line.

    Answers the score before and after and the reasons (ux12-feeds:
    rescore-silent, 2026-09-23): the button reloaded the list and said
    nothing, so an unchanged score looked like a click that did not work.
    """
    record_case = _authorise_record(conn, user, record_id, "ingest.read")
    before = conn.execute(
        "SELECT priority FROM ingest.record WHERE id = %s",
        (record_id,)).fetchone()
    try:
        IngestService(conn).score_records([record_id], actor_id=user.user_id)
    except IngestError as exc:
        raise Problem(404, "Not found", safe_detail(exc)) from exc
    after = conn.execute(
        "SELECT priority, priority_detail FROM ingest.record WHERE id = %s",
        (record_id,)).fetchone()
    if before is None or after is None:
        raise Problem(404, "Not found", "no such record")
    allowed = {str(c) for c in _authorised_cases_for_ingest(conn, user)}
    return {"record_id": str(record_id), "priority": float(after[0]),
            "priority_before": float(before[0]),
            "priority_detail": _visible_detail(after[1], record_case, allowed)}


class RescoreAllBody(BaseModel):
    case_id: UUID


@router.post("/records/rescore", response_model=dict,
             dependencies=[Depends(rate_limit("capture"))])
def rescore_case(
    body: RescoreAllBody,
    user: CurrentUser = Depends(require_global("ingest.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Rescore every record in one case's queue the caller may read.

    The reason to rescore is that a watch changed, and a watch changes for
    a whole case at once; pressing Rescore on each row is how the records
    below the first screen never get asked (ux12-feeds:rescore-silent).
    Metered under `capture`: one call, many writes. The case gate and the
    caller's labels bound it exactly as `/records` bounds the listing.

    **One break-glass use when a grant let it in (r2 c6, 2026-09-24).**
    The membership test is a question and counts nothing, which is right
    for the listing it was written for and wrong for a request that then
    writes every record's priority: on a case reached only through a
    grant, a whole-case rescore left the officer's card reading unused.
    So the request is gated once more at the case's own labels, counted.
    The record filter stays at the caller's own ceiling, not the grant's,
    as `/records` filters it: raising it would reach records above the
    caller's clearance on a case within it, which this gate would not
    count.
    """
    allowed = _authorised_cases_for_ingest(conn, user)
    if body.case_id not in allowed:
        raise Problem(404, "Not found", "no such case")
    authorize_object(conn, user, case_id=body.case_id,
                     permission_key="ingest.read")
    clearance, compartments = user_ceiling(conn, user.user_id)
    ids = [row[0] for row in conn.execute(
        """SELECT id FROM ingest.record
            WHERE case_id = %s AND purged_at IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s""",
        (body.case_id, clearance.name, list(compartments))).fetchall()]
    result = IngestService(conn).score_records(ids, actor_id=user.user_id)
    return {"case_id": str(body.case_id), **result}


@router.get("/keys", response_model=dict)
def keys(
    include_revoked: bool = Query(False),
    user: CurrentUser = Depends(require_global("ingest.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Issued keys. **Never the secret** — it exists once, at issue.

    `last_used_at` is the column that matters: docs/12 says a key unused
    for thirty days is either a dead integration or somebody else's.
    """
    rows = conn.execute(
        """SELECT k.id, k.key_id, k.name, k.environment, k.declared_category,
                  k.classification_ceiling, k.forced_compartment,
                  k.created_at, k.expires_at, k.last_used_at, k.revoked_at,
                  k.revoked_reason,
                  (SELECT count(*) FROM ingest.batch b WHERE b.api_key_id = k.id)
             FROM ingest.api_key k
            WHERE (%s OR k.revoked_at IS NULL)
            ORDER BY k.revoked_at NULLS FIRST, k.last_used_at NULLS FIRST""",
        (include_revoked,)).fetchall()
    now = datetime.now(timezone.utc)
    return {"keys": [{
        "id": str(r[0]), "key_id": r[1], "name": r[2], "environment": r[3],
        "declared_category": r[4], "classification_ceiling": r[5],
        "forced_compartment": r[6],
        "created_at": r[7].isoformat(),
        "expires_at": r[8].isoformat(),
        "expired": r[8] <= now,
        "last_used_at": r[9].isoformat() if r[9] else None,
        "stale_days": (now - r[9]).days if r[9] else None,
        "revoked_at": r[10].isoformat() if r[10] else None,
        "revoked_reason": r[11],
        "batch_count": r[12],
    } for r in rows], "count": len(rows),
        # What the Issue form may offer (ux12-feeds:keys-tab-read-only,
        # 2026-09-23): the categories the database accepts, which of them
        # need a compartment, and the compartments THIS caller holds. A key
        # forced into a compartment its issuer cannot read files every
        # record it brings where nobody on the operator side can see it.
        "form": {
            "categories": list(CATEGORIES),
            "needs_compartment": sorted(HIGH_RISK_CATEGORIES),
            "compartments": sorted(user_ceiling(conn, user.user_id)[1]),
            "max_ttl_days": 365,
        }}


# ---------------------------------------------------------------------------
# Victim credentials. Masked by default; the reveal is a two-person act.
# ---------------------------------------------------------------------------

@router.get("/records/{record_id}/credentials", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def credentials(
    record_id: UUID,
    user: CurrentUser = Depends(require_global("ingest.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Credentials attached to a record, MASKED.

    This is the default and the only view most work needs: whether a
    credential exists, for what service, and how strong it is, without
    the value. docs/12 wants the unmasked value to be an event, not a
    page load.
    """
    case_id = _authorise_record(conn, user, record_id, "ingest.read")
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        rows = IngestService(conn, clearance=clearance.name,
                             compartments=compartments).credentials_masked(
            record_id, case_id=case_id)
    except IngestError as exc:
        raise Problem(404, "Not found", "no such record in this case") from exc
    return {"record_id": str(record_id),
            "case_id": str(case_id) if case_id else None,
            "credentials": rows, "count": len(rows), "notice": L2_NOTICE}


class AuthoriseBody(BaseModel):
    case_id: UUID
    granted_to: UUID
    #: What this authorisation covers. Not decoration: an authorisation
    #: whose scope nobody wrote down is one nobody can say was exceeded.
    scope_note: str = Field(min_length=20)
    #: The basis in law or policy. docs/16 L2 is why this is mandatory.
    legal_basis: str = Field(min_length=10)
    duration_days: int = Field(default=7, ge=1, le=30)


@router.post("/pii-authorisations", response_model=dict, status_code=201)
def grant_pii_authorisation(
    body: AuthoriseBody,
    user: CurrentUser = Depends(require_global("victim_pii.authorise")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Authorise somebody ELSE to reveal victim credentials.

    Two people, on purpose. `victim_pii.authorise` is held by
    SECURITY_OFFICER and not by case roles, so the person who wants the
    value and the person who permits it are structurally different people
    -- the same reasoning as four-eyes approval and break-glass review.
    """
    authorize_object(conn, user, case_id=body.case_id,
                     permission_key="victim_pii.authorise")
    if body.granted_to == user.user_id:
        raise Problem(
            400, "Invalid request",
            "you cannot authorise your own reveal: the authorisation is "
            "the control, and authorising yourself removes it")
    try:
        auth_id = IngestService(conn).grant_pii_authorisation(
            case_id=body.case_id, granted_to=body.granted_to,
            granted_by=user.user_id, scope_note=body.scope_note,
            legal_basis=body.legal_basis,
            duration=timedelta(days=body.duration_days))
    except IngestError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"id": str(auth_id), "granted_to": str(body.granted_to),
            "expires_in_days": body.duration_days,
            "notice": L2_NOTICE}


class RevealBody(BaseModel):
    case_id: UUID
    reason: str = Field(min_length=10)


@router.post("/credentials/{credential_id}/reveal", response_model=dict,
             dependencies=[Depends(rate_limit("evidence.export"))])
def reveal_credential(
    credential_id: UUID, body: RevealBody,
    user: CurrentUser = Depends(require_global("victim_pii.reveal")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Reveal ONE credential, under a live authorisation.

    Step-up gated and audited per credential. A 451 here is not a
    technical failure: it means no live authorisation covers this reveal,
    which is the control working.
    """
    authorize_object(conn, user, case_id=body.case_id,
                     permission_key="victim_pii.reveal")
    # The credential must belong to the case whose authorisation is being
    # relied on, and that check now lives in the SERVICE (docs/17 F15(a))
    # rather than here, so a worker or a script calling it directly gets it
    # too. `CaseMismatch` and "no such credential" both surface as 404: a
    # status code must not tell you that a credential you may not read
    # exists somewhere else.
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        value = IngestService(
            conn, clearance=clearance.name, compartments=compartments
        ).reveal_credential(
            credential_id, actor_id=user.user_id, case_id=body.case_id,
            reason=body.reason)
    except AuthorisationRequired as exc:
        raise Problem(451, "Unavailable for legal reasons", safe_detail(exc)) from exc
    except CaseMismatch as exc:
        raise Problem(404, "Not found",
                      "no such credential in this case") from exc
    except IngestError as exc:
        if "no such credential" in str(exc):
            raise Problem(404, "Not found", safe_detail(exc)) from exc
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return {"credential_id": str(credential_id), "value": value,
            "notice": ("This reveal is audited against you and the "
                       "authorisation that permitted it. " + L2_NOTICE)}


class FingerprintSearchBody(BaseModel):
    """CR12: the value travels in a BODY, not a query string.

    It used to be `value: str = Query(...)`, which puts a victim's email
    address or password in the GET request line — and therefore in every
    uvicorn and nginx access log, in plaintext, outside the compartment
    gate, outside the PII-authorisation gate, and under whatever retention
    the log shipper happens to have. These values are stored as ciphertext
    in the database precisely so that plaintext is not loggable; a query
    parameter undid that for the one endpoint whose whole input is the
    plaintext.

    The sibling reveal endpoint already used a POST body for the same
    reason. This is now consistent with it.
    """

    value: str = Field(..., min_length=3)
    case_id: UUID


@router.post("/search", response_model=dict,
             dependencies=[Depends(rate_limit("search"))])
def search_by_fingerprint(
    body: FingerprintSearchBody,
    user: CurrentUser = Depends(require_global("ingest.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Look up a record by an EXACT selector, never by free text.

    decision 52: free-text PII search across stealer logs is impossible
    here, not merely forbidden. There is no tsvector, no trigram index and
    the values are ciphertext, so there is nothing to run a LIKE against.
    This endpoint matches a fingerprint of an exact value -- you can ask
    "is this address in the corpus", and you cannot ask "show me every
    address at this company".
    """
    authorize_object(conn, user, case_id=body.case_id,
                     permission_key="ingest.read")
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        # The ceiling is carried INTO the query now (docs/17 F15(b)). It
        # used to answer for the whole corpus and be filtered here, which
        # is not the same thing: the hit count, the timing and the audit
        # event were all computed over records the caller may not read, so
        # the disclosure had already happened by the time the filter ran.
        rows = IngestService(
            conn, clearance=clearance.name, compartments=compartments
        ).search_by_fingerprint(body.value, actor_id=user.user_id,
                                 case_id=body.case_id)
        # Clearance is not assignment: a RED analyst may read the LABEL of
        # a case they are not on. The case predicate stays here because
        # assignment is the router's knowledge, not the service's.
        allowed = {str(c) for c in _authorised_cases_for_ingest(conn, user)}
        rows = [r for r in rows
                if r.get("case_id") is None or str(r["case_id"]) in allowed]
    except AuthorisationRequired as exc:
        raise Problem(451, "Unavailable for legal reasons", safe_detail(exc)) from exc
    except IngestError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"matches": rows, "count": len(rows),
            "note": ("Exact-match only, by construction (decision 52). "
                     "An empty result means this exact value is not in the "
                     "corpus, not that nothing similar is."),
            "notice": L2_NOTICE}
