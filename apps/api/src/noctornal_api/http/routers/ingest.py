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
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, Field

from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    current_user,
    get_conn,
    require_global,
    require_step_up,
    user_ceiling,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.ingest import (
    AuthorisationRequired,
    CaseMismatch,
    IngestError,
    IngestService,
)
from noctornal_api.rawstore import MissingObject, RawBatchStorage, RawStoreError
from noctornal_api.security.access import tlp_from_name
from noctornal_api.security.sessions import STEP_UP_FRESHNESS


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
            "raw ingest storage is not configured, and docs/12 requires the "
            "raw payload to be persisted before parsing. Set MINIO_ENDPOINT / "
            "MINIO_ACCESS_KEY / MINIO_SECRET_KEY and INGEST_BUCKET.") from exc
    return IngestService(conn, storage, **kw)

router = APIRouter(prefix="/ingest", tags=["ingest"])

L2_NOTICE = (
    "docs/16 L2 is BLOCKING and unresolved: the lawful basis for holding "
    "stealer-log data about thousands of uninvolved people, victim "
    "notification obligations, and the real retention period are external "
    "determinations. The 90-day default is a placeholder."
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


def _authorised_cases_for_ingest(conn: psycopg.Connection,
                                 user: CurrentUser) -> list[UUID]:
    """Cases where the full five-part gate would allow `ingest.read`."""
    rows = conn.execute(
        """SELECT c.id
             FROM iam.case_assignment ca
             JOIN core."case" c ON c.id = ca.case_id
             JOIN iam.app_user u ON u.id = ca.user_id
            WHERE ca.user_id = %s
              AND (ca.expires_at IS NULL OR ca.expires_at > now())
              AND u.is_active
              AND EXISTS (SELECT 1 FROM iam.role_permission rp
                           WHERE rp.role_key = ca.role_key
                             AND rp.permission_key = 'ingest.read')
              AND c.classification <= u.tlp_clearance
              AND c.compartments <@ u.compartments""",
        (user.user_id,)).fetchall()
    return [r[0] for r in rows]




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

    raw = await request.body()
    try:
        result = svc.accept(
            key, raw, content_type=request.headers.get("content-type"),
            idempotency_key=idempotency_key)
    except IngestError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {
        "batch_id": str(result.batch_id),
        "accepted": result.accepted,
        "duplicate": result.duplicate,
        "detail": result.detail,
        "notice": ("Accepted for later parsing. Nothing has been parsed, "
                   "categorised or written to a case yet. Unparseable "
                   "fragments go to the dead-letter queue with the raw "
                   "bytes rather than being dropped (invariant 12)."),
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
    #: will ever notice is still live.
    ttl_days: int = Field(default=90, ge=1, le=730)


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
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {
        "id": str(issued.id), "key_id": issued.key_id,
        "secret": issued.token,
        "expires_at": issued.expires_at.isoformat(),
        "notice": ("This secret is shown ONCE and is not stored in "
                   "recoverable form. The key is write-only: it can submit "
                   "batches and read nothing (invariant 11)."),
    }


class RevokeKeyBody(BaseModel):
    reason: str = Field(min_length=5)


@router.post("/keys/{key_row_id}/revoke", response_model=dict)
def revoke_key(
    key_row_id: UUID, body: RevokeKeyBody,
    user: CurrentUser = Depends(require_global("ingest.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    try:
        IngestService(conn).revoke_key(
            key_row_id, actor_id=user.user_id, reason=body.reason)
    except IngestError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
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
            "silent loss (invariant 12).") from exc
    except IngestError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    try:
        result = svc.parse_batch(
            batch_id, raw=raw, case_id=body.case_id,
            parser_version=body.parser_version)
    except IngestError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    return {
        "batch_id": str(batch_id), "records": result.records,
        "dead_letters": result.dead, "duplicates": result.duplicates,
        "warnings": result.warnings,
        "notice": ("Fragments that failed to parse are in the dead-letter "
                   "queue, structurally redacted — keys, types and lengths, "
                   "never values. The verbatim bytes stay in the batch's raw "
                   "object under its own retention. Silent drops are how you "
                   "find out six months later that a feed has been "
                   "half-failing (invariant 12)."),
    }


@router.get("/dead-letters", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def dead_letters(
    api_key_id: UUID | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    user: CurrentUser = Depends(require_global("ingest.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """What did not parse, and why.

    A rising dead-letter rate on one key is the signal that a provider
    changed their format -- and it is invisible unless somebody looks,
    which is what this endpoint is for.
    """
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
        """SELECT id, batch_id, error_class, error_detail, occurred_at,
                  replayed_at, resolution, raw_fragment, redacted,
                  classification, retain_until
             FROM ingest.dead_letter
            WHERE (%s::uuid IS NULL OR api_key_id = %s)
              AND purged_at IS NULL
              AND classification <= %s::core.tlp AND compartments <@ %s
            ORDER BY occurred_at DESC LIMIT %s""",
        (api_key_id, api_key_id, clearance.name, list(compartments),
         limit)).fetchall()
    out = {"dead_letters": [
        {"id": str(r[0]), "batch_id": str(r[1]) if r[1] else None,
         "error_class": r[2], "error_detail": r[3],
         "occurred_at": r[4].isoformat() if r[4] else None,
         "replayed_at": r[5].isoformat() if r[5] else None,
         "resolution": r[6],
         "fragment": r[7] if r[8] else None,
         "fragment_withheld": not r[8],
         "classification": r[9],
         "retain_until": r[10].isoformat() if r[10] else None}
        for r in rows],
        "count": len(rows),
        "notice": ("Fragments are structurally redacted: keys, types and "
                   "lengths only, never values. Rows recorded before "
                   "2026-07-25 are withheld until the repair script runs.")}
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


@router.post("/dead-letters/{dead_letter_id}/replay", response_model=dict,
             dependencies=[Depends(rate_limit("capture"))])
def replay(
    dead_letter_id: UUID, body: ReplayBody,
    user: CurrentUser = Depends(require_global("ingest.replay")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Re-parse a repaired fragment after fixing the parser."""
    if body.case_id is not None:
        authorize_object(conn, user, case_id=body.case_id,
                         permission_key="ingest.replay")
    try:
        record_id = IngestService(conn).replay(
            dead_letter_id, actor_id=user.user_id, repaired=body.repaired,
            case_id=body.case_id)
    except IngestError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    return {"dead_letter_id": str(dead_letter_id),
            "record_id": str(record_id),
            "notice": ("The original fragment is retained. A repair that "
                       "overwrote it would make the next format change "
                       "unattributable.")}


# ---------------------------------------------------------------------------
# The triage queue itself
# ---------------------------------------------------------------------------

#: Shared by `/records` and `/quarantine`. One projection, so the two
#: endpoints cannot drift into returning different shapes for the same row
#: -- and so a column added for one is never accidentally exposed by the
#: other under a different permission.
_QUEUE_SQL = """
        SELECT r.id, r.case_id, r.category, r.category_confidence,
               r.category_source, r.priority, r.priority_detail,
               r.created_at, r.duplicate_of, r.classification,
               r.compartments, r.retain_until, b.received_at,
               k.name, k.key_id,
               (SELECT count(*) FROM ingest.victim_credential vc
                 WHERE vc.record_id = r.id),
               (SELECT count(*) FROM ingest.record d
                 WHERE d.duplicate_of = r.id)
          FROM ingest.record r
          JOIN ingest.batch b ON b.id = r.batch_id
          JOIN ingest.api_key k ON k.id = b.api_key_id
         WHERE r.purged_at IS NULL"""


def _queue_row(r) -> dict:
    return {
        "id": str(r[0]),
        "case_id": str(r[1]) if r[1] else None,
        "quarantined": r[1] is None,
        "category": r[2],
        "category_confidence": float(r[3]),
        "category_source": r[4],
        "priority": float(r[5]),
        "priority_detail": r[6],
        "created_at": r[7].isoformat(),
        "is_duplicate": r[8] is not None,
        "classification": r[9],
        "compartments": list(r[10] or []),
        "retain_until": r[11].isoformat() if r[11] else None,
        "received_at": r[12].isoformat() if r[12] else None,
        "feed": r[13], "key_id": r[14],
        "credential_count": r[15],
        "duplicate_count": r[16],
    }


@router.get("/records", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def records(
    case_id: UUID | None = Query(None),
    category: str | None = Query(None),
    include_duplicates: bool = Query(False),
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
    (invariant 12). `duplicate_count` says how many were folded away.

    **The payload is not returned.** A record can hold a whole stealer log;
    this is a queue, and the fields here are the ones an analyst triages on.

    Records attached to no case are NOT here — see `/quarantine`. They are
    a different job with a different verb, and a hidden branch inside one
    endpoint that widens what it returns based on a second permission is
    exactly the shape that becomes a hole.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    allowed = _authorised_cases_for_ingest(conn, user)
    if case_id is not None and case_id not in allowed:
        raise Problem(404, "Not found", "no such case")
    scope = [case_id] if case_id is not None else allowed

    rows = conn.execute(
        _QUEUE_SQL + """
              AND r.case_id = ANY(%s)
              AND (%s::text IS NULL OR r.category = %s)
              AND (%s OR r.duplicate_of IS NULL)
              AND r.classification <= %s::core.tlp
              AND r.compartments <@ %s
            ORDER BY r.priority DESC, r.created_at DESC
            LIMIT %s""",
        (scope, category, category, include_duplicates,
         clearance.name, list(compartments), limit)).fetchall()
    return {"records": [_queue_row(r) for r in rows], "count": len(rows),
            "notice": (
                "Near-duplicates are folded, not dropped — duplicate_count "
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

    `ingest.manage` is the operator verb: it already covers issuing keys
    and parsing batches, which is the same job. It is deliberately NOT
    `ingest.read` — SYS_ADMIN holding that would mean the operator reads
    every case's records, which is the over-broad grant this system exists
    to avoid.

    The classification predicate still applies. Unattached is not
    unclassified: the record carries the issuing key's ceiling.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    rows = conn.execute(
        _QUEUE_SQL + """
              AND r.case_id IS NULL
              AND r.classification <= %s::core.tlp
              AND r.compartments <@ %s
            ORDER BY r.priority DESC, r.created_at DESC
            LIMIT %s""",
        (clearance.name, list(compartments), limit)).fetchall()
    return {"records": [_queue_row(r) for r in rows], "count": len(rows),
            "notice": ("Unattached material. Attaching it to a case is what "
                       "puts it under that case's authority and review "
                       "clock; until then it expires on the category's.")}


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
    """
    _authorise_record(conn, user, record_id, "ingest.read")
    try:
        score = IngestService(conn).score_record(record_id)
    except IngestError as exc:
        raise Problem(404, "Not found", str(exc)) from exc
    return {"record_id": str(record_id), "priority": score}


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
    } for r in rows], "count": len(rows)}


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
        raise Problem(400, "Invalid request", str(exc)) from exc
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
        raise Problem(451, "Unavailable for legal reasons", str(exc)) from exc
    except CaseMismatch as exc:
        raise Problem(404, "Not found",
                      "no such credential in this case") from exc
    except IngestError as exc:
        if "no such credential" in str(exc):
            raise Problem(404, "Not found", str(exc)) from exc
        raise Problem(409, "Conflict", str(exc)) from exc
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
        raise Problem(451, "Unavailable for legal reasons", str(exc)) from exc
    except IngestError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {"matches": rows, "count": len(rows),
            "note": ("Exact-match only, by construction (decision 52). "
                     "An empty result means this exact value is not in the "
                     "corpus, not that nothing similar is."),
            "notice": L2_NOTICE}
