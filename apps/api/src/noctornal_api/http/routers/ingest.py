"""Ingest over HTTP: the 202 endpoint, key management, and victim PII.

`POST /ingest` takes an ingest API key; every other route takes a session and the five-part gate.
Keys are write-only (invariant 11): the key path returns a batch id and reads nothing. Nothing is
parsed in the request (docs/12): raw bytes are stored and parsed later, so an unparseable fragment
reaches `ingest.dead_letter` (invariant 12). Victim credentials are masked; a reveal needs a live
`ingest.pii_authorisation` from a holder of `victim_pii.authorise`, is step-up gated and audited
per credential, and does not settle the open lawful-basis question (docs/16 L2).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import NamedTuple
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, Field

from noctornal_api.db import SystemPurpose, system_connection
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
    system_conn,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.body_ceiling import own_body_cap
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

#: Printed by the console when a key is issued. It names the legal item by its register number,
#: which counsel uses, not a design document's path, which the reader cannot open.
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

    `ingest.record` carries its own labels, which `IngestService` writes but never reads, so the
    router checks them or a record's victims are visible to any holder of the global `ingest.read`.
    Read as a fact: under row-level security a record above the caller would be absent, and the
    gate would never refuse it and audit the refusal (decision 141).
    """
    row = conn.execute(
        """SELECT case_id, classification, compartments
             FROM iam.ingest_record_facts(%s)""", (record_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such record")
    return row[0], row[1], frozenset(row[2] or [])


def _operator_may_see_quarantine(conn: psycopg.Connection, user: CurrentUser,
                                 classification: str,
                                 compartments: frozenset[str]) -> None:
    """The gate for a record attached to no case. Raises 404 or returns.

    Not `require_global`, a dependency that runs before the record is read: the same three checks
    (verb through a global role, account active, step-up where required) plus the label check. 404
    for every failure, since a distinct status would be an existence oracle (deps.py rule 2).
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
        # Quarantine: no case assignment can reach it, so the operator verb `/quarantine` uses is
        # the gate, and the labels still apply. `rescore` writes `priority` through a method with no
        # label predicate, so this must not be skipped.
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
    """The five-part gate on a global verb, as a question.

    `PgAccessResolver.resolve_global` gathers the facts and `evaluate()` decides, so an object with
    no case gets the same evaluator as every other. None when the context cannot be resolved (an
    inactive account, an unknown permission), which every caller treats as denied.
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

    Asks the gate with no object (CLEAR, no compartments) and reads two checks off the decision:
    the verb, and step-up freshness. `fresh` is True whenever the permission needs no step-up.
    """
    decision = _decision_global(conn, user, permission_key)
    if decision is None:
        return False, False
    return (CHECK_ROLE not in decision.failed_checks,
            CHECK_STEP_UP not in decision.failed_checks)


def _case_allows(conn: psycopg.Connection, user: CurrentUser, case_id: UUID,
                 permission_key: str, *, classification: str | None = None,
                 compartments: frozenset[str] = frozenset()) -> bool:
    """The five-part gate on one case, as a question: `authorize_object` without the refusal and
    the audit row, for a listing that answers what the caller may see. Element labels compose with
    the case's as in `authorize_object` (`effective_labels`). A resolution failure, or a case that
    is gone, is False: it fails closed."""
    try:
        eff_cls, eff_comp = effective_labels(conn, case_id, classification, compartments)
        ctx = PgAccessResolver(conn).resolve(
            user_id=user.user_id, case_id=case_id, permission_key=permission_key,
            object_classification=eff_cls, object_compartments=eff_comp,
            mfa_satisfied_at=user.session_mfa_at,
            # A question, so no audit row and no break-glass use: one queue load asks it per case
            # and per label set.
            count_use=False)
    except (AccessResolutionError, Problem):
        return False
    return evaluate(ctx).allowed


def _authorised_cases_for_ingest(conn: psycopg.Connection,
                                 user: CurrentUser) -> list[UUID]:
    """Cases where the five-part gate allows `ingest.read`, asked of the gate one case at a time so
    a check added to `evaluate()` applies here too."""
    candidates = conn.execute(
        "SELECT case_id FROM iam.case_assignment WHERE user_id = %s ORDER BY case_id",
        (user.user_id,)).fetchall()
    return [row[0] for row in candidates
            if _case_allows(conn, user, row[0], "ingest.read")]


# ---------------------------------------------------------------------------
# The write path. Key-authenticated, and the ONLY endpoint a key can reach.
# ---------------------------------------------------------------------------

@router.post("", status_code=202, response_model=dict,
             # Not a USER-scoped limit: the caller presents an ingest key, not a session, and a
             # USER-scoped subject would reject every submission. The catalogue entry says why
             # CREDENTIAL scope is sound here.
             dependencies=[Depends(rate_limit("ingest.submit"))])
# The key's own cap, read after the key authenticates; the default body ceiling does not apply.
@own_body_cap
async def submit(
    request: Request,
    authorization: str | None = Header(default=None),
    idempotency_key: str | None = Header(default=None,
                                         alias="Idempotency-Key"),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Accept a batch and return 202. Nothing is parsed here.

    Authenticated by a write-only ingest API key (invariant 11), before any of the body is read.
    The body is capped at the key's `max_bytes_per_request` (32 MiB by default) while it streams: a
    declared length over the cap is refused before a byte is read, and a chunked body on the chunk
    that crosses it, with a 413 naming the cap.
    """
    svc = _with_raw(conn)
    # From the server's own view of the connection, never from a header:
    # an allowlist is only a control if the caller cannot choose the
    # address it is compared against.
    peer = request.client.host if request.client else None
    token = _key_from_header(authorization)
    key = svc.authenticate(token, peer_ip=peer)
    if key is not None and key.get("ip_allowlist") and not peer:
        # Defence in depth, unreachable by design: `authenticate()` returns None for an
        # allowlisted key when the peer address is unknown. It stays so that if the service is ever
        # relaxed the router still fails closed.
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
    #: Mandatory expiry: a key with no expiry is one nobody notices is still live (docs/12). The
    #: ceiling matches the service's MAX_KEY_TTL (365 days), so validation and service agree.
    ttl_days: int = Field(default=90, ge=1, le=365)


#: A key is issued and revoked on a system connection: the keys are read-only to the request role
#: (migration 0179), so a statement injected into a request cannot mint or revive one past this
#: gate and its step-up.
_KEYS_CONN = system_conn(SystemPurpose.CONFIGURATION)


@router.post("/keys", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("evidence.export"))])
def issue_key(
    body: IssueKeyBody,
    user: CurrentUser = Depends(require_global("ingest.manage")),
    sconn: psycopg.Connection = Depends(_KEYS_CONN),
) -> dict:
    """Issue a key. **The secret is returned exactly once, here.**

    It is never stored in plaintext and cannot be recovered -- a lost key
    is reissued, not looked up. Expiry is mandatory: docs/12 treats a key
    with no expiry as one nobody will ever notice is still live.
    """
    try:
        issued = IngestService(sconn).issue_key(
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
    sconn: psycopg.Connection = Depends(_KEYS_CONN),
) -> dict:
    """Revoke a key. Step-up gated through `ingest.manage`, audited with the reason, and 404 for a
    key that is unknown or already revoked."""
    try:
        IngestService(sconn).revoke_key(
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

#: What a parse that names a case is told. A batch is parsed into the
#: unattached queue and a record is attached to a case afterwards, on the word
#: of someone who works that case (`attach_record`).
PARSE_NAMES_A_CASE = (
    "a batch is parsed into the unattached queue, not into a case. Attach "
    "each record to a case afterwards with POST /ingest/records/{id}/attach, "
    "which asks for ingest.replay on that case, so that material goes into a "
    "case on the word of somebody who works it")


class ParseBody(BaseModel):
    #: Refused when given: a client still sending one is told where the case step is (400,
    #: `PARSE_NAMES_A_CASE`) rather than served a parse that ignores it. The service keeps its own
    #: `case_id` for the operator scripts that seed a case (`seed_feeds_demo.py`).
    case_id: UUID | None = None
    parser_version: str = "1"


@router.post("/batches/{batch_id}/parse", response_model=dict,
             dependencies=[Depends(rate_limit("capture"))])
def parse_batch(
    batch_id: UUID, body: ParseBody,
    user: CurrentUser = Depends(require_global("ingest.manage")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Parse an accepted batch into the unattached queue.

    Separate from acceptance so a malformed 50MB dump is a background
    problem rather than a request timeout, and so the dead-letter queue
    can hold what did not parse. The operator's verb is the only gate, and
    the records land in no case: the triage flow attaches each one to the
    case that will work it (`attach_record`).
    """
    if body.case_id is not None:
        raise Problem(400, "Invalid request", PARSE_NAMES_A_CASE)
    if conn.execute("SELECT 1 FROM ingest.batch WHERE id = %s",
                    (batch_id,)).fetchone() is None:
        raise Problem(404, "Not found", "no such batch")
    # `raw_for` reads the object and verifies it against `raw_sha256` before returning:
    # re-parsing something that is not what arrived attributes records to a submission that never
    # happened. (`ingest.batch.raw_bytes` is the byte count, not the bytes.)
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
            batch_id, raw=raw, parser_version=body.parser_version)
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
    """What did not parse, and why, scoped to what the caller may read.

    A rising dead-letter rate on one key is the sign that a provider changed their format. A row
    whose batch fed a case goes to holders of `ingest.read` on that case; one that fed no case goes
    to holders of `ingest.manage`, and with its step-up lapsed `scope.unattached_withheld` says so.
    Every row is `evaluate()`'s decision, so there is no `require_global`: a caller with neither verb
    gets a 403 and its AUTHZ_DENIED row. `case_id` narrows to one case's batches (404 for a case the
    caller may not read); a row's `api_key_id` is what the `api_key_id` filter takes.
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
        # A key is visible to a case reader only if it fed one of their cases, and 404 either way
        # (deps.py rule 2), as `/records` answers for a case off-scope. The batch's cases are read
        # as a fact: a feed into the caller's case whose records sit above them still fed it.
        fed = conn.execute(
            """SELECT 1 FROM ingest.batch b
                CROSS JOIN LATERAL iam.ingest_batch_reach(b.id, %s::uuid[]) f
                WHERE b.api_key_id = %s
                  AND pg_catalog.cardinality(f.cases) > 0
                LIMIT 1""", (allowed, api_key_id)).fetchone()
        if fed is None:
            raise Problem(404, "Not found", "no such key")

    # The fragment is returned because it is redacted structurally before it is stored (migration
    # 0040): keys, types and lengths, never a value. Older rows are verbatim and withheld
    # (`redacted` says which; `scripts/redact_dead_letters.py` repairs them). Never render
    # `raw_fragment` as HTML (invariant 10). The cases each batch fed are read as facts
    # (`iam.ingest_batch_reach`), not through the record policy, or a batch whose records sit above
    # the caller would read as unattached. `fed_scope` is within `allowed`, so one ask answers both.
    clearance, compartments = user_ceiling(conn, user.user_id)
    rows = conn.execute(
        """SELECT dl.id, dl.batch_id, dl.error_class, dl.error_detail,
                  dl.occurred_at, dl.replayed_at, dl.resolution,
                  dl.raw_fragment, dl.redacted, dl.classification,
                  dl.retain_until, k.name, k.key_id,
                  fed.cases,
                  dl.compartments, dl.api_key_id
             FROM ingest.dead_letter dl
             LEFT JOIN ingest.api_key k ON k.id = dl.api_key_id
             CROSS JOIN LATERAL iam.ingest_batch_reach(dl.batch_id, %s::uuid[]) fed
            WHERE (%s::uuid IS NULL OR dl.api_key_id = %s)
              AND dl.purged_at IS NULL
              AND dl.classification <= %s::core.tlp
              AND dl.compartments <@ %s
              AND (fed.cases && %s::uuid[] OR (%s AND fed.unattached))
            ORDER BY dl.occurred_at DESC LIMIT %s""",
        (allowed, api_key_id, api_key_id, clearance.name, list(compartments),
         fed_scope, with_unattached, limit)).fetchall()

    # The decision on each row is the gate's, not the query's: the predicates above only bound the
    # fetch, and `evaluate()` judges the row's own labels through its case, or through the global
    # verb when unattached, so a predicate missing from the SELECT is still refused. Decided once
    # per (case, labels), which a feed's dead letters share.
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
    # Who may repair and replay what, so the pane offers the action only where the replay route
    # takes it: `ingest.replay` for any listed row, and the operator for an unattached row into
    # quarantine (`replay`). Asked of the gate with no audit row: a listing asks, it does not refuse.
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
         # The feed, named: a rising rate on one key is the signal. `/records` shows both to the
         # same readers.
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
    #: Every case a record of its batch went to that the caller may read: the dead letter's own, as
    #: far as the caller can see. Enough for the move check, whose target case has passed the gate
    #: and so is one of them if the batch fed it.
    fed: tuple[UUID, ...] = ()
    #: Those of `fed` the caller reads it through (`how == "case"`).
    seen: tuple[UUID, ...] = ()


def _dead_letter_reach(conn: psycopg.Connection, user: CurrentUser,
                       dead_letter_id: UUID) -> _Reach:
    """How the caller sees this dead letter, if at all: the listing's rule for one row. "case"
    through a case its batch fed (`ingest.read` there, against the row's own labels); "operator"
    for a row whose batch fed no case (the operator verb, fresh, same labels); None when the
    listing would not show it.

    Asked as questions (`_case_allows`), so no break-glass use is counted here; `replay` counts
    once, at the gate that lets it through. The batch's cases are read as a fact, not through the
    record policy, under which a batch whose records sit above the caller would read as the
    operator's. Whether it fed no case at all is told only to the operator."""
    row = conn.execute(
        """SELECT dl.classification, dl.compartments, fed.cases, fed.unattached
             FROM ingest.dead_letter dl
             CROSS JOIN LATERAL iam.ingest_batch_reach(dl.batch_id, NULL) fed
            WHERE dl.id = %s AND dl.purged_at IS NULL""",
        (dead_letter_id,)).fetchone()
    if row is None:
        return _Reach(None)
    labels = (row[0], frozenset(row[1] or []))
    fed = tuple(row[2] or ())
    if not fed and not row[3]:
        # It fed a case, none of them the caller's: the listing would not
        # show it, and it is nobody's quarantine.
        return _Reach(None, *labels)
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


# A read-only case (CLOSED, ARCHIVED or PURGED) refuses a record put into it or triaged in it:
# that is content, not governance. The one gate is `deps.refuse_if_case_read_only` (the states
# `cases.CONTENT_READ_ONLY_STATES`, a 409 titled `CASE_READ_ONLY_TITLE`, a CASE_READ_ONLY_REFUSED
# audit row). Replay, attach and category correction gate on `ingest.replay`, a content verb, so
# `authorize_object` refuses them itself; record triage gates on `ingest.read` and calls the gate
# by hand.


@router.post("/dead-letters/{dead_letter_id}/replay", response_model=dict,
             dependencies=[Depends(rate_limit("capture"))])
def replay(
    dead_letter_id: UUID, body: ReplayBody,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Re-parse a repaired fragment after fixing the parser.

    The dead letter must be one the caller's listing would show (`_dead_letter_reach`), else the
    404 an unknown id gets. The operator replays an unattached one into quarantine; putting it into
    a case needs `ingest.replay` there, asked with the fragment's labels and counted (preferring a
    case the caller reads without a grant). A replay never moves between cases, since the record
    keeps its batch and would make the batch's dead letters another case's too.
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

#: Shared by `/records`, `/quarantine` and `/records/{id}`: one projection, so the endpoints
#: cannot drift into different shapes or expose a column under a different permission. It takes
#: the caller's scope as named parameters (`vis`, the cases whose queue they read; `qok`, whether
#: unattached rows are theirs; the ceiling `clearance` and `comps`), which bound what a row says
#: about other records: the duplicate columns count only copies the caller may read, per feed,
#: since an unseen copy may be a second source, and `duplicate_of*` names a primary only when
#: readable. `triage_*` and `category_was` are read back from the audit chain. The page is chosen
#: first over `ingest.record` alone and the lookups run for its rows only (`dup` is one pass on
#: `record_duplicate_of_idx`, migration 0072). Column 16 is a placeholder under row-level
#: security: `duplicate_count` is `_copy_totals`.
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
               NULL::bigint,
               dupx.feeds, dupx.seen::bigint,
               prim.received_at, prim.feed, prim.visible,
               tri.detail, tri.occurred_at, tri.actor,
               cor.detail, dupx.sources
          FROM page
          JOIN ingest.record r ON r.id = page.id
          JOIN ingest.batch b ON b.id = r.batch_id
          JOIN ingest.api_key k ON k.id = b.api_key_id
          LEFT JOIN LATERAL (
                SELECT array_agg(x.name ORDER BY x.name)
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

#: A record's readable copies, for its detail view: the query that route runs, as a constant so
#: test_ingest_duplicate_index_pg.py EXPLAINs this text rather than a copy. An index lookup on
#: `record_duplicate_of_idx` (migration 0072).
_COPIES_SQL = """SELECT d.id, b.received_at, k.name
             FROM ingest.record d
             JOIN ingest.batch b ON b.id = d.batch_id
             JOIN ingest.api_key k ON k.id = b.api_key_id
            WHERE d.duplicate_of = %s AND d.purged_at IS NULL
              AND d.classification <= %s::core.tlp
              AND d.compartments <@ %s
              AND (d.case_id = ANY(%s::uuid[]) OR (%s AND d.case_id IS NULL))
            ORDER BY b.received_at"""

#: The latest triage state of `r`, for the page's filter: the same lookup
#: the projection's `tri` makes, asked only when a triage filter is on.
_TRIAGE_STATE = """coalesce((SELECT e.detail ->> 'state' FROM audit.event e
                         WHERE e.object_id = r.id
                           AND e.action = 'INGEST_RECORD_TRIAGED'
                         ORDER BY e.seq DESC LIMIT 1), 'NEW')"""


def _visible_detail(detail: dict | None, record_case: UUID | None,
                    allowed: set[str]) -> dict | None:
    """The score's reasons, with every watch the caller may not read taken out.

    A record in a case is scored against that case's watches and the case-less ones, which its
    readers may see. A quarantined record is scored against every watch, so a watch on a case the
    operator is not on has its name and selector withheld and the term says only that it exists. A
    record never scored keeps its null detail.
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


def _copy_totals(conn: psycopg.Connection, record_ids: list) -> dict:
    """Every folded copy of each record, unseen ones included: `duplicate_count` is the total, and
    the console says how much of it is unseen. A WITHHELD count on a system connection, over ids
    the caller's own read returned, so it names no record the caller could not already read."""
    if not record_ids:
        return {}
    with system_connection(SystemPurpose.WITHHELD, reuse=conn) as sconn:
        return {row[0]: int(row[1]) for row in sconn.execute(
            """SELECT duplicate_of, count(*) FROM ingest.record
                WHERE duplicate_of = ANY(%s::uuid[])
                GROUP BY duplicate_of""", (list(record_ids),)).fetchall()}


def _queue_row(r, allowed: set[str] | None = None,
               copies: dict | None = None) -> dict:
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
        "duplicate_count": (copies or {}).get(r[0], 0),
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
    """Counts over the whole of a case queue, whatever filter is on.

    The Category select is built from these counts, which no filter narrows. `watched_untriaged`
    is the Feeds rail badge: records matching a watched selector that nobody has triaged, folded
    duplicates not counted. Two statements, because the badge is read on every case open: the
    category counts touch no audit row, and triage state is looked up only for the watched matches.
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
    """The queue, highest priority first; never the payload.

    Near-duplicates are hidden and counted, not dropped (invariant 12): `duplicate_count` says how
    many were folded away and `duplicate_feeds` which feeds sent the readable ones. Records with no
    case are in `/quarantine`, under their own verb. `triage_state` filters on the latest triage
    decision (NEW is "none yet"); `facets` counts the whole scope by category whatever the filters,
    with the watched-and-untriaged count the rail badge shows.
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
    copies = _copy_totals(conn, [r[0] for r in rows])
    return {"records": [_queue_row(r, seen, copies) for r in rows],
            "count": len(rows),
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
    """Records that belong to no case yet, for the operator to attach (`POST /records/{id}/attach`).

    Gated on the operator verb `ingest.manage`, not `ingest.read`, which would let the operator read
    every case's records. The classification predicate still applies: an unattached record carries
    the issuing key's ceiling.
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
    copies = _copy_totals(conn, [r[0] for r in rows])
    return {"records": [_queue_row(r, seen, copies) for r in rows],
            "count": len(rows),
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
    """One queue record's metadata, never its payload.

    The score's reasons, the feed and key, the batch and its digest, the payload's shape through
    `redact_structure` (keys, types and lengths, never a value), the readable folded copies and
    the record's history from the audit chain. Gated by what the record is, as `rescore` is, with a
    404 for a record the caller may not read.
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
    out = _queue_row(row, seen, _copy_totals(conn, [row[0]]))
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
        _COPIES_SQL,
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
    """Mark a queue record Triaged, Linked (to what) or Discarded (why), or put it back to New.

    Audited, and the latest decision is the record's state. The reader's verb, since the analyst
    working the queue decides a hit is noise: `ingest.read` on the case with the record's labels,
    or the operator verb for a quarantined one; 404 for a record the caller may not read.
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
    """Attach a quarantined record to a case, the one way a feed's record reaches a case.

    The record needs the operator verb, fresh; the target case needs `ingest.replay` there with the
    record's labels, a verb the case's own team holds, so material enters a case on the word of
    somebody who works it. A record already in a case is refused, and a read-only case is refused
    by the gate.
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
    """Correct the classifier's category; corrections are training data (docs/12).

    Gated on `ingest.replay` on the record's case, the repair verb, since a category decides the
    record's retention, handling and score; a quarantined record needs the operator verb. The
    classifier's output is kept in the audit event and returned as `category_was`.
    """
    # Read first, 404 for a record the caller may not see; then the repair
    # verb, which refuses 403 like any other missing verb on a case the
    # caller is on, because they already know the record is there.
    case_id = _authorise_record(conn, user, record_id, "ingest.read")
    if case_id is not None:
        _cid, classification, compartments = _own_record(conn, record_id)
        # Refuses a read-only case too: `ingest.replay` is a content verb. Not counted, since the
        # read gate above already counted any grant use for these labels; the verb, the lifecycle
        # and the refusal are still checked.
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
    """Recompute one record's triage score, answering the score before and after and the reasons.

    The score depends on `collect.watch` selectors, which change. No `require_global` on the route:
    a record in a case needs `ingest.read` and that case's gate, a quarantined one the operator
    verb, and `_authorise_record` picks, with a 404 either way.
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
    """Rescore every record in one case's queue the caller may read, since a watch changes for a
    whole case at once.

    Metered under `capture`: one call, many writes. Bounded by the case gate and the caller's
    labels as `/records` is, and gated once more at the case's own labels, counted, so a grant
    that let it in records a use. The record filter stays at the caller's own ceiling, not the
    grant's, as in `/records`.
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
        # What the Issue form may offer: the categories the database accepts, which need a
        # compartment, and the compartments this caller holds. A key forced into a compartment its
        # issuer cannot read files every record where nobody on the operator side can see it.
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
    """Authorise somebody else to reveal victim credentials.

    Two people, on purpose: `victim_pii.authorise` is held by SECURITY_OFFICER and not by case
    roles, so the person who wants the value and the person who permits it are different people.
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
    # The credential must belong to the case whose authorisation is relied on; the service checks
    # it, so a worker or script calling it directly does too. `CaseMismatch` and "no such
    # credential" are both a 404, so the status does not say a credential exists elsewhere.
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
    """The value travels in a body, not a query string.

    A query parameter would put a victim's email address or password in the request line, and so
    in plaintext in every access log, outside every gate; the database holds these values as
    ciphertext so that plaintext is not loggable.
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
    """Look up a record by an exact selector, never by free text.

    Free-text PII search across stealer logs is impossible here, not merely forbidden (decision 52):
    the values are ciphertext with no text index, and this matches a fingerprint of an exact value.
    """
    authorize_object(conn, user, case_id=body.case_id,
                     permission_key="ingest.read")
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        # The ceiling is carried into the query, not applied afterwards: the hit count, the timing
        # and the audit event must not be computed over records the caller may not read.
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
