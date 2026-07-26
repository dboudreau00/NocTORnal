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

from datetime import timedelta
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import BaseModel, Field

from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    get_conn,
    require_global,
    require_step_up,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.ingest import (
    AuthorisationRequired,
    IngestError,
    IngestService,
)

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


def _authorise_record(conn: psycopg.Connection, user: CurrentUser,
                      record_id: UUID, permission: str) -> UUID:
    """Gate a record by its OWN case and its OWN labels.

    Answered as 404 either way: a status code must not be an existence
    oracle (deps.py rule 2), and "this record exists but is not yours" is
    itself a disclosure about a compartmented case.
    """
    case_id, classification, compartments = _own_record(conn, record_id)
    if case_id is None:
        # A record not yet attached to a case is quarantine material.
        # Only the ingest operators see it.
        return case_id
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
    svc = IngestService(conn)
    # From the server's own view of the connection, never from a header:
    # an allowlist is only a control if the caller cannot choose the
    # address it is compared against.
    peer = request.client.host if request.client else None
    token = _key_from_header(authorization)
    key = svc.authenticate(token, peer_ip=peer)
    if key is not None and key.get("ip_allowlist") and not peer:
        # Fail CLOSED. The service skips the allowlist when peer_ip is
        # None (`if allowlist and peer_ip:`), so a deployment where the
        # ASGI scope carries no client -- a unix socket, some proxy
        # setups -- silently dropped the control instead of enforcing it.
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


def _batch_bytes(raw_key: str | None) -> bytes | None:
    """Fetch a batch's payload, or None if it is not retrievable.

    **Currently always None, and that is the honest state.**
    `IngestService.accept()` writes the payload only when it is
    constructed with a storage adapter, and every construction in this
    router passes none -- so the bytes were never stored. `ingest.batch`
    keeps `raw_key` and `raw_bytes` (a byte COUNT, not the bytes), which
    is what made the first version of this endpoint shred a run of NULs
    into the dead-letter queue on every call.

    Returning None makes the endpoint refuse with a 409 that says why.
    The alternative -- an empty buffer -- parses to zero records and marks
    the batch PARSED, silently losing it, which is invariant 12 failing on
    the one path designed to catch loss.

    Wiring an ingest storage adapter is the remaining Phase 9 work
    (`ROADMAP-REMAINING`: "the HTTP 202 endpoint wiring"). It needs a
    `put(key, data)` / `get(key)` pair; `EvidenceStorage` is NOT it --
    its `put` demands a media type and an object-lock retention date,
    because an exhibit and a quarantined third-party dump are different
    things with different retention.
    """
    return None


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
    # `ingest.batch.raw_bytes` is a bigint -- the byte COUNT, not the
    # bytes. `bytes(<int>)` allocates that many NULs, so every parse
    # shredded a run of zeros into the dead-letter queue and never touched
    # the batch. The payload lives in object storage under `raw_key`.
    row = conn.execute(
        "SELECT raw_key, raw_bytes FROM ingest.batch WHERE id = %s",
        (batch_id,)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "no such batch")
    raw = _batch_bytes(row[0])
    if raw is None:
        raise Problem(
            409, "Conflict",
            "the raw payload for this batch is not retrievable: object "
            "storage is not configured, so `accept()` recorded the batch "
            "without storing its bytes. Parsing would dead-letter the "
            "whole batch rather than fail, which is worse.")
    try:
        result = IngestService(conn).parse_batch(
            batch_id, raw=raw, case_id=body.case_id,
            parser_version=body.parser_version)
    except IngestError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    return {
        "batch_id": str(batch_id), "records": result.records,
        "dead_letters": result.dead, "duplicates": result.duplicates,
        "warnings": result.warnings,
        "notice": ("Fragments that failed to parse are in the dead-letter "
                   "queue WITH their raw bytes. Silent drops are how you "
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
    # `raw_fragment` is deliberately NOT selected. It is the unparsed
    # attacker-supplied bytes, which is exactly what a triage list should
    # summarise rather than render.
    rows = conn.execute(
        """SELECT id, batch_id, error_class, error_detail, occurred_at,
                  replayed_at, resolution
             FROM ingest.dead_letter
            WHERE (%s::uuid IS NULL OR api_key_id = %s)
            ORDER BY occurred_at DESC LIMIT %s""",
        (api_key_id, api_key_id, limit)).fetchall()
    out = {"dead_letters": [
        {"id": str(r[0]), "batch_id": str(r[1]) if r[1] else None,
         "error_class": r[2], "error_detail": r[3],
         "occurred_at": r[4].isoformat() if r[4] else None,
         "replayed_at": r[5].isoformat() if r[5] else None,
         "resolution": r[6]} for r in rows],
        "count": len(rows)}
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
    rows = IngestService(conn).credentials_masked(record_id)
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
    # relied on. The service checks that a live authorisation exists for
    # `case_id` and then decrypts by credential id with no join back to
    # the record -- so an authorisation on ANY case decrypted any
    # credential in the corpus, and the audit event recorded the wrong
    # case against the disclosure. Reproduced live by the service review.
    row = conn.execute(
        """SELECT r.case_id FROM ingest.victim_credential vc
             JOIN ingest.record r ON r.id = vc.record_id
            WHERE vc.id = %s""", (credential_id,)).fetchone()
    if row is None or row[0] != body.case_id:
        raise Problem(404, "Not found", "no such credential in this case")
    try:
        value = IngestService(conn).reveal_credential(
            credential_id, actor_id=user.user_id, case_id=body.case_id,
            reason=body.reason)
    except AuthorisationRequired as exc:
        raise Problem(451, "Unavailable for legal reasons", str(exc)) from exc
    except IngestError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc
    return {"credential_id": str(credential_id), "value": value,
            "notice": ("This reveal is audited against you and the "
                       "authorisation that permitted it. " + L2_NOTICE)}


@router.get("/search", response_model=dict,
            dependencies=[Depends(rate_limit("search"))])
def search_by_fingerprint(
    value: str = Query(..., min_length=3),
    case_id: UUID = Query(...),
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
    authorize_object(conn, user, case_id=case_id,
                     permission_key="ingest.read")
    try:
        rows = IngestService(conn).search_by_fingerprint(
            value, actor_id=user.user_id, case_id=case_id)
        # The service query carries no case predicate, so it answers for
        # the WHOLE corpus: one authorisation on one case became a yes/no
        # oracle plus metadata against every other case's holdings,
        # including compartments the caller is not read into. Filtered
        # here until the service takes the caller's ceiling the way
        # CommsService does.
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
