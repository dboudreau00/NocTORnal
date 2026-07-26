"""Social-engineering evidence over HTTP: captures, BEC email, vishing calls.

docs/19. Structurally this is the samples router's sibling — **metadata
renders, bytes do not** — with one deliberate exception that is the most
security-sensitive endpoint added to this platform since `/download`:

## `/captures/{id}/screenshot` is the first inline exhibit path

Every other exhibit route in NocTORnal serves `application/octet-stream`
with `Content-Disposition: attachment`, so nothing has ever been handed to
the browser to interpret. A phishing screenshot has to be, or the subsystem
is useless. Five things guard it, and all five are load-bearing:

1. The five-part access gate, twice: against the CAPTURE's composed labels
   and again against the EXHIBIT's own. Both are needed — a RED exhibit can
   be referenced by an AMBER capture, and the exhibit's labels are the ones
   `EvidenceService.view()` does not check (it has no authorisation at all).
2. The evidence id is read from the capture row, and every id a caller
   supplies at CREATE time is verified to be in-case and readable by them
   first.

   > This guard was originally written as "a caller cannot name one, so the
   > 'attach any exhibit to a capture I can see' pivot does not exist."
   > **That was false**: `CaptureIn.screenshot_evidence_id` is
   > caller-supplied. An adversarial pass on 2026-07-26 showed an AMBER
   > analyst attaching a known RED exhibit id to their own AMBER capture and
   > having the RED image rendered inline. The pivot existed; guard 1's
   > second half and the create-time check are what actually close it.

3. `is_hostile_markup` refuses outright — checked AFTER the case and label
   checks, so it cannot become an oracle about a row the caller may not see.
4. The content type is re-derived from the MAGIC BYTES and the response is
   labelled with what was found — never with `media_type`, which is
   `UploadFile.content_type` and therefore whatever the uploading client
   said. An HTML document labelled `image/png` is the exact attack, and
   believing the column is how it lands.
5. `Content-Security-Policy: default-src 'none'; sandbox`, `nosniff`, and
   `Cross-Origin-Resource-Policy: same-origin` — so even if 1–4 were all
   wrong at once, the browser has no scripting context to execute in.

## Permissions are reused, not invented

`evidence.read` and `evidence.upload`. A capture, a parsed message and a
CDR are provenance records ABOUT evidence, and the authority to see the
exhibit and the authority to see the row describing it should not be two
different grants that can drift apart. Adding `deception.*` permissions
would also mean every existing role silently holds none of them.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, File, Form, Response, UploadFile
from pydantic import BaseModel

from noctornal_api.deception import (
    MAX_EML_BYTES,
    DeceptionError,
    DeceptionService,
    defang,
    parse_eml,
    raster_type_of,
    selector_candidates_for_call,
    selector_candidates_for_email,
)
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    check_writable_labels,
    current_user,
    get_conn,
    user_ceiling,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/cases/{case_id}/deception", tags=["deception"])


def _svc(conn: psycopg.Connection) -> DeceptionService:
    return DeceptionService(conn)


def _ceiling(conn: psycopg.Connection, user: CurrentUser):
    tlp, comps = user_ceiling(conn, user.user_id)
    return tlp.name, comps


# ---------------------------------------------------------------------------
# Captures
# ---------------------------------------------------------------------------

#: Mirrored from the `_known` CHECK constraints in migrations 0048/0050.
#: Without these a caller-supplied string reached the driver and came back
#: as a raw CheckViolation -- a 500 -- from an endpoint whose every other
#: refusal is a 422 with a sentence. The constraints stay: they are what
#: holds when a migration or a psql session does the write.
_CAPTURE_METHODS = frozenset({
    "MANUAL_BROWSER", "HEADLESS", "VENDOR_API", "ANALYST_UPLOAD",
    "VICTIM_SUPPLIED", "PASSIVE_FEED"})
_HOP_KINDS = frozenset({
    "REQUESTED", "HTTP_30X", "META_REFRESH", "JS", "FRAME", "DNS_CNAME"})
_CALL_DIRECTIONS = frozenset({
    "INBOUND_TO_VICTIM", "OUTBOUND_FROM_VICTIM", "UNKNOWN"})
_RECORD_SOURCES = frozenset({
    "CARRIER_CDR", "PBX_LOG", "SIP_CAPTURE", "VICTIM_STATEMENT",
    "HANDSET_LOG", "THIRD_PARTY_REPORT"})
_DISPOSITIONS = frozenset({
    "ANSWERED", "NO_ANSWER", "BUSY", "VOICEMAIL", "REJECTED", "FAILED"})
_ATTESTATIONS = frozenset({"A", "B", "C"})


def _one_of(value, allowed, field):
    if value is not None and value not in allowed:
        raise Problem(422, "Invalid field",
                      f"{field} must be one of {', '.join(sorted(allowed))}")
    return value


def _clean_hops(hops: list[dict]) -> list[dict]:
    """Validate the free-form hop list before it reaches the driver.

    `hops: list[dict]` is unvalidated by pydantic, so `{"hops": [{}]}`
    raised KeyError inside the service -- neither DeceptionError nor
    ValueError, therefore a 500.
    """
    out = []
    for i, hop in enumerate(hops or []):
        if not isinstance(hop, dict) or not str(hop.get("url", "")).strip():
            raise Problem(422, "Invalid field",
                          f"hops[{i}] needs a non-empty url")
        _one_of(hop.get("hop_kind"), _HOP_KINDS, f"hops[{i}].hop_kind")
        out.append(hop)
    return out


class CaptureIn(BaseModel):
    requested_url: str
    capture_method: str
    final_url: str | None = None
    capture_tool: str | None = None
    egress_profile_id: str | None = None
    user_agent: str | None = None
    viewport: str | None = None
    http_status: int | None = None
    is_live: bool | None = None
    page_title: str | None = None
    visible_text: str | None = None
    favicon_hash: str | None = None
    screenshot_evidence_id: str | None = None
    dom_evidence_id: str | None = None
    har_evidence_id: str | None = None
    tls_subject: str | None = None
    tls_issuer: str | None = None
    tls_spki_sha256: str | None = None
    #: docs/19 §6, legal item L5. Entering credentials — including canary
    #: ones — into a phishing page may constitute unauthorised access.
    #: There is no code in this platform that does it; this records that a
    #: human did, under a written authority.
    submitted_input: bool = False
    submission_authority_ref: str | None = None
    hops: list[dict] = []
    note: str | None = None
    classification: str = "AMBER"
    compartments: list[str] = []


@router.post("/captures", status_code=201,
             dependencies=[Depends(rate_limit("capture"))])
def create_capture(
    case_id: UUID, body: CaptureIn,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    authorize_object(conn, user, case_id=case_id, permission_key="evidence.upload")
    check_writable_labels(conn, user, classification=body.classification,
                          compartments=frozenset(body.compartments))
    # Every referenced exhibit must be IN THIS CASE and readable BY THIS
    # CALLER, checked before the row is written.
    #
    # The three evidence columns are only FK-constrained, which means a
    # caller could name any id in `core.evidence`: a nonexistent one gave a
    # `ForeignKeyViolation` (a 500), and one from another case was accepted
    # — an existence oracle over the whole table, and the way the
    # screenshot endpoint's missing label check was reachable.
    for field in ("screenshot_evidence_id", "dom_evidence_id",
                  "har_evidence_id"):
        raw = getattr(body, field)
        if not raw:
            continue
        try:
            exhibit_id = UUID(raw)
        except ValueError as exc:
            raise Problem(422, "Invalid field", f"{field} is not a UUID") from exc
        found = conn.execute(
            "SELECT case_id, classification, compartments "
            "  FROM core.evidence WHERE id = %s", (exhibit_id,)).fetchone()
        # Same answer for "does not exist" and "belongs to a case you
        # cannot see": a status code must not be an existence oracle.
        if found is None or found[0] != case_id:
            raise Problem(404, "Not found", f"no such exhibit for {field}")
        authorize_object(conn, user, case_id=case_id,
                         permission_key="evidence.read",
                         classification=found[1],
                         compartments=frozenset(found[2] or []))
    _one_of(body.capture_method, _CAPTURE_METHODS, "capture_method")
    hops = _clean_hops(body.hops)
    if not body.requested_url.strip():
        raise Problem(422, "Invalid field", "requested_url is required")
    try:
        capture_id = _svc(conn).record_capture(
            case_id=case_id,
            requested_url=body.requested_url,
            capture_method=body.capture_method,
            captured_by=user.user_id,
            final_url=body.final_url,
            hops=hops,
            egress_profile_id=(UUID(body.egress_profile_id)
                               if body.egress_profile_id else None),
            screenshot_evidence_id=(UUID(body.screenshot_evidence_id)
                                    if body.screenshot_evidence_id else None),
            dom_evidence_id=(UUID(body.dom_evidence_id)
                             if body.dom_evidence_id else None),
            har_evidence_id=(UUID(body.har_evidence_id)
                             if body.har_evidence_id else None),
            tls={"subject": body.tls_subject, "issuer": body.tls_issuer,
                 "spki_sha256": (bytes.fromhex(body.tls_spki_sha256)
                                 if body.tls_spki_sha256 else None)},
            submitted_input=body.submitted_input,
            submission_authority_ref=body.submission_authority_ref,
            classification=body.classification,
            compartments=frozenset(body.compartments),
            capture_tool=body.capture_tool, user_agent=body.user_agent,
            viewport=body.viewport, http_status=body.http_status,
            is_live=body.is_live, page_title=body.page_title,
            visible_text=body.visible_text, favicon_hash=body.favicon_hash,
            note=body.note,
        )
    except DeceptionError as exc:
        raise Problem(422, "Capture refused", str(exc)) from exc
    except ValueError as exc:
        raise Problem(422, "Invalid field", str(exc)) from exc
    return {"id": str(capture_id)}


@router.get("/captures")
def list_captures(
    case_id: UUID, limit: int = 100,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    authorize_object(conn, user, case_id=case_id, permission_key="evidence.read")
    clearance, comps = _ceiling(conn, user)
    return {"captures": _svc(conn).captures(
        case_id, clearance=clearance, compartments=comps, limit=min(limit, 500))}


@router.get("/captures/{capture_id}")
def get_capture(
    case_id: UUID, capture_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    authorize_object(conn, user, case_id=case_id, permission_key="evidence.read")
    clearance, comps = _ceiling(conn, user)
    capture = _svc(conn).capture(capture_id, clearance=clearance, compartments=comps)
    if capture is None or capture["case_id"] != str(case_id):
        # Identical answer for "does not exist", "belongs to another case"
        # and "you may not see it" — a status code must not be an
        # existence oracle for a compartmented case.
        raise Problem(404, "Not found", "no such capture")
    return capture


@router.get("/captures/{capture_id}/screenshot")
def capture_screenshot(
    case_id: UUID, capture_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """The one inline exhibit path in the platform. See the module
    docstring for the five guards; each `Problem` below is one of them."""
    from noctornal_api.evidence import EvidenceService, EvidenceStorage, IntegrityError

    authorize_object(conn, user, case_id=case_id, permission_key="evidence.read")
    clearance, comps = _ceiling(conn, user)
    capture = _svc(conn).capture(capture_id, clearance=clearance, compartments=comps)
    if capture is None or capture["case_id"] != str(case_id):
        raise Problem(404, "Not found", "no such capture")
    evidence_id = capture.get("screenshot_evidence_id")
    if not evidence_id:
        raise Problem(404, "Not found", "this capture has no screenshot")

    row = conn.execute(
        "SELECT is_hostile_markup, case_id, classification, compartments "
        "  FROM core.evidence WHERE id = %s",
        (UUID(evidence_id),)).fetchone()
    if row is None:
        raise Problem(404, "Not found", "the screenshot exhibit is missing")

    # THE EXHIBIT'S OWN CASE, FIRST. Before anything else is revealed about
    # it, including whether it is hostile.
    #
    # Found by an adversarial pass, 2026-07-26. The hostile check used to
    # run before this one, which made the endpoint a three-way oracle over
    # `core.evidence` for a caller holding an id out of band:
    #   409 -> the row exists and is hostile
    #   404 "no such capture" -> exists, not hostile, another case
    #   404 "the screenshot exhibit is missing" -> does not exist
    # Rule (b) of the access gate: authorisation is decided BEFORE
    # existence is revealed.
    if row[1] != case_id:
        raise Problem(404, "Not found", "no such capture")

    # THE EXHIBIT'S OWN LABELS. `EvidenceService.view()` has no
    # authorisation of its own -- `_fetch_verified` is `WHERE id = %s` and
    # nothing more -- so the gate has to happen here, exactly as
    # `routers/evidence._authorize_exhibit` does it.
    #
    # This was missing, and it was reachable. `screenshot_evidence_id` is
    # caller-supplied on `POST /captures`, so an AMBER analyst who knew a
    # RED exhibit's id (from a former clearance, a report, a custody trail)
    # could attach it to their own AMBER capture and have the RED image
    # rendered inline in their browser. The capture's labels were composed
    # correctly and the exhibit's were never consulted at all -- rule (a),
    # "an element is protected by BOTH its own labels and its case's",
    # violated on the one path in the product that hands bytes to a browser
    # to interpret.
    authorize_object(conn, user, case_id=case_id,
                     permission_key="evidence.read",
                     classification=row[2],
                     compartments=frozenset(row[3] or []))

    if row[0]:
        raise Problem(
            409, "Not renderable",
            "this exhibit is marked as attacker-authored markup and is "
            "download-only (invariant 10). Fetch it from the sample origin.")

    try:
        data = EvidenceService(conn, EvidenceStorage()).view(
            UUID(evidence_id), user.user_id)
    except IntegrityError as exc:
        raise Problem(409, "Integrity failure", str(exc)) from exc

    media_type = raster_type_of(data)
    if media_type is None:
        # The stored media_type said image; the bytes disagree. That is
        # either a broken upload or the attack this check exists for, and
        # both end the same way.
        raise Problem(
            415, "Not an image",
            "the stored bytes are not a raster image (the declared media "
            "type is client-supplied and is not trusted here)")
    return Response(
        content=data, media_type=media_type,
        headers={
            "Content-Disposition": f'inline; filename="{capture_id}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cross-Origin-Resource-Policy": "same-origin",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "private, no-store",
        },
    )


# ---------------------------------------------------------------------------
# Email (BEC)
# ---------------------------------------------------------------------------

@router.post("/emails", status_code=201,
             dependencies=[Depends(rate_limit("evidence.ingest"))])
async def upload_email(
    case_id: UUID,
    file: UploadFile = File(...),
    direction: str = Form("INBOUND_TO_VICTIM"),
    classification: str = Form("AMBER"),
    display_name_impersonates: str | None = Form(None),
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Ingest a `.eml`: store the raw bytes as a hostile exhibit, then
    parse the headers into findings.

    The exhibit lands FIRST and the parse is derived from it, never the
    other way round. If the parser is improved next year, the exhibit is
    still the thing the analysis was made from — invariant 5's spirit: the
    original is not edited by a better reading of it.
    """
    from noctornal_api.evidence import EvidenceService, EvidenceStorage

    authorize_object(conn, user, case_id=case_id, permission_key="evidence.upload")
    check_writable_labels(conn, user, classification=classification)

    data = await _read_capped(file, MAX_EML_BYTES)
    svc = EvidenceService(conn, EvidenceStorage())
    result = svc.ingest(
        case_id=case_id,
        title=file.filename or "message.eml",
        media_type="message/rfc822",
        data=data,
        acquired_by=user.user_id,
        acquisition_method="MANUAL_UPLOAD",
        classification=classification,
        is_hostile_markup=True,      # explicit; the derivation agrees
    )
    parsed = parse_eml(data)
    try:
        message_id = _svc(conn).record_email(
            case_id=case_id, evidence_id=result.evidence_id, parsed=parsed,
            recorded_by=user.user_id, direction=direction,
            display_name_impersonates=display_name_impersonates,
            classification=classification)
    except DeceptionError as exc:
        raise Problem(422, "Not recorded", str(exc)) from exc
    return {"id": str(message_id), "evidence_id": str(result.evidence_id),
            "parse_gaps": parsed.gaps,
            "from_replyto_divergent": parsed.from_replyto_divergent,
            "selector_candidates": selector_candidates_for_email(parsed)}


@router.get("/emails")
def list_emails(
    case_id: UUID, divergent_only: bool = False, limit: int = 100,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    authorize_object(conn, user, case_id=case_id, permission_key="evidence.read")
    clearance, comps = _ceiling(conn, user)
    return {"emails": _svc(conn).emails(
        case_id, clearance=clearance, compartments=comps,
        divergent_only=divergent_only, limit=min(limit, 500))}


@router.get("/emails/{message_id}")
def get_email(
    case_id: UUID, message_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    authorize_object(conn, user, case_id=case_id, permission_key="evidence.read")
    clearance, comps = _ceiling(conn, user)
    message = _svc(conn).email(message_id, clearance=clearance, compartments=comps)
    if message is None or message["case_id"] != str(case_id):
        raise Problem(404, "Not found", "no such message")
    return message


# ---------------------------------------------------------------------------
# Calls (vishing)
# ---------------------------------------------------------------------------

class CallIn(BaseModel):
    started_at: datetime
    direction: str
    record_source: str
    #: WHAT THE VICTIM SAW. Attacker-chosen; never becomes a selector.
    presented_number: str | None = None
    presented_number_e164: str | None = None
    presented_name: str | None = None
    #: WHAT THE NETWORK SAW. Durable.
    originating_trunk: str | None = None
    p_asserted_identity: str | None = None
    carrier_name: str | None = None
    stir_shaken_attestation: str | None = None
    stir_shaken_verified: bool = False
    called_number_e164: str | None = None
    ended_at: datetime | None = None
    duration_seconds: int | None = None
    disposition: str | None = None
    sip_call_id: str | None = None
    sip_from_uri: str | None = None
    sip_to_uri: str | None = None
    source_ip: str | None = None
    evidence_id: str | None = None
    #: Legal item L4. Content, not metadata — refused without a basis.
    recording_evidence_id: str | None = None
    recording_lawful_basis: str | None = None
    note: str | None = None
    classification: str = "AMBER"
    compartments: list[str] = []


@router.post("/calls", status_code=201,
             dependencies=[Depends(rate_limit("capture"))])
def create_call(
    case_id: UUID, body: CallIn,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    authorize_object(conn, user, case_id=case_id, permission_key="evidence.upload")
    check_writable_labels(conn, user, classification=body.classification,
                          compartments=frozenset(body.compartments))
    payload = body.model_dump()
    for key in ("started_at", "direction", "record_source", "classification",
                "compartments", "recording_evidence_id",
                "recording_lawful_basis"):
        payload.pop(key, None)
    for key in ("evidence_id",):
        if payload.get(key):
            payload[key] = UUID(payload[key])
    _one_of(body.direction, _CALL_DIRECTIONS, "direction")
    _one_of(body.record_source, _RECORD_SOURCES, "record_source")
    _one_of(body.disposition, _DISPOSITIONS, "disposition")
    _one_of(body.stir_shaken_attestation, _ATTESTATIONS,
            "stir_shaken_attestation")
    if body.source_ip:
        import ipaddress
        try:
            ipaddress.ip_address(body.source_ip)
        except ValueError as exc:
            raise Problem(422, "Invalid field",
                          "source_ip is not an IP address") from exc
    try:
        call_id = _svc(conn).record_call(
            case_id=case_id, started_at=body.started_at,
            direction=body.direction, record_source=body.record_source,
            recorded_by=user.user_id,
            recording_evidence_id=(UUID(body.recording_evidence_id)
                                   if body.recording_evidence_id else None),
            recording_lawful_basis=body.recording_lawful_basis,
            classification=body.classification,
            compartments=frozenset(body.compartments), **payload)
    except DeceptionError as exc:
        raise Problem(422, "Call refused", str(exc)) from exc
    except ValueError as exc:
        raise Problem(422, "Invalid field", str(exc)) from exc
    return {"id": str(call_id)}


@router.get("/calls")
def list_calls(
    case_id: UUID, limit: int = 100,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    authorize_object(conn, user, case_id=case_id, permission_key="evidence.read")
    clearance, comps = _ceiling(conn, user)
    calls = _svc(conn).calls(case_id, clearance=clearance,
                             compartments=comps, limit=min(limit, 500))
    for call in calls:
        call["selector_candidates"] = selector_candidates_for_call({
            **call["durable"], **{
                "called_number_e164": call["called_number_e164"],
                "sip_from_uri": call["sip_from_uri"],
                "sip_to_uri": call["sip_to_uri"],
                "presented_number_e164": call["presented"]["number_e164"],
            }})
    return {"calls": calls}


@router.get("/defang")
def defang_preview(
    case_id: UUID, value: str,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Defang an arbitrary string for safe display or a report.

    Case-scoped and gated even though it is a pure function of its input:
    an ungated utility endpoint on an authenticated API is a free oracle,
    and there is no reason to hand one out.
    """
    authorize_object(conn, user, case_id=case_id, permission_key="evidence.read")
    return {"value": value[:4096], "defanged": defang(value[:4096])}


async def _read_capped(file: UploadFile, cap: int) -> bytes:
    """Read the upload, refusing at the first chunk that crosses the cap.

    Same shape and same reason as `routers/samples._read_capped`: an
    unbounded `await file.read()` accumulates the whole body BEFORE the
    size check, so the cap is documented, enforced, and useless against
    exactly the thing a cap is for.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > cap:
            raise Problem(413, "Too large",
                          f"message exceeds the {cap} byte cap")
        chunks.append(chunk)
    if total == 0:
        raise Problem(422, "Empty", "no bytes were uploaded")
    return b"".join(chunks)
