"""Sample handling over HTTP (Phase 8, docs/11, invariant 10).

COUNSEL MUST REVIEW A DEPLOYMENT OF THIS. See `samples.py` and the README
warning block; the short version is that a store of attacker-supplied
binaries will eventually receive material whose possession alone is an
offence, and the code being correct does not make the deployment lawful.

## Metadata renders here. Bytes do not.

Every endpoint in this file returns JSON about a sample -- hashes, file
type, entropy, analysis findings, custody. That is invariant 10's first
half, and it is why the UI can show a sample at all.

The second half is that `/download` returns the encrypted archive and is
the ONLY endpoint that touches sample bytes, and it refuses unless the
request arrived at the configured sample origin. The check is in the
service so it cannot be skipped by a second caller, and the response
headers are the belt to that braces: `application/octet-stream`,
`Content-Disposition: attachment`, `nosniff`, and a CSP of `sandbox` so
that even if something upstream serves this as HTML the browser will not
execute it.

## Two permissions that do not imply each other

`sample.read` is case-side: an analyst may see that a sample exists and
what the lab found. `sample.download` is lab-side and step-up gated: it is
the one action in this system that puts working malware on somebody's
disk. `MALWARE_ANALYST` holds the second and deliberately holds no case
access at all.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, File, Form, Request, Response, UploadFile
from pydantic import BaseModel, Field

from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    check_writable_labels,
    current_user,
    get_conn,
    require_global,
    require_step_up,
    user_ceiling,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.samples import (
    MAX_SAMPLE_BYTES,
    PolicyNotDeclared,
    Sample,
    SampleError,
    SampleService,
    policy_declared,
    sample_origin,
)

router = APIRouter(prefix="/samples", tags=["samples"])


def _svc(conn: psycopg.Connection) -> SampleService:
    from noctornal_api.samples import SampleStorage
    return SampleService(conn, SampleStorage())


class SampleOut(BaseModel):
    id: str
    case_id: str | None
    sha256: str
    sha1: str | None
    md5: str | None
    original_filename: str | None
    byte_size: int
    state: str
    reject_reason: str | None
    file_type: str | None
    entropy: float | None
    #: What triage could NOT establish, and why. A NULL imphash reads as
    #: "no imports"; a recorded gap reads as "nobody looked".
    triage_gaps: list
    submitted_by: str
    submitted_at: str
    source_note: str | None
    assigned_to: str | None
    classification: str


def _out(s: Sample) -> SampleOut:
    return SampleOut(
        id=str(s.id), case_id=str(s.case_id) if s.case_id else None,
        sha256=s.sha256, sha1=s.sha1, md5=s.md5,
        original_filename=s.original_filename, byte_size=s.byte_size,
        state=s.state, reject_reason=s.reject_reason, file_type=s.file_type,
        entropy=s.entropy, triage_gaps=s.triage_gaps,
        submitted_by=str(s.submitted_by),
        submitted_at=s.submitted_at.isoformat(), source_note=s.source_note,
        assigned_to=str(s.assigned_to) if s.assigned_to else None,
        classification=s.classification,
    )


async def _read_capped(file: UploadFile) -> bytes:
    """Read the upload, refusing as soon as it exceeds the cap.

    `await file.read()` with no argument buffers the WHOLE body first and
    the service checks the size afterwards — so a caller could hand the API
    four gigabytes and the refusal arrived only once four gigabytes had
    been accumulated. The cap was documented, enforced, and useless against
    the thing a cap is for.

    Chunked, and it stops at the first chunk that crosses the line. The
    limit is `MAX_SAMPLE_BYTES` itself rather than a second number, because
    two limits drift and the one that drifts is the one nobody is looking
    at.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_SAMPLE_BYTES:
            raise Problem(
                413, "Payload too large",
                f"a sample submission is capped at {MAX_SAMPLE_BYTES} bytes; "
                f"anything larger is a disk image or a mistake. The upload "
                f"was refused at the cap rather than buffered whole.")
        chunks.append(chunk)
    return b"".join(chunks)


@router.get("/policy", response_model=dict)
def policy_status(_: CurrentUser = Depends(current_user)) -> dict:
    """Whether an operator has declared a prohibited-content policy, and
    whether a separate sample origin is configured.

    Surfaced rather than buried so that "sample submission is refused" has
    a discoverable cause. Returns the operator's own reference, which is
    the point of asking for a reference rather than a boolean.
    """
    declared, detail = policy_declared()
    origin = sample_origin()
    return {
        "policy_declared": declared,
        "policy_reference": detail if declared else None,
        "detail": None if declared else detail,
        "sample_origin_configured": bool(origin),
        "counsel_review_required": True,
        "notice": (
            "Counsel must review this deployment before it is used in any "
            "absolute sense. A store of attacker-supplied binaries will "
            "eventually receive material whose possession alone is an "
            "offence, and the handling rules differ by jurisdiction. This "
            "software records a declaration; it cannot verify one."
        ),
    }


@router.post("", response_model=SampleOut, status_code=201,
             dependencies=[Depends(rate_limit("evidence.ingest"))])
async def submit(
    request: Request,
    file: UploadFile = File(...),
    case_id: UUID | None = Form(None),
    source_note: str | None = Form(None),
    classification: str = Form("AMBER"),
    compartments: str = Form(""),
    user: CurrentUser = Depends(require_global("sample.submit")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SampleOut:
    """Land a sample in QUARANTINE. Nothing reaches the RE queue until
    triage has run, and nothing is accepted at all until a
    prohibited-content policy has been declared.

    `sample.submit` is a GLOBAL permission — `require_global` resolves the
    verb, the active account and step-up freshness, and knows nothing about
    a case. So a caller holding it could previously attach a sample to ANY
    case id, including one the access gate would answer 404 for: a write
    into a case file they cannot see, which then carries that case's labels
    and appears in its report. `authorize_object` closes that, and it is
    the same five-part decision every other case-scoped write makes.

    `compartments` exists at all now because the form had no field for it,
    so every sample landed with `'{}'` whatever its case required. The
    service unions the case's in regardless; this is for the case where the
    SAMPLE is more restricted than the case it came from, which is the
    normal direction for a sample carrying a source's fingerprints.
    """
    parsed = frozenset(c.strip() for c in compartments.split(",") if c.strip())
    # Refuse to author what the caller could not read back. Without this a
    # holder of `sample.submit` — CASE_OWNER, ANALYST and REVIEWER all hold
    # it — could land a RED sample from an AMBER account: a row they
    # created, cannot see, and cannot correct. It also closes the first
    # step of the original critical, which began "submit at RED, then
    # download it".
    #
    # Applied on BOTH paths. `authorize_object` covers the case-attached
    # one and composes the case's labels in, but a sample with no case
    # never reaches it, and an unattached sample is exactly where an
    # over-labelled row would sit unnoticed.
    check_writable_labels(conn, user, classification=classification,
                          compartments=parsed)
    if case_id is not None:
        authorize_object(conn, user, case_id=case_id,
                         permission_key="sample.submit",
                         classification=classification, compartments=parsed)
    data = await _read_capped(file)
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        return _out(_svc(conn).submit(
            data, submitted_by=user.user_id, case_id=case_id,
            # The filename is stored for the record and is NEVER used as a
            # path component or rendered unescaped.
            original_filename=file.filename, source_note=source_note,
            classification=classification, compartments=parsed,
            # Only for how much the duplicate refusal may say: uploading a
            # hash you suspect and reading the error back is a cheap probe
            # for "is anybody else working this intrusion".
            visible_to_clearance=clearance.name,
            visible_to_compartments=held))
    except PolicyNotDeclared as exc:
        # 451: the refusal is legal, not technical, and a 400 would send
        # somebody looking at their upload.
        raise Problem(451, "Unavailable for legal reasons", str(exc)) from exc
    except SampleError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


@router.get("", response_model=dict)
def queue(
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The RE queue, filtered by the caller's own clearance and compartments
    COMPOSED with each sample's case.

    Both directions matter and the service handles both: a sample can be
    classified above its case, so the case gate alone would leak its
    existence; and it can sit below its case, because `lab.sample` has no
    classification floor trigger, so the sample's own labels alone would
    leak the case's.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    rows = _svc(conn).queue(clearance=clearance.name, compartments=compartments)
    return {"samples": [_out(s).model_dump(mode="json") for s in rows]}


@router.get("/{sample_id}", response_model=dict)
def detail(
    sample_id: UUID,
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One sample's metadata, its findings and its custody ledger.

    The label check moved INTO the service as `visible()` (F19). It used to
    live here, comparing the sample's own classification and compartments
    and nothing else — so a sample submitted into a RED compartmented case
    at the router's `AMBER` default was readable by anyone with AMBER
    clearance, because `lab.sample` has no `enforce_tlp_floor` trigger to
    stop the row existing at AMBER in the first place.

    Doing it in the service means the composition is written once and a
    second caller cannot skip it. That is not hypothetical: `download()` is
    the caller that skipped it.
    """
    svc = _svc(conn)
    clearance, compartments = user_ceiling(conn, user.user_id)
    # 404 rather than 403: a status code must not be an existence oracle
    # for a compartmented case (deps.py rule 2).
    sample = svc.visible(sample_id, clearance=clearance.name,
                         compartments=compartments)
    if sample is None:
        raise Problem(404, "Not found", "no such sample")
    return {"sample": _out(sample).model_dump(mode="json"),
            "analyses": svc.analyses(sample_id),
            "detonations": svc.detonations(sample_id),
            "custody": svc.custody(sample_id)}


@router.post("/{sample_id}/download")
def download(
    sample_id: UUID, request: Request,
    user: CurrentUser = Depends(require_global("sample.download")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """The encrypted archive. The ONLY endpoint that touches sample bytes.

    The origin check is in the service, not here, so a second caller cannot
    skip it. These headers are the belt to that braces: even if something
    upstream decided to serve this as HTML, `sandbox` in the CSP means the
    browser will not execute it, and `nosniff` means it will not guess.
    """
    # Where the request actually arrived, from the server's own view of the
    # URL -- never from a header the client controls.
    arrived_at = f"{request.url.scheme}://{request.url.netloc}"
    # The caller's ceiling, exactly as `detail()` twenty lines above already
    # does. Its absence here was the worst defect found in this codebase:
    # `detail()` 404'd an over-classified sample and this endpoint handed
    # the same caller its bytes one request later.
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        blob, digest = _svc(conn).download(
            sample_id, actor_id=user.user_id, request_origin=arrived_at,
            clearance=clearance.name, compartments=compartments)
    except SampleError as exc:
        if "no such sample" in str(exc):
            # 404, not 409: "this sample exists but is not yours" is itself
            # a disclosure about a compartmented case.
            raise Problem(404, "Not found", "no such sample") from exc
        raise Problem(409, "Conflict", str(exc)) from exc
    return Response(
        content=blob, media_type="application/octet-stream",
        headers={
            # Named for its hash. The attacker's filename never reappears.
            "Content-Disposition": f'attachment; filename="{digest}.zip"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
            "X-Sample-Archive-Password": "infected",
        },
    )


class RejectBody(BaseModel):
    reason: str = Field(min_length=1)
    #: Defaults to destroying, because that is what a rejection means. The
    #: opt-out exists for the one case the service refuses outright: a
    #: sample under a legal hold, where preservation and destruction are
    #: both legal obligations and the caller has to say which one they are
    #: acting under. Making it a parameter rather than an override keeps
    #: the choice in the request body, where the audit row records it.
    purge_bytes: bool = True


@router.post("/{sample_id}/reject", response_model=SampleOut)
def reject(
    sample_id: UUID, body: RejectBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SampleOut:
    """Record THAT something was rejected and why, without retaining the
    content. The bytes go; the row stays.

    Unless the sample is under a legal hold, in which case the service
    refuses and says so — docs/08: a hold overrides all deletion,
    everywhere.

    ## CR11 (2026-07-26) — the destructive path had no label check

    `reject(purge_bytes=True)` is irreversible: it deletes the object and
    zeroes the data key. It resolved the sample through `get()`, which is
    `WHERE id = %s` with no clearance, compartment or case predicate, and
    the route gated only on the GLOBAL `sample.analyse` role.

    `download()` composes the sample's labels with its case's before it
    will serve a byte. `reject()` — which destroys those same bytes
    forever — did not. So a MALWARE_ANALYST, who deliberately holds no
    case access at all, could permanently destroy a sample belonging to a
    compartmented case knowing only its UUID.

    The check runs BEFORE anything is deleted, and returns the same
    "no such sample" a nonexistent id gives: a 403 here would confirm that
    a particular sample exists in a case the caller cannot see.
    """
    clearance, comps = user_ceiling(conn, user.user_id)
    if _svc(conn).visible(sample_id, clearance=clearance.name,
                          compartments=comps) is None:
        raise Problem(404, "Not found", "no such sample")
    try:
        return _out(_svc(conn).reject(sample_id, actor_id=user.user_id,
                                      reason=body.reason,
                                      purge_bytes=body.purge_bytes))
    except SampleError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


class AssignBody(BaseModel):
    analyst_id: UUID


@router.post("/{sample_id}/assign", response_model=SampleOut)
def assign(
    sample_id: UUID, body: AssignBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SampleOut:
    try:
        return _out(_svc(conn).assign(sample_id, analyst_id=body.analyst_id,
                                      actor_id=user.user_id))
    except SampleError as exc:
        raise Problem(409, "Conflict", str(exc)) from exc


class AnalysisBody(BaseModel):
    kind: str
    findings: dict = Field(default_factory=dict)
    extracted_selectors: list = Field(default_factory=list)
    yara_hits: list[str] = Field(default_factory=list)
    family_assessment: str | None = None
    confidence: str | None = None
    narrative: str | None = None
    tool: str | None = None
    tool_version: str | None = None


@router.post("/{sample_id}/analysis", response_model=dict, status_code=201)
def record_analysis(
    sample_id: UUID, body: AnalysisBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Findings are machine-readable by construction. A family attribution
    without a confidence is refused: it is an assessment, and one without a
    confidence is a fact wearing an assessment's clothes."""
    try:
        analysis_id = _svc(conn).record_analysis(
            sample_id, analyst_id=user.user_id, kind=body.kind,
            findings=body.findings, extracted_selectors=body.extracted_selectors,
            yara_hits=body.yara_hits or None,
            family_assessment=body.family_assessment, confidence=body.confidence,
            narrative=body.narrative, tool=body.tool,
            tool_version=body.tool_version)
    except SampleError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {"id": str(analysis_id)}


class DetonationBody(BaseModel):
    target: str
    exposure_level: str
    authorised_by: UUID | None = None
    note: str | None = None


@router.post("/{sample_id}/detonation", response_model=dict, status_code=201)
def request_detonation(
    sample_id: UUID, body: DetonationBody,
    user: CurrentUser = Depends(require_global("sample.detonate")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record a detonation request. **Nothing is submitted anywhere** --
    docs/11 is emphatic that you integrate with a sandbox rather than build
    one, and no integration exists.

    Anything other than a private instance needs a named authoriser and a
    note, because submitting to a vendor or public sandbox exposes the
    sample AND your interest in it, and operators watch public sandboxes
    for their own samples.
    """
    try:
        det_id = _svc(conn).request_detonation(
            sample_id, requested_by=user.user_id, target=body.target,
            exposure_level=body.exposure_level,
            authorised_by=body.authorised_by, note=body.note)
    except SampleError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return {"id": str(det_id),
            "submitted": False,
            "notice": "Recorded only. No sandbox integration exists; nothing "
                      "has been sent anywhere."}
