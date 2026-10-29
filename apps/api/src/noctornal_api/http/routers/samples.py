"""Sample handling over HTTP (docs/11, invariant 10).

COUNSEL MUST REVIEW A DEPLOYMENT OF THIS (see `samples.py` and the README): a store of
attacker-supplied binaries will eventually receive material whose possession alone is an offence.

Every endpoint returns JSON about a sample except `/download`, which serves the encrypted archive
as an `octet-stream` attachment with `nosniff` and a `sandbox` CSP, and only when this process is
the sample origin by configuration, never by the Host header (`samples.origin_split()`, checked in
the service). With `NOCTORNAL_SAMPLE_ORIGIN` unset every download refuses and readiness fails. A
`__Host-` cookie cannot reach that origin, so the console presents a one-shot ticket minted here,
and the redemption re-reads the account and live clearance; a Bearer token still works for other
callers. The download is metered on the peer address, since a body credential is known only after
a look-up. `sample.download` is lab-side and step-up, `sample.read` case-side; neither implies the
other, and `MALWARE_ANALYST` holds no case access.
"""
from __future__ import annotations

import hashlib
import os
from datetime import timedelta
from uuid import UUID

import psycopg
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    Query,
    Request,
    Response,
    UploadFile,
)
from psycopg.types.json import Json
from pydantic import BaseModel, Field

from noctornal_api.db import SystemPurpose, bind_ticket, system_connection
from noctornal_api.http.deps import (
    CASE_READ_ONLY_TITLE,
    SESSION_COOKIE,
    CurrentUser,
    authorize_object,
    check_writable_labels,
    current_user,
    get_conn,
    refuse_if_case_read_only,
    require_global,
    require_step_up,
    session_token,
    system_conn,
    user_ceiling,
)
from noctornal_api.http.body_ceiling import credential_in_body
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import (
    BodyCappedRoute,
    body_cap,
    client_ip,
    enforce,
    rate_limit,
)
from noctornal_api import fuzzyhash, lab_archive, lab_similarity, lab_triage
from noctornal_api.config import SAMPLE_CAP_ENV, cap_is_declared
from noctornal_api.iam_admin import IamAdminService
from noctornal_api.ratelimit import ip_subject
from noctornal_api.security.access import tlp_from_name
from noctornal_api.samples import (
    AUTHORISE_PERMISSION,
    DERIVED_GAP_STEPS,
    MAX_AUTHORISATION_DAYS,
    MAX_SAMPLE_BYTES,
    PRESERVE,
    QUEUE_STATES,
    RETRIEVE_PERMISSION,
    TICKET_DOWNLOAD,
    TICKET_RETRIEVAL,
    WORKING_SET,
    AuthorisationRequired,
    PolicyNotDeclared,
    ProhibitedContentMatch,
    Sample,
    SampleCaseReadOnly,
    SampleError,
    SampleService,
    disposition_setting,
    origin_split,
    policy_declared,
)

# `route_class=BodyCappedRoute` is what makes the `@body_cap` marker on `submit` work: for marked
# endpoints it wraps the ASGI receive the multipart parser reads through, so an upload is cut off
# as it arrives, not after it is spooled (routers/evidence.py explains the mechanism).
router = APIRouter(prefix="/samples", tags=["samples"],
                   route_class=BodyCappedRoute)


def _svc(conn: psycopg.Connection, *, preserving: bool = False
         ) -> SampleService:
    """The service with the sample store, and the preservation store when the caller is about to
    preserve or retrieve.

    `PreservationStorage()` raises when its credentials are missing, and a queue read must not fail
    on the absence of a store it will never touch."""
    from noctornal_api.samples import PreservationStorage, SampleStorage
    return SampleService(conn, SampleStorage(),
                         PreservationStorage() if preserving else None)


def _ticket_svc(conn: psycopg.Connection) -> SampleService:
    """The service with no storage, for the two steps that decide who may have bytes without
    touching any.

    `SampleStorage()` raises when the bucket is unconfigured, and the mint runs on the application
    process, which does not serve malware: a decision about access must not fail on a credential
    it never uses. The route that serves a sample builds its own store.
    """
    return SampleService(conn)


#: The download's gate, shared so the ticket mint states the same one and the download can apply
#: it by call: FastAPI resolves every declared dependency, so a route that authenticates two ways
#: cannot declare either (see `download`). The key is spelled out, not taken from
#: `samples.DOWNLOAD_PERMISSION`, because `test_ui_invariants` pins this line literally; a test
#: holds the two spellings equal.
_REQUIRE_DOWNLOAD = require_global("sample.download")

#: A ticket is 43 URL-safe characters, so 2 KB of form body is room for it and nothing worth
#: having. Without a bound the sample origin would buffer whatever an unauthenticated caller sent
#: before deciding it was not a ticket.
_TICKET_BODY_CAP = 2 * 1024


def _ip_hash(request: Request) -> bytes | None:
    """The peer address, hashed, for the ticket row and its audit.

    `client_ip` rather than `request.client.host`, for the reason
    `routers/auth.py` records against the same three lines: behind a
    proxy the latter is the load balancer, so every event was attributed
    to the address of the thing in front of the application.
    """
    ip = client_ip(request)
    return hashlib.sha256(ip.encode()).digest() if ip else None


def _download_url(sample_origin: str, sample_id: UUID) -> str:
    """Where the ticket is to be redeemed.

    Built from `API_PREFIX`, as `app._DOWNLOAD_PATH` (the pattern the sample process's allow-list
    and CORS answer match on) is, so the URL is a path this deployment serves. `http/app.py`
    imports this module, so the import is deferred to call time.
    """
    from noctornal_api.http.app import API_PREFIX
    return f"{sample_origin}{API_PREFIX}/samples/{sample_id}/download"


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
    #: Names for the two uuids above: who submitted the sample and who holds it.
    submitted_by_name: str | None = None
    submitted_by_email: str | None = None
    assigned_to_name: str | None = None
    assigned_to_email: str | None = None
    compartments: list[str] = []
    #: The labels the sample is handled at: its own composed with its case's, which is what
    #: `queue()` and `visible()` gate on, and the malware analyst's only marking of it.
    #: `inherited_compartments` come from the case and not the sample; `classification_inherited`
    #: is true when the case raised the level above the sample's own.
    effective_classification: str | None = None
    effective_compartments: list[str] = []
    inherited_compartments: list[str] = []
    classification_inherited: bool = False
    #: `bytes_disposition` is one of `in_sample_store`, `preserved`, `destroyed` or `kept`
    #: (migration 0063); the `preserved_*` fields say where a preserved sample went. `legal_hold`
    #: is the sample's own.
    bytes_disposition: str = "in_sample_store"
    preserved_bucket: str | None = None
    preserved_key: str | None = None
    preserved_at: str | None = None
    legal_hold: bool = False
    #: True when the sample's case is CLOSED, ARCHIVED or PURGED, so the Lab work, detonation and
    #: reject routes refuse it with the case's 409. On the row because the Lab lists samples from
    #: every case, so the open case's state cannot decide what the card offers. The state itself
    #: is not named.
    case_read_only: bool = False
    #: What static triage computed, None until it ran (`triage_gaps` says why each is absent).
    #: `tlsh` is canonical, with no T1 prefix; the console shows and copies it with one.
    imphash: str | None = None
    rich_header_hash: str | None = None
    ssdeep: str | None = None
    tlsh: str | None = None
    #: `{common, why}`: an imphash every .NET binary shares says nothing
    #: about who wrote this one.
    imphash_common: dict = {"common": False, "why": None}
    #: The latest static-triage run: status (never, queued, running, done,
    #: failed, skipped, abandoned), who asked or that it was scheduled,
    #: its times, why it failed, and the limits it ran under. Never its
    #: steps or any YARA rule set.
    static_triage: dict = {"status": "never"}
    #: Whether and when the sample was screened, and how many hash lists its newest screening
    #: record consulted.
    screening_outcome: str = "NOT_SCREENED"
    screened_at: str | None = None
    screening_lists_consulted: int | None = None
    #: Archive expansion: the archive sample this one was cut from, and its path inside it; the
    #: detail's `archive` carries the tree at the reader's labels.
    parent_sample_id: str | None = None
    archive_path: str | None = None


def _out(s: Sample, names: dict | None = None,
         case: tuple[str, frozenset[str]] | None = None,
         case_read_only: bool = False) -> SampleOut:
    """`case` is the sample's case's `(classification, compartments)`, or
    None for a sample with no case (or one whose labels were not looked
    up, when the sample's own labels are the handling labels: `submit`
    has just raised them to the case's floor)."""
    names = names or {}
    sub = names.get(str(s.submitted_by), {})
    held = names.get(str(s.assigned_to), {}) if s.assigned_to else {}
    own_tlp, own_comps = s.classification, frozenset(s.compartments)
    case_tlp, case_comps = case if case else (own_tlp, frozenset())
    effective = max(tlp_from_name(own_tlp), tlp_from_name(case_tlp)).name
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
        submitted_by_name=sub.get("name"), submitted_by_email=sub.get("email"),
        assigned_to_name=held.get("name"), assigned_to_email=held.get("email"),
        compartments=sorted(s.compartments),
        effective_classification=effective,
        effective_compartments=sorted(own_comps | case_comps),
        inherited_compartments=sorted(case_comps - own_comps),
        classification_inherited=effective != own_tlp,
        bytes_disposition=s.bytes_disposition,
        preserved_bucket=s.preserved_bucket, preserved_key=s.preserved_key,
        preserved_at=s.preserved_at.isoformat() if s.preserved_at else None,
        legal_hold=s.legal_hold,
        case_read_only=case_read_only,
        imphash=s.imphash, rich_header_hash=s.rich_header_hash,
        ssdeep=s.ssdeep, tlsh=s.tlsh,
        imphash_common={"common": s.imphash in fuzzyhash.COMMON_IMPHASHES,
                        "why": fuzzyhash.COMMON_IMPHASHES.get(s.imphash or "")},
        screening_outcome=s.screening_outcome,
        screened_at=s.screened_at.isoformat() if s.screened_at else None,
        parent_sample_id=str(s.parent_sample_id) if s.parent_sample_id else None,
        archive_path=s.archive_path,
    )


def _named(svc: SampleService, samples: list[Sample]) -> list[dict]:
    """`_out` for a list, with every submitter and assignee resolved in
    one query rather than one per row, and every case's labels in one
    more, so each row carries the labels it is handled at, and whether
    its case is read-only in one more again."""
    names = svc.people([s.submitted_by for s in samples]
                       + [s.assigned_to for s in samples])
    cases = svc.case_labels([s.case_id for s in samples])
    shut = svc.read_only_cases([s.case_id for s in samples])
    # The gaps computed at read time replace any stored copy of the same step (legacy rows), and
    # each row carries its latest static-triage run, each in one query for the whole page.
    derived = svc.derived_gaps(samples)
    runs = svc.static_triage_summaries([s.id for s in samples])
    # How many lists each row's newest screening consulted.
    screened = svc.screening_summaries([s.id for s in samples])
    out = []
    for s in samples:
        row = _out(s, names, cases.get(str(s.case_id)),
                   case_read_only=str(s.case_id) in shut).model_dump(mode="json")
        row["triage_gaps"] = [
            g for g in (row["triage_gaps"] or [])
            if not (isinstance(g, dict) and g.get("step") in DERIVED_GAP_STEPS)
        ] + derived.get(str(s.id), [])
        row["static_triage"] = runs.get(str(s.id), {"status": "never"})
        row["screening_lists_consulted"] = (
            screened.get(str(s.id), {}).get("lists_consulted"))
        out.append(row)
    return out


def _named_one(svc: SampleService, sample: Sample) -> SampleOut:
    """One sample the way the queue shows it, for the routes that answer
    with the row they changed."""
    return SampleOut(**_named(svc, [sample])[0])


@router.get("/policy", response_model=dict)
def policy_status(user: CurrentUser = Depends(current_user),
                  conn: psycopg.Connection = Depends(get_conn)) -> dict:
    """Whether an operator has declared a prohibited-content policy, and which separate sample
    origin is configured, so a refused submission has a discoverable cause.

    `sample_origin` is where the console fetches a download from, or null.
    `sample_origin_configured` is true only when the split is usable (set, an origin, and not a
    second name for the application's); `sample_origin_problem` says why not. For the submit form,
    `designated_person` is who a refused analyst contacts, and `your_clearance` and
    `your_compartments`, the caller's own, bound the labels it offers.
    """
    declared, detail = policy_declared()
    split = origin_split()
    usable = split.split_problem is None
    disposition, disposition_problem = disposition_setting()
    clearance, held = user_ceiling(conn, user.user_id)
    return {
        "policy_declared": declared,
        "policy_reference": detail if declared else None,
        "detail": None if declared else detail,
        "designated_person":
            os.environ.get("NOCTORNAL_DESIGNATED_PERSON", "").strip() or None,
        "your_clearance": clearance.name,
        "your_compartments": sorted(held),
        "sample_origin_configured": usable,
        "sample_origin": split.sample if usable else None,
        "sample_origin_problem": split.split_problem,
        # The cap `submit` enforces on THIS process, for the picker.
        "max_sample_bytes": MAX_SAMPLE_BYTES,
        # What a rejection does with the bytes, so the console's confirmation can say so before it
        # happens, and the reason when the setting is one this build refuses.
        "rejected_sample_disposition": disposition,
        "rejected_sample_disposition_problem": disposition_problem,
        "max_sample_bytes_declared": cap_is_declared(SAMPLE_CAP_ENV),
        "counsel_review_required": True,
        # Counts only, never a list's name.
        "screening": _screening_policy(conn),
        # Never the URL, the host or the token.
        "sandbox": _sandbox_policy(),
        "notice": (
            "Counsel must review this deployment before it is used. A store "
            "of attacker-supplied binaries will eventually receive material "
            "whose possession alone is an offence, and the handling rules "
            "differ by jurisdiction. This software records a declaration; "
            "it cannot verify one."
        ),
    }


def _sandbox_policy() -> dict:
    """The configured sandbox, as the console may show it."""
    from noctornal_api.sandbox import policy_block
    return policy_block()


def _screening_policy(conn: psycopg.Connection) -> dict:
    """The policy block's screening facts (counts only)."""
    from noctornal_api.screening import policy_block
    return policy_block(conn)


@router.post("", response_model=SampleOut, status_code=201,
             dependencies=[Depends(rate_limit("evidence.ingest"))])
@body_cap(lambda: MAX_SAMPLE_BYTES, what="a sample submission")
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
    """Land a sample in QUARANTINE. Nothing reaches the RE queue until triage has run, and nothing
    is accepted until a prohibited-content policy has been declared.

    `BodyCappedRoute` caps the body at `MAX_SAMPLE_BYTES` as it arrives, and the 413 names the cap.
    `sample.submit` is global and knows nothing about a case, so a case id is authorised by
    `authorize_object`, as every case-scoped write is: otherwise a holder could write into a case
    file they cannot see. `compartments` is for a sample more restricted than its case; the service
    unions the case's in regardless.
    """
    parsed = frozenset(c.strip() for c in compartments.split(",") if c.strip())
    # Refuse to author what the caller could not read back: otherwise a holder of `sample.submit`
    # could land a RED sample from an AMBER account, a row they cannot see or correct. On both
    # paths: `authorize_object` covers only the case-attached one, and an unattached sample is
    # where an over-labelled row would sit unnoticed.
    check_writable_labels(conn, user, classification=classification,
                          compartments=parsed)
    if case_id is not None:
        authorize_object(conn, user, case_id=case_id,
                         permission_key="sample.submit",
                         classification=classification, compartments=parsed)
    # Bounded before it starts: the route class refused anything over the
    # cap at the receive. The service re-checks the length as its own
    # precondition.
    data = await file.read()
    clearance, held = user_ceiling(conn, user.user_id)
    svc = _svc(conn)
    try:
        # The submission on a system connection: its duplicate check must find a sample the
        # submitter may not see, or the upload stores a second copy of live malware (and the unique
        # hash turns it into a 500). What a refusal may say is still decided by the submitter's own
        # labels, below.
        with system_connection(SystemPurpose.SAMPLE_INTAKE, reuse=conn) as sconn:
            submitted = _svc(sconn).submit(
                data, submitted_by=user.user_id, case_id=case_id,
                # The filename is stored for the record and is NEVER used as
                # a path component or rendered unescaped.
                original_filename=file.filename, source_note=source_note,
                classification=classification, compartments=parsed,
                # Only for how much the duplicate refusal may say: uploading
                # a hash you suspect and reading the error back is a cheap
                # probe for "is anybody else working this intrusion".
                visible_to_clearance=clearance.name,
                visible_to_compartments=held)
        return _named_one(svc, submitted)
    except PolicyNotDeclared as exc:
        # 451: the refusal is legal, not technical, and a 400 would send
        # somebody looking at their upload.
        raise Problem(451, "Unavailable for legal reasons", safe_detail(exc)) from exc
    except ProhibitedContentMatch as exc:
        # Legal too: the sentence names whom to contact and never the list or its category; the
        # console shows it and opens no card.
        raise Problem(451, "Unavailable for legal reasons", safe_detail(exc)) from None
    except SampleError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


@router.get("", response_model=dict)
def queue(
    state: str | None = Query(default=None),
    case_id: UUID | None = Query(default=None),
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The RE queue, filtered by the caller's own clearance and compartments composed with each
    sample's case.

    Both directions matter: a sample can be classified above its case, so the case gate alone
    would leak its existence, and below it, since `lab.sample` has no classification floor
    trigger, so its own labels alone would leak the case's. `state` picks one of the six queue
    states, none meaning the working set (quarantined, triaged, assigned), and any other is a 400
    naming them rather than an empty list; `case_id` narrows to one case.
    """
    if state is not None and state.strip():
        wanted = state.strip().upper()
        if wanted not in QUEUE_STATES:
            raise Problem(
                400, "Invalid request",
                f"unknown sample state {state!r}: filter by one of "
                f"{', '.join(QUEUE_STATES)}, or leave it empty for the "
                f"working set")
        states: tuple[str, ...] = (wanted,)
    else:
        wanted = None
        states = WORKING_SET
    clearance, compartments = user_ceiling(conn, user.user_id)
    svc = _svc(conn)
    rows = svc.queue(states=states, case_id=case_id,
                     clearance=clearance.name, compartments=compartments)
    return {"samples": _named(svc, rows), "state": wanted,
            "states": list(states),
            "case_id": str(case_id) if case_id else None}


@router.get("/preserved", response_model=dict)
def preserved_for_authorisation(
    user: CurrentUser = Depends(require_global("sample.preserved.authorise")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The Security Officer's way in to the preserved samples.

    Security Officers hold no `sample.read` and read no case content, so this is gated on the
    officer's own verb, step-up included, like the break-glass review queue the console shows it
    beside. It returns each preserved sample's identity, where it is held, and its authorisations,
    none of its content (`preserved_for_authorisation` says what is left out and why). Declared
    ahead of `/{sample_id}`, which would otherwise take "preserved" for an id.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    # No storage: this reads rows, and a list about who may have bytes must
    # not fail over credentials for a store it never touches.
    samples = SampleService(conn).preserved_for_authorisation(
        clearance=clearance.name, compartments=compartments)
    return {"samples": samples, "count": len(samples),
            "authorise_permission": AUTHORISE_PERMISSION,
            "retrieve_permission": RETRIEVE_PERMISSION}


# ---------------------------------------------------------------------------
# Prohibited-content screening. Declared ahead of `/{sample_id}`, beside `/preserved`. None of
# these is served on the sample origin: its allow-list admits the two download paths alone.
# ---------------------------------------------------------------------------

_REVIEW_SCREENING = require_global("sample.screening.review")
_MANAGE_SCREENING = require_global("sample.screening.manage")


def _screening_problem(exc: Exception) -> Problem:
    from noctornal_api.screening import ScreeningConflict, ScreeningRefused
    if isinstance(exc, ScreeningRefused):
        return Problem(451, "Unavailable for legal reasons", safe_detail(exc))
    if isinstance(exc, ScreeningConflict):
        return Problem(409, "Conflict", safe_detail(exc))
    return Problem(400, "Invalid request", safe_detail(exc))


@router.get("/screening", response_model=dict)
def screening_overview(
    unreviewed: bool = Query(default=False),
    user: CurrentUser = Depends(_REVIEW_SCREENING),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The Security Officer's screening record: the authorities, the lists, and every match,
    newest first.

    The match list is label-free (docs/00 decision 126): the officer must see every match whatever
    its labels, so each row carries only a hash prefix, the time, the list names, the disposition
    then and now, the alert state and the reviews. `you_may_open` says whether the full record,
    gated at `/screening/results/{id}`, is within the officer's ceiling. No route returns an entry
    of any list."""
    from noctornal_api import screening
    clearance, held = user_ceiling(conn, user.user_id)
    svc = screening.ScreeningService(conn)
    # The match list and the section's counts on a system connection: they are label-free on
    # purpose, and under row-level security the officer's own view would drop every match above
    # them. `you_may_open` is still computed against the officer's labels.
    with system_connection(SystemPurpose.SCREENING, reuse=conn) as sconn:
        now = screening.state(sconn)
        matches = screening.ScreeningService(sconn).results(
            clearance=clearance.name, compartments=held,
            unreviewed_only=unreviewed)
    declared, _detail = policy_declared()
    return {
        "authority": {"declared": now.authority is not None,
                      "reference": now.authority,
                      "problem": now.authority_problem},
        "policy_declared": declared,
        "exact_hash_only": True,
        "sentence": screening.EXACT_HASH_SENTENCE,
        "archive_sentence": screening.ARCHIVE_MEMBERS_SENTENCE,
        "lists": svc.lists(),
        "matches": matches,
        "counts": {"matches": now.matches, "unreviewed": now.unreviewed_matches,
                   "pending_preservation": now.pending_preservation,
                   "bytes_not_found": now.bytes_not_found,
                   "behind": now.behind, "purges_pending": now.purges_pending},
        "last_pass_at": now.last_pass_at.isoformat() if now.last_pass_at else None,
        "categories": list(screening.CATEGORIES),
        "review_actions": list(screening.REVIEW_ACTIONS),
        "list_cap_bytes": screening.list_cap(),
        "you_may_manage": IamAdminService(conn).holds_global_permission(
            user.user_id, screening.MANAGE_PERMISSION),
    }


@router.get("/screening/results/{result_id}", response_model=dict)
def screening_result(
    result_id: UUID,
    user: CurrentUser = Depends(_REVIEW_SCREENING),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One match's record, a 404 unless the officer's ceiling reaches the
    sample's composed labels. Never the filename, source note, rejection
    reason, analyses or custody. Audited as opened."""
    from noctornal_api.screening import ScreeningService
    clearance, held = user_ceiling(conn, user.user_id)
    out = ScreeningService(conn).open_result(
        result_id, actor_id=user.user_id, clearance=clearance.name,
        compartments=held)
    if out is None:
        raise Problem(404, "Not found", "no such screening record")
    return out


def _list_cap() -> int:
    from noctornal_api.screening import list_cap
    return list_cap()


@router.post("/screening/lists", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("screening.import"))])
@body_cap(_list_cap, what="a hash list imported through the console (a "
                          "larger one goes through scripts/sample_screen.py "
                          "import)")
async def import_screening_list(
    file: UploadFile = File(...),
    name: str = Form(...),
    provider: str = Form(...),
    authority_reference: str = Form(...),
    category: str = Form(...),
    user: CurrentUser = Depends(_MANAGE_SCREENING),
    # On a system connection: the in-request pass screens every held sample against the new list,
    # not only the ones the officer may read.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.SCREENING)),
) -> dict:
    """Import a list under both recorded authorities (451 names the one
    missing), in one transaction, then screen every held sample against it
    in this request (database work only, budgeted; the worker moves the
    bytes of any match). 409 for a second active copy of the same file,
    400 naming the first bad line."""
    from functools import partial

    from starlette.concurrency import run_in_threadpool

    from noctornal_api.screening import ScreeningError, ScreeningService
    try:
        # Off the event loop: the parse, the COPY and the in-request pass (up to 20 s) are
        # synchronous, and this route is async only for the upload, as in lab_yara.
        return await run_in_threadpool(partial(
            ScreeningService(sconn).import_list,
            file.file, name=name, provider=provider,
            authority_reference=authority_reference, category=category,
            actor_id=user.user_id, via="console"))
    except ScreeningError as exc:
        raise _screening_problem(exc) from None


class RetireListBody(BaseModel):
    reason: str = Field(min_length=10, max_length=2000)
    purge_entries: bool = False


@router.post("/screening/lists/{list_id}/retire", response_model=dict)
def retire_screening_list(
    list_id: UUID, body: RetireListBody,
    user: CurrentUser = Depends(_MANAGE_SCREENING),
    # The lists are read-only to the request role (migration 0179), so this writes on the
    # SCREENING connection, as their import does.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.SCREENING)),
) -> dict:
    """Stop comparing against a list. Nothing is deleted here: a sample
    that matched stays matched, and the entries, if their purge is asked
    for, are deleted by the worker in batches."""
    from noctornal_api.screening import ScreeningError, ScreeningService
    try:
        return ScreeningService(sconn).retire_list(
            list_id, actor_id=user.user_id, reason=body.reason,
            purge_entries=body.purge_entries)
    except ScreeningError as exc:
        raise _screening_problem(exc) from None


@router.post("/screening/lists/{list_id}/purge", response_model=dict)
def purge_screening_list(
    list_id: UUID,
    user: CurrentUser = Depends(_MANAGE_SCREENING),
    # On the SCREENING connection, as the retirement above.
    sconn: psycopg.Connection = Depends(system_conn(SystemPurpose.SCREENING)),
) -> dict:
    """Ask for a retired list's entries to be deleted, later than its
    retirement: a licence may require it when it ends."""
    from noctornal_api.screening import ScreeningError, ScreeningService
    try:
        return ScreeningService(sconn).request_purge(list_id,
                                                    actor_id=user.user_id)
    except ScreeningError as exc:
        raise _screening_problem(exc) from None


@router.post("/screening/rescan", response_model=dict,
             dependencies=[Depends(rate_limit("screening.rescan"))])
def start_screening_pass(
    user: CurrentUser = Depends(_MANAGE_SCREENING),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """A screening pass, now: database work only, budgeted to 20 seconds.
    The worker finishes anything left and moves matched bytes."""
    from noctornal_api.screening import ScreeningService
    # Every held sample, whatever the officer may read.
    with system_connection(SystemPurpose.SCREENING, reuse=conn) as sconn:
        return ScreeningService(sconn).rescan(trigger="RESCAN",
                                              actor_id=user.user_id,
                                              move_bytes=False, budget_seconds=20)


class ScreeningReviewBody(BaseModel):
    action: str
    reference: str | None = Field(default=None, max_length=500)
    note: str | None = Field(default=None, max_length=4000)


@router.post("/screening/results/{result_id}/reviews", response_model=dict,
             status_code=201)
def review_screening_result(
    result_id: UUID, body: ScreeningReviewBody,
    user: CurrentUser = Depends(_REVIEW_SCREENING),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record the officer's review of a match. DISPOSED_OUTSIDE records that counsel directed
    disposal of the held copy outside the product; it changes nothing here. Not gated on the
    sample's labels: the officer governs every match on the label-free list, and a review reveals
    nothing of the record."""
    from noctornal_api.screening import ScreeningError, ScreeningService
    try:
        # On a system connection: the officer reviews any match on the label-free list, including
        # one whose sample is above them, and the review row hangs off a result row security would
        # otherwise hide from them.
        with system_connection(SystemPurpose.SCREENING, reuse=conn) as sconn:
            return ScreeningService(sconn).review(
                result_id, actor_id=user.user_id, action=body.action,
                reference=body.reference, note=body.note)
    except ScreeningError as exc:
        raise _screening_problem(exc) from None


# ---------------------------------------------------------------------------
# The sandbox sign-off. Declared ahead of `/{sample_id}`. Not `require_global("sample.read")`: a
# lead investigator assigned to the case may hold no global role; the service decides who may act,
# and answers 404 to everyone else.
# ---------------------------------------------------------------------------

class SignOffBody(BaseModel):
    approve: bool
    note: str | None = Field(default=None, max_length=2000)


@router.get("/detonations/awaiting-signoff", response_model=dict)
def detonations_awaiting_signoff(
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The requests waiting for the CALLER's sign-off, each re-gated by the
    same eligibility reader the sign-off uses."""
    from noctornal_api.sandbox import SandboxService
    rows = SandboxService(conn).awaiting_signoff(user.user_id)
    return {"detonations": rows, "count": len(rows)}


@router.post("/detonations/{detonation_id}/sign-off", response_model=dict,
             dependencies=[Depends(rate_limit("sample.detonate"))])
def sign_off_detonation(
    detonation_id: UUID, body: SignOffBody,
    user: CurrentUser = Depends(current_user),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Approve (QUEUED) or decline (DECLINED) a request naming you. 404
    unless you are its named, still eligible authoriser and it waits."""
    from noctornal_api.sandbox import NotYours, SandboxError, SandboxService
    try:
        return SandboxService(conn).sign_off(
            detonation_id, actor_id=user.user_id, approve=body.approve,
            note=body.note)
    except NotYours:
        raise Problem(404, "Not found", "no such detonation request") from None
    except SandboxError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


@router.post("/detonations/{detonation_id}/cancel", response_model=dict,
             dependencies=[Depends(rate_limit("sample.detonate"))])
def cancel_detonation(
    detonation_id: UUID,
    user: CurrentUser = Depends(current_user),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Withdraw a request that has not been sent: its requester or its
    named authoriser."""
    from noctornal_api.sandbox import NotYours, SandboxError, SandboxService
    try:
        return SandboxService(conn).cancel(detonation_id, actor_id=user.user_id)
    except NotYours:
        raise Problem(404, "Not found", "no such detonation request") from None
    except SandboxError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


class SimilarByValueBody(BaseModel):
    """A value search. The value travels here, in the body, and never in
    the URL, and it is never logged, audited or stored: a hash an analyst
    pastes can be the thing they are investigating. Unconstrained in the
    model on purpose: a validation error would echo it back, and the
    service's own check names the expected form without repeating it."""
    by: str
    value: str
    ssdeep_min: int = lab_similarity.SSDEEP_MIN_DEFAULT
    tlsh_max: int = lab_similarity.TLSH_MAX_DEFAULT
    limit: int = lab_similarity.LIMIT_DEFAULT
    include_rejected: bool = False


#: The sample column a searched value is compared with.
_VALUE_COLUMN = {"imphash": "imphash", "rich_header": "rich_header_hash",
                 "ssdeep": "ssdeep", "tlsh": "tlsh"}


@router.post("/similar", response_model=dict,
             dependencies=[Depends(rate_limit("sample.similar"))])
@body_cap(lambda: 1024, what="a similarity query")
def similar_by_value(
    body: SimilarByValueBody,
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Samples you can see whose imphash, Rich header, ssdeep or TLSH is the value given, or near
    it. Validated before any work (a 400 names the expected form); metered by its own limit,
    tighter than search; not audited, as search is not. Declared ahead of `/{sample_id}`."""
    try:
        value = lab_similarity.canonical_value(body.by, body.value)
        clearance, held = user_ceiling(conn, user.user_id)
        out = lab_similarity.similar(
            conn, hashes={_VALUE_COLUMN[body.by]: value}, by=body.by,
            thresholds=lab_similarity.Thresholds(
                body.ssdeep_min, body.tlsh_max, body.limit,
                body.include_rejected),
            clearance=clearance.name, compartments=held)
    except lab_similarity.SimilarityError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from None
    return out


@router.get("/{sample_id}", response_model=dict)
def detail(
    sample_id: UUID,
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One sample's metadata, its findings and its custody ledger.

    The label check is the service's `visible()`, which composes the case's labels in, so a second
    caller cannot skip it: `lab.sample` has no `enforce_tlp_floor` trigger, so a sample can sit
    below its case's labels.
    """
    svc = _svc(conn)
    clearance, compartments = user_ceiling(conn, user.user_id)
    # 404 rather than 403: a status code must not be an existence oracle
    # for a compartmented case (deps.py rule 2).
    sample = svc.visible(sample_id, clearance=clearance.name,
                         compartments=compartments)
    if sample is None:
        raise Problem(404, "Not found", "no such sample")
    # Recorded after the label check, so a refused read writes nothing, and before the ledger is
    # read, so the reader sees their own look.
    svc.record_view(sample_id, actor_id=user.user_id)
    # The reader's ceiling reaches the findings too: a machine YARA row, or an assessment derived
    # from one, is shown only to a reader who may see its rule set, and custody says no more about
    # it than that.
    ceiling = {"clearance": clearance.name, "compartments": compartments}
    out = {"sample": _named(svc, [sample])[0],
           "analyses": svc.analyses(sample_id, **ceiling),
           "detonations": svc.detonations(sample_id),
           "custody": svc.custody(sample_id, **ceiling),
           # The last five runs, the same fields as the row's summary, and whether this deployment
           # can run YARA at all.
           "static_runs": lab_triage.static_runs(conn, sample_id),
           "yara_engine": _yara_engine(),
           # Whether this sample may be sent to the configured sandbox now, and why not: the one
           # eligibility reader.
           "sandbox": _sandbox_for(conn, sample_id),
           # The archive this sample was cut from and the members cut from it, each at the
           # reader's labels.
           "archive": lab_archive.tree_for(conn, sample_id, **ceiling),
           # What this reader may do here, so the card offers the lab's own work (assign, record
           # an analysis, reject, detonate) to the people who can do it and says who can to
           # everybody else. A hint for the console; every route still decides for itself.
           "you_may": _you_may(conn, user)}
    if sample.preserved_key:
        out["preservation"] = {
            "authorisations": svc.preservation_authorisations(sample_id),
            "you_hold_a_live_authorisation":
                svc.live_preservation_authorisation(user.user_id, sample_id)
                is not None,
            "authorise_permission": AUTHORISE_PERMISSION,
            "retrieve_permission": RETRIEVE_PERMISSION,
        }
    return out


def _sandbox_for(conn: psycopg.Connection, sample_id: UUID) -> dict:
    from noctornal_api.sandbox import eligibility, sandbox_settings
    settings, problem = sandbox_settings()
    eligible, reason = eligibility(conn, sample_id, settings)
    return {"configured": settings is not None, "problem": problem,
            "eligible": eligible, "reason": reason}


def _you_may(conn: psycopg.Connection, user: CurrentUser) -> dict:
    """The lab verbs this caller holds, read the way `require_global`
    reads them but without the step-up clause: this widens nothing, it
    only decides which controls the card draws."""
    iam = IamAdminService(conn)
    analyse = iam.holds_global_permission(user.user_id, "sample.analyse")
    return {"analyse": analyse,
            "detonate": iam.holds_global_permission(user.user_id,
                                                    "sample.detonate"),
            "download": iam.holds_global_permission(user.user_id,
                                                    "sample.download"),
            # Running static triage on demand is the analyst's verb.
            "static_triage": analyse}


def _yara_engine() -> dict:
    """Whether YARA can run in this deployment, and which engine."""
    from noctornal_api.yara_rules import engine_version
    version = engine_version()
    return {"installed": version is not None, "version": version}


@router.get("/{sample_id}/people", response_model=dict)
def people(
    sample_id: UUID,
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The people the sample card's two pickers offer, by name.

    `assignees`: active accounts holding `sample.analyse` that can see this sample.
    `detonation_authorisers`: who can sign off a non-private detonation (a lead investigator on
    the sample's case, cleared for it, and not the caller). Each list goes only to a caller who can
    use it, so `sample.read` alone does not make this a directory of the lab and the case's leads.
    404 for a sample the caller may not see, as `detail` answers.
    """
    from noctornal_ontology.definition import SELECTOR_TYPES

    _visible_or_404(conn, user, sample_id)
    svc = SampleService(conn)
    may = _you_may(conn, user)
    return {
        "assignees": svc.eligible_assignees(sample_id) if may["analyse"] else [],
        "detonation_authorisers": (
            svc.detonation_authorisers(sample_id, exclude=user.user_id)
            if may["detonate"] else []),
        # The record form's selector types. The console's copy of the
        # ontology comes from a CASE route the malware analyst cannot
        # call, so the lab carries the one list it needs.
        "selector_types": ([{"key": t.key, "display_name": t.display_name}
                            for t in SELECTOR_TYPES]
                           if may["analyse"] else []),
        "you_may": may,
    }


class DownloadTicketOut(BaseModel):
    #: Returned exactly once. The row holds its SHA-256 and nothing else,
    #: so this string exists in this response and in the page that asked
    #: for it, and nowhere a log, a backup or a Referer can reach.
    ticket: str
    expires_at: str
    #: Absolute, on the SAMPLE origin: the console must not have to
    #: assemble it, because assembling it from `location.origin` is how
    #: the Lab pane came to fetch the application origin in the first
    #: place -- the one place the download is guaranteed to refuse.
    download_url: str


@router.post("/{sample_id}/download-ticket", response_model=DownloadTicketOut,
             status_code=201)
def mint_download_ticket(
    sample_id: UUID,
    request: Request,
    user: CurrentUser = Depends(_REQUIRE_DOWNLOAD),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> DownloadTicketOut:
    """A one-shot, sixty-second authority to download one sample from the sample origin, which a
    `__Host-` cookie cannot reach by design.

    A POST under the ordinary session, so the CSRF double-submit applies and no prefetcher, link
    scanner or unfurl can mint one. The double-submit stops other origins, not a script injected
    into the console's own, which is why the ticket is scoped to one sample and a minute rather
    than being the session token. `SampleService.issue_download_ticket` runs the same
    `_downloadable` check as `download()`, so no ticket is minted for a sample the caller could
    not download directly; it also refuses when this process is the sample origin or the split is
    unusable.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        # A ticket row binds its holder once spent, so the request role may not write one
        # (migration 0109): minted on a system connection, after the gate above, with the caller's
        # ceiling.
        with system_connection(SystemPurpose.TICKETS, reuse=conn) as sconn:
            ticket = _ticket_svc(sconn).issue_download_ticket(
                sample_id, actor_id=user.user_id, clearance=clearance.name,
                compartments=compartments,
                # Which session asked, for the audit chain. Recorded, never
                # re-checked at redemption: see 0061.
                session_id=user.session_id, ip_hash=_ip_hash(request))
    except SampleError as exc:
        if "no such sample" in str(exc):
            # 404, and the same 404 `detail()` gives: "this sample exists
            # but is not yours" is itself a disclosure about a
            # compartmented case.
            raise Problem(404, "Not found", "no such sample") from exc
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    # Not None: every split whose `sample` is unset was refused above,
    # by the service, before a row was written.
    sample_origin = origin_split().sample or ""
    return DownloadTicketOut(
        ticket=ticket.raw,
        expires_at=ticket.expires_at.isoformat(),
        download_url=_download_url(sample_origin, sample_id))


def _meter_download(request: Request, response: Response) -> None:
    """Meter the download on the peer address, before anything else runs.

    The address is the only subject that exists here: the credential may be a ticket in the body,
    unknown until looked up, and a caller cannot mint an address as they can a token. A route-level
    dependency, so FastAPI solves it first, and with no connection of its own, unlike
    `limits.rate_limit`, whose IP branch opens one (a real connect) to audit a denial. So a denial
    here is logged by `enforce` and never written to `audit.event`: an unauthenticated caller must
    not be able to cause audit writes.
    """
    enforce(request, response, "sample.download",
            ip_subject(client_ip(request)))


def _credential_presented(request: Request) -> None:
    """Refuse a request that presents nothing, before a connection opens.

    A tokenless request must 401 without opening a database connection, as `deps.session_token`
    ensures elsewhere, so an unauthenticated flood costs no connections and an outage still
    answers 401. A ticket travels in the body, so this asks from the headers alone whether any
    credential is present; a body counts without being read, since reading it here would parse it
    twice. Junk in a body therefore costs a connection, as junk in `Authorization` does.
    """
    # The origin split is asked first, as the exhibit route's `_production_presented` does, so a
    # ticket posted to the application process is refused before `redeem_download_ticket` spends
    # it and audits a redemption that served nothing. Configuration only, so this opens no
    # connection.
    split = origin_split()
    if not split.serves_here:
        raise Problem(409, "Conflict", split.refusal or "")
    if (request.headers.get("authorization")
            or request.cookies.get(SESSION_COOKIE)
            or request.headers.get("transfer-encoding")):
        return
    if (request.headers.get("content-length") or "0") != "0":
        return
    raise Problem(401, "Unauthenticated",
                  "no session token and no download ticket")


def _download_actor(request: Request, conn: psycopg.Connection,
                    sample_id: UUID, ticket: str | None
                    ) -> tuple[UUID, UUID | None, str]:
    """Who is downloading, the ticket that proved it if one did, and what that ticket was minted
    for: a download, or the retrieval of a preserved sample (migration 0063). A session is always a
    download; a retrieval crosses on a ticket or not at all.

    The two authentications cannot both be `Depends`, since FastAPI resolves every declared
    dependency and `_REQUIRE_DOWNLOAD` would 401 a good ticket, so they are composed by hand from
    the same callables the rest of the API uses, never reimplemented. A presented ticket wins, so a
    request carrying both spends it. `redeem_download_ticket` re-reads the holder's `is_active` and
    `sample.download` in the service, and `download()` reads `user_ceiling` live. The ticket path
    does not re-derive the session, a residual docs/17 states.
    """
    if ticket:
        try:
            spent = _ticket_svc(conn).redeem_download_ticket(
                ticket, sample_id=sample_id, ip_hash=_ip_hash(request))
        except SampleError as exc:
            # 401, not 403: a spent or expired ticket is an expired credential. One answer for all
            # four refusal reasons, because "already redeemed" would tell the holder of a stolen
            # ticket that it was real.
            raise Problem(401, "Unauthenticated", safe_detail(exc)) from exc
        # The sample origin runs no session, so under row-level security this connection is bound
        # to the spent ticket's holder before anything is read for them.
        bind_ticket(conn, ticket)
        return spent
    raw = session_token(request, request.headers.get("authorization"))
    user = current_user(request, raw, conn)
    _REQUIRE_DOWNLOAD(user, conn)
    require_step_up(user, conn)
    return user.user_id, None, TICKET_DOWNLOAD


@router.post("/{sample_id}/download",
             dependencies=[Depends(_meter_download)])
@body_cap(_TICKET_BODY_CAP, what="a download ticket")
@credential_in_body
def download(
    sample_id: UUID,
    request: Request,
    #: The one-shot ticket, in the form body. Not a query parameter: a URL reaches the access log,
    #: the Referer and the browser history. Not JSON: form encoding is CORS-safelisted, so the
    #: redemption is a simple cross-origin request with no preflight, while JSON would need
    #: `content-type` in `app._preflight`'s `Access-Control-Allow-Headers`.
    ticket: str | None = Form(default=None),
    _presented: None = Depends(_credential_presented),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """The encrypted archive: the only endpoint that touches sample bytes.

    The origin check is in the service and reads configuration, so a second caller cannot skip it
    and the route passes nothing from the request (`request.url` is built from the Host header).
    If anything upstream served this as HTML, `sandbox` in the CSP stops it executing and `nosniff`
    stops the browser guessing. A session or a one-shot `ticket` from `download-ticket` proves the
    caller (`_download_actor`); either way one user is the actor the labels are checked against,
    the audit names and the custody row records.
    """
    actor_id, ticket_id, purpose = _download_actor(request, conn, sample_id,
                                                   ticket)
    # The caller's ceiling, as `detail()` applies it: without it an over-classified sample that
    # `detail()` hides would still be served. Read live, so a clearance withdrawn since the ticket
    # was minted bites before the bytes move.
    clearance, compartments = user_ceiling(conn, actor_id)
    try:
        if purpose == TICKET_RETRIEVAL:
            # A preserved sample: the same archive, from the preservation store, under a live
            # authorisation `retrieve_preserved` checks again here, so one revoked inside the
            # ticket's minute bites before a byte moves.
            blob, digest = _svc(conn, preserving=True).retrieve_preserved(
                sample_id, actor_id=actor_id,
                clearance=clearance.name, compartments=compartments,
                ticket_id=ticket_id)
        else:
            blob, digest = _svc(conn).download(
                sample_id, actor_id=actor_id,
                clearance=clearance.name, compartments=compartments,
                ticket_id=ticket_id)
    except AuthorisationRequired as exc:
        raise Problem(451, "Unavailable for legal reasons",
                      safe_detail(exc)) from exc
    except SampleError as exc:
        if "no such sample" in str(exc):
            # 404, not 409: "this sample exists but is not yours" is itself
            # a disclosure about a compartmented case.
            raise Problem(404, "Not found", "no such sample") from exc
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
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
    #: True disposes of the bytes as the deployment decided, by
    #: `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION`: preserved under a legal hold by default, destroyed
    #: only where an operator chose `destroy`. False records the rejection and disposes of nothing.
    #: Kept in the request body, where the custody row records it; the `description` is what a
    #: script client reads in the API document.
    purge_bytes: bool = Field(
        default=True,
        description=(
            "true: dispose of the working copy as the deployment decided "
            "(NOCTORNAL_REJECTED_SAMPLE_DISPOSITION). `preserve`, the "
            "default since Alpha 6, keeps the bytes under a legal hold that "
            "nothing in the product lifts; `destroy` deletes them for good, "
            "which is what true meant until Alpha 6. false: record the "
            "rejection and dispose of nothing. GET /samples/policy reports "
            "the disposition in force."))


@router.post("/{sample_id}/reject", response_model=SampleOut)
def reject(
    sample_id: UUID, body: RejectBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    # A fresh sign-in, whatever `sample.analyse` itself requires: a rejection moves the evidence
    # into the preservation store, which it cannot leave without two people, or destroys it under
    # `destroy`, and a session somebody walked away from must not be enough for either. The console
    # asks for the sign-in before it sends (`smpStepUp`).
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> SampleOut:
    """Record that something was rejected and why. The row stays; what happens to the bytes is the
    deployment's decision. Needs a sign-in from the last 15 minutes (step-up), like a download.

    With `purge_bytes` true (the default) the working copy is disposed of as
    `NOCTORNAL_REJECTED_SAMPLE_DISPOSITION` says. `preserve`, the default, copies the ciphertext
    into the preservation store under a legal hold and keeps the data key before deleting the
    working copy; if the store refuses the copy, nothing changes. `destroy` deletes the object and
    zeroes the data key, which is what true meant before preservation was the default. With
    `purge_bytes` false nothing is disposed of. `GET /samples/policy` reports the disposition in
    force. A legal hold on the sample or its case refuses destruction (docs/08); preservation is
    not a deletion.

    The label check, composing the case's labels as `download()` does, runs before anything is
    disposed of: without it the global `sample.analyse` would let a MALWARE_ANALYST destroy a
    compartmented case's sample by its uuid. A hidden sample gets the same "no such sample" as a
    nonexistent id, since a 403 would confirm it exists.
    """
    clearance, comps = user_ceiling(conn, user.user_id)
    sample = _svc(conn).visible(sample_id, clearance=clearance.name,
                                compartments=comps)
    if sample is None:
        raise Problem(404, "Not found", "no such sample")
    # A rejection changes the sample and disposes of its working copy, so a read-only case refuses
    # it whatever the disposition: its material leaves only through the retention purge, which
    # takes two people.
    _refuse_if_read_only(conn, user, sample, "sample.analyse")
    disposition, _problem = disposition_setting()
    try:
        # The preservation store is built only when this rejection uses it, so a destroying
        # deployment or a rejection that disposes of nothing is not refused over its credentials.
        # The service refuses an unknown disposition, naming the variable.
        svc = _svc(conn, preserving=body.purge_bytes
                   and disposition == PRESERVE)
        rejected = svc.reject(sample_id, actor_id=user.user_id,
                              reason=body.reason,
                              purge_bytes=body.purge_bytes)
    except SampleCaseReadOnly as exc:
        raise _read_only_problem(conn, user, sample, "sample.analyse",
                                 exc) from exc
    except SampleError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return _named_one(svc, rejected)


class AssignBody(BaseModel):
    analyst_id: UUID


@router.post("/{sample_id}/assign", response_model=SampleOut)
def assign(
    sample_id: UUID, body: AssignBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> SampleOut:
    """Put a quarantined or triaged sample in one analyst's hands.

    The sample must be one the caller can see (the 404 `detail` gives), since assigning is a write
    against it, and the assignee must be in `eligible_assignees`: an active account holding
    `sample.analyse` that can see the sample. Refused with the case's 409 when the sample's case is
    read-only.
    """
    sample = _visible_or_404(conn, user, sample_id)
    _refuse_if_read_only(conn, user, sample, "sample.analyse")
    svc = _svc(conn)
    if str(body.analyst_id) not in {
            a["id"] for a in svc.eligible_assignees(sample_id)}:
        raise Problem(
            400, "Invalid request",
            "a sample can be assigned only to an active malware analyst "
            "(sample.analyse) who is cleared to see it")
    try:
        return _named_one(svc, svc.assign(
            sample_id, analyst_id=body.analyst_id, actor_id=user.user_id))
    except SampleCaseReadOnly as exc:
        raise _read_only_problem(conn, user, sample, "sample.analyse",
                                 exc) from exc
    except SampleError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc


#: What a recorded analysis can say it was, and how sure an attribution
#: can be. Mirrored from the service and the `analytic_confidence` type so
#: a bad value is a sentence rather than a database error.
_ANALYSIS_KINDS = ("STATIC", "YARA", "MANUAL_RE", "SANDBOX", "VENDOR")
_CONFIDENCES = ("LOW", "MODERATE", "HIGH")


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
    #: The YARA rule set version this assessment was taken from, when the card's "Use as family
    #: assessment" made it: the row is then read through that set's labels too, never below its
    #: source.
    derived_from_version_id: UUID | None = None


@router.post("/{sample_id}/analysis", response_model=dict, status_code=201)
def record_analysis(
    sample_id: UUID, body: AnalysisBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record an analysis. Findings are machine-readable by construction, and a family attribution
    without a confidence is refused: it would be a fact wearing an assessment's clothes.

    Refused with the 404 `detail` gives for a sample the caller cannot see, since an analysis is a
    write against it, and with the case's 409 when its case is read-only: an attribution dated
    after `closed_at` is the post-closure material the rule keeps out. Each extracted selector
    must name its type and value, or it can never be proposed into the case
    (`propose_extracted_selector`)."""
    sample = _visible_or_404(conn, user, sample_id)
    _refuse_if_read_only(conn, user, sample, "sample.analyse")
    if body.kind not in _ANALYSIS_KINDS:
        raise Problem(400, "Invalid request",
                      f"kind must be one of {', '.join(_ANALYSIS_KINDS)}")
    if body.confidence is not None and body.confidence not in _CONFIDENCES:
        raise Problem(400, "Invalid request",
                      f"confidence must be one of {', '.join(_CONFIDENCES)}")
    from noctornal_ontology.definition import SELECTOR_TYPES
    known = {s.key for s in SELECTOR_TYPES}
    for i, entry in enumerate(body.extracted_selectors):
        kind = (str(entry.get("selector_type") or entry.get("type") or "")
                .strip().upper() if isinstance(entry, dict) else "")
        if not (kind and str(entry.get("value") or "").strip()):
            raise Problem(
                400, "Invalid request",
                f"extracted selector {i + 1} needs a selector_type and a value")
        if kind not in known:
            raise Problem(
                400, "Invalid request",
                f"extracted selector {i + 1} names an unknown selector type "
                f"{kind!r}")
    if body.derived_from_version_id is not None:
        _check_derived_from(conn, user, sample_id, body.derived_from_version_id)
    try:
        analysis_id = _svc(conn).record_analysis(
            sample_id, analyst_id=user.user_id, kind=body.kind,
            findings=body.findings, extracted_selectors=body.extracted_selectors,
            yara_hits=body.yara_hits or None,
            family_assessment=body.family_assessment, confidence=body.confidence,
            narrative=body.narrative, tool=body.tool,
            tool_version=body.tool_version,
            derived_from_version_id=body.derived_from_version_id)
    except SampleCaseReadOnly as exc:
        raise _read_only_problem(conn, user, sample, "sample.analyse",
                                 exc) from exc
    except SampleError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"id": str(analysis_id)}


def _check_derived_from(conn: psycopg.Connection, user: CurrentUser,
                        sample_id: UUID, version_id: UUID) -> None:
    """An assessment says it came from a rule set version: 404 unless the caller may see that
    version's set, 400 unless a machine YARA row of that version exists on this sample."""
    from noctornal_api.yara_rules import RulesetService
    clearance, held = user_ceiling(conn, user.user_id)
    if RulesetService(conn).visible_version(
            version_id, clearance=clearance.name, compartments=held) is None:
        raise Problem(404, "Not found", "no such rule set version")
    if conn.execute(
            """SELECT 1 FROM lab.sample_analysis
                WHERE sample_id = %s AND origin = 'machine' AND kind = 'YARA'
                  AND yara_ruleset_version_id = %s LIMIT 1""",
            (sample_id, version_id)).fetchone() is None:
        raise Problem(400, "Invalid request",
                      "an assessment can be taken only from a scan of this "
                      "sample by that rule set version")


class ProposeBody(BaseModel):
    #: Which entry of the analysis's `extracted_selectors`, from 0. The
    #: caller names the entry and nothing else: the proposal is derived
    #: from what the analysis recorded.
    index: int = Field(ge=0)


@router.post("/{sample_id}/analyses/{analysis_id}/propose",
             response_model=dict, status_code=202,
             dependencies=[Depends(rate_limit("capture"))])
def propose_selector(
    sample_id: UUID, analysis_id: UUID, body: ProposeBody,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Propose one extracted selector into the sample's case triage queue.

    docs/11's "findings flow back as assertions", through the normal proposal path: nothing
    reaches the graph until a case analyst accepts it in Triage, as their assertion graded as an
    inference. The lab analyst needs no case access and gets none: the answer is 202 (nothing the
    caller may see was created) and `{"sent": true, "label"}` whether a proposal was queued, one
    already existed or the case holds the entity, and names no case code, so a role barred from
    case content cannot probe the graph with values it typed. Metered like capture, because a loop
    here floods a queue.
    """
    sample = _visible_or_404(conn, user, sample_id)
    # The gate's refusal, not only the service's: titled so the console knows it, and audited.
    _refuse_if_read_only(conn, user, sample, "sample.analyse")
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        # Under the caller's ceiling: a finding the caller cannot see is "no such analysis",
        # however they learned its id. The Lab proposes into a case its analyst is not on, and
        # "already in the graph" is judged against the whole case, so the proposal runs on a system
        # connection; the caller's ceiling still decides which analysis they may use.
        with system_connection(SystemPurpose.LAB_PROPOSE, reuse=conn) as sconn:
            out = SampleService(sconn).propose_extracted_selector(
                sample, analysis_id, body.index, actor_id=user.user_id,
                clearance=clearance.name, compartments=held)
    except SampleCaseReadOnly as exc:
        raise _read_only_problem(conn, user, sample, "sample.analyse",
                                 exc) from exc
    except SampleError as exc:
        if "no such analysis" in str(exc):
            raise Problem(404, "Not found", "no such analysis") from exc
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return out


def _refuse_triage(conn: psycopg.Connection, user: CurrentUser,
                   sample_id: UUID, status: int, title: str, reason: str,
                   message: str) -> Problem:
    """An on-demand refusal, audited with its reason code."""
    conn.execute(
        """INSERT INTO audit.event (actor_id, actor_kind, action, object_type,
                                    object_id, outcome, detail)
           VALUES (%s, 'USER', 'SAMPLE_STATIC_TRIAGE_REFUSED', 'sample', %s,
                   'DENIED', %s)""",
        (user.user_id, sample_id, Json({"reason": reason})))
    return Problem(status, title, message)


@router.post("/{sample_id}/static-triage", response_model=dict,
             status_code=202,
             dependencies=[Depends(rate_limit("sample.triage"))])
def run_static_triage(
    sample_id: UUID,
    background: BackgroundTasks,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Queue static triage of one sample now.

    The request never waits for a child: it enqueues (merging into a run already queued for the
    sample, which then names this caller too) and answers 202, and a background task starts the
    run after the response when a slot is free (`will_run: now`), or the next cron pass takes it
    (`next_pass`). 404 for a sample the caller may not see; the case's 409 for a closed case; 451
    while no prohibited-content policy is declared; 409 for a rejected sample, one above the
    analysis maximum (naming the setting) or one whose triage is running now. Every refusal is
    audited.
    """
    sample = _visible_or_404(conn, user, sample_id)
    _refuse_if_read_only(conn, user, sample, "sample.analyse")
    declared, detail = policy_declared()
    if not declared:
        raise _refuse_triage(conn, user, sample_id, 451,
                             "Unavailable for legal reasons", "policy", detail)
    if sample.state == "REJECTED":
        raise _refuse_triage(conn, user, sample_id, 409, "Conflict", "rejected",
                             "a rejected sample is never analysed")
    settings = lab_triage.settings_or_default()
    if sample.byte_size > settings.max_bytes:
        raise _refuse_triage(
            conn, user, sample_id, 409, "Conflict", "too_large",
            f"this sample is larger than {lab_triage.MAX_BYTES_ENV} allows "
            f"static triage to read")
    # Sweep first, so a run whose process died cannot leave a permanent
    # "already running".
    lab_triage.sweep_abandoned(conn)
    if lab_triage.running_run(conn, sample_id) is not None:
        raise _refuse_triage(conn, user, sample_id, 409, "Conflict", "running",
                             "static triage is already running on this sample")
    result = lab_triage.enqueue(conn, sample_id, trigger="ON_DEMAND",
                                requested_by=user.user_id)
    if result.run_id is None:
        raise _refuse_triage(conn, user, sample_id, 409, "Conflict", "excluded",
                             "this sample cannot be analysed")
    free = lab_triage.slot_free(conn, settings.concurrency)
    background.add_task(lab_triage.run_queued_detached, result.run_id)
    run = conn.execute(
        "SELECT id, status, queued_at FROM lab.static_run WHERE id = %s",
        (result.run_id,)).fetchone()
    return {"run": {"id": str(run[0]), "status": run[1].lower(),
                    "trigger_kind": "requested",
                    "queued_at": run[2].isoformat()},
            "merged": result.merged,
            "will_run": "now" if free else "next_pass",
            "sample": _named(SampleService(conn), [sample])[0]}


@router.get("/{sample_id}/similar", response_model=dict,
            dependencies=[Depends(rate_limit("sample.similar"))])
def similar_samples(
    sample_id: UUID,
    by: str = Query(default="all"),
    ssdeep_min: int = Query(default=lab_similarity.SSDEEP_MIN_DEFAULT),
    tlsh_max: int = Query(default=lab_similarity.TLSH_MAX_DEFAULT),
    limit: int = Query(default=lab_similarity.LIMIT_DEFAULT),
    include_rejected: bool = Query(default=False),
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Samples you can see that are similar to this one.

    The sample is checked first and the hashes compared are read from the row the caller may see,
    so a hidden sample's 404 is the same as a random id's. Candidates are found under the Lab's one
    label gate: a sample you may not see is neither listed nor counted. Metered by
    `sample.similar`; not audited."""
    sample = _visible_or_404(conn, user, sample_id)
    clearance, held = user_ceiling(conn, user.user_id)
    try:
        out = lab_similarity.similar(
            conn, hashes={"imphash": sample.imphash,
                          "rich_header_hash": sample.rich_header_hash,
                          "ssdeep": sample.ssdeep, "tlsh": sample.tlsh},
            by=by, thresholds=lab_similarity.Thresholds(
                ssdeep_min, tlsh_max, limit, include_rejected),
            clearance=clearance.name, compartments=held, exclude=sample_id,
            sample_id=sample_id)
    except lab_similarity.SimilarityError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from None
    return {"sample_id": str(sample_id), **out}


class DetonationBody(BaseModel):
    #: "record" is never sent; "submit" asks the sandbox worker to send it. There is no free-text
    #: CAPE options field.
    mode: str = Field(default="record", pattern="^(record|submit)$")
    target: str | None = Field(default=None, max_length=200)
    exposure_level: str | None = None
    authorised_by: UUID | None = None
    note: str | None = Field(default=None, max_length=2000)
    network_route: str | None = Field(default=None, max_length=64)
    package: str | None = Field(default=None, pattern="^[a-z0-9_]{1,32}$")
    timeout_s: int | None = Field(default=None, ge=30, le=1200)
    platform: str | None = Field(default=None, pattern="^(windows|linux)$")
    machine: str | None = Field(default=None, pattern="^[A-Za-z0-9_.-]{1,64}$")


@router.post("/{sample_id}/detonation", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("sample.detonate"))])
def request_detonation(
    sample_id: UUID, body: DetonationBody,
    user: CurrentUser = Depends(require_global("sample.detonate")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Record a detonation request. Nothing is sent from here: `record` is never sent, and `submit`
    asks the sandbox worker to send it (docs/11: integrate with a sandbox rather than build one).

    Anything other than a private instance needs a named authoriser and a note, because submitting
    to a vendor or public sandbox exposes the sample and your interest in it, and operators watch
    public sandboxes for their own samples. The authoriser is somebody `GET /samples/{id}/people`
    lists, never the caller, and the answer names them. Refused with the 404 `detail` gives for a
    sample the caller cannot see, and with the case's 409 when its case is read-only.
    """
    sample = _visible_or_404(conn, user, sample_id)
    _refuse_if_read_only(conn, user, sample, "sample.detonate")
    if body.mode == "submit":
        # Refused with 409 naming the reason; nothing is sent here.
        from noctornal_api.sandbox import SandboxError, SandboxService
        try:
            return SandboxService(conn).request(
                sample_id, requested_by=user.user_id,
                network_route=body.network_route,
                authorised_by=body.authorised_by, note=body.note,
                package=body.package, timeout_s=body.timeout_s,
                platform=body.platform, machine=body.machine)
        except SampleCaseReadOnly as exc:
            raise _read_only_problem(conn, user, sample, "sample.detonate",
                                     exc) from exc
        except (SandboxError, SampleError) as exc:
            raise Problem(409, "Conflict", safe_detail(exc)) from exc
    if not body.target or not body.exposure_level:
        raise Problem(400, "Invalid request",
                      "a record-only request names the target and its exposure")
    try:
        det_id = _svc(conn).request_detonation(
            sample_id, requested_by=user.user_id, target=body.target,
            exposure_level=body.exposure_level,
            authorised_by=body.authorised_by, note=body.note)
    except SampleCaseReadOnly as exc:
        raise _read_only_problem(conn, user, sample, "sample.detonate",
                                 exc) from exc
    except SampleError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    named = (_svc(conn).people([body.authorised_by]).get(str(body.authorised_by))
             if body.authorised_by else None)
    return {"id": str(det_id), "mode": "record",
            "submitted": False,
            # PENDING: the named person has been told, and has confirmed nothing in the product.
            "status": "PENDING",
            "authoriser_confirmed": False,
            "authorised_by_name": (named or {}).get("name"),
            "authorised_by_email": (named or {}).get("email"),
            # A record-only request is never sent, whether or not a sandbox is configured.
            "notice": ("Recorded only. This request is never sent anywhere."
                       + (" The person you named has not confirmed it in the "
                          "product, and they have been told it names them."
                          if body.authorised_by else ""))}


# ---------------------------------------------------------------------------
# Preserved samples: two people to get one back out (migration 0063)
# ---------------------------------------------------------------------------

class PreservationAuthoriseBody(BaseModel):
    #: The person being authorised, by account id or email. The Security
    #: Officer knows the person, not their uuid.
    granted_to: str = Field(min_length=1)
    #: What may be retrieved and why. Not decoration: an authorisation
    #: whose scope nobody wrote down is one nobody can say was exceeded.
    scope_note: str = Field(min_length=21)
    legal_basis: str = Field(min_length=1)
    duration_days: int = Field(default=7, ge=1, le=MAX_AUTHORISATION_DAYS)


def _visible_or_404(conn: psycopg.Connection, user: CurrentUser,
                    sample_id: UUID) -> Sample:
    """The sample, or the 404 `detail` gives. No storage: a question about
    labels must not fail over bucket credentials it never uses."""
    clearance, compartments = user_ceiling(conn, user.user_id)
    sample = SampleService(conn).visible(sample_id, clearance=clearance.name,
                                         compartments=compartments)
    if sample is None:
        raise Problem(404, "Not found", "no such sample")
    return sample


def _refuse_if_read_only(conn: psycopg.Connection, user: CurrentUser,
                         sample: Sample, permission_key: str) -> None:
    """The case's read-only rule, for a Lab write on an existing sample: assign, record an
    analysis, propose a selector, request a detonation and reject.

    A sample attached to a case is that case's content (`cases.CONTENT_READ_ONLY_STATES`), and
    these routes gate on global lab verbs that never reach `authorize_object`; without this a
    closed case's sample would take new attributions after `closed_at`, and under `destroy` one
    analyst could destroy it. The rule is the gate's own, called by hand: one 409 titled
    `CASE_READ_ONLY_TITLE` and one audit row. Called after the label check, so a caller who cannot
    see the sample gets the 404; one who can see it but not its case learns the case's state, never
    its code. Preserved-retrieval authorisation and the download are governance and reads, so they
    are not routed here."""
    if sample.case_id is not None:
        refuse_if_case_read_only(conn, user, sample.case_id, permission_key)


def _read_only_problem(conn: psycopg.Connection, user: CurrentUser,
                       sample: Sample, permission_key: str,
                       exc: SampleCaseReadOnly) -> Problem:
    """The service's own read-only refusal (`SampleCaseReadOnly`), which
    fires when the case was closed after `_refuse_if_read_only` looked,
    answered and audited as the gate answers it. The gate raises; the
    Problem returned is for a case reopened again in between."""
    _refuse_if_read_only(conn, user, sample, permission_key)
    return Problem(409, CASE_READ_ONLY_TITLE, safe_detail(exc))


@router.post("/{sample_id}/preserved/authorisations", response_model=dict,
             status_code=201)
def authorise_preserved_retrieval(
    sample_id: UUID, body: PreservationAuthoriseBody,
    user: CurrentUser = Depends(require_global("sample.preserved.authorise")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Authorise somebody ELSE to retrieve one preserved sample.

    `sample.preserved.authorise` is held by SECURITY_OFFICER alone and
    `sample.preserved.retrieve` by CASE_OWNER alone, so the person who
    wants the material and the person who permits it are structurally
    different people. Self-authorisation is refused here, in the service,
    and by a CHECK in 0063. Step-up, because the permission requires it.
    """
    _visible_or_404(conn, user, sample_id)
    svc = _svc(conn)
    try:
        granted_to = svc.resolve_account(body.granted_to)
        if granted_to == user.user_id:
            raise SampleError(
                "you cannot authorise your own retrieval: the authorisation "
                "is the control, and authorising yourself removes it")
        auth_id = svc.grant_preservation_authorisation(
            sample_id, granted_to=granted_to, granted_by=user.user_id,
            scope_note=body.scope_note, legal_basis=body.legal_basis,
            duration=timedelta(days=body.duration_days))
    except SampleError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
    return {"id": str(auth_id), "granted_to": str(granted_to),
            "expires_in_days": body.duration_days}


@router.post("/{sample_id}/preserved/authorisations/{authorisation_id}/revoke",
             response_model=dict)
def revoke_preserved_retrieval(
    sample_id: UUID, authorisation_id: UUID,
    user: CurrentUser = Depends(require_global("sample.preserved.authorise")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """End an authorisation early. It stays on the record as revoked."""
    _visible_or_404(conn, user, sample_id)
    try:
        _svc(conn).revoke_preservation_authorisation(
            authorisation_id, sample_id=sample_id, actor_id=user.user_id)
    except SampleError as exc:
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    return {"id": str(authorisation_id), "revoked": True}


@router.post("/{sample_id}/preserved/retrieval-ticket",
             response_model=DownloadTicketOut, status_code=201)
def mint_retrieval_ticket(
    sample_id: UUID,
    request: Request,
    user: CurrentUser = Depends(require_global("sample.preserved.retrieve")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> DownloadTicketOut:
    """A one-shot ticket to retrieve one preserved sample, spent at the sample origin's download
    path as a download ticket is.

    Not a route of its own: the bytes are sample bytes (invariant 10), and the sample origin
    serves only its download path and exhibit production (`app._allowed_on_sample_origin`), so a
    second byte-serving route would be a second door. The ticket carries its purpose, so the
    redemption re-reads `sample.preserved.retrieve` rather than `sample.download`, reads the
    preservation store and checks the live authorisation again. 451 when the caller holds no live
    authorisation: the two-person control working, audited as a refusal.
    """
    clearance, compartments = user_ceiling(conn, user.user_id)
    try:
        # Minted on a system connection, as the download ticket is.
        with system_connection(SystemPurpose.TICKETS, reuse=conn) as sconn:
            ticket = _ticket_svc(sconn).issue_retrieval_ticket(
                sample_id, actor_id=user.user_id, clearance=clearance.name,
                compartments=compartments, session_id=user.session_id,
                ip_hash=_ip_hash(request))
    except AuthorisationRequired as exc:
        raise Problem(451, "Unavailable for legal reasons",
                      safe_detail(exc)) from exc
    except SampleError as exc:
        if "no such sample" in str(exc):
            raise Problem(404, "Not found", "no such sample") from exc
        raise Problem(409, "Conflict", safe_detail(exc)) from exc
    sample_origin = origin_split().sample or ""
    return DownloadTicketOut(
        ticket=ticket.raw,
        expires_at=ticket.expires_at.isoformat(),
        download_url=_download_url(sample_origin, sample_id))
