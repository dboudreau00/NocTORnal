"""YARA rule sets over HTTP (F12, 2026-09-24).

Mounted at `/samples/yara`, included in the app BEFORE the samples router
so no path here is ever read as a sample id.

Every route that names a set or a version first checks that the caller
may see its set (`_ruleset_visible_or_404`): a set above the caller's
labels answers exactly as one that does not exist. The officer's pending
list is filtered by the officer's own ceiling, the /samples/preserved
precedent.

Two permissions that no role may hold together (iam.separated_duty):
`sample.yara.manage` (the lab: create sets, upload and adopt versions,
queue rescans) and `sample.yara.activate` (the Security Officer: activate
or deactivate a version somebody else sponsored, clearing its licence).
Both require a fresh sign-in, which `require_global` enforces from the
permission rows. Reading rule text needs `sample.analyse` and sight of
the set; the listing needs `sample.read` and never carries source.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    File,
    Form,
    UploadFile,
)
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from noctornal_api import lab_triage, yara_rules
from noctornal_api.http.deps import (
    CurrentUser,
    check_writable_labels,
    get_conn,
    require_global,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import BodyCappedRoute, body_cap, rate_limit
from noctornal_api.iam_admin import IamAdminService

router = APIRouter(prefix="/samples/yara", tags=["samples"],
                   route_class=BodyCappedRoute)

MANAGE = "sample.yara.manage"
ACTIVATE = "sample.yara.activate"


def _ceiling(conn, user) -> dict:
    clearance, held = user_ceiling(conn, user.user_id)
    return {"clearance": clearance.name, "compartments": held}


def _ruleset_visible_or_404(conn, user, *, ruleset_id: UUID | None = None,
                            version_id: UUID | None = None) -> dict:
    """The set or version, or the 404 a nonexistent one gets."""
    svc = yara_rules.RulesetService(conn)
    ceiling = _ceiling(conn, user)
    found = (svc.visible_ruleset(ruleset_id, **ceiling) if ruleset_id
             else svc.visible_version(version_id, **ceiling))
    if found is None:
        raise Problem(404, "Not found", "no such rule set" if ruleset_id
                      else "no such rule set version")
    return found


def _problem(exc: yara_rules.RulesetError) -> Problem:
    title = {400: "Invalid request", 404: "Not found"}.get(exc.status, "Conflict")
    return Problem(exc.status, title, safe_detail(exc))


def _you_may(conn, user) -> dict:
    iam = IamAdminService(conn)
    return {"manage": iam.holds_global_permission(user.user_id, MANAGE),
            "activate": iam.holds_global_permission(user.user_id, ACTIVATE),
            "view_source": iam.holds_global_permission(user.user_id,
                                                       "sample.analyse")}


def _engine() -> dict:
    key = yara_rules.build_key()
    return {"installed": key is not None,
            "version": yara_rules.engine_version(),
            "platform": key.platform if key else yara_rules.host_platform(),
            "extra": yara_rules.EXTRA}


@router.get("/rulesets", response_model=dict)
def list_rulesets(
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Every rule set the caller may see, with its versions' metadata
    (never source), this host's build status, the open activation, the
    licence and the provenance."""
    sets = yara_rules.RulesetService(conn).listing(
        key=yara_rules.build_key(), **_ceiling(conn, user))
    return {"rulesets": sets, "count": len(sets), "engine": _engine(),
            "you_may": _you_may(conn, user)}


class RulesetBody(BaseModel):
    key: str
    display_name: str
    description: str | None = None
    classification: str = "AMBER"
    compartments: list[str] = Field(default_factory=list)


@router.post("/rulesets", response_model=dict, status_code=201,
             dependencies=[Depends(rate_limit("yara.ruleset"))])
def create_ruleset(
    body: RulesetBody,
    user: CurrentUser = Depends(require_global(MANAGE)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """A new, empty rule set, at labels the caller can write."""
    comps = frozenset(c.strip() for c in body.compartments if c.strip())
    check_writable_labels(conn, user, classification=body.classification,
                          compartments=comps)
    try:
        return yara_rules.RulesetService(conn).create(
            key=body.key, display_name=body.display_name,
            description=body.description, classification=body.classification,
            compartments=comps, actor_id=user.user_id)
    except yara_rules.RulesetError as exc:
        raise _problem(exc) from exc


@router.post("/rulesets/{ruleset_id}/versions", response_model=dict,
             status_code=201,
             dependencies=[Depends(rate_limit("yara.ruleset"))])
@body_cap(yara_rules.upload_cap, what="a rule set upload")
async def add_version(
    ruleset_id: UUID,
    background: BackgroundTasks,
    file: UploadFile = File(...),
    licence: str = Form(...),
    licence_review_required: bool = Form(False),
    source_name: str | None = Form(None),
    source_url: str | None = Form(None),
    source_commit: str | None = Form(None),
    note: str | None = Form(None),
    user: CurrentUser = Depends(require_global(MANAGE)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One immutable version of a set: a .yar/.yara file or a .zip of
    them, with its licence as the source states it. Compiled later, never
    in this request; a background task starts the compile when a slot is
    free, and the next static triage pass otherwise."""
    _ruleset_visible_or_404(conn, user, ruleset_id=ruleset_id)
    data = await file.read()
    try:
        # Off the event loop: parsing a hostile zip is bounded, but it is
        # still CPU work in the API process, and this route is async for
        # the upload (on 2026-09-24 a bundle that got past the old
        # preflight held the loop 30 s).
        bundle = await run_in_threadpool(yara_rules.parse_bundle,
                                         file.filename, data)
    except yara_rules.BundleError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from None
    provenance = {"via": "upload"}
    for k, v in (("source_name", source_name), ("source_url", source_url),
                 ("source_commit", source_commit)):
        if v and v.strip():
            provenance[k] = v.strip()[:500]
    key = yara_rules.build_key()
    try:
        out = yara_rules.RulesetService(conn).add_version(
            ruleset_id, bundle, licence=licence,
            licence_review_required=licence_review_required,
            provenance=provenance, note=note, uploaded_by=user.user_id,
            key=key)
    except yara_rules.RulesetError as exc:
        raise _problem(exc) from exc
    if key is not None:
        background.add_task(lab_triage.compile_one_detached,
                            UUID(out["id"]))
    return out


@router.post("/versions/{version_id}/adopt", response_model=dict,
             dependencies=[Depends(rate_limit("yara.ruleset"))])
def adopt_version(
    version_id: UUID,
    user: CurrentUser = Depends(require_global(MANAGE)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """A lab member vouches for a version scripts/yara_db.py imported, so
    it has a sponsor an officer's activation can be checked against."""
    _ruleset_visible_or_404(conn, user, version_id=version_id)
    try:
        return yara_rules.RulesetService(conn).adopt(version_id,
                                                     actor_id=user.user_id)
    except yara_rules.RulesetError as exc:
        raise _problem(exc) from exc


@router.get("/versions/{version_id}", response_model=dict)
def get_version(
    version_id: UUID,
    user: CurrentUser = Depends(require_global("sample.read")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """A version's metadata and this host's build report. No source."""
    found = _ruleset_visible_or_404(conn, user, version_id=version_id)
    found = {k: v for k, v in found.items() if k != "files"}
    # This version alone, not the whole listing (until 2026-09-24 this
    # view rebuilt every set's listing per request).
    v = yara_rules.RulesetService(conn).version_out(
        version_id, yara_rules.build_key())
    if v is None:
        raise Problem(404, "Not found", "no such rule set version")
    return {**found, **v}


@router.get("/versions/{version_id}/files/{index}", response_model=dict,
            dependencies=[Depends(rate_limit("yara.source"))])
def get_version_file(
    version_id: UUID, index: int,
    user: CurrentUser = Depends(require_global("sample.analyse")),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """One file's text, at most 1 MiB, by position so rule paths stay out
    of URLs. The console renders it as text only. Rule text carries
    malicious byte patterns, so it is shown only to an analyst who may
    see the set."""
    _ruleset_visible_or_404(conn, user, version_id=version_id)
    try:
        return yara_rules.RulesetService(conn).file_text(version_id, index)
    except yara_rules.RulesetError as exc:
        raise _problem(exc) from exc


@router.get("/pending", response_model=dict)
def pending(
    user: CurrentUser = Depends(require_global(ACTIVATE)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """The Security Officer's list: versions not active, each with its
    sponsor, licence, review flag and build summary, and the open
    activations. Metadata only, filtered by the officer's ceiling."""
    out = yara_rules.RulesetService(conn).pending(
        key=yara_rules.build_key(), **_ceiling(conn, user))
    return {**out, "engine": _engine(), "you": str(user.user_id)}


class ActivateBody(BaseModel):
    licence_acknowledgement: str | None = None
    replace_open: bool = False


@router.post("/versions/{version_id}/activate", response_model=dict,
             dependencies=[Depends(rate_limit("yara.ruleset"))])
def activate(
    version_id: UUID, body: ActivateBody, background: BackgroundTasks,
    user: CurrentUser = Depends(require_global(ACTIVATE)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Activate a version somebody else sponsored. Activation does not
    rescan held samples; a retrohunt does, when the lab asks for one."""
    _ruleset_visible_or_404(conn, user, version_id=version_id)
    key = yara_rules.build_key()
    try:
        return yara_rules.RulesetService(conn).activate(
            version_id, actor_id=user.user_id,
            licence_acknowledgement=body.licence_acknowledgement,
            replace_open=body.replace_open, key=key)
    except yara_rules.RulesetError as exc:
        if exc.code == "not_compiled" and key is not None:
            background.add_task(lab_triage.compile_one_detached, version_id)
        raise _problem(exc) from exc


class DeactivateBody(BaseModel):
    reason: str


@router.post("/versions/{version_id}/deactivate", response_model=dict,
             dependencies=[Depends(rate_limit("yara.ruleset"))])
def deactivate(
    version_id: UUID, body: DeactivateBody,
    user: CurrentUser = Depends(require_global(ACTIVATE)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Switch a rule set off. The activator's verb only: turning a
    detection off is as sensitive as turning it on."""
    _ruleset_visible_or_404(conn, user, version_id=version_id)
    try:
        return yara_rules.RulesetService(conn).deactivate(
            version_id, actor_id=user.user_id, reason=body.reason)
    except yara_rules.RulesetError as exc:
        raise _problem(exc) from exc


@router.post("/versions/{version_id}/retrohunt", response_model=dict,
             dependencies=[Depends(rate_limit("yara.ruleset"))])
def retrohunt(
    version_id: UUID,
    user: CurrentUser = Depends(require_global(MANAGE)),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Queue a scan of the held samples YOU can see with one active
    version. The runs name you, so each read's custody names you; the
    answer counts only your own view."""
    found = _ruleset_visible_or_404(conn, user, version_id=version_id)
    try:
        return lab_triage.retrohunt(
            conn, version_id, ruleset_id=UUID(found["ruleset_id"]),
            number=found["version"], actor_id=user.user_id,
            **_ceiling(conn, user))
    except yara_rules.RulesetError as exc:
        raise _problem(exc) from exc


__all__ = ["router"]
