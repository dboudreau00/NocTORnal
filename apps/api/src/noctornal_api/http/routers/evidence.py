"""Evidence endpoints: upload (WORM), download, integrity check, custody
log, and linking to graph elements.

Element-level authorization: an exhibit may be classified more restrictively
than its case, so these handlers gate on the EVIDENCE row's own
classification/compartments via authorize_object — one complete five-part
decision against the right object.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, File, Form, Response, UploadFile
from pydantic import BaseModel

from noctornal_api.evidence import EvidenceService, EvidenceStorage
from noctornal_api.http.deps import (
    CurrentUser,
    authorize_object,
    check_writable_labels,
    current_user,
    get_conn,
    require,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit

router = APIRouter(prefix="/cases/{case_id}/evidence", tags=["evidence"])


def _svc(conn: psycopg.Connection) -> EvidenceService:
    return EvidenceService(conn, EvidenceStorage())


def _authorize_exhibit(
    conn: psycopg.Connection, user: CurrentUser, case_id: UUID,
    evidence_id: UUID, permission_key: str,
) -> None:
    """Authorize an exhibit, deciding access BEFORE revealing existence.

    A caller who fails the case-level gate gets the same 403 whether or not
    the exhibit id is real, so status codes are not an existence oracle for
    someone whose assignment has expired but who still knows old ids. Only
    once the case check passes does a missing row become a 404, and the
    element's own labels then apply on top (authorize_object unions the
    case's compartments and takes the stricter classification).
    """
    authorize_object(conn, user, case_id=case_id, permission_key=permission_key)
    row = conn.execute(
        """SELECT classification, compartments FROM core.evidence
            WHERE id = %s AND case_id = %s""",
        (evidence_id, case_id),
    ).fetchone()
    if row is None:
        raise Problem(404, "Not found", "evidence does not exist in this case")
    authorize_object(conn, user, case_id=case_id, permission_key=permission_key,
                     classification=row[0], compartments=frozenset(row[1] or []))


class IngestOut(BaseModel):
    evidence_id: str
    sha256: str
    deduplicated: bool


# Every ingest writes to object-locked WORM storage. Those bytes cannot be
# deleted before their retention expires, so an upload loop is a permanent
# storage commitment nobody can undo — a limit here is about cost that
# cannot be reclaimed, not about CPU.
@router.post("", response_model=IngestOut, status_code=201,
             dependencies=[Depends(rate_limit("evidence.ingest"))])
async def upload(
    case_id: UUID,
    file: UploadFile = File(...),
    title: str = Form(...),
    acquisition_method: str = Form("MANUAL_UPLOAD"),
    classification: str = Form("AMBER"),
    description: str | None = Form(None),
    source_url: str | None = Form(None),
    user: CurrentUser = Depends(require("evidence.upload")),
    conn: psycopg.Connection = Depends(get_conn),
) -> IngestOut:
    data = await file.read()
    if not data:
        raise Problem(400, "Invalid request", "empty upload")
    check_writable_labels(conn, user, classification=classification)
    res = _svc(conn).ingest(
        case_id=case_id, title=title,
        media_type=file.content_type or "application/octet-stream",
        data=data, acquired_by=user.user_id,
        acquisition_method=acquisition_method, classification=classification,
        description=description, source_url=source_url,
    )
    return IngestOut(evidence_id=str(res.evidence_id), sha256=res.sha256_hex,
                     deduplicated=res.deduplicated)


@router.get("/{evidence_id}/content")
def download(
    case_id: UUID, evidence_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """Serve the exhibit bytes. The service re-verifies the hash and fails
    closed, so a tampered object is never served. Attachment + nosniff;
    docs/11 additionally requires a SEPARATE ORIGIN for sample bytes — that
    origin split is a deployment concern, not enforced here."""
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.read")
    data = _svc(conn).view(evidence_id, user.user_id)
    return Response(
        content=data, media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{evidence_id}"',
                 "X-Content-Type-Options": "nosniff"},
    )


@router.post("/{evidence_id}/export",
             dependencies=[Depends(rate_limit("evidence.export"))])
def export(
    case_id: UUID, evidence_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    """Export for release outside the platform. evidence.export is a
    step-up permission, so the gate's fifth check demands fresh MFA; the
    service additionally refuses AMBER_STRICT/RED (invariant 8)."""
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.export")
    data = _svc(conn).export(evidence_id, user.user_id)
    return Response(
        content=data, media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{evidence_id}"',
                 "X-Content-Type-Options": "nosniff"},
    )


class VerifyOut(BaseModel):
    ok: bool


@router.post("/{evidence_id}/verify", response_model=VerifyOut)
def verify(
    case_id: UUID, evidence_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> VerifyOut:
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.read")
    return VerifyOut(ok=_svc(conn).verify_integrity(evidence_id, user.user_id))


class CustodyOut(BaseModel):
    action: str
    actor_id: str
    occurred_at: datetime
    hash_verified: bool | None


@router.get("/{evidence_id}/custody", response_model=list[CustodyOut])
def custody(
    case_id: UUID, evidence_id: UUID,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> list[CustodyOut]:
    """The chain of custody — 'who touched this exhibit, and when'."""
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.read")
    return [
        CustodyOut(action=e.action, actor_id=str(e.actor_id),
                   occurred_at=e.occurred_at, hash_verified=e.hash_verified)
        for e in _svc(conn).custody_log(evidence_id)
    ]


class LinkBody(BaseModel):
    node_id: UUID | None = None
    edge_id: UUID | None = None
    relevance: str | None = None
    page_ref: str | None = None


@router.post("/{evidence_id}/links", status_code=204)
def link(
    case_id: UUID, evidence_id: UUID, body: LinkBody,
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> Response:
    if (body.node_id is None) == (body.edge_id is None):
        raise Problem(400, "Invalid request", "exactly one of node_id / edge_id")
    _authorize_exhibit(conn, user, case_id, evidence_id, "evidence.upload")
    # The link target must live in the SAME case: core.evidence_link has no
    # same-case constraint (unlike core.edge), so an unchecked node_id would
    # attach an evidentiary claim to a node in a case the caller has no
    # rights over, audited only under this case.
    target_ok = conn.execute(
        "SELECT 1 FROM core.node WHERE id = %s AND case_id = %s"
        if body.node_id is not None else
        "SELECT 1 FROM core.edge WHERE id = %s AND case_id = %s",
        (body.node_id or body.edge_id, case_id),
    ).fetchone()
    if target_ok is None:
        raise Problem(400, "Invalid request", "link target is not in this case")
    svc = _svc(conn)
    if body.node_id is not None:
        svc.link_to_node(evidence_id=evidence_id, node_id=body.node_id,
                         created_by=user.user_id, relevance=body.relevance,
                         page_ref=body.page_ref)
    else:
        svc.link_to_edge(evidence_id=evidence_id, edge_id=body.edge_id,
                         created_by=user.user_id, relevance=body.relevance,
                         page_ref=body.page_ref)
    return Response(status_code=204)
