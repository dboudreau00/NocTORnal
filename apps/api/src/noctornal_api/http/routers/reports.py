"""Report generation and release (Phase 6, docs/08).

Two endpoints and one distinction between them, which is the whole design:

- **`POST /report`** builds a document at a target classification. Nothing
  above that level is read at any point -- the redaction is structural (see
  `reports.py`), so it cannot be defeated by a name in a rationale field.
  Gated on `report.generate`, which is not step-up: producing a redacted
  summary for a colleague is ordinary work.

- **`POST /report/release`** is the one that hands it to somebody. It calls
  the egress gate with the DOCUMENT's classification, which is the point of
  building at a lower level: an AMBER_STRICT case can produce a GREEN report
  and the GREEN report may leave when the case never could. Gated on
  `report.export`, which IS step-up, and audited as an export.

Building and releasing are separate because an analyst should be able to see
exactly what would leave before anything does. A single endpoint that builds
and sends is a single click between a case file and an inbox.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Query, Response
from psycopg.types.json import Json
from pydantic import BaseModel

from noctornal_api.egress import Destination
from noctornal_api.http.deps import (
    CurrentUser,
    get_conn,
    require,
    require_step_up,
    user_ceiling,
)
from noctornal_api.http.errors import Problem
from noctornal_api.http.limits import rate_limit
from noctornal_api.security.access import AccessResolutionError, tlp_from_name
from noctornal_api.reports import (
    ReportBuilder,
    ReportError,
    check_egress,
    render_markdown,
)

router = APIRouter(prefix="/cases/{case_id}/report", tags=["reports"])

_TLP = frozenset({"CLEAR", "GREEN", "AMBER", "AMBER_STRICT", "RED"})


def _target_within_ceiling(conn: psycopg.Connection, user: CurrentUser,
                           target_tlp: str) -> str:
    """The classification a report may be BUILT at, for this caller.

    ## CR1 (CRITICAL, 2026-07-26) — this used to be the caller's string

    `target_tlp` arrived from the query string, was checked against the
    name set, and was then handed to `ReportBuilder` verbatim. The builder
    passes it to `GraphService(clearance=...)` and binds evidence on
    `classification <= target`, so a HIGHER target strictly WIDENS what
    comes back. Nothing clamped it.

    `require("report.generate")` gates the caller against the CASE's label,
    and a RED element may legitimately live in an AMBER case. So an AMBER
    analyst — properly assigned, properly permissioned — could call
    `?target_tlp=RED` and receive the RED nodes' labels, types and
    attributes plus the RED exhibits' titles and hashes, in a document
    stamped `X-TLP: RED`. The build endpoint returns the report directly;
    the egress gate only runs on `/release`, so nothing downstream caught
    it either.

    Both call sites already read `user_ceiling(...)` and used only `[1]`,
    the compartments. Index `[0]` — the clearance — was computed and
    discarded. That is the shape this codebase keeps finding in itself: a
    defence written, present in the call, and never actually consulted.

    Clamping rather than rejecting is deliberate. Asking for a report "at
    RED" when you hold AMBER is an ordinary mistake, and the useful answer
    is the AMBER report you were entitled to, with the marking that matches
    what is actually in it. A 400 would tell an under-cleared caller that
    the higher tier exists and is worth asking for.
    """
    ceiling, _ = user_ceiling(conn, user.user_id)
    try:
        requested = tlp_from_name(target_tlp)
    except AccessResolutionError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc
    return min(requested, ceiling).name


@router.post("", response_model=dict,
             dependencies=[Depends(rate_limit("analytics.suite"))])
def build(
    case_id: UUID,
    target_tlp: str = Query("AMBER", description="Classification to prepare at"),
    preset: str = Query("all"),
    include_hypotheses: bool = Query(True),
    fmt: str = Query("json", pattern="^(json|markdown)$"),
    user: CurrentUser = Depends(require("report.generate")),
    conn: psycopg.Connection = Depends(get_conn),
):
    """Prepare a report. Builds only; releases nothing.

    Rate-limited on the analytics budget because it materialises a
    projection and, with hypotheses on, scores a matrix -- the same class of
    work, and there is no reason to give it a second, separate allowance.
    """
    if target_tlp not in _TLP:
        raise Problem(400, "Invalid request",
                      f"target_tlp must be one of {', '.join(sorted(_TLP))}")
    # CR1: clamped to the caller's own clearance BEFORE the builder sees
    # it. `target_tlp` used to travel from the query string to
    # `GraphService(clearance=...)` untouched.
    effective_tlp = _target_within_ceiling(conn, user, target_tlp)
    try:
        report = ReportBuilder(conn).build(
            case_id, target_tlp=effective_tlp, generated_by=user.user_id,
            preset=preset, include_hypotheses=include_hypotheses,
            # The requester's read-in. The report is built at the TARGET
            # classification but never above the caller's own compartments:
            # a ceiling of RED does not read anybody into anything.
            compartments=user_ceiling(conn, user.user_id)[1])
    except ReportError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc

    _audit(conn, case_id, user.user_id, "REPORT_GENERATED", {
        # Both, because "asked for RED, got AMBER" is the interesting line
        # in an audit log and one field cannot say it.
        "target_tlp": effective_tlp,
        "target_tlp_requested": target_tlp,
        "nodes_withheld": report.redaction.nodes_withheld,
        "edges_withheld": report.redaction.edges_withheld,
        "evidence_withheld": report.redaction.evidence_withheld,
    })

    if fmt == "markdown":
        return Response(
            content=render_markdown(report), media_type="text/markdown",
            headers={
                # The classification travels with the bytes, not just in the
                # body: a file saved out of a browser loses everything that
                # was only on the page.
                "X-TLP": report.redaction.built_at_tlp,
                # The case code is withheld when the case's own labels are
                # above the ceiling, and the withheld marker is not a
                # filename -- it has brackets, spaces and a colon in it. A
                # saved file must not carry the codename the document
                # deliberately omits, either.
                "Content-Disposition":
                    f'attachment; filename="{_slug(report)}-'
                    f'TLP-{report.redaction.built_at_tlp}.md"',
                "X-Content-Type-Options": "nosniff",
            })
    return report.as_dict()


class ReleaseBody(BaseModel):
    target_tlp: str = "AMBER"
    destination: str
    destination_ceiling: str | None = None
    recipient_note: str | None = None


@router.post("/release", response_model=dict)
def release(
    case_id: UUID, body: ReleaseBody,
    user: CurrentUser = Depends(require("report.export")),
    _fresh: None = Depends(require_step_up),
    conn: psycopg.Connection = Depends(get_conn),
) -> dict:
    """Check whether the built document may go to a destination, and record
    the decision either way.

    The gate is called with the DOCUMENT's classification, never the case's.
    A refusal is audited as loudly as a permission: "we tried to send this
    and the platform stopped us" is exactly the event a later review wants
    to find, and an unrecorded refusal is indistinguishable from nobody
    having tried.
    """
    if body.target_tlp not in _TLP:
        raise Problem(400, "Invalid request", "unknown target_tlp")
    try:
        destination = Destination(body.destination)
    except ValueError as exc:
        raise Problem(400, "Invalid request",
                      f"unknown destination {body.destination!r}; one of "
                      f"{', '.join(d.value for d in Destination)}") from exc

    # CR1: the release path had the same hole, and this one hands the
    # result across the boundary.
    effective_tlp = _target_within_ceiling(conn, user, body.target_tlp)
    try:
        report = ReportBuilder(conn).build(
            case_id, target_tlp=effective_tlp, generated_by=user.user_id,
            compartments=user_ceiling(conn, user.user_id)[1])
    except ReportError as exc:
        raise Problem(400, "Invalid request", str(exc)) from exc

    decision = check_egress(report, destination,
                            destination_ceiling=body.destination_ceiling)
    _audit(conn, case_id, user.user_id,
           "REPORT_RELEASED" if decision.allowed else "REPORT_RELEASE_REFUSED",
           {# CR1 follow-up: the EFFECTIVE value, plus what was asked for.
        # This audited body.target_tlp, so an AMBER analyst posting
        # target_tlp=RED left a permanent append-only record saying a
        # RED document had crossed the boundary -- on the one action
        # that actually crosses it. The build path was fixed and this
        # one was missed.
        "target_tlp": effective_tlp,
        "target_tlp_requested": body.target_tlp, "destination": destination.value,
            "reason": decision.reason, "note": body.recipient_note},
           outcome="SUCCESS" if decision.allowed else "DENIED")

    if decision.denied:
        raise Problem(403, "Egress refused", decision.explain())
    return {
        "allowed": True,
        "classification": report.redaction.built_at_tlp,
        "destination": destination.value,
        "redaction": report.redaction.statement(),
        "document": render_markdown(report),
        "notice": (
            "The platform does not deliver this. It has decided the document "
            "MAY leave at this classification; sending it, and to whom, is "
            "still a human act with a human's name on it."
        ),
    }


def _slug(report) -> str:
    """A filename stem. The case code when the document carries it, and a
    neutral one when it does not — never the withheld marker, and never the
    codename the report deliberately left out."""
    if report.redaction.header_withheld:
        return "report"
    return "".join(ch if ch.isalnum() or ch in "-_" else "-"
                   for ch in report.case["code"])[:64] or "report"


def _audit(conn, case_id: UUID, actor_id: UUID, action: str, detail: dict,
           outcome: str = "SUCCESS") -> None:
    conn.execute(
        """INSERT INTO audit.event
               (actor_id, actor_kind, action, object_type, object_id,
                case_id, outcome, detail)
           VALUES (%s, 'USER', %s, 'case', %s, %s, %s, %s)""",
        (actor_id, action, case_id, case_id, outcome, Json(detail)))
