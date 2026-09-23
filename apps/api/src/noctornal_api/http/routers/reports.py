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

## A file to save comes out of the release

ux15-report:report-download-bypasses-egress (2026-09-22). `POST /report`
also answered `fmt=markdown` with the finished file as an attachment,
under `report.generate` alone: no step-up, no egress check, audited only
as REPORT_GENERATED. The console's "Download markdown" button called it,
so a RED document, which invariant 8 says never leaves "webhooks and
export alike", went to disk one click after Prepare. And when an analyst
did ask the gate, the release rebuilt with hypotheses ON whatever the
preview had said, so the verdict could be about a different document from
the file saved.

So the markdown now comes from `/release` alone: the gate judges the
document with the same `include_hypotheses` and `preset` the preview used,
and the answer carries the cleared bytes and a filename. Both endpoints
return `content_digest`, so the console can refuse to save a cleared
document that is not the one the analyst previewed. `fmt=markdown` on the
build endpoint is refused with a pointer to the release, rather than
silently answered as JSON: a client that asked for a file must learn that
the file now has a gate in front of it.

What this does NOT claim. The build response still carries the same
markdown as `document`, so the preview can show the analyst the exact text
before anything is judged. A script holding `report.generate` can
therefore write that text to disk without asking the gate. That is not new
exposure (the JSON has always carried the same content as structured data,
and the preview exists to be read), but it means the gate is a recorded
decision on the console's only path to a file, not a wall around the
content. The release's copy differs from the build's in one line: its
"Generated" time is the moment it was cleared. `content_digest` leaves that
line out, which is why a matching digest means the same document.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Path, Query
from psycopg.types.json import Json
from pydantic import BaseModel

from noctornal_api.egress import Destination
from noctornal_api.http.deps import (
    CurrentUser,
    audit_auth_event,
    authorize_object,
    current_user,
    effective_labels,
    get_conn,
    require,
    require_step_up,
    user_ceiling,
)
from noctornal_api.http.errors import Problem, safe_detail
from noctornal_api.http.limits import rate_limit
from noctornal_api.projections import PRESETS
from noctornal_api.security.access import (
    CHECK_STEP_UP,
    AccessResolutionError,
    evaluate,
    tlp_from_name,
)
from noctornal_api.reports import (
    ReportBuilder,
    ReportError,
    check_egress,
    content_digest,
    render_markdown,
)
from noctornal_api.stores import PgAccessResolver

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
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc
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
) -> dict:
    """Prepare a report. Builds only; releases nothing.

    Rate-limited on the analytics budget because it materialises a
    projection and, with hypotheses on, scores a matrix -- the same class of
    work, and there is no reason to give it a second, separate allowance.

    The JSON carries the markdown the document would be (`document`) and
    its `content_digest`, so the console's preview is the document rather
    than a second rendering of it that can drift.
    """
    if fmt == "markdown":
        # Checked before anything is read or audited: nothing is built.
        raise Problem(
            409, "Egress check required",
            "A report file leaves the platform, so it is no longer served "
            "here. Ask POST /report/release with destination 'export' (and "
            "the same target_tlp, preset and include_hypotheses); it judges "
            "the document at the egress gate and returns the markdown it "
            "cleared.")
    if target_tlp not in _TLP:
        raise Problem(400, "Invalid request",
                      f"target_tlp must be one of {', '.join(sorted(_TLP))}")
    _known_preset(preset)
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
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc

    _audit(conn, case_id, user.user_id, "REPORT_GENERATED", {
        # Both, because "asked for RED, got AMBER" is the interesting line
        # in an audit log and one field cannot say it.
        "target_tlp": effective_tlp,
        "target_tlp_requested": target_tlp,
        "nodes_withheld": report.redaction.nodes_withheld,
        "edges_withheld": report.redaction.edges_withheld,
        "evidence_withheld": report.redaction.evidence_withheld,
    })

    out = report.as_dict()
    out["document"] = render_markdown(report)
    out["content_digest"] = content_digest(report)
    out["preset"] = preset
    out["include_hypotheses"] = include_hypotheses
    return out


def _known_preset(preset: str) -> None:
    """An unknown preset is the caller's mistake, said as one. It reached
    `GraphService.project` and surfaced as a 500."""
    if preset not in PRESETS:
        raise Problem(400, "Invalid request",
                      f"unknown preset {preset!r}; one of "
                      f"{', '.join(sorted(PRESETS))}")


def _filename(report) -> str:
    """The saved file's name. The classification is in it, because a file
    saved out of a browser loses everything that was only on the page; and
    the case code is left out when the document withholds it, because the
    withheld marker is not a filename (brackets, spaces, a colon) and a
    saved file must not carry the codename the document omits either."""
    return f"{_slug(report)}-TLP-{report.redaction.built_at_tlp}.md"


class ReleaseBody(BaseModel):
    target_tlp: str = "AMBER"
    destination: str
    destination_ceiling: str | None = None
    recipient_note: str | None = None
    # The preview's own parameters. The release used to rebuild with the
    # builder's defaults, so a preview prepared with hypotheses OFF was
    # cleared as a document with them ON (ux15-report, 2026-09-22).
    include_hypotheses: bool = True
    preset: str = "all"


_EXPORT = "report.export"

# The sentence `require_step_up` answers a stale session with, word for
# word: the console recognises it (app.js `reportNeedsSignIn`), and a test
# holds the two together.
STEP_UP_DETAIL = ("re-authenticate with your second factor before "
                  "performing this operation")


def _require_export(
    case_id: UUID = Path(...),
    user: CurrentUser = Depends(current_user),
    conn: psycopg.Connection = Depends(get_conn),
) -> CurrentUser:
    """`require("report.export")`, except that a sign-in which is the ONLY
    thing missing is told so.

    `report.export` is a step-up permission, and `authorize_object` answers
    every failed check, a stale sign-in included, with "missing permission
    report.export on this case". A Lead investigator fifteen minutes into a
    session read that they lacked the permission they hold, and the console
    showed it as an egress refusal with no way to sign in again in place
    (final review C15, 2026-09-23).

    The first fix ran `require_step_up` ahead of the permission gate. That
    gave the right sentence and lost the audit row's case: a stale
    session's denied export was recorded with no case and no permission,
    and an unassigned caller probing a case's export left nothing against
    the case at all (final review C15 follow-up, 2026-09-23). So this is
    the one five-part decision `authorize_object` makes, and only its
    wording changes, only when step-up freshness is the sole failed check.
    That can only happen to a caller assigned to the case, who already
    knows it exists, so the sentence reveals nothing. Every other outcome,
    the 404 for an unassigned caller and "missing permission" for a role
    that a sign-in would not fix, is still `authorize_object`'s own, with
    its own audit row.
    """
    eff_cls, eff_comp = effective_labels(conn, case_id)
    decision = evaluate(PgAccessResolver(conn).resolve(
        user_id=user.user_id, case_id=case_id, permission_key=_EXPORT,
        object_classification=eff_cls, object_compartments=eff_comp,
        mfa_satisfied_at=user.session_mfa_at))
    if decision.allowed:
        return user
    if decision.failed_checks == (CHECK_STEP_UP,):
        # The row `authorize_object` would have written, case included.
        audit_auth_event(conn, "AUTHZ_DENIED", user.user_id, case_id,
                         {"permission": _EXPORT,
                          "failed_checks": list(decision.failed_checks)})
        raise Problem(403, "Forbidden", STEP_UP_DETAIL)
    authorize_object(conn, user, case_id=case_id, permission_key=_EXPORT)
    return user


@router.post("/release", response_model=dict)
def release(
    case_id: UUID, body: ReleaseBody,
    user: CurrentUser = Depends(_require_export),
    # Kept although `report.export` already demands a fresh sign-in: the
    # seed flag is data, and this route must not stop asking if it changes.
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

    Three different 403s can come back, and the console tells them apart:
    "Egress refused" is the gate's verdict on the document; a detail asking
    to re-authenticate is a sign-in that has gone stale and is all that is
    missing; anything else is the caller's role or labels on the case.
    """
    if body.target_tlp not in _TLP:
        raise Problem(400, "Invalid request", "unknown target_tlp")
    _known_preset(body.preset)
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
            preset=body.preset, include_hypotheses=body.include_hypotheses,
            compartments=user_ceiling(conn, user.user_id)[1])
    except ReportError as exc:
        raise Problem(400, "Invalid request", safe_detail(exc)) from exc

    digest = content_digest(report)
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
            "reason": decision.reason, "note": body.recipient_note,
            # WHICH document was judged, so the record can be matched to
            # the file that left (ux15-report, 2026-09-22).
            "content_digest": digest, "preset": body.preset,
            "include_hypotheses": body.include_hypotheses},
           outcome="SUCCESS" if decision.allowed else "DENIED")

    if decision.denied:
        raise Problem(403, "Egress refused", decision.explain())
    return {
        "allowed": True,
        "classification": report.redaction.built_at_tlp,
        "destination": destination.value,
        "redaction": report.redaction.statement(),
        "document": render_markdown(report),
        "content_digest": digest,
        "filename": _filename(report),
        "preset": body.preset,
        "include_hypotheses": body.include_hypotheses,
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
