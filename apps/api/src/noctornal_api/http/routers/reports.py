"""Report generation and release (docs/08).

`POST /report` builds a document at a target classification under `report.generate`, not step-up;
nothing above that level is read, so the redaction is structural. `POST /report/release` judges it
at the document's own classification under step-up `report.export`, audited as an export, so an
AMBER_STRICT case can release a GREEN report, and it alone answers with a file, built as the
preview was. Both return `content_digest`, which leaves out the "Generated" line, so the console
saves only the document previewed. The build still carries the markdown for the preview, so the
gate is a recorded decision on the console's only path to a file, not a wall around the content.
"""
from __future__ import annotations

from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, Path, Query
from psycopg.types.json import Json
from pydantic import BaseModel

from noctornal_api import jira, transports
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
    TLP_NAMES,
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

_TLP = frozenset(TLP_NAMES)


def _target_within_ceiling(conn: psycopg.Connection, user: CurrentUser,
                           target_tlp: str) -> str:
    """The classification a report may be built at: the target, clamped to the caller's clearance.

    The builder reads everything at or below the target, and the case gate checks only the case's
    label, which a RED element in an AMBER case is above, so an unclamped target would widen what
    comes back. Clamping rather than refusing is deliberate: the caller gets the report they were
    entitled to, marked for what is in it, and a 400 would tell them the higher tier exists.
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

    Rate-limited on the analytics budget: it materialises a projection and, with hypotheses on,
    scores a matrix. The JSON carries the document's markdown and its `content_digest`, so the
    console's preview is the document rather than a second rendering that can drift.
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
    # Clamped to the caller's own clearance before the builder sees it.
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
        # The three figures are what the document says, so they follow the
        # case's withheld-disclosure setting (0030): a 0 under NONE or
        # PRESENCE is "not stated", and the setting is recorded beside them
        # so the row cannot be read as "nothing was withheld".
        "disclosure": report.redaction.disclosure,
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


def _stricter(typed: str | None, configured: str | None) -> str | None:
    """The lower of two ceilings, either of which may be absent. One that
    cannot be read is passed on as it is, so the gate refuses it as unknown
    and does not take it for the other (fail closed)."""
    if configured is None:
        return typed
    if typed is None:
        return configured
    try:
        a, b = tlp_from_name(typed), tlp_from_name(configured)
    except AccessResolutionError:
        try:
            tlp_from_name(typed)
        except AccessResolutionError:
            return typed
        return configured
    return (a if a <= b else b).name


def _release_ceiling(conn: psycopg.Connection, destination: Destination,
                     typed: str | None) -> str | None:
    """The ceiling a release is judged against: the lower of the one the caller typed and the one
    the deployment configured for that destination.

    The drain judges every delivery against the configured one (`transports.configured_ceiling`,
    and for Jira `jira.configured_ceiling`, the destination's own ceiling under the host cap), so a
    release judged on the typed one alone could pass a document the drain then refuses. Export has
    no destination to configure."""
    if destination is Destination.SMTP:
        configured = transports.configured_ceiling(transports.SMTP)
    elif destination is Destination.WEBHOOK:
        configured = transports.configured_ceiling(transports.WEBHOOK)
    elif destination is Destination.JIRA:
        configured = jira.configured_ceiling(conn)
    else:
        configured = None
    return _stricter(typed, configured)


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
    # The preview's own parameters, so the release clears the document that was previewed.
    include_hypotheses: bool = True
    preset: str = "all"


_EXPORT = "report.export"

#: Where `/release` judges a document going: the destinations outside the platform that a person
#: sends a finished document to, in the order the console offers them.
RELEASE_DESTINATIONS: tuple[Destination, ...] = (
    Destination.EXPORT, Destination.SMTP, Destination.JIRA, Destination.WEBHOOK)

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
    """`require("report.export")`, but a stale sign-in that is the only failed check is told so.

    `authorize_object` answers every failed check, a stale sign-in included, with "missing
    permission report.export on this case". This makes the same five-part decision, so the audit
    row keeps its case (running `require_step_up` first would lose it), and changes only the
    wording when step-up freshness is the sole failed check. That can only happen to a caller
    assigned to the case, who knows it exists, so the sentence reveals nothing.
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
    """Check whether the built document may go to a destination; record the verdict either way.

    The gate is called with the document's classification, never the case's. A refusal is audited
    like a permission, since an unrecorded refusal is indistinguishable from nobody having tried.
    Three 403s come back: "Egress refused" is the gate's verdict on the document, a detail asking
    to re-authenticate is a stale sign-in and nothing else, and anything else is the caller's role
    or labels on the case.
    """
    if body.target_tlp not in _TLP:
        raise Problem(400, "Invalid request", "unknown target_tlp")
    _known_preset(body.preset)
    try:
        destination = Destination(body.destination)
    except ValueError:
        destination = None
    if destination not in RELEASE_DESTINATIONS:
        # A release is the gated way out, so only a destination outside the platform is judged:
        # the gate allows anything to `in_app`, which would record a RED report as released.
        # Nothing is built or audited for any other.
        raise Problem(400, "Invalid request",
                      f"a report is released to one of "
                      f"{', '.join(d.value for d in RELEASE_DESTINATIONS)}; "
                      f"{body.destination!r} is not a destination a released "
                      f"document goes to. Inside the platform, the prepared "
                      f"report is already on screen.")

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
    ceiling = _release_ceiling(conn, destination, body.destination_ceiling)
    decision = check_egress(report, destination, destination_ceiling=ceiling)
    _audit(conn, case_id, user.user_id,
           "REPORT_RELEASED" if decision.allowed else "REPORT_RELEASE_REFUSED",
           {# CR1 follow-up: the EFFECTIVE value, plus what was asked for.
        # The requested value alone would leave an append-only record of a RED document released
        # whenever an AMBER caller asked for RED.
        "target_tlp": effective_tlp,
        "target_tlp_requested": body.target_tlp, "destination": destination.value,
            # The ceiling the document was judged against, which is the lower
            # of the one typed and the one configured for the destination.
            "destination_ceiling": ceiling,
            "reason": decision.reason, "note": body.recipient_note,
            # Which document was judged, so the record can be matched to the file that left.
            "content_digest": digest, "preset": body.preset,
            "include_hypotheses": body.include_hypotheses},
           outcome="SUCCESS" if decision.allowed else "DENIED")

    if decision.denied:
        raise Problem(403, "Egress refused", decision.explain())
    return {
        "allowed": True,
        "classification": report.redaction.built_at_tlp,
        "destination": destination.value,
        "destination_ceiling": ceiling,
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
